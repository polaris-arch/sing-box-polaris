//go:build windows

package listener

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/windows"
)

var windowsWildcardBytes = [3]byte{0x52, 0x31, 0x30}

type windowsWildcardHandler struct {
	done  chan error
	owner *admissionFixture
}

func (h windowsWildcardHandler) NewConnection(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	var err error
	defer func() { h.done <- errors.Join(err, conn.Close()) }()
	graph, ok := adapter.RuntimeLeaseFromContext(ctx)
	if !ok {
		err = errors.New("native wildcard handler has no graph admission")
		return
	}
	admitted, ok := graph.(*graphFixture)
	if !ok || admitted.owner != h.owner {
		err = errors.New("native family entered a different logical admission")
		return
	}
	resource, ok := adapter.RuntimeResourceLeaseFromContext(ctx, h.owner.id)
	if !ok {
		err = errors.New("native wildcard handler has no exact receiving resource")
		return
	}
	received, ok := resource.(*resourceFixture)
	if !ok || received.owner != h.owner {
		err = errors.New("native family entered a different receiving resource")
		return
	}
	err = windowsWildcardEcho(conn)
}

func windowsWildcardEcho(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var received [3]byte
	if _, err := io.ReadFull(conn, received[:]); err != nil {
		return err
	}
	if received != windowsWildcardBytes {
		return fmt.Errorf("wrong native wildcard bytes: %x", received)
	}
	if n, err := conn.Write(received[:]); err != nil {
		return err
	} else if n != len(received) {
		return io.ErrShortWrite
	}
	var trailing [1]byte
	if n, err := conn.Read(trailing[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("native peer did not finish its write side: %d, %v", n, err)
	}
	return nil
}

func windowsWildcardListener(t *testing.T, port uint16) (*Listener, *admissionFixture, chan error) {
	t.Helper()
	a := newAdmissionFixture()
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	ctx = adapter.ContextWithRuntimeResourceSource(ctx, sourceFixture{a})
	ctx = ContextWithRuntimeBinding(ctx, RuntimeBinding{Admission: a})
	address := badoption.Addr(netip.IPv6Unspecified())
	done := make(chan error, 2)
	l := New(Options{
		Context: ctx, Logger: logger, Network: []string{N.NetworkTCP},
		Listen: option.ListenOptions{Listen: &address, ListenPort: port}, ConnectionHandler: windowsWildcardHandler{done, a},
	})
	t.Cleanup(func() {
		if err := l.RuntimeCloseAndWait(); err != nil {
			t.Error(err)
		}
		if err := scope.Close(); err != nil {
			t.Error(err)
		}
	})
	return l, a, done
}

type windowsNativeTCP struct {
	network                  string
	address                  netip.Addr
	port                     int
	v6only, reuse, exclusive int
}

func windowsWildcardReadback(t *testing.T, socket net.Listener) windowsNativeTCP {
	t.Helper()
	tcp, ok := socket.(*net.TCPListener)
	if !ok {
		t.Fatalf("native listener is %T, want *net.TCPListener", socket)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got windowsNativeTCP
	err = control.Raw(raw, func(fd uintptr) error {
		handle := windows.Handle(fd)
		address, err := windows.Getsockname(handle)
		if err != nil {
			return err
		}
		switch local := address.(type) {
		case *windows.SockaddrInet4:
			got.network, got.address, got.port = "tcp4", netip.AddrFrom4(local.Addr), local.Port
		case *windows.SockaddrInet6:
			if local.ZoneId != 0 {
				return fmt.Errorf("unexpected native IPv6 zone %d", local.ZoneId)
			}
			got.network, got.address, got.port = "tcp6", netip.AddrFrom16(local.Addr), local.Port
			got.v6only, err = windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("native wildcard has unexpected socket family %T", address)
		}
		got.reuse, err = windows.GetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR)
		if err != nil {
			return err
		}
		got.exclusive, err = windows.GetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual native %s local=%s V6ONLY=%d REUSEADDR=%d EXCLUSIVEADDRUSE=%d", got.network,
		net.JoinHostPort(got.address.String(), fmt.Sprint(got.port)), got.v6only, got.reuse, got.exclusive)
	return got
}

func windowsWildcardPair(t *testing.T, l *Listener, wantPort int) (map[string]*runtimeTCPMember, int) {
	t.Helper()
	members := l.runtimeTCPMembers()
	if len(members) != 2 {
		t.Fatalf("runtime wildcard owns %d native members, want exactly 2", len(members))
	}
	if l.tcpListener != nil || l.TCPListener() != nil {
		t.Fatal("runtime wildcard leaked a legacy raw descriptor alias")
	}
	if raw, err := l.ListenTCP(); raw != nil || !errors.Is(err, ErrRuntimeRawTransport) {
		t.Fatal("runtime wildcard raw listen bypassed staged admission", raw, err)
	}
	byFamily := make(map[string]*runtimeTCPMember, 2)
	port := wantPort
	for _, member := range members {
		got := windowsWildcardReadback(t, member.socket)
		if got.port == 0 || port != 0 && got.port != port {
			t.Fatalf("native members do not share the selected nonzero port: got %d want %d", got.port, port)
		}
		port = got.port
		switch got.network {
		case "tcp4":
			if got.address != netip.IPv4Unspecified() || got.reuse != 0 || got.exclusive != 0 {
				t.Fatal("actual IPv4 member lost ordinary wildcard custody", got)
			}
		case "tcp6":
			if got.address != netip.IPv6Unspecified() || got.v6only != 1 || got.reuse != 0 || got.exclusive != 1 {
				t.Fatal("actual IPv6 member lost narrow exclusive IPv6-only custody", got)
			}
		default:
			t.Fatal("unexpected actual TCP family", got)
		}
		if byFamily[got.network] != nil {
			t.Fatal("duplicate actual TCP family", got.network)
		}
		if member.spec.network != got.network || member.spec.address != got.address || int(member.spec.port) != got.port {
			t.Fatal("runtime member spec differs from its actual native tuple", member.spec, got)
		}
		byFamily[got.network] = member
	}
	if byFamily["tcp4"] == nil || byFamily["tcp6"] == nil || byFamily["tcp4"] == byFamily["tcp6"] {
		t.Fatal("wildcard is not two distinct native family members")
	}
	return byFamily, port
}

func windowsWildcardExchange(network, address string) (err error) {
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if n, writeErr := conn.Write(windowsWildcardBytes[:]); writeErr != nil {
		return writeErr
	} else if n != len(windowsWildcardBytes) {
		return io.ErrShortWrite
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	var reply [3]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != windowsWildcardBytes {
		return fmt.Errorf("wrong wildcard receiver reply: %x", reply)
	}
	var trailing [1]byte
	if n, readErr := conn.Read(trailing[:]); n != 0 || readErr != io.EOF {
		return fmt.Errorf("native receiver did not close after peer EOF: %d, %v", n, readErr)
	}
	return nil
}

func windowsWildcardJoin(t *testing.T, done <-chan error, exchangeErr error) {
	t.Helper()
	select {
	case handled := <-done:
		if exchangeErr != nil || handled != nil {
			t.Fatal("native wildcard byte exchange", exchangeErr, handled)
		}
	case <-time.After(time.Second):
		t.Fatal("native wildcard handler did not join", exchangeErr)
	}
}

func windowsWildcardClosed(t *testing.T, socket net.Listener) {
	t.Helper()
	raw, err := socket.(*net.TCPListener).SyscallConn()
	entered := false
	if err == nil {
		err = raw.Control(func(uintptr) { entered = true })
	}
	if entered || !errors.Is(err, net.ErrClosed) {
		t.Fatal("joined runtime close retained a usable native descriptor", entered, err)
	}
}

func TestRuntimeWindowsWildcardHasNativeDualFamilyBytesAndJoinedClose(t *testing.T) {
	l, a, done := windowsWildcardListener(t, 0)
	if err := l.Prepare(); err != nil {
		t.Fatal(err)
	}
	members, port := windowsWildcardPair(t, l, 0)
	sockets := [2]net.Listener{members["tcp4"].socket, members["tcp6"].socket}
	gateway := l.runtime.gateway
	source, ok := adapter.RuntimeResourceSourceFromContext(l.ctx)
	if !ok || source.ID() != a.id || gateway.admission != a || gateway.source != source {
		t.Fatal("native family members do not share the original logical admission/resource source")
	}
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		err := windowsWildcardExchange(peer.network, net.JoinHostPort(peer.host, fmt.Sprint(port)))
		windowsWildcardJoin(t, done, err)
		if l.runtime.gateway != gateway || a.sourceCalls.Load() != 0 {
			t.Fatal("native family bypassed the single logical admission/resource")
		}
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	status := l.RuntimeStatus()
	if status.Phase != "closed" || status.CloseError != nil || status.IngressError != nil {
		t.Fatal("native wildcard close did not join both ingress workers", status)
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal("repeated joined close changed its first result", err)
	}
	for _, socket := range sockets {
		windowsWildcardClosed(t, socket)
	}
	for _, peer := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		conn, err := net.DialTimeout(peer.network, net.JoinHostPort(peer.host, fmt.Sprint(port)), time.Second)
		if err == nil {
			closeErr := conn.Close()
			t.Fatal("closed native family still admitted a fresh connection", peer.network, closeErr)
		}
		var dialError *net.OpError
		if !errors.As(err, &dialError) || dialError.Op != "dial" {
			t.Fatal("closed native family did not reject its actual dial", peer.network, err)
		}
	}
	// Accepted transport lifetime does not prove the exclusive tuple immediately
	// reusable. Reclaim is asserted separately below, with no accepted carriers.
}

func windowsWildcardHolder(t *testing.T, network, host string, port, exclusive int) net.Listener {
	t.Helper()
	config := net.ListenConfig{Control: func(actualNetwork, _ string, raw syscall.RawConn) error {
		if actualNetwork != network {
			return fmt.Errorf("holder received network %q, want %q", actualNetwork, network)
		}
		return control.Raw(raw, func(fd uintptr) error {
			handle := windows.Handle(fd)
			if network == "tcp6" {
				if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
					return err
				}
			}
			if exclusive == 1 {
				return windows.SetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR), 1)
			}
			return nil
		})
	}}
	holder, err := config.Listen(context.Background(), network, net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := holder.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	got := windowsWildcardReadback(t, holder)
	if got.network != network || got.address != netip.MustParseAddr(host) || got.port == 0 ||
		port != 0 && got.port != port || got.reuse != 0 || got.exclusive != exclusive || network == "tcp6" && got.v6only != 1 {
		t.Fatal("actual native holder differs from requested family/tuple/policy", got)
	}
	return holder
}

func windowsWildcardBindFailure(t *testing.T, candidate *Listener, network string, port int) {
	t.Helper()
	err := candidate.Prepare()
	var listenError *net.OpError
	if !errors.As(err, &listenError) || listenError.Op != "listen" || listenError.Net != network {
		t.Fatal("occupied tuple did not reach actual candidate family bind failure", network, err)
	}
	address, ok := listenError.Addr.(*net.TCPAddr)
	if !ok || address.Port != port || !address.IP.IsUnspecified() || (address.IP.To4() != nil) != (network == "tcp4") {
		t.Fatal("candidate bind failed on a different actual family/tuple", listenError)
	}
	if candidate.RuntimeStatus().Phase != "closed" || candidate.RuntimeStatus().CloseError != nil {
		t.Fatal("rejected candidate did not join its owned close", candidate.RuntimeStatus())
	}
}

func TestRuntimeWindowsWildcardRejectsOccupiedIPv6AndReclaimsAfterClose(t *testing.T) {
	holder := windowsWildcardHolder(t, "tcp6", "::", 0, 1)
	port := holder.Addr().(*net.TCPAddr).Port
	candidate, _, _ := windowsWildcardListener(t, uint16(port))
	windowsWildcardBindFailure(t, candidate, "tcp6", port)
	// The first IPv6 bind failed. Its disjoint IPv4 tuple must not be leaked.
	free4 := windowsWildcardHolder(t, "tcp4", "0.0.0.0", port, 1)
	if err := free4.Close(); err != nil {
		t.Fatal(err)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	// This holder has never accepted, so exact-pair reclaim tests listen custody
	// without claiming accepted TCP kernel state has become inactive.
	reclaimed, _, _ := windowsWildcardListener(t, uint16(port))
	if err := reclaimed.Prepare(); err != nil {
		t.Fatal("retired holder left its actual tuple reserved", err)
	}
	members, _ := windowsWildcardPair(t, reclaimed, port)
	sockets := [2]net.Listener{members["tcp4"].socket, members["tcp6"].socket}
	if err := reclaimed.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	for _, socket := range sockets {
		windowsWildcardClosed(t, socket)
	}
}

func windowsWildcardHolderExchange(t *testing.T, holder net.Listener) {
	t.Helper()
	if err := holder.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := holder.Accept()
		if err == nil {
			err = errors.Join(windowsWildcardEcho(conn), conn.Close())
		}
		done <- err
	}()
	host := holder.Addr().(*net.TCPAddr)
	err := windowsWildcardExchange("tcp6", net.JoinHostPort("::1", fmt.Sprint(host.Port)))
	windowsWildcardJoin(t, done, err)
}

func TestRuntimeWindowsWildcardRejectsSpecificIPv6HolderAndPreservesByteReceiver(t *testing.T) {
	for _, test := range []struct {
		name      string
		exclusive int
	}{{"ordinary", 0}, {"exclusive", 1}} {
		t.Run(test.name, func(t *testing.T) {
			holder := windowsWildcardHolder(t, "tcp6", "::1", 0, test.exclusive)
			port := holder.Addr().(*net.TCPAddr).Port
			windowsWildcardHolderExchange(t, holder)
			candidate, _, _ := windowsWildcardListener(t, uint16(port))
			windowsWildcardBindFailure(t, candidate, "tcp6", port)
			windowsWildcardHolderExchange(t, holder)
			got := windowsWildcardReadback(t, holder)
			if got.address != netip.IPv6Loopback() || got.port != port || got.v6only != 1 || got.reuse != 0 || got.exclusive != test.exclusive {
				t.Fatal("failed candidate changed original specific IPv6 holder", got)
			}
		})
	}
}

func TestRuntimeWindowsWildcardSecondBindFailureReleasesFirstNativeMember(t *testing.T) {
	holder := windowsWildcardHolder(t, "tcp4", "0.0.0.0", 0, 1)
	port := holder.Addr().(*net.TCPAddr).Port
	candidate, _, _ := windowsWildcardListener(t, uint16(port))
	// Runtime wildcard preparation binds IPv6 first and retains it before the
	// ordinary IPv4 bind. This actual second-family collision must close it.
	windowsWildcardBindFailure(t, candidate, "tcp4", port)
	reclaimed6 := windowsWildcardHolder(t, "tcp6", "::", port, 1)
	if err := reclaimed6.Close(); err != nil {
		t.Fatal("failed candidate left its first native IPv6 member reserved", err)
	}
	got := windowsWildcardReadback(t, holder)
	if got.network != "tcp4" || got.address != netip.IPv4Unspecified() || got.port != port || got.reuse != 0 || got.exclusive != 1 {
		t.Fatal("partial candidate cleanup changed the original IPv4 holder", got)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	reclaimed, _, _ := windowsWildcardListener(t, uint16(port))
	if err := reclaimed.Prepare(); err != nil {
		t.Fatal("failed candidate left a native family tuple reserved", err)
	}
	windowsWildcardPair(t, reclaimed, port)
	if err := reclaimed.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
