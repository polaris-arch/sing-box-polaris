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

type windowsWildcardHandler struct{ done chan error }

func (h windowsWildcardHandler) NewConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	var err error
	defer func() { h.done <- errors.Join(err, conn.Close()) }()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	var received [3]byte
	if _, err = io.ReadFull(conn, received[:]); err != nil {
		return
	}
	if received != windowsWildcardBytes {
		err = fmt.Errorf("wrong native wildcard bytes: %x", received)
		return
	}
	var n int
	n, err = conn.Write(received[:])
	if err == nil && n != len(received) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return
	}
	var trailing [1]byte
	if n, readErr := conn.Read(trailing[:]); n != 0 || readErr != io.EOF {
		err = fmt.Errorf("native peer did not finish its write side: %d, %v", n, readErr)
	}
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
	l := New(Options{Context: ctx, Logger: logger, Network: []string{N.NetworkTCP},
		Listen: option.ListenOptions{Listen: &address, ListenPort: port}, ConnectionHandler: windowsWildcardHandler{done}})
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

func windowsWildcardReadback(t *testing.T, socket net.Listener, wantV6Only, wantPort int) {
	t.Helper()
	raw, err := socket.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = control.Raw(raw, func(fd uintptr) error {
		handle := windows.Handle(fd)
		address, err := windows.Getsockname(handle)
		if err != nil {
			return err
		}
		local, ok := address.(*windows.SockaddrInet6)
		if !ok || local.Addr != [16]byte{} || local.ZoneId != 0 || local.Port != wantPort {
			return fmt.Errorf("wrong actual native wildcard tuple: %+v", address)
		}
		v6only, err := windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		if err != nil {
			return err
		}
		reuse, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR)
		if err != nil {
			return err
		}
		exclusive, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR))
		if err != nil {
			return err
		}
		t.Logf("native wildcard AF_INET6 local=[::]:%d V6ONLY=%d REUSEADDR=%d EXCLUSIVEADDRUSE=%d", local.Port, v6only, reuse, exclusive)
		if v6only != wantV6Only || wantV6Only == 1 && exclusive == 0 {
			return errors.New("actual wildcard socket options differ from requested custody")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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

func TestRuntimeWindowsWildcardHasNativeDualFamilyBytesAndJoinedClose(t *testing.T) {
	l, _, done := windowsWildcardListener(t, 0)
	if err := l.Prepare(); err != nil {
		t.Fatal(err)
	}
	port := l.tcpListener.Addr().(*net.TCPAddr).Port
	windowsWildcardReadback(t, l.tcpListener, 0, port)
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		err := windowsWildcardExchange(peer.network, net.JoinHostPort(peer.host, fmt.Sprint(port)))
		// Always join the finite real handler before inspecting either result.
		var handled error
		select {
		case handled = <-done:
		case <-time.After(time.Second):
			t.Fatal("native wildcard handler did not join", err)
		}
		if err != nil || handled != nil {
			t.Fatal("native wildcard byte exchange", peer.network, err, handled)
		}
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if l.RuntimeStatus().Phase != "closed" {
		t.Fatal("native wildcard close did not join ingress")
	}
	reclaimed, err := net.Listen("tcp6", net.JoinHostPort("::", fmt.Sprint(port)))
	if err != nil {
		t.Fatal("joined close did not release original IPv6 tuple", err)
	}
	if err := reclaimed.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeWindowsWildcardRejectsOccupiedIPv6AndReclaimsAfterClose(t *testing.T) {
	config := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error {
		if network != "tcp6" {
			return fmt.Errorf("holder received network %q", network)
		}
		return control.Raw(raw, func(fd uintptr) error {
			handle := windows.Handle(fd)
			if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
				return err
			}
			return windows.SetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR), 1)
		})
	}}
	holder, err := config.Listen(context.Background(), "tcp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	holderClosed := false
	t.Cleanup(func() {
		if !holderClosed {
			if err := holder.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	port := holder.Addr().(*net.TCPAddr).Port
	windowsWildcardReadback(t, holder, 1, port)
	candidate, _, _ := windowsWildcardListener(t, uint16(port))
	err = candidate.Prepare()
	if err == nil {
		windowsWildcardReadback(t, candidate.tcpListener, 0, port)
	}
	var listenError *net.OpError
	if !errors.As(err, &listenError) || listenError.Op != "listen" {
		t.Fatal("occupied IPv6 tuple did not reach actual candidate bind failure", err)
	}
	if candidate.RuntimeStatus().Phase != "closed" || candidate.RuntimeStatus().CloseError != nil {
		t.Fatal("rejected candidate did not join its owned close", candidate.RuntimeStatus())
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	holderClosed = true
	reclaimed, _, _ := windowsWildcardListener(t, uint16(port))
	if err := reclaimed.Prepare(); err != nil {
		t.Fatal("retired holder left its actual tuple reserved", err)
	}
	windowsWildcardReadback(t, reclaimed.tcpListener, 0, port)
	if err := reclaimed.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
