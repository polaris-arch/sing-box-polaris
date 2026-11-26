package openconnect

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

type materialResourceDirectoryManager struct{ filemanager.Manager }

func (m materialResourceDirectoryManager) ConfigurationDirectoryPath(path string) string {
	return m.BasePath(path)
}

func TestMaterialSourcePreservesEmptyAndUsesWindowsResourceBase(t *testing.T) {
	directory := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), directory, "", 0, 0)
	if material, err := materialSource(ctx, "tls.client_certificate", nil, "client.pem"); err != nil || material.Path != "client.pem" {
		t.Fatalf("ordinary file manager changed material: %+v, %v", material, err)
	}
	ctx = service.ContextWith[filemanager.Manager](ctx, materialResourceDirectoryManager{service.FromContext[filemanager.Manager](ctx)})
	for _, path := range []string{"", "client.pem"} {
		material, err := materialSource(ctx, "tls.client_certificate", nil, path)
		if err != nil {
			t.Fatal(err)
		}
		expected := path
		if runtime.GOOS == "windows" && path != "" {
			expected = filepath.Join(directory, path)
		}
		if material.Path != expected {
			t.Fatalf("material path = %q; want %q", material.Path, expected)
		}
	}
	if _, err := materialSource(ctx, "tls.client_certificate", []string{"inline"}, "client.pem"); err == nil {
		t.Fatal("inline material and a path must still conflict")
	}
}

func fixtureRuntimeClient() *runtimeClientState {
	ctx, cancel := context.WithCancel(context.Background())
	return &runtimeClientState{ctx: ctx, cancel: cancel, scope: adapter.NewScope(ctx, log.NewNOPFactory().Logger()), callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), closeDone: make(chan struct{})}
}

func TestRuntimeClientPublicationRequiresCompletedStage(t *testing.T) {
	r := fixtureRuntimeClient()
	defer r.close()
	e := &Endpoint{runtime: r}
	if _, err := e.RuntimePreparePublication(); err == nil {
		t.Fatal("unprepared client admitted")
	}
	r.stageDone = make(chan struct{})
	r.staged = true
	close(r.stageDone)
	publish, err := e.RuntimePreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	if r.gate.Load() || r.ingress.Load() {
		t.Fatal("prepare published")
	}
	publish()
	if !r.gate.Load() || !r.ingress.Load() {
		t.Fatal("publication missing")
	}
	e.RuntimeStop()
	if r.ingress.Load() || !r.gate.Load() {
		t.Fatal("retirement stopped retained flows")
	}
}

func TestRuntimeClientJoinsCallbacksBeforeDeviceCleanup(t *testing.T) {
	r := fixtureRuntimeClient()
	leave, err := r.callbacks.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	nativeClosed := make(chan struct{})
	r.nativeClose = func() error { close(nativeClosed); return nil }
	deviceClosed := make(chan struct{})
	r.scope.Add(func() error { close(deviceClosed); return nil })
	done := make(chan struct{})
	go func() { defer close(done); _ = r.close() }()
	select {
	case <-nativeClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("native stop not requested")
	}
	select {
	case <-deviceClosed:
		t.Fatal("device destroyed while callback admitted")
	default:
	}
	leave()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback completion not joined")
	}
	select {
	case <-deviceClosed:
	default:
		t.Fatal("device cleanup missing")
	}
}

func TestRuntimeClientLateNativeConstructorCompensates(t *testing.T) {
	r := fixtureRuntimeClient()
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	failure := errors.New("native close failed")
	err := r.installNative(func() error { calls++; return failure })
	if calls != 1 || !tls.IsRuntimeCleanupIncomplete(err) {
		t.Fatal("late constructor lost cleanup uncertainty")
	}
}

func TestRuntimeClientNativeCloseErrorIsSticky(t *testing.T) {
	r := fixtureRuntimeClient()
	calls := 0
	r.nativeClose = func() error { calls++; return errors.New("native close failed") }
	first := r.close()
	second := r.close()
	if !tls.IsRuntimeCleanupIncomplete(first) || second != first || calls != 1 {
		t.Fatal("native cleanup result changed")
	}
}

type blockedRuntimeClientConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	err     error
}

func (c *blockedRuntimeClientConn) Close() error {
	close(c.started)
	<-c.release
	return errors.Join(c.Conn.Close(), c.err)
}

func TestRuntimeClientJoinsPendingTLSCarrierClose(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "successful carrier close"},
		{name: "failed carrier close", err: errors.New("physical close failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureRuntimeClient()
			conn, peer := net.Pipe()
			defer peer.Close()
			raw := &blockedRuntimeClientConn{Conn: conn, started: make(chan struct{}), release: make(chan struct{}), err: tt.err}
			wrapped, fence := outbound.WrapRuntimeOwnedConn(raw)
			creation, err := r.carriers.Begin()
			if err != nil {
				t.Fatal(err)
			}
			err = creation.Register(fence)
			creation.Done()
			if err != nil {
				t.Fatal(err)
			}
			release := sync.OnceFunc(func() { close(raw.release) })
			defer release()
			nativeResult := make(chan error, 1)
			r.nativeClose = func() error {
				err := stdtls.Client(&runtimeCSTPConn{wrapped}, &stdtls.Config{}).Close()
				nativeResult <- err
				return err
			}
			done := make(chan error, 1)
			go func() { done <- r.close() }()
			select {
			case <-raw.started:
			case <-time.After(5 * time.Second):
				t.Fatal("carrier close was not requested")
			}
			select {
			case err := <-nativeResult:
				if err != nil {
					t.Errorf("native TLS close rejected the pending request: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("native TLS close blocked on physical completion")
			}
			select {
			case err := <-done:
				t.Fatalf("runtime returned before physical close: %v", err)
			default:
			}
			release()
			select {
			case err := <-done:
				if !errors.Is(err, raw.err) {
					t.Fatalf("runtime close = %v; want %v", err, raw.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runtime did not join physical close")
			}
		})
	}
}

type runtimeClientTestSource struct{}

func (runtimeClientTestSource) ID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "openconnect-test", Sequence: 1}
}

func (s runtimeClientTestSource) Acquire() (adapter.RuntimeResourceLease, error) {
	return runtimeClientTestLease{s.ID()}, nil
}

type runtimeClientTestLease struct{ id adapter.RuntimeResourceID }

func (l runtimeClientTestLease) ID() adapter.RuntimeResourceID               { return l.id }
func (l runtimeClientTestLease) Fork() (adapter.RuntimeResourceLease, error) { return l, nil }
func (runtimeClientTestLease) Retiring() <-chan struct{}                     { return nil }
func (runtimeClientTestLease) Release()                                      {}

type blockedRuntimeClientPacketConn struct {
	*net.UDPConn
	blocked *blockedRuntimeClientConn
}

func (c *blockedRuntimeClientPacketConn) Close() error { return c.blocked.Close() }

type runtimeClientTestDialer struct{ conn net.Conn }

func (d runtimeClientTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (runtimeClientTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestRuntimeClientJoinsPendingDTLSCarrierClose(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "successful carrier close"},
		{name: "failed carrier close", err: errors.New("physical close failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureRuntimeClient()
			r.source = runtimeClientTestSource{}
			r.begin = func(ctx context.Context) (context.Context, func(), error) { return ctx, func() {}, nil }
			peer, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			blocked := &blockedRuntimeClientConn{Conn: conn, started: make(chan struct{}), release: make(chan struct{}), err: tt.err}
			raw := &blockedRuntimeClientPacketConn{UDPConn: conn, blocked: blocked}
			lease, _ := r.source.Acquire()
			ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
			udpConn, err := r.wrapDialer(runtimeClientTestDialer{raw}).DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(peer.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := udpConn.(net.PacketConn); !ok {
				t.Fatalf("UDP carrier %T lost the net.PacketConn method set", udpConn)
			}
			release := sync.OnceFunc(func() { close(blocked.release) })
			defer release()
			nativeResult := make(chan error, 1)
			r.nativeClose = func() error {
				// sing-openconnect anyConnectDTLSChannel.terminate.
				var err error
				if closeErr := udpConn.Close(); closeErr != nil && !E.IsClosed(closeErr) {
					err = E.Cause(closeErr, "close DTLS connection")
				}
				nativeResult <- err
				return err
			}
			done := make(chan error, 1)
			go func() { done <- r.close() }()
			select {
			case <-blocked.started:
			case <-time.After(5 * time.Second):
				t.Fatal("carrier close was not requested")
			}
			select {
			case err := <-nativeResult:
				if err != nil {
					t.Errorf("native DTLS close rejected the pending request: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("native DTLS close blocked on physical completion")
			}
			select {
			case err := <-done:
				t.Fatalf("runtime returned before physical close: %v", err)
			default:
			}
			release()
			select {
			case err := <-done:
				if !errors.Is(err, blocked.err) {
					t.Fatalf("runtime close = %v; want %v", err, blocked.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runtime did not join physical close")
			}
		})
	}
}
