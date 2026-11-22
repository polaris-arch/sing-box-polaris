package masque

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/device"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	transportMASQUE "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func fixtureRuntimeClient() *runtimeClientState {
	ctx, cancel := context.WithCancel(context.Background())
	return &runtimeClientState{ctx: ctx, cancel: cancel, scope: adapter.NewScope(ctx, log.NewNOPFactory().Logger()), callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), closeDone: make(chan struct{})}
}

func TestRuntimeClientPublicationRequiresCompletedStage(t *testing.T) {
	r := fixtureRuntimeClient()
	defer r.close()
	e := &ClientEndpoint{runtime: r}
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

func TestCleanupDiagnosticMasquePhaseAndPanic(t *testing.T) {
	r := fixtureRuntimeClient()
	e := &ClientEndpoint{runtime: r}
	if phase, failed := e.RuntimeCleanupObservation(); phase != 0 || failed {
		t.Fatal(phase, failed)
	}
	r.nativeClose = func() error { panic("private native value") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("diagnostic swallowed native panic")
			}
		}()
		_ = r.close()
	}()
	phase, failed := e.RuntimeCleanupObservation()
	if phase != 3 || !failed {
		t.Fatal("panic must retain native stage and failure, not done", phase, failed)
	}
}

type masqueProbeDevice struct{ device.Device }

func (masqueProbeDevice) Start() error                                   { return nil }
func (masqueProbeDevice) UpdateConfiguration(device.Configuration) error { return nil }
func (masqueProbeDevice) FrontHeadroom() int                             { return 0 }

func (masqueProbeDevice) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (masqueProbeDevice) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

type masqueProbeDialer struct {
	N.Dialer
	dials chan masqueProbePhysicalDial
}

type masqueProbePhysicalDial struct {
	ctx    context.Context
	result chan masqueProbeDialResult
}

type masqueProbeDialResult struct {
	conn net.Conn
	err  error
}

func (d masqueProbeDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	dial := masqueProbePhysicalDial{ctx: ctx, result: make(chan masqueProbeDialResult, 1)}
	d.dials <- dial
	select {
	case result := <-dial.result:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func fixtureMasqueProbeEndpoint(t *testing.T) (*ClientEndpoint, <-chan masqueProbePhysicalDial) {
	t.Helper()
	ctx := pause.WithDefaultManager(t.Context())
	dialer := masqueProbeDialer{dials: make(chan masqueProbePhysicalDial, 8)}
	httpClient, err := transportHTTP.NewClient(transportHTTP.ClientOptions{Dialer: dialer, Version: 1, Server: M.ParseSocksaddr("192.0.2.1:80")})
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().Logger()
	endpoint := &ClientEndpoint{endpointBase: endpointBase{logger: logger}, ctx: ctx, device: masqueProbeDevice{}, onDemand: true, scopedProbes: true}
	endpoint.state.Store(&clientState{})
	endpoint.client, err = transportMASQUE.NewClient(transportMASQUE.ClientOptions{
		Context: ctx, Logger: logger, HTTPClient: httpClient, Handler: endpoint, StartSuspended: true, ScopedProbes: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint.client.Start()
	t.Cleanup(func() { _ = endpoint.client.Close() })
	return endpoint, dialer.dials
}

func masqueProbeReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case received := <-ch:
		return received
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MASQUE probe")
		var zero T
		return zero
	}
}

func masqueProbeServeTunnel(t *testing.T, dial masqueProbePhysicalDial) <-chan struct{} {
	t.Helper()
	conn, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		reader := bufio.NewReader(server)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}
		if _, err := io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n\r\n"); err != nil {
			return
		}
		if _, _, err := transportHTTP.ReadVarint(reader); err != nil {
			return
		}
		length, _, err := transportHTTP.ReadVarint(reader)
		if err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return
		}
		// ADDRESS_ASSIGN for request 1, IPv4 192.0.2.2/32.
		if _, err := server.Write([]byte{1, 7, 1, 4, 192, 0, 2, 2, 32}); err == nil {
			_, _ = io.Copy(io.Discard, reader)
		}
	}()
	dial.result <- masqueProbeDialResult{conn: conn}
	return done
}

func TestMasqueProbeActivationFollowsCarriersAndDevicePause(t *testing.T) {
	endpoint, dials := fixtureMasqueProbeEndpoint(t)
	ctx := urltest.ContextWithBackgroundProbe(t.Context())
	destination := M.ParseSocksaddr("192.0.2.9:80")
	start := func() <-chan masqueProbeDialResult {
		result := make(chan masqueProbeDialResult, 1)
		go func() {
			conn, err := endpoint.DialContext(ctx, N.NetworkTCP, destination)
			result <- masqueProbeDialResult{conn: conn, err: err}
		}()
		return result
	}
	first := start()
	dial := masqueProbeReceive(t, dials)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := endpoint.DialContext(canceled, N.NetworkTCP, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled ordinary dial = %v", err)
	}
	if err := endpoint.writePacketBuffers(nil); err != nil {
		t.Fatal(err)
	}
	if !urltest.IsBackgroundProbe(dial.ctx) {
		t.Fatal("cold probe or device writer consumed foreground admission")
	}
	tunnelDone := masqueProbeServeTunnel(t, dial)
	tcp := masqueProbeReceive(t, first)
	if tcp.err != nil {
		t.Fatal(tcp.err)
	}
	defer tcp.conn.Close()
	packet, err := endpoint.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := tcp.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !endpoint.client.Ready() {
		t.Fatal("closing TCP released a tunnel still held by UDP")
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	masqueProbeReceive(t, tunnelDone)
	if err := endpoint.writePacketBuffers(nil); err != nil {
		t.Fatal(err)
	}
	second := start()
	dial = masqueProbeReceive(t, dials)
	if !urltest.IsBackgroundProbe(dial.ctx) {
		t.Fatal("a device writer revived durable foreground demand after probe teardown")
	}
	manager := service.FromContext[pause.Manager](endpoint.ctx)
	manager.DevicePause()
	if err := masqueProbeReceive(t, second).err; !errors.Is(err, urltest.ErrProbeNotRun) {
		t.Fatalf("paused scoped dial = %v", err)
	}
	if _, err := endpoint.DialContext(ctx, N.NetworkTCP, destination); !errors.Is(err, urltest.ErrProbeNotRun) {
		t.Fatalf("scoped dial started during pause, err = %v", err)
	}
	manager.DeviceWake()
	probeResult := make(chan error, 1)
	go func() {
		_, err := urltest.URLTest(ctx, "http://192.0.2.9/generate_204", endpoint)
		probeResult <- err
	}()
	masqueProbeReceive(t, dials).result <- masqueProbeDialResult{err: adapter.ErrOutboundForegroundSlot}
	if err := masqueProbeReceive(t, probeResult); !errors.Is(err, urltest.ErrProbeNotRun) || !errors.Is(err, adapter.ErrOutboundForegroundSlot) {
		t.Fatalf("local refusal did not preserve measurement history, err = %v", err)
	}
}

type masqueProbeWaitingContext struct {
	context.Context
	waiting chan struct{}
}

func (ctx masqueProbeWaitingContext) Done() <-chan struct{} {
	select {
	case ctx.waiting <- struct{}{}:
	default:
	}
	return ctx.Context.Done()
}

func TestMasqueProbeLateForegroundAndReferenceKeep(t *testing.T) {
	for _, mode := range []string{"carrier scoped", "ordinary", "referenced"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, dials := fixtureMasqueProbeEndpoint(t)
			destination := M.ParseSocksaddr("192.0.2.9:80")
			start := func(ctx context.Context) <-chan masqueProbeDialResult {
				result := make(chan masqueProbeDialResult, 1)
				go func() {
					conn, err := endpoint.DialContext(ctx, N.NetworkTCP, destination)
					result <- masqueProbeDialResult{conn: conn, err: err}
				}()
				return result
			}
			background := start(urltest.ContextWithBackgroundProbe(t.Context()))
			first := masqueProbeReceive(t, dials)
			if !urltest.IsBackgroundProbe(first.ctx) {
				t.Fatal("initial dial was not background")
			}
			var foreground <-chan masqueProbeDialResult
			if mode == "referenced" {
				endpoint.SetKeepIdleConnections(true)
			} else {
				waiter := masqueProbeWaitingContext{Context: t.Context(), waiting: make(chan struct{}, 1)}
				var ctx context.Context = waiter
				if mode == "carrier scoped" {
					ctx = urltest.ContextWithSharedBackgroundProbe(waiter, nil)
				}
				foreground = start(ctx)
				masqueProbeReceive(t, waiter.waiting)
			}
			first.result <- masqueProbeDialResult{err: errors.Join(adapter.ErrOutboundForegroundSlot, adapter.ErrOutboundForegroundSlot)}
			second := masqueProbeReceive(t, dials)
			if urltest.IsBackgroundProbe(second.ctx) {
				t.Fatal("retry did not admit the real foreground demand")
			}
			tunnelDone := masqueProbeServeTunnel(t, second)
			bg := masqueProbeReceive(t, background)
			if bg.err != nil {
				t.Fatal(bg.err)
			}
			if err := bg.conn.Close(); err != nil {
				t.Fatal(err)
			}
			if !endpoint.client.Ready() {
				t.Fatal("background release retired a foreground-held tunnel")
			}
			if foreground != nil {
				fg := masqueProbeReceive(t, foreground)
				if fg.err != nil {
					t.Fatal(fg.err)
				}
				if err := fg.conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "carrier scoped" {
				if !endpoint.client.Ready() {
					t.Fatal("durable foreground demand was released with a probe carrier")
				}
				endpoint.SetKeepIdleConnections(false)
			}
			masqueProbeReceive(t, tunnelDone)
		})
	}
}

func TestMasqueProbeRestartCancelsPendingDial(t *testing.T) {
	endpoint, dials := fixtureMasqueProbeEndpoint(t)
	ctx := urltest.ContextWithBackgroundProbe(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := endpoint.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("192.0.2.9:80"))
		result <- err
	}()
	first := masqueProbeReceive(t, dials)
	endpoint.client.RestartSession()
	if err := first.ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("reset returned with the old dial still active, err = %v", err)
	}
	second := masqueProbeReceive(t, dials)
	if !urltest.IsBackgroundProbe(second.ctx) {
		t.Fatal("an existing probe gained foreground admission on reset")
	}
	realFailure := errors.New("failed to reach server")
	mixed := errors.Join(realFailure, adapter.ErrOutboundForegroundSlot)
	second.result <- masqueProbeDialResult{err: mixed}
	if err := masqueProbeReceive(t, result); !errors.Is(err, realFailure) || errors.Is(err, urltest.ErrProbeNotRun) {
		t.Fatalf("real network error changed after reset, err = %v", err)
	}
}

type masqueBlockedSetupConn struct {
	net.Conn
	writing    chan struct{}
	closing    chan struct{}
	allowClose chan struct{}
	writeOnce  sync.Once
}

func (c *masqueBlockedSetupConn) Write(payload []byte) (int, error) {
	if len(payload) != 0 && payload[0] == 2 { // ADDRESS_REQUEST
		c.writeOnce.Do(func() { close(c.writing) })
	}
	return c.Conn.Write(payload)
}

func (c *masqueBlockedSetupConn) Close() error {
	err := c.Conn.Close()
	close(c.closing)
	<-c.allowClose
	return err
}

func TestMasqueProbePauseJoinsBlockedSessionSetup(t *testing.T) {
	endpoint, dials := fixtureMasqueProbeEndpoint(t)
	start := func(ctx context.Context) <-chan error {
		result := make(chan error, 1)
		go func() {
			_, err := endpoint.DialContext(urltest.ContextWithBackgroundProbe(ctx), N.NetworkTCP, M.ParseSocksaddr("192.0.2.9:80"))
			result <- err
		}()
		return result
	}
	first := start(t.Context())
	dial := masqueProbeReceive(t, dials)
	conn, server := net.Pipe()
	blocked := &masqueBlockedSetupConn{Conn: conn, writing: make(chan struct{}), closing: make(chan struct{}), allowClose: make(chan struct{})}
	releaseClose := sync.OnceFunc(func() { close(blocked.allowClose) })
	t.Cleanup(releaseClose)
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
			_, _ = io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n\r\n")
		}
		// This peer never reads the initial capsule, so only Close can unblock it.
	}()
	dial.result <- masqueProbeDialResult{conn: blocked}
	masqueProbeReceive(t, blocked.writing)
	manager := service.FromContext[pause.Manager](endpoint.ctx)
	manager.DevicePause()
	masqueProbeReceive(t, blocked.closing)
	if err := masqueProbeReceive(t, first); !errors.Is(err, urltest.ErrProbeNotRun) {
		t.Fatalf("paused setup error = %v", err)
	}
	manager.DeviceWake()
	waiter := masqueProbeWaitingContext{Context: t.Context(), waiting: make(chan struct{}, 1)}
	second := start(waiter)
	masqueProbeReceive(t, waiter.waiting)
	select {
	case <-dials:
		t.Fatal("a successor dial raced the unfinished setup close")
	default:
	}
	releaseClose()
	masqueProbeReceive(t, dials).result <- masqueProbeDialResult{err: adapter.ErrOutboundForegroundSlot}
	if err := masqueProbeReceive(t, second); !adapter.IsOutboundForegroundSlot(err) {
		t.Fatalf("successor after setup close = %v", err)
	}
}
