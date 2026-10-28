//go:build with_quic

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/dns/transport"

	mDNS "github.com/miekg/dns"
)

func TestQUICIdleControlPreservesSharedUsers(t *testing.T) {
	var closed atomic.Int32
	pool := transport.NewConnPool(transport.ConnPoolOptions[*httpclient.RuntimeQUICSession]{
		Mode:    transport.ConnPoolSingle,
		IsAlive: func(*httpclient.RuntimeQUICSession) bool { return true },
		Close:   func(*httpclient.RuntimeQUICSession, error) { closed.Add(1) },
	})
	tr := &Transport{connection: pool, fence: outbound.NewRuntimeIOFence(pool.Close)}
	defer tr.RuntimeCloseAndWait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func(context.Context) (*httpclient.RuntimeQUICSession, error) {
		return new(httpclient.RuntimeQUICSession), nil
	}
	first, _, err := pool.Acquire(ctx, dial)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := pool.Acquire(ctx, dial)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected a multiplexed QUIC session")
	}
	tr.CloseIdleConnections()
	tr.SetKeepIdleConnections(false)
	pool.Release(first, true)
	if closed.Load() != 0 {
		t.Fatal("idle control closed a session with a remaining request")
	}
	pool.Release(second, true)
	if closed.Load() != 1 {
		t.Fatal("disabled retention did not close the final released session")
	}
	tr.SetKeepIdleConnections(true)
	next, _, err := pool.Acquire(ctx, dial)
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(next, true)
	if closed.Load() != 1 {
		t.Fatal("re-enabled retention did not retain an idle session")
	}
	tr.CloseIdleConnections()
	if closed.Load() != 2 {
		t.Fatal("explicit idle trim did not close the retained session")
	}
}

type idleHTTP3Engine struct {
	roundTrip func(*http.Request) (*http.Response, error)
	close     func() error
	closes    atomic.Int32
}

func (e *idleHTTP3Engine) RoundTrip(r *http.Request) (*http.Response, error) {
	return e.roundTrip(r)
}

func (e *idleHTTP3Engine) Close() error {
	e.closes.Add(1)
	if e.close != nil {
		return e.close()
	}
	return nil
}

func newIdleHTTP3Transport(engine *idleHTTP3Engine) (*HTTP3Transport, *dnsHTTP3Epoch) {
	epoch := &dnsHTTP3Epoch{
		transport: engine,
		boundary:  httpclient.NewRuntimeTransportBoundary(engine.Close),
	}
	tr := &HTTP3Transport{
		destination: &url.URL{Scheme: "https", Host: "dns.test", Path: "/dns-query"},
		headers:     make(http.Header),
		tlsConfig:   &tls.Config{},
		transport:   epoch,
		transports:  []*dnsHTTP3Epoch{epoch},
		keepIdle:    true,
	}
	tr.fence = outbound.NewRuntimeIOFence(tr.closeOwned)
	return tr, epoch
}

type idleHTTP3Body struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func (b *idleHTTP3Body) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.reader.Read(p)
}

func (b *idleHTTP3Body) Close() error {
	b.closed.Store(true)
	return nil
}

func waitIdleSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestHTTP3IdleControlIncludesResponseBody(t *testing.T) {
	for _, restoreRetention := range []bool{false, true} {
		name := "close_on_final_body"
		if restoreRetention {
			name = "retention_reenabled_while_active"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			message := new(mDNS.Msg)
			message.SetQuestion("example.org.", mDNS.TypeA)
			answer := new(mDNS.Msg)
			answer.SetReply(message)
			wire, err := answer.Pack()
			if err != nil {
				t.Fatal(err)
			}
			body := &idleHTTP3Body{
				reader:  bytes.NewReader(wire),
				entered: make(chan struct{}),
				release: make(chan struct{}),
			}
			var unblockOnce sync.Once
			unblock := func() { unblockOnce.Do(func() { close(body.release) }) }
			defer unblock()
			engine := &idleHTTP3Engine{
				roundTrip: func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(wire)), Body: body}, nil
				},
				close: func() error {
					if !body.closed.Load() {
						return errors.New("HTTP3 session closed before DNS body close")
					}
					return nil
				},
			}
			tr, epoch := newIdleHTTP3Transport(engine)
			result := make(chan error, 1)
			go func() {
				_, err := tr.Exchange(ctx, message)
				result <- err
			}()
			waitIdleSignal(t, ctx, body.entered)
			tr.CloseIdleConnections()
			tr.SetKeepIdleConnections(false)
			if engine.closes.Load() != 0 || tr.transport != epoch {
				t.Fatal("idle trim retired a transport with an active response")
			}
			if restoreRetention {
				tr.SetKeepIdleConnections(true)
			}
			unblock()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !body.closed.Load() {
				t.Fatal("exchange did not close the response body")
			}
			expectedCloses := int32(1)
			if restoreRetention {
				expectedCloses = 0
			}
			if engine.closes.Load() != expectedCloses {
				t.Fatal("final exchange release ignored the current retention policy")
			}
			tr.CloseIdleConnections()
			tr.CloseIdleConnections()
			if engine.closes.Load() != 1 || tr.transport != nil {
				t.Fatal("idle trim was not idempotent and lazy")
			}
			if len(tr.transports) != 0 {
				t.Fatal("successful idle cleanup retained completed epoch resources")
			}
			if err := tr.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTP3IdleWaitsForEveryExchange(t *testing.T) {
	engine := new(idleHTTP3Engine)
	tr, epoch := newIdleHTTP3Transport(engine)
	first, err := tr.acquireTransport()
	if err != nil {
		t.Fatal(err)
	}
	second, err := tr.acquireTransport()
	if err != nil {
		t.Fatal(err)
	}
	tr.SetKeepIdleConnections(false)
	tr.releaseTransport(first)
	if engine.closes.Load() != 0 || tr.transport != epoch {
		t.Fatal("first completed exchange retired a multiplexed active epoch")
	}
	tr.releaseTransport(second)
	if engine.closes.Load() != 1 || tr.transport != nil {
		t.Fatal("final completed exchange did not retire its idle epoch")
	}
	tr.SetKeepIdleConnections(true)
	next, err := tr.acquireTransport()
	if err != nil {
		t.Fatal(err)
	}
	if next == epoch {
		t.Fatal("a new exchange selected a detached epoch")
	}
	tr.releaseTransport(next)
	if err := tr.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	tr.CloseIdleConnections()
	tr.SetKeepIdleConnections(false)
	if _, err := tr.acquireTransport(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("idle control reopened a terminally closed transport")
	}
}

type idleHTTP3LateResource struct {
	entered chan struct{}
	release chan struct{}
}

func (r *idleHTTP3LateResource) RuntimeCloseAndWait() error {
	close(r.entered)
	<-r.release
	return errors.New("late HTTP3 resource cleanup failed")
}

func TestHTTP3IdleTrimJoinsLateDialAndKeepsCleanupError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine := new(idleHTTP3Engine)
	tr, epoch := newIdleHTTP3Transport(engine)
	// Model a canceled request whose detached dependency dial is still live.
	dialCtx, leaveDial, err := epoch.boundary.BeginDial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idleDone := make(chan struct{})
	go func() {
		tr.CloseIdleConnections()
		close(idleDone)
	}()
	waitIdleSignal(t, ctx, dialCtx.Done())
	resource := &idleHTTP3LateResource{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resource.release) }) }
	defer release()
	registerDone := make(chan error, 1)
	go func() {
		defer leaveDial()
		registerDone <- epoch.boundary.RegisterResource(resource)
	}()
	waitIdleSignal(t, ctx, resource.entered)
	select {
	case <-idleDone:
		t.Fatal("idle trim returned while late-result cleanup was still live")
	default:
	}
	// An idle close must detach before joining foreign cleanup. New admission
	// can use another epoch without waiting for, or reusing, the closing one.
	next, err := tr.acquireTransport()
	if err != nil {
		t.Fatal(err)
	}
	if next == epoch {
		t.Fatal("new admission reused the closing epoch")
	}
	tr.releaseTransport(next)
	release()
	waitIdleSignal(t, ctx, idleDone)
	select {
	case err := <-registerDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("late result was not rejected by the retired boundary")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := tr.RuntimeCloseAndWait(); err == nil || !strings.Contains(err.Error(), "late HTTP3 resource cleanup failed") {
		t.Fatalf("lost sticky idle cleanup failure: %v", err)
	}
}

func TestHTTP3FailedExchangeReleasesIdleEpoch(t *testing.T) {
	engine := &idleHTTP3Engine{
		roundTrip: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("HTTP3 exchange failed")
		},
	}
	tr, epoch := newIdleHTTP3Transport(engine)
	// Set the policy while a reservation is active, preserving the fake epoch
	// until Exchange has selected it.
	reservation, err := tr.acquireTransport()
	if err != nil {
		t.Fatal(err)
	}
	tr.SetKeepIdleConnections(false)
	message := new(mDNS.Msg)
	message.SetQuestion("example.org.", mDNS.TypeA)
	if _, err := tr.Exchange(context.Background(), message); err == nil {
		t.Fatal("expected exchange error")
	}
	if epoch.active != 1 || engine.closes.Load() != 0 {
		t.Fatal("failed exchange leaked admission or interrupted another request")
	}
	tr.releaseTransport(reservation)
	if engine.closes.Load() != 1 {
		t.Fatal("failed exchange left an idle epoch retained")
	}
	if err := tr.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
