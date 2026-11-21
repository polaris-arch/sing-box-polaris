package cronet

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

func lifecycleTestClient(state clientState) *NaiveClient {
	c := &NaiveClient{ctx: context.Background(), started: make(chan struct{}), closed: make(chan struct{}), connections: make(map[*BidirectionalConn]struct{})}
	c.state.Store(uint32(state))
	if state == clientStateRunning {
		close(c.started)
	}
	return c
}

func awaitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not finish")
	}
}

func TestNaiveDormantClientControlsAndClose(t *testing.T) {
	c := lifecycleTestClient(clientStateCreated)
	if err := c.StartOnDemand(t.Context()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	if _, err := c.DialEarly(ctx, dest); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled first dial: %v", err)
	}
	c.CloseAllConnections()
	if state := clientState(c.state.Load()); state != clientStateDormant {
		t.Fatalf("cold client state = %v, want dormant", state)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DialEarly(context.Background(), dest); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after cold close: %v", err)
	}
}

func TestNaiveCustomRootsValidateBeforeDormancy(t *testing.T) {
	if err := checkLibrary(); err != nil {
		t.Skipf("Cronet library unavailable: %v", err)
	}
	server := httptest.NewTLSServer(nil)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	server.Close()

	for _, roots := range []struct {
		name    string
		pem     string
		invalid bool
	}{
		{name: "valid", pem: string(cert)},
		{name: "invalid", pem: "invalid certificate", invalid: true},
	} {
		t.Run(roots.name, func(t *testing.T) {
			quotaDenied := errors.New("engine quota denied")
			deny := true
			var reserved, released int
			client, err := NewNaiveClient(NaiveClientOptions{
				Context:                 t.Context(),
				ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", 443),
				TrustedRootCertificates: roots.pem,
				DNSResolver:             func(context.Context, *mDNS.Msg) *mDNS.Msg { return nil },
				ReserveEngines: func(ctx context.Context, count int) (func(int), error) {
					if ctx != t.Context() {
						t.Fatal("trusted root validation used the wrong admission context")
					}
					if deny {
						return nil, quotaDenied
					}
					reserved += count
					return func(count int) { released += count }, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := client.StartOnDemand(t.Context()); !errors.Is(err, quotaDenied) || clientState(client.state.Load()) != clientStateCreated {
				t.Fatalf("scratch quota denial must leave the client created: state=%v err=%v", clientState(client.state.Load()), err)
			}
			deny = false
			err = client.StartOnDemand(t.Context())
			if reserved != 1 || released != 1 {
				t.Fatalf("scratch engine accounting: reserved=%d released=%d", reserved, released)
			}
			if roots.invalid {
				if err == nil || clientState(client.state.Load()) != clientStateClosed {
					t.Fatalf("invalid roots did not reject startup and close the client: %v", err)
				}
				return
			}
			if err != nil || !client.IsDormant() || len(client.engines) != 0 {
				t.Fatalf("valid roots should leave a dormant client with no engine: state=%v, engines=%d, err=%v",
					clientState(client.state.Load()), len(client.engines), err)
			}
		})
	}
}

func TestNaiveEngineReservations(t *testing.T) {
	if err := checkLibrary(); err != nil {
		t.Skipf("Cronet library unavailable: %v", err)
	}
	for _, tc := range []struct {
		name     string
		onDemand bool
		single   bool
		roots    string
	}{
		{name: "eager"},
		{name: "on-demand-single-engine", onDemand: true, single: true},
		{name: "partial-start", roots: "invalid certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const concurrency = 3
			engineCount := concurrency
			if tc.single || runtime.GOOS == "ios" {
				engineCount = 1
			}
			quotaDenied := errors.New("engine quota denied")
			deny := true
			var requests, releases []int
			client, err := NewNaiveClient(NaiveClientOptions{
				Context:                 t.Context(),
				ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", 443),
				InsecureConcurrency:     concurrency,
				TestForceSingleEngine:   tc.single,
				TrustedRootCertificates: tc.roots,
				DNSResolver:             func(context.Context, *mDNS.Msg) *mDNS.Msg { return nil },
				ReserveEngines: func(_ context.Context, count int) (func(int), error) {
					requests = append(requests, count)
					if deny {
						return nil, quotaDenied
					}
					return func(count int) { releases = append(releases, count) }, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			})

			wantState := clientStateCreated
			if tc.onDemand {
				if err := client.StartOnDemand(t.Context()); err != nil {
					t.Fatal(err)
				}
				wantState = clientStateDormant
				_, err = client.DialEarly(t.Context(), M.Socksaddr{})
			} else {
				err = client.Start()
			}
			if !errors.Is(err, quotaDenied) || clientState(client.state.Load()) != wantState || client.proxyCancel != nil || len(releases) != 0 {
				t.Fatalf("quota denial: state=%v releases=%v err=%v", clientState(client.state.Load()), releases, err)
			}

			deny = false
			err = client.Start()
			if !slices.Equal(requests, []int{engineCount, engineCount}) {
				t.Fatalf("reservation requests %v, want two batches of %d", requests, engineCount)
			}
			var wantReleases []int
			if tc.roots != "" {
				if err == nil || clientState(client.state.Load()) != clientStateClosed {
					t.Fatalf("invalid roots did not abort startup: state=%v err=%v", clientState(client.state.Load()), err)
				}
				if engineCount > 1 {
					wantReleases = append(wantReleases, engineCount-1)
				}
				wantReleases = append(wantReleases, 1)
				if !slices.Equal(releases, wantReleases) {
					t.Fatalf("partial startup releases %v, want %v", releases, wantReleases)
				}
			} else {
				if err != nil || len(client.engines) != engineCount || len(releases) != 0 {
					t.Fatalf("startup retry: engines=%d releases=%v err=%v", len(client.engines), releases, err)
				}
				for range engineCount {
					wantReleases = append(wantReleases, 1)
				}
			}
			for range 2 {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(releases, wantReleases) {
				t.Fatalf("close releases %v, want %v", releases, wantReleases)
			}
		})
	}
}

func TestNaiveAdmissionSealsBeforeJoin(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	if !c.beginOperation() || !c.beginCallback() {
		t.Fatal("running admission rejected")
	}
	// The close authority seals both gates before starting any join.
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	if c.beginOperation() || c.beginCallback() {
		t.Fatal("admission reopened after seal")
	}
	finished := make(chan struct{})
	go func() { _ = c.doClose(); close(finished) }()
	// An already admitted callback may still register its worker after seal.
	c.proxyWaitGroup.Add(1)
	c.finishOperation(&c.pending)
	c.finishOperation(&c.callbacks)
	select {
	case <-finished:
		t.Fatal("close returned before admitted worker exited")
	default:
	}
	c.proxyWaitGroup.Done()
	awaitLifecycle(t, finished)
}

func TestNaiveIdleSealWaitsForNativeWorkAndStreams(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	idle := make(chan struct{}, 1)
	c.onIdle = func() { idle <- struct{}{} }
	if !c.beginOperation() || !c.beginCallback() {
		t.Fatal("running admission rejected")
	}
	if c.TrySealIdle() {
		t.Fatal("sealed during native operation")
	}
	conn := &BidirectionalConn{done: make(chan struct{})}
	c.trackConnection(conn)
	c.finishOperation(&c.pending)
	if c.TrySealIdle() {
		t.Fatal("sealed during native callback")
	}
	c.finishOperation(&c.callbacks)
	if c.TrySealIdle() {
		t.Fatal("sealed with an active stream")
	}
	select {
	case <-idle:
		t.Fatal("idle signaled before stream termination")
	default:
	}
	conn.onTerminate()
	awaitLifecycle(t, idle)
	if !c.TrySealIdle() || c.TrySealIdle() || c.beginOperation() || c.beginCallback() {
		t.Fatal("idle seal did not close both gates exactly once")
	}
	if _, err := c.DialEarly(t.Context(), M.Socksaddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after idle seal: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNaiveTerminalRegistrationAndReleaseOnce(t *testing.T) {
	for _, alreadyDone := range []bool{false, true} {
		c := lifecycleTestClient(clientStateRunning)
		if !c.beginOperation() {
			t.Fatal("admission rejected")
		}
		conn := &BidirectionalConn{done: make(chan struct{})}
		if alreadyDone {
			close(conn.done)
		}
		c.trackConnection(conn)
		if !alreadyDone {
			if len(c.connections) != 1 {
				t.Fatal("stream escaped ownership")
			}
			// Simulate the terminal signal after native deletion was queued.
			conn.onTerminate()
			conn.onTerminate()
		}
		if len(c.connections) != 0 {
			t.Fatal("terminal stream retained")
		}
		c.pending.Done()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNaiveRepeatedCloseWaitsForOriginalCompletion(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	if !c.beginOperation() {
		t.Fatal("admission rejected")
	}
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	var wait sync.WaitGroup
	wait.Add(8)
	for range 8 {
		go func() {
			defer wait.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	finished := make(chan struct{})
	go func() { _ = c.doClose(); close(finished) }()
	select {
	case <-c.closed:
		t.Fatal("close completed while creation admitted")
	default:
	}
	c.pending.Done()
	awaitLifecycle(t, finished)
	wait.Wait()
}

func TestNaiveShutdownFailureNeverDestroys(t *testing.T) {
	for _, success := range []bool{false, true} {
		called := false
		released := 0
		err := shutdownNaiveEngine(func() Result {
			if success {
				return ResultSuccess
			}
			return Result(-1)
		}, func() { called = true }, func(count int) {
			if !called {
				t.Error("released before destroy completed")
			}
			released += count
		})
		if called != success || (err == nil) != success {
			t.Fatalf("success=%v destroy=%v error=%v", success, called, err)
		}
		if (success && released != 1) || (!success && released != 0) {
			t.Fatalf("success=%v released=%d", success, released)
		}
	}
}

func TestNaiveClosedResultIsSticky(t *testing.T) {
	c := lifecycleTestClient(clientStateCreated)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = lifecycleTestClient(clientStateClosing)
	want := errors.New("native completion uncertain")
	c.closeError = want
	c.state.Store(uint32(clientStateClosed))
	close(c.closed)
	if err := c.Close(); err != want {
		t.Fatalf("sticky error = %v", err)
	}
}

func TestNaiveDialCreationBarrierAndTerminalOwnership(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	c.streamEngines = []StreamEngine{{}}
	entered, proceed, dialDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	conn := &BidirectionalConn{done: make(chan struct{}), close: make(chan struct{}), cancelled: true}
	go func() {
		_, err := c.dialEarly(context.Background(), M.Socksaddr{},
			func(StreamEngine, context.Context, logger.ContextLogger, bool, bool) *BidirectionalConn {
				close(entered)
				<-proceed
				return conn
			},
			func(conn *BidirectionalConn, _, _ string, _ map[string]string, _ int, _ bool) error {
				if conn.onTerminate == nil {
					t.Error("Start preceded terminal ownership")
				}
				return nil
			})
		if err != nil {
			t.Error(err)
		}
		close(dialDone)
	}()
	awaitLifecycle(t, entered)
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	closed := make(chan struct{})
	go func() { _ = c.doClose(); close(closed) }()
	if c.beginOperation() {
		t.Fatal("late creation admitted")
	}
	select {
	case <-closed:
		t.Fatal("close overtook admitted creation")
	default:
	}
	close(proceed)
	awaitLifecycle(t, dialDone)
	awaitLifecycle(t, conn.close) // Close requested cancellation; no native callback yet.
	select {
	case <-closed:
		t.Fatal("cancellation request was treated as terminal completion")
	default:
	}
	conn.onTerminate()
	awaitLifecycle(t, closed)
}

func TestNaiveDialStartFailureAndInlineTerminal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		c := lifecycleTestClient(clientStateRunning)
		c.streamEngines = []StreamEngine{{}}
		conn := &BidirectionalConn{done: make(chan struct{})}
		want := errors.New("start failed")
		_, err := c.dialEarly(context.Background(), M.Socksaddr{},
			func(StreamEngine, context.Context, logger.ContextLogger, bool, bool) *BidirectionalConn { return conn },
			func(conn *BidirectionalConn, _, _ string, _ map[string]string, _ int, _ bool) error {
				if conn.onTerminate == nil {
					t.Fatal("Start preceded terminal ownership")
				}
				close(conn.done)
				conn.onTerminate()
				if fail {
					return want
				}
				return nil
			})
		if fail && err != want || !fail && err != nil {
			t.Fatalf("start error = %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNaiveControlOperationJoinsBeforeDestruction(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	c.engines = []Engine{{}}
	entered, release, controlDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		c.closeAllConnections(func(Engine) { close(entered); <-release })
		close(controlDone)
	}()
	awaitLifecycle(t, entered)
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	c.closeAllConnections(func(Engine) { t.Error("control passed sealed gate") })
	joined := make(chan struct{})
	go func() { c.pending.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("control use was not retained")
	default:
	}
	close(release)
	awaitLifecycle(t, controlDone)
	awaitLifecycle(t, joined)
}
