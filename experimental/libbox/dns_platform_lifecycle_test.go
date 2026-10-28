package libbox

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
)

type fakeDNSFunc func() error

func (f fakeDNSFunc) Invoke() error { return f() }

type fakeDNSPlatform struct {
	raw      func() bool
	lookup   func(*ExchangeContext, string, string) error
	exchange func(*ExchangeContext, []byte) error
}

func (p *fakeDNSPlatform) Raw() bool {
	if p.raw != nil {
		return p.raw()
	}
	return false
}

func (p *fakeDNSPlatform) Lookup(c *ExchangeContext, network, domain string) error {
	if p.lookup != nil {
		return p.lookup(c, network, domain)
	}
	c.Success("203.0.113.1")
	return nil
}

func (p *fakeDNSPlatform) Exchange(c *ExchangeContext, message []byte) error {
	return p.exchange(c, message)
}

func dnsTestQuery() *mDNS.Msg {
	query := new(mDNS.Msg)
	query.SetQuestion("example.invalid.", mDNS.TypeA)
	return query
}

func awaitDNSDrain(t *testing.T, p *platformTransport) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for p.calls.snapshot().inFlight != 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if p.calls.snapshot().inFlight != 0 {
		t.Fatal("platform call or registration did not actually finish")
	}
}

func assertDNSContextDetached(t *testing.T, c *ExchangeContext) {
	t.Helper()
	c.access.Lock()
	defer c.access.Unlock()
	if !c.completed || c.context != nil || c.registrations != nil || c.error != nil || c.addresses != nil || len(c.message.Question) != 0 {
		t.Fatal("completed ExchangeContext retained mutable result or capable references")
	}
}

func TestDNSPlatformBackgroundSuccessStopsOnCancel(t *testing.T) {
	before := runtime.NumGoroutine()
	var invoked atomic.Int32
	p := &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error {
		c.OnCancel(fakeDNSFunc(func() error { invoked.Add(1); return nil }))
		c.Success("203.0.113.1")
		return nil
	}}}
	for range 300 {
		response, err := p.Exchange(context.Background(), dnsTestQuery())
		if err != nil || response == nil || len(response.Answer) != 1 {
			t.Fatalf("success was canceled by internal cleanup: %v / %v", response, err)
		}
	}
	awaitDNSDrain(t, p)
	runtime.GC()
	if invoked.Load() != 0 || runtime.NumGoroutine() > before+4 {
		t.Fatal("successful public OnCancel retained permanent waiters")
	}
}

func TestDNSPlatformPreCancelledSkipsAllPlatformAccess(t *testing.T) {
	var calls atomic.Int32
	p := &platformTransport{iif: &fakeDNSPlatform{raw: func() bool { calls.Add(1); return false }, lookup: func(*ExchangeContext, string, string) error { calls.Add(1); return nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Exchange(ctx, dnsTestQuery()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	awaitDNSDrain(t, p)
	if calls.Load() != 0 {
		t.Fatal("pre-canceled query entered platform Raw or Lookup")
	}
}

func TestDNSPlatformOnCancelAndCompletionRace(t *testing.T) {
	for range 200 {
		var invoked atomic.Int32
		var registering sync.WaitGroup
		registering.Add(1)
		var captured *ExchangeContext
		p := &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error {
			captured = c
			go func() { defer registering.Done(); c.OnCancel(fakeDNSFunc(func() error { invoked.Add(1); return nil })) }()
			c.Success("203.0.113.1")
			return nil
		}}}
		if _, err := p.Exchange(context.Background(), dnsTestQuery()); err != nil {
			t.Fatal(err)
		}
		registering.Wait()
		awaitDNSDrain(t, p)
		assertDNSContextDetached(t, captured)
		if invoked.Load() != 0 {
			t.Fatal("finish/registration race resurrected cancellation after success")
		}
	}
}

func TestDNSPlatformFrozenResultRejectsConcurrentLateWrites(t *testing.T) {
	var captured *ExchangeContext
	p := &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error { captured = c; c.Success("203.0.113.1"); return nil }}}
	response, err := p.Exchange(context.Background(), dnsTestQuery())
	if err != nil {
		t.Fatal(err)
	}
	late := dns.FixedResponse(1, dnsTestQuery().Question[0], []netip.Addr{netip.MustParseAddr("203.0.113.2")}, 60)
	lateBytes, err := late.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var invoked atomic.Int32
	var writing sync.WaitGroup
	for range 8 {
		writing.Go(func() {
			for range 50 {
				captured.Success("203.0.113.2")
				captured.RawSuccess(lateBytes)
				captured.ErrorCode(mDNS.RcodeServerFailure)
				captured.ErrnoCode(int32(syscall.EIO))
				captured.OnCancel(fakeDNSFunc(func() error { invoked.Add(1); return nil }))
			}
		})
	}
	writing.Wait()
	if len(response.Answer) != 1 || response.Answer[0].(*mDNS.A).A.String() != "203.0.113.1" || invoked.Load() != 0 {
		t.Fatal("late platform callback changed frozen result or cancellation state")
	}
	assertDNSContextDetached(t, captured)
}

func TestDNSPlatformUpperReturnKeepsBlockedPlatformLease(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var captured *ExchangeContext
	p := &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error {
		captured = c
		close(entered)
		<-release
		c.Success("203.0.113.1")
		return nil
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	upper := make(chan error, 1)
	go func() { _, err := p.Exchange(ctx, dnsTestQuery()); upper <- err }()
	awaitDNSFinished(t, entered)
	cancel()
	select {
	case err := <-upper:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upper query did not return on cancellation")
	}
	if p.calls.snapshot().inFlight != 1 {
		t.Fatal("upper cancellation erased blocked platform call")
	}
	if err := p.close(); err != nil {
		t.Fatalf("busy Close changed operational result: %v", err)
	}
	if p.calls.snapshot().inFlight != 1 {
		t.Fatal("Close erased a platform call before actual return")
	}
	close(release)
	awaitDNSDrain(t, p)
	assertDNSContextDetached(t, captured)
}

func TestDNSPlatformReentrantCloseDoesNotJoinRunningCallback(t *testing.T) {
	registered, callbackEntered, releaseCallback := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var captured *ExchangeContext
	var p *platformTransport
	p = &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error {
		captured = c
		c.OnCancel(fakeDNSFunc(func() error {
			if err := p.close(); err != nil {
				return err
			}
			close(callbackEntered)
			<-releaseCallback
			return nil
		}))
		close(registered)
		<-callbackEntered
		return nil
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	upper := make(chan error, 1)
	go func() { _, err := p.Exchange(ctx, dnsTestQuery()); upper <- err }()
	awaitDNSFinished(t, registered)
	cancel()
	awaitDNSFinished(t, callbackEntered)
	select {
	case <-upper:
	case <-time.After(time.Second):
		t.Fatal("reentrant Close waited for its own cancellation callback")
	}
	deadline := time.Now().Add(time.Second)
	for {
		captured.access.Lock()
		completed := captured.completed
		captured.access.Unlock()
		if completed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual platform return waited for callback exit")
		}
		runtime.Gosched()
	}
	if p.calls.snapshot().inFlight != 1 {
		t.Fatal("actual return prematurely released a running callback lease")
	}
	assertDNSContextDetached(t, captured)
	close(releaseCallback)
	awaitDNSDrain(t, p)
}

func TestDNSPlatformCloseDuringRawIsNonblockingAndRejectsAdmission(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var lookups atomic.Int32
	p := &platformTransport{iif: &fakeDNSPlatform{raw: func() bool { close(entered); <-release; return false }, lookup: func(*ExchangeContext, string, string) error { lookups.Add(1); return nil }}}
	upper := make(chan error, 1)
	go func() { _, err := p.Exchange(context.Background(), dnsTestQuery()); upper <- err }()
	awaitDNSFinished(t, entered)
	closed := make(chan error, 1)
	go func() { closed <- p.close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Raw held the admission gate across platform access")
	}
	if p.calls.snapshot().inFlight != 1 {
		t.Fatal("Raw access bypassed the call lease")
	}
	if _, err := p.Exchange(context.Background(), dnsTestQuery()); !errors.Is(err, errDNSCallAdmissionClosed) {
		t.Fatal("Close allowed new platform access")
	}
	if err := <-upper; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	awaitDNSDrain(t, p)
	if lookups.Load() != 0 {
		t.Fatal("canceled Raw call started another platform query")
	}
}

func TestDNSPlatformErrorPriorityAndRawFrozenSnapshot(t *testing.T) {
	platformFailure := errors.New("actual platform error")
	for _, raw := range []bool{false, true} {
		for _, failure := range []string{"platform", "errno", "rcode", "success"} {
			t.Run(map[bool]string{false: "lookup", true: "raw"}[raw]+"/"+failure, func(t *testing.T) {
				var captured *ExchangeContext
				respond := func(c *ExchangeContext) error {
					captured = c
					if raw {
						answer := dns.FixedResponse(7, dnsTestQuery().Question[0], []netip.Addr{netip.MustParseAddr("203.0.113.1")}, 60)
						data, _ := answer.Pack()
						c.RawSuccess(data)
					} else {
						c.Success("203.0.113.1")
					}
					switch failure {
					case "platform":
						c.ErrorCode(mDNS.RcodeServerFailure)
						return platformFailure
					case "errno":
						c.ErrnoCode(int32(syscall.EIO))
					case "rcode":
						c.ErrorCode(mDNS.RcodeNameError)
					}
					return nil
				}
				p := &platformTransport{iif: &fakeDNSPlatform{raw: func() bool { return raw }, lookup: func(c *ExchangeContext, _, _ string) error { return respond(c) }, exchange: func(c *ExchangeContext, _ []byte) error { return respond(c) }}}
				response, err := p.Exchange(context.Background(), dnsTestQuery())
				switch failure {
				case "platform":
					if !errors.Is(err, platformFailure) {
						t.Fatal("response error overrode platform error", err)
					}
				case "errno":
					if !errors.Is(err, syscall.EIO) {
						t.Fatal(err)
					}
				case "rcode":
					if !errors.Is(err, dns.RcodeError(mDNS.RcodeNameError)) {
						t.Fatal(err)
					}
				case "success":
					if err != nil || len(response.Answer) != 1 {
						t.Fatalf("%v / %v", response, err)
					}
					captured.RawSuccess([]byte{1})
					if len(response.Answer) != 1 {
						t.Fatal("raw result was aliased with mutable context")
					}
				}
				assertDNSContextDetached(t, captured)
			})
		}
	}
}

func TestDNSPlatformAsyncLeasePrecedesRawAndCloseStaysNil(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p := &platformTransport{iif: &fakeDNSPlatform{raw: func() bool { close(entered); <-release; return false }}}
	result := make(chan error, 1)
	p.ExchangeAsync(context.Background(), dnsTestQuery(), func(_ *mDNS.Msg, err error) { result <- err })
	awaitDNSFinished(t, entered)
	if p.calls.snapshot().inFlight != 1 {
		t.Fatal("ExchangeAsync launched platform goroutine without admission")
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	awaitDNSDrain(t, p)
}

func TestDNSPlatformCallbackFailureDoesNotChangeOperationalClose(t *testing.T) {
	registered, invoked := make(chan struct{}), make(chan struct{})
	failure := errors.New("callback cleanup failed")
	p := &platformTransport{iif: &fakeDNSPlatform{lookup: func(c *ExchangeContext, _, _ string) error {
		c.OnCancel(fakeDNSFunc(func() error { close(invoked); return failure }))
		close(registered)
		<-invoked
		return nil
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := p.Exchange(ctx, dnsTestQuery()); result <- err }()
	awaitDNSFinished(t, registered)
	cancel()
	<-result
	awaitDNSDrain(t, p)
	if !errors.Is(p.calls.snapshot().failure, failure) {
		t.Fatal("local snapshot lost callback failure")
	}
	if err := p.close(); err != nil {
		t.Fatal("local proof failure changed operational Close", err)
	}
}

func TestPlatformTransportScopeCloseSealsAdmission(t *testing.T) {
	p, err := newPlatformTransport(context.Background(), log.NewNOPFactory().Logger(), &fakeDNSPlatform{}, "local", option.LocalDNSServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	for _, stage := range adapter.ListStartStages {
		err = p.Start(stage, scope)
		if err != nil {
			t.Fatal(err)
		}
	}
	if p.calls.snapshot().sealed || p.iif == nil {
		t.Fatal("started transport is already sealed")
	}
	err = scope.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !p.calls.snapshot().sealed || p.iif != nil {
		t.Fatal("closing the scope did not seal the transport")
	}
	_, err = p.calls.begin(context.Background())
	if err == nil {
		t.Fatal("sealed transport admitted a platform call")
	}
}
