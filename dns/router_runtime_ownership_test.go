package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Real constructor, rule initialization and Start; only the upstream socket work
// is replaced. The resource close function owns this receiver's private scope.
func operationTestRouter(t *testing.T, rules []option.DNSRule, transport *policyTestTransport) (*Router, *runtimegraph.ResourceOwner, adapter.RuntimeResourceLease) {
	t.Helper()
	var scope *adapter.Scope
	owner, construction := operationTestOwner(t, 1, nil, func() error { return scope.Close() })
	scope = adapter.NewScope(owner.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { owner.Seal(); construction.Release(); operationTestClosed(t, owner) })
	ctx := service.ContextWithDefaultRegistry(adapter.ContextWithRuntimeResourceSource(scope.Context(), owner))
	service.MustRegister[adapter.DNSTransportManager](ctx, &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{transport.Tag(): transport}, defaultTransport: transport})
	router, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{DisableCache: true}, RouterClientDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if router.runtimeResource != owner || router.client.(*Client).runtimeResource != owner {
		t.Fatal("constructor-bound receiver lost")
	}
	if err := router.Initialize(rules); err != nil {
		t.Fatal(err)
	}
	if err := scope.Start("dns", router, adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	return router, owner, construction
}

func TestRouterUnmarkedAsyncOwnsPolicyResumeAndLegacy(t *testing.T) {
	for _, mode := range []string{"policy", "resume", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			bodyEntered, bodyRelease := make(chan struct{}), make(chan struct{})
			callbackEntered, callbackRelease, callbackReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			callReturned := make(chan struct{})
			var bodyOnce, callbackOnce sync.Once
			transport := &policyTestTransport{tag: "leaf", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				close(bodyEntered)
				<-bodyRelease
				return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
			}}
			rules := []option.DNSRule{evaluateRule("leaf", "answer", false), respondRule("answer", false, true)}
			options := adapter.DNSQueryOptions{DisableCache: true, Timeout: 5 * time.Second}
			if mode == "policy" {
				rules = policyTestRules(t, []string{"leaf"})
				options = policyOptions(5 * time.Second)
			}
			if mode == "legacy" {
				rules = nil
			}
			router, owner, construction := operationTestRouter(t, rules, transport)
			if mode == "legacy" {
				router.legacyDNSMode = true
			}
			t.Cleanup(func() {
				bodyOnce.Do(func() { close(bodyRelease) })
				callbackOnce.Do(func() { close(callbackRelease) })
				router.StopRuntimeProducers()
				owner.Seal()
				construction.Release()
				refreshTestAwait(t, callReturned)
				refreshTestAwait(t, callbackReturned)
				operationTestClosed(t, owner)
			})
			go func() {
				defer close(callReturned)
				router.ExchangeAsync(context.Background(), correctnessQuestion(mDNS.TypeA), options, func(*mDNS.Msg, error) {
					router.StopRuntimeProducers() // Nonjoining even on this callback stack.
					close(callbackEntered)
					<-callbackRelease
					close(callbackReturned)
				})
			}()
			refreshTestAwait(t, bodyEntered)
			owner.Seal()
			construction.Release()
			operationTestPending(t, owner)
			bodyOnce.Do(func() { close(bodyRelease) })
			refreshTestAwait(t, callbackEntered)
			operationTestPending(t, owner)
			callbackOnce.Do(func() { close(callbackRelease) })
			refreshTestAwait(t, callbackReturned)
			refreshTestAwait(t, callReturned)
			operationTestClosed(t, owner)
		})
	}
}

func TestRouterCanceledPolicyFutureRetainsActualReceiver(t *testing.T) {
	entered, release, leafReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	transport := &policyTestTransport{tag: "leaf", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		close(entered)
		<-release
		return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
	}, afterCallback: func() { close(leafReturned) }}
	router, owner, construction := operationTestRouter(t, policyTestRules(t, []string{"leaf"}), transport)
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		once.Do(func() { close(release) })
		router.StopRuntimeProducers()
		owner.Seal()
		construction.Release()
		refreshTestAwait(t, returned)
		refreshTestAwait(t, leafReturned)
		operationTestClosed(t, owner)
	})
	go func() {
		defer close(returned)
		_, _ = router.Exchange(ctx, correctnessQuestion(mDNS.TypeA), policyOptions(5*time.Second))
	}()
	refreshTestAwait(t, entered)
	cancel()
	refreshTestAwait(t, returned)
	owner.Seal()
	construction.Release()
	router.StopRuntimeProducers()
	operationTestPending(t, owner)
	once.Do(func() { close(release) })
	refreshTestAwait(t, leafReturned)
	operationTestClosed(t, owner)
}
