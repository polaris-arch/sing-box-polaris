package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeDNSTransport struct {
	tag         string
	delay       time.Duration
	immediate   bool
	rcode       int
	address     netip.Addr
	exchangeErr error

	access       sync.Mutex
	queryCount   atomic.Int32
	firstQueried time.Time
}

func (t *fakeDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (t *fakeDNSTransport) Type() string {
	return "fake"
}

func (t *fakeDNSTransport) Tag() string {
	return t.tag
}

func (t *fakeDNSTransport) Dependencies() []string {
	return nil
}

func (t *fakeDNSTransport) Reset() {
}

func (t *fakeDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.access.Lock()
	if t.firstQueried.IsZero() {
		t.firstQueried = time.Now()
	}
	t.access.Unlock()
	t.queryCount.Add(1)
	select {
	case <-time.After(t.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if t.exchangeErr != nil {
		return nil, t.exchangeErr
	}
	if t.rcode != mDNS.RcodeSuccess {
		return FixedResponseStatus(message, t.rcode), nil
	}
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{t.address}, 300), nil
}

func (t *fakeDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if t.immediate {
		callback(t.Exchange(ctx, message))
		return
	}
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

type fakeDNSTransportManager struct {
	transports       map[string]adapter.DNSTransport
	defaultTransport adapter.DNSTransport
}

func (m *fakeDNSTransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

func (m *fakeDNSTransportManager) Transports() []adapter.DNSTransport {
	return nil
}

func (m *fakeDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *fakeDNSTransportManager) Default() adapter.DNSTransport {
	return m.defaultTransport
}

func (m *fakeDNSTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

func (m *fakeDNSTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func raceTestRouter(t *testing.T, transports ...*fakeDNSTransport) *Router {
	transportMap := make(map[string]adapter.DNSTransport)
	for _, transport := range transports {
		transportMap[transport.tag] = transport
	}
	return &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       transportMap,
			defaultTransport: transportMap["final"],
		},
		client: NewClient(ClientOptions{
			Context:      context.Background(),
			DisableCache: true,
			Logger:       log.NewNOPFactory().Logger(),
		}),
	}
}

func raceTestRules(t *testing.T, rawRules []option.DNSRule) []adapter.DNSRule {
	rules := make([]adapter.DNSRule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), rawRule, true, false)
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return rules
}

func raceTestExchange(router *Router, rules []adapter.DNSRule) exchangeWithRulesResult {
	message := &mDNS.Msg{
		Id:               1,
		RecursionDesired: true,
		Question: []mDNS.Question{{
			Name:   "race.example.org.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	metadata := &adapter.InboundContext{
		Domain:    "race.example.org",
		QueryType: mDNS.TypeA,
	}
	ctx := adapter.WithContext(context.Background(), metadata)
	return router.exchangeWithRules(ctx, rules, message, adapter.DNSQueryOptions{}, false)
}

func evaluateRule(server string, tag string, speculative bool) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeEvaluate,
				EvaluateOptions: option.DNSEvaluateActionOptions{
					Server:      server,
					Tag:         tag,
					Speculative: speculative,
				},
			},
		},
	}
}

func respondRule(responseTag string, race bool, requireSuccess bool) option.DNSRule {
	rule := option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: responseTag},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRespond,
				Race:   race,
			},
		},
	}
	if requireSuccess {
		successRcode := option.DNSRCode(mDNS.RcodeSuccess)
		rule.DefaultOptions.ResponseRcode = &successRcode
	}
	return rule
}

func routeRule(server string, speculative bool) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:      server,
					Speculative: speculative,
				},
			},
		},
	}
}

func responseAddress(t *testing.T, response *mDNS.Msg) netip.Addr {
	require.NotNil(t, response)
	require.Len(t, response.Answer, 1)
	record, isA := response.Answer[0].(*mDNS.A)
	require.True(t, isA)
	address, _ := netip.AddrFromSlice(record.A)
	return address.Unmap()
}

// The shared timer fixture above remains unchanged for its external users.
// This fixture controls transport work, not DNS eligibility or arbitration.
type controlledDNSTransport struct {
	fakeDNSTransport
	owner          *testing.T
	entered        chan struct{}
	release        chan struct{}
	replied        chan struct{}
	cancelSeen     chan struct{}
	cancelExit     chan struct{}
	cancelErr      error // Written before cancelSeen; read only after it.
	rawDone        chan struct{}
	callbackDone   chan struct{}
	asyncReturned  chan struct{}
	releaseOnce    sync.Once
	cancelOnce     sync.Once
	cancelExitOnce sync.Once
	releaseIssued  atomic.Bool
	replyIssued    atomic.Bool
	inlineDone     atomic.Bool
	asyncCalls     atomic.Int32
	waitFor        <-chan struct{}
	entryAfter     []*controlledDNSTransport
}

func controlledDNSUpstream(tag, address string) *controlledDNSTransport {
	upstream := &controlledDNSTransport{
		fakeDNSTransport: fakeDNSTransport{tag: tag, rcode: mDNS.RcodeSuccess},
		entered:          make(chan struct{}), release: make(chan struct{}),
		replied: make(chan struct{}), cancelSeen: make(chan struct{}),
		cancelExit: make(chan struct{}),
		rawDone:    make(chan struct{}), callbackDone: make(chan struct{}),
		asyncReturned: make(chan struct{}),
	}
	if address != "" {
		upstream.address = netip.MustParseAddr(address)
	}
	return upstream
}

func (u *controlledDNSTransport) allow() {
	u.releaseOnce.Do(func() {
		u.releaseIssued.Store(true)
		close(u.release)
	})
}

func (u *controlledDNSTransport) allowCancelExit() {
	u.cancelExitOnce.Do(func() { close(u.cancelExit) })
}

func (u *controlledDNSTransport) canceled(ctx context.Context) (*mDNS.Msg, error) {
	cause := ctx.Err()
	u.cancelOnce.Do(func() {
		u.cancelErr = cause
		close(u.cancelSeen)
	})
	// Only the test after its winning result, or cleanup, releases raw cancellation.
	<-u.cancelExit
	return nil, cause
}

func (u *controlledDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if u.queryCount.Add(1) != 1 {
		return nil, context.Canceled // Counts below independently reject duplicate work.
	}
	defer close(u.rawDone)
	for _, predecessor := range u.entryAfter {
		// This runs at the actual transport entry, not on the test's main goroutine.
		if !predecessor.replyIssued.Load() {
			u.owner.Errorf("transport %s entered before %s response decision", u.tag, predecessor.tag)
			return nil, context.Canceled
		}
	}
	close(u.entered)
	if u.waitFor != nil {
		select {
		case <-u.waitFor:
		case <-ctx.Done():
			return u.canceled(ctx)
		}
	}
	select {
	case <-u.release:
	case <-ctx.Done():
		return u.canceled(ctx)
	}
	if ctx.Err() != nil {
		return u.canceled(ctx)
	}
	var response *mDNS.Msg
	if u.exchangeErr == nil {
		if u.rcode != mDNS.RcodeSuccess {
			response = FixedResponseStatus(message, u.rcode)
		} else {
			response = FixedResponse(message.Id, message.Question[0], []netip.Addr{u.address}, 300)
		}
	}
	// A natural response/error decision is distinct from cancellation and raw exit.
	u.replyIssued.Store(true)
	close(u.replied)
	return response, u.exchangeErr
}

func (u *controlledDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	if u.asyncCalls.Add(1) != 1 {
		u.owner.Errorf("transport %s received duplicate ExchangeAsync call", u.tag)
		callback(nil, context.Canceled)
		return
	}
	defer close(u.asyncReturned)
	work := func() {
		defer close(u.callbackDone)
		response, err := u.Exchange(ctx, message)
		callback(response, err) // The real Client/Router callback must actually return.
	}
	if u.immediate {
		work()
		u.inlineDone.Store(true)
		return
	}
	go work()
}

// This is only a deadlock watchdog. No elapsed time is a correctness predicate.
func controlledDNSWait(t *testing.T, event <-chan struct{}, label string) bool {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-event:
		return true
	case <-timer.C:
		t.Errorf("DNS fixture did not join/reach %s", label)
		return false
	}
}

func controlledDNSAwait(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	if !controlledDNSWait(t, event, label) {
		t.FailNow()
	}
}

func (u *controlledDNSTransport) inlineCompleted(t *testing.T) {
	t.Helper()
	controlledDNSAwait(t, u.callbackDone, u.tag+" callback")
	controlledDNSAwait(t, u.asyncReturned, u.tag+" ExchangeAsync return")
	require.True(t, u.inlineDone.Load(), "the immediate callback must finish inline")
}

func (u *controlledDNSTransport) heldThroughResult(t *testing.T) {
	t.Helper()
	require.False(t, u.releaseIssued.Load(), "the slow success path was never released")
	require.False(t, u.replyIssued.Load(), "cancellation is not successful completion")
	controlledDNSAwait(t, u.cancelSeen, u.tag+" cancellation observed")
	require.ErrorIs(t, u.cancelErr, context.Canceled, "held %s must be canceled by the winner rather than expire", u.tag)
	u.allowCancelExit()
	controlledDNSAwait(t, u.rawDone, u.tag+" raw exit")
	controlledDNSAwait(t, u.callbackDone, u.tag+" callback exit")
}

// Delegation exposes actual rule progress in the full-entry controls; it never
// changes a rule's bindings, match result, action or racing policy.
type controlledDNSRule struct {
	adapter.DNSRule
	raceSeen   chan struct{}
	matchSeen  chan struct{}
	actionSeen chan struct{}
	raceOnce   sync.Once
	matchOnce  sync.Once
	actionOnce sync.Once
}

func (r *controlledDNSRule) Race() bool {
	racing := r.DNSRule.Race()
	r.raceOnce.Do(func() { close(r.raceSeen) })
	return racing
}

func (r *controlledDNSRule) Match(metadata *adapter.InboundContext) bool {
	matched := r.DNSRule.Match(metadata)
	r.matchOnce.Do(func() { close(r.matchSeen) })
	return matched
}

func (r *controlledDNSRule) Action() adapter.RuleAction {
	action := r.DNSRule.Action()
	r.actionOnce.Do(func() { close(r.actionSeen) })
	return action
}

type controlledDNSRun struct {
	t             *testing.T
	router        *Router
	rules         []adapter.DNSRule
	observed      []*controlledDNSRule
	ctx           context.Context
	cancel        context.CancelFunc
	message       *mDNS.Msg
	done          chan struct{}
	walkDone      chan struct{}
	resume        chan struct{}
	resumeOnce    sync.Once
	staged        bool
	state         dnsRuleWalkState
	suspension    *dnsWalkSuspension
	initial       exchangeWithRulesResult
	result        exchangeWithRulesResult
	returnOrdered atomic.Bool
}

func controlledDNSStart(t *testing.T, staged bool, raw []option.DNSRule, returnAfter []*controlledDNSTransport, transports ...*controlledDNSTransport) *controlledDNSRun {
	t.Helper()
	rules := raceTestRules(t, raw)
	observed := make([]*controlledDNSRule, len(rules))
	for index, rule := range rules {
		observed[index] = &controlledDNSRule{
			DNSRule: rule, raceSeen: make(chan struct{}),
			matchSeen: make(chan struct{}), actionSeen: make(chan struct{}),
		}
		rules[index] = observed[index]
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = adapter.WithContext(ctx, &adapter.InboundContext{Domain: "race.example.org", QueryType: mDNS.TypeA})
	router := raceTestRouter(t)
	mapping := make(map[string]adapter.DNSTransport)
	for _, upstream := range transports {
		upstream.owner = t
		mapping[upstream.tag] = upstream
	}
	router.transport = &fakeDNSTransportManager{transports: mapping, defaultTransport: mapping["final"]}
	run := &controlledDNSRun{
		t: t, router: router, rules: rules, observed: observed,
		ctx: ctx, cancel: cancel, staged: staged,
		done: make(chan struct{}), walkDone: make(chan struct{}), resume: make(chan struct{}),
		state: dnsRuleWalkState{lastLoggedIndex: -1},
		message: &mDNS.Msg{Id: 1, RecursionDesired: true, Question: []mDNS.Question{{
			Name: "race.example.org.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET,
		}}},
	}
	t.Cleanup(func() {
		cancel()
		for _, upstream := range transports {
			upstream.allow()
			upstream.allowCancelExit()
		}
		run.continueWalk()
		controlledDNSWait(t, run.done, "request return")
		// The Router promises cancellation, not a join of our transport callbacks.
		// Join those separately, even after an assertion aborts the test body.
		for _, upstream := range transports {
			if upstream.queryCount.Load() != 0 || upstream.asyncCalls.Load() != 0 {
				controlledDNSWait(t, upstream.rawDone, upstream.tag+" raw exit")
			}
			if upstream.asyncCalls.Load() != 0 {
				controlledDNSWait(t, upstream.callbackDone, upstream.tag+" callback exit")
				controlledDNSWait(t, upstream.asyncReturned, upstream.tag+" async call return")
			}
		}
		closeRules(run.rules)
	})
	go func() {
		defer close(run.done)
		if staged {
			// Only the real walker creates futures, armed rules and this suspension.
			defer cancelDNSFutures(&run.state)
			run.initial, run.suspension = router.walkDNSRules(ctx, run.rules, run.message, &run.state, false)
			close(run.walkDone)
			<-run.resume
			if run.suspension == nil {
				run.result = run.initial
			} else {
				run.result = router.resumeExchangeWithRules(ctx, run.rules, run.message, &run.state, false, run.suspension)
			}
		} else {
			// Every original branch still exercises the complete production entry.
			run.result = router.exchangeWithRules(ctx, run.rules, run.message, adapter.DNSQueryOptions{}, false)
		}
		ordered := true
		for _, upstream := range returnAfter {
			ordered = ordered && upstream.replyIssued.Load()
		}
		run.returnOrdered.Store(ordered) // Snapshot at the real return, before main can observe it.
	}()
	return run
}

func (r *controlledDNSRun) continueWalk() {
	r.resumeOnce.Do(func() { close(r.resume) })
}

// For the full entry, first require a real delegated rule call after worker
// progress. The paired staged case then checks the actual suspension/arbiter.
func (r *controlledDNSRun) progressed(index int, phase string) {
	r.t.Helper()
	if r.staged {
		return
	}
	rule := r.observed[index]
	var event <-chan struct{}
	switch phase {
	case "race":
		event = rule.raceSeen
	case "match":
		event = rule.matchSeen
	case "action":
		event = rule.actionSeen
	default:
		r.t.Fatalf("unknown fixture progress phase %q", phase)
	}
	controlledDNSAwait(r.t, event, "delegated rule "+phase)
}

// Paired with the full-entry case, this directly observes a real wait boundary.
// It does not poll a result channel or manufacture an unresolved future.
func (r *controlledDNSRun) pending(ordered *controlledDNSTransport) {
	r.t.Helper()
	if !r.staged {
		return
	}
	controlledDNSAwait(r.t, r.walkDone, "initial walk suspension")
	require.NoError(r.t, r.initial.err)
	require.Nil(r.t, r.initial.response)
	require.NotNil(r.t, r.suspension, "the real walk must suspend")
	if r.suspension.await != nil {
		// A completed binding may now advance the same real walker into drain.
		// An unresolved ordered binding must produce the same await again.
		r.initial, r.suspension = r.router.walkDNSRules(r.ctx, r.rules, r.message, &r.state, false)
		require.NoError(r.t, r.initial.err)
		require.Nil(r.t, r.initial.response)
		require.NotNil(r.t, r.suspension)
	}
	require.Nil(r.t, r.suspension.pending, "no terminal/default route may be admitted yet")
	if ordered != nil {
		require.NotNil(r.t, r.suspension.await)
		require.Same(r.t, ordered, r.suspension.await.transport)
	} else {
		require.True(r.t, r.suspension.drain)
	}
	result, pending, committed := r.router.sweepArmedDNSRules(r.ctx, r.message, &r.state, false)
	require.False(r.t, committed, "the actual arbiter must not publish an ineligible result")
	require.Nil(r.t, pending)
	require.NoError(r.t, result.err)
	require.Nil(r.t, result.response)
}

func (r *controlledDNSRun) answer(address string) {
	r.t.Helper()
	controlledDNSAwait(r.t, r.done, "winning result")
	require.True(r.t, r.returnOrdered.Load(), "real return preceded its required response decisions")
	require.NoError(r.t, r.result.err)
	require.Equal(r.t, netip.MustParseAddr(address), responseAddress(r.t, r.result.response))
}

func controlledDNSModes(t *testing.T, test func(t *testing.T, staged bool)) {
	t.Helper()
	t.Run("exchange", func(t *testing.T) { test(t, false) })
	t.Run("walk-suspension-resume", func(t *testing.T) { test(t, true) })
}

func controlledDNSBoundRoute(race, speculative bool) option.DNSRule {
	successRcode := option.DNSRCode(mDNS.RcodeSuccess)
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: "y"},
				ResponseRcode: &successRcode,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute, Race: race,
				RouteOptions: option.DNSRouteActionOptions{Server: "final", Speculative: speculative},
			},
		},
	}
}

func controlledDNSLogicalRule() option.DNSRule {
	successRcode := option.DNSRCode(mDNS.RcodeSuccess)
	return option.DNSRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalDNSRule{
			RawLogicalDNSRule: option.RawLogicalDNSRule{
				Mode: C.LogicalTypeAnd,
				Rules: []option.DNSRule{
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								MatchResponse: &option.DNSRuleMatchResponse{Enabled: true},
								ResponseRcode: &successRcode,
							},
						},
					},
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								MatchResponse: &option.DNSRuleMatchResponse{Enabled: true, Tag: "y"},
								ResponseRcode: &successRcode,
							},
						},
					},
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRespond,
				Race:   true,
			},
		},
	}
}

// Both evaluations enter before either decision is released. The primary error
// remains an ordered barrier even after the secondary response is available.
func TestDNSEvaluateParallelFallback(t *testing.T) {
	t.Parallel()
	controlledDNSModes(t, func(t *testing.T, staged bool) {
		x := controlledDNSUpstream("x", "192.0.2.1")
		x.exchangeErr = context.DeadlineExceeded
		y := controlledDNSUpstream("y", "192.0.2.2")
		run := controlledDNSStart(t, staged, []option.DNSRule{
			evaluateRule("x", "x", false), evaluateRule("y", "y", false),
			respondRule("x", false, true), respondRule("y", false, true),
		}, []*controlledDNSTransport{x, y}, x, y)
		controlledDNSAwait(t, x.entered, "x entered")
		controlledDNSAwait(t, y.entered, "y entered concurrently with unresolved x")
		y.allow()
		controlledDNSAwait(t, y.callbackDone, "secondary callback")
		run.progressed(2, "race")
		run.pending(x)
		run.continueWalk()
		x.allow()
		run.answer("192.0.2.2")
		require.Equal(t, int32(1), x.queryCount.Load())
		require.Equal(t, int32(1), y.queryCount.Load())
	})
}

// Only one eligible candidate is released at a time. This does not impose a
// global earliest-publication order on an ordinary all-ready snapshot.
func TestDNSRaceFastestWins(t *testing.T) {
	t.Parallel()
	for _, winner := range []string{"y", "x"} {
		t.Run(winner+"-ready-first", func(t *testing.T) {
			x := controlledDNSUpstream("x", "192.0.2.1")
			y := controlledDNSUpstream("y", "192.0.2.2")
			first, held := y, x
			if winner == "x" {
				first, held = x, y
			}
			run := controlledDNSStart(t, false, []option.DNSRule{
				evaluateRule("x", "x", false), evaluateRule("y", "y", false),
				respondRule("x", true, true), respondRule("y", true, true),
			}, []*controlledDNSTransport{first}, x, y)
			controlledDNSAwait(t, x.entered, "x entered")
			controlledDNSAwait(t, y.entered, "y entered")
			first.allow()
			run.answer(first.address.String())
			held.heldThroughResult(t)
			require.Equal(t, int32(1), x.queryCount.Load())
			require.Equal(t, int32(1), y.queryCount.Load())
		})
	}
}

// Y really invokes the Client/Router callback inline, with X already entered.
// Its result must arrive while X's successful response remains unavailable.
func TestDNSRaceImmediateLaterResponseWins(t *testing.T) {
	t.Parallel()
	x := controlledDNSUpstream("x", "192.0.2.1")
	y := controlledDNSUpstream("y", "192.0.2.2")
	y.immediate, y.waitFor = true, x.entered
	y.allow()
	run := controlledDNSStart(t, false, []option.DNSRule{
		evaluateRule("x", "x", false), evaluateRule("y", "y", false),
		respondRule("x", true, true), respondRule("y", true, true),
	}, []*controlledDNSTransport{y}, x, y)
	run.answer("192.0.2.2")
	y.inlineCompleted(t)
	x.heldThroughResult(t)
	require.Equal(t, int32(1), x.queryCount.Load())
	require.Equal(t, int32(1), y.queryCount.Load())
}

// The inline miss is rejected by the real compiled rule. The paired staged
// control witnesses the remaining armed wait before X is allowed to answer.
func TestDNSRaceImmediateMissContinues(t *testing.T) {
	t.Parallel()
	controlledDNSModes(t, func(t *testing.T, staged bool) {
		x := controlledDNSUpstream("x", "192.0.2.1")
		y := controlledDNSUpstream("y", "")
		y.immediate, y.waitFor, y.rcode = true, x.entered, mDNS.RcodeNameError
		y.allow()
		run := controlledDNSStart(t, staged, []option.DNSRule{
			evaluateRule("x", "x", false), evaluateRule("y", "y", false),
			respondRule("y", true, true), respondRule("x", true, true),
		}, []*controlledDNSTransport{x, y}, x, y)
		y.inlineCompleted(t)
		run.progressed(3, "action")
		run.pending(nil)
		run.continueWalk()
		x.allow()
		run.answer("192.0.2.1")
		require.Equal(t, int32(1), x.queryCount.Load())
		require.Equal(t, int32(1), y.queryCount.Load())
	})
}

// The synchronous hit routes through final while X is held. The same route
// with an inline miss must remain unqueried and let X win instead.
func TestDNSRaceImmediateRouteCommits(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{true, false} {
		name := "inline-miss"
		if hit {
			name = "inline-hit"
		}
		t.Run(name, func(t *testing.T) {
			check := func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				y := controlledDNSUpstream("y", "192.0.2.2")
				final := controlledDNSUpstream("final", "192.0.2.9")
				y.immediate, y.waitFor = true, x.entered
				if !hit {
					y.rcode = mDNS.RcodeNameError
				}
				y.allow()
				final.allow()
				required := []*controlledDNSTransport{y}
				if !hit {
					required = append(required, x)
				}
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "x", false), evaluateRule("y", "y", false),
					respondRule("x", true, true), controlledDNSBoundRoute(true, false),
				}, required, x, y, final)
				y.inlineCompleted(t)
				if hit {
					controlledDNSAwait(t, final.entered, "matched final route")
					run.answer("192.0.2.9")
					require.Equal(t, int32(1), final.queryCount.Load())
					x.heldThroughResult(t)
				} else {
					run.progressed(3, "match")
					run.pending(nil)
					require.Equal(t, int32(0), final.queryCount.Load())
					run.continueWalk()
					x.allow()
					run.answer("192.0.2.1")
					require.Equal(t, int32(0), final.queryCount.Load())
				}
				require.Equal(t, int32(1), x.queryCount.Load())
				require.Equal(t, int32(1), y.queryCount.Load())
			}
			if hit {
				check(t, false)
			} else {
				controlledDNSModes(t, check)
			}
		})
	}
}

// Non-racing rule order must survive the reversed response completion order.
func TestDNSOrderedReadsPreferEarlierRule(t *testing.T) {
	t.Parallel()
	controlledDNSModes(t, func(t *testing.T, staged bool) {
		x := controlledDNSUpstream("x", "192.0.2.1")
		y := controlledDNSUpstream("y", "192.0.2.2")
		run := controlledDNSStart(t, staged, []option.DNSRule{
			evaluateRule("x", "x", false), evaluateRule("y", "y", false),
			respondRule("x", false, true), respondRule("y", false, true),
		}, []*controlledDNSTransport{x, y}, x, y)
		controlledDNSAwait(t, x.entered, "x entered")
		controlledDNSAwait(t, y.entered, "y entered")
		y.allow()
		controlledDNSAwait(t, y.callbackDone, "later ordered response")
		run.progressed(2, "race")
		run.pending(x)
		run.continueWalk()
		x.allow()
		run.answer("192.0.2.1")
		require.Equal(t, int32(1), x.queryCount.Load())
		require.Equal(t, int32(1), y.queryCount.Load())
	})
}

// Default must not enter before the race decision. A hit never queries it;
// a miss admits exactly one final query after X's natural response decision.
func TestDNSRaceBarrierProtectsDefaultRoute(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{true, false} {
		name := "miss"
		if hit {
			name = "hit"
		}
		t.Run(name, func(t *testing.T) {
			controlledDNSModes(t, func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				if !hit {
					x.rcode = mDNS.RcodeNameError
				}
				final := controlledDNSUpstream("final", "192.0.2.9")
				final.entryAfter = []*controlledDNSTransport{x}
				final.allow()
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "x", false), respondRule("x", true, true),
				}, []*controlledDNSTransport{x}, x, final)
				controlledDNSAwait(t, x.entered, "pending race entered")
				run.progressed(1, "action")
				run.pending(nil)
				require.Equal(t, int32(0), final.queryCount.Load())
				run.continueWalk()
				x.allow()
				if hit {
					run.answer("192.0.2.1")
					require.Equal(t, int32(0), final.queryCount.Load())
				} else {
					run.answer("192.0.2.9")
					require.Equal(t, int32(1), final.queryCount.Load())
				}
				require.Equal(t, int32(1), x.queryCount.Load())
			})
		})
	}
}

// A speculative response is already available at the real drain boundary,
// but may only be used after a miss; a hit suppresses that publication.
func TestDNSSpeculativeRoute(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{false, true} {
		name := "miss"
		if hit {
			name = "hit"
		}
		t.Run(name, func(t *testing.T) {
			controlledDNSModes(t, func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				if !hit {
					x.rcode = mDNS.RcodeNameError
				}
				final := controlledDNSUpstream("final", "192.0.2.9")
				final.immediate, final.waitFor = true, x.entered
				final.allow()
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "x", false), respondRule("x", true, true),
					routeRule("final", true),
				}, []*controlledDNSTransport{x}, x, final)
				controlledDNSAwait(t, x.entered, "pending race entered")
				final.inlineCompleted(t)
				require.True(t, final.replyIssued.Load())
				require.False(t, x.replyIssued.Load())
				run.pending(nil)
				run.continueWalk()
				x.allow()
				if hit {
					run.answer("192.0.2.1")
				} else {
					run.answer("192.0.2.9")
				}
				require.Equal(t, int32(1), x.queryCount.Load())
				require.Equal(t, int32(1), final.queryCount.Load())
			})
		})
	}
}

// A ready, matching non-racing Y cannot preempt pending race X. Both the
// hit and miss retain the complete entry plus a real matched/drain control.
func TestDNSNonRaceCommitWaitsForPendingRace(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{true, false} {
		name := "miss"
		if hit {
			name = "hit"
		}
		t.Run(name, func(t *testing.T) {
			controlledDNSModes(t, func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				if !hit {
					x.rcode = mDNS.RcodeNameError
				}
				y := controlledDNSUpstream("y", "192.0.2.2")
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "x", false), evaluateRule("y", "y", false),
					respondRule("x", true, true), respondRule("y", false, true),
				}, []*controlledDNSTransport{x, y}, x, y)
				controlledDNSAwait(t, x.entered, "x entered")
				controlledDNSAwait(t, y.entered, "y entered")
				y.allow()
				controlledDNSAwait(t, y.callbackDone, "matched non-racing response")
				run.progressed(3, "match")
				run.pending(nil)
				run.continueWalk()
				x.allow()
				if hit {
					run.answer("192.0.2.1")
				} else {
					run.answer("192.0.2.2")
				}
				require.Equal(t, int32(1), x.queryCount.Load())
				require.Equal(t, int32(1), y.queryCount.Load())
			})
		})
	}
}

// The bound speculative route must launch on Y readiness while X is held.
// The paired X hit keeps that same launched final response from winning.
func TestDNSSpeculativeRouteOnBindingRule(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{false, true} {
		name := "miss"
		if hit {
			name = "hit"
		}
		t.Run(name, func(t *testing.T) {
			controlledDNSModes(t, func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				if !hit {
					x.rcode = mDNS.RcodeNameError
				}
				y := controlledDNSUpstream("y", "192.0.2.2")
				final := controlledDNSUpstream("final", "192.0.2.9")
				final.immediate, final.waitFor = true, x.entered
				final.allow()
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "x", false), evaluateRule("y", "y", false),
					respondRule("x", true, true), controlledDNSBoundRoute(false, true),
				}, []*controlledDNSTransport{x, y}, x, y, final)
				controlledDNSAwait(t, x.entered, "x entered")
				controlledDNSAwait(t, y.entered, "binding y entered")
				y.allow()
				controlledDNSAwait(t, y.callbackDone, "binding y callback")
				run.pending(nil) // In staged mode this advances the bound route from await to drain.
				final.inlineCompleted(t)
				require.True(t, final.replyIssued.Load())
				require.False(t, x.replyIssued.Load())
				run.pending(nil) // Observe the actual arbiter with final ready and X still unavailable.
				run.continueWalk()
				x.allow()
				if hit {
					run.answer("192.0.2.1")
				} else {
					run.answer("192.0.2.9")
				}
				require.Equal(t, int32(1), x.queryCount.Load())
				require.Equal(t, int32(1), y.queryCount.Load())
				require.Equal(t, int32(1), final.queryCount.Load())
			})
		})
	}
}

// A ready rejected answer is not eligible. The real sweep disarms X while Y
// remains held, then Y is explicitly released and wins.
func TestDNSRaceSkipsRejectedResponse(t *testing.T) {
	t.Parallel()
	controlledDNSModes(t, func(t *testing.T, staged bool) {
		x := controlledDNSUpstream("x", "")
		x.rcode = mDNS.RcodeNameError
		y := controlledDNSUpstream("y", "192.0.2.2")
		run := controlledDNSStart(t, staged, []option.DNSRule{
			evaluateRule("x", "x", false), evaluateRule("y", "y", false),
			respondRule("x", true, true), respondRule("y", true, true),
		}, []*controlledDNSTransport{x, y}, x, y)
		controlledDNSAwait(t, x.entered, "rejected upstream entered")
		controlledDNSAwait(t, y.entered, "eligible upstream entered")
		x.allow()
		controlledDNSAwait(t, x.callbackDone, "rejected response callback")
		run.progressed(2, "match")
		run.pending(nil)
		run.continueWalk()
		y.allow()
		run.answer("192.0.2.2")
		require.Equal(t, int32(1), x.queryCount.Load())
		require.Equal(t, int32(1), y.queryCount.Load())
	})
}

// The anonymous X and named Y remain actual compiled logical-AND bindings.
// Y alone cannot admit the logical rule; an X miss leaves Z eligible later.
func TestDNSLogicalRace(t *testing.T) {
	t.Parallel()
	for _, hit := range []bool{true, false} {
		name := "logical-miss"
		if hit {
			name = "logical-hit"
		}
		t.Run(name, func(t *testing.T) {
			controlledDNSModes(t, func(t *testing.T, staged bool) {
				x := controlledDNSUpstream("x", "192.0.2.1")
				if !hit {
					x.rcode = mDNS.RcodeNameError
				}
				y := controlledDNSUpstream("y", "192.0.2.2")
				z := controlledDNSUpstream("z", "192.0.2.3")
				required := []*controlledDNSTransport{x, y}
				if !hit {
					required = append(required, z)
				}
				run := controlledDNSStart(t, staged, []option.DNSRule{
					evaluateRule("x", "", false), evaluateRule("y", "y", false),
					evaluateRule("z", "z", false), controlledDNSLogicalRule(),
					respondRule("z", true, true),
				}, required, x, y, z)
				controlledDNSAwait(t, x.entered, "anonymous x entered")
				controlledDNSAwait(t, y.entered, "named y entered")
				controlledDNSAwait(t, z.entered, "competitor z entered")
				y.allow()
				controlledDNSAwait(t, y.callbackDone, "only named binding ready")
				run.progressed(3, "action")
				run.progressed(4, "action")
				run.pending(nil)
				if hit {
					run.continueWalk()
					x.allow()
					run.answer("192.0.2.1")
					z.heldThroughResult(t)
				} else {
					x.allow()
					controlledDNSAwait(t, x.callbackDone, "anonymous binding miss")
					run.pending(nil)
					run.continueWalk()
					z.allow()
					run.answer("192.0.2.3")
				}
				require.Equal(t, int32(1), x.queryCount.Load())
				require.Equal(t, int32(1), y.queryCount.Load())
				require.Equal(t, int32(1), z.queryCount.Load())
			})
		})
	}
}
