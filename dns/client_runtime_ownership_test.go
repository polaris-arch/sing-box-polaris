package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	mDNS "github.com/miekg/dns"
)

type runtimeOwnershipView struct { adapter.RuntimeView; identity adapter.RuntimeRevision }
func (v *runtimeOwnershipView) Identity() adapter.RuntimeRevision { return v.identity }

func operationTestOwner(t *testing.T, sequence uint64, deps []adapter.RuntimeResourceLease, closeFn func() error) (*runtimegraph.ResourceOwner, adapter.RuntimeResourceLease) {
	t.Helper()
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "dns-operations", Sequence: sequence}, deps, closeFn)
	if err != nil { t.Fatal(err) }
	construction, err := owner.Acquire()
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { owner.Seal(); construction.Release() })
	return owner, construction
}
func operationTestClient(owner *runtimegraph.ResourceOwner) *Client {
	ctx := adapter.ContextWithRuntimeResourceSource(owner.Context(), owner)
	client := NewClient(ClientOptions{Context: ctx, DisableCache: true, Logger: log.NewNOPFactory().Logger()})
	client.Start()
	return client
}
func operationTestClosed(t *testing.T, owner *runtimegraph.ResourceOwner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.WaitClosed(ctx); err != nil { t.Fatal(err) }
}
func operationTestPending(t *testing.T, owner *runtimegraph.ResourceOwner) {
	t.Helper()
	select { case <-owner.Closed(): t.Fatal("actual receiving resource closed early"); default: }
}

func TestReceivingClientForeignLineageActualBodyAndCallback(t *testing.T) {
	ownerA, constructionA := operationTestOwner(t, 1, nil, nil)
	ownerB, constructionB := operationTestOwner(t, 2, nil, nil)
	first, receiver := operationTestClient(ownerA), operationTestClient(ownerB)
	store, err := runtimegraph.NewStore("dns-operations")
	if err != nil { t.Fatal(err) }
	graph, err := runtimegraph.NewGraph(&runtimeOwnershipView{identity: adapter.RuntimeRevision{Incarnation: "dns-operations", Revision: 1}}, []adapter.RuntimeResourceLease{constructionA})
	if err != nil { t.Fatal(err) }
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: "dns-operations"}, graph); err != nil { t.Fatal(err) }
	root, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	ctx, releaseParent, admitted := first.admitBackgroundRefresh(adapter.ContextWithRuntimeLease(context.Background(), root))
	if !admitted { t.Fatal("parent refresh not admitted") }
	bodyEntered, bodyRelease := make(chan struct{}), make(chan struct{})
	callbackEntered, callbackRelease, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var bodyOnce, callbackOnce sync.Once
	t.Cleanup(func() {
		bodyOnce.Do(func() { close(bodyRelease) }); callbackOnce.Do(func() { close(callbackRelease) })
		releaseParent(); root.Release(); store.Seal(); constructionA.Release(); constructionB.Release()
		first.stopBackgroundRefreshes(); receiver.stopBackgroundRefreshes(); ownerA.Seal(); ownerB.Seal()
		refreshTestAwait(t, returned); refreshTestDrain(t, first); operationTestClosed(t, ownerA); operationTestClosed(t, ownerB)
	})
	transport := &policyTestTransport{tag: "blocked", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		if dnsRefreshLineage(ctx) != first.refreshOwner { return nil, errors.New("foreign lineage changed") }
		if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, ownerB.ID()); !ok { return nil, errors.New("receiver reservation missing") }
		close(bodyEntered); <-bodyRelease
		response := new(mDNS.Msg); response.SetReply(message); return response, nil
	}}
	go receiver.ExchangeAsync(ctx, transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{DisableCache: true}, nil, func(*mDNS.Msg, error) {
		close(callbackEntered); <-callbackRelease; close(returned)
	})
	refreshTestAwait(t, bodyEntered)
	releaseParent(); root.Release(); store.Seal(); constructionA.Release(); constructionB.Release()
	ownerA.Seal(); ownerB.Seal()
	// The receiver's own lineage is empty, but the actual receiving operation
	// belongs to another lineage and must still pin both resources and graph A.
	refreshTestDrain(t, receiver)
	operationTestPending(t, ownerA); operationTestPending(t, ownerB)
	bodyOnce.Do(func() { close(bodyRelease) })
	refreshTestAwait(t, callbackEntered)
	operationTestPending(t, ownerA); operationTestPending(t, ownerB)
	callbackOnce.Do(func() { close(callbackRelease) })
	refreshTestAwait(t, returned)
	first.stopBackgroundRefreshes(); refreshTestDrain(t, first)
	operationTestClosed(t, ownerA); operationTestClosed(t, ownerB)
}

type synchronousTailTransport struct {
	adapter.DNSTransport
	callbackReturned chan struct{}
	tailRelease chan struct{}
}
func (t *synchronousTailTransport) Tag() string { return "sync-tail" }
func (t *synchronousTailTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	response := new(mDNS.Msg); response.SetReply(message)
	callback(response, nil)
	close(t.callbackReturned)
	<-t.tailRelease
}
func TestClientAsyncRetainsInvocationAfterSynchronousCallback(t *testing.T) {
	owner, construction := operationTestOwner(t, 1, nil, nil)
	client := operationTestClient(owner)
	transport := &synchronousTailTransport{callbackReturned: make(chan struct{}), tailRelease: make(chan struct{})}
	returned := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(transport.tailRelease) }); refreshTestAwait(t, returned); client.stopBackgroundRefreshes(); owner.Seal(); construction.Release(); operationTestClosed(t, owner) })
	go func() { defer close(returned); client.ExchangeAsync(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{DisableCache: true}, nil, func(*mDNS.Msg, error) {}) }()
	refreshTestAwait(t, transport.callbackReturned)
	owner.Seal(); construction.Release()
	operationTestPending(t, owner)
	once.Do(func() { close(transport.tailRelease) })
	refreshTestAwait(t, returned); operationTestClosed(t, owner)
}

func TestClientReleasedContinuationCannotBecomeNewRoot(t *testing.T) {
	owner, construction := operationTestOwner(t, 1, nil, nil)
	client := operationTestClient(owner)
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), construction)
	construction.Release()
	transport := policyReply("never", 0, 0, "192.0.2.1")
	_, err := client.Exchange(ctx, transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
	if !errors.Is(err, runtimegraph.ErrLeaseReleased) { t.Fatalf("released continuation admitted: %v", err) }
	if transport.calls.Load() != 0 { t.Fatal("stale pointer reached transport") }
	owner.Seal(); operationTestClosed(t, owner)
}

func TestRuntimeOperationRetainsInheritedForeignReceiver(t *testing.T) {
	first, firstLease := operationTestOwner(t, 1, nil, nil)
	second, secondLease := operationTestOwner(t, 2, nil, nil)
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), firstLease)
	bound, release, err := adapter.AcquireRuntimeOperation(ctx, second)
	if err != nil { t.Fatal(err) }
	t.Cleanup(release)
	firstLease.Release(); secondLease.Release(); first.Seal(); second.Seal()
	operationTestPending(t, first); operationTestPending(t, second)
	for _, owner := range []*runtimegraph.ResourceOwner{first, second} { if _, ok := adapter.RuntimeResourceLeaseFromContext(bound, owner.ID()); !ok { t.Fatal("inherited receiver missing") } }
	release(); operationTestClosed(t, first); operationTestClosed(t, second)
}

func TestRuntimeLookupPairJoinsActualWorkersAfterCancellation(t *testing.T) {
	owner, construction := operationTestOwner(t, 1, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{}, 2); release := make(chan struct{}); returned := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	t.Cleanup(func() { cancel(); once.Do(func() { close(release) }); refreshTestAwait(t, returned); owner.Seal(); construction.Release(); operationTestClosed(t, owner) })
	go func() {
		defer close(returned)
		_, _, _ = runRuntimeLookupPair(ctx, owner, func(context.Context, uint16) ([]netip.Addr, error) { calls.Add(1); entered <- struct{}{}; <-release; return nil, context.Canceled })
	}()
	for range 2 { select { case <-entered: case <-time.After(5*time.Second): t.Fatal("family not launched") } }
	cancel(); owner.Seal(); construction.Release()
	operationTestPending(t, owner)
	select { case <-returned: t.Fatal("waiter returned before actual family workers"); default: }
	once.Do(func() { close(release) }); refreshTestAwait(t, returned); operationTestClosed(t, owner)
	if calls.Load() != 2 { t.Fatal("wrong family count") }
}

func TestForeignClientMultiHopSealedTransportContinuation(t *testing.T) {
	transportOwner, transportConstruction := operationTestOwner(t, 3, nil, nil)
	middleOwner, middleConstruction := operationTestOwner(t, 2, []adapter.RuntimeResourceLease{transportConstruction}, nil)
	clientOwner, clientConstruction := operationTestOwner(t, 1, []adapter.RuntimeResourceLease{middleConstruction}, nil)
	// This admitted foreign Client B invocation need not appear in the caller's
	// graph. Its actual receiver continuation carries the captured dependency DAG.
	foreignOwner, foreignConstruction := operationTestOwner(t, 4, nil, nil)
	store, err := runtimegraph.NewStore("dns-operations")
	if err != nil { t.Fatal(err) }
	graph, err := runtimegraph.NewGraph(&runtimeOwnershipView{identity: adapter.RuntimeRevision{Incarnation: "dns-operations", Revision: 1}}, []adapter.RuntimeResourceLease{foreignConstruction})
	if err != nil { t.Fatal(err) }
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: "dns-operations"}, graph); err != nil { t.Fatal(err) }
	root, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { root.Release(); store.Seal(); foreignOwner.Seal(); foreignConstruction.Release() })
	clientCtx, releaseClient, err := adapter.AcquireRuntimeOperation(adapter.ContextWithRuntimeLease(context.Background(), root), clientOwner)
	if err != nil { t.Fatal(err) }
	t.Cleanup(releaseClient)
	root.Release(); store.Seal(); foreignOwner.Seal(); foreignConstruction.Release()
	clientConstruction.Release(); middleConstruction.Release(); transportConstruction.Release()
	clientOwner.Seal(); middleOwner.Seal(); transportOwner.Seal()
	transportCtx, releaseTransport, err := adapter.AcquireRuntimeOperation(clientCtx, transportOwner)
	if err != nil { t.Fatalf("captured sealed transport rejected: %v", err) }
	t.Cleanup(releaseTransport)
	if _, ok := adapter.RuntimeResourceLeaseFromContext(transportCtx, transportOwner.ID()); !ok { t.Fatal("actual transport continuation missing") }
	releaseClient()
	operationTestPending(t, clientOwner); operationTestPending(t, middleOwner); operationTestPending(t, transportOwner)
	releaseTransport()
	operationTestClosed(t, clientOwner); operationTestClosed(t, middleOwner); operationTestClosed(t, transportOwner); operationTestClosed(t, foreignOwner)
	if _, _, err := adapter.AcquireRuntimeOperation(clientCtx, transportOwner); !errors.Is(err, runtimegraph.ErrLeaseReleased) { t.Fatalf("expired source admitted: %v", err) }
}

func TestResourceContinuationRejectsMissingAndForeignIDs(t *testing.T) {
	owner, construction := operationTestOwner(t, 1, nil, nil)
	continuation, ok := construction.(adapter.RuntimeResourceContinuation)
	if !ok { t.Fatal("typed dependency continuation unavailable") }
	for _, id := range []adapter.RuntimeResourceID{{Incarnation: "dns-operations", Sequence: 99}, {Incarnation: "other-run", Sequence: 1}} {
		if lease, err := continuation.RetainResource(id); !errors.Is(err, runtimegraph.ErrResourceNotMember) || lease != nil { t.Fatalf("unbound resource admitted: %v %v", lease, err) }
	}
	construction.Release(); owner.Seal(); operationTestClosed(t, owner)
	if lease, err := continuation.RetainResource(owner.ID()); !errors.Is(err, runtimegraph.ErrLeaseReleased) || lease != nil { t.Fatal("released source resurrected") }
}

func TestRuntimeRefreshDuplicateAndSealedRootLeaveNoReservations(t *testing.T) {
	owner, construction := operationTestOwner(t, 1, nil, nil)
	store := &correctnessCacheStore{}
	client := refreshTestClient(adapter.ContextWithRuntimeResourceSource(owner.Context(), owner), store)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	transport := &policyTestTransport{tag: "refresh", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		close(entered); <-release; return nil, errors.New("refresh failure")
	}}
	question := correctnessQuestion(mDNS.TypeA)
	key := refreshTestStale(t, client, store, transport, question)
	t.Cleanup(func() { once.Do(func() { close(release) }); client.stopBackgroundRefreshes(); owner.Seal(); construction.Release(); refreshTestDrain(t, client); operationTestClosed(t, owner) })
	client.backgroundRefreshDNS(context.Background(), transport, key, question, adapter.DNSQueryOptions{}, nil)
	refreshTestAwait(t, entered)
	for range 3 { client.backgroundRefreshDNS(context.Background(), transport, key, question, adapter.DNSQueryOptions{}, nil) }
	owner.Seal(); construction.Release()
	newKey := key; newKey.Name = "sealed.example."
	client.backgroundRefreshDNS(context.Background(), transport, newKey, question, adapter.DNSQueryOptions{}, nil)
	if _, loaded := client.backgroundRefresh.Load(newKey); loaded { t.Fatal("sealed receiver published refresh key") }
	operationTestPending(t, owner)
	once.Do(func() { close(release) }); refreshTestDrain(t, client); operationTestClosed(t, owner)
	if transport.calls.Load() != 1 { t.Fatal("duplicate/sealed refresh launched work") }
}

func TestRuntimeNestedRefreshKeepsReceivingStoresAndForeignLineage(t *testing.T) {
	ownerA, constructionA := operationTestOwner(t, 1, nil, nil)
	ownerB, constructionB := operationTestOwner(t, 2, nil, nil)
	storeA, storeB := &correctnessCacheStore{}, &correctnessCacheStore{}
	first := refreshTestClient(adapter.ContextWithRuntimeResourceSource(ownerA.Context(), ownerA), storeA)
	receiver := refreshTestClient(adapter.ContextWithRuntimeResourceSource(ownerB.Context(), ownerB), storeB)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); first.stopBackgroundRefreshes(); receiver.stopBackgroundRefreshes(); ownerA.Seal(); ownerB.Seal(); constructionA.Release(); constructionB.Release(); refreshTestDrain(t, first); refreshTestDrain(t, receiver); operationTestClosed(t, ownerA); operationTestClosed(t, ownerB) })
	question := correctnessQuestion(mDNS.TypeA)
	nested := &policyTestTransport{tag: "nested", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		if dnsRefreshLineage(ctx) != first.refreshOwner { return nil, errors.New("foreign lineage lost") }
		if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, ownerB.ID()); !ok { return nil, errors.New("receiving Client B missing") }
		close(entered); <-release
		return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")}, 60), nil
	}}
	refreshTestStale(t, receiver, storeB, nested, question)
	outer := &policyTestTransport{tag: "outer", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) { return receiver.Exchange(ctx, nested, message, adapter.DNSQueryOptions{}, nil) }}
	outerKey := refreshTestStale(t, first, storeA, outer, question)
	foreground, cancelForeground := context.WithCancel(context.Background())
	_, err := first.Exchange(foreground, outer, question, adapter.DNSQueryOptions{}, nil)
	cancelForeground()
	if err != nil { t.Fatal(err) }
	refreshTestAwait(t, entered)
	if err := dependenciesWaitRefresh(first, outerKey); err != nil { t.Fatal(err) }
	refreshTestDrain(t, receiver) // B's own lineage is empty; A owns nested work.
	ownerA.Seal(); ownerB.Seal(); constructionA.Release(); constructionB.Release()
	operationTestPending(t, ownerA); operationTestPending(t, ownerB)
	once.Do(func() { close(release) }); refreshTestDrain(t, first)
	operationTestClosed(t, ownerA); operationTestClosed(t, ownerB)
	if storeA.writeCount() != 2 || storeB.writeCount() != 2 { t.Fatal("nested refresh wrote the wrong receiver store") }
}

func TestClientPublicExchangeContinuesMultiHopAfterSeal(t *testing.T) {
	leafOwner, leafConstruction := operationTestOwner(t, 3, nil, nil)
	middleOwner, middleConstruction := operationTestOwner(t, 2, []adapter.RuntimeResourceLease{leafConstruction}, nil)
	clientOwner, clientConstruction := operationTestOwner(t, 1, []adapter.RuntimeResourceLease{middleConstruction}, nil)
	foreignOwner, foreignConstruction := operationTestOwner(t, 4, nil, nil)
	store, err := runtimegraph.NewStore("dns-operations")
	if err != nil { t.Fatal(err) }
	graph, err := runtimegraph.NewGraph(&runtimeOwnershipView{identity: adapter.RuntimeRevision{Incarnation: "dns-operations", Revision: 1}}, []adapter.RuntimeResourceLease{foreignConstruction})
	if err != nil { t.Fatal(err) }
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: "dns-operations"}, graph); err != nil { t.Fatal(err) }
	root, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	client := operationTestClient(clientOwner)
	entered, continueLeaf, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var exchangeErr error
	t.Cleanup(func() {
		once.Do(func() { close(continueLeaf) }); root.Release(); store.Seal(); client.stopBackgroundRefreshes()
		for _, owner := range []*runtimegraph.ResourceOwner{clientOwner, middleOwner, leafOwner, foreignOwner} { owner.Seal() }
		for _, lease := range []adapter.RuntimeResourceLease{clientConstruction, middleConstruction, leafConstruction, foreignConstruction} { lease.Release() }
		refreshTestAwait(t, returned)
		for _, owner := range []*runtimegraph.ResourceOwner{clientOwner, middleOwner, leafOwner, foreignOwner} { operationTestClosed(t, owner) }
	})
	leaf := &policyTestTransport{tag: "leaf", exchange: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		close(entered); <-continueLeaf
		bound, release, err := adapter.AcquireRuntimeOperation(ctx, leafOwner)
		if err != nil { return nil, err }
		defer release()
		if _, ok := adapter.RuntimeResourceLeaseFromContext(bound, leafOwner.ID()); !ok { return nil, errors.New("transitive leaf not retained") }
		return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
	}}
	go func() { defer close(returned); _, exchangeErr = client.Exchange(adapter.ContextWithRuntimeLease(context.Background(), root), leaf, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{DisableCache: true}, nil) }()
	refreshTestAwait(t, entered)
	root.Release(); store.Seal()
	for _, owner := range []*runtimegraph.ResourceOwner{clientOwner, middleOwner, leafOwner, foreignOwner} { owner.Seal() }
	for _, lease := range []adapter.RuntimeResourceLease{clientConstruction, middleConstruction, leafConstruction, foreignConstruction} { lease.Release() }
	for _, owner := range []*runtimegraph.ResourceOwner{clientOwner, middleOwner, leafOwner, foreignOwner} { operationTestPending(t, owner) }
	once.Do(func() { close(continueLeaf) }); refreshTestAwait(t, returned)
	if exchangeErr != nil { t.Fatalf("actual Client continuation rejected sealed captured transport: %v", exchangeErr) }
	for _, owner := range []*runtimegraph.ResourceOwner{clientOwner, middleOwner, leafOwner, foreignOwner} { operationTestClosed(t, owner) }
}

func TestRuntimeOwnershipCopyPreservesReceiverValuesAndCallerCancellation(t *testing.T) {
	type receiverKey struct{}
	owner, construction := operationTestOwner(t, 1, nil, nil)
	caller, cancelCaller := context.WithCancel(context.Background())
	bound, release, err := adapter.AcquireRuntimeOperation(caller, owner)
	if err != nil { t.Fatal(err) }
	defer release()
	cancelCaller()
	if bound.Err() != context.Canceled { t.Fatal("receiving invocation lost caller cancellation") }
	receiver, cancelReceiver := context.WithCancel(context.WithValue(context.Background(), receiverKey{}, "private receiver"))
	defer cancelReceiver()
	copied := adapter.ContextWithRuntimeOwnership(receiver, bound)
	if copied.Err() != nil || copied.Value(receiverKey{}) != "private receiver" { t.Fatal("ownership copy replaced receiving context") }
	if _, ok := adapter.RuntimeResourceLeaseFromContext(copied, owner.ID()); !ok { t.Fatal("borrowed receiver ownership missing") }
	cancelReceiver()
	if copied.Err() != context.Canceled { t.Fatal("ownership copy detached operational cancellation") }
	owner.Seal(); construction.Release(); release(); operationTestClosed(t, owner)
}

func TestRuntimeOperationMissingContinuationRejectsSealedReceiver(t *testing.T) {
	first, firstLease := operationTestOwner(t, 1, nil, nil)
	missing, missingLease := operationTestOwner(t, 2, nil, nil)
	missing.Seal()
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), firstLease)
	if bound, release, err := adapter.AcquireRuntimeOperation(ctx, missing); !errors.Is(err, runtimegraph.ErrResourceSealed) || bound != nil || release != nil { t.Fatalf("unrelated source admitted sealed receiver: %v", err) }
	first.Seal(); firstLease.Release(); missingLease.Release()
	operationTestClosed(t, first); operationTestClosed(t, missing)
}
