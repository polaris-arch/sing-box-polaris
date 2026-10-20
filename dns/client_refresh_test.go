package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func refreshTestClient(ctx context.Context, store *correctnessCacheStore) *Client {
	client := NewClient(ClientOptions{Context: ctx, Timeout: 5*time.Second, OptimisticTimeout: time.Hour, Logger: log.NewNOPFactory().Logger()})
	client.Start()
	if store != nil { client.dnsCache = store }
	return client
}

func refreshTestAwait(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select { case <-signal: case <-time.After(5*time.Second): t.Fatal("refresh barrier timed out") }
}

func refreshTestDrain(t *testing.T, client *Client) {
	t.Helper()
	client.stopBackgroundRefreshes()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.waitBackgroundRefreshes(ctx))
}

func refreshTestPending(t *testing.T, client *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, client.waitBackgroundRefreshes(ctx), context.Canceled)
}

func refreshTestStale(t *testing.T, client *Client, store *correctnessCacheStore, transport adapter.DNSTransport, question *mDNS.Msg) dnsCacheKey {
	t.Helper()
	key := client.newCacheKey(transport, question.Question[0], question, adapter.DNSQueryOptions{})
	response := FixedResponse(question.Id, question.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
	packed, err := response.Pack()
	require.NoError(t, err)
	require.NoError(t, store.SaveDNSCache(key.persistentName(), key.Name, key.Qtype, packed, time.Now().Add(-time.Minute)))
	return key
}

func TestRefreshNestedLineageSameAndCrossClient(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(map[bool]string{false:"same", true:"cross"}[cross], func(t *testing.T) {
			firstStore, otherStore, candidateStore := &correctnessCacheStore{}, &correctnessCacheStore{}, &correctnessCacheStore{}
			first := refreshTestClient(context.Background(), firstStore)
			receiver, receiverStore := first, firstStore
			if cross { receiver, receiverStore = refreshTestClient(context.Background(), otherStore), otherStore }
			candidate := refreshTestClient(context.Background(), candidateStore)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }); refreshTestDrain(t, first); refreshTestDrain(t, receiver); refreshTestDrain(t, candidate) })
			question := correctnessQuestion(mDNS.TypeA)
			nested := &policyTestTransport{tag:"nested", exchange:func(ctx context.Context, message *mDNS.Msg)(*mDNS.Msg,error) {
				if dnsRefreshLineage(ctx) != first.refreshOwner { return nil, errors.New("nested lineage changed") }
				close(entered)
				<-release // Ignore cancellation so Wait must measure actual return.
				return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")},60),nil
			}}
			nestedKey := refreshTestStale(t, receiver, receiverStore, nested, question)
			outer := &policyTestTransport{tag:"outer", exchange:func(ctx context.Context, message *mDNS.Msg)(*mDNS.Msg,error) {
				return receiver.Exchange(ctx, nested, message, adapter.DNSQueryOptions{},nil)
			}}
			outerKey := refreshTestStale(t, first, firstStore, outer, question)
			// A foreground caller is already canceled immediately after the stale
			// response; that waiter lifetime must not cancel background work.
			foreground, cancel := context.WithCancel(context.Background())
			_, err := first.Exchange(foreground, outer, question, adapter.DNSQueryOptions{},nil)
			cancel()
			require.NoError(t,err)
			refreshTestAwait(t,entered)
			// This reused helper observes only outer application cleanup. Overall
			// completion is proved separately by the actual lineage Wait below.
			require.NoError(t,dependenciesWaitRefresh(first,outerKey))
			first.stopBackgroundRefreshes()
			refreshTestPending(t,first)
			if cross { refreshTestDrain(t,receiver); refreshTestPending(t,first) }
			require.Zero(t,candidateStore.writeCount())
			once.Do(func(){close(release)})
			refreshTestDrain(t,first)
			_, loaded := receiver.backgroundRefresh.Load(nestedKey)
			require.False(t,loaded)
			if cross { require.Equal(t,2,receiverStore.writeCount()) } else { require.Equal(t,4,firstStore.writeCount()) }
			require.Zero(t,candidateStore.writeCount())
		})
	}
}

func TestRefreshDuplicateAndSealedNestedLeaveNoWork(t *testing.T) {
	store := &correctnessCacheStore{}
	client := refreshTestClient(context.Background(),store)
	entered, release := make(chan struct{}),make(chan struct{})
	var once sync.Once
	t.Cleanup(func(){once.Do(func(){close(release)});refreshTestDrain(t,client)})
	question := correctnessQuestion(mDNS.TypeA)
	transport := &policyTestTransport{tag:"duplicate",exchange:func(ctx context.Context,message *mDNS.Msg)(*mDNS.Msg,error){close(entered);<-release;return nil,errors.New("transport failure")}}
	key := refreshTestStale(t,client,store,transport,question)
	_,err := client.Exchange(context.Background(),transport,question,adapter.DNSQueryOptions{},nil)
	require.NoError(t,err);refreshTestAwait(t,entered)
	for range 3 { _,err=client.Exchange(context.Background(),transport,question,adapter.DNSQueryOptions{},nil);require.NoError(t,err) }
	client.stopBackgroundRefreshes()
	marked := context.WithValue(context.Background(),dnsRefreshLineageKey{},client.refreshOwner)
	newQuestion := question.Copy();newQuestion.Question[0].Name="sealed.example."
	newKey := client.newCacheKey(transport,newQuestion.Question[0],newQuestion,adapter.DNSQueryOptions{})
	client.backgroundRefreshDNS(marked,transport,newKey,newQuestion,adapter.DNSQueryOptions{},nil)
	_,loaded := client.backgroundRefresh.Load(newKey);require.False(t,loaded)
	refreshTestPending(t,client)
	once.Do(func(){close(release)});refreshTestDrain(t,client)
	_,loaded=client.backgroundRefresh.Load(key);require.False(t,loaded)
	require.EqualValues(t,1,transport.calls.Load())
}

func TestRefreshMarkedAsyncWaitsForCallbackAndRejectsSynchronously(t *testing.T) {
	client := refreshTestClient(context.Background(),nil)
	ctx, releaseParent, admitted := client.admitBackgroundRefresh(context.Background())
	require.True(t,admitted)
	callbackEntered, releaseCallback, callbackReturned := make(chan struct{}),make(chan struct{}),make(chan struct{})
	var once sync.Once
	t.Cleanup(func(){once.Do(func(){close(releaseCallback)});releaseParent();refreshTestDrain(t,client)})
	transport := policyReply("callback",0,0,"192.0.2.1")
	client.ExchangeAsync(ctx,transport,correctnessQuestion(mDNS.TypeA),adapter.DNSQueryOptions{DisableCache:true},nil,func(*mDNS.Msg,error){client.stopBackgroundRefreshes();close(callbackEntered);<-releaseCallback;close(callbackReturned)})
	refreshTestAwait(t,callbackEntered)
	releaseParent()
	refreshTestPending(t,client)
	called := false
	client.ExchangeAsync(ctx,transport,correctnessQuestion(mDNS.TypeA),adapter.DNSQueryOptions{},nil,func(_ *mDNS.Msg,err error){called=true;require.ErrorIs(t,err,context.Canceled)})
	require.True(t,called)
	once.Do(func(){close(releaseCallback)})
	refreshTestAwait(t,callbackReturned);refreshTestDrain(t,client)
	// Stop applies only to refresh work, not ordinary foreground operations.
	foreground := make(chan struct{})
	client.ExchangeAsync(context.Background(),transport,correctnessQuestion(mDNS.TypeAAAA),adapter.DNSQueryOptions{DisableCache:true},nil,func(_ *mDNS.Msg,err error){if err==nil {close(foreground)}})
	refreshTestAwait(t,foreground)
}

func TestRefreshLineageThroughPolicyAndLookupFamilies(t *testing.T) {
	seen := make(chan context.Context,4)
	transport := &policyTestTransport{tag:"policy-leaf",exchange:func(ctx context.Context,message *mDNS.Msg)(*mDNS.Msg,error){
		if dnsRefreshLineage(ctx)==nil {return nil,errors.New("lineage missing")}
		seen<-ctx
		address := netip.MustParseAddr("192.0.2.1")
		if message.Question[0].Qtype == mDNS.TypeAAAA { address = netip.MustParseAddr("2001:db8::1") }
		return FixedResponse(message.Id,message.Question[0],[]netip.Addr{address},60),nil
	}}
	router := policyRouter(t,policyTestRules(t,[]string{"policy-leaf"}),transport)
	client := router.client.(*Client)
	ctx, release, admitted := client.admitBackgroundRefresh(context.Background())
	require.True(t,admitted)
	t.Cleanup(func(){release();refreshTestDrain(t,client)})
	ctx = adapter.OverrideContext(adapter.WithContext(ctx,&adapter.InboundContext{}))
	_,err := router.Exchange(ctx,correctnessQuestion(mDNS.TypeA),policyOptions(5*time.Second))
	require.NoError(t,err)
	select {case observed := <-seen: require.Same(t,client.refreshOwner,dnsRefreshLineage(observed));default:t.Fatal("policy evaluate did not preserve lineage")}
	_,_ = client.Lookup(ctx,transport,"families.example",adapter.DNSQueryOptions{Strategy:C.DomainStrategyAsIS,Timeout:5*time.Second,DisableCache:true},nil)
	for range 2 {select {case observed := <-seen: require.Same(t,client.refreshOwner,dnsRefreshLineage(observed));default:t.Fatal("lookup family did not preserve lineage")}}
	release();refreshTestDrain(t,client)
}

func TestRefreshPolicyCancellationDoesNotCompleteBlockedEvaluate(t *testing.T) {
	entered, releaseLeaf, parentDone := make(chan struct{}),make(chan struct{}),make(chan struct{})
	var once sync.Once
	transport := &policyTestTransport{tag:"blocked-leaf",exchange:func(ctx context.Context,message *mDNS.Msg)(*mDNS.Msg,error){
		close(entered)
		<-releaseLeaf
		return FixedResponse(message.Id,message.Question[0],[]netip.Addr{netip.MustParseAddr("192.0.2.1")},60),nil
	}}
	router := policyRouter(t,policyTestRules(t,[]string{"blocked-leaf"}),transport)
	client := router.client.(*Client)
	ctx,releaseParent,admitted := client.admitBackgroundRefresh(context.Background())
	require.True(t,admitted)
	t.Cleanup(func(){
		once.Do(func(){close(releaseLeaf)})
		client.stopBackgroundRefreshes()
		refreshTestAwait(t,parentDone)
		releaseParent()
		refreshTestDrain(t,client)
	})
	go func(){defer close(parentDone);defer releaseParent();_,_=router.Exchange(ctx,correctnessQuestion(mDNS.TypeA),policyOptions(5*time.Second))}()
	refreshTestAwait(t,entered)
	client.stopBackgroundRefreshes()
	refreshTestAwait(t,parentDone) // Canceled future returned, leaf invocation did not.
	refreshTestPending(t,client)
	once.Do(func(){close(releaseLeaf)})
	refreshTestDrain(t,client)
}

func TestRefreshContextUsesReceivingHostAndLineageCancellation(t *testing.T) {
	first := refreshTestClient(context.Background(),nil)
	host,cancelHost := context.WithCancel(context.Background())
	defer cancelHost()
	receiver := refreshTestClient(host,nil)
	caller,cancelCaller := context.WithCancel(context.Background())
	caller = context.WithValue(caller,dnsRefreshLineageKey{},first.refreshOwner)
	ctx,release,admitted := receiver.admitBackgroundRefresh(caller)
	require.True(t,admitted)
	defer release()
	defer refreshTestDrain(t,receiver)
	// Cleanup order must release the inherited operation before joining first.
	t.Cleanup(func(){release();refreshTestDrain(t,first)})
	cancelCaller()
	require.NoError(t,ctx.Err())
	cancelHost()
	refreshTestAwait(t,ctx.Done())
	require.Same(t,first.refreshOwner,dnsRefreshLineage(ctx))
	first.stopBackgroundRefreshes()
	refreshTestPending(t,first)
	release()
	refreshTestDrain(t,first)
}
