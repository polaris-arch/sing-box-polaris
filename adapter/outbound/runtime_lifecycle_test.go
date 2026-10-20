package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type lifecycleSource struct { mu sync.Mutex; refs int; sealed bool; retiring chan struct{}; sequence uint64; dependencies map[adapter.RuntimeResourceID]*lifecycleSource }
type lifecycleLease struct { owner *lifecycleSource; released bool }
func newLifecycleSource() *lifecycleSource { return &lifecycleSource{retiring: make(chan struct{}), sequence: 1} }
func (s *lifecycleSource) ID() adapter.RuntimeResourceID { return adapter.RuntimeResourceID{Incarnation: "carrier-test", Sequence: s.sequence} }
func (s *lifecycleSource) Acquire() (adapter.RuntimeResourceLease, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.sealed { return nil, net.ErrClosed }
	s.refs++; return &lifecycleLease{owner: s}, nil
}
func (s *lifecycleSource) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.refs }
func (s *lifecycleSource) seal() { s.mu.Lock(); defer s.mu.Unlock(); s.sealed = true; close(s.retiring) }
func (l *lifecycleLease) ID() adapter.RuntimeResourceID { return l.owner.ID() }
func (l *lifecycleLease) Retiring() <-chan struct{} { return l.owner.retiring }
func (l *lifecycleLease) Fork() (adapter.RuntimeResourceLease, error) {
	l.owner.mu.Lock(); defer l.owner.mu.Unlock()
	if l.released { return nil, net.ErrClosed }
	l.owner.refs++; return &lifecycleLease{owner: l.owner}, nil
}
func (l *lifecycleLease) Release() {
	l.owner.mu.Lock(); defer l.owner.mu.Unlock()
	if l.released { return }; l.released = true; l.owner.refs--
}

type lifecycleConn struct {
	readEntered, readContinue chan struct{}
	closeEntered, closeContinue chan struct{}
	closeErr error
	closePanic bool
	closes atomic.Int32
}
func (c *lifecycleConn) Read([]byte) (int, error) {
	if c.readEntered != nil { close(c.readEntered); <-c.readContinue }
	return 0, net.ErrClosed
}
func (*lifecycleConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *lifecycleConn) Close() error {
	c.closes.Add(1)
	if c.closeEntered != nil { close(c.closeEntered); <-c.closeContinue }
	if c.closePanic { panic("close callback") }
	return c.closeErr
}
func (*lifecycleConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (*lifecycleConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (*lifecycleConn) SetDeadline(time.Time) error { return nil }
func (*lifecycleConn) SetReadDeadline(time.Time) error { return nil }
func (*lifecycleConn) SetWriteDeadline(time.Time) error { return nil }
func (c *lifecycleConn) ReadFrom(p []byte) (int, net.Addr, error) { n, err := c.Read(p); return n, &net.UDPAddr{}, err }
func (c *lifecycleConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func lifecycleDial(t *testing.T, source *lifecycleSource, raw *lifecycleConn) net.Conn {
	t.Helper()
	conn, err := DialRuntimeConn(context.Background(), source, func(context.Context) (net.Conn, error) { return raw, nil })
	if err != nil { t.Fatal(err) }
	return conn
}

func TestRuntimeCarrierCloseDoesNotReleaseInFlightRead(t *testing.T) {
	source := newLifecycleSource()
	raw := &lifecycleConn{readEntered: make(chan struct{}), readContinue: make(chan struct{})}
	conn := lifecycleDial(t, source, raw)
	done := make(chan struct{})
	go func() { _, _ = conn.Read(make([]byte, 1)); close(done) }()
	<-raw.readEntered
	if source.count() != 2 { t.Fatal("read did not retain the actual receiver") }
	source.seal()
	if err := conn.Close(); err != nil { t.Fatal(err) }
	if source.count() != 1 { t.Fatal("close released an admitted read tail") }
	if _, err := conn.Write(nil); !errors.Is(err, net.ErrClosed) { t.Fatal("closed carrier admitted a new call") }
	close(raw.readContinue); <-done
	if source.count() != 0 { t.Fatal("completed read retained its reservation") }
}

func TestRuntimeCarrierConcurrentCloseObservesOneActualResult(t *testing.T) {
	source := newLifecycleSource()
	raw := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	conn := lifecycleDial(t, source, raw)
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	<-raw.closeEntered
	if err := conn.Close(); !errors.Is(err, ErrRuntimeClosePending) { t.Fatalf("concurrent close = %v", err) }
	if source.count() != 1 { t.Fatal("pending close was treated as terminal") }
	close(raw.closeContinue)
	if err := <-done; err != nil { t.Fatal(err) }
	if err := conn.Close(); err != nil { t.Fatalf("pending observation replaced terminal result: %v", err) }
	if raw.closes.Load() != 1 || source.count() != 0 { t.Fatal("close was repeated or terminal lease leaked") }
}

func TestRuntimeCarrierUncertainCloseIsStickyAndRetains(t *testing.T) {
	for _, panicClose := range []bool{false, true} {
		source := newLifecycleSource()
		raw := &lifecycleConn{closeErr: context.Canceled, closePanic: panicClose}
		conn := lifecycleDial(t, source, raw)
		err := conn.Close()
		if err == nil || errors.Is(err, context.Canceled) { t.Fatal("uncertainty is filterable or absent") }
		if conn.Close() != err { t.Fatal("uncertain result was not sticky") }
		if source.count() != 1 || raw.closes.Load() != 1 { t.Fatal("unknown completion lost its exact closure") }
	}
}

func TestRuntimeDialRetainsCreationAndContinuesAfterRetirement(t *testing.T) {
	source := newLifecycleSource()
	entered, proceed := make(chan struct{}), make(chan struct{})
	result := make(chan net.Conn, 1)
	go func() {
		conn, err := DialRuntimeConn(context.Background(), source, func(context.Context) (net.Conn, error) {
			close(entered); <-proceed; return &lifecycleConn{}, nil
		})
		if err != nil { result <- nil; return }; result <- conn
	}()
	<-entered
	if source.count() != 1 { t.Fatal("pending creation has no receiver reservation") }
	source.seal(); close(proceed)
	conn := <-result
	if conn == nil { t.Fatal("retirement revoked an admitted creation") }
	if _, err := conn.Write([]byte("old stream")); err != nil { t.Fatal(err) }
	if err := conn.Close(); err != nil { t.Fatal(err) }
	if source.count() != 0 { t.Fatal("creation reservation was not transferred") }
}

func TestRuntimePacketMethodsRetainAndDialPreservesPacketContract(t *testing.T) {
	source := newLifecycleSource()
	raw := &lifecycleConn{readEntered: make(chan struct{}), readContinue: make(chan struct{})}
	conn := lifecycleDial(t, source, raw)
	packet, ok := conn.(net.PacketConn)
	if !ok { t.Fatal("UDP DialContext lost net.PacketConn") }
	done := make(chan struct{})
	go func() { _, _, _ = packet.ReadFrom(nil); close(done) }()
	<-raw.readEntered
	if err := packet.Close(); err != nil { t.Fatal(err) }
	if source.count() != 1 { t.Fatal("packet read tail was released") }
	close(raw.readContinue); <-done
	if source.count() != 0 { t.Fatal("packet read tail did not release") }
}

func TestRuntimeConstructorCleanupRejectsCanceledAndClosedScopes(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
		if cancelParent { cancel() } else { _ = scope.Close() }
		var calls atomic.Int32
		bound := adapter.ContextWithConstructionScope(context.Background(), scope)
		registered, err := RegisterRuntimeCleanup(bound, func() error { calls.Add(1); return nil })
		if !registered || err == nil || calls.Load() != 1 { t.Fatal("immediate cleanup published a successful constructor") }
		cancel()
	}
	var calls atomic.Int32
	registered, err := RegisterRuntimeCleanup(context.Background(), func() error { calls.Add(1); return nil })
	if registered || err != nil || calls.Load() != 0 { t.Fatal("standalone constructor was immediately destroyed") }
}

type lifecycleUnknownCloser struct{}
func (lifecycleUnknownCloser) Close() error { return context.Canceled }
func TestRuntimeUnknownWorkerCleanupSurvivesScopeFiltering(t *testing.T) {
	source := newLifecycleSource()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), source)
	_, err := RegisterRuntimeCleanup(ctx, func() error { return CloseRuntimeResource(ctx, "test pool", lifecycleUnknownCloser{}) })
	if err != nil { t.Fatal(err) }
	if err := scope.Close(); err == nil { t.Fatal("Scope filtered unknown worker completion") }
}

func (l *lifecycleLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	l.owner.mu.Lock()
	if l.released { l.owner.mu.Unlock(); return nil, net.ErrClosed }
	dependency := l.owner.dependencies[id]
	if id == l.owner.ID() { dependency = l.owner }
	l.owner.mu.Unlock()
	if dependency == nil { return nil, errors.New("foreign dependency") }
	dependency.mu.Lock(); defer dependency.mu.Unlock()
	dependency.refs++
	return &lifecycleLease{owner: dependency}, nil
}

func TestRuntimeOwnedSessionRequiresLiveExactClosure(t *testing.T) {
	owner, dependency, foreign := newLifecycleSource(), newLifecycleSource(), newLifecycleSource()
	dependency.sequence, foreign.sequence = 2, 3
	owner.dependencies = map[adapter.RuntimeResourceID]*lifecycleSource{dependency.ID(): dependency}
	lease, _ := owner.Acquire()
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
	owned, err := ContextForRuntimeOwnedSession(ctx, owner)
	if err != nil { t.Fatal(err) }
	for _, source := range []*lifecycleSource{owner, dependency} {
		if ok, err := ValidateRuntimeOwnedSession(owned, source); err != nil || !ok { t.Fatalf("captured receiver: %v", err) }
	}
	if ok, err := ValidateRuntimeOwnedSession(owned, foreign); err == nil || ok { t.Fatal("foreign source root admission bypassed closure") }
	lease.Release()
	if _, err := ValidateRuntimeOwnedSession(owned, owner); err == nil { t.Fatal("released continuation was revived") }
	if owner.count() != 0 || dependency.count() != 0 || foreign.count() != 0 { t.Fatal("proof retained a baseline") }
}

func TestRuntimeOwnedSameSCCDoesNotSelfPinAndNestedOwnersStayDistinct(t *testing.T) {
	outer, nested := newLifecycleSource(), newLifecycleSource(); nested.sequence = 2
	outer.dependencies = map[adapter.RuntimeResourceID]*lifecycleSource{nested.ID(): nested}
	lease, _ := outer.Acquire()
	ctx, err := ContextForRuntimeOwnedSession(adapter.ContextWithRuntimeResourceLease(context.Background(), lease), outer)
	if err != nil { t.Fatal(err) }
	conn, err := DialRuntimeConn(ctx, outer, func(context.Context) (net.Conn, error) { return &lifecycleConn{}, nil })
	if err != nil { t.Fatal(err) }
	if outer.count() != 1 { t.Fatal("internal physical connection self-pinned its owner") }
	_ = conn.Close()
	admitted, release, err := adapter.AcquireRuntimeOperation(ctx, nested)
	if err != nil { t.Fatal(err) }
	nestedContext, err := ContextForRuntimeOwnedSession(admitted, nested)
	if err != nil { t.Fatal(err) }
	if _, err := ValidateRuntimeOwnedSession(nestedContext, outer); err == nil { t.Fatal("nested owner inherited outer authority outside its own closure") }
	release(); lease.Release()
	if outer.count() != 0 || nested.count() != 0 { t.Fatal("nested proof leaked") }
}

func TestRuntimeOwnedFenceJoinsActualMethodTail(t *testing.T) {
	raw := &lifecycleConn{readEntered: make(chan struct{}), readContinue: make(chan struct{})}
	conn, fence := WrapRuntimeOwnedConn(raw)
	readDone := make(chan struct{})
	go func() { _, _ = conn.Read(nil); close(readDone) }()
	<-raw.readEntered
	if err := fence.Close(); err != nil && !errors.Is(err, ErrRuntimeClosePending) { t.Fatal(err) }
	if _, err := fence.Acquire(); !errors.Is(err, net.ErrClosed) { t.Fatal("sealed fence admitted callback") }
	done := make(chan error, 1)
	go func() { done <- fence.Wait() }()
	select { case <-done: t.Fatal("close return was mistaken for method completion"); default: }
	close(raw.readContinue); <-readDone
	if err := <-done; err != nil { t.Fatal(err) }
}

func TestRuntimeFenceSetLateCreationJoinsBeforeCompleting(t *testing.T) {
	set := NewRuntimeIOFenceSet()
	creation, err := set.Begin(); if err != nil { t.Fatal(err) }
	set.Stop()
	if _, err := set.Begin(); !errors.Is(err, net.ErrClosed) { t.Fatal("post-seal creation admitted") }
	raw := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	_, fence := WrapRuntimeOwnedConn(raw)
	registered := make(chan error, 1)
	go func() { defer creation.Done(); registered <- creation.Register(fence) }()
	<-raw.closeEntered
	done := make(chan error, 1); go func() { done <- set.Wait() }()
	select { case <-done: t.Fatal("pending late close was certified complete"); default: }
	close(raw.closeContinue)
	if err := <-registered; !errors.Is(err, net.ErrClosed) { t.Fatalf("late publication: %v", err) }
	if err := <-done; err != nil { t.Fatal(err) }
}

func TestRuntimeFenceSetQuarantinesFailureAndPanic(t *testing.T) {
	set := NewRuntimeIOFenceSet()
	creation, _ := set.Begin()
	_, fence := WrapRuntimeOwnedConn(&lifecycleConn{closeErr: context.Canceled})
	if err := creation.Register(fence); err != nil { t.Fatal(err) }; creation.Done()
	if err := set.RuntimeCloseAndWait(); err == nil || errors.Is(err, context.Canceled) { t.Fatal("failed close lost quarantine") }
	set = NewRuntimeIOFenceSet()
	func() {
		defer func() { _ = recover() }()
		creation, _ := set.Begin(); defer creation.Done()
		panic("unknown creation tail")
	}()
	if err := set.RuntimeCloseAndWait(); err == nil { t.Fatal("creation panic was certified complete") }
}

type lifecycleRawConn struct { controls atomic.Int32 }
func (c *lifecycleRawConn) Control(callback func(uintptr)) error { c.controls.Add(1); callback(7); return nil }
func (c *lifecycleRawConn) Read(callback func(uintptr) bool) error { callback(7); return nil }
func (c *lifecycleRawConn) Write(callback func(uintptr) bool) error { callback(7); return nil }
type lifecycleSyscallConn struct { lifecycleConn; raw *lifecycleRawConn }
func (c *lifecycleSyscallConn) SyscallConn() (syscall.RawConn, error) { return c.raw, nil }
func (*lifecycleSyscallConn) SetNoDelay(bool) error { return nil }

func TestRuntimeDescriptorCallbackRetainsAndSeals(t *testing.T) {
	source := newLifecycleSource()
	raw := &lifecycleSyscallConn{raw:&lifecycleRawConn{}}
	conn,err := DialRuntimeConn(context.Background(),source,func(context.Context)(net.Conn,error){return raw,nil})
	if err!=nil{t.Fatal(err)}
	control,err:=RuntimeTCPControl(conn);if err!=nil{t.Fatal(err)}
	descriptor,err:=control.SyscallConn();if err!=nil{t.Fatal(err)}
	entered,proceed:=make(chan struct{}),make(chan struct{})
	done:=make(chan error,1)
	go func(){done<-descriptor.Control(func(uintptr){close(entered);<-proceed})}();<-entered
	if err:=conn.Close();err!=nil{t.Fatal(err)}
	if source.count()!=1{t.Fatal("descriptor callback lost exact receiver")}
	if err:=descriptor.Control(func(uintptr){t.Error("post-seal descriptor escaped")});!errors.Is(err,net.ErrClosed){t.Fatal(err)}
	if err:=control.SetNoDelay(true);!errors.Is(err,net.ErrClosed){t.Fatal("post-seal TCP control admitted")}
	close(proceed);if err:=<-done;err!=nil{t.Fatal(err)}
	if source.count()!=0||raw.raw.controls.Load()!=1{t.Fatal("descriptor callback did not release exactly once")}
}

func (s *lifecycleSource) RetainCapturedResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	if id == s.ID() { return nil, errors.New("captured source must not self-retain") }
	s.mu.Lock(); dependency := s.dependencies[id]; s.mu.Unlock()
	if dependency == nil { return nil, errors.New("foreign captured resource") }
	dependency.mu.Lock(); defer dependency.mu.Unlock()
	dependency.refs++
	return &lifecycleLease{owner: dependency}, nil
}

func TestRuntimeRegisteredOwnedFenceContinuesWithoutSelfPin(t *testing.T) {
	owner, dependency, foreign := newLifecycleSource(), newLifecycleSource(), newLifecycleSource()
	dependency.sequence, foreign.sequence = 2, 3
	owner.dependencies = map[adapter.RuntimeResourceID]*lifecycleSource{dependency.ID(): dependency}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	constructor := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
	fence := NewRuntimeIOFence(nil)
	admit, err := RegisterRuntimeOwnedFence(constructor, fence); if err != nil { t.Fatal(err) }
	owner.seal() // graph retirement cannot pin or revoke the registered owner fence
	foreignLease, _ := foreign.Acquire(); foreignLease.Release()
	ctx, release, err := admit(adapter.ContextWithRuntimeResourceLease(context.Background(), foreignLease))
	if err != nil { t.Fatal(err) }
	if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, foreign.ID()); ok { t.Fatal("internal owner inherited another stream's identity") }
	owned, err := ContextForRuntimeOwnedSession(ctx, owner); if err != nil { t.Fatal(err) }
	if ok, err := ValidateRuntimeOwnedSession(owned, dependency); err != nil || !ok { t.Fatalf("dependency: %v",err) }
	if _, err := ValidateRuntimeOwnedSession(owned, foreign); err == nil { t.Fatal("owned fence admitted foreign resource") }
	conn, err := DialRuntimeConn(owned, owner, func(context.Context) (net.Conn,error) { return &lifecycleConn{},nil })
	if err != nil { t.Fatal(err) }; _ = conn.Close()
	if owner.count()!=0 || dependency.count()!=0 { t.Fatal("physical owner work self-pinned or leaked a dependency proof") }
	lease, _ := adapter.RuntimeResourceLeaseFromContext(ctx, owner.ID())
	retiring := lease.Retiring()
	if err := fence.Close(); err != nil && !errors.Is(err, ErrRuntimeClosePending) { t.Fatal(err) }
	select { case <-retiring: default: t.Fatal("owner fence did not signal retirement") }
	if _, _, err := admit(context.Background()); !errors.Is(err,net.ErrClosed) { t.Fatal("closed owner fence issued new authority") }
	if _, err := lease.Fork(); !errors.Is(err,net.ErrClosed) { t.Fatal("closing owner fence admitted a new callback") }
	done:=make(chan error,1);go func(){done<-fence.Wait()}()
	select{case <-done:t.Fatal("cleanup skipped an admitted physical creation");default:}
	release();if err:=<-done;err!=nil{t.Fatal(err)}
	continuation,ok:=lease.(adapter.RuntimeResourceContinuation);if !ok{t.Fatal("owned lease lost dependency continuation")}
	if _,err:=continuation.RetainResource(dependency.ID());err==nil{t.Fatal("released owned capability revived")}
	if err:=scope.Close();err!=nil{t.Fatal(err)}
}

func TestRuntimeOwnedFenceRequiresConstructorRegistration(t *testing.T) {
	source := newLifecycleSource()
	if _,err:=RegisterRuntimeOwnedFence(adapter.ContextWithRuntimeResourceSource(context.Background(),source),NewRuntimeIOFence(nil));err==nil{t.Fatal("unregistered source issued owned authority")}
	admit,err:=RegisterRuntimeOwnedFence(context.Background(),NewRuntimeIOFence(nil));if err!=nil{t.Fatal(err)}
	ctx,release,err:=admit(context.Background());if err!=nil||ctx==nil{t.Fatal(err)};release()
	scope:=adapter.NewScope(context.Background(),log.NewNOPFactory().Logger());_ = scope.Close()
	ctx=adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(context.Background(),scope),source)
	if _,err:=RegisterRuntimeOwnedFence(ctx,NewRuntimeIOFence(nil));err==nil{t.Fatal("canceled construction published owner callback")}
}

type lifecycleAccountingConn struct { lifecycleConn; entered,proceed chan struct{}; calls atomic.Int32 }
func(c *lifecycleAccountingConn)IOActivityFuncs()(func(int),func(int)){
	return func(int){c.calls.Add(1);close(c.entered);<-c.proceed},nil
}
func TestRuntimeCopiedAccountingCallbackRetainsAndSeals(t *testing.T){
	source:=newLifecycleSource()
	raw:=&lifecycleAccountingConn{entered:make(chan struct{}),proceed:make(chan struct{})}
	conn,err:=DialRuntimeConn(context.Background(),source,func(context.Context)(net.Conn,error){return raw,nil});if err!=nil{t.Fatal(err)}
	onRead,_:=RuntimeIOActivityFuncs(conn);if onRead==nil{t.Fatal("lost explicit descriptor traffic accounting")}
	done:=make(chan struct{});go func(){onRead(1);close(done)}();<-raw.entered
	if err:=conn.Close();err!=nil{t.Fatal(err)}
	if source.count()!=1{t.Fatal("accounting callback lost exact receiver")}
	onRead(2)
	close(raw.proceed);<-done
	if source.count()!=0||raw.calls.Load()!=1{t.Fatal("copied callback escaped seal or leaked")}
}

type lifecycleProtocolWrapper struct { net.Conn }
func (c *lifecycleProtocolWrapper) Upstream() any { return c.Conn }
func TestRuntimeTrustedProtocolDescriptorTraversalKeepsAllFences(t *testing.T) {
	raw:=&lifecycleSyscallConn{raw:&lifecycleRawConn{}}
	inner,innerFence:=WrapRuntimeOwnedConn(raw)
	outer,outerFence:=WrapRuntimeOwnedConn(&lifecycleProtocolWrapper{Conn:inner})
	descriptor,err:=RuntimeSyscallConn(outer);if err!=nil{t.Fatal(err)}
	if _,ok:=outer.(interface{Upstream()any});ok{t.Fatal("runtime boundary exposed raw protocol chain")}
	if err:=descriptor.Control(func(uintptr){});err!=nil{t.Fatal(err)}
	if err:=innerFence.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
	if err:=descriptor.Control(func(uintptr){t.Error("inner carrier fence bypassed")});!errors.Is(err,net.ErrClosed){t.Fatal(err)}
	if err:=outerFence.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
	if raw.raw.controls.Load()!=1{t.Fatal("descriptor operation escaped nested seal")}
}

func TestNestedCreationCleanupUncertaintyRetainsAdmission(t *testing.T) {
 for _, packet := range []bool{false,true} {
  source := newLifecycleSource()
  failure := errors.Join(errors.New("handshake failed"),&runtimeCleanupError{"raw close unknown"})
  if packet {
   _,err := ListenRuntimePacket(context.Background(),source,func(context.Context)(net.PacketConn,error){return nil,failure})
   if err == nil { t.Fatal("missing failure") }
  } else {
   _,err := DialRuntimeConn(context.Background(),source,func(context.Context)(net.Conn,error){return nil,failure})
   if err == nil { t.Fatal("missing failure") }
  }
  if source.count()!=1 { t.Fatal("uncertain nested cleanup released its only reservation") }
 }
 source:=newLifecycleSource()
 _,_ = DialRuntimeConn(context.Background(),source,func(context.Context)(net.Conn,error){return nil,errors.New("ordinary failure")})
 if source.count()!=0 { t.Fatal("ordinary no-resource failure retained admission") }
}

func TestRuntimeTrustedProtocolTCPControlKeepsInnerFence(t *testing.T){
 raw:=&lifecycleSyscallConn{raw:&lifecycleRawConn{}}
 inner,innerFence:=WrapRuntimeOwnedConn(raw)
 outer,outerFence:=WrapRuntimeOwnedConn(&lifecycleProtocolWrapper{Conn:inner})
 control,err:=RuntimeTCPControl(outer);if err!=nil{t.Fatal("legacy wrapper lost TCP capability",err)}
 if err:=control.SetNoDelay(true);err!=nil{t.Fatal(err)}
 if err:=innerFence.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
 if err:=control.SetNoDelay(false);!errors.Is(err,net.ErrClosed){t.Fatal("control skipped closed inner fence",err)}
 if err:=outerFence.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
}

func TestRuntimeNestedOwnedCloseJoinsOneFixedWorker(t *testing.T) {
 raw := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
 inner, innerFence := WrapRuntimeOwnedConn(raw)
 outer, outerFence := WrapRuntimeOwnedConn(inner)
 if err := inner.Close(); !errors.Is(err, ErrRuntimeClosePending) { t.Fatalf("request: %v", err) }
 <-raw.closeEntered
 if err := outer.Close(); !errors.Is(err, ErrRuntimeClosePending) { t.Fatalf("outer request: %v", err) }
 done := make(chan error, 1)
 go func() { done <- outerFence.RuntimeCloseAndWait() }()
 select { case <-done: t.Fatal("nested pending close was treated as terminal"); default: }
 close(raw.closeContinue)
 if err := <-done; err != nil { t.Fatal(err) }
 if err := innerFence.Wait(); err != nil { t.Fatal(err) }
 if raw.closes.Load() != 1 { t.Fatal("nested close repeated raw cleanup") }
}

func TestRuntimeOwnedCloseCallbackCanRequestWithoutJoiningItself(t *testing.T) {
 fence := NewRuntimeIOFence(nil)
 release, err := fence.Acquire(); if err != nil { t.Fatal(err) }
 if err := fence.Close(); err != nil && !errors.Is(err, ErrRuntimeClosePending) { t.Fatal(err) }
 done := make(chan error, 1); go func() { done <- fence.Wait() }()
 select { case <-done: t.Fatal("admitted callback was not retained"); default: }
 release()
 if err := <-done; err != nil { t.Fatal(err) }
}
