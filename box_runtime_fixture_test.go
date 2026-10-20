package box

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// These fixtures use Box.New and the production constructors, managers, stages,
// planner, publisher and owners. Only the platform boundary and observation of
// the otherwise lifecycle-free SOCKS object are supplied by the test. No dial
// or packet exchange is issued. On Windows, the real NetworkManager starts
// and closes the native power listener; failures remain test failures.
type runtimeTestPlatform struct{ adapter.PlatformInterface }

func (*runtimeTestPlatform) UsePlatformAutoRedirect() bool { return false }

func (*runtimeTestPlatform) Initialize(adapter.NetworkManager) error  { return nil }
func (*runtimeTestPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (*runtimeTestPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (*runtimeTestPlatform) UsePlatformNetworkInterfaces() bool                     { return true }
func (*runtimeTestPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (*runtimeTestPlatform) UsePlatformAutoDetectInterfaceControl() bool            { return false }
func (*runtimeTestPlatform) UnderNetworkExtension() bool                            { return false }
func (*runtimeTestPlatform) ClearDNSCache()                                         {}
func (*runtimeTestPlatform) UsePlatformConnectionOwnerFinder() bool                 { return true }
func (*runtimeTestPlatform) UsePlatformWIFIMonitor() bool                           { return true }
func (*runtimeTestPlatform) UsePlatformNeighborResolver() bool                      { return false }

type runtimeTestBarrier struct {
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newRuntimeTestBarrier() *runtimeTestBarrier {
	return &runtimeTestBarrier{entered: make(chan struct{}), release: make(chan struct{})}
}
func (b *runtimeTestBarrier) block() { b.enterOnce.Do(func() { close(b.entered) }); <-b.release }
func (b *runtimeTestBarrier) open()  { b.releaseOnce.Do(func() { close(b.release) }) }

// Time limits only diagnose missing progress. Every race is ordered by an
// explicit constructor, lifecycle, publication or cleanup barrier, never sleep.
func runtimeTestWait(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func runtimeTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type runtimeTestSocks struct {
	*socks.Outbound
	ctx           context.Context
	access        sync.Mutex
	stages        []adapter.StartStage
	closed        chan struct{}
	closeCount    int
	startHook     func(adapter.StartStage) error
	closeHook     func() error
	idleHook      func(bool)
	closeIdleHook func()
}

func (o *runtimeTestSocks) SetKeepIdleConnections(keep bool) {
	o.access.Lock()
	hook := o.idleHook
	o.access.Unlock()
	if hook != nil {
		hook(keep)
	}
}

func (o *runtimeTestSocks) CloseIdleConnections() {
	o.access.Lock()
	hook := o.closeIdleHook
	o.access.Unlock()
	if hook != nil {
		hook()
	}
}

func (o *runtimeTestSocks) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	o.access.Lock()
	o.stages = append(o.stages, stage)
	hook := o.startHook
	o.access.Unlock()
	if hook != nil {
		return hook(stage)
	}
	return nil
}

func (o *runtimeTestSocks) cleanup() error {
	o.access.Lock()
	o.closeCount++
	hook := o.closeHook
	o.access.Unlock()
	var err error
	if hook != nil {
		err = hook()
	}
	close(o.closed)
	return err
}

func (o *runtimeTestSocks) snapshot() ([]adapter.StartStage, int) {
	o.access.Lock()
	defer o.access.Unlock()
	return append([]adapter.StartStage(nil), o.stages...), o.closeCount
}

type runtimeTestFixture struct {
	box             *Box
	ctx             context.Context
	access          sync.Mutex
	objects         map[string][]*runtimeTestSocks
	constructorHook func(*runtimeTestSocks) error
}

func newRuntimeTestConstruction(t *testing.T, content []byte, constructorHook func(*runtimeTestSocks) error) (*runtimeTestFixture, Options) {
	t.Helper()
	if runtime.GOOS == "android" {
		t.Skip("Android system certificate boundary requires its own platform fixture")
	}
	f := &runtimeTestFixture{objects: make(map[string][]*runtimeTestSocks), constructorHook: constructorHook}
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	group.RegisterSelector(outbounds)
	outbound.Register[option.SOCKSOutboundOptions](outbounds, C.TypeSOCKS, func(ctx context.Context, router adapter.Router, log log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		actual, err := socks.NewOutbound(ctx, router, log, tag, options)
		if err != nil {
			return nil, err
		}
		observed := &runtimeTestSocks{Outbound: actual.(*socks.Outbound), ctx: ctx, closed: make(chan struct{})}
		if err := adapter.DeferConstructionCleanup(ctx, observed.cleanup); err != nil {
			return nil, err
		}
		f.access.Lock()
		f.objects[tag] = append(f.objects[tag], observed)
		hook := f.constructorHook
		f.access.Unlock()
		if hook != nil {
			if err := hook(observed); err != nil {
				return nil, err
			}
		}
		return observed, nil
	})
	dnsTransports := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsTransports)
	transport.RegisterTCP(dnsTransports)
	ctx := Context(context.Background(), inbound.NewRegistry(), outbounds, endpoint.NewRegistry(), dnsTransports, boxService.NewRegistry(), boxCertificate.NewRegistry())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeTestPlatform{})
	f.ctx = ctx
	var options option.Options
	if err := json.UnmarshalContext(ctx, content, &options); err != nil {
		t.Fatal(err)
	}
	return f, Options{Options: options, Context: ctx}
}

func newRuntimeTestFixture(t *testing.T, content []byte, constructorHook func(*runtimeTestSocks) error) *runtimeTestFixture {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, content, constructorHook)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	if instance.runtime == nil {
		t.Fatal("Box.New did not use the connected initial construction path")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := instance.closeRuntimeResourcesContext(ctx); err != nil {
			t.Errorf("runtime fixture cleanup: %v", err)
			return
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Errorf("outer fixture cleanup: %v", err)
		}
	})
	return f
}

func runtimeTestConfig(port int, domain string) []byte {
	return []byte(fmt.Sprintf(`{
		"log":{"disabled":true},
		"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},
		"outbounds":[
			{"type":"socks","tag":"a","server":"192.0.2.1","server_port":%d,"version":"5"},
			{"type":"socks","tag":"b","server":"192.0.2.2","server_port":1080,"version":"5"},
			{"type":"selector","tag":"select","outbounds":["a","b"],"default":"a"}
		],
		"route":{"final":"select","rule_set":[{"type":"inline","tag":"sites","rules":[{"domain_suffix":[%q]}]}],"rules":[{"rule_set":"sites","action":"route","outbound":"select"}]}
	}`, port, domain))
}

func (f *runtimeTestFixture) start(t *testing.T) {
	t.Helper()
	if err := f.box.Start(); err != nil {
		t.Fatal(err)
	}
}

func (f *runtimeTestFixture) object(t *testing.T, tag string, index int) *runtimeTestSocks {
	t.Helper()
	f.access.Lock()
	defer f.access.Unlock()
	if len(f.objects[tag]) <= index {
		t.Fatalf("missing %s constructor %d", tag, index)
	}
	return f.objects[tag][index]
}

func (f *runtimeTestFixture) count(tag string) int {
	f.access.Lock()
	defer f.access.Unlock()
	return len(f.objects[tag])
}

func (f *runtimeTestFixture) setConstructorHook(hook func(*runtimeTestSocks) error) {
	f.access.Lock()
	f.constructorHook = hook
	f.access.Unlock()
}

func (f *runtimeTestFixture) identity() RuntimeIdentity {
	f.box.runtime.access.Lock()
	defer f.box.runtime.access.Unlock()
	return f.box.runtime.active
}

func (f *runtimeTestFixture) plan(t *testing.T, content []byte) (RuntimeConfigPlan, RuntimeConfigApply) {
	t.Helper()
	plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Applicable || len(plan.Errors) != 0 {
		t.Fatalf("candidate not applicable: %+v", plan)
	}
	return plan, RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
}

func (f *runtimeTestFixture) acquire(t *testing.T) (adapter.RuntimeLease, *runtimeView) {
	t.Helper()
	lease, err := f.box.runtime.store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	view, ok := lease.View().(*runtimeView)
	if !ok {
		t.Fatal("published graph does not contain actual runtime view")
	}
	return lease, view
}

func runtimeTestResource(t *testing.T, f *runtimeTestFixture, id adapter.RuntimeResourceID) *runtimeResource {
	t.Helper()
	f.box.runtime.access.Lock()
	defer f.box.runtime.access.Unlock()
	resource := f.box.runtime.catalog[id]
	if resource == nil {
		t.Fatalf("resource not catalogued: %+v", id)
	}
	return resource
}

func runtimeTestApplyAsync(f *runtimeTestFixture, ctx context.Context, request RuntimeConfigApply) <-chan struct {
	operation RuntimeConfigOperation
	err       error
} {
	result := make(chan struct {
		operation RuntimeConfigOperation
		err       error
	}, 1)
	go func() {
		operation, err := f.box.applyRuntimeConfig(ctx, "actor-a", request)
		result <- struct {
			operation RuntimeConfigOperation
			err       error
		}{operation, err}
	}()
	return result
}

func runtimeTestReceiveApply(t *testing.T, result <-chan struct {
	operation RuntimeConfigOperation
	err       error
}) RuntimeConfigOperation {
	t.Helper()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatal(value.err)
		}
		return value.operation
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not return after its barrier opened")
		return RuntimeConfigOperation{}
	}
}
