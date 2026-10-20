package daemon

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type runtimeURLTestPlatform struct { adapter.PlatformInterface }
func (*runtimeURLTestPlatform) UsePlatformAutoRedirect() bool { return false }
func (*runtimeURLTestPlatform) Initialize(adapter.NetworkManager) error { return nil }
func (*runtimeURLTestPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (*runtimeURLTestPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor { return nil }
func (*runtimeURLTestPlatform) UsePlatformNetworkInterfaces() bool { return true }
func (*runtimeURLTestPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (*runtimeURLTestPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (*runtimeURLTestPlatform) UnderNetworkExtension() bool { return false }
func (*runtimeURLTestPlatform) ClearDNSCache() {}
func (*runtimeURLTestPlatform) UsePlatformConnectionOwnerFinder() bool { return true }
func (*runtimeURLTestPlatform) UsePlatformWIFIMonitor() bool { return true }
func (*runtimeURLTestPlatform) UsePlatformNeighborResolver() bool { return false }

type runtimeURLTestOutbound struct {
	*socks.Outbound
	source adapter.RuntimeResourceSource
	entered chan context.Context
	release chan struct{}
	closed chan struct{}
}
func (o *runtimeURLTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.entered <- ctx
	<-o.release // Deliberately uncooperative actual dial, not a canceled waiter.
	return nil, errors.New("injected URL test dial failure")
}
func runtimeURLTestWait(t *testing.T, done <-chan struct{}) { t.Helper(); select { case <-done: case <-time.After(5*time.Second): t.Fatal("missing daemon runtime URL test barrier") } }

// Actual New/Start, admitted Store, resource scopes and RPC path are exercised.
// Only the OS monitor and the raw SOCKS dial boundary are replaced.
func TestRuntimeDaemonURLTestAdmitsBeforeDispatchAndOwnsRawCompletion(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "android" { t.Skip("platform power/certificate boundary requires its native fixture") }
	history := urltest.NewHistoryStorage(); defer history.Close()
	registry := outbound.NewRegistry(); direct.RegisterOutbound(registry)
	var actual *runtimeURLTestOutbound
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		value, err := socks.NewOutbound(ctx, router, logger, tag, options); if err != nil { return nil, err }
		source, ok := adapter.RuntimeResourceSourceFromContext(ctx); if !ok { return nil, errors.New("actual constructor is not resource-bound") }
		actual = &runtimeURLTestOutbound{Outbound: value.(*socks.Outbound), source: source, entered: make(chan context.Context, 1), release: make(chan struct{}), closed: make(chan struct{})}
		if err := adapter.DeferConstructionCleanup(ctx, func() error { close(actual.closed); return nil }); err != nil { return nil, err }
		return actual, nil
	})
	transports := dns.NewTransportRegistry(); transport.RegisterUDP(transports)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), registry, endpoint.NewRegistry(), transports, boxService.NewRegistry(), boxCertificate.NewRegistry())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeURLTestPlatform{})
	ctx = service.ContextWithPtr(ctx, history)
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"socks","tag":"node","server":"192.0.2.1","server_port":1080,"version":"5"}],"route":{"final":"node"}}`), &options); err != nil { t.Fatal(err) }
	instance, err := box.New(box.Options{Context: ctx, Options: options}); if err != nil { t.Fatal(err) }
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(actual.release) }) }
	t.Cleanup(func() { unblock(); if err := instance.CloseWithResult(); err != nil { t.Errorf("actual Box cleanup: %v", err) } })
	started := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}, instance: &Instance{ctx: ctx, instance: instance, outboundManager: instance.Outbound(), urlTestHistoryStorage: history, logFactory: instance.LogFactory()}}
	if probe, bound, err := instance.AcquireRuntimeURLTest(ctx, "node"); !bound || err == nil { if probe != nil { probe.Release() }; t.Fatal("unpublished Box admitted a manual probe") }
	if _, err := started.URLTest(ctx, &URLTestRequest{OutboundTag: "node"}); err == nil { t.Fatal("RPC scheduled before graph publication") }
	select { case <-actual.entered: t.Fatal("unready RPC invoked raw dial"); default: }
	if err := instance.Start(); err != nil { t.Fatal(err) }
	request, cancelRequest := context.WithCancel(ctx)
	if _, err := started.URLTest(request, &URLTestRequest{OutboundTag: "node"}); err != nil { t.Fatal(err) }
	cancelRequest() // Accepted asynchronous RPC work belongs to the host.
	var dialContext context.Context
	select { case dialContext = <-actual.entered: case <-time.After(5*time.Second): t.Fatal("actual manual dial not dispatched") }
	if dialContext.Err() != nil { t.Fatal("host-owned RPC work inherited completed request cancellation") }
	if _, ok := adapter.RuntimeLeaseFromContext(dialContext); !ok { t.Fatal("dispatch lacks admitted graph") }
	if _, ok := adapter.RuntimeResourceLeaseFromContext(dialContext, actual.source.ID()); !ok { t.Fatal("dispatch lacks actual receiving resource") }
	closeDone := make(chan struct{}); closeResult := make(chan error, 1)
	go func() { closeResult <- instance.CloseWithResult(); close(closeDone) }()
	runtimeURLTestWait(t, dialContext.Done())
	select { case <-actual.closed: t.Fatal("resource cleanup overtook blocked actual worker"); default: }
	select { case <-closeDone: t.Fatal("Box shutdown claimed completion while actual dial remained"); default: }
	unblock(); runtimeURLTestWait(t, closeDone); runtimeURLTestWait(t, actual.closed)
	if err := <-closeResult; err != nil { t.Fatal(err) }
	if history.LoadURLTestHistory("node") != nil { t.Fatal("shutdown result survived in visible history") }
}
