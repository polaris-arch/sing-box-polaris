package box

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/mixed"
	protocolTun "github.com/sagernet/sing-box/protocol/tun"
	nativeTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func TestRuntimeClientMobileTunGeometryIsClosedAndIsNotAuthority(t *testing.T) {
	for _, platform := range []string{"android", "ios"} {
		t.Run(platform, func(t *testing.T) {
			base := map[string]stdjson.RawMessage{"type": []byte("\"tun\""), "tag": []byte("\"tun-in\""), "address": []byte("[\"172.19.0.1/16\"]"), "mtu": []byte("1500"), "auto_route": []byte("true")}
			if !runtimeClientTunShape(base, platform) {
				t.Fatal("real mobile /16 default rejected")
			}
			base["address"] = []byte("[\"172.19.0.1/16\",\"fdfe:dcba:9876::1/126\"]")
			base["udp_mapping"] = []byte("\"endpoint_independent\"")
			base["udp_filtering"] = []byte("\"address_and_port_dependent\"")
			base["route_exclude_address"] = []byte("[\"192.168.0.0/16\",\"fd00::/8\"]")
			if !runtimeClientTunShape(base, platform) {
				t.Fatal("finite mobile IPv6/NAT/exclusion geometry rejected")
			}
			base["auto_route"] = []byte("false")
			if !runtimeClientTunShape(base, platform) {
				t.Fatal("mobile explicit auto_route=false rejected")
			}
			base["auto_route"] = []byte("true")
			base["route_exclude_address"] = []byte("[\"127.0.0.0/8\"]")
			if runtimeClientTunShape(base, platform) {
				t.Fatal("mobile loopback exclusion cannot be applied by provider")
			}
			base["route_exclude_address"] = []byte("[\"192.168.0.0/16\"]")
			for key, value := range map[string]string{"interface_name": "\"foreign\"", "include_mac_address": "[\"02:00:00:00:00:01\"]", "exclude_mac_address": "[\"02:00:00:00:00:01\"]", "auto_redirect": "true", "strict_route": "true", "dns_mode": "\"hijack\"", "platform": "{\"http_proxy\":{\"enabled\":true,\"server\":\"127.0.0.1\",\"server_port\":7890}}", "stack": "\"go\"", "include_package": "[\"com.example.app\"]"} {
				base[key] = []byte(value)
				if runtimeClientTunShape(base, platform) {
					t.Fatal("unsupported mobile field admitted", key)
				}
				delete(base, key)
			}
			base["exclude_package"] = []byte("[\"com.example.direct\"]")
			if runtimeClientTunShape(base, platform) != (platform == "android") {
				t.Fatal("Android exclusion crossed platform")
			}
			base["exclude_package"] = []byte("[\"bad package\"]")
			if runtimeClientTunShape(base, platform) {
				t.Fatal("unbounded/invalid package geometry")
			}
			delete(base, "exclude_package")
			base["address"] = []byte("[\"172.19.0.1/30\"]")
			if runtimeClientTunShape(base, platform) != (platform == "ios") {
				t.Fatal("fixed /30 explicit projection crossed platform")
			}
			base["address"] = []byte("[\"10.0.0.1/24\"]")
			if runtimeClientTunShape(base, platform) {
				t.Fatal("generic subnet editor acquired native authority")
			}
		})
	}
}

func clientShapeIPv6Port(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 socket fixture unavailable:", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func clientShapeMixedOptions(t *testing.T, listen string, port int) *option.HTTPMixedInboundOptions {
	t.Helper()
	var value option.HTTPMixedInboundOptions
	if err := json.Unmarshal([]byte(fmt.Sprintf("{\"listen\":%q,\"listen_port\":%d}", listen, port)), &value); err != nil {
		t.Fatal(err)
	}
	return &value
}

func clientShapeFinish(t *testing.T, f *runtimeTestFixture) {
	t.Helper()
	t.Cleanup(func() {
		if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
			t.Error(err)
			return
		}
		if err := f.box.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
}

func TestRuntimeAppAllowLANBothDirectionsAndMixedPortWithLANPublicApply(t *testing.T) {
	for _, row := range []struct {
		name, before, after string
		changePort          bool
	}{
		{"allowLAN-on", "127.0.0.1", "::", false},
		{"allowLAN-off", "::", "127.0.0.1", false},
		{"mixed-port-with-LAN", "::", "::", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			oldPort := clientShapeIPv6Port(t)
			newPort := oldPort
			if row.changePort {
				for newPort == oldPort {
					newPort = clientShapeIPv6Port(t)
				}
			}
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "client-shapes.test"), nil)
			mixed.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, row.before, oldPort)}}
			instance, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			f.box = instance
			clientShapeFinish(t, f)
			f.start(t)
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, row.after, newPort)}}
			content, err := json.MarshalContext(f.ctx, options.Options)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := instance.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
			if err != nil || legacy.Applicable {
				t.Fatal("legacy allowLAN boundary changed", legacy, err)
			}
			plan, request := runtimeClientPlan(t, f, content)
			if !plan.ImpactConfirmationRequired || len(plan.Impacts) == 0 || !plan.Impacts[0].ReconnectRequired {
				t.Fatal("actual wildcard handoff omitted confirmation", plan)
			}
			bad := request
			bad.AcceptedImpactDigest = ""
			if _, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", bad); err == nil {
				t.Fatal("caps/policy replaced user confirmation")
			}
			operation, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
			if err != nil || operation.Active.Revision != request.Expected.Revision+1 {
				t.Fatal("actual App listener handoff failed", operation, err)
			}
			connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", newPort), time.Second)
			if err != nil {
				t.Fatal("published listener has no actual socket", err)
			}
			_ = connection.Close()
		})
	}
}

func TestRuntimeAppAllowLANIPv6CollisionRestoresOriginalPublicIngress(t *testing.T) {
	port := clientShapeIPv6Port(t)
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "client-shapes.test"), nil)
	mixed.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, "127.0.0.1", port)}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	clientShapeFinish(t, f)
	f.start(t)
	// A Windows default socket does not prove exclusive ownership. The
	// platform fixture holds only IPv6 and verifies its actual socket options.
	holder := clientShapeIPv6CollisionHolder(t, port)
	holderAddr, ok := holder.Addr().(*net.TCPAddr)
	if !ok || holderAddr.Port != port || holderAddr.IP.To4() != nil || !holderAddr.IP.IsUnspecified() {
		_ = holder.Close()
		t.Fatal("holder did not bind the candidate IPv6 wildcard tuple", holder.Addr())
	}
	t.Cleanup(func() {
		if err := holder.Close(); err != nil {
			t.Error("close collision holder", err)
			return
		}
		// Reclaim exactly the same IPv6 tuple while the original IPv4
		// ingress is still alive; cleanup must release its real capability.
		reclaimed := clientShapeIPv6CollisionHolder(t, port)
		if err := reclaimed.Close(); err != nil {
			t.Error("close reclaimed collision holder", err)
		}
	})
	original, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal("IPv6-only holder displaced original IPv4 ingress", err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	before := f.identity()
	_, beforeView := f.acquire(t)
	options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, "::", port)}}
	content, err := json.MarshalContext(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	_, request := runtimeClientPlan(t, f, content)
	operation, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active != request.Expected || f.identity() != before || strings.HasPrefix(operation.State, "COMMITTED") {
		t.Fatal("IPv6 collision changed current graph", operation, err)
	}
	_, afterView := f.acquire(t)
	if afterView != beforeView {
		t.Fatal("failed IPv6 bind replaced the original graph view")
	}
	found := slices.ContainsFunc(operation.Errors, func(problem RuntimePlanError) bool { return problem.Code == "LISTENER_BIND_FAILED" })
	if !found {
		t.Fatal("candidate did not reach actual wildcard bind failure", operation)
	}
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal("original loopback ingress not restored", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal("restored mixed ingress did not receive SOCKS greeting", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{5, 0} {
		t.Fatal("restored original mixed ingress did not serve SOCKS greeting", reply, err)
	}
}

// The only replaced boundary is the original provider device. Core uses the
// real TUN constructor, Go stack/MemoryTun, RuntimeSet, receipt publication,
// rollback and retirement. This is not an OS VPN/FD proof or libbox ABI test.
type clientShapeLegacyTunPlatform struct {
	runtimeTestPlatform
	legacyOpens atomic.Int32
}

func (*clientShapeLegacyTunPlatform) UsePlatformInterface() bool { return true }
func (*clientShapeLegacyTunPlatform) ProcessPlatformOptions(option.TunPlatformOptions) error {
	return nil
}
func (*clientShapeLegacyTunPlatform) NetworkExtensionIncludeAllNetworks() bool { return false }
func (p *clientShapeLegacyTunPlatform) OpenInterface(options *nativeTun.Options, _ option.TunPlatformOptions) (nativeTun.Tun, error) {
	p.legacyOpens.Add(1)
	return nativeTun.NewMemoryTun(nativeTun.MemoryTunOptions{MTU: int(options.MTU)}), nil
}

type clientShapeNativeTunPlatform struct {
	*clientShapeLegacyTunPlatform
	version      atomic.Int32
	access       sync.Mutex
	sessions     []*clientShapeNativeTunSession
	failNextOpen bool
}

func (p *clientShapeNativeTunPlatform) RuntimeTunVersion() int { return int(p.version.Load()) }
func (p *clientShapeNativeTunPlatform) NewRuntimeTunSession(options *nativeTun.Options, _ option.TunPlatformOptions, previous adapter.RuntimeTunSession, receipt *adapter.RuntimeTunReceipt) (adapter.RuntimeTunSession, error) {
	p.access.Lock()
	defer p.access.Unlock()
	var old *clientShapeNativeTunSession
	if previous != nil {
		var ok bool
		old, ok = previous.(*clientShapeNativeTunSession)
		if !ok || old.platform != p {
			return nil, errors.New("foreign previous original owner")
		}
	}
	session := &clientShapeNativeTunSession{platform: p, previous: old, receipt: receipt, mtu: options.MTU, failOpen: p.failNextOpen, retiredDone: make(chan struct{})}
	p.failNextOpen = false
	p.sessions = append(p.sessions, session)
	return session, nil
}

func (p *clientShapeNativeTunPlatform) snapshot() []*clientShapeNativeTunSession {
	p.access.Lock()
	defer p.access.Unlock()
	return append([]*clientShapeNativeTunSession(nil), p.sessions...)
}

type clientShapeNativeTunSession struct {
	platform                             *clientShapeNativeTunPlatform
	previous                             *clientShapeNativeTunSession
	receipt                              *adapter.RuntimeTunReceipt
	mtu                                  uint32
	devices                              []*nativeTun.MemoryTun
	failOpen, prepared, aborted, retired bool
	retiredDone                          chan struct{}
}

func (s *clientShapeNativeTunSession) OwnerID() string { return s.receipt.OwnerID() }
func clientShapeDevicesClosed(devices []*nativeTun.MemoryTun) bool {
	for _, device := range devices {
		if _, err := device.WritePackets(nil); !errors.Is(err, os.ErrClosed) {
			return false
		}
	}
	return true
}

func (s *clientShapeNativeTunSession) Prepare() error {
	s.platform.access.Lock()
	defer s.platform.access.Unlock()
	if s.previous != nil && (!clientShapeDevicesClosed(s.previous.devices) || s.previous.receipt.Published()) {
		return errors.New("native preparation preceded old Core join/suspension")
	}
	s.prepared = true
	return nil
}

func (s *clientShapeNativeTunSession) Validate() error {
	s.platform.access.Lock()
	defer s.platform.access.Unlock()
	if !s.prepared || s.aborted || s.retired {
		return errors.New("native original session unavailable")
	}
	return nil
}

func (s *clientShapeNativeTunSession) OpenInterface(options *nativeTun.Options) (nativeTun.Tun, error) {
	s.platform.access.Lock()
	defer s.platform.access.Unlock()
	if !s.prepared || s.aborted || s.retired {
		return nil, errors.New("invalid native original owner")
	}
	if s.failOpen {
		return nil, errors.New("fixture duplicate failure after actual native Prepare")
	}
	device := nativeTun.NewMemoryTun(nativeTun.MemoryTunOptions{MTU: int(options.MTU)})
	s.devices = append(s.devices, device)
	return device, nil
}

func (s *clientShapeNativeTunSession) Abort() error {
	s.platform.access.Lock()
	defer s.platform.access.Unlock()
	if !clientShapeDevicesClosed(s.devices) {
		return errors.New("candidate native abort preceded Core device join")
	}
	s.aborted = true
	return nil
}

func (s *clientShapeNativeTunSession) Retire() error {
	s.platform.access.Lock()
	defer s.platform.access.Unlock()
	if !clientShapeDevicesClosed(s.devices) {
		return errors.New("native retirement preceded actual Core device close")
	}
	if !s.retired {
		s.retired = true
		close(s.retiredDone)
	}
	return nil
}

func clientShapeTunFixture(t *testing.T, platform adapter.PlatformInterface) (*runtimeTestFixture, Options) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "android" && runtime.GOOS != "ios" {
		t.Skip("client TUN geometry has no implementation on this platform")
	}
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "native-shapes.test"), nil)
	f.ctx = service.ContextWith[adapter.PlatformInterface](f.ctx, platform)
	options.Context = f.ctx
	protocolTun.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	address := "172.19.0.1/16"
	if runtime.GOOS == "darwin" {
		address = "172.19.0.1/30"
	}
	options.Inbounds = []option.Inbound{{Type: C.TypeTun, Tag: "tun-in", Options: &option.TunInboundOptions{Address: []netip.Prefix{netip.MustParsePrefix(address)}, MTU: 1500, AutoRoute: true}}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	clientShapeFinish(t, f)
	f.start(t)
	return f, options
}

func clientShapeTunCandidate(t *testing.T, f *runtimeTestFixture, options Options) []byte {
	t.Helper()
	next := *options.Inbounds[0].Options.(*option.TunInboundOptions)
	next.MTU = 1600
	next.Address = append(append([]netip.Prefix(nil), next.Address...), netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
	candidate := options.Options
	candidate.Inbounds = []option.Inbound{{Type: C.TypeTun, Tag: "tun-in", Options: &next}}
	content, err := json.MarshalContext(f.ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestRuntimeRegisteredV1TunPublicPlanApplyUsesActualOwnerReceiptAndJoin(t *testing.T) {
	bridge := &clientShapeNativeTunPlatform{clientShapeLegacyTunPlatform: &clientShapeLegacyTunPlatform{}}
	bridge.version.Store(1)
	f, options := clientShapeTunFixture(t, bridge)
	first := bridge.snapshot()
	if len(first) != 1 || !first[0].receipt.Published() || bridge.legacyOpens.Load() != 0 {
		t.Fatal("initial actual native owner not published")
	}
	content := clientShapeTunCandidate(t, f, options)
	legacy, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil || legacy.Applicable {
		t.Fatal("registered V1 replaced stored-policy guard", legacy, err)
	}
	plan, request := runtimeClientPlan(t, f, content)
	if len(bridge.snapshot()) != 1 {
		t.Fatal("Plan provisioned a native session")
	}
	if !plan.ImpactConfirmationRequired || !slices.ContainsFunc(plan.Impacts, func(impact RuntimeImpact) bool { return impact.Path == "inbounds" && impact.ReconnectRequired }) {
		t.Fatal("native migration omitted reset risk", plan)
	}
	bad := request
	bad.AcceptedImpactDigest = ""
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", bad); err == nil {
		t.Fatal("V1 registration replaced impact acceptance")
	}
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != request.Expected.Revision+1 {
		t.Fatal("registered finite TUN candidate not published", operation, err)
	}
	current := bridge.snapshot()
	if len(current) != 2 || current[1].previous != first[0] || current[1].mtu != 1600 || !current[1].receipt.Published() || first[0].receipt.Published() || bridge.legacyOpens.Load() != 0 {
		t.Fatal("public Apply bypassed original provider/receipt")
	}
	runtimeTestWait(t, first[0].retiredDone, "original native owner retirement")
	replay, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || replay.Active != operation.Active || len(bridge.snapshot()) != 2 {
		t.Fatal("replay repeated native effects", replay, err)
	}
}

func TestRuntimeNativePublicPlanRejectsOldAbsentUnknownOrLostV1(t *testing.T) {
	t.Run("old SDK has no registration interface", func(t *testing.T) {
		platform := &clientShapeLegacyTunPlatform{}
		f, options := clientShapeTunFixture(t, platform)
		content := clientShapeTunCandidate(t, f, options)
		plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), content, nil, RuntimeClientImpactPolicyExplicit)
		if err != nil || plan.Applicable || platform.legacyOpens.Load() != 1 {
			t.Fatal("old SDK gained replacement from GOOS/policy", plan, err)
		}
	})
	for _, version := range []int32{0, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			bridge := &clientShapeNativeTunPlatform{clientShapeLegacyTunPlatform: &clientShapeLegacyTunPlatform{}}
			bridge.version.Store(1)
			f, options := clientShapeTunFixture(t, bridge)
			bridge.version.Store(version)
			plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), clientShapeTunCandidate(t, f, options), nil, RuntimeClientImpactPolicyExplicit)
			if err != nil || plan.Applicable || len(bridge.snapshot()) != 1 || bridge.legacyOpens.Load() != 0 {
				t.Fatal("unregistered/quarantined/unknown version admitted", plan, err)
			}
		})
	}
}

func TestRuntimeNativePublicPlanKeepsOriginalCapturedPhysicalDependencies(t *testing.T) {
	bridge := &clientShapeNativeTunPlatform{clientShapeLegacyTunPlatform: &clientShapeLegacyTunPlatform{}}
	bridge.version.Store(1)
	f, options := clientShapeTunFixture(t, bridge)
	f.box.runtime.access.Lock()
	f.box.runtime.tunDependencies["inbound:tun-in"] = "not-the-captured-identity"
	f.box.runtime.access.Unlock()
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), clientShapeTunCandidate(t, f, options), nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || plan.Applicable || len(bridge.snapshot()) != 1 {
		t.Fatal("V1 recaptured/ignored original physical closure", plan, err)
	}
}

func TestRuntimeNativePublicApplyFailureRetainsOriginalSessionForRestoration(t *testing.T) {
	bridge := &clientShapeNativeTunPlatform{clientShapeLegacyTunPlatform: &clientShapeLegacyTunPlatform{}}
	bridge.version.Store(1)
	f, options := clientShapeTunFixture(t, bridge)
	first := bridge.snapshot()[0]
	_, request := runtimeClientPlan(t, f, clientShapeTunCandidate(t, f, options))
	bridge.access.Lock()
	bridge.failNextOpen = true
	bridge.access.Unlock()
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active != request.Expected || strings.HasPrefix(operation.State, "COMMITTED") {
		t.Fatal("failed native duplicate changed active graph", operation, err)
	}
	waitRetryState(t, f.box.runtime, func() bool {
		record := f.box.runtime.plans[request.TransactionID]
		return record.operation != nil && record.operation.State == "ABORTED_UNAPPLIED"
	})
	bridge.access.Lock()
	sessions := append([]*clientShapeNativeTunSession(nil), bridge.sessions...)
	restored := len(first.devices) > 1 && !first.aborted && !first.retired
	aborted := len(sessions) == 2 && sessions[1].aborted
	bridge.access.Unlock()
	if !restored || !aborted || !first.receipt.Published() || sessions[1].receipt.Published() || bridge.legacyOpens.Load() != 0 {
		t.Fatal("rollback lost or replaced original native custody")
	}
}
