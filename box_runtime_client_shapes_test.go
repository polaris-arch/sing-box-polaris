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
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
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
		t.Fatal("required IPv6 socket fixture unavailable:", err)
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

func clientShapeSOCKSGreeting(network, address string) (err error) {
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if n, writeErr := conn.Write([]byte{5, 1, 0}); writeErr != nil {
		return writeErr
	} else if n != 3 {
		return io.ErrShortWrite
	}
	var reply [2]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, 0} {
		return fmt.Errorf("wrong actual mixed ingress SOCKS reply: %x", reply)
	}
	return nil
}

// The holder must receive IPv6 bytes itself. Its accept worker and both peers
// share the existing one-second bound and are joined before close/reclaim.
func clientShapeIPv6HolderBytes(holder net.Listener, port int) error {
	tcp, ok := holder.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("holder has no finite native TCP accept: %T", holder)
	}
	deadline := time.Now().Add(time.Second)
	if err := tcp.SetDeadline(deadline); err != nil {
		return err
	}
	sentinel := [4]byte{'h', 'o', 'l', 'd'}
	done := make(chan error, 1)
	go func() {
		conn, err := tcp.AcceptTCP()
		if err == nil {
			err = func() error {
				if err := conn.SetDeadline(deadline); err != nil {
					return err
				}
				var received [4]byte
				if _, err := io.ReadFull(conn, received[:]); err != nil {
					return err
				}
				if received != sentinel {
					return fmt.Errorf("IPv6 holder received foreign bytes: %x", received)
				}
				if n, err := conn.Write(received[:]); err != nil {
					return err
				} else if n != len(received) {
					return io.ErrShortWrite
				}
				var trailing [1]byte
				if n, err := conn.Read(trailing[:]); n != 0 || err != io.EOF {
					return fmt.Errorf("holder peer did not finish its write side: %d, %v", n, err)
				}
				return nil
			}()
			err = errors.Join(err, conn.Close())
		}
		done <- err
	}()
	clientErr := func() (err error) {
		conn, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), time.Second)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, conn.Close()) }()
		if err = conn.SetDeadline(deadline); err != nil {
			return err
		}
		if n, err := conn.Write(sentinel[:]); err != nil {
			return err
		} else if n != len(sentinel) {
			return io.ErrShortWrite
		}
		if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
			return err
		}
		var reply [4]byte
		if _, err = io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if reply != sentinel {
			return fmt.Errorf("IPv6 bytes reached another receiver: %x", reply)
		}
		var trailing [1]byte
		if n, err := conn.Read(trailing[:]); n != 0 || err != io.EOF {
			return fmt.Errorf("holder did not close after peer EOF: %d, %v", n, err)
		}
		return nil
	}()
	serverErr := <-done
	return errors.Join(clientErr, serverErr, tcp.SetDeadline(time.Time{}))
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
			if err := clientShapeSOCKSGreeting("tcp4", fmt.Sprintf("127.0.0.1:%d", newPort)); err != nil {
				t.Fatal("published IPv4 ingress did not serve actual SOCKS bytes", err)
			}
			if row.after == "::" {
				if err := clientShapeSOCKSGreeting("tcp6", fmt.Sprintf("[::1]:%d", newPort)); err != nil {
					t.Fatal("published allowLAN ingress lost native IPv6 SOCKS bytes", err)
				}
			} else {
				closed, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", newPort), time.Second)
				if err == nil {
					_ = closed.Close()
					t.Fatal("allowLAN-off retained an IPv6 listening socket")
				}
			}
		})
	}
}

func TestRuntimeAppAllowLANIPv6CollisionRestoresOriginalPublicIngress(t *testing.T) {
	port := clientShapeIPv6Port(t)
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "client-shapes.test"), nil)
	// On an unexpected commit, retain actual bound family/options/tuple logs.
	options.Log = &option.LogOptions{Level: "debug", DisableColor: true}
	mixed.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, "127.0.0.1", port)}}
	clientShapeUseDirect(&options)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	clientShapeFinish(t, f)
	f.start(t)
	held := clientShapeOpenTunnel(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	held.exchange(t, "before-collision")
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
	if err := clientShapeIPv6HolderBytes(holder, port); err != nil {
		t.Fatal("original IPv6 tuple holder did not receive actual sentinel bytes", err)
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
		t.Log("candidate native family/options/local tuple are recorded by the actual bind readback above")
		t.Log("IPv4 mixed SOCKS byte receiver:", clientShapeSOCKSGreeting("tcp4", fmt.Sprintf("127.0.0.1:%d", port)))
		t.Log("IPv6 original holder sentinel byte receiver:", clientShapeIPv6HolderBytes(holder, port))
		t.Fatal("IPv6 collision changed current graph", operation, err)
	}
	if err := clientShapeIPv6HolderBytes(holder, port); err != nil {
		t.Fatal("failed candidate changed the original IPv6 byte receiver", err)
	}
	_, afterView := f.acquire(t)
	if afterView != beforeView {
		t.Fatal("failed IPv6 bind replaced the original graph view")
	}
	found := slices.ContainsFunc(operation.Errors, func(problem RuntimePlanError) bool { return problem.Code == "LISTENER_BIND_FAILED" })
	if !found {
		t.Fatal("candidate did not reach actual wildcard bind failure", operation)
	}
	held.exchange(t, "after-collision")
	held.finish(t)
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

// Use the registered production direct outbound for literal loopback targets.
// The SOCKS fixtures in runtimeTestConfig remain present and unchanged.
func clientShapeUseDirect(options *Options) {
	options.Outbounds = append(options.Outbounds, option.Outbound{Type: C.TypeDirect, Tag: "native-echo", Options: &option.DirectOutboundOptions{}})
	route := *options.Route
	route.Final = "native-echo"
	options.Route = &route
}

type clientShapeTunnel struct {
	client, peer *net.TCPConn
	closeOnce    sync.Once
	closeErr     error
}

func (p *clientShapeTunnel) close() error {
	p.closeOnce.Do(func() { p.closeErr = errors.Join(p.client.Close(), p.peer.Close()) })
	return p.closeErr
}

// Both ends are real TCP sockets. The peer is accepted synchronously after the
// production mixed/SOCKS CONNECT succeeds; no test echo worker can outlive it.
func clientShapeOpenTunnel(t *testing.T, network, address string) *clientShapeTunnel {
	t.Helper()
	echo, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := echo.Close(); err != nil {
			t.Error("close literal local peer listener", err)
		}
	}()
	if err := echo.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatal("dial actual mixed ingress", err)
	}
	client, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		t.Fatalf("native TCP carrier has type %T", connection)
	}
	// Register cleanup before any handshake assertion can terminate the test.
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Write([]byte{5, 1, 0}); err != nil || n != 3 {
		t.Fatal("write actual SOCKS greeting", n, err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("actual mixed receiver rejected SOCKS greeting", greeting, err)
	}
	port := echo.Addr().(*net.TCPAddr).Port
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if n, err := client.Write(request); err != nil || n != len(request) {
		t.Fatal("write real SOCKS CONNECT", n, err)
	}
	var response [4]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || response[0] != 5 || response[1] != 0 || response[2] != 0 {
		t.Fatal("production SOCKS CONNECT did not reach local peer", response, err)
	}
	remaining := 0
	switch response[3] {
	case 1:
		remaining = 6
	case 4:
		remaining = 18
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			t.Fatal(err)
		}
		remaining = int(length[0]) + 2
	default:
		t.Fatal("invalid actual SOCKS CONNECT address type", response)
	}
	if _, err := io.ReadFull(client, make([]byte, remaining)); err != nil {
		t.Fatal("read actual SOCKS CONNECT bound address", err)
	}
	peer, err := echo.AcceptTCP()
	if err != nil {
		t.Fatal("accept production direct outbound", err)
	}
	p := &clientShapeTunnel{client: client, peer: peer}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error("close real held tunnel", err)
		}
	})
	return p
}

func (p *clientShapeTunnel) exchange(t *testing.T, payload string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	if err := errors.Join(p.client.SetDeadline(deadline), p.peer.SetDeadline(deadline)); err != nil {
		t.Fatal(err)
	}
	data := []byte(payload)
	if n, err := p.client.Write(data); err != nil || n != len(data) {
		t.Fatal("held SOCKS carrier write", n, err)
	}
	received := make([]byte, len(data))
	if _, err := io.ReadFull(p.peer, received); err != nil || string(received) != payload {
		t.Fatal("actual local peer lost held-carrier bytes", string(received), err)
	}
	if n, err := p.peer.Write(received); err != nil || n != len(received) {
		t.Fatal("actual local peer reply", n, err)
	}
	if _, err := io.ReadFull(p.client, received); err != nil || string(received) != payload {
		t.Fatal("held SOCKS carrier lost return bytes", string(received), err)
	}
}

func (p *clientShapeTunnel) finish(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	if err := errors.Join(p.client.SetDeadline(deadline), p.peer.SetDeadline(deadline)); err != nil {
		t.Fatal(err)
	}
	if err := p.client.CloseWrite(); err != nil {
		t.Fatal("finish held client write side", err)
	}
	var tail [1]byte
	if n, err := p.peer.Read(tail[:]); n != 0 || err != io.EOF {
		t.Fatal("production tunnel did not forward client EOF", n, err)
	}
	if err := p.peer.CloseWrite(); err != nil {
		t.Fatal("finish local peer write side", err)
	}
	if n, err := p.client.Read(tail[:]); n != 0 || err != io.EOF {
		t.Fatal("production tunnel did not forward peer EOF", n, err)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeAppListenerHandoffPreservesActualHeldFamilyTunnels(t *testing.T) {
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
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "held-client-shapes.test"), nil)
			mixed.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
			clientShapeUseDirect(&options)
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, row.before, oldPort)}}
			runtimeResourceNew(t, f, options)
			f.start(t)
			if row.changePort {
				newPort = clientShapeIPv6Port(t)
				if newPort == oldPort {
					t.Fatal("distinct native port fixture returned the old port")
				}
			}
			oldLease, oldView := f.acquire(t)
			oldInbound, ok := oldView.inbounds.Get("mixed-in")
			if !ok {
				t.Fatal("original real mixed receiver is absent")
			}
			oldResource := runtimeTestResource(t, f, oldView.componentIDs["inbound:mixed-in"])
			held4 := clientShapeOpenTunnel(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", oldPort))
			held4.exchange(t, "old-v4-before")
			var held6 *clientShapeTunnel
			if row.before == "::" {
				held6 = clientShapeOpenTunnel(t, "tcp6", fmt.Sprintf("[::1]:%d", oldPort))
				held6.exchange(t, "old-v6-before")
			}
			// Only the actual accepted carriers may keep this old inbound owner alive.
			oldLease.Release()
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, row.after, newPort)}}
			_, request := runtimeClientPlan(t, f, runtimeResourceEncode(t, f, options.Options))
			operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
			if err != nil || !strings.HasPrefix(operation.State, "COMMITTED") || operation.Active.Revision != request.Expected.Revision+1 || operation.RetirementState != "PENDING" {
				t.Fatal("real held-family public handoff did not commit with retained owner", operation, err)
			}
			select {
			case <-oldResource.owner.Closed():
				t.Fatal("old accepted carrier lost its original inbound owner")
			default:
			}
			held4.exchange(t, "old-v4-after")
			if held6 != nil {
				held6.exchange(t, "old-v6-after")
			}
			newLease, newView := f.acquire(t)
			newInbound, ok := newView.inbounds.Get("mixed-in")
			if !ok || newView == oldView || newInbound == oldInbound || newView.componentIDs["inbound:mixed-in"] == oldResource.id {
				t.Fatal("published receiver did not belong to the new actual graph")
			}
			newLease.Release()
			fresh4 := clientShapeOpenTunnel(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", newPort))
			fresh4.exchange(t, "new-v4-receiver")
			fresh4.finish(t)
			if row.after == "::" {
				fresh6 := clientShapeOpenTunnel(t, "tcp6", fmt.Sprintf("[::1]:%d", newPort))
				fresh6.exchange(t, "new-v6-receiver")
				fresh6.finish(t)
			}
			if row.after != "::" || row.changePort {
				unexpected, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", oldPort), time.Second)
				if err == nil {
					_ = unexpected.Close()
					t.Fatal("post-K retirement left old native IPv6 listening ingress open")
				}
			}
			held4.finish(t)
			if held6 != nil {
				held6.finish(t)
			}
			if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
				t.Fatal("old inbound owner did not drain after real carrier completion", err)
			}
		})
	}
}

// Reuse the existing callback fixture but declare this entirely local fault as
// having no external registration debt. Each registration uses its constructor's
// exact preparing context, so no stage callback is shared between Box instances.
type clientShapeLateEffect struct{ runtimeCertificateAliasEffect }

func (*clientShapeLateEffect) RuntimeExternalEffects() bool { return false }

func TestRuntimeAppLateAbortResumesHeldIPv6AndOriginalPublicIngress(t *testing.T) {
	for _, row := range []struct {
		name, after        string
		changePort, cancel bool
	}{
		{"allowLAN-off-effect", "127.0.0.1", false, false},
		{"port-change-cancel", "::", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			oldPort := clientShapeIPv6Port(t)
			newPort := oldPort
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "late-client-shapes.test"), nil)
			clientShapeUseDirect(&options)
			var fail atomic.Bool
			var reached atomic.Int32
			var cancel context.CancelFunc
			cause := errors.New("fixture failure after actual listener Stage")
			registry := service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry)
			inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeMixed, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, value option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
				actual, err := mixed.NewInbound(ctx, router, logger, tag, value)
				if err != nil {
					return nil, err
				}
				// Reuse the existing callback-only post-bind fixture. The registered
				// object remains the production mixed inbound and its native listener.
				effect := &clientShapeLateEffect{runtimeCertificateAliasEffect{stage: func() error {
					if !fail.Load() {
						return nil
					}
					listeners := actual.(inbound.RuntimePreparedInbound).RuntimeListeners()
					if len(listeners) != 1 {
						return errors.New("late failure has no exact candidate logical listener")
					}
					for _, l := range listeners {
						if l.RuntimeStatus().Phase != "armed" {
							return errors.New("late failure ran before actual candidate listeners armed")
						}
					}
					reached.Add(1)
					if row.cancel {
						cancel()
						return nil
					}
					return cause
				}}}
				if err := adapter.RegisterRuntimePostBindEffect(ctx, effect); err != nil {
					return nil, err
				}
				return actual, nil
			})
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, "::", oldPort)}}
			runtimeResourceNew(t, f, options)
			f.start(t)
			if row.changePort {
				newPort = clientShapeIPv6Port(t)
				if newPort == oldPort {
					t.Fatal("distinct native port fixture returned the old port")
				}
			}
			held4 := clientShapeOpenTunnel(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", oldPort))
			held6 := clientShapeOpenTunnel(t, "tcp6", fmt.Sprintf("[::1]:%d", oldPort))
			held4.exchange(t, "late-old-v4-before")
			held6.exchange(t, "late-old-v6-before")
			before := f.identity()
			oldLease, oldView := f.acquire(t)
			oldLease.Release()
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: clientShapeMixedOptions(t, row.after, newPort)}}
			_, request := runtimeClientPlan(t, f, runtimeResourceEncode(t, f, options.Options))
			ctx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			cancel = cancelRequest
			fail.Store(true)
			operation, err := f.box.ApplyRuntimeConfig(ctx, "actor-a", request)
			if err != nil || reached.Load() != 1 || operation.Active != before || f.identity() != before || strings.HasPrefix(operation.State, "COMMITTED") {
				t.Fatal("late actual Stage failure lost original identity or missed its injection", operation, reached.Load(), err)
			}
			if !slices.ContainsFunc(operation.Errors, func(problem RuntimePlanError) bool { return problem.Code == "PREPARATION_FAILED" }) || slices.ContainsFunc(operation.Errors, func(problem RuntimePlanError) bool {
				return problem.Code == "LISTENER_BIND_FAILED" || problem.Code == "LISTENER_RESTORATION_FAILED"
			}) {
				t.Fatal("late failure was replaced by early bind refusal or lost restoration", operation)
			}
			newLease, afterView := f.acquire(t)
			if afterView != oldView {
				t.Fatal("late failed candidate replaced the original graph view")
			}
			newLease.Release()
			held4.exchange(t, "late-old-v4-after")
			held6.exchange(t, "late-old-v6-after")
			fresh4 := clientShapeOpenTunnel(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", oldPort))
			fresh6 := clientShapeOpenTunnel(t, "tcp6", fmt.Sprintf("[::1]:%d", oldPort))
			fresh4.exchange(t, "resumed-v4-receiver")
			fresh6.exchange(t, "resumed-v6-receiver")
			fresh4.finish(t)
			fresh6.finish(t)
			if row.changePort {
				// No candidate accepted connection exists; reclaim both exact families
				// only after Apply's candidate-first cleanup has returned.
				v6 := clientShapeIPv6CollisionHolder(t, newPort)
				if err := v6.Close(); err != nil {
					t.Fatal("candidate IPv6 tuple cleanup", err)
				}
				v4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", newPort))
				if err != nil {
					t.Fatal("candidate IPv4 tuple was not released", err)
				}
				if err := v4.Close(); err != nil {
					t.Fatal(err)
				}
			}
			held4.finish(t)
			held6.finish(t)
		})
	}
}

func TestRuntimeListenerRetirementObserverPreservesStickyUnknownReceipt(t *testing.T) {
	cause := errors.New("first physical listener close remained unknown")
	for _, row := range []struct {
		name, retirement string
		err              error
	}{
		{"listener-first-error", "PENDING", cause},
		{"prior-post-commit-unknown", "UNKNOWN", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			identity := RuntimeIdentity{Incarnation: "observer", Revision: 2, EffectiveDigest: "committed"}
			record := &runtimePlanRecord{actor: "actor-a", inFlight: true, storageCharge: 19, operation: &RuntimeConfigOperation{ContractVersion: RuntimeConfigContractVersion, TransactionID: "observer", State: "COMMITTED", Active: identity, Durable: true, RetirementState: row.retirement}}
			if row.retirement == "UNKNOWN" {
				record.operation.Errors = []RuntimePlanError{{Code: "POST_COMMIT_FAILURE"}}
			}
			c := &runtimeCoordinator{active: identity, now: time.Now, plans: map[string]*runtimePlanRecord{"observer": record}, planStorage: 19}
			instance := &Box{runtime: c}
			instance.observeRuntimeRetirement(record, nil, row.err)
			// A later otherwise successful observer must not launder the first result.
			instance.observeRuntimeRetirement(record, nil, nil)
			status, err := instance.GetRuntimeConfigStatus("actor-a", identity.Incarnation, "observer")
			if err != nil || status.LookupState != "FOUND" || status.Operation == nil || status.Operation.RetirementState != "UNKNOWN" || status.Operation.State != "COMMITTED" || status.Operation.Active != identity || !status.Operation.Durable {
				t.Fatal("retirement error changed commit or vanished from actual status", status, err)
			}
			if !record.inFlight || record.receiptExpires != 0 || c.planStorage != record.storageCharge || c.plans["observer"] != record {
				t.Fatal("unknown cleanup receipt was expired or uncharged", record, c.planStorage)
			}
		})
	}
}

func TestRuntimeListenerRetirementObserverWaitsForActualOwnerBarrier(t *testing.T) {
	barrier := newRuntimeTestBarrier()
	defer barrier.open()
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "observer", Sequence: 1}, nil, func() error { barrier.block(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	runtimeTestWait(t, barrier.entered, "actual old owner cleanup")
	identity := RuntimeIdentity{Incarnation: "observer", Revision: 2, EffectiveDigest: "committed"}
	record := &runtimePlanRecord{inFlight: true, operation: &RuntimeConfigOperation{State: "COMMITTED_DURABILITY_PENDING", Active: identity, RetirementState: "PENDING"}}
	instance := &Box{runtime: &runtimeCoordinator{now: time.Now}}
	done := make(chan struct{})
	go func() {
		instance.observeRuntimeRetirement(record, []*runtimeResource{{owner: owner}}, nil)
		close(done)
	}()
	t.Cleanup(func() {
		barrier.open()
		runtimeTestWait(t, done, "retirement observer cleanup join")
	})
	select {
	case <-done:
		t.Fatal("observer certified drain before actual old owner cleanup")
	default:
	}
	instance.runtime.access.Lock()
	pending := record.operation.RetirementState == "PENDING" && record.inFlight && record.receiptExpires == 0
	instance.runtime.access.Unlock()
	if !pending {
		t.Fatal("held cleanup lost its pending charged receipt")
	}
	barrier.open()
	runtimeTestWait(t, done, "actual retirement observer")
	if record.operation.RetirementState != "DRAINED" || record.inFlight || record.receiptExpires == 0 || record.operation.State != "COMMITTED_DURABILITY_PENDING" || record.operation.Active != identity || record.operation.Durable {
		t.Fatal("successful actual owner drain changed durability or missed completion", record.operation)
	}
}

func TestRuntimeListenerRetirementOwnerFailureStaysInCatalog(t *testing.T) {
	cause := errors.New("sticky listener completion fixture")
	scope := adapter.NewScope(context.Background(), nil)
	scope.Add(func() error { return runtimeCleanupResult(cause) })
	id := adapter.RuntimeResourceID{Incarnation: "observer", Sequence: 1}
	owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	if err := owner.WaitClosed(runtimeTestContext(t)); !errors.Is(err, cause) || !errors.Is(err, errRuntimeCleanupIncomplete) {
		t.Fatal("actual original scope cleanup lost sticky completion", err)
	}
	resource := &runtimeResource{id: id, owner: owner, scope: scope}
	record := &runtimePlanRecord{inFlight: true, operation: &RuntimeConfigOperation{State: "COMMITTED", RetirementState: "PENDING"}}
	c := &runtimeCoordinator{now: time.Now, catalog: map[adapter.RuntimeResourceID]*runtimeResource{id: resource}}
	instance := &Box{runtime: c}
	instance.observeRuntimeRetirement(record, []*runtimeResource{resource}, nil)
	c.access.Lock()
	c.pruneRuntimeCatalogLocked()
	kept := c.catalog[id] == resource
	c.access.Unlock()
	if !kept || record.operation.RetirementState != "UNKNOWN" || !record.inFlight || record.receiptExpires != 0 {
		t.Fatal("actual owner failure was pruned or receipt falsely drained", record.operation, kept)
	}
}
