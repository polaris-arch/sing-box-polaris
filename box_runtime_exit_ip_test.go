package box

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func newExitIPRuntimeFixture(t *testing.T) *runtimeTestFixture {
	t.Helper()
	fixture, options := newRuntimeTestConstruction(t, []byte(`{
		"log":{"disabled":true},
		"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},
		"outbounds":[
			{"type":"socks","tag":"a","server":"192.0.2.1","server_port":1080},
			{"type":"socks","tag":"b","server":"192.0.2.2","server_port":1080},
			{"type":"direct","tag":"direct"},
			{"type":"selector","tag":"nested","outbounds":["a"]},
			{"type":"socks","tag":"detoured","server":"192.0.2.3","server_port":1080,"detour":"direct"},
			{"type":"socks","tag":"wrapped","server":"192.0.2.4","server_port":1080},
			{"type":"socks","tag":"socks4","server":"192.0.2.5","server_port":1080,"version":"4"},
			{"type":"selector","tag":"proxy-selector","outbounds":["a","b","direct","nested","detoured","wrapped","socks4"],"default":"a"}
		],
		"route":{"final":"proxy-selector"}
	}`), nil)
	registry := service.FromContext[adapter.OutboundRegistry](options.Context).(*outbound.Registry)
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		leaf, err := socks.NewOutbound(ctx, router, logger, tag, options)
		if err == nil && tag == "wrapped" {
			return &runtimeTestSocks{Outbound: leaf.(*socks.Outbound)}, nil
		}
		return leaf, err
	})
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	fixture.box = instance
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	fixture.start(t)
	return fixture
}

func selectExitIPTestLeaf(t *testing.T, fixture *runtimeTestFixture, tag string) {
	t.Helper()
	selector, exists := fixture.box.Outbound().Outbound(runtimeExitIPSelector)
	if !exists || !selector.(interface{ SelectOutbound(string) bool }).SelectOutbound(tag) {
		t.Fatalf("select %q", tag)
	}
}

func TestRuntimeExitIPAdmissionAndNoDial(t *testing.T) {
	fixture := newExitIPRuntimeFixture(t)
	ctx := runtimeTestContext(t)
	active := fixture.identity()
	calls := 0
	fetch := func(_ context.Context, leaf adapter.Outbound) ([]byte, error) {
		calls++
		if _, ok := leaf.(*socks.Outbound); !ok || leaf.Tag() != "a" {
			t.Fatalf("wrong actual graph leaf: %T %s", leaf, leaf.Tag())
		}
		return []byte("ip=198.51.100.4\nloc=US\n"), nil
	}
	body, err := fixture.box.probeRuntimeExitIP(ctx, active, "a", fetch)
	if err != nil || len(body) == 0 || calls != 1 {
		t.Fatalf("exact leaf did not run once: calls=%d err=%v", calls, err)
	}
	checkDenied := func(identity RuntimeIdentity, tag string) {
		t.Helper()
		body, err := fixture.box.probeRuntimeExitIP(ctx, identity, tag, fetch)
		if !errors.Is(err, ErrRuntimeExitIPNotAdmitted) || body != nil || calls != 1 {
			t.Fatalf("unexpected provider admission: calls=%d err=%v", calls, err)
		}
	}
	wrongInstance := active
	wrongInstance.Incarnation = "other-instance"
	checkDenied(wrongInstance, "a")
	wrongGraph := active
	wrongGraph.Revision++
	checkDenied(wrongGraph, "a")
	wrongDigest := active
	wrongDigest.EffectiveDigest = "other-digest"
	checkDenied(wrongDigest, "a")
	checkDenied(active, "b")
	checkDenied(active, "missing")
	for _, tag := range []string{"direct", "nested", "detoured", "wrapped", "socks4", "a"} {
		selectExitIPTestLeaf(t, fixture, tag)
		checkDenied(active, "a")
		if tag != "a" {
			checkDenied(fixture.identity(), tag)
		}
	}
	if live := fixture.identity(); live.ControlRevision == active.ControlRevision || live.Revision != active.Revision {
		t.Fatal("A/B/A did not advance only the control revision")
	}
	// A new network epoch rejects all work until native network setup is ready.
	history := service.PtrFromContext[urltest.HistoryStorage](fixture.box.runtime.ctx)
	next := history.AdvanceNetworkEpoch()
	checkDenied(fixture.identity(), "a")
	if !history.MarkReady(next) {
		t.Fatal("could not restore network readiness")
	}
}

func TestRuntimeExitIPCancelsAndDrainsBeforeNextAdmission(t *testing.T) {
	f := newExitIPRuntimeFixture(t)
	ctx := runtimeTestContext(t)
	active := f.identity()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := f.box.probeRuntimeExitIP(ctx, active, "a", func(ctx context.Context, _ adapter.Outbound) ([]byte, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return []byte("stale"), nil
		})
		result <- err
	}()
	defer close(release)
	runtimeTestWait(t, entered, "actual exit probe")
	selectExitIPTestLeaf(t, f, "b")
	selectExitIPTestLeaf(t, f, "a")
	runtimeTestWait(t, canceled, "revision cancels the actual probe")
	current := f.identity()
	fetches := 0
	fetch := func(_ context.Context, _ adapter.Outbound) ([]byte, error) {
		fetches++
		return []byte("new"), nil
	}
	if _, err := f.box.probeRuntimeExitIP(ctx, current, "a", fetch); !errors.Is(err, ErrRuntimeExitIPBusy) || fetches != 0 {
		t.Fatalf("second provider request entered an undrained slot: calls=%d err=%v", fetches, err)
	}
	release <- struct{}{}
	select {
	case err := <-result:
		if !errors.Is(err, ErrRuntimeExitIPSuperseded) {
			t.Fatalf("superseded body returned: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := f.box.probeRuntimeExitIP(ctx, current, "a", fetch); err != nil || fetches != 1 {
		t.Fatalf("drained slot was not readmitted: calls=%d err=%v", fetches, err)
	}
}

func TestRuntimeExitIPResponseBounds(t *testing.T) {
	normal := "ip=198.51.100.4\nloc=US\n"
	for _, test := range []struct {
		name, response string
		want           string
	}{
		{"trace", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(normal), normal), normal},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n", ""},
		{"short-body", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + normal, ""},
		{"oversize-body", "HTTP/1.0 200 OK\r\n\r\n" + strings.Repeat("x", runtimeExitIPMaxBody+1), ""},
		{"oversize-header", "HTTP/1.0 200 OK\r\nX-Data: " + strings.Repeat("x", runtimeExitIPMaxResponse) + "\r\n\r\n" + normal, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, runtimeExitIPURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := readRuntimeExitIPResponse(strings.NewReader(test.response), request)
			if string(body) != test.want || (err == nil) != (test.want != "") {
				t.Fatalf("response decision: bytes=%d err=%v", len(body), err)
			}
		})
	}
}

func TestRuntimeExitIPUnconfirmedCleanupQuarantinesFastSlot(t *testing.T) {
	f := newExitIPRuntimeFixture(t)
	ctx := runtimeTestContext(t)
	calls := 0
	fetch := func(_ context.Context, _ adapter.Outbound) ([]byte, error) {
		calls++
		return []byte("unsafe"), ErrRuntimeExitIPUncertain
	}
	body, err := f.box.probeRuntimeExitIP(ctx, f.identity(), "a", fetch)
	if body != nil || !errors.Is(err, ErrRuntimeExitIPUncertain) {
		t.Fatalf("unconfirmed close published: %v", err)
	}
	selectExitIPTestLeaf(t, f, "b")
	if _, err := f.box.probeRuntimeExitIP(ctx, f.identity(), "b", fetch); !errors.Is(err, ErrRuntimeExitIPBusy) || calls != 1 {
		t.Fatalf("quarantined fast slot was readmitted: calls=%d err=%v", calls, err)
	}
}

func TestRuntimeExitIPCallerDeadlineReservesDrainTime(t *testing.T) {
	f := newExitIPRuntimeFixture(t)
	short, cancelShort := context.WithTimeout(runtimeTestContext(t), runtimeExitIPDrainWindow)
	defer cancelShort()
	if _, err := f.box.probeRuntimeExitIP(short, f.identity(), "a", func(context.Context, adapter.Outbound) ([]byte, error) {
		t.Fatal("provider started without a drain window")
		return nil, nil
	}); !errors.Is(err, ErrRuntimeExitIPNotAdmitted) {
		t.Fatalf("unexpected result with exhausted provider time: %v", err)
	}

	caller, cancelCaller := context.WithTimeout(runtimeTestContext(t), time.Second)
	defer cancelCaller()
	responseDeadline, _ := caller.Deadline()
	_, err := f.box.probeRuntimeExitIP(caller, f.identity(), "a", func(ctx context.Context, _ adapter.Outbound) ([]byte, error) {
		providerDeadline, _ := ctx.Deadline()
		if !providerDeadline.Equal(responseDeadline.Add(-runtimeExitIPDrainWindow)) {
			t.Fatalf("provider deadline %v, caller %v", providerDeadline, responseDeadline)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, ErrRuntimeExitIPUnavailable) || caller.Err() != nil {
		t.Fatalf("clean provider deadline failed to leave time for a drain witness: err=%v caller=%v", err, caller.Err())
	}
}

type exitIPSocketFixture struct {
	adapter.Outbound
	socket  net.Conn
	network string
	address M.Socksaddr
}

func (f *exitIPSocketFixture) DialContext(_ context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	f.network, f.address = network, address
	return f.socket, nil
}

func TestRuntimeExitIPCancellationClosesActualSocket(t *testing.T) {
	parent := runtimeTestContext(t)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	transport, peer := net.Pipe()
	defer peer.Close()
	defer transport.Close()
	fixture := &exitIPSocketFixture{socket: transport}
	done := make(chan error, 1)
	go func() {
		_, err := fetchRuntimeExitIP(ctx, fixture)
		done <- err
	}()
	deadline, _ := ctx.Deadline()
	_ = peer.SetDeadline(deadline)
	var byteOfClientHello [1]byte
	if _, err := peer.Read(byteOfClientHello[:]); err != nil || byteOfClientHello[0] != 22 {
		t.Fatalf("TLS ClientHello did not enter the selected socket: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled TLS handshake returned an accepted body")
		}
	case <-parent.Done():
		t.Fatal("canceled TLS handshake retained the socket")
	}
	if _, err := peer.Read(byteOfClientHello[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("probe returned before the canceled connection closed: %v", err)
	}
	if fixture.network != N.NetworkTCP || fixture.address != (M.Socksaddr{Fqdn: runtimeExitIPHost, Port: 443}) {
		t.Fatalf("unexpected probe destination: %s %s", fixture.network, fixture.address)
	}
}
