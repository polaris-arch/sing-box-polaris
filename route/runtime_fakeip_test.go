package route

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/miekg/dns"
)

type mappingTestGraph struct {
	access   sync.Mutex
	released bool
}

func (*mappingTestGraph) View() adapter.RuntimeView { return nil }
func (l *mappingTestGraph) Fork() (adapter.RuntimeLease, error) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.released {
		return nil, errors.New("released")
	}
	return &mappingTestGraph{}, nil
}

func (*mappingTestGraph) RetainResource(adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	return nil, errors.New("unused")
}
func (l *mappingTestGraph) Release() { l.access.Lock(); l.released = true; l.access.Unlock() }

type mappingTestToken struct {
	releases *atomic.Int32
	once     sync.Once
}

func (*mappingTestToken) Address() netip.Addr { return netip.MustParseAddr("198.18.0.2") }
func (*mappingTestToken) Domain() string      { return "example.org" }
func (l *mappingTestToken) Fork() (adapter.FakeIPMappingLease, error) {
	return &mappingTestToken{releases: l.releases}, nil
}
func (l *mappingTestToken) Release() { l.once.Do(func() { l.releases.Add(1) }) }

type mappingTestProtection struct {
	token      adapter.FakeIPMappingLease
	err        error
	recognized bool
}

func (p mappingTestProtection) AcquireMapping(netip.Addr) (adapter.FakeIPMappingLease, bool, error) {
	return p.token, p.recognized, p.err
}

func (mappingTestProtection) ProtectAnswer(*dns.Msg) (adapter.FakeIPAnswerLease, error) {
	return nil, nil
}

func TestRuntimeMappingSurvivesEarlyFlowCloseThroughWorkerFork(t *testing.T) {
	root := withRuntimeMappings(&mappingTestGraph{})
	worker, err := root.Fork()
	if err != nil {
		t.Fatal(err)
	}
	var releases atomic.Int32
	token := &mappingTestToken{releases: &releases}
	domain, recognized, err := recognizeRuntimeFakeIP(adapter.ContextWithRuntimeLease(context.Background(), root), mappingTestProtection{token: token, recognized: true}, token.Address())
	if err != nil || !recognized || domain != "example.org" {
		t.Fatalf("recognition: %q %v %v", domain, recognized, err)
	}
	root.Release()
	if releases.Load() != 0 {
		t.Fatal("flow close freed active worker mapping")
	}
	late, err := worker.Fork()
	if err != nil {
		t.Fatal(err)
	}
	worker.Release()
	if releases.Load() != 0 {
		t.Fatal("continuation failed to retain mapping")
	}
	late.Release()
	late.Release()
	if releases.Load() != 1 {
		t.Fatalf("mapping release count: %d", releases.Load())
	}
	if _, err := worker.Fork(); err == nil {
		t.Fatal("released handle fork succeeded")
	}
}

func TestRuntimeMappingRejectsMissingAdmissionAndUnknownSyntheticAddress(t *testing.T) {
	var releases atomic.Int32
	token := &mappingTestToken{releases: &releases}
	if _, _, err := recognizeRuntimeFakeIP(context.Background(), mappingTestProtection{token: token, recognized: true}, token.Address()); err == nil {
		t.Fatal("unowned mapping escaped")
	}
	if releases.Load() != 1 {
		t.Fatal("failed handoff leaked mapping")
	}
	missing := errors.New("synthetic address has no mapping")
	if _, recognized, err := recognizeRuntimeFakeIP(context.Background(), mappingTestProtection{err: missing}, token.Address()); !errors.Is(err, missing) || recognized {
		t.Fatal("missing synthetic mapping fell through")
	}
	if _, recognized, err := recognizeRuntimeFakeIP(context.Background(), mappingTestProtection{}, netip.MustParseAddr("192.0.2.1")); err != nil || recognized {
		t.Fatal("ordinary address rejected")
	}
}
