package certificate

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type runtimeProviderFixture struct {
	tag      string
	stages   atomic.Int32
	prepare  func() error
	validate func() error
}

func (p *runtimeProviderFixture) Type() string { return "fixture" }
func (p *runtimeProviderFixture) Tag() string  { return p.tag }
func (*runtimeProviderFixture) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func (*runtimeProviderFixture) Start(adapter.StartStage, *adapter.Scope) error {
	return errors.New("legacy Start called for runtime provider")
}

func (p *runtimeProviderFixture) RuntimeValidate() error {
	if p.validate != nil {
		return p.validate()
	}
	return nil
}

func (p *runtimeProviderFixture) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	p.stages.Add(1)
	if p.prepare != nil {
		return p.prepare()
	}
	return nil
}
func (*runtimeProviderFixture) StageRuntime(context.Context) error { return nil }
func (*runtimeProviderFixture) CompensateRuntime() error           { return nil }
func (*runtimeProviderFixture) RuntimeActivate()                   {}
func (*runtimeProviderFixture) RuntimeStop()                       {}
func (*runtimeProviderFixture) RuntimeCloseAndWait() error         { return nil }
func (*runtimeProviderFixture) RuntimeResourceID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "certificate-fixture", Sequence: 1}
}

func TestRuntimeCertificateInventoryOwnsOnlyNewMembers(t *testing.T) {
	manager := NewRuntimeManager(nil)
	owned := &runtimeProviderFixture{tag: "owned"}
	borrowed := &runtimeProviderFixture{tag: "borrowed"}
	owned.validate = func() error { manager.CertificateProviders(); return nil }
	owned.prepare = func() error {
		if _, ok := manager.Get("owned"); !ok {
			return errors.New("lookup missing")
		}
		return nil
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	defer scope.Close()
	if err := manager.Insert(owned, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(borrowed, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	copy := manager.CertificateProviders()
	copy[0] = nil
	if manager.CertificateProviders()[0] != owned {
		t.Fatal("inventory slice escaped")
	}
	if err := manager.Insert(&runtimeProviderFixture{tag: "late"}, scope); err == nil {
		t.Fatal("frozen inventory mutated")
	}
	for _, stage := range adapter.ListStartStages {
		if err := manager.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	if owned.stages.Load() != int32(len(adapter.ListStartStages)) || borrowed.stages.Load() != 0 {
		t.Fatal("borrowed provider restarted or stage repeated")
	}
	providers, err := manager.PreparedProviders()
	if err != nil || len(providers) != 1 || providers[0] != owned {
		t.Fatal("borrowed provider gained activation/cleanup ownership", err)
	}
}

func TestRuntimeCertificateInventorySharesConcurrentStageFailure(t *testing.T) {
	manager := NewRuntimeManager(nil)
	entered, finish := make(chan struct{}), make(chan struct{})
	failure := errors.New("fixture preparation failure")
	member := &runtimeProviderFixture{tag: "owned", prepare: func() error { close(entered); <-finish; return failure }}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	defer scope.Close()
	if err := manager.Insert(member, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateStart, scope); err == nil {
		t.Fatal("unfrozen inventory started")
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- manager.Start(adapter.StartStateStart, scope) }()
	<-entered
	go func() { second <- manager.Start(adapter.StartStateStart, scope) }()
	close(finish)
	if !errors.Is(<-first, failure) || !errors.Is(<-second, failure) || member.stages.Load() != 1 {
		t.Fatal("concurrent caller observed invented stage success")
	}
}

func TestRuntimeCertificateInventoryNeverCallsLegacyConstructor(t *testing.T) {
	manager := NewRuntimeManager(nil)
	if err := manager.Create(context.Background(), nil, "tag", "fixture", nil); err == nil {
		t.Fatal("unrestricted Create admitted")
	}
	if _, err := manager.PreparedProviders(); err == nil {
		t.Fatal("unfrozen inventory escaped")
	}
	failure := errors.New("endpoint lifecycle unavailable")
	if err := manager.Insert(&runtimeProviderFixture{tag: "bad", validate: func() error { return failure }}, nil); !errors.Is(err, failure) {
		t.Fatal("concrete lifecycle failure hidden")
	}
	if len(manager.CertificateProviders()) != 0 {
		t.Fatal("invalid provider inserted")
	}
}

func (*runtimeProviderFixture) RuntimeExternalEffects() bool { return false }
