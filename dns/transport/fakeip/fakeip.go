package fakeip

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.FakeIPDNSServerOptions](registry, C.DNSTypeFakeIP, NewTransport)
}

var _ adapter.FakeIPTransport = (*Transport)(nil)

type Transport struct {
	work              lifecycle.Work
	runtimeResource   adapter.RuntimeResourceSource
	constructionOwned bool
	startOnce         sync.Once
	startErr          error
	closeOnce         sync.Once
	closeErr          error
	dns.TransportAdapter
	logger       logger.ContextLogger
	store        adapter.FakeIPStore
	inet4Enabled bool
	inet6Enabled bool
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.FakeIPDNSServerOptions) (adapter.DNSTransport, error) {
	inet4Range := options.Inet4Range.Build(netip.Prefix{})
	inet6Range := options.Inet6Range.Build(netip.Prefix{})
	if !inet4Range.IsValid() && !inet6Range.IsValid() {
		return nil, E.New("at least one of inet4_range or inet6_range must be set")
	}
	resource, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	var store adapter.FakeIPStore
	if manager, ok := ManagerFromContext(ctx); ok {
		var err error
		if migration, ok := RangeMigrationFromContext(ctx); ok {
			if migration.manager != manager {
				return nil, ErrMigrationStale
			}
			store, err = migration.Borrow(inet4Range, inet6Range)
		} else if permit, ok := AnswerPermitFromContext(ctx); ok {
			store, err = manager.BorrowCandidate(inet4Range, inet6Range, permit)
		} else if resource != nil {
			return nil, ErrAnswerPermitRequired
		} else {
			store, err = manager.Borrow(inet4Range, inet6Range)
		}
		if err != nil {
			return nil, err
		}
	} else {
		if resource != nil {
			return nil, ErrManagerRequired
		}
		store = NewStore(ctx, logger, inet4Range, inet6Range)
	}
	t := &Transport{
		runtimeResource:  resource,
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeFakeIP, tag, nil),
		logger:           logger,
		store:            store,
		inet4Enabled:     inet4Range.IsValid(),
		inet6Enabled:     inet6Range.IsValid(),
	}
	var err error
	t.constructionOwned, err = lifecycle.ConstructionCleanup(ctx, t.close)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.startOnce.Do(func() {
		if !t.constructionOwned {
			_, t.startErr = lifecycle.ConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), t.close)
		}
	})
	if t.startErr != nil {
		return t.startErr
	}
	done, ok := t.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	if scope.Context().Err() != nil {
		return scope.Context().Err()
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	err := t.store.Start()
	if err != nil {
		return err
	}
	if t.work.Sealed() {
		return lifecycle.ErrStopped
	}
	return scope.Context().Err()
}

func (t *Transport) Reset() {
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	_, done, err := t.work.Operation(ctx, t.runtimeResource)
	if err != nil {
		return nil, err
	}
	defer done()
	return t.exchange(message)
}

func (t *Transport) exchange(message *mDNS.Msg) (*mDNS.Msg, error) {
	question := message.Question[0]
	if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA {
		return nil, E.New("only IP queries are supported by fakeip")
	}
	if question.Qtype == mDNS.TypeA && !t.inet4Enabled || question.Qtype == mDNS.TypeAAAA && !t.inet6Enabled {
		return dns.FixedResponseStatus(message, mDNS.RcodeSuccess), nil
	}
	domain := dns.FqdnToDomain(question.Name)
	if len(domain) > 255 {
		return nil, E.New("domain name too long for fakeip")
	}
	address, err := t.store.Create(domain, question.Qtype == mDNS.TypeAAAA)
	if err != nil {
		return nil, err
	}
	return dns.FixedResponse(message.Id, question, []netip.Addr{address}, C.DefaultDNSTTL), nil
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	_, done, err := t.work.Operation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	defer done()
	callback(t.exchange(message))
}

func (t *Transport) Store() adapter.FakeIPStore {
	return t.store
}

func (t *Transport) StopRuntimeProducers()  {}
func (t *Transport) StopRuntimeOperations() { t.work.Seal() }
func (t *Transport) close() error {
	t.closeOnce.Do(func() {
		t.StopRuntimeOperations()
		t.work.Wait()
		t.closeErr = lifecycle.Uncertain("fake-IP transport", t.store.Close())
	})
	return t.closeErr
}

// ProtectAnswer is immutable selected-response provenance. The Box manager,
// rather than this transport's resource lifetime, owns the reservation.
func (t *Transport) ProtectAnswer(response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	if store, ok := t.store.(*borrowedStore); ok {
		return store.manager.protectAnswer(store.namespace, response)
	}
	return nil, nil // standalone legacy allocator has no range migration
}

var _ adapter.FakeIPAnswerProtection = (*Transport)(nil)

func (t *Transport) ProtectAnswerContext(ctx context.Context, response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	if store, ok := t.store.(*borrowedStore); ok {
		return store.manager.protectAnswerContext(ctx, store.namespace, response)
	}
	return nil, nil
}

var _ adapter.FakeIPAnswerContextProtection = (*Transport)(nil)
