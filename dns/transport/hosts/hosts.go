package hosts

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.HostsDNSServerOptions](registry, C.DNSTypeHosts, NewTransport)
}

var (
	_ adapter.DNSTransport                    = (*Transport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*Transport)(nil)
)

type Transport struct {
	work              lifecycle.Work
	runtimeResource   adapter.RuntimeResourceSource
	constructionOwned bool
	closeOnce         sync.Once
	startOnce         sync.Once
	startErr          error
	dns.TransportAdapter
	files      []*File
	predefined map[string][]netip.Addr
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.HostsDNSServerOptions) (adapter.DNSTransport, error) {
	var (
		files      []*File
		predefined = make(map[string][]netip.Addr)
	)
	if len(options.Path) == 0 {
		defaultFile, err := NewDefaultContext(ctx)
		if err != nil {
			return nil, err
		}
		files = append(files, defaultFile)
	} else {
		for _, path := range options.Path {
			files = append(files, NewFile(ctx, filemanager.BasePath(ctx, os.ExpandEnv(path))))
		}
	}
	if options.Predefined != nil {
		for _, entry := range options.Predefined.Entries() {
			predefined[mDNS.CanonicalName(entry.Key)] = slices.Clone(entry.Value)
		}
	}
	resource, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	t := &Transport{
		runtimeResource:  resource,
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeHosts, tag, nil),
		files:            files,
		predefined:       predefined,
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
	if t.work.Sealed() {
		return lifecycle.ErrStopped
	}
	return scope.Context().Err()
}

func (t *Transport) Reset() {
}

func (t *Transport) PreferredDomain(domain string) bool {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return false
	}
	defer done()
	if _, loaded := t.predefined[domain]; loaded {
		return true
	}
	for _, file := range t.files {
		if len(file.Lookup(domain)) > 0 {
			return true
		}
	}
	return false
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
	domain := mDNS.CanonicalName(question.Name)
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		if addresses, ok := t.predefined[domain]; ok {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
		for _, file := range t.files {
			addresses := file.Lookup(domain)
			if len(addresses) > 0 {
				return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
			}
		}
	}
	return &mDNS.Msg{
		Id:       message.Id,
		Rcode:    mDNS.RcodeNameError,
		Response: true,
		Question: []mDNS.Question{question},
	}, nil
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

func (t *Transport) StopRuntimeProducers()  {}
func (t *Transport) StopRuntimeOperations() { t.work.Seal() }
func (t *Transport) close() error {
	t.closeOnce.Do(func() {
		t.StopRuntimeOperations()
		t.work.Wait()
		for _, file := range t.files {
			_ = file.Close()
		}
	})
	return nil
}
