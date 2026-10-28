package libbox

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type LocalDNSTransport interface {
	Raw() bool
	Lookup(ctx *ExchangeContext, network string, domain string) error
	Exchange(ctx *ExchangeContext, message []byte) error
}

type platformTransport struct {
	dns.TransportAdapter
	iif               LocalDNSTransport
	preferredResolver *local.PreferredDomainResolver
	networkManager    adapter.NetworkManager
	calls             dnsCallGate
}

func newPlatformTransport(ctx context.Context, logger log.ContextLogger, iif LocalDNSTransport, tag string, options option.LocalDNSServerOptions) (*platformTransport, error) {
	preferredResolver, err := local.NewPreferredDomainResolver(ctx, logger, options)
	if err != nil {
		return nil, err
	}
	return &platformTransport{
		TransportAdapter:  dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, tag, options),
		iif:               iif,
		preferredResolver: preferredResolver,
		networkManager:    service.FromContext[adapter.NetworkManager](ctx),
	}, nil
}

func (p *platformTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		// Start runs once per stage; register the close only once.
		scope.Add(p.close)
	}
	p.preferredResolver.Start(stage)
	return nil
}

func (p *platformTransport) close() error {
	p.calls.access.Lock()
	cancels, _ := p.calls.sealAndSnapshotLocked()
	p.iif = nil
	p.calls.access.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	// Cancellation and local counts do not change the operational close result.
	// Existing workers and registration drain tasks still own in-flight leases.
	return nil
}

func (p *platformTransport) Reset() {
}

func (p *platformTransport) PreferredDomain(domain string) bool {
	return p.preferredResolver.PreferredDomain(domain)
}

func (p *platformTransport) ServerAddresses() []netip.Addr {
	if p.networkManager == nil {
		return nil
	}
	defaultInterface := p.networkManager.DefaultNetworkInterface()
	if defaultInterface == nil {
		return nil
	}
	var serverAddresses []netip.Addr
	for _, server := range defaultInterface.DNSServers {
		serverAddr, err := netip.ParseAddr(server)
		if err == nil {
			serverAddresses = append(serverAddresses, serverAddr)
		}
	}
	return serverAddresses
}

func (p *platformTransport) SearchDomains() []string {
	if p.networkManager == nil {
		return nil
	}
	defaultInterface := p.networkManager.DefaultNetworkInterface()
	if defaultInterface == nil {
		return nil
	}
	return defaultInterface.DNSSearchDomains
}

func (p *platformTransport) Environment() []string {
	if p.networkManager == nil {
		return nil
	}
	defaultInterface := p.networkManager.DefaultNetworkInterface()
	if defaultInterface == nil {
		return nil
	}
	return defaultInterface.DNSServers
}

type dnsPlatformResult struct {
	response *mDNS.Msg
	err      error
}

func (p *platformTransport) startExchange(ctx context.Context, message *mDNS.Msg) (<-chan dnsPlatformResult, <-chan struct{}, error) {
	p.calls.access.Lock()
	lease, err := p.calls.beginLocked(ctx)
	iif, preferredResolver := p.iif, p.preferredResolver
	p.calls.access.Unlock()
	if err != nil {
		return nil, nil, err
	}
	callCtx := lease.ctx
	if message == nil {
		lease.returned()
		return nil, nil, E.New("nil DNS query")
	}
	request := message.Copy()
	response := &ExchangeContext{context: callCtx}
	done := make(chan dnsPlatformResult, 1)
	// The interface reference is captured under the admission gate; this worker
	// keeps it even if Close detaches the transport's reference.
	go func() {
		result := dnsPlatformResult{}
		raw := false
		var question mDNS.Question
		defer func() {
			if recovered := recover(); recovered != nil {
				result.err = fmt.Errorf("platform DNS call panicked: %v", recovered)
			}
			snapshot, registrations := response.complete()
			lease.returned(registrations...)
			if result.err == nil {
				result.err = snapshot.err
			}
			if result.err == nil && result.response == nil {
				if raw {
					result.response = snapshot.message
				} else {
					result.response = dns.FixedResponse(request.Id, question, snapshot.addresses, C.DefaultDNSTTL)
				}
			}
			// A canceled upper caller may already be gone; delivery never blocks drain.
			done <- result
		}()
		if err := callCtx.Err(); err != nil {
			result.err = err
			return
		}
		if preferredResolver != nil {
			result.response = preferredResolver.Lookup(request)
			if result.response != nil {
				return
			}
		}
		if iif == nil {
			result.err = E.New("missing platform DNS transport")
			return
		}
		// Raw is itself a platform call, covered by this lease and outside the gate.
		raw = iif.Raw()
		if err := callCtx.Err(); err != nil {
			result.err = err
			return
		}
		if raw {
			messageBytes, err := request.Pack()
			if err != nil {
				result.err = err
				return
			}
			result.err = iif.Exchange(response, messageBytes)
			return
		}
		if len(request.Question) == 0 {
			result.err = E.New("DNS query has no question")
			return
		}
		question = request.Question[0]
		var network string
		switch question.Qtype {
		case mDNS.TypeA:
			network = "ip4"
		case mDNS.TypeAAAA:
			network = "ip6"
		default:
			result.err = E.New("only IP queries are supported by current version of Android")
			return
		}
		result.err = iif.Lookup(response, network, question.Name)
	}()
	return done, lease.aborted, nil
}

func waitPlatformDNS(done <-chan dnsPlatformResult, ctx context.Context, aborted <-chan struct{}) (*mDNS.Msg, error) {
	select {
	case result := <-done:
		return result.response, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-aborted:
		return nil, context.Canceled
	}
}

func (p *platformTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done, aborted, err := p.startExchange(ctx, message)
	if err != nil {
		return nil, err
	}
	return waitPlatformDNS(done, ctx, aborted)
}

func (p *platformTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	done, aborted, err := p.startExchange(ctx, message)
	go func() {
		if err != nil {
			callback(nil, err)
			return
		}
		callback(waitPlatformDNS(done, ctx, aborted))
	}()
}

type Func interface {
	Invoke() error
}

type ExchangeContext struct {
	access        sync.Mutex
	context       context.Context
	message       mDNS.Msg
	addresses     []netip.Addr
	error         error
	registrations []*dnsCancelRegistration
	completed     bool
}

// The cancellation holder contains only the callable capability. In particular
// it never captures an ExchangeContext, transport or host through our closure.
type dnsCancelHolder struct {
	access   sync.Mutex
	callback Func
}

func (h *dnsCancelHolder) invoke() error {
	h.access.Lock()
	callback := h.callback
	h.callback = nil
	h.access.Unlock()
	if callback == nil {
		return nil
	}
	return callback.Invoke()
}

type dnsExchangeSnapshot struct {
	message   *mDNS.Msg
	addresses []netip.Addr
	err       error
}

func (c *ExchangeContext) complete() (dnsExchangeSnapshot, []*dnsCancelRegistration) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.completed {
		return dnsExchangeSnapshot{}, nil
	}
	c.completed = true
	snapshot := dnsExchangeSnapshot{message: c.message.Copy(), addresses: append([]netip.Addr(nil), c.addresses...), err: c.error}
	registrations := c.registrations
	c.context, c.registrations = nil, nil
	c.message, c.addresses, c.error = mDNS.Msg{}, nil, nil
	return snapshot, registrations
}

func (c *ExchangeContext) OnCancel(callback Func) {
	holder := &dnsCancelHolder{callback: callback}
	registration := makeDNSCancelRegistration(holder.invoke)
	c.access.Lock()
	if c.completed || c.context == nil {
		c.access.Unlock()
		registration.stopAndDetach()
		return
	}
	ctx := c.context
	c.registrations = append(c.registrations, registration)
	c.access.Unlock()
	// complete can win this gap. An already stopped registration refuses arm.
	registration.arm(ctx)
}

func (c *ExchangeContext) Success(result string) {
	addresses := common.Map(common.Filter(strings.Split(result, "\n"), func(it string) bool {
		return !common.IsEmpty(it)
	}), func(it string) netip.Addr {
		return M.ParseSocksaddrHostPort(it, 0).Unwrap().Addr
	})
	c.access.Lock()
	defer c.access.Unlock()
	if !c.completed {
		c.addresses = addresses
	}
}

func (c *ExchangeContext) RawSuccess(result []byte) {
	message := new(mDNS.Msg)
	err := message.Unpack(result)
	c.access.Lock()
	defer c.access.Unlock()
	if c.completed {
		return
	}
	if err != nil {
		c.error = E.Cause(err, "parse response")
	} else {
		c.message = *message
	}
}

func (c *ExchangeContext) ErrorCode(code int32) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.completed {
		c.error = dns.RcodeError(code)
	}
}

func (c *ExchangeContext) ErrnoCode(code int32) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.completed {
		c.error = syscall.Errno(code)
	}
}

var (
	_ adapter.DNSTransport                    = (*platformTransport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*platformTransport)(nil)
	_ adapter.DNSTransportWithConfiguration   = (*platformTransport)(nil)
	_ adapter.DNSTransportWithEnvironment     = (*platformTransport)(nil)
)
