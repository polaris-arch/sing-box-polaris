package dns

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	mDNS "github.com/miekg/dns"
)

// Both family workers reserve before publication and join their actual return.
// A canceled waiter cannot leave a task using the receiver after its lease ends.
func runRuntimeLookupPair(ctx context.Context, source adapter.RuntimeResourceSource, lookup func(context.Context, uint16) ([]netip.Addr, error)) ([]netip.Addr, []netip.Addr, error) {
	ctx4, release4, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil { return nil, nil, err }
	ctx6, release6, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil { release4(); return nil, nil, err }
	var response4, response6 []netip.Addr
	var err4, err6 error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() { defer joined.Done(); defer release4(); response4, err4 = lookup(ctx4, mDNS.TypeA); if err4 != nil { response4 = nil } }()
	go func() { defer joined.Done(); defer release6(); response6, err6 = lookup(ctx6, mDNS.TypeAAAA); if err6 != nil { response6 = nil } }()
	joined.Wait()
	if err4 != nil { err4 = E.Cause(err4, "exchange4") }
	if err6 != nil { err6 = E.Cause(err6, "exchange6") }
	return response4, response6, E.Errors(err4, err6)
}
