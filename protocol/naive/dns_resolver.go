package naive

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

// Keep the callback seam independent of the optional native Cronet binary so
// the real policy dispatch is testable without starting a proxy or DNS socket.
func newDNSResolver(router adapter.DNSRouter, options adapter.DNSQueryOptions, log logger.ContextLogger) func(context.Context, *mDNS.Msg) *mDNS.Msg {
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		response, err := router.Exchange(ctx, request, options)
		if err != nil {
			log.Error("DNS exchange failed: ", err)
			return dns.FixedResponseStatus(request, mDNS.RcodeServerFailure)
		}
		return response
	}
}
