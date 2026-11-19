package clashapi

import (
	"context"
	"net/http"
	"net/url"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/miekg/dns"
)

func dnsRouter(router adapter.DNSRouter) http.Handler {
	r := chi.NewRouter()
	r.Get("/query", queryDNS(router))
	r.Get("/lookup", lookupDNS(router))
	return r
}

func lookupDNS(router adapter.DNSRouter) http.HandlerFunc {
	const maxAddresses = 64
	// A 254-byte hostname with a trailing root dot can be fully escaped.
	const maxQueryBytes = len("name=") + 3*254
	return func(w http.ResponseWriter, r *http.Request) {
		var name string
		if len(r.URL.RawQuery) <= maxQueryBytes {
			query, err := url.ParseQuery(r.URL.RawQuery)
			if names := query["name"]; err == nil && len(query) == 1 && len(names) == 1 {
				name = names[0]
			}
		}
		if name == "." || !M.IsDomainName(name) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid lookup name"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), C.DNSTimeout)
		defer cancel()
		addresses, err := router.Lookup(ctx, name, adapter.DNSQueryOptions{UseRules: true})
		if err != nil || ctx.Err() != nil || len(addresses) == 0 || len(addresses) > maxAddresses {
			render.Status(r, http.StatusBadGateway)
			render.JSON(w, r, newError("DNS lookup failed"))
			return
		}
		// Preserve every result so consumers can reject mixed answer sets.
		render.JSON(w, r, render.M{"version": 1, "addresses": addresses})
	}
}

func queryDNS(router adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		qTypeStr := r.URL.Query().Get("type")
		if qTypeStr == "" {
			qTypeStr = "A"
		}

		qType, exist := dns.StringToType[qTypeStr]
		if !exist {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid query type"))
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DNSTimeout)
		defer cancel()

		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(name), qType)
		resp, err := router.Exchange(ctx, &msg, adapter.DNSQueryOptions{})
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		responseData := render.M{
			"Status":   resp.Rcode,
			"Question": resp.Question,
			"Server":   "internal",
			"TC":       resp.Truncated,
			"RD":       resp.RecursionDesired,
			"RA":       resp.RecursionAvailable,
			"AD":       resp.AuthenticatedData,
			"CD":       resp.CheckingDisabled,
		}

		rr2Json := func(rr dns.RR) render.M {
			header := rr.Header()
			return render.M{
				"name": header.Name,
				"type": header.Rrtype,
				"TTL":  header.Ttl,
				"data": rr.String()[len(header.String()):],
			}
		}

		if len(resp.Answer) > 0 {
			responseData["Answer"] = common.Map(resp.Answer, rr2Json)
		}
		if len(resp.Ns) > 0 {
			responseData["Authority"] = common.Map(resp.Ns, rr2Json)
		}
		if len(resp.Extra) > 0 {
			responseData["Additional"] = common.Map(resp.Extra, rr2Json)
		}

		render.JSON(w, r, responseData)
	}
}
