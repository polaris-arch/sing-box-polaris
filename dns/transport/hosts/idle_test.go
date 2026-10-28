package hosts

import (
	"context"
	"net/netip"
	"testing"

	mDNS "github.com/miekg/dns"
)

func TestHostsIdleControlPreservesLookups(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.11")
	transport := &Transport{predefined: map[string][]netip.Addr{"kept.example.": {address}}}
	request := new(mDNS.Msg)
	request.SetQuestion("kept.example.", mDNS.TypeA)
	transport.ExchangeAsync(context.Background(), request, func(response *mDNS.Msg, err error) {
		if err != nil || len(response.Answer) != 1 {
			t.Fatal("lookup failed before idle effect", err)
		}
		transport.SetKeepIdleConnections(false)
		transport.CloseIdleConnections()
		transport.SetKeepIdleConnections(true)
		if transport.work.Sealed() {
			t.Fatal("idle effect stopped an admitted hosts callback")
		}
	})
	response, err := transport.Exchange(context.Background(), request)
	if err != nil || len(response.Answer) != 1 || transport.predefined["kept.example."][0] != address {
		t.Fatal("idle control changed hosts data", err)
	}
}
