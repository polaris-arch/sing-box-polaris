package local

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// searchUpstream is a loopback name server that records the names it is asked
// for. A name mapped to an invalid address exists without records.
type searchUpstream struct {
	access  sync.Mutex
	records map[string]netip.Addr
	queried []string
}

func (u *searchUpstream) ServeDNS(writer mDNS.ResponseWriter, request *mDNS.Msg) {
	question := request.Question[0]
	u.access.Lock()
	u.queried = append(u.queried, question.Name)
	address, exists := u.records[question.Name]
	u.access.Unlock()
	response := new(mDNS.Msg)
	if !exists {
		response.SetRcode(request, mDNS.RcodeNameError)
	} else {
		response.SetReply(request)
		if address.IsValid() && question.Qtype == mDNS.TypeA {
			response.Answer = append(response.Answer, &mDNS.A{
				Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
				A:   address.AsSlice(),
			})
		}
	}
	writer.WriteMsg(response)
}

func exchangeWithSearch(t *testing.T, search []string, ndots int, records map[string]netip.Addr, name string, qtype uint16) (*mDNS.Msg, []string) {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &searchUpstream{records: records}
	server := &mDNS.Server{PacketConn: packetConn, Handler: upstream}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	config := &systemconfig.Config{
		Servers:  []M.Socksaddr{M.SocksaddrFromNet(packetConn.LocalAddr())},
		Search:   search,
		Ndots:    ndots,
		Timeout:  5 * time.Second,
		Attempts: 1,
	}
	original := loadConfiguration
	loadConfiguration = func(*systemconfig.Source) *systemconfig.Config { return config }
	t.Cleanup(func() { loadConfiguration = original })
	transport := &Transport{
		TransportAdapter:  dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, "local", option.LocalDNSServerOptions{}),
		ctx:               context.Background(),
		logger:            log.NewNOPFactory().Logger(),
		preferredResolver: new(PreferredDomainResolver),
		dialer:            N.SystemDialer,
	}
	t.Cleanup(func() {
		serverSet := transport.serverSet.Swap(nil)
		if serverSet != nil {
			serverSet.serverScope.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := new(mDNS.Msg)
	request.SetQuestion(name, qtype)
	response, err := transport.Exchange(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Question) != 1 || response.Question[0].Name != name {
		t.Fatalf("response question %v, want %s", response.Question, name)
	}
	upstream.access.Lock()
	defer upstream.access.Unlock()
	return response, slices.Clone(upstream.queried)
}

func TestSearchDomains(t *testing.T) {
	search := []string{"corp.example.", "lab.example."}
	address := netip.MustParseAddr("192.0.2.10")
	testCases := []struct {
		name        string
		search      []string
		ndots       int
		records     map[string]netip.Addr
		question    string
		qtype       uint16
		wantQueried []string
		wantAnswer  bool
	}{
		{
			name:        "single label resolves in a search domain",
			search:      search,
			ndots:       1,
			records:     map[string]netip.Addr{"nas.lab.example.": address},
			question:    "nas.",
			wantQueried: []string{"nas.corp.example.", "nas.lab.example."},
			wantAnswer:  true,
		},
		{
			name:        "single label falls back to the name itself",
			search:      search,
			ndots:       1,
			question:    "nas.",
			wantQueried: []string{"nas.corp.example.", "nas.lab.example.", "nas."},
		},
		{
			name:        "single label without ndots tries the name itself first",
			search:      search,
			ndots:       0,
			records:     map[string]netip.Addr{"nas.corp.example.": address},
			question:    "nas.",
			wantQueried: []string{"nas.", "nas.corp.example."},
			wantAnswer:  true,
		},
		{
			name:        "single label without search domains",
			ndots:       1,
			records:     map[string]netip.Addr{"nas.": address},
			question:    "nas.",
			wantQueried: []string{"nas."},
			wantAnswer:  true,
		},
		{
			name:        "multiple labels are queried as is",
			search:      search,
			ndots:       1,
			records:     map[string]netip.Addr{"www.example.org.": address},
			question:    "www.example.org.",
			wantQueried: []string{"www.example.org."},
			wantAnswer:  true,
		},
		{
			name:        "missing name with multiple labels is not searched",
			search:      search,
			ndots:       1,
			question:    "missing.example.org.",
			wantQueried: []string{"missing.example.org."},
		},
		{
			name:        "multiple labels below ndots are not searched",
			search:      search,
			ndots:       5,
			question:    "missing.example.org.",
			wantQueried: []string{"missing.example.org."},
		},
		{
			name:        "multiple labels without search domains",
			ndots:       1,
			question:    "missing.example.org.",
			wantQueried: []string{"missing.example.org."},
		},
		{
			name:        "reverse name is not searched",
			search:      search,
			ndots:       1,
			question:    "10.2.0.192.in-addr.arpa.",
			qtype:       mDNS.TypePTR,
			wantQueried: []string{"10.2.0.192.in-addr.arpa."},
		},
		{
			name:        "root is not searched",
			search:      search,
			ndots:       1,
			records:     map[string]netip.Addr{".": {}},
			question:    ".",
			qtype:       mDNS.TypeNS,
			wantQueried: []string{"."},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			qtype := testCase.qtype
			if qtype == 0 {
				qtype = mDNS.TypeA
			}
			response, queried := exchangeWithSearch(t, testCase.search, testCase.ndots, testCase.records, testCase.question, qtype)
			if !slices.Equal(queried, testCase.wantQueried) {
				t.Fatalf("queried %v, want %v", queried, testCase.wantQueried)
			}
			if !testCase.wantAnswer {
				if len(response.Answer) != 0 {
					t.Fatalf("unexpected answer %v", response.Answer)
				}
				return
			}
			if response.Rcode != mDNS.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("rcode %s with %d answers, want one answer", mDNS.RcodeToString[response.Rcode], len(response.Answer))
			}
			record, isA := response.Answer[0].(*mDNS.A)
			if !isA || record.Hdr.Name != testCase.question || !record.A.Equal(address.AsSlice()) {
				t.Fatalf("answer %v, want %s for %s", response.Answer[0], address, testCase.question)
			}
		})
	}
}
