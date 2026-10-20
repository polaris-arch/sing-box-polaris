package dns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
)

type fakeIPAdmissionAnswer struct {
	once      sync.Once
	delivered atomic.Bool
	aborted   atomic.Bool
}

func (a *fakeIPAdmissionAnswer) Delivered(time.Time) { a.once.Do(func() { a.delivered.Store(true) }) }
func (a *fakeIPAdmissionAnswer) Abort()              { a.once.Do(func() { a.aborted.Store(true) }) }

type fakeIPAdmissionTransport struct {
	policyTestTransport
	kind        string
	observedTTL atomic.Uint32
	calls       atomic.Int32
	answer      *fakeIPAdmissionAnswer
}

func (t *fakeIPAdmissionTransport) Type() string { return t.kind }
func (t *fakeIPAdmissionTransport) ProtectAnswer(response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	t.calls.Add(1)
	t.observedTTL.Store(response.Answer[0].Header().Ttl)
	return t.answer, nil
}

func newFakeIPAdmissionTransport(kind string) *fakeIPAdmissionTransport {
	return &fakeIPAdmissionTransport{kind: kind, answer: &fakeIPAdmissionAnswer{}, policyTestTransport: policyTestTransport{tag: "selected", exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		response := new(mDNS.Msg)
		response.SetReply(q)
		response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: q.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 600}, A: net.ParseIP("198.18.0.2").To4()}}
		return response, nil
	}}}
}

func TestFakeIPFinalAdmissionObservesRewrittenTTLAndPendingEgress(t *testing.T) {
	transport := newFakeIPAdmissionTransport(C.DNSTypeFakeIP)
	client := NewClient(ClientOptions{Context: context.Background(), DisableCache: true, Logger: log.NewNOPFactory().Logger()})
	batch := &adapter.FakeIPAnswerBatch{}
	ttl := uint32(1200)
	response, err := client.Exchange(adapter.ContextWithFakeIPAnswerSink(context.Background(), batch), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{RewriteTTL: &ttl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Answer[0].Header().Ttl != ttl || transport.observedTTL.Load() != ttl {
		t.Fatal("observer ran before final TTL rewrite")
	}
	if transport.answer.delivered.Load() {
		t.Fatal("query completion was mistaken for actual egress")
	}
	batch.Delivered(time.Now())
	if !transport.answer.delivered.Load() || transport.answer.aborted.Load() {
		t.Fatal("egress did not transfer pending answer")
	}
}

func TestFakeIPInnerClientAndRealTransportDoNotIssueAnswers(t *testing.T) {
	client := NewClient(ClientOptions{Context: context.Background(), DisableCache: true, Logger: log.NewNOPFactory().Logger()})
	for _, kind := range []string{C.DNSTypeFakeIP, "udp"} {
		transport := newFakeIPAdmissionTransport(kind)
		ctx := context.Background()
		if kind == C.DNSTypeFakeIP {
			ctx = context.WithValue(ctx, fakeIPRouterAdmissionKey{}, true)
		}
		if _, err := client.Exchange(ctx, transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil); err != nil {
			t.Fatal(err)
		}
		if transport.calls.Load() != 0 {
			t.Fatal("inner policy candidate or real DNS answer was issued as fake-IP")
		}
	}
}

func TestFakeIPSelectedObserverOwnsPublicHandoff(t *testing.T) {
	transport := newFakeIPAdmissionTransport(C.DNSTypeFakeIP)
	client := NewClient(ClientOptions{Context: context.Background(), DisableCache: true, Logger: log.NewNOPFactory().Logger()})
	if _, err := client.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if transport.calls.Load() != 1 || !transport.answer.delivered.Load() {
		t.Fatal("public core handoff failed to complete selected namespace reservation")
	}
}
