package adapter

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testAnswerLease struct { delivered int; aborted int; at time.Time }
func (a *testAnswerLease) Delivered(at time.Time) { a.delivered++; a.at = at }
func (a *testAnswerLease) Abort() { a.aborted++ }
type testProtection struct { answer *testAnswerLease }
func (p testProtection) ProtectAnswer(*dns.Msg) (FakeIPAnswerLease, error) { return p.answer, nil }
func (testProtection) AcquireMapping(netip.Addr) (FakeIPMappingLease, bool, error) { return nil, false, nil }

func TestFakeIPAnswerBatchTransfersActualDelivery(t *testing.T) {
	answer := new(testAnswerLease)
	batch := new(FakeIPAnswerBatch)
	ctx := ContextWithFakeIPAnswerSink(ContextWithFakeIPProtection(context.Background(), testProtection{answer}), batch)
	if err := ProtectFakeIPAnswer(ctx, new(dns.Msg)); err != nil { t.Fatal(err) }
	if answer.delivered != 0 || answer.aborted != 0 { t.Fatal("handoff completed pending core egress") }
	at := time.Unix(100, 0)
	batch.Delivered(at); batch.Abort()
	if answer.delivered != 1 || answer.aborted != 0 || answer.at != at { t.Fatal("actual delivery completion lost") }
	late := new(testAnswerLease)
	if err := batch.Add(late); !errors.Is(err, ErrFakeIPAnswerSinkClosed) { t.Fatal("late egress admitted") }
}

func TestFakeIPPublicHandoffDoesNotLeakPendingReservation(t *testing.T) {
	answer := new(testAnswerLease)
	ctx := ContextWithFakeIPProtection(context.Background(), testProtection{answer})
	if err := ProtectFakeIPAnswer(ctx, new(dns.Msg)); err != nil { t.Fatal(err) }
	if answer.delivered != 1 || answer.at.IsZero() { t.Fatal("public handoff retained an unbounded undelivered answer") }
}
