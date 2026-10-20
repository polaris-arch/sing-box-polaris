package adapter

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// FakeIPMappingLease is an atomic recognition result plus the lifetime of that
// exact address/domain identity. Fork before handing it to a stream or NAT
// owner; cancellation is not completion and does not release a mapping.
type FakeIPMappingLease interface {
	Address() netip.Addr
	Domain() string
	Fork() (FakeIPMappingLease, error)
	Release()
}

// FakeIPAnswerLease holds finalized answer identities across core-owned egress.
// Delivered starts/extends protection from actual completion and final RR TTLs.
// An ambiguous partial write counts as delivered. Abort is valid only when the
// answer definitely did not escape. The first terminal call wins.
type FakeIPAnswerLease interface {
	Delivered(time.Time)
	Abort()
}

type FakeIPAnswerProtection interface {
	ProtectAnswer(*dns.Msg) (FakeIPAnswerLease, error)
}

type FakeIPProtection interface {
	FakeIPAnswerProtection
	AcquireMapping(netip.Addr) (FakeIPMappingLease, bool, error)
}

type FakeIPAnswerSink interface {
	Add(FakeIPAnswerLease) error
}

type (
	fakeIPAnswerSinkKey       struct{}
	fakeIPProtectionKey       struct{}
	fakeIPAnswerProtectionKey struct{}
)

func ContextWithFakeIPAnswerSink(ctx context.Context, sink FakeIPAnswerSink) context.Context {
	return context.WithValue(ctx, fakeIPAnswerSinkKey{}, sink)
}

func FakeIPAnswerSinkFromContext(ctx context.Context) (FakeIPAnswerSink, bool) {
	sink, ok := ctx.Value(fakeIPAnswerSinkKey{}).(FakeIPAnswerSink)
	return sink, ok && sink != nil
}

func ContextWithFakeIPProtection(ctx context.Context, protection FakeIPProtection) context.Context {
	return context.WithValue(ctx, fakeIPProtectionKey{}, protection)
}

func FakeIPProtectionFromContext(ctx context.Context) (FakeIPProtection, bool) {
	protection, ok := ctx.Value(fakeIPProtectionKey{}).(FakeIPProtection)
	return protection, ok && protection != nil
}

// ContextWithFakeIPAnswerProtection carries the selected allocator namespace,
// not just a fake-IP boolean, through policy result/copy paths.
func ContextWithFakeIPAnswerProtection(ctx context.Context, protection FakeIPAnswerProtection) context.Context {
	return context.WithValue(ctx, fakeIPAnswerProtectionKey{}, protection)
}

func FakeIPAnswerProtectionFromContext(ctx context.Context) (FakeIPAnswerProtection, bool) {
	protection, ok := ctx.Value(fakeIPAnswerProtectionKey{}).(FakeIPAnswerProtection)
	return protection, ok && protection != nil
}

// ProtectFakeIPAnswer runs after all response TTL rewriting. Internal egress
// transfers the reservation to its sink. Public APIs without a sink establish
// TTL validity at core handoff; their callers own any later external delay.
// There is deliberately no indefinitely-pending default reservation.
func ProtectFakeIPAnswer(ctx context.Context, response *dns.Msg) error {
	protection, ok := FakeIPAnswerProtectionFromContext(ctx)
	if !ok {
		protection, ok = FakeIPProtectionFromContext(ctx)
	}
	if !ok || response == nil {
		return nil
	}
	var answer FakeIPAnswerLease
	var err error
	if contextual, ok := protection.(FakeIPAnswerContextProtection); ok {
		answer, err = contextual.ProtectAnswerContext(ctx, response)
	} else {
		answer, err = protection.ProtectAnswer(response)
	}
	if err != nil {
		return err
	}
	if answer == nil {
		return nil
	}
	if sink, ok := FakeIPAnswerSinkFromContext(ctx); ok {
		if err := sink.Add(answer); err != nil {
			answer.Abort()
			return err
		}
	} else {
		answer.Delivered(time.Now())
	}
	return nil
}

var ErrFakeIPAnswerSinkClosed = errors.New("fake-IP answer egress is already complete")

// FakeIPAnswerBatch is a per-core-egress sink. Terminal operations snapshot
// under its mutex and invoke lease methods outside it. Late Add is rejected.
type FakeIPAnswerBatch struct {
	access  sync.Mutex
	closed  bool
	answers []FakeIPAnswerLease
}

func (b *FakeIPAnswerBatch) Add(answer FakeIPAnswerLease) error {
	if answer == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return ErrFakeIPAnswerSinkClosed
	}
	b.answers = append(b.answers, answer)
	return nil
}

func (b *FakeIPAnswerBatch) take() []FakeIPAnswerLease {
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	answers := b.answers
	b.answers = nil
	return answers
}

func (b *FakeIPAnswerBatch) Delivered(at time.Time) {
	for _, answer := range b.take() {
		answer.Delivered(at)
	}
}

func (b *FakeIPAnswerBatch) Abort() {
	for _, answer := range b.take() {
		answer.Abort()
	}
}
