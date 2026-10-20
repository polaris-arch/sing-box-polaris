package fakeip

import (
	"context"
	"errors"
	"sync/atomic"
)

var (
	ErrCandidateNotCommitted = errors.New("fake-IP candidate cannot issue answers before publication")
	ErrAnswerPermitRequired  = errors.New("runtime fake-IP transport requires a publication answer permit")
)

// AnswerPermit is prepared closed and committed only within the coordinator's
// publication barrier, after all failure-prone checks. Abort never revokes an
// already-published permit; retired graph work keeps its normal continuation.
type AnswerPermit struct{ state atomic.Uint32 }

func NewAnswerPermit() *AnswerPermit { return new(AnswerPermit) }
func (p *AnswerPermit) Commit() error {
	if p == nil {
		return ErrAnswerPermitRequired
	}
	if p.state.CompareAndSwap(0, 1) || p.state.Load() == 1 {
		return nil
	}
	return ErrCandidateNotCommitted
}
func (p *AnswerPermit) Abort() {
	if p != nil {
		p.state.CompareAndSwap(0, 2)
	}
}
func (p *AnswerPermit) admitted() bool { return p != nil && p.state.Load() == 1 }

type answerPermitContextKey struct{}

func ContextWithAnswerPermit(ctx context.Context, permit *AnswerPermit) context.Context {
	return context.WithValue(ctx, answerPermitContextKey{}, permit)
}

func AnswerPermitFromContext(ctx context.Context) (*AnswerPermit, bool) {
	permit, ok := ctx.Value(answerPermitContextKey{}).(*AnswerPermit)
	return permit, ok && permit != nil
}
