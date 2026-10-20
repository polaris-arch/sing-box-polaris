package tun

import (
	"context"
	"errors"
)

// RuntimeSetTransaction replaces only physical TUN participants. Existing
// non-TUN resources and the current Box graph remain alive throughout staging.
// Physical replacement resets affected TUN sessions and cannot undo that reset.
type RuntimeSetTransaction struct {
	previous          []*Inbound
	next              []*Inbound
	attempted         []*Inbound
	staged            bool
	compensated       bool
	compensationError error
}

func NewRuntimeSetTransaction(previous, next []*Inbound) *RuntimeSetTransaction {
	return &RuntimeSetTransaction{previous: append([]*Inbound(nil), previous...), next: append([]*Inbound(nil), next...)}
}

func (t *RuntimeSetTransaction) Stage(ctx context.Context) error {
	if t.staged {
		return errors.New("TUN physical transaction already staged")
	}
	t.staged = true
	for _, previous := range t.previous {
		if err := ctx.Err(); err != nil {
			return err
		}
		t.attempted = append(t.attempted, previous)
		if err := previous.RuntimeSuspendPhysical(ctx); err != nil {
			return err
		}
	}
	for _, next := range t.next {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := next.RuntimeStagePhysical(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (t *RuntimeSetTransaction) PreparePublication() (*RuntimeTunPublication, error) {
	if !t.staged || t.compensated {
		return nil, errors.New("TUN transaction is not publishable")
	}
	return PrepareRuntimeTunPublication(t.next)
}

func (t *RuntimeSetTransaction) Compensate(ctx context.Context) error {
	if t.compensated {
		return t.compensationError
	}
	t.compensated = true
	// Do not reopen old devices while a new/uncertain owner may still own the
	// interface, routes or platform VPN handle.
	for i := len(t.next) - 1; i >= 0; i-- {
		if err := t.next[i].RuntimeSuspendPhysical(ctx); err != nil {
			t.compensationError = errors.Join(t.compensationError, err)
		}
	}
	if t.compensationError != nil {
		return t.compensationError
	}
	for _, previous := range t.attempted {
		if err := previous.RuntimeStagePhysical(ctx); err != nil {
			t.compensationError = errors.Join(t.compensationError, err)
			continue
		}
		publication, err := PrepareRuntimeTunPublication([]*Inbound{previous})
		if err != nil {
			t.compensationError = errors.Join(t.compensationError, err)
			continue
		}
		publication.Publish()
	}
	return t.compensationError
}
func (t *RuntimeSetTransaction) AffectedSessionsReset() bool { return len(t.attempted) != 0 }
