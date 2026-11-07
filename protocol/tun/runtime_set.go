package tun

import (
	"context"
	"errors"
	"slices"
)

// RuntimeSetTransaction replaces only physical TUN participants. Existing
// non-TUN resources and the current Box graph remain alive throughout staging.
// Physical replacement resets affected TUN sessions and cannot undo that reset.
type RuntimeSetTransaction struct {
	previous          []*Inbound
	next              []*Inbound
	attempted         []*Inbound
	staged            bool
	stageComplete     bool
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
	// Validate the entire finite inventory before touching any old device.
	seen := make(map[*Inbound]bool)
	for _, participant := range append(append([]*Inbound(nil), t.previous...), t.next...) {
		if participant == nil || seen[participant] {
			return errors.New("TUN transaction requires distinct physical owners")
		}
		seen[participant] = true
		if err := participant.RuntimeValidate(); err != nil {
			return err
		}
		if len(t.previous) != 0 {
			if err := participant.RuntimeReplacementSupported(); err != nil {
				return err
			}
		}
	}
	// Bind native original owners before touching any old physical resource.
	for _, next := range t.next {
		if next.platformInterface == nil || !next.platformInterface.UsePlatformInterface() {
			continue
		}
		if len(t.previous) == 0 {
			continue
		} // V1 initial startup
		if len(t.previous) != 1 || len(t.next) != 1 {
			return errors.New("native TUN transaction requires one exact carrier")
		}
		if err := next.bindRuntimeNativePrevious(t.previous[0]); err != nil {
			return err
		}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	t.stageComplete = true
	return nil
}

func (t *RuntimeSetTransaction) PreparePublication() (*RuntimeTunPublication, error) {
	if !t.stageComplete || t.compensated {
		return nil, errors.New("TUN transaction is not publishable")
	}
	return PrepareRuntimeTunPublication(t.next)
}

func (t *RuntimeSetTransaction) Compensate(ctx context.Context) error {
	if !t.staged {
		return nil // validation failed before any physical effect
	}
	if t.compensated {
		return t.compensationError
	}
	t.compensated = true
	// Do not reopen old devices while a new/uncertain owner may still own the
	// interface, routes or platform VPN handle.
	for _, next := range slices.Backward(t.next) {
		if err := next.RuntimeSuspendPhysical(ctx); err != nil {
			t.compensationError = errors.Join(t.compensationError, err)
		}
	}
	if t.compensationError != nil {
		return t.compensationError
	}
	// Native Abort may replay old settings and produce a different original FD.
	// It runs only after every candidate reader/duplicate has truly joined.
	for _, next := range slices.Backward(t.next) {
		if err := next.RuntimeAbortNative(ctx); err != nil {
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
