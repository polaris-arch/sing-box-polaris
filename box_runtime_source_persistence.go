package box

import (
	"context"
	"errors"
	"time"
)

const runtimeSourceOnlyMode = "source_only_unchanged_configuration"

type runtimeSourcePersistenceBase struct {
	identity                               RuntimeIdentity
	durable, anchor                        RuntimeIdentity
	digest, desiredDigest, desiredRevision string
	ownerReload, known                     bool
}
type runtimeSourcePersistenceLineage struct {
	current RuntimeIdentity
	base    runtimeSourcePersistenceBase
}

func sameSourceConfigurationRevision(a, b RuntimeIdentity) bool {
	return a.Incarnation == b.Incarnation && a.Revision == b.Revision && a.EffectiveDigest == b.EffectiveDigest
}

// Missing evidence alone is never a clean UNKNOWN provenance.
func (c *runtimeCoordinator) cleanSourceConfigurationLocked() bool {
	return c.initialPhase == 2 && (c.active.Revision == 1 || c.durableIdentity == c.active ||
		c.sourceLineage != nil && sameSourceConfigurationRevision(c.sourceLineage.current, c.active))
}

func (c *runtimeCoordinator) captureSourcePersistenceBaseLocked(expected RuntimeIdentity) (*runtimeSourcePersistenceBase, error) {
	if c.active != expected || !c.cleanSourceConfigurationLocked() {
		return nil, errors.New("source base configuration has no clean provenance")
	}
	b := &runtimeSourcePersistenceBase{identity: expected, durable: c.durableIdentity, digest: c.durableDigest, desiredDigest: c.durableDesiredDigest, desiredRevision: c.durableDesiredRevision, ownerReload: c.durableOwnerReload}
	b.anchor = c.durableIdentity
	if c.sourceLineage != nil && sameSourceConfigurationRevision(c.sourceLineage.current, expected) {
		b.anchor = c.sourceLineage.base.anchor // fixed historical anchor, not a growing parent chain
	}
	b.known = expected.EffectiveDigest != "" && c.durableDigest == expected.EffectiveDigest && c.durableIdentity == expected && c.durableOwnerReload && c.durableDesiredDigest != "" && c.durableDesiredRevision != ""
	return b, nil
}

func (c *runtimeCoordinator) checkSourcePersistenceBaseLocked(b *runtimeSourcePersistenceBase) error {
	if b == nil || c.stopped || c.active != b.identity || !c.cleanSourceConfigurationLocked() || c.runtimeSourcePersistencePendingLocked() ||
		c.configurationOwner != nil && c.configurationOwner.operation != nil && !c.configurationOwner.operation.Durable {
		return errors.New("source base configuration owner changed")
	}
	if b.durable != c.durableIdentity || b.digest != c.durableDigest || b.desiredDigest != c.durableDesiredDigest || b.desiredRevision != c.durableDesiredRevision || b.ownerReload != c.durableOwnerReload {
		return errors.New("source base persistence evidence changed")
	}
	return nil
}

func runtimeSourceOnlyRecord(r *runtimePlanRecord) bool {
	return r != nil && r.sourceProof != nil && r.sourceProof.closure.persistenceBase != nil
}

func runtimeSourceOnlyContext(ctx context.Context) bool {
	p, _ := ctx.Value(runtimeSourceApplyProofKey{}).(*runtimeSourceApplyProof)
	return p != nil && p.closure.persistenceBase != nil
}

// Called only after successful graph/active/record publication while the same
// coordinator access and control-effects fence is still held. No I/O or ACK.
func (c *runtimeCoordinator) settleSourceOnlyLocked(r *runtimePlanRecord, active RuntimeIdentity) error {
	if !runtimeSourceOnlyRecord(r) || c.active != active || c.pendingPersistence != nil || c.configurationOwner != nil {
		return errors.New("source-only settlement scope changed")
	}
	b := *r.sourceProof.closure.persistenceBase
	if !sameSourceConfigurationRevision(r.operation.Before, b.identity) || r.canonical == nil || active.EffectiveDigest != b.identity.EffectiveDigest {
		return errors.New("source-only base mismatch")
	}
	r.operation.PersistenceMode = runtimeSourceOnlyMode
	r.operation.State = "COMMITTED"
	r.operation.Durable = b.known
	r.operation.OwnerReloadAcknowledged = false // no new native reload or new App D ACK
	if b.known {
		r.operation.DesiredStateDigest = b.desiredDigest
		r.operation.DesiredStateRevision = b.desiredRevision
		c.durableIdentity = active // same configuration; historical D evidence is preserved verbatim
	} else {
		r.operation.Errors = append(r.operation.Errors, RuntimePlanError{Code: "BASE_CONFIGURATION_DURABILITY_UNPROVEN", Message: "source resources committed; original configuration durability remains unproven"})
	}
	// No provider callback, no new App acknowledgement and no namespace tail.
	c.sourceLineage = &runtimeSourcePersistenceLineage{current: active, base: b}
	return nil
}

type runtimeSourcePersistenceDriver struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	wake   chan struct{}
	record *runtimePlanRecord // coordinator.access; exact original task, never actor lookup
}

func (s *Box) registerOriginalExactSourceTailLocked(r *runtimePlanRecord) {
	c := s.runtime
	if c.stopped || r.sourceProof == nil || r.actor != runtimeSourceProducerActor || r.persistenceUncertain ||
		!r.persistenceRetrySafe || !r.persistenceTailEntered || r.persistenceCallback == nil ||
		r.operation == nil || r.operation.Durable || r.operation.PersistenceMode != "exact_configuration_file" ||
		c.persistenceMode != "exact_configuration_file" || c.pendingPersistence != r || c.configurationOwner != r {
		return
	}
	if c.sourceDriver == nil {
		ctx, cancel := context.WithCancel(c.ctx)
		c.sourceDriver = &runtimeSourcePersistenceDriver{ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
		go s.runOriginalSourcePersistenceDriver(c.sourceDriver)
	}
	c.sourceDriver.record = r
	select {
	case c.sourceDriver.wake <- struct{}{}:
	default:
	}
}

func (c *runtimeCoordinator) sourceDriverEligibleLocked(r *runtimePlanRecord) bool {
	return r != nil && !c.stopped && c.pendingPersistence == r && c.configurationOwner == r &&
		r.sourceProof != nil && r.actor == runtimeSourceProducerActor && r.persistenceTailEntered && r.persistenceRetrySafe &&
		!r.persistenceUncertain && r.persistenceCallback != nil && r.operation != nil && !r.operation.Durable &&
		r.operation.State == "COMMITTED_DURABILITY_PENDING" && r.operation.PersistenceMode == "exact_configuration_file" &&
		c.persistenceMode == "exact_configuration_file" && c.active == r.operation.Active && c.sourceIntentEpoch == r.sourceDriverEpoch
}

// Instance-owned, one slot. Retirement of the publishing producer does not
// cancel this work. Only actual instance/control/intent and original tail fences do.
func (s *Box) runOriginalSourcePersistenceDriver(d *runtimeSourcePersistenceDriver) {
	defer close(d.done)
	c := s.runtime
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		}
		backoff := 250 * time.Millisecond
		for {
			timer := time.NewTimer(backoff)
			select {
			case <-d.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			c.access.Lock()
			r := d.record
			if !c.sourceDriverEligibleLocked(r) {
				if d.record == r {
					d.record = nil
				}
				c.access.Unlock()
				break
			}
			if c.preparing || r.retryInFlight || r.acknowledging {
				c.access.Unlock()
				continue
			}
			request := RuntimePersistenceRetry{ContractVersion: RuntimeConfigContractVersion, TransactionID: r.plan.TransactionID, Active: r.operation.Active, PersistenceMode: r.operation.PersistenceMode}
			c.access.Unlock()
			_, _ = s.retryRuntimePersistence(d.ctx, r.actor, request)
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}
}
