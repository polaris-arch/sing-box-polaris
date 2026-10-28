package box

import (
	"context"
	"errors"
)

// RuntimePersistenceRetry identifies the original publication, not a new Apply.
type RuntimePersistenceRetry struct {
	ContractVersion uint32
	TransactionID   string
	Active          RuntimeIdentity
	PersistenceMode string
}

func (s *Box) RetryRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceRetry) (RuntimeConfigOperation, error) {
	return s.retryRuntimePersistence(ctx, actor, request)
}

// Validate under access both before and after acquiring controlEffects. The
// first check makes synchronous callback reentry fail instead of self-deadlock.
func (c *runtimeCoordinator) validatePersistenceRetry(actor string, request RuntimePersistenceRetry) (*runtimePlanRecord, error) {
	if request.ContractVersion != RuntimeConfigContractVersion || c.stopped || c.preparing {
		return nil, errors.New("runtime persistence retry unavailable or busy")
	}
	r := c.plans[request.TransactionID]
	if r == nil || r.actor != actor || r.operation == nil || !r.persistenceTailEntered || r.retryInFlight {
		return nil, errors.New("unknown original persistence transaction")
	}
	if c.active != request.Active || r.operation.Active != request.Active || r.operation.PersistenceMode != request.PersistenceMode || c.persistenceMode != request.PersistenceMode {
		return nil, errors.New("runtime persistence retry identity conflict")
	}
	if r != c.pendingPersistence && (r.receiptExpires != 0 && c.now().UnixMilli() >= r.receiptExpires) {
		return nil, errors.New("original persistence receipt expired")
	}
	if r.operation.Durable || r.awaitingOwnerAcknowledgement {
		return r, nil
	}
	if r != c.pendingPersistence || !r.persistenceRetrySafe || r.persistenceCallback == nil || r.operation.State != "COMMITTED_DURABILITY_PENDING" {
		return nil, errors.New("original persistence callback is not retryable")
	}
	return r, nil
}

func (s *Box) retryRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceRetry) (RuntimeConfigOperation, error) {
	c := s.runtime
	if c == nil {
		return RuntimeConfigOperation{}, errors.New("runtime configuration adapter unavailable")
	}
	c.access.Lock()
	_, err := c.validatePersistenceRetry(actor, request)
	c.access.Unlock()
	if err != nil {
		return RuntimeConfigOperation{}, err
	}
	if err = c.controlEffects.LockContext(ctx); err != nil {
		return RuntimeConfigOperation{}, err
	}
	defer c.controlEffects.Unlock()
	c.access.Lock()
	r, err := c.validatePersistenceRetry(actor, request)
	if err != nil {
		c.access.Unlock()
		return RuntimeConfigOperation{}, err
	}
	if r.operation.Durable || r.awaitingOwnerAcknowledgement {
		result := cloneRuntimeOperation(*r.operation)
		c.access.Unlock()
		return result, nil
	}
	r.retryInFlight = true
	c.preparing = true
	c.workDone = make(chan struct{})
	c.access.Unlock()
	defer func() {
		c.access.Lock()
		r.retryInFlight = false
		c.preparing = false
		close(c.workDone)
		c.access.Unlock()
	}()
	// After admission cancellation cannot detach the original synchronous tail.
	// Close joins workDone; a stuck owner remains visibly pending, never freed.
	err = c.persistRuntimeTransactionLocked(c.ctx, request.Active, r.canonical, r.selectorIntents, r.persistenceCallback, r.persistenceParticipant)
	c.access.Lock()
	defer c.access.Unlock()
	filtered := r.operation.Errors[:0]
	for _, problem := range r.operation.Errors {
		if problem.Code != "PERSISTENCE_FAILED" && problem.Code != "OWNER_ACKNOWLEDGEMENT_REQUIRED" {
			filtered = append(filtered, problem)
		}
	}
	r.operation.Errors = filtered
	var ownerPending *RuntimeOwnerAcknowledgementRequiredError
	if errors.As(err, &ownerPending) && ownerPending.Mode == "app_authoritative_regeneration" && request.PersistenceMode == ownerPending.Mode {
		r.awaitingOwnerAcknowledgement = true
		r.operation.OwnerReloadAcknowledged = true
		r.operation.Errors = append(r.operation.Errors, RuntimePlanError{Code: "OWNER_ACKNOWLEDGEMENT_REQUIRED", Message: "owner reload content accepted; authoritative desired-state acknowledgement pending"})
	} else if err == nil && request.PersistenceMode != "app_authoritative_regeneration" {
		r.operation.State = "COMMITTED"
		r.operation.Durable = true
		c.durableDigest = request.Active.EffectiveDigest
		c.durableIdentity = request.Active
		c.durableDesiredDigest = ""
		c.durableDesiredRevision = ""
		c.durableOwnerReload = false
		if c.pendingPersistence == r {
			c.pendingPersistence = nil
		}
		r.receiptExpires = c.now().Add(runtimePlanLifetime).UnixMilli()
	} else {
		r.operation.Errors = append(r.operation.Errors, RuntimePlanError{Code: "PERSISTENCE_FAILED", Message: "active configuration committed; owner persistence acknowledgement pending"})
	}
	return cloneRuntimeOperation(*r.operation), nil
}
