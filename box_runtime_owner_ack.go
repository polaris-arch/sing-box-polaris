package box

import (
	"context"
	"encoding/hex"
	"errors"
)

// This is a successful provider reload receipt, not crash durability. Only the
// authenticated App owner can attest that its captured desired state remains
// durably authoritative under its established regeneration contract.
type RuntimeOwnerAcknowledgementRequiredError struct{ Mode string }

func (*RuntimeOwnerAcknowledgementRequiredError) Error() string {
	return "authoritative owner acknowledgement required"
}

type RuntimePersistenceAcknowledgement struct {
	ContractVersion      uint32
	TransactionID        string
	Active               RuntimeIdentity
	PersistenceMode      string
	DesiredStateDigest   string
	DesiredStateRevision string
}

func (s *Box) AcknowledgeRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceAcknowledgement) (RuntimeConfigOperation, error) {
	return s.acknowledgeRuntimePersistence(ctx, actor, request)
}

func (s *Box) acknowledgeRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceAcknowledgement) (RuntimeConfigOperation, error) {
	if request.ContractVersion != RuntimeConfigContractVersion || request.PersistenceMode != "app_authoritative_regeneration" {
		return RuntimeConfigOperation{}, errors.New("unsupported owner acknowledgement")
	}
	digest, err := hex.DecodeString(request.DesiredStateDigest)
	if err != nil || len(digest) != 32 || len(request.DesiredStateRevision) == 0 || len(request.DesiredStateRevision) > 256 {
		return RuntimeConfigOperation{}, errors.New("invalid desired-state evidence")
	}
	c := s.runtime
	if c == nil {
		return RuntimeConfigOperation{}, errors.New("runtime unavailable")
	}
	if err = c.controlEffects.LockContext(ctx); err != nil {
		return RuntimeConfigOperation{}, err
	}
	defer c.controlEffects.Unlock()
	c.access.Lock()
	record := c.plans[request.TransactionID]
	if record == nil || record.actor != actor || record.operation == nil || (record != c.pendingPersistence && record.receiptExpires != 0 && c.now().UnixMilli() >= record.receiptExpires) {
		c.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("unknown owner transaction")
	}
	if c.stopped || c.preparing || c.active != request.Active || record.operation.Active != request.Active || c.persistenceMode != request.PersistenceMode {
		c.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("owner acknowledgement identity changed")
	}
	if record.operation.Durable {
		if record.operation.DesiredStateDigest != request.DesiredStateDigest || record.operation.DesiredStateRevision != request.DesiredStateRevision {
			c.access.Unlock()
			return RuntimeConfigOperation{}, errors.New("owner acknowledgement replay conflict")
		}
		result := cloneRuntimeOperation(*record.operation)
		c.access.Unlock()
		return result, nil
	}
	if !record.awaitingOwnerAcknowledgement || !record.operation.OwnerReloadAcknowledged || record.operation.State != "COMMITTED_DURABILITY_PENDING" {
		c.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("provider reload has not acknowledged this transaction")
	}
	defer c.access.Unlock()
	record.awaitingOwnerAcknowledgement = false
	if c.configurationOwner == record {
		c.configurationOwner = nil
	}
	if c.pendingPersistence == record {
		c.pendingPersistence = nil
	}
	record.receiptExpires = c.now().Add(runtimePlanLifetime).UnixMilli()
	record.operation.State = "COMMITTED"
	record.operation.Durable = true
	record.operation.DesiredStateDigest = request.DesiredStateDigest
	record.operation.DesiredStateRevision = request.DesiredStateRevision
	filtered := record.operation.Errors[:0]
	for _, problem := range record.operation.Errors {
		if problem.Code != "OWNER_ACKNOWLEDGEMENT_REQUIRED" && problem.Code != "PERSISTENCE_FAILED" {
			filtered = append(filtered, problem)
		}
	}
	record.operation.Errors = filtered
	c.durableDigest = request.Active.EffectiveDigest
	c.durableIdentity = request.Active
	c.durableDesiredDigest = request.DesiredStateDigest
	c.durableDesiredRevision = request.DesiredStateRevision
	c.durableOwnerReload = true
	return cloneRuntimeOperation(*record.operation), nil
}
