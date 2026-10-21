package box

import "errors"

type RuntimeConfigStatus struct {
	ContractVersion                uint32
	Active                         RuntimeIdentity
	Operation                      *RuntimeConfigOperation
	LookupState                    string
	DurableAppliedDigest           string
	PersistenceMode                string
	DurableDesiredStateDigest      string
	DurableDesiredStateRevision    string
	DurableOwnerReloadAcknowledged bool
}

func (s *Box) GetRuntimeConfigStatus(actor, incarnation, transaction string) (RuntimeConfigStatus, error) {
	c := s.runtime
	if c == nil {
		return RuntimeConfigStatus{}, errors.New("runtime configuration adapter unavailable")
	}
	c.access.Lock()
	defer c.access.Unlock()
	result := RuntimeConfigStatus{ContractVersion: RuntimeConfigContractVersion, Active: c.active, DurableAppliedDigest: c.durableDigest, PersistenceMode: c.persistenceMode, DurableDesiredStateDigest: c.durableDesiredDigest, DurableDesiredStateRevision: c.durableDesiredRevision, DurableOwnerReloadAcknowledged: c.durableOwnerReload, LookupState: "ACTIVE_ONLY"}
	if incarnation != "" && incarnation != c.active.Incarnation {
		result.LookupState = "WRONG_INCARNATION"
		return result, nil
	}
	if transaction == "" {
		return result, nil
	}
	record := c.plans[transaction]
	if record == nil || record.actor != actor || record.operation == nil {
		result.LookupState = "UNKNOWN_OR_EXPIRED"
		return result, nil
	}
	operation := cloneRuntimeOperation(*record.operation)
	result.Operation = &operation
	result.LookupState = "FOUND"
	return result, nil
}

// BindRuntimePersistence is set by the existing authenticated owner before
// startup. The callback receives a detached effective snapshot after publication.
// It cannot roll back the commit and its errors stay visible in operation status.
func (s *Box) BindRuntimePersistence(persist func(RuntimeIdentity, []byte) error) error {
	return s.BindRuntimePersistenceMode(persist, "owner_acknowledged")
}

func (s *Box) BindRuntimePersistenceMode(persist func(RuntimeIdentity, []byte) error, mode string) error {
	return s.BindRuntimePersistenceOptions(persist, mode, false)
}

// BindRuntimePersistenceOptions explicitly opts a host into same-identity,
// same-byte replay after partial success, errors or a later namespace failure.
// Callbacks are synchronous and must not call Close, Ack or control operations.
// Generic callbacks remain non-repeatable unless their owner makes this promise.
func (s *Box) BindRuntimePersistenceOptions(persist func(RuntimeIdentity, []byte) error, mode string, retrySafe bool) error {
	if mode != "owner_acknowledged" && mode != "exact_configuration_file" && mode != "app_authoritative_regeneration" {
		return errors.New("unsupported runtime persistence mode")
	}
	if s.runtime == nil {
		return errors.New("runtime configuration adapter unavailable")
	}
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if s.runtime.initialPhase != 0 || s.runtime.preparing {
		return errors.New("runtime persistence binding is already active")
	}
	s.runtime.persist = persist
	s.runtime.persistenceMode = mode
	s.runtime.persistenceRetrySafe = retrySafe
	return nil
}
