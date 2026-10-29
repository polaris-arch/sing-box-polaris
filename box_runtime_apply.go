package box

import (
	"context"
	"errors"
	"math"

	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func (s *Box) PlanRuntimeConfig(ctx context.Context, actor string, expected RuntimeIdentity, content []byte) (RuntimeConfigPlan, error) {
	return s.planRuntimeConfig(ctx, actor, expected, content)
}

func (s *Box) PlanRuntimeConfigWithSelections(ctx context.Context, actor string, expected RuntimeIdentity, content []byte, intents []RuntimeSelectorIntent) (RuntimeConfigPlan, error) {
	return s.planRuntimeConfig(ctx, actor, expected, content, intents...)
}

func (s *Box) ApplyRuntimeConfig(ctx context.Context, actor string, request RuntimeConfigApply) (RuntimeConfigOperation, error) {
	return s.applyRuntimeConfig(ctx, actor, request)
}

func (s *Box) applyRuntimeConfig(ctx context.Context, actor string, request RuntimeConfigApply) (result RuntimeConfigOperation, resultErr error) {
	if request.ContractVersion != RuntimeConfigContractVersion {
		return RuntimeConfigOperation{}, errors.New("unsupported runtime contract version")
	}
	coordinator := s.runtime
	if coordinator == nil {
		return RuntimeConfigOperation{}, errors.New("runtime configuration adapter unavailable")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return RuntimeConfigOperation{}, err
	}
	fingerprint := runtimeDigest(encoded)
	if err := coordinator.checkRuntimeNoOpApply(ctx, actor, request); err != nil {
		return RuntimeConfigOperation{}, err
	}
	coordinator.access.Lock()
	record := coordinator.plans[request.TransactionID]
	if record == nil || record.actor != actor || record.plan.PlanID != request.PlanID {
		coordinator.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("unknown or expired runtime plan")
	}
	if record.consumed {
		if record.fingerprint != fingerprint {
			coordinator.access.Unlock()
			return RuntimeConfigOperation{}, errors.New("runtime transaction fingerprint conflict")
		}
		if record.operation == nil {
			coordinator.access.Unlock()
			return RuntimeConfigOperation{}, errors.New("runtime outcome unavailable; reconcile active revision")
		}
		operation := cloneRuntimeOperation(*record.operation)
		coordinator.access.Unlock()
		return operation, nil
	}
	if coordinator.initialPhase != 2 || coordinator.stopped || coordinator.preparing || coordinator.active != request.Expected || record.plan.Expected != request.Expected || coordinator.now().UnixMilli() >= record.plan.ExpiresAtUnixMilli || request.CandidateDigest != record.plan.CandidateDigest || request.AcceptedImpactDigest != record.plan.ImpactDigest {
		coordinator.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("runtime plan precondition changed")
	}
	if len(record.selectorIntents) > 0 && coordinator.active.ControlRevision == math.MaxUint64 {
		coordinator.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("runtime control revision exhausted")
	}
	if !record.plan.NoOp && coordinator.active.Revision == math.MaxUint64 {
		coordinator.access.Unlock()
		return RuntimeConfigOperation{}, errors.New("runtime graph revision exhausted")
	}
	if err := ctx.Err(); err != nil {
		coordinator.access.Unlock()
		return RuntimeConfigOperation{}, err
	}
	if record.plan.NoOp {
		record.consumed = true
		record.fingerprint = fingerprint
		state := "COMMITTED_DURABILITY_PENDING"
		durable := coordinator.durableIdentity == coordinator.active
		desiredDigest, desiredRevision := "", ""
		if durable {
			state = "COMMITTED"
			desiredDigest = coordinator.durableDesiredDigest
			desiredRevision = coordinator.durableDesiredRevision
		}
		record.operation = &RuntimeConfigOperation{ContractVersion: RuntimeConfigContractVersion, TransactionID: request.TransactionID, State: state, Before: coordinator.active, Active: coordinator.active, CandidateDigest: record.plan.CandidateDigest, ImpactDigest: record.plan.ImpactDigest, Durable: durable, PersistenceMode: coordinator.persistenceMode, OwnerReloadAcknowledged: durable && coordinator.durableOwnerReload, DesiredStateDigest: desiredDigest, DesiredStateRevision: desiredRevision, RetirementState: "DRAINED"}
		record.receiptExpires = coordinator.now().Add(runtimePlanLifetime).UnixMilli()
		operation := cloneRuntimeOperation(*record.operation)
		coordinator.access.Unlock()
		return operation, nil
	}
	record.consumed = true
	record.inFlight = true
	record.fingerprint = fingerprint
	record.operation = &RuntimeConfigOperation{ContractVersion: RuntimeConfigContractVersion, TransactionID: request.TransactionID, State: "PREPARING", PersistenceMode: coordinator.persistenceMode, Before: coordinator.active, Active: coordinator.active, CandidateDigest: record.plan.CandidateDigest, ImpactDigest: record.plan.ImpactDigest, Impacts: cloneRuntimeImpacts(record.plan.Impacts)}
	coordinator.preparing = true
	coordinator.workDone = make(chan struct{})
	next := coordinator.active
	next.Revision++
	next.EffectiveDigest = record.plan.CandidateDigest
	if len(record.selectorIntents) > 0 {
		next.ControlRevision++
	}
	coordinator.access.Unlock()

	published := false
	defer func() {
		if recovered := recover(); recovered != nil {
			coordinator.access.Lock()
			pending := coordinator.pendingPrepared
			committed := published
			if committed {
				record.operation.RetirementState = "UNKNOWN"
				record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "POST_COMMIT_FAILURE", Message: "active revision published; reconcile operation status"})
			}
			if !committed {
				record.operation.State = "ABORTING_UNAPPLIED"
				record.operation.Errors = []RuntimePlanError{{Code: "PREPARATION_PANIC", Message: "candidate preparation failed"}}
			}
			result = cloneRuntimeOperation(*record.operation)
			coordinator.access.Unlock()
			if !committed {
				if pending != nil {
					pending.abort()
					s.recordRuntimeCertificateEffects(record, pending)
					s.recordRuntimeTunRestoration(record, pending)
				}
				go s.observeRuntimeAbort(record, pending)
			}
			resultErr = nil
		}
		coordinator.access.Lock()
		coordinator.preparing = false
		close(coordinator.workDone)
		coordinator.access.Unlock()
	}()
	// Only preparation work observes request cancellation. Committed component
	// contexts are constructed under coordinator.ctx by prepareRuntimeGraphWithSelections.
	prepared, prepareErr := s.prepareRuntimeGraphWithSelections(ctx, next, record.options, record.selectorIntents, record.sources...)
	if prepareErr == nil && prepared.rootDigest != record.rootDigest {
		prepareErr = errors.New("root content changed after planning")
	}
	if prepareErr == nil {
		prepareErr = runtimeCheckSources(coordinator.ctx, record.sources)
	}
	if prepareErr == nil {
		prepareErr = ctx.Err()
	}
	if prepareErr == nil && len(runtimeValidateBoundInterfaces(coordinator.ctx, record.options)) > 0 {
		prepareErr = errors.New("requested outbound interface became unavailable")
	}
	if prepareErr == nil && coordinator.reference != nil {
		pause, pauseErr := coordinator.reference.Pause(ctx)
		if pause != nil {
			defer pause.Resume()
		}
		if pauseErr != nil {
			prepareErr = pauseErr
		}
	}
	var previous []*runtimeResource
	var operation RuntimeConfigOperation
	// Drain an already-admitted control effect before publishing. Waiting takes
	// no coordinator/admission guard; once held, publication and the effect's
	// current-identity check cannot pass each other.
	func() {
		if prepareErr == nil {
			if err := coordinator.controlEffects.LockContext(ctx); err != nil {
				prepareErr = err
			} else {
				defer coordinator.controlEffects.Unlock()
			}
		}
		if prepareErr == nil {
			prepareErr = prepared.stageRuntimeCertificates(ctx)
		}
		if prepareErr == nil {
			prepareErr = s.prepareRuntimePostBindEffects(ctx, prepared)
		}
		if prepareErr == nil {
			prepareErr = s.stageRuntimeTun(ctx, prepared, runtimeAcceptedListenerReconnect(record.plan.Impacts))
		}
		if prepareErr == nil {
			prepareErr = s.stageRuntimeListeners(ctx, prepared, runtimeAcceptedListenerReconnect(record.plan.Impacts))
		}
		if prepareErr == nil {
			prepareErr = prepared.stageRuntimePostBindEffects(ctx)
		}
		if prepareErr == nil {
			release, selectionErr := coordinator.lockRuntimeSelectorIntents(ctx, request.Expected, record.selectorIntents)
			if release != nil {
				defer release()
			}
			if selectionErr != nil {
				prepareErr = selectionErr
			}
		}
		var publication runtimeFakeIPPublication
		if prepared != nil {
			publication.logPublication = prepared.logPublication
			publication.dnsStores = prepared.dnsStores
			publication.endpoints = prepared.endpointTransaction
		}
		if prepareErr == nil {
			prepareErr = prepared.endpointTransaction.PreparePublication()
		}
		if prepareErr == nil {
			publication.commit, prepareErr = prepared.fenceRuntimeFakeIP()
			defer func() { publication.abort() }()
			if prepareErr == nil && prepared.tunTransaction != nil {
				publication.tun, prepareErr = prepared.tunTransaction.PreparePublication()
			}
			if prepareErr == nil && prepared.listenerTransaction != nil {
				publication.listeners, prepareErr = prepared.listenerTransaction.PreparePublication()
			}
		}
		if prepareErr == nil {
			prepareErr = prepared.validateRuntimeCertificateClaims()
		}
		coordinator.access.Lock()
		defer coordinator.access.Unlock()
		if prepareErr == nil && (coordinator.stopped || coordinator.active != request.Expected) {
			prepareErr = errors.New("runtime changed during preparation")
		}
		if prepareErr == nil {
			prepareErr = ctx.Err()
		}
		if prepareErr == nil {
			_, prepareErr = publication.publish(coordinator.store, request.Expected.graphRevision(), prepared.graph)
			if prepareErr == nil {
				published = true
				prepared.published = true
				previous = coordinator.resources
				coordinator.resources = append([]*runtimeResource(nil), prepared.resources...)
				for _, resource := range prepared.resources {
					resource.networkReady = true
				}
				coordinator.rootDigest = prepared.rootDigest
				coordinator.tunDependencies = prepared.tunDependencies
				coordinator.options = record.options
				coordinator.currentSources = append([]runtimeSourceSnapshot(nil), record.sources...)
				coordinator.canonical = append([]byte(nil), record.canonical...)
				coordinator.active = next
				coordinator.pendingPersistence = nil
				if coordinator.clashMode != nil {
					coordinator.clashMode.RuntimeReplaceModes(clashmode.CalculateModeList(record.options))
				}
				record.operation.Active = next
				record.operation.State = "COMMITTED_DURABILITY_PENDING"
				record.operation.RetirementState = "PENDING"
			}
		}
		if prepareErr != nil {
			record.operation.State = "ABORTING_UNAPPLIED"
			record.operation.Errors = []RuntimePlanError{{Code: "PREPARATION_FAILED", Message: "candidate was not published"}}
			var structured interface{ RuntimePlanError() RuntimePlanError }
			if errors.As(prepareErr, &structured) {
				record.operation.Errors = append(record.operation.Errors, structured.RuntimePlanError())
			}
		}
		operation = cloneRuntimeOperation(*record.operation)
	}()
	if prepareErr != nil {
		if prepared != nil {
			prepared.abort()
			s.recordRuntimeListenerRestoration(record, prepared)
			s.recordRuntimeCertificateEffects(record, prepared)
			s.recordRuntimeTunRestoration(record, prepared)
			s.recordRuntimePostBindEffects(record, prepared)
		}
		go s.observeRuntimeAbort(record, prepared)
		coordinator.access.Lock()
		operation = cloneRuntimeOperation(*record.operation)
		coordinator.access.Unlock()
		return operation, nil
	}
	if prepared.fakeIPMigration != nil {
		prepared.fakeIPMigration.ActivatePersistence()
	}
	service.PtrFromContext[urltest.HistoryStorage](coordinator.ctx).SetRuntimeActiveHistories(prepared.view.runtimeActiveHistories())
	prepared.releaseConstruction()
	for _, activate := range prepared.activate {
		activate()
	}
	current := make(map[*runtimeResource]bool, len(prepared.resources))
	for _, resource := range prepared.resources {
		current[resource] = true
	}
	var retired []*runtimeResource
	for _, resource := range previous {
		if current[resource] {
			continue
		}
		if resource.stop != nil {
			resource.stop()
		}
		resource.owner.Seal()
		retired = append(retired, resource)
	}
	coordinator.access.Lock()
	persist := coordinator.persist
	coordinator.access.Unlock()
	if persist != nil {
		// A persisted canonical snapshot alone does not certify completion of
		// the migration's already-admitted namespace writers or exact links.
		// All fallible durability work stays outside the publication guard.
		var migration runtimePersistenceParticipant
		if prepared.fakeIPMigration != nil {
			migration = prepared.fakeIPMigration
		}
		coordinator.access.Lock()
		record.persistenceCallback = persist
		record.persistenceParticipant = migration
		record.persistenceRetrySafe = coordinator.persistenceRetrySafe
		record.persistenceTailEntered = true
		if coordinator.active == next && (record.persistenceRetrySafe || coordinator.persistenceMode == "app_authoritative_regeneration") {
			coordinator.pendingPersistence = record
		}
		coordinator.access.Unlock()
		persistErr := coordinator.persistRuntimeTransaction(coordinator.ctx, next, record.canonical, record.selectorIntents, persist, migration)
		coordinator.access.Lock()
		var ownerPending *RuntimeOwnerAcknowledgementRequiredError
		if errors.As(persistErr, &ownerPending) && ownerPending.Mode == "app_authoritative_regeneration" && coordinator.persistenceMode == ownerPending.Mode {
			record.awaitingOwnerAcknowledgement = true
			record.persistenceParticipant = migration
			record.operation.OwnerReloadAcknowledged = true
			record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "OWNER_ACKNOWLEDGEMENT_REQUIRED", Message: "owner reload content accepted; authoritative desired-state acknowledgement pending"})
		} else if persistErr == nil && coordinator.persistenceMode != "app_authoritative_regeneration" {
			record.operation.State = "COMMITTED"
			record.operation.Durable = true
			coordinator.durableDigest = next.EffectiveDigest
			coordinator.durableIdentity = next
			coordinator.durableDesiredDigest = ""
			coordinator.durableDesiredRevision = ""
			coordinator.durableOwnerReload = false
		} else {
			record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "PERSISTENCE_FAILED", Message: "active configuration committed; owner persistence acknowledgement pending"})
		}
		if coordinator.pendingPersistence == record && (record.operation.Durable || (!record.persistenceRetrySafe && !record.awaitingOwnerAcknowledgement)) {
			coordinator.pendingPersistence = nil
		}
		coordinator.access.Unlock()
	}
	go s.observeRuntimeRetirement(record, retired)
	coordinator.access.Lock()
	operation = cloneRuntimeOperation(*record.operation)
	coordinator.access.Unlock()
	return operation, nil
}

func (s *Box) observeRuntimeAbort(record *runtimePlanRecord, prepared *preparedRuntimeGraph) {
	var err error
	if prepared != nil {
		if prepared.fakeIPMigration != nil {
			err = prepared.fakeIPMigration.WaitPersistence(context.Background())
		}
		err = errors.Join(err, waitRuntimeResources(context.Background(), prepared.created))
	}
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if err == nil {
		if prepared != nil && ((prepared.listenerRestoration != nil && !prepared.listenerRestoration.Restored) || prepared.compensationError != nil || prepared.externalEffectsAttempted || prepared.tunRestorationError != nil || prepared.postBindError != nil) {
			record.operation.State = "ABORTED_DEGRADED"
		} else {
			record.operation.State = "ABORTED_UNAPPLIED"
		}
		record.inFlight = false
		record.receiptExpires = s.runtime.now().Add(runtimePlanLifetime).UnixMilli()
	}
	// Sticky cleanup failures retain the charged record and uncertain resources.
}

func (s *Box) observeRuntimeRetirement(record *runtimePlanRecord, resources []*runtimeResource) {
	err := waitRuntimeResources(context.Background(), resources)
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if err != nil {
		record.operation.RetirementState = "UNKNOWN"
	} else {
		record.operation.RetirementState = "DRAINED"
		record.inFlight = false
		record.receiptExpires = s.runtime.now().Add(runtimePlanLifetime).UnixMilli()
	}
}
