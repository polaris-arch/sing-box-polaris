package box

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
)

const (
	runtimePlanLimit        = 256
	runtimePlanStorageLimit = 128 << 20
	runtimeConfigByteLimit  = 4 << 20
	runtimePlanLifetime     = 5 * time.Minute
)

type runtimePlanRecord struct {
	plan                         RuntimeConfigPlan
	actor                        string
	options                      option.Options
	canonical                    []byte
	sources                      []runtimeSourceSnapshot
	selectorIntents              []RuntimeSelectorIntent
	rootDigest                   [32]byte
	consumed                     bool
	operation                    *RuntimeConfigOperation
	fingerprint                  string
	inFlight                     bool
	storageCharge                int
	receiptExpires               int64
	awaitingOwnerAcknowledgement bool
	acknowledging                bool
	persistenceParticipant       runtimePersistenceParticipant
	persistenceCallback          func(RuntimeIdentity, []byte) error
	persistenceRetrySafe         bool
	persistenceTailEntered       bool
	retryInFlight                bool
}

type runtimeCoordinator struct {
	fakeIP                 *fakeip.Manager
	access                 sync.Mutex
	controlEffects         runtimeEffectGate
	ctx                    context.Context
	store                  *runtimegraph.Store
	active                 RuntimeIdentity
	options                option.Options
	canonical              []byte
	durableDigest          string
	durableIdentity        RuntimeIdentity
	durableDesiredDigest   string
	durableDesiredRevision string
	durableOwnerReload     bool
	persist                func(RuntimeIdentity, []byte) error
	persistenceMode        string
	persistenceRetrySafe   bool
	pendingPersistence     *runtimePlanRecord
	resources              []*runtimeResource
	plans                  map[string]*runtimePlanRecord
	planStorage            int
	sequence               uint64
	resourceSequence       uint64
	catalog                map[adapter.RuntimeResourceID]*runtimeResource
	stable                 *runtimeResource
	reference              *route.RuntimeReferenceManager
	referenceReservation   adapter.RuntimeResourceLease
	stableReservation      adapter.RuntimeResourceLease
	ingressScope           *adapter.Scope
	ingressCloseOnce       sync.Once
	ingressCloseError      error
	gateway                *route.RuntimeRouter
	trackers               route.RuntimeTrackers
	clashMode              *clashmode.Manager
	initialSources         []runtimeSourceSnapshot
	currentSources         []runtimeSourceSnapshot
	rootDigest             [32]byte
	initialPhase           int
	initialRouter          *route.Router
	platformRequirements   route.RuntimeRequirements
	tunDependencies        map[string]string
	initialPrepared        *preparedRuntimeGraph
	pendingPrepared        *preparedRuntimeGraph
	stopped                bool
	preparing              bool
	workDone               chan struct{}
	shutdownOnce           sync.Once
	shutdownDone           chan struct{}
	shutdownError          error
	now                    func() time.Time
}

func newRuntimeCoordinator(ctx context.Context) (*runtimeCoordinator, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	incarnation := hex.EncodeToString(nonce[:])
	store, err := runtimegraph.NewStore(incarnation)
	if err != nil {
		return nil, err
	}
	return &runtimeCoordinator{ctx: ctx, store: store, active: RuntimeIdentity{Incarnation: incarnation}, plans: make(map[string]*runtimePlanRecord), catalog: make(map[adapter.RuntimeResourceID]*runtimeResource), shutdownDone: make(chan struct{}), now: time.Now}, nil
}

func runtimeDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func cloneRuntimePlan(plan RuntimeConfigPlan) RuntimeConfigPlan {
	plan.Impacts = cloneRuntimeImpacts(plan.Impacts)
	plan.Errors = append([]RuntimePlanError(nil), plan.Errors...)
	for i := range plan.Errors {
		plan.Errors[i].DependencyPath = append([]string(nil), plan.Errors[i].DependencyPath...)
	}
	return plan
}

func cloneRuntimeImpacts(impacts []RuntimeImpact) []RuntimeImpact {
	result := append([]RuntimeImpact(nil), impacts...)
	for i := range result {
		result[i].AffectedSessionClasses = append([]string(nil), result[i].AffectedSessionClasses...)
	}
	return result
}

func cloneRuntimeOperation(operation RuntimeConfigOperation) RuntimeConfigOperation {
	operation.Impacts = cloneRuntimeImpacts(operation.Impacts)
	operation.Errors = cloneRuntimePlan(RuntimeConfigPlan{Errors: operation.Errors}).Errors
	return operation
}

// planRuntimeConfig receives a server-authenticated actor scope, never a client
// field or credential hash. Parsing and bounded source reads run outside guards.
func (s *Box) planRuntimeConfig(ctx context.Context, actor string, expected RuntimeIdentity, content []byte, selectorIntents ...RuntimeSelectorIntent) (RuntimeConfigPlan, error) {
	plan := RuntimeConfigPlan{ContractVersion: RuntimeConfigContractVersion, Expected: expected}
	if len(content) == 0 || len(content) > runtimeConfigByteLimit {
		return plan, errors.New("runtime config exceeds bounded input size")
	}
	coordinator := s.runtime
	if coordinator == nil {
		return plan, errors.New("runtime configuration adapter is unavailable")
	}
	coordinator.access.Lock()
	if coordinator.initialPhase != 2 || coordinator.stopped || coordinator.active != expected {
		coordinator.access.Unlock()
		return plan, errors.New("stale or stopped runtime")
	}
	base := append([]byte(nil), coordinator.canonical...)
	parseContext := coordinator.ctx
	provisioned := coordinator.platformRequirements
	currentSources := append([]runtimeSourceSnapshot(nil), coordinator.currentSources...)
	tunDependencies := coordinator.tunDependencies
	baseRootDigest := coordinator.rootDigest
	coordinator.access.Unlock()
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	var options option.Options
	if err := json.UnmarshalContext(parseContext, append([]byte(nil), content...), &options); err != nil {
		// Parser errors can quote options containing credentials. The public plan
		// reports a bounded code; callers may use their local config validator.
		plan.Errors = []RuntimePlanError{{Code: "INVALID_CONFIG", Message: "configuration failed schema validation"}}
		return plan, nil
	}
	selectorIntents = cloneRuntimeSelectorIntents(selectorIntents)
	if err := runtimeValidateSelectorIntents(options, selectorIntents); err != nil {
		plan.Errors = []RuntimePlanError{{Code: "INVALID_SELECTOR_INTENT", Path: "outbounds", Message: "selector target or member is invalid"}}
		return plan, nil
	}
	if len(selectorIntents) > 0 {
		if err := coordinator.controlEffects.LockContext(ctx); err != nil {
			return plan, err
		}
		release, selectionErr := coordinator.lockRuntimeSelectorIntents(ctx, expected, selectorIntents)
		if release != nil {
			release()
		}
		coordinator.controlEffects.Unlock()
		if selectionErr != nil {
			plan.Errors = []RuntimePlanError{{Code: "STALE_SELECTION", Path: "outbounds", Message: "confirmed selector winner changed"}}
			return plan, nil
		}
	}
	canonical, err := json.MarshalContext(parseContext, options)
	if err != nil {
		return plan, errors.New("cannot canonicalize runtime configuration")
	}
	plan.CandidateDigest = runtimeDigest(canonical)
	plan.Impacts, plan.Errors = runtimeConfigCompatibility(parseContext, base, canonical, options)
	if len(plan.Errors) != 0 {
		return cloneRuntimePlan(plan), nil
	}
	if problems := runtimeValidateBoundInterfaces(parseContext, options); len(problems) > 0 {
		plan.Errors = problems
		return cloneRuntimePlan(plan), nil
	}
	if problems := runtimeFakeIPRangeProblems(coordinator.fakeIP, options); len(problems) > 0 {
		plan.Errors = problems
		plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: "dns.servers", UpdateClass: "RESTART_REQUIRED", Reason: "retained fake-IP range identity changes", ReconnectRequired: true})
		return cloneRuntimePlan(plan), nil
	}
	var trusted map[string]runtimeSourceSnapshot
	if runtimeHasRemoteSources(options) {
		session, sourceProblem := s.prepareRuntimeSourceDownload(expected, canonical, options)
		if sourceProblem != nil {
			plan.Errors = []RuntimePlanError{*sourceProblem}
			if sourceProblem.Code == "RESTART_REQUIRED" {
				plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: sourceProblem.Path, UpdateClass: "RESTART_REQUIRED", Reason: sourceProblem.Message, ReconnectRequired: true})
			}
			return cloneRuntimePlan(plan), nil
		}
		var downloadErr error
		trusted, downloadErr = runtimePrepareRemoteSources(ctx, options, plan.CandidateDigest, session)
		if downloadErr != nil {
			plan.Errors = []RuntimePlanError{{Code: "SOURCE_PREPARATION_FAILED", Path: "route.rule_set", Message: "source bytes could not be prepared; active configuration unchanged"}}
			return cloneRuntimePlan(plan), nil
		}
	}
	// Freeze sources before admitting an executable plan. The resulting options
	// are private decoded values and constructors never reread mutable inputs.
	options, sources, sourceDigest, sourceErrors := runtimeSnapshotSources(ctx, parseContext, options, trusted)
	if len(sourceErrors) != 0 {
		plan.Errors = sourceErrors
		return cloneRuntimePlan(plan), nil
	}
	if !runtimePlatformRequirementsAvailable(provisioned, route.RuntimeRequirementsFor(common.PtrValueOrDefault(options.Route), common.PtrValueOrDefault(options.DNS))) {
		plan.Errors = []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "route", DependencyPath: []string{"runtime.platform"}, Message: "candidate requires a platform resource not provisioned by the running instance"}}
		plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: "route", UpdateClass: "RESTART_REQUIRED", Reason: "additional platform resource required", ReconnectRequired: true})
		return cloneRuntimePlan(plan), nil
	}
	candidateTun, tunErr := runtimeTunDependencySignatures(parseContext, options)
	if tunErr != nil {
		plan.Errors = []RuntimePlanError{{Code: "INVALID_DEPENDENCY_GRAPH", Path: "inbounds", Message: "candidate physical dependency graph could not be validated"}}
		return plan, nil
	}
	if runtimeTunDependencyChanges(tunDependencies, candidateTun) {
		plan.Errors = []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "inbounds", DependencyPath: []string{"tun.physical_dependencies"}, Message: "candidate changes a captured TUN host, route-set or flow capability dependency"}}
		plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: "inbounds", UpdateClass: "RESTART_REQUIRED", Reason: "captured TUN physical dependency changes", ReconnectRequired: true})
		return plan, nil
	}
	plan.DependencyDigest, err = runtimePlannedDependencyDigest(parseContext, options, sourceDigest)
	if err != nil {
		plan.Errors = []RuntimePlanError{{Code: "INVALID_DEPENDENCY_GRAPH", Message: "candidate dependency graph is incomplete or ambiguous"}}
		return cloneRuntimePlan(plan), nil
	}
	plannedRootDigest, rootErr := coordinator.runtimeCaptureRootDigest(ctx, expected)
	if rootErr != nil {
		plan.Errors = []RuntimePlanError{{Code: "ROOT_SNAPSHOT_UNAVAILABLE", Path: "certificate", Message: "root content could not be frozen; current configuration retained"}}
		return plan, nil
	}
	plan.DependencyDigest = runtimeDigest(append(append([]byte(plan.DependencyDigest), 0), plannedRootDigest[:]...))
	if problems, replacementErr := s.preflightRuntimeNodeReplacements(ctx, options, selectorIntents, plannedRootDigest); replacementErr != nil {
		plan.Errors = []RuntimePlanError{{Code: "INVALID_DEPENDENCY_GRAPH", Message: "replacement ownership could not be validated"}}
		return cloneRuntimePlan(plan), nil
	} else if len(problems) > 0 {
		plan.Errors = problems
		for _, problem := range problems {
			plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: problem.Path, UpdateClass: "RESTART_REQUIRED", Reason: problem.Message, ReconnectRequired: true})
		}
		return cloneRuntimePlan(plan), nil
	}
	if endpointErr := s.preflightRuntimeEndpoints(ctx, options, selectorIntents, plannedRootDigest); endpointErr != nil {
		var structured interface{ RuntimePlanError() RuntimePlanError }
		if errors.As(endpointErr, &structured) {
			problem := structured.RuntimePlanError()
			plan.Errors = []RuntimePlanError{problem}
			plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: problem.Path, UpdateClass: problem.Code, Reason: problem.Message, ReconnectRequired: true})
		} else {
			plan.Errors = []RuntimePlanError{{Code: "ENDPOINT_PREFLIGHT_FAILED", Path: "endpoints", Message: "endpoint dependencies could not be prepared safely"}}
		}
		return cloneRuntimePlan(plan), nil
	}
	if len(selectorIntents) > 0 {
		encoded, _ := json.Marshal(selectorIntents)
		plan.DependencyDigest = runtimeDigest(append(append([]byte(plan.DependencyDigest), 0), encoded...))
		for _, intent := range selectorIntents {
			reason := "apply explicit selector target in the new graph"
			if intent.PinCurrentTCP {
				reason = "pin the confirmed TCP winner for both TCP and UDP in the new graph"
			}
			plan.Impacts = append(plan.Impacts, RuntimeImpact{Path: "outbounds", UpdateClass: "LOCAL_REPLACE", Reason: reason, AffectedSessionClasses: []string{"new admissions"}})
		}
	}
	plan.NoOp = plannedRootDigest == baseRootDigest && len(selectorIntents) == 0 && bytes.Equal(base, canonical) && runtimeEqualSourceSnapshots(currentSources, sources) && coordinator.runtimeNoOpDependenciesCurrent(ctx, expected, sources)
	if plan.NoOp {
		plan.Impacts = nil
	}
	impactBytes, err := json.Marshal(struct {
		Impacts         []RuntimeImpact
		SelectorIntents []RuntimeSelectorIntent
	}{plan.Impacts, selectorIntents})
	if err != nil {
		return plan, err
	}
	plan.ImpactDigest = runtimeDigest(impactBytes)
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	coordinator.access.Lock()
	defer coordinator.access.Unlock()
	if coordinator.initialPhase != 2 || coordinator.stopped || coordinator.active != expected {
		return RuntimeConfigPlan{}, errors.New("stale or stopped runtime")
	}
	now := coordinator.now()
	for id, record := range coordinator.plans {
		deadline := record.plan.ExpiresAtUnixMilli
		if record.consumed {
			deadline = record.receiptExpires
		}
		if record != coordinator.pendingPersistence && !record.inFlight && !record.acknowledging && !record.retryInFlight && deadline != 0 && now.UnixMilli() >= deadline {
			coordinator.planStorage -= record.storageCharge
			delete(coordinator.plans, id)
		}
	}
	intentBytes, _ := json.Marshal(selectorIntents)
	charge := len(content) + 2*len(canonical) + 2*len(intentBytes)
	for _, source := range sources {
		charge += 2 * len(source.content)
	}
	if charge > runtimePlanStorageLimit-coordinator.planStorage {
		return RuntimeConfigPlan{}, errors.New("runtime plan storage budget exhausted")
	}
	if len(coordinator.plans) >= runtimePlanLimit {
		return RuntimeConfigPlan{}, errors.New("runtime plan capacity exhausted")
	}
	if coordinator.sequence == math.MaxUint64 {
		return RuntimeConfigPlan{}, errors.New("runtime transaction sequence exhausted")
	}
	coordinator.sequence++
	identity := fmt.Sprintf("%s:%d", coordinator.active.Incarnation, coordinator.sequence)
	plan.PlanID = "plan:" + identity
	plan.TransactionID = "transaction:" + identity
	plan.ExpiresAtUnixMilli = now.Add(runtimePlanLifetime).UnixMilli()
	plan.Applicable = true
	coordinator.planStorage += charge
	coordinator.plans[plan.TransactionID] = &runtimePlanRecord{storageCharge: charge, plan: cloneRuntimePlan(plan), actor: actor, options: options, sources: sources, selectorIntents: selectorIntents, rootDigest: plannedRootDigest, canonical: append([]byte(nil), canonical...)}
	return cloneRuntimePlan(plan), nil
}
