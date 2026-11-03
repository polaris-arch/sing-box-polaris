package box

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
)

const runtimeSourceProducerActor = "internal:runtime-source-producer"

// A source refresh recognizes the already admitted finite client graph, not a
// new user decision. After materialization it must prove no additional platform
// demand and no replacement of physical/effectful owners. All normal Plan,
// immutable-source, actor, CAS, expiry, replay and Apply guards still run.
func (p *runtimeSourceProducer) planSourceRefresh(ctx context.Context, expected RuntimeIdentity, content []byte) (RuntimeConfigPlan, error) {
	if p == nil || p.box == nil || p.ctx == nil {
		return RuntimeConfigPlan{}, errors.New("source producer unavailable")
	}
	request, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	return p.box.planRuntimeConfigInternal(request, runtimeSourceProducerActor, expected, content, RuntimeClientImpactPolicyExplicit, p)
}

type runtimeSourcePlan struct {
	lease           adapter.RuntimeLease
	accepted        route.RuntimeRequirements
	available       route.RuntimeRequirements
	resources       []*runtimeResource
	persistenceBase *runtimeSourcePersistenceBase
}

// coordinator.access is held. Matching text or a forged actor name alone is
// never this authority: the actual active producer object must be a member.
func (c *runtimeCoordinator) checkRuntimeSourcePlanLocked(p *runtimeSourceProducer, expected RuntimeIdentity, content []byte) error {
	if c.preparing {
		return errors.New("source refresh waits for the original transaction owner")
	}
	return c.checkRuntimeSourceOwnerLocked(p, expected, content)
}

func (c *runtimeCoordinator) checkRuntimeSourceOwnerLocked(p *runtimeSourceProducer, expected RuntimeIdentity, content []byte) error {
	if p == nil || p.box == nil || p.box.runtime != c || p.ctx == nil || p.ctx.Err() != nil || c.stopped || c.initialPhase != 2 || c.active != expected || !bytes.Equal(c.canonical, content) {
		return errors.New("stale or stopped source producer")
	}
	if c.runtimeSourcePersistencePendingLocked() {
		return errors.New("source refresh waits for the original transaction owner")
	}
	for _, resource := range c.resources {
		if resource.sourceProducer == p && resource.fingerprint == p.fingerprint && resource.networkReady {
			return nil
		}
	}
	return errors.New("source producer is not in the current closure")
}

func (c *runtimeCoordinator) captureRuntimeSourcePlanLocked(p *runtimeSourceProducer, expected RuntimeIdentity, content []byte) (*runtimeSourcePlan, error) {
	if err := c.checkRuntimeSourcePlanLocked(p, expected, content); err != nil {
		return nil, err
	}
	return c.captureRuntimeSourceOwnerClosureLocked(expected)
}

func (c *runtimeCoordinator) captureRuntimeSourceOwnerClosureLocked(expected RuntimeIdentity) (*runtimeSourcePlan, error) {
	lease, err := c.store.Acquire()
	if err != nil {
		return nil, err
	}
	view, ok := lease.View().(*runtimeView)
	if !ok || view.identity != expected.graphRevision() {
		lease.Release()
		return nil, errors.New("source owner graph changed")
	}
	router, ok := view.router.(*route.Router)
	if !ok || view.platform == nil {
		lease.Release()
		return nil, errors.New("current platform owner unavailable")
	}
	accepted := route.RuntimeRequirementsFor(common.PtrValueOrDefault(c.options.Route), common.PtrValueOrDefault(c.options.DNS))
	// This queries immutable published objects, not initial requested flags or
	// native I/O. The graph lease retains their complete resource closure.
	available := router.RuntimeProvisionedRequirements(accepted)
	var base *runtimeSourcePersistenceBase
	if c.persistenceMode == "app_authoritative_regeneration" {
		base, err = c.captureSourcePersistenceBaseLocked(expected)
		if err != nil {
			lease.Release()
			return nil, err
		}
	}
	return &runtimeSourcePlan{lease: lease, accepted: accepted, available: available, resources: append([]*runtimeResource(nil), c.resources...), persistenceBase: base}, nil
}

func runtimeSourceRequirementsCovered(have, need route.RuntimeRequirements) bool {
	// Unlike the public legacy preparation predicate there is intentionally no
	// "can prepare first process searcher" exception for an unattended refresh.
	if need.Process && !have.Process || need.Neighbor && !have.Neighbor || need.WIFI && !have.WIFI {
		return false
	}
	files := make(map[string]bool, len(have.DHCPLeaseFiles))
	for _, path := range have.DHCPLeaseFiles {
		files[path] = true
	}
	for _, path := range need.DHCPLeaseFiles {
		if !files[path] {
			return false
		}
	}
	return true
}
func (p *runtimeSourcePlan) covers(need route.RuntimeRequirements) bool {
	// Existing unused native availability does not authorize newly requested
	// lookups; the demand must also be present in the accepted frozen graph.
	return runtimeSourceRequirementsCovered(p.accepted, need) && runtimeSourceRequirementsCovered(p.available, need)
}
func runtimeSourceConfirmationProblem(path, message string) RuntimePlanError {
	return RuntimePlanError{Code: "SOURCE_REFRESH_REQUIRES_CONFIRMATION", Path: path, Message: message}
}

func (p *runtimeSourcePlan) replacementProblems(ctx context.Context, options option.Options, rootDigest [32]byte) ([]RuntimePlanError, error) {
	replaced, err := runtimeReplacementNames(ctx, options, nil, rootDigest, p.resources)
	if err != nil {
		return nil, err
	}
	_, configs, err := runtimeConfigNodes(ctx, runtimeResolveGraphDefaults(options))
	if err != nil {
		return nil, err
	}
	var names []string
	for name, config := range configs {
		if replaced[name] && (config.inbound != nil || config.endpoint != nil || config.service != nil || config.provider != nil) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var problems []RuntimePlanError
	for _, name := range names {
		problems = append(problems, runtimeSourceConfirmationProblem(name, "source dependency replacement requires an explicit owner/impact decision"))
	}
	return problems, nil
}

// Never supersede an unresolved original durability owner from an unattended
// update, including a failed non-retry-safe callback that cannot be pinned.
// Revision one is the accepted startup configuration; controls do not change
// its configuration persistence identity.
func (c *runtimeCoordinator) runtimeSourcePersistencePendingLocked() bool {
	if c.pendingPersistence != nil || c.configurationOwner != nil && c.configurationOwner.operation != nil && !c.configurationOwner.operation.Durable {
		return true
	}
	for _, r := range c.plans {
		if r.operation != nil && (r.operation.State == "ABORTING_UNAPPLIED" || r.operation.State == "ABORTED_DEGRADED" || r.operation.RetirementState == "UNKNOWN") {
			return true
		}
	}
	if c.persistenceMode == "app_authoritative_regeneration" {
		return !c.cleanSourceConfigurationLocked()
	}
	return c.persist != nil && c.active.Revision > 1 && (c.durableIdentity.Incarnation != c.active.Incarnation || c.durableIdentity.Revision != c.active.Revision || c.durableIdentity.EffectiveDigest != c.active.EffectiveDigest)
}

type runtimeSourceApplyProofKey struct{}

// Stored privately on the executable Plan. This contains no live reservation;
// Apply must still own the original actor/CAS and a current published closure.
type runtimeSourceApplyProof struct {
	producer        *runtimeSourceProducer
	expected        RuntimeIdentity
	transactionID   string
	rootDigest      [32]byte
	tunDependencies map[string]string
	closure         runtimeSourcePlan
}

// Run before constructing any candidate logger, namespace, cohort or endpoint.
// The original immutable source bytes and current native owners are checked
// before possible external constructors, not merely after their side effects.
func (s *Box) validateRuntimeSourcePreparation(ctx context.Context, identity RuntimeIdentity, options option.Options) error {
	proof, _ := ctx.Value(runtimeSourceApplyProofKey{}).(*runtimeSourceApplyProof)
	if proof == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c := s.runtime
	c.access.Lock()
	record := c.plans[proof.transactionID]
	if record == nil || record.sourceProof != proof || record.actor != runtimeSourceProducerActor || !record.inFlight || !c.preparing ||
		identity.Incarnation != proof.expected.Incarnation || identity.Revision != proof.expected.Revision+1 || identity.EffectiveDigest != record.plan.CandidateDigest {
		c.access.Unlock()
		return errors.New("source preparation has no original in-flight plan")
	}
	if err := c.checkRuntimeSourceOwnerLocked(proof.producer, proof.expected, record.canonical); err != nil {
		c.access.Unlock()
		return err
	}
	current, err := c.captureRuntimeSourceOwnerClosureLocked(proof.expected)
	c.access.Unlock()
	if err != nil {
		return err
	}
	defer current.lease.Release()
	need := route.RuntimeRequirementsFor(common.PtrValueOrDefault(options.Route), common.PtrValueOrDefault(options.DNS))
	if !proof.closure.covers(need) || !current.covers(need) {
		return errors.New("source preparation requires new platform authority")
	}
	if err := runtimeCheckSources(ctx, record.sources); err != nil {
		return err
	}
	rootDigest, err := c.runtimeCaptureRootDigest(ctx, proof.expected)
	if err != nil {
		return err
	}
	if rootDigest != proof.rootDigest {
		return errors.New("source root content changed before construction")
	}
	tunDependencies, err := runtimeTunDependencySignatures(c.ctx, options)
	if err != nil {
		return err
	}
	if runtimeTunDependencyChanges(proof.tunDependencies, tunDependencies) {
		return errors.New("source physical dependencies changed before construction")
	}
	problems, err := current.replacementProblems(c.ctx, options, rootDigest)
	if err != nil {
		return err
	}
	if len(problems) != 0 {
		return errors.New("source preparation requires physical owner replacement")
	}
	if base := proof.closure.persistenceBase; base != nil {
		c.access.Lock()
		err := c.checkSourcePersistenceBaseLocked(base)
		c.access.Unlock()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Close the early-check -> root snapshot window before constructors. Both root
// and TUN inputs are those the candidate will actually use, and must still be
// the original source-only proof rather than fresh physical authority.
func runtimeCheckSourcePreparedInputs(ctx context.Context, prepared *preparedRuntimeGraph) error {
	proof, _ := ctx.Value(runtimeSourceApplyProofKey{}).(*runtimeSourceApplyProof)
	if proof == nil {
		return nil
	}
	if prepared.rootDigest != proof.rootDigest || runtimeTunDependencyChanges(proof.tunDependencies, prepared.tunDependencies) {
		return errors.New("source inputs changed before candidate construction")
	}
	return ctx.Err()
}
