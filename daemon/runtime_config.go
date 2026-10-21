package daemon

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing/common/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type runtimeActorKey struct{}

// ContextWithRuntimeActor is used after server authentication. No request field
// or credential-derived hash supplies this scope.
func ContextWithRuntimeActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, runtimeActorKey{}, actor)
}

func runtimeActor(ctx context.Context) (string, error) {
	actor, ok := ctx.Value(runtimeActorKey{}).(string)
	if !ok || actor == "" {
		return "", status.Error(codes.Unauthenticated, "runtime actor scope missing")
	}
	return actor, nil
}

func (s *StartedService) runtimeInstance() (*box.Box, error) {
	s.serviceAccess.RLock()
	instance := s.instance
	s.serviceAccess.RUnlock()
	if instance == nil || instance.instance == nil {
		return nil, status.Error(codes.Unavailable, "runtime unavailable")
	}
	return instance.instance, nil
}

func runtimeIdentity(value box.RuntimeIdentity) *RuntimeIdentity {
	return &RuntimeIdentity{Incarnation: value.Incarnation, AppliedRevision: value.Revision, EffectiveDigest: value.EffectiveDigest}
}

func runtimeExpected(value *RuntimeIdentity, control uint64) (box.RuntimeIdentity, error) {
	if value == nil || value.Incarnation == "" || value.AppliedRevision == 0 || value.EffectiveDigest == "" {
		return box.RuntimeIdentity{}, status.Error(codes.InvalidArgument, "runtime identity required")
	}
	return box.RuntimeIdentity{Incarnation: value.Incarnation, Revision: value.AppliedRevision, EffectiveDigest: value.EffectiveDigest, ControlRevision: control}, nil
}

func runtimeErrors(values []box.RuntimePlanError) []*RuntimePlanError {
	result := make([]*RuntimePlanError, 0, len(values))
	for _, value := range values {
		result = append(result, &RuntimePlanError{Code: value.Code, EffectivePath: value.Path, DependencyPath: append([]string(nil), value.DependencyPath...), Message: value.Message})
	}
	return result
}

func runtimeImpacts(values []box.RuntimeImpact) []*RuntimeImpact {
	result := make([]*RuntimeImpact, 0, len(values))
	for _, value := range values {
		result = append(result, &RuntimeImpact{ResourceId: value.ResourceID, EffectivePath: value.Path, UpdateClass: RuntimeUpdateClass(RuntimeUpdateClass_value[value.UpdateClass]), Reason: value.Reason, AffectedSessionClasses: append([]string(nil), value.AffectedSessionClasses...), ReconnectRequired: value.ReconnectRequired})
	}
	return result
}

func runtimeOperation(value box.RuntimeConfigOperation) *RuntimeConfigOperation {
	return &RuntimeConfigOperation{PersistenceMode: value.PersistenceMode, OwnerReloadAcknowledged: value.OwnerReloadAcknowledged, DesiredStateDigest: value.DesiredStateDigest, DesiredStateRevision: value.DesiredStateRevision, ContractVersion: value.ContractVersion, TransactionId: value.TransactionID, State: RuntimeOperationState(RuntimeOperationState_value[value.State]), Before: runtimeIdentity(value.Before), Active: runtimeIdentity(value.Active), CandidateDigest: value.CandidateDigest, ImpactDigest: value.ImpactDigest, Impacts: runtimeImpacts(value.Impacts), Errors: runtimeErrors(value.Errors), Durable: value.Durable, RetirementState: value.RetirementState, ControlRevision: value.Active.ControlRevision}
}

func (s *StartedService) GetRuntimeCapabilities(ctx context.Context, _ *emptypb.Empty) (*RuntimeCapabilities, error) {
	if _, err := runtimeActor(ctx); err != nil {
		return nil, err
	}
	instance, err := s.runtimeInstance()
	if err != nil {
		return nil, err
	}
	capability := instance.RuntimeCapabilities()
	result := &RuntimeCapabilities{ContractVersion: capability.ContractVersion, ConnectedHotEnabled: capability.Enabled, Active: runtimeIdentity(capability.Identity), ReceiptRetentionSeconds: 300, MaxReceipts: 256, FullEffectiveSchemaSupported: capability.FullConfiguration, ControlRevision: capability.Identity.ControlRevision}
	for _, path := range capability.PendingAdapters {
		result.Fields = append(result.Fields, &RuntimeFieldCapability{EffectivePath: path, UpdateClass: RuntimeUpdateClass_PENDING_ADAPTER})
	}
	return result, nil
}

func (s *StartedService) PlanRuntimeConfig(ctx context.Context, request *PlanRuntimeConfigRequest) (*RuntimeConfigPlan, error) {
	actor, err := runtimeActor(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.ContractVersion != box.RuntimeConfigContractVersion {
		return nil, status.Error(codes.InvalidArgument, "unsupported runtime contract version")
	}
	expected, err := runtimeExpected(request.Expected, request.ExpectedControlRevision)
	if err != nil {
		return nil, err
	}
	instance, inheritedOverrides, err := s.runtimePlanInstance()
	if err != nil {
		return nil, err
	}
	if len(request.ConfigContent) == 0 || len(request.ConfigContent) > 4<<20 {
		return nil, status.Error(codes.ResourceExhausted, "runtime configuration input budget exceeded")
	}
	overrides := inheritedOverrides
	if request.Overrides != nil {
		overrides = &OverrideOptions{AutoRedirect: request.Overrides.AutoRedirect, IncludePackage: append([]string(nil), request.Overrides.IncludePackage...), ExcludePackage: append([]string(nil), request.Overrides.ExcludePackage...)}
	}
	// Reuse the pure existing parse/override/OOM projection, without acquiring
	// directory resources, constructing an Instance, or publishing a snapshot.
	prepared, err := s.prepareInstance(ctx, request.ConfigContent, overrides)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid runtime configuration")
	}
	effective, err := json.MarshalContext(prepared.ctx, prepared.options)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid effective configuration")
	}
	if len(request.SelectorIntents) > 256 {
		return nil, status.Error(codes.ResourceExhausted, "selector intent budget exceeded")
	}
	var intents []box.RuntimeSelectorIntent
	for _, intent := range request.SelectorIntents {
		if intent == nil {
			return nil, status.Error(codes.InvalidArgument, "nil selector intent")
		}
		intents = append(intents, box.RuntimeSelectorIntent{Group: intent.Group, Selected: intent.Selected, PinCurrentTCP: intent.PinCurrentTcp, ExpectedSelectionPath: append([]string(nil), intent.ExpectedSelectionPath...)})
	}
	plan, err := instance.PlanRuntimeConfigWithSelections(ctx, actor, expected, effective, intents)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &RuntimeConfigPlan{ContractVersion: plan.ContractVersion, PlanId: plan.PlanID, TransactionId: plan.TransactionID, Expected: runtimeIdentity(plan.Expected), CandidateDigest: plan.CandidateDigest, DependencyDigest: plan.DependencyDigest, ImpactDigest: plan.ImpactDigest, Impacts: runtimeImpacts(plan.Impacts), Errors: runtimeErrors(plan.Errors), ExpiresAtUnixMilli: plan.ExpiresAtUnixMilli, Applicable: plan.Applicable, NoOp: plan.NoOp, ExpectedControlRevision: plan.Expected.ControlRevision}, nil
}

func (s *StartedService) ApplyRuntimeConfig(ctx context.Context, request *ApplyRuntimeConfigRequest) (*RuntimeConfigOperation, error) {
	actor, err := runtimeActor(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.ContractVersion != box.RuntimeConfigContractVersion {
		return nil, status.Error(codes.InvalidArgument, "unsupported runtime contract version")
	}
	expected, err := runtimeExpected(request.Expected, request.ExpectedControlRevision)
	if err != nil {
		return nil, err
	}
	instance, err := s.runtimeInstance()
	if err != nil {
		return nil, err
	}
	operation, err := instance.ApplyRuntimeConfig(ctx, actor, box.RuntimeConfigApply{ContractVersion: request.ContractVersion, PlanID: request.PlanId, TransactionID: request.TransactionId, Expected: expected, CandidateDigest: request.CandidateDigest, AcceptedImpactDigest: request.AcceptedImpactDigest})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return runtimeOperation(operation), nil
}

func (s *StartedService) GetRuntimeConfigStatus(ctx context.Context, request *RuntimeConfigStatusRequest) (*RuntimeConfigStatus, error) {
	actor, err := runtimeActor(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.ContractVersion != box.RuntimeConfigContractVersion {
		return nil, status.Error(codes.InvalidArgument, "unsupported runtime contract version")
	}
	instance, err := s.runtimeInstance()
	if err != nil {
		return nil, err
	}
	current, err := instance.GetRuntimeConfigStatus(actor, request.RuntimeIncarnation, request.TransactionId)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	result := &RuntimeConfigStatus{PersistenceMode: current.PersistenceMode, DurableDesiredStateDigest: current.DurableDesiredStateDigest, DurableDesiredStateRevision: current.DurableDesiredStateRevision, DurableOwnerReloadAcknowledged: current.DurableOwnerReloadAcknowledged, ContractVersion: current.ContractVersion, Active: runtimeIdentity(current.Active), LookupState: RuntimeLookupState(RuntimeLookupState_value[current.LookupState]), DurableAppliedDigest: current.DurableAppliedDigest, ControlRevision: current.Active.ControlRevision}
	if current.Operation != nil {
		result.Operation = runtimeOperation(*current.Operation)
	}
	return result, nil
}

func (s *StartedService) AcknowledgeRuntimePersistence(ctx context.Context, request *RuntimePersistenceAcknowledgementRequest) (*RuntimeConfigOperation, error) {
	actor, err := runtimeActor(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.ContractVersion != box.RuntimeConfigContractVersion {
		return nil, status.Error(codes.InvalidArgument, "unsupported runtime contract version")
	}
	active, err := runtimeExpected(request.Active, request.ControlRevision)
	if err != nil {
		return nil, err
	}
	instance, err := s.runtimeInstance()
	if err != nil {
		return nil, err
	}
	operation, err := instance.AcknowledgeRuntimePersistence(ctx, actor, box.RuntimePersistenceAcknowledgement{
		ContractVersion: request.ContractVersion, TransactionID: request.TransactionId, Active: active,
		PersistenceMode: request.PersistenceMode, DesiredStateDigest: request.DesiredStateDigest, DesiredStateRevision: request.DesiredStateRevision,
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return runtimeOperation(operation), nil
}

func (s *StartedService) RetryRuntimePersistence(ctx context.Context, request *RuntimePersistenceRetryRequest) (*RuntimeConfigOperation, error) {
	actor, err := runtimeActor(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.ContractVersion != box.RuntimeConfigContractVersion {
		return nil, status.Error(codes.InvalidArgument, "unsupported runtime contract version")
	}
	active, err := runtimeExpected(request.Active, request.ControlRevision)
	if err != nil {
		return nil, err
	}
	instance, err := s.runtimeInstance()
	if err != nil {
		return nil, err
	}
	operation, err := instance.RetryRuntimePersistence(ctx, actor, box.RuntimePersistenceRetry{
		ContractVersion: request.ContractVersion, TransactionID: request.TransactionId, Active: active, PersistenceMode: request.PersistenceMode,
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return runtimeOperation(operation), nil
}
