package box

import "github.com/sagernet/sing-box/adapter"

const RuntimeConfigContractVersion uint32 = 1

type RuntimeIdentity struct {
	Incarnation     string `json:"incarnation"`
	Revision        uint64 `json:"applied_revision,string"`
	EffectiveDigest string `json:"effective_digest"`
	ControlRevision uint64 `json:"control_revision,string"`
}

func (i RuntimeIdentity) graphRevision() adapter.RuntimeRevision {
	return adapter.RuntimeRevision{Incarnation: i.Incarnation, Revision: i.Revision}
}

type RuntimeImpact struct {
	ResourceID             string   `json:"resource_id"`
	Path                   string   `json:"effective_path"`
	UpdateClass            string   `json:"update_class"`
	Reason                 string   `json:"reason"`
	AffectedSessionClasses []string `json:"affected_session_classes"`
	ReconnectRequired      bool     `json:"reconnect_required"`
}
type (
	RuntimePlanError struct {
		Code           string   `json:"code"`
		Path           string   `json:"effective_path"`
		DependencyPath []string `json:"dependency_path"`
		Message        string   `json:"message"`
	}
	RuntimeConfigPlan struct {
		ContractVersion    uint32             `json:"contract_version"`
		PlanID             string             `json:"plan_id"`
		TransactionID      string             `json:"transaction_id"`
		Expected           RuntimeIdentity    `json:"expected"`
		CandidateDigest    string             `json:"candidate_digest"`
		DependencyDigest   string             `json:"dependency_digest"`
		ImpactDigest       string             `json:"impact_digest"`
		Impacts            []RuntimeImpact    `json:"impacts"`
		Errors             []RuntimePlanError `json:"errors"`
		ExpiresAtUnixMilli int64              `json:"expires_at_unix_milli,string"`
		Applicable         bool               `json:"applicable"`
		NoOp               bool               `json:"no_op"`
	}
)
type RuntimeConfigApply struct {
	ContractVersion      uint32          `json:"contract_version"`
	PlanID               string          `json:"plan_id"`
	TransactionID        string          `json:"transaction_id"`
	Expected             RuntimeIdentity `json:"expected"`
	CandidateDigest      string          `json:"candidate_digest"`
	AcceptedImpactDigest string          `json:"accepted_impact_digest"`
}
type RuntimeConfigOperation struct {
	ContractVersion         uint32             `json:"contract_version"`
	TransactionID           string             `json:"transaction_id"`
	State                   string             `json:"state"`
	Before                  RuntimeIdentity    `json:"before"`
	Active                  RuntimeIdentity    `json:"active"`
	CandidateDigest         string             `json:"candidate_digest"`
	ImpactDigest            string             `json:"impact_digest"`
	Impacts                 []RuntimeImpact    `json:"impacts"`
	Errors                  []RuntimePlanError `json:"errors"`
	Durable                 bool               `json:"durable"`
	PersistenceMode         string             `json:"persistence_mode"`
	OwnerReloadAcknowledged bool               `json:"owner_reload_acknowledged"`
	DesiredStateDigest      string             `json:"desired_state_digest"`
	DesiredStateRevision    string             `json:"desired_state_revision"`
	RetirementState         string             `json:"retirement_state"`
}
type RuntimeConfigCapabilities struct {
	ContractVersion   uint32          `json:"contract_version"`
	FullConfiguration bool            `json:"full_configuration"`
	Enabled           bool            `json:"enabled"`
	Identity          RuntimeIdentity `json:"identity"`
	SupportedPaths    []string        `json:"supported_paths"`
	PendingAdapters   []string        `json:"pending_adapters"`
}
