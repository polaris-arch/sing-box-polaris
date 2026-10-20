package daemon

import (
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
)

const tailscaleDirectoryRetirementVersion = "polaris-ts-directory-retirement-v1"

type tailscaleDirectoryInstance struct {
	RunNonce       string                           `json:"runNonce"`
	ConfigDigest   string                           `json:"configDigest"`
	Terminal       string                           `json:"terminal"`
	CensusComplete bool                             `json:"censusComplete"`
	Nodes          []adapter.TailscaleDirectoryNode `json:"nodes"`
}

func (r *tailscaleRetirementRun) captureDirectories(scopes func() []adapter.TailscaleDirectoryNode) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.directoryScopes == nil && r.directoryFinal == nil {
		r.directoryScopes = scopes
	}
}

func (r *tailscaleRetirementRun) directorySnapshotUnderLock() tailscaleDirectoryInstance {
	result := tailscaleDirectoryInstance{
		RunNonce: r.binding.RunNonce, ConfigDigest: r.binding.ConfigDigest,
		Terminal: "Unknown", Nodes: []adapter.TailscaleDirectoryNode{},
	}
	if r.directoryFinal != nil {
		result = *r.directoryFinal
		result.Nodes = append([]adapter.TailscaleDirectoryNode{}, result.Nodes...)
		return result
	}
	if r.directoryScopes != nil {
		result.Nodes = append(result.Nodes, r.directoryScopes()...)
	}
	// Live scope may contain a complete original census without claiming
	// retirement. Native prepareStop binds precisely this original inventory.
	result.CensusComplete = r.directoryCensus(result.Nodes)
	return result
}

func (r *tailscaleRetirementRun) directoryCensus(nodes []adapter.TailscaleDirectoryNode) bool {
	if len(nodes) != len(r.expected) {
		return false
	}
	expected, tags, paths := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, tag := range r.expected {
		if expected[tag] {
			return false
		}
		expected[tag] = true
	}
	for _, node := range nodes {
		if !expected[node.Tag] || tags[node.Tag] || paths[node.StateDirectory] || node.StateDirectory == "" ||
			node.RunNonce != r.binding.RunNonce || node.ConfigDigest != r.binding.ConfigDigest || node.CensusVersion != 1 {
			return false
		}
		tags[node.Tag], paths[node.StateDirectory] = true, true
	}
	return true
}

func (r *tailscaleRetirementRun) freezeDirectories(nodes []adapter.TailscaleDirectoryNode, constructed bool) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.directoryFinal != nil {
		return
	}
	result := tailscaleDirectoryInstance{
		RunNonce: r.binding.RunNonce, ConfigDigest: r.binding.ConfigDigest,
		Terminal: "Unknown", Nodes: append([]adapter.TailscaleDirectoryNode{}, nodes...),
	}
	result.CensusComplete = constructed && r.directoryCensus(nodes)
	complete := result.CensusComplete
	for _, node := range nodes {
		if node.WriterState != "SealedDrained" || node.DirectoryIdentity == "" || node.Incarnation == "" || node.DirectoryEpoch == "" || node.Failure != "" {
			complete = false
		}
	}
	if complete {
		result.Terminal = "SealedDrained"
		if len(nodes) == 0 {
			result.Terminal = "NoDirectoryConstruction"
		}
	}
	r.directoryFinal = &result
	if complete {
		r.directoryPreparation = nil
	}
	// Do not retain an unnecessary live Box graph once original results freeze.
	r.directoryScopes = nil
}

// applyDirectoryDomainAuthority acts on an export copy, including already frozen
// runs. A historical positive snapshot cannot survive later domain revocation.
func applyDirectoryDomainAuthority(result tailscaleDirectoryInstance, domain *adapter.TailscaleDirectoryDomain) tailscaleDirectoryInstance {
	if domain.Active() {
		return result
	}
	result.Terminal = "Unknown"
	result.CensusComplete = false
	result.Nodes = append([]adapter.TailscaleDirectoryNode{}, result.Nodes...)
	for index := range result.Nodes {
		result.Nodes[index].WriterState = "Unknown"
		result.Nodes[index].Failure = "managed directory domain is absent, inactive, or revoked"
	}
	return result
}

func (s *StartedService) ExportTailscaleDirectoryRetirement() string {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	result := struct {
		ContractVersion       string                       `json:"contractVersion"`
		GlobalCleanupEvidence string                       `json:"globalCleanupEvidence"`
		Instances             []tailscaleDirectoryInstance `json:"instances"`
	}{tailscaleDirectoryRetirementVersion, "CleanupUnknown", []tailscaleDirectoryInstance{}}
	for _, run := range s.snapshotTailscaleRetirementRuns() {
		run.access.Lock()
		authority := adapter.TailscaleDirectoryDomainFromContext(s.ctx)
		if run.directoryAuthorityBound {
			authority = run.directoryAuthority
		}
		snapshot := applyDirectoryDomainAuthority(run.directorySnapshotUnderLock(), authority)
		result.Instances = append(result.Instances, snapshot)
		run.access.Unlock()
	}
	payload, _ := json.Marshal(result)
	return string(payload)
}
