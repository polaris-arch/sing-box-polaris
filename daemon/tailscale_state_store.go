package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/format"
)

const tailscaleStoreRetirementVersion = "polaris-ts-auth-writer-retirement-v1"
const maxTailscaleRetirementRuns = 256

type tailscaleRetirementInstance struct {
	RunNonce       string                       `json:"runNonce"`
	ConfigDigest   string                       `json:"configDigest"`
	Terminal       string                       `json:"terminal"`
	CensusComplete bool                         `json:"censusComplete"`
	Nodes          []adapter.TailscaleStoreNode `json:"nodes"`
}
type tailscaleRetirementRun struct {
	directoryScopes func() []adapter.TailscaleDirectoryNode
	directoryFinal  *tailscaleDirectoryInstance
	access          sync.Mutex
	binding         adapter.TailscaleStoreRunBinding
	expected        []string
	active          []adapter.TailscaleStoreNode
	final           *tailscaleRetirementInstance
}

func newTailscaleRetirementRun(content string, options option.Options) (*tailscaleRetirementRun, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(content))
	run := &tailscaleRetirementRun{binding: adapter.TailscaleStoreRunBinding{RunNonce: hex.EncodeToString(nonce[:]), ConfigDigest: hex.EncodeToString(digest[:])}}
	for index, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		tag := endpoint.Tag
		if tag == "" {
			tag = format.ToString(index)
		}
		run.expected = append(run.expected, tag)
	}
	return run, nil
}
func (r *tailscaleRetirementRun) capture(nodes []adapter.TailscaleStoreNode) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.final == nil && r.active == nil {
		r.active = append([]adapter.TailscaleStoreNode{}, nodes...)
	}
}
func (r *tailscaleRetirementRun) freeze(nodes []adapter.TailscaleStoreNode, constructed bool) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.final != nil {
		return
	}
	result := r.snapshotUnderLock()
	result.Nodes = append([]adapter.TailscaleStoreNode{}, nodes...)
	result.CensusComplete = constructed && len(nodes) == len(r.expected)
	tags, paths := map[string]bool{}, map[string]bool{}
	expected := map[string]bool{}
	for _, tag := range r.expected {
		if expected[tag] {
			result.CensusComplete = false
		}
		expected[tag] = true
	}
	anyStore := false
	for _, node := range nodes {
		if !expected[node.Tag] || tags[node.Tag] || paths[node.StateFile] || node.StateFile == "" || node.RunNonce != r.binding.RunNonce || node.ConfigDigest != r.binding.ConfigDigest {
			result.CensusComplete = false
		}
		tags[node.Tag] = true
		paths[node.StateFile] = true
		if node.WriterState == "SealedDrained" {
			anyStore = true
		} else if node.WriterState != "NoStoreConstruction" {
			result.CensusComplete = false
		}
	}
	if result.CensusComplete {
		result.Terminal = "NoStoreConstruction"
		if anyStore {
			result.Terminal = "SealedDrained"
		}
	}
	r.final = &result
}
func (r *tailscaleRetirementRun) snapshotUnderLock() tailscaleRetirementInstance {
	return tailscaleRetirementInstance{RunNonce: r.binding.RunNonce, ConfigDigest: r.binding.ConfigDigest, Terminal: "Unknown", Nodes: append([]adapter.TailscaleStoreNode{}, r.active...)}
}
func (r *tailscaleRetirementRun) snapshot() tailscaleRetirementInstance {
	r.access.Lock()
	defer r.access.Unlock()
	result := r.snapshotUnderLock()
	if r.final != nil {
		result = *r.final
		result.Nodes = append([]adapter.TailscaleStoreNode{}, r.final.Nodes...)
	}
	return result
}

// Export is read-only, includes every retained original run, and never accepts
// a caller nonce/config/path or promotes ordinary close to a global proof.
func (s *StartedService) ExportTailscaleStoreRetirement() string {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	result := struct {
		ContractVersion       string                        `json:"contractVersion"`
		GlobalCleanupEvidence string                        `json:"globalCleanupEvidence"`
		Instances             []tailscaleRetirementInstance `json:"instances"`
	}{ContractVersion: tailscaleStoreRetirementVersion, GlobalCleanupEvidence: "CleanupUnknown", Instances: []tailscaleRetirementInstance{}}
	for _, run := range s.tailscaleRetirementRuns {
		result.Instances = append(result.Instances, run.snapshot())
	}
	payload, _ := json.Marshal(result)
	return string(payload)
}
