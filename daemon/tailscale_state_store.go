package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/format"
)

const (
	tailscaleStoreRetirementVersion = "polaris-ts-auth-writer-retirement-v1"
	maxTailscaleRetirementRuns      = 256
)

type tailscaleRetirementInstance struct {
	RunNonce       string                       `json:"runNonce"`
	ConfigDigest   string                       `json:"configDigest"`
	Terminal       string                       `json:"terminal"`
	CensusComplete bool                         `json:"censusComplete"`
	Nodes          []adapter.TailscaleStoreNode `json:"nodes"`
}
type tailscaleRetirementRun struct {
	// Bound only to the original instance. A duplicate Close returning nil is
	// not completion, and failed construction never gets successful eligibility.
	closeFinished          <-chan struct{}
	originalCloseSucceeded bool
 runtimeNoAcquisition bool // exact runtime child marker plus actual never-entered preparation
	directoryPreparation preparedDirectoryResources
	directoryAuthority *adapter.TailscaleDirectoryDomain
	directoryAuthorityBound bool
	directoryScopes        func() []adapter.TailscaleDirectoryNode
	directoryFinal         *tailscaleDirectoryInstance
	access                 sync.Mutex
	binding                adapter.TailscaleStoreRunBinding
	expected               []string
	active                 []adapter.TailscaleStoreNode
	final                  *tailscaleRetirementInstance
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
	for _, run := range s.snapshotTailscaleRetirementRuns() {
		result.Instances = append(result.Instances, run.snapshot())
	}
	payload, _ := json.Marshal(result)
	return string(payload)
}

// admitTailscaleRetirementRun runs only at the next construction admission under
// lifecycleAccess. Never prune at stop/export: native prepareStop and terminal
// receipts require the same original run census, including empty runs.
func (s *StartedService) admitTailscaleRetirementRun() error {
	s.serviceAccess.Lock()
	var live *tailscaleRetirementRun
	if s.instance != nil {
		live = s.instance.tailscaleRetirement
	}
	s.serviceAccess.Unlock()
	s.tailscaleRetirementAccess.Lock()
	defer s.tailscaleRetirementAccess.Unlock()
	retained := s.tailscaleRetirementRuns[:0]
	for _, run := range s.tailscaleRetirementRuns {
		if run == live || !run.reclaimableEmptyRun() {
			retained = append(retained, run)
		}
	}
	clear(s.tailscaleRetirementRuns[len(retained):])
	s.tailscaleRetirementRuns = retained
	if len(retained) >= maxTailscaleRetirementRuns {
		return fmt.Errorf("Tailscale retirement census capacity reached")
	}
	return nil
}

func (r *tailscaleRetirementRun) reclaimableEmptyRun() bool {
	r.access.Lock()
	defer r.access.Unlock()
	select {
	case <-r.closeFinished:
	default:
		return false
	}
	return r.originalCloseSucceeded && (len(r.expected) == 0 || r.runtimeNoAcquisition) &&
		r.final != nil && r.final.CensusComplete && r.final.Terminal == "NoStoreConstruction" && len(r.final.Nodes) == 0 &&
		r.directoryFinal != nil && r.directoryFinal.CensusComplete && r.directoryFinal.Terminal == "NoDirectoryConstruction" && len(r.directoryFinal.Nodes) == 0
}

// The registry is independent of lifecycleAccess: a live HOT graph can reserve
// new physical births without re-entering the outer start/reload lock. Exports
// copy the exact original run pointers, then inspect each run outside this lock.
func(s *StartedService)snapshotTailscaleRetirementRuns()[]*tailscaleRetirementRun{
 s.tailscaleRetirementAccess.Lock();defer s.tailscaleRetirementAccess.Unlock()
 return append([]*tailscaleRetirementRun(nil),s.tailscaleRetirementRuns...)
}
func(s *StartedService)appendTailscaleRetirementRun(run *tailscaleRetirementRun)error{
 s.tailscaleRetirementAccess.Lock();defer s.tailscaleRetirementAccess.Unlock()
 // This is a new construction admission, the only allowed pruning boundary.
 retained:=s.tailscaleRetirementRuns[:0]
 for _,original:=range s.tailscaleRetirementRuns{if !original.reclaimableEmptyRun(){retained=append(retained,original)}}
 clear(s.tailscaleRetirementRuns[len(retained):]);s.tailscaleRetirementRuns=retained
 if len(s.tailscaleRetirementRuns)>=maxTailscaleRetirementRuns{return fmt.Errorf("Tailscale retirement census capacity reached")}
 s.tailscaleRetirementRuns=append(s.tailscaleRetirementRuns,run);return nil
}
