package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/format"
)

const (
	tailscaleStoreRetirementVersion = "polaris-ts-auth-writer-retirement-v1"
	tailscaleStartupCohortVersion   = "polaris-ts-startup-cohort-v1"
	maxTailscaleRetirementRuns      = 256
	maxTailscaleStartupCohortBytes  = 1 << 20
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
	closeFinished           <-chan struct{}
	originalCloseSucceeded  bool
	runtimeNoAcquisition    bool // exact runtime child marker plus actual never-entered preparation
	historyPinned           bool // original native-writer or typed startup census
	nativeChildReservations int
	directoryPreparation    preparedDirectoryResources
	directoryAuthority      *adapter.TailscaleDirectoryDomain
	directoryAuthorityBound bool
	directoryScopes         func() []adapter.TailscaleDirectoryNode
	directoryFinal          *tailscaleDirectoryInstance
	access                  sync.Mutex
	binding                 adapter.TailscaleStoreRunBinding
	expected                []string
	startupExpected         []string
	startupChildren         []*tailscaleRetirementRun
	startupSealed           bool
	active                  []adapter.TailscaleStoreNode
	final                   *tailscaleRetirementInstance
}

func newTailscaleRetirementRun(content string, options option.Options) (*tailscaleRetirementRun, error) {
	digest := sha256.Sum256([]byte(content))
	return newTailscaleRetirementRunWithDigest(hex.EncodeToString(digest[:]), options)
}

func newTailscaleRetirementRunWithDigest(digest string, options option.Options) (*tailscaleRetirementRun, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &tailscaleRetirementRun{
		binding:  adapter.TailscaleStoreRunBinding{RunNonce: hex.EncodeToString(nonce[:]), ConfigDigest: digest},
		expected: tailscaleRetirementTags(options.Endpoints),
	}, nil
}

func tailscaleRetirementTags(endpoints []option.Endpoint) []string {
	var tags []string
	for index, endpoint := range endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		tag := endpoint.Tag
		if tag == "" {
			tag = format.ToString(index)
		}
		tags = append(tags, tag)
	}
	return tags
}

func (r *tailscaleRetirementRun) recordStartupChild(child *tailscaleRetirementRun) {
	r.access.Lock()
	defer r.access.Unlock()
	if !r.startupSealed {
		r.startupChildren = append(r.startupChildren, child)
	}
}

type tailscaleStartupCohort struct {
	ContractVersion string                        `json:"contractVersion"`
	CensusComplete  bool                          `json:"censusComplete"`
	Parent          tailscaleRetirementInstance   `json:"parent"`
	InitialChildren []tailscaleRetirementInstance `json:"initialChildren"`
}

func (r *tailscaleRetirementRun) sealStartup(observe bool) string {
	r.access.Lock()
	r.startupSealed = true
	expected := r.startupExpected
	children := r.startupChildren
	r.startupExpected = nil
	r.startupChildren = nil
	r.access.Unlock()
	if !observe {
		return ""
	}
	parent, complete := r.startupScope()
	cohort := tailscaleStartupCohort{
		ContractVersion: tailscaleStartupCohortVersion,
		Parent:          parent,
		InitialChildren: make([]tailscaleRetirementInstance, 0, len(children)),
	}
	tags := make(map[string]bool, len(expected))
	for _, tag := range expected {
		complete = complete && !tags[tag]
		tags[tag] = true
	}
	files := make(map[string]bool, len(tags))
	consume := func(row tailscaleRetirementInstance) {
		for _, node := range row.Nodes {
			complete = complete && tags[node.Tag] && !files[node.StateFile]
			delete(tags, node.Tag)
			files[node.StateFile] = true
		}
	}
	consume(parent)
	for _, child := range children {
		row, known := child.startupScope()
		complete = complete && known
		consume(row)
		cohort.InitialChildren = append(cohort.InitialChildren, row)
	}
	cohort.CensusComplete = complete && len(tags) == 0
	payload, err := json.Marshal(cohort)
	if err != nil || len(payload) > maxTailscaleStartupCohortBytes {
		return ""
	}
	// Retain the same original row after later whole-service reloads, even
	// when its exact observed startup/terminal census has no StateStore.
	r.access.Lock()
	r.historyPinned = true
	r.access.Unlock()
	return string(payload)
}

func (r *tailscaleRetirementRun) startupScope() (tailscaleRetirementInstance, bool) {
	r.access.Lock()
	defer r.access.Unlock()
	row := r.snapshotUnderLock()
	complete := r.active != nil && r.final == nil && len(row.Nodes) == len(r.expected)
	for _, node := range row.Nodes {
		complete = complete && slices.Contains(r.expected, node.Tag) &&
			node.RunNonce == r.binding.RunNonce && node.ConfigDigest == r.binding.ConfigDigest &&
			filepath.IsAbs(node.StateDirectory) && filepath.Join(node.StateDirectory, "tailscaled.state") == node.StateFile
	}
	return row, complete
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
	return s.checkTailscaleRetirementAdmissionLocked(live)
}

// Construction admission is the only pruning boundary. Count native
// reservations even though they have no writer history until classified.
func (s *StartedService) checkTailscaleRetirementAdmissionLocked(live *tailscaleRetirementRun) error {
	retained := s.tailscaleRetirementRuns[:0]
	for _, run := range s.tailscaleRetirementRuns {
		if run == live || !run.reclaimableEmptyRun() {
			retained = append(retained, run)
		}
	}
	clear(s.tailscaleRetirementRuns[len(retained):])
	s.tailscaleRetirementRuns = retained
	if len(retained)+s.tailscaleReservedRuns >= maxTailscaleRetirementRuns {
		return fmt.Errorf("tailscale retirement census capacity reached")
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
	return !r.historyPinned && r.nativeChildReservations == 0 && r.originalCloseSucceeded &&
		(len(r.expected) == 0 || r.runtimeNoAcquisition) &&
		r.final != nil && r.final.CensusComplete && r.final.Terminal == "NoStoreConstruction" && len(r.final.Nodes) == 0 &&
		r.directoryFinal != nil && r.directoryFinal.CensusComplete && r.directoryFinal.Terminal == "NoDirectoryConstruction" && len(r.directoryFinal.Nodes) == 0
}

// The registry is independent of lifecycleAccess: a live HOT graph can reserve
// new physical births without re-entering the outer start/reload lock. Exports
// copy the exact original run pointers, then inspect each run outside this lock.
func (s *StartedService) snapshotTailscaleRetirementRuns() []*tailscaleRetirementRun {
	s.tailscaleRetirementAccess.Lock()
	defer s.tailscaleRetirementAccess.Unlock()
	return append([]*tailscaleRetirementRun(nil), s.tailscaleRetirementRuns...)
}

func (s *StartedService) appendTailscaleRetirementRun(run *tailscaleRetirementRun) error {
	s.tailscaleRetirementAccess.Lock()
	defer s.tailscaleRetirementAccess.Unlock()
	if err := s.checkTailscaleRetirementAdmissionLocked(nil); err != nil {
		return err
	}
	s.tailscaleRetirementRuns = append(s.tailscaleRetirementRuns, run)
	return nil
}

type nativeTailscaleRunReservation struct {
	once   sync.Once
	host   *StartedService
	run    *tailscaleRetirementRun
	parent *tailscaleRetirementRun
}

func (s *StartedService) reserveNativeTailscaleRetirementRun(run, parent *tailscaleRetirementRun) (*nativeTailscaleRunReservation, error) {
	s.tailscaleRetirementAccess.Lock()
	defer s.tailscaleRetirementAccess.Unlock()
	if parent != nil && !slices.Contains(s.tailscaleRetirementRuns, parent) {
		return nil, fmt.Errorf("original native Tailscale parent census is unavailable")
	}
	if err := s.checkTailscaleRetirementAdmissionLocked(parent); err != nil {
		return nil, err
	}
	if parent != nil {
		parent.access.Lock()
		parent.nativeChildReservations++
		parent.access.Unlock()
	}
	run.historyPinned = true
	s.tailscaleReservedRuns++
	return &nativeTailscaleRunReservation{host: s, run: run, parent: parent}, nil
}

func (r *nativeTailscaleRunReservation) finish(retain bool) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.host.tailscaleRetirementAccess.Lock()
		defer r.host.tailscaleRetirementAccess.Unlock()
		if r.parent != nil {
			r.parent.access.Lock()
			r.parent.nativeChildReservations--
			if retain {
				// The host native ledger can observe both original rows. Keep the
				// empty parent even when the old Box closes at strict Reload.
				r.parent.historyPinned = true
			}
			r.parent.access.Unlock()
		}
		if retain {
			r.host.tailscaleRetirementRuns = append(r.host.tailscaleRetirementRuns, r.run)
		}
		r.host.tailscaleReservedRuns--
	})
}
