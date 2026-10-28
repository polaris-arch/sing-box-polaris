package libbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

const ConfigValidationContractVersion = "polaris-validation-v1"

// ConfigValidationResult separates config admission from cleanup evidence.
// SHA-256 covers the exact UTF-8 config bytes passed to this call. A caller must
// match all binding fields and recognized enums before consuming any evidence.
// A constructed config always reports CleanupUnknown: construction and disposal
// returning is not a proof that nothing was left behind.
type ConfigValidationResult struct {
	requestID                string
	configDigest             string
	contractVersion          string
	validation               string
	cleanup                  string
	validationError          string
	cleanupError             string
	tailscaleStoreRetirement string
	tailscaleStoreMembership string
}

func (r *ConfigValidationResult) GetRequestID() string       { return r.requestID }
func (r *ConfigValidationResult) GetConfigDigest() string    { return r.configDigest }
func (r *ConfigValidationResult) GetContractVersion() string { return r.contractVersion }
func (r *ConfigValidationResult) GetValidation() string      { return r.validation }
func (r *ConfigValidationResult) GetCleanup() string         { return r.cleanup }
func (r *ConfigValidationResult) GetValidationError() string { return r.validationError }
func (r *ConfigValidationResult) GetCleanupError() string    { return r.cleanupError }

// GetTailscaleStoreRetirement reads the immutable original invocation snapshot.
// It neither constructs nor seals a Store and is independent of global cleanup.
func (r *ConfigValidationResult) GetTailscaleStoreRetirement() string {
	return r.tailscaleStoreRetirement
}

// GetTailscaleStoreMembership reads this original validation's immutable scope
// snapshot. Complete membership is independent of writer or global retirement.
func (r *ConfigValidationResult) GetTailscaleStoreMembership() string {
	return r.tailscaleStoreMembership
}

// CheckConfigWithResult constructs and disposes without PreStart or Start.
// timeoutMillis must be in [1, 60000]. Timeout cancels construction but returns
// CleanupUnknown while its worker continues rollback/close. This API has no late
// callback and never upgrades the returned receipt; late work retains its own
// original request binding. Native completion alone is not a disposal proof.
func CheckConfigWithResult(configContent string, requestID string, timeoutMillis int64) *ConfigValidationResult {
	return checkConfigWithResultRandom(configContent, requestID, timeoutMillis, constructAndDisposeConfig, rand.Reader)
}

type configConstructor func(context.Context, option.Options) (error, error)

func checkConfigWithResult(configContent string, requestID string, timeoutMillis int64, construct configConstructor) *ConfigValidationResult {
	return checkConfigWithResultRandom(configContent, requestID, timeoutMillis, construct, rand.Reader)
}

func checkConfigWithResultRandom(configContent string, requestID string, timeoutMillis int64, construct configConstructor, entropy io.Reader) *ConfigValidationResult {
	digest := sha256.Sum256([]byte(configContent))
	binding := ConfigValidationResult{
		requestID:                requestID,
		configDigest:             hex.EncodeToString(digest[:]),
		contractVersion:          ConfigValidationContractVersion,
		validation:               "InternalFailure",
		cleanup:                  "NoConstruction",
		tailscaleStoreRetirement: validationTailscaleUnknown,
		tailscaleStoreMembership: marshalValidationTailscaleMembership(validationTailscaleMembership{
			ContractVersion: validationTailscaleMembershipVersion, RequestID: requestID,
			ConfigDigest: hex.EncodeToString(digest[:]), MembershipState: "Unknown", Targets: []validationTailscaleTarget{},
		}),
	}
	if requestID == "" || timeoutMillis < 1 || timeoutMillis > 60000 {
		binding.validationError = "invalid validation request binding or timeout"
		return &binding
	}
	ctx, cancel := context.WithTimeout(baseContext(nil), time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()
	run := &validationTailscaleRun{requestID: binding.requestID, binding: adapter.TailscaleStoreRunBinding{ConfigDigest: binding.configDigest}}
	completed := make(chan ConfigValidationResult, 1)
	go func(result ConfigValidationResult, ctx context.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				result.validation = "InternalFailure"
				result.cleanup = "CleanupUnknown"
				result.validationError = fmt.Sprintf("validation panicked: %v", recovered)
				result.tailscaleStoreRetirement = run.unknownSnapshot()
				result.tailscaleStoreMembership = run.membershipSnapshot(ctx, false)
			}
			run.closeAdmission()
			completed <- result
		}()
		// Random work stays inside the original bounded worker. No constructor
		// can observe this context until its own original nonce is established.
		if run.initialize(entropy) {
			originalBinding := run.binding
			ctx = service.ContextWithPtr(ctx, &originalBinding)
			observer := adapter.TailscaleStoreConstructionObserver{Observe: run.observe}
			ctx = service.ContextWithPtr(ctx, &observer)
		}
		options, err := parseConfig(ctx, configContent)
		if err != nil {
			result.validation = "Rejected"
			result.validationError = err.Error()
			result.tailscaleStoreRetirement = run.unknownSnapshot()
			result.tailscaleStoreMembership = run.membershipSnapshot(ctx, false)
			return
		}
		if ctx.Err() != nil {
			result.validationError = ctx.Err().Error()
			result.tailscaleStoreRetirement = run.unknownSnapshot()
			result.tailscaleStoreMembership = run.membershipSnapshot(ctx, false)
			return
		}
		// All construction branches remain unknown until acquire/error/async
		// paths of every enabled constructor have a reviewed disposal proof.
		result.cleanup = "CleanupUnknown"
		run.prepare(ctx, options)
		validationErr, cleanupErr := construct(ctx, options)
		if validationErr != nil {
			result.validation = "Rejected"
			result.validationError = validationErr.Error()
		} else {
			result.validation = "Accepted"
		}
		if cleanupErr != nil {
			result.cleanupError = cleanupErr.Error()
		}
		result.tailscaleStoreRetirement = run.finish(ctx, validationErr == nil)
		// The original constructor/cleanup callback has actually returned. Its
		// global disposal error is preserved above, independent of full scopes.
		result.tailscaleStoreMembership = run.membershipSnapshot(ctx, validationErr == nil)
		if ctx.Err() != nil {
			result.cleanup = "CleanupUnknown"
			result.validation = "InternalFailure"
			result.validationError = ctx.Err().Error()
			result.tailscaleStoreRetirement = run.unknownSnapshot()
			result.tailscaleStoreMembership = run.membershipSnapshot(ctx, false)
		}
	}(binding, ctx)
	select {
	case result := <-completed:
		return &result
	case <-ctx.Done():
		// Do not read the worker's mutable state, infer quiescence from cancel,
		// or let its eventual completion mutate this immutable receipt.
		binding.cleanup = "CleanupUnknown"
		binding.validationError = ctx.Err().Error()
		binding.cleanupError = "construction or disposal completion is unobserved"
		binding.tailscaleStoreRetirement = run.unknownSnapshot()
		binding.tailscaleStoreMembership = run.membershipSnapshot(ctx, false)
		return &binding
	}
}

func constructAndDisposeConfig(ctx context.Context, options option.Options) (error, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, (*platformInterfaceStub)(nil))
	instance, validationErr, report := box.NewWithConstructionReport(box.Options{Context: ctx, Options: options})
	cancel()
	if validationErr != nil {
		return validationErr, report.CleanupError
	}
	return nil, errors.Join(report.CleanupError, instance.CloseWithResult())
}

const validationTailscaleUnknown = `{"contractVersion":"polaris-ts-auth-writer-retirement-v1","globalCleanupEvidence":"CleanupUnknown","instances":[]}`

const validationTailscaleMembershipVersion = "polaris-ts-store-target-membership-v1"

type validationTailscaleTarget struct {
	Tag            string `json:"tag"`
	StateDirectory string `json:"stateDirectory"`
	StateFile      string `json:"stateFile"`
}

type validationTailscaleMembership struct {
	ContractVersion string                      `json:"contractVersion"`
	RequestID       string                      `json:"requestID"`
	ConfigDigest    string                      `json:"configDigest"`
	RunNonce        string                      `json:"runNonce"`
	MembershipState string                      `json:"membershipState"`
	Targets         []validationTailscaleTarget `json:"targets"`
}

func marshalValidationTailscaleMembership(document validationTailscaleMembership) string {
	payload, err := json.Marshal(document)
	if err != nil {
		return "" // A malformed payload cannot supply membership to a consumer.
	}
	return string(payload)
}

type validationTailscaleInstance struct {
	RunNonce       string                       `json:"runNonce"`
	ConfigDigest   string                       `json:"configDigest"`
	Terminal       string                       `json:"terminal"`
	CensusComplete bool                         `json:"censusComplete"`
	Nodes          []adapter.TailscaleStoreNode `json:"nodes"`
}

type validationTailscaleScope struct {
	tag, directory, file string
}

type validationTailscaleGuard struct {
	node   adapter.TailscaleStoreNode
	retire func(time.Time) adapter.TailscaleStoreNode
}

// This census belongs only to the original validation worker/context. It holds
// original guards while rollback may be blocked; it is not a runtime registry.
type validationTailscaleRun struct {
	access              sync.Mutex
	binding             adapter.TailscaleStoreRunBinding
	expected            []validationTailscaleScope
	expectedValid       bool
	guards              []validationTailscaleGuard
	closed              bool
	requestID           string
	membershipEligible  bool
	membershipLate      bool
	membershipCommitted bool
}

func (r *validationTailscaleRun) initialize(entropy io.Reader) bool {
	var nonce [32]byte
	if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return false
	}
	r.binding.RunNonce = hex.EncodeToString(nonce[:])
	return true
}

func (r *validationTailscaleRun) prepare(ctx context.Context, options option.Options) {
	expected := []validationTailscaleScope{}
	valid := true
	for index, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		settings, ok := endpoint.Options.(*option.TailscaleEndpointOptions)
		if !ok || settings == nil {
			valid = false
			continue
		}
		tag := endpoint.Tag
		if tag == "" {
			tag = format.ToString(index)
		}
		directory := settings.StateDirectory
		if directory == "" {
			directory = "tailscale"
		}
		directory = filemanager.BasePath(ctx, os.ExpandEnv(directory))
		canonical, err := adapter.CanonicalTailscaleStateDirectory(directory)
		if err != nil {
			valid = false
			continue
		}
		expected = append(expected, validationTailscaleScope{tag, canonical, filepath.Join(canonical, "tailscaled.state")})
	}
	r.access.Lock()
	defer r.access.Unlock()
	if !r.closed {
		r.expected, r.expectedValid = expected, valid
	}
}

func (r *validationTailscaleRun) observe(node adapter.TailscaleStoreNode, retire func(time.Time) adapter.TailscaleStoreNode) bool {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed || r.binding.RunNonce == "" || retire == nil {
		if !r.membershipCommitted {
			r.membershipLate = true
		}
		return false
	}
	r.guards = append(r.guards, validationTailscaleGuard{node, retire})
	return true
}

func (r *validationTailscaleRun) closeAdmission() {
	r.access.Lock()
	r.closed = true
	r.access.Unlock()
}

func marshalValidationTailscale(instance validationTailscaleInstance) string {
	result := struct {
		ContractVersion       string                        `json:"contractVersion"`
		GlobalCleanupEvidence string                        `json:"globalCleanupEvidence"`
		Instances             []validationTailscaleInstance `json:"instances"`
	}{"polaris-ts-auth-writer-retirement-v1", "CleanupUnknown", []validationTailscaleInstance{instance}}
	payload, err := json.Marshal(result)
	if err != nil {
		return validationTailscaleUnknown
	}
	return string(payload)
}

func (r *validationTailscaleRun) unknownSnapshot() string {
	r.access.Lock()
	defer r.access.Unlock()
	r.closed = true
	if r.binding.RunNonce == "" {
		return validationTailscaleUnknown
	}
	instance := validationTailscaleInstance{RunNonce: r.binding.RunNonce, ConfigDigest: r.binding.ConfigDigest, Terminal: "Unknown", Nodes: []adapter.TailscaleStoreNode{}}
	for _, guard := range r.guards {
		instance.Nodes = append(instance.Nodes, guard.node)
	}
	return marshalValidationTailscale(instance)
}

func (r *validationTailscaleRun) finish(ctx context.Context, constructed bool) string {
	r.access.Lock()
	eligible := !r.closed && r.expectedValid
	r.membershipEligible = eligible && constructed
	r.closed = true
	binding := r.binding
	expected := append([]validationTailscaleScope{}, r.expected...)
	guards := append([]validationTailscaleGuard{}, r.guards...)
	r.access.Unlock()
	if binding.RunNonce == "" {
		return validationTailscaleUnknown
	}
	deadline, bounded := ctx.Deadline()
	instance := validationTailscaleInstance{RunNonce: binding.RunNonce, ConfigDigest: binding.ConfigDigest, Terminal: "Unknown", Nodes: []adapter.TailscaleStoreNode{}}
	complete := eligible && constructed && bounded && len(expected) > 0 && len(guards) == len(expected)
	known := map[validationTailscaleScope]bool{}
	tags, files := map[string]bool{}, map[string]bool{}
	for _, scope := range expected {
		if known[scope] || tags[scope.tag] || files[scope.file] {
			complete = false
		}
		known[scope], tags[scope.tag], files[scope.file] = true, true, true
	}
	clear(tags)
	clear(files)
	anyStore := false
	for _, guard := range guards {
		node := guard.node
		if bounded {
			node = guard.retire(deadline)
		}
		instance.Nodes = append(instance.Nodes, node)
		scope := validationTailscaleScope{node.Tag, node.StateDirectory, node.StateFile}
		if !known[scope] || tags[node.Tag] || files[node.StateFile] || node.RunNonce != binding.RunNonce || node.ConfigDigest != binding.ConfigDigest || scope != (validationTailscaleScope{guard.node.Tag, guard.node.StateDirectory, guard.node.StateFile}) {
			complete = false
		}
		tags[node.Tag], files[node.StateFile] = true, true
		if node.WriterState == "SealedDrained" {
			anyStore = true
		} else if node.WriterState != "NoStoreConstruction" {
			complete = false
		}
	}
	if !bounded || time.Now().After(deadline) || ctx.Err() != nil {
		complete = false
	}
	if complete {
		instance.CensusComplete = true
		instance.Terminal = "NoStoreConstruction"
		if anyStore {
			instance.Terminal = "SealedDrained"
		}
	}
	payload := marshalValidationTailscale(instance)
	if !bounded || time.Now().After(deadline) || ctx.Err() != nil {
		return r.unknownSnapshot()
	}
	return payload
}

func validationTailscaleHex64(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// Snapshot commit shares the original registration lock. A rejected observer
// before commit is sticky Unknown; after commit the original same guard still
// seals before handoff, without upgrading or changing the returned string.
func (r *validationTailscaleRun) membershipSnapshot(ctx context.Context, completed bool) string {
	r.access.Lock()
	defer r.access.Unlock()
	document := validationTailscaleMembership{
		ContractVersion: validationTailscaleMembershipVersion, RequestID: r.requestID,
		ConfigDigest: r.binding.ConfigDigest, RunNonce: r.binding.RunNonce,
		MembershipState: "Unknown", Targets: []validationTailscaleTarget{},
	}
	deadline, bounded := ctx.Deadline()
	complete := completed && r.closed && r.membershipEligible && !r.membershipLate && bounded &&
		r.requestID != "" && validationTailscaleHex64(r.binding.RunNonce) && validationTailscaleHex64(r.binding.ConfigDigest) &&
		len(r.expected) == len(r.guards)
	known := map[validationTailscaleScope]bool{}
	tags, files := map[string]bool{}, map[string]bool{}
	for _, scope := range r.expected {
		if known[scope] || tags[scope.tag] || files[scope.file] {
			complete = false
		}
		known[scope], tags[scope.tag], files[scope.file] = true, true, true
	}
	clear(tags)
	clear(files)
	for _, guard := range r.guards {
		node := guard.node
		scope := validationTailscaleScope{node.Tag, node.StateDirectory, node.StateFile}
		if !known[scope] || tags[node.Tag] || files[node.StateFile] || node.RunNonce != r.binding.RunNonce || node.ConfigDigest != r.binding.ConfigDigest {
			complete = false
		}
		tags[node.Tag], files[node.StateFile] = true, true
	}
	if !bounded || time.Now().After(deadline) || ctx.Err() != nil {
		complete = false
	}
	if complete {
		document.MembershipState = "Complete"
		for _, scope := range r.expected {
			document.Targets = append(document.Targets, validationTailscaleTarget{scope.tag, scope.directory, scope.file})
		}
	}
	payload := marshalValidationTailscaleMembership(document)
	if !bounded || time.Now().After(deadline) || ctx.Err() != nil {
		document.MembershipState, document.Targets = "Unknown", []validationTailscaleTarget{}
		payload = marshalValidationTailscaleMembership(document)
	}
	r.membershipCommitted = true
	return payload
}
