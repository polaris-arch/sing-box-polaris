package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
)

// TailscaleDirectoryDomain is a native-owned capability, never a JSON option.
// Its base is the trusted AppGroup configuration directory (container/polaris).
// Activation requires the caller's live, same-instance native/core handshake.
// Path authorization is not filesystem custody: the endpoint must still acquire
// the lease and check directory identity and symlinks before choosing a path.
type TailscaleDirectoryDomain struct {
	mu                                          sync.Mutex
	failureMu                                   sync.Mutex
	base, logicalRoot, physicalRoot, ownerNonce string
	active                                      bool
	failure                                     error
	failureHandler                              func(error) error
	failurePersistenceError                     error
	activated                                   bool
	activationAttempted                         bool
}

func NewTailscaleDirectoryDomain(base, ownerNonce string) (*TailscaleDirectoryDomain, error) {
	if !canonicalDirectoryPath(base) || base == filepath.VolumeName(base)+string(filepath.Separator) || strings.TrimSpace(ownerNonce) == "" {
		return nil, errors.New("invalid trusted Tailscale directory domain")
	}
	return &TailscaleDirectoryDomain{base: base, logicalRoot: filepath.Join(base, "tailscale"), physicalRoot: filepath.Join(base, "tailscale-g4-v1"), ownerNonce: ownerNonce}, nil
}

func canonicalDirectoryPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

// SetFailureHandler installs trusted durable revocation before activation.
// The handler must mark the physical domain unsafe under its admission lock,
// synchronously close all IO, and report any uncertainty. It must not call Fail.
func (d *TailscaleDirectoryDomain) SetFailureHandler(handler func(error) error) error {
	if d == nil || handler == nil {
		return errors.New("missing durable domain failure handler")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activationAttempted || d.failure != nil || d.failureHandler != nil {
		return errors.New("domain failure handler is already fixed")
	}
	d.failureHandler = handler
	return nil
}

func (d *TailscaleDirectoryDomain) Activate() error {
	if d == nil {
		return errors.New("missing Tailscale directory domain")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activationAttempted {
		return errors.New("directory domain activation is one-shot")
	}
	d.activationAttempted = true
	if d.failure != nil {
		return d.failure
	}
	if d.ownerNonce == "" || d.base == "" || d.failureHandler == nil {
		return errors.New("uninitialized or non-durable Tailscale directory domain")
	}
	d.activated = true
	d.active = true
	return nil
}

// Fail irrevocably removes in-memory authority first, then durably revokes the
// domain. A non-nil return forbids legacy Start: the unsafe marker is uncertain.
// Concurrent callers wait for the same first persistence result; no retry can
// erase an ambiguous close or turn it into permission to start legacy writers.
func (d *TailscaleDirectoryDomain) Fail(err error) error {
	if d == nil {
		return errors.New("missing Tailscale directory domain")
	}
	if err == nil {
		return nil
	}
	d.failureMu.Lock()
	defer d.failureMu.Unlock()
	d.mu.Lock()
	if d.failure != nil {
		result := d.failurePersistenceError
		d.mu.Unlock()
		return result
	}
	d.failure = err
	d.active = false
	handler := d.failureHandler
	d.mu.Unlock()
	persistErr := errors.New("missing durable domain failure handler")
	if handler != nil {
		persistErr = handler(err)
	}
	d.mu.Lock()
	d.failurePersistenceError = persistErr
	d.mu.Unlock()
	return persistErr
}

// FailurePersistenceError waits for any in-progress durable revocation.
func (d *TailscaleDirectoryDomain) FailurePersistenceError() error {
	if d == nil {
		return errors.New("missing Tailscale directory domain")
	}
	d.failureMu.Lock()
	defer d.failureMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failurePersistenceError
}

// Activated is independent of proof validity: a durably failed domain can
// admit legacy work after the one successful handshake, never before it.
func (d *TailscaleDirectoryDomain) Activated() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activated
}

func (d *TailscaleDirectoryDomain) Active() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active && d.failure == nil && d.ownerNonce != ""
}

func (d *TailscaleDirectoryDomain) Failure() error {
	if d == nil {
		return errors.New("missing Tailscale directory domain")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failure
}

func (d *TailscaleDirectoryDomain) LogicalRoot() string  { return d.logicalRoot }
func (d *TailscaleDirectoryDomain) PhysicalRoot() string { return d.physicalRoot }
func (d *TailscaleDirectoryDomain) OwnerNonce() string   { return d.ownerNonce }

type tailscaleDirectoryDomainKey struct{}
type tailscaleDirectoryMappingKey struct{}

func ContextWithTailscaleDirectoryDomain(ctx context.Context, d *TailscaleDirectoryDomain) context.Context {
	return context.WithValue(ctx, tailscaleDirectoryDomainKey{}, d)
}
func TailscaleDirectoryDomainFromContext(ctx context.Context) *TailscaleDirectoryDomain {
	d, _ := ctx.Value(tailscaleDirectoryDomainKey{}).(*TailscaleDirectoryDomain)
	return d
}

// Each input is a final decoded endpoint, not an untrusted enrollment claim.
type TailscaleDirectoryMappingInput struct {
	StateDirectory, TaildropDirectory string
}
type TailscaleDirectoryMapping struct {
	domain  *TailscaleDirectoryDomain
	entries map[TailscaleDirectoryMappingInput]TailscaleDirectoryMappingInput
}

// NewTailscaleDirectoryMapping validates the WHOLE set before returning authority.
// Empty/default Taildrop paths are intentionally ineligible: the core default is
// relative to workingPath, not necessarily a child of this endpoint's state.
func NewTailscaleDirectoryMapping(d *TailscaleDirectoryDomain, inputs []TailscaleDirectoryMappingInput) (*TailscaleDirectoryMapping, error) {
	if !d.Active() {
		return nil, errors.New("inactive Tailscale directory domain")
	}
	m := &TailscaleDirectoryMapping{domain: d, entries: make(map[TailscaleDirectoryMappingInput]TailscaleDirectoryMappingInput)}
	seen := make(map[string]bool)
	for _, in := range inputs {
		valid := canonicalDirectoryPath(in.StateDirectory) && filepath.Dir(in.StateDirectory) == d.logicalRoot && canonicalDirectoryPath(in.TaildropDirectory)
		rel, err := filepath.Rel(in.StateDirectory, in.TaildropDirectory)
		valid = valid && err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
		if !valid || seen[in.StateDirectory] {
			err := errors.New("tailscale configuration is outside managed directory domain")
			d.Fail(err)
			return nil, err
		}
		seen[in.StateDirectory] = true
		state := filepath.Join(d.physicalRoot, filepath.Base(in.StateDirectory))
		m.entries[in] = TailscaleDirectoryMappingInput{state, filepath.Join(state, rel)}
	}
	return m, nil
}

func (m *TailscaleDirectoryMapping) Domain() *TailscaleDirectoryDomain { return m.domain }

// Resolve supplies a candidate only. It neither creates nor selects a directory.
// Under its lease the endpoint must preserve existing logical state, reuse only
// authenticated physical state, and atomically enroll a new ID. Never use Stat
// alone as proof, migrate old state, or release custody before scoped IO drains.
func (m *TailscaleDirectoryMapping) Resolve(state, taildrop string) (string, string, bool) {
	if m == nil || !m.domain.Active() {
		return "", "", false
	}
	out, ok := m.entries[TailscaleDirectoryMappingInput{state, taildrop}]
	return out.StateDirectory, out.TaildropDirectory, ok
}

func ContextWithTailscaleDirectoryMapping(ctx context.Context, m *TailscaleDirectoryMapping) context.Context {
	return context.WithValue(ctx, tailscaleDirectoryMappingKey{}, m)
}
func TailscaleDirectoryMappingFromContext(ctx context.Context) *TailscaleDirectoryMapping {
	m, _ := ctx.Value(tailscaleDirectoryMappingKey{}).(*TailscaleDirectoryMapping)
	return m
}
