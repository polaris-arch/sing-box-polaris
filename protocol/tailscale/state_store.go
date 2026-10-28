//go:build with_tailscale

package tailscale

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/store"
	"github.com/sagernet/tailscale/util/dirscope"
)

const (
	stateStoreDrainTimeout = 5 * time.Second
	maxStateStoreBytes     = 4 << 20
)

// guardedStateStore owns the only delegate supplied to tsnet.Server.Store.
// Its lazy factory and every read/write share admission. Seal is permanent,
// including when construction or a delegate write is blocked or fails.
type guardedStateStore struct {
	directoryScope   *dirscope.Scope
	directoryReady   func() bool
	access           sync.Mutex
	initAccess       sync.Mutex
	sealed           bool
	inflight         int
	drained          chan struct{}
	drainedAt        time.Time
	factoryAttempted bool
	factoryFailed    bool
	delegate         ipn.StateStore
	factory          func() (ipn.StateStore, error)
	node             adapter.TailscaleStoreNode
	scopeValid       bool
	retireOnce       sync.Once
	terminal         adapter.TailscaleStoreNode
}

func newGuardedStateStore(ctx context.Context, tag, directory string, factory func() (ipn.StateStore, error)) *guardedStateStore {
	node := adapter.TailscaleStoreNode{
		Tag: tag, StateDirectory: directory,
		StateFile: filepath.Join(directory, "tailscaled.state"), WriterState: "Unknown",
		StateFileState: "Unknown", ProfileState: "Unknown",
	}
	if binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx); binding != nil {
		node.RunNonce, node.ConfigDigest = binding.RunNonce, binding.ConfigDigest
	}
	canonical, err := canonicalStateDirectory(directory)
	if err == nil {
		node.StateDirectory = canonical
		node.StateFile = filepath.Join(canonical, "tailscaled.state")
	}
	guard := &guardedStateStore{node: node, scopeValid: err == nil, factory: factory, drained: make(chan struct{})}
	if observer := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](ctx); observer != nil {
		accepted := false
		func() {
			defer func() {
				if !accepted {
					guard.seal()
				}
			}()
			if observer.Observe != nil {
				accepted = observer.Observe(node, func(deadline time.Time) adapter.TailscaleStoreNode {
					return guard.retire(deadline, nil)
				})
			}
		}()
	}
	return guard
}

// Resolve existing parents without creating the lazy FileStore directory.
func canonicalStateDirectory(path string) (string, error) {
	return adapter.CanonicalTailscaleStateDirectory(path)
}

func (s *guardedStateStore) admit() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.sealed {
		return os.ErrClosed
	}
	s.inflight++
	return nil
}

func (s *guardedStateStore) release() {
	s.access.Lock()
	defer s.access.Unlock()
	s.inflight--
	if s.sealed && s.inflight == 0 {
		s.drainedAt = time.Now()
		close(s.drained)
	}
}

func (s *guardedStateStore) initialized() (delegate ipn.StateStore, err error) {
	s.initAccess.Lock()
	defer s.initAccess.Unlock()
	if s.delegate != nil {
		return s.delegate, nil
	}
	if s.factoryFailed {
		return nil, errors.New("tailscale state store initialization failed")
	}
	s.factoryAttempted = true
	// A panic preserves its original propagation and marks possible construction
	// Unknown. The caller's defer still releases this initializer's admission.
	defer func() {
		if delegate == nil {
			s.factoryFailed = true
		}
	}()
	canonical, err := canonicalStateDirectory(s.node.StateDirectory)
	if err != nil || canonical != s.node.StateDirectory || !s.scopeValid {
		return nil, errors.New("tailscale state scope changed before initialization")
	}
	delegate, err = s.factory()
	if err != nil || delegate == nil {
		return nil, errors.New("tailscale state store initialization failed")
	}
	s.delegate = delegate
	return delegate, nil
}

func (s *guardedStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	if err := s.admit(); err != nil {
		return nil, err
	}
	defer s.release()
	delegate, err := s.initialized()
	if err != nil {
		return nil, err
	}
	return delegate.ReadState(id)
}

func (s *guardedStateStore) WriteState(id ipn.StateKey, value []byte) error {
	if err := s.admit(); err != nil {
		return err
	}
	defer s.release()
	delegate, err := s.initialized()
	if err != nil {
		return err
	}
	return delegate.WriteState(id, value)
}

func (s *guardedStateStore) isSealed() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.sealed
}

func (s *guardedStateStore) seal() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.sealed {
		return
	}
	s.sealed = true
	if s.inflight == 0 {
		s.drainedAt = time.Now()
		close(s.drained)
	}
}

func (s *guardedStateStore) retire(deadline time.Time, profile func() (string, string)) adapter.TailscaleStoreNode {
	s.retireOnce.Do(func() {
		result := s.node
		s.seal()
		timer := time.NewTimer(max(time.Until(deadline), 0))
		defer timer.Stop()
		select {
		case <-s.drained:
		case <-timer.C:
			s.terminal = result
			return
		}
		// Both select cases can be ready when this goroutine resumes. Actual
		// completion time, not random select choice, bounds the drain proof.
		s.access.Lock()
		drainedAt := s.drainedAt
		s.access.Unlock()
		if drainedAt.IsZero() || drainedAt.After(deadline) {
			s.terminal = result
			return
		}
		s.initAccess.Lock()
		attempted, failed := s.factoryAttempted, s.factoryFailed
		s.initAccess.Unlock()
		if !s.scopeValid || failed {
			s.terminal = result
			return
		}
		if attempted {
			result.WriterState = "SealedDrained"
		} else {
			result.WriterState = "NoStoreConstruction"
		}
		// A never-started owner has no process lease. Do not inspect its path
		// merely to improve an authentication witness.
		if s.directoryScope != nil && (s.directoryReady == nil || !s.directoryReady()) {
			s.terminal = result
			return
		}
		type fileWitness struct {
			content   []byte
			state     string
			err       error
			completed time.Time
		}
		fileReady := make(chan fileWitness, 1)
		go func() {
			release, scopeErr := s.directoryScope.Begin()
			if scopeErr != nil {
				fileReady <- fileWitness{state: "Unknown", err: scopeErr, completed: time.Now()}
				return
			}
			defer release()
			content, state, err := readStateFile(result.StateDirectory, result.StateFile, s.directoryScope.Fail)
			fileReady <- fileWitness{content, state, err, time.Now()}
		}()
		var witness fileWitness
		select {
		case witness = <-fileReady:
		case <-timer.C:
			s.terminal = result
			return
		}
		if witness.err != nil || witness.completed.After(deadline) {
			s.terminal = result
			return
		}
		content, fileState := witness.content, witness.state
		result.StateFileState = fileState
		if fileState == "Regular" {
			digest := sha256.Sum256(content)
			result.StateFileRevision = hex.EncodeToString(digest[:])
		}
		if profile == nil {
			if fileState == "Missing" {
				result.ProfileState = "None"
			}
			s.terminal = result
			return
		}
		// CurrentProfile locks the original backend. A blocked metadata observer is
		// not a drain certificate, and a late return cannot upgrade this terminal.
		type reference struct {
			id, key   string
			completed time.Time
		}
		metadata := make(chan reference, 1)
		go func() { id, key := profile(); metadata <- reference{id, key, time.Now()} }()
		select {
		case current := <-metadata:
			if current.completed.After(deadline) {
				break
			}
			if fileState == "Regular" && profileMatchesState(content, current.id, current.key) {
				digest := sha256.Sum256([]byte("polaris-ts-profile-v1\x00" + current.id + "\x00" + current.key))
				result.ProfileState = "Bound"
				result.ProfileFingerprint = hex.EncodeToString(digest[:])
			} else if fileState == "Missing" && current.id == "" && current.key == "" {
				result.ProfileState = "None"
			}
		case <-timer.C:
		}
		s.terminal = result
	})
	return s.terminal
}

func readStateFile(directory, path string, failures ...func(error)) (data []byte, state string, resultErr error) {
	canonical, err := canonicalStateDirectory(directory)
	if err != nil || canonical != directory {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return nil, "Unknown", errors.New("Tailscale state scope changed")
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "Missing", nil
	}
	if err != nil {
		return nil, "Unknown", err
	}
	if !before.Mode().IsRegular() || before.Size() > maxStateStoreBytes {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return nil, "Unknown", errors.New("Tailscale state file is not bounded regular data")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "Unknown", err
	}
	defer func() {
		closeErr := file.Close()
		for _, fail := range failures {
			fail(closeErr)
		}
		if closeErr != nil {
			state = "Unknown"
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return nil, "Unknown", errors.New("Tailscale state file changed")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxStateStoreBytes+1))
	if err != nil || len(content) > maxStateStoreBytes {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return nil, "Unknown", errors.New("Tailscale state file read failed")
	}
	after, err := os.Lstat(path)
	canonicalAfter, canonicalErr := canonicalStateDirectory(directory)
	if err != nil || canonicalErr != nil || canonicalAfter != directory || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return nil, "Unknown", errors.New("Tailscale state file changed")
	}
	return content, "Regular", nil
}

func profileMatchesState(content []byte, id, key string) bool {
	if id == "" || key == "" {
		return false
	}
	var state map[string]string
	if json.Unmarshal(content, &state) != nil {
		return false
	}
	current, err := base64.StdEncoding.Strict().DecodeString(state["_current-profile"])
	if err != nil || string(current) != key {
		return false
	}
	profilesBytes, err := base64.StdEncoding.Strict().DecodeString(state["_profiles"])
	if err != nil {
		return false
	}
	var profiles map[string]struct{ ID, Key string }
	if json.Unmarshal(profilesBytes, &profiles) != nil {
		return false
	}
	entry, ok := profiles[id]
	return ok && entry.ID == id && entry.Key == key
}

// Scope is immutable constructor metadata. Reading it does not create or seal
// a FileStore and cannot report a positive writer/profile/file terminal.
func (t *Endpoint) TailscaleStateStoreScope() adapter.TailscaleStoreNode {
	if t.stateStore == nil {
		return adapter.TailscaleStoreNode{Tag: t.Tag(), WriterState: "Unknown", StateFileState: "Unknown", ProfileState: "Unknown"}
	}
	return t.stateStore.node
}

func (t *Endpoint) RetireTailscaleStateStore(deadline time.Time) adapter.TailscaleStoreNode {
	if t.stateStore == nil {
		return adapter.TailscaleStoreNode{Tag: t.Tag(), WriterState: "Unknown", StateFileState: "Unknown", ProfileState: "Unknown"}
	}
	// This original pointer is retained before ordinary Close swaps it away.
	backend := t.localBackend.Load()
	var reference func() (string, string)
	if backend != nil {
		reference = func() (string, string) {
			profile := backend.CurrentProfile()
			if !profile.Valid() {
				return "", ""
			}
			return string(profile.ID()), string(profile.Key())
		}
	}
	return t.stateStore.retire(deadline, reference)
}

// retireStateStore is the construction cleanup of the endpoint. It seals only
// this known Store and reports a writer whose retirement could not be
// confirmed. It is registered when the endpoint is constructed, so it also
// runs for an endpoint that was never started.
func (t *Endpoint) retireStateStore() error {
	result := t.RetireTailscaleStateStore(time.Now().Add(stateStoreDrainTimeout))
	if result.WriterState == "Unknown" {
		//nolint:staticcheck // ST1005: Tailscale is a proper noun; preserve the stable error contract.
		return errors.New("Tailscale state writer retirement unknown")
	}
	return nil
}

func makeStateStore(ctx context.Context, tag, directory string, scopes ...*dirscope.Scope) *guardedStateStore {
	var scope *dirscope.Scope
	if len(scopes) == 1 {
		scope = scopes[0]
	}
	guard := newGuardedStateStore(ctx, tag, directory, nil)
	guard.directoryScope = scope
	guard.factory = func() (ipn.StateStore, error) {
		if scope != nil && (guard.directoryReady == nil || !guard.directoryReady()) {
			return nil, errors.New("directory lifetime lease not acquired")
		}
		return store.NewFileStoreWithScope(func(string, ...any) {}, guard.node.StateFile, scope)
	}
	return guard
}
