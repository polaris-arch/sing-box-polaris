//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/adapter"
)

type preparedDirectoryKey struct{}

type preparedDirectoryEntry struct {
	tag, originalState, originalTaildrop string
	state, taildrop                      string
	owner                                *directoryOwner
	binding                              bool
	bound                                bool
	failed                               bool
	cleanup                              func() error
	validate                             func() error
}

type preparedDirectoryBinding struct {
	plan     *PreparedDirectoryLeases
	entry    *preparedDirectoryEntry
	finished bool
}

func (p *PreparedDirectoryLeases) Context() context.Context { return p.ctx }

func beginPreparedDirectoryBinding(ctx context.Context, tag, state, taildrop string) (*preparedDirectoryBinding, error) {
	p, _ := ctx.Value(preparedDirectoryKey{}).(*PreparedDirectoryLeases)
	if p == nil {
		return nil, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aborted || p.committed {
		return nil, errors.New("prepared directory plan is terminal")
	}
	for _, e := range p.entries {
		if e.tag != tag {
			continue
		}
		if e.originalState != state || e.originalTaildrop != taildrop || e.binding || e.bound || e.failed || e.owner == nil {
			return nil, errors.New("prepared directory binding mismatch or replay")
		}
		e.binding = true
		return &preparedDirectoryBinding{plan: p, entry: e}, nil
	}
	return nil, errors.New("prepared directory binding missing")
}

func (b *preparedDirectoryBinding) publish(cleanup func() error) {
	b.plan.mu.Lock()
	b.entry.cleanup = cleanup
	b.plan.mu.Unlock()
}

func (b *preparedDirectoryBinding) finish(success bool) {
	b.plan.mu.Lock()
	defer b.plan.mu.Unlock()
	if b.finished {
		if !success {
			b.entry.bound = false
			b.entry.failed = true
		}
		return
	}
	b.finished = true
	b.entry.binding = false
	b.entry.bound = success
	b.entry.failed = !success
}

func (p *PreparedDirectoryLeases) Snapshot() []adapter.TailscaleDirectoryNode {
	p.mu.Lock()
	owners := make([]*directoryOwner, 0, len(p.entries))
	for _, e := range p.entries {
		if e.owner != nil {
			owners = append(owners, e.owner)
		}
	}
	p.mu.Unlock()
	result := make([]adapter.TailscaleDirectoryNode, 0, len(owners))
	for _, owner := range owners {
		result = append(result, owner.snapshot())
	}
	return result
}

func (p *PreparedDirectoryLeases) Abort() error {
	p.mu.Lock()
	if p.committed {
		p.mu.Unlock()
		return errors.New("prepared directory plan already committed")
	}
	if p.aborted {
		p.mu.Unlock()
		return errors.New("prepared directory abort already requested; original evidence retained")
	}
	p.aborted = true
	var work []func() error
	var result error
	for _, e := range p.entries {
		if e.binding {
			result = errors.Join(result, fmt.Errorf("directory %s constructor still in flight", e.tag))
			continue
		}
		if e.cleanup != nil {
			work = append(work, e.cleanup)
		} else if e.owner != nil {
			d := e.owner
			work = append(work, func() error {
				d.scope.Seal()
				// No constructor captured this owner, so there are no writers.
				err := d.lease.Close()
				if err != nil {
					d.scope.Fail(err)
					d.mu.Lock()
					d.node.Failure = err.Error()
					d.mu.Unlock()
				}
				return err
			})
		}
	}
	p.mu.Unlock()
	for _, cleanup := range work {
		result = errors.Join(result, cleanup())
	}
	return result
}

func (p *PreparedDirectoryLeases) Validate(nodes []adapter.TailscaleDirectoryNode) error {
	// Validation does filesystem IO, never under the plan mutex. The lifecycle
	// coordinator excludes Abort and no binding remains active at this point.
	p.mu.Lock()
	if p.aborted || p.committed {
		p.mu.Unlock()
		return errors.New("prepared directory commit is terminal")
	}
	entries := append([]*preparedDirectoryEntry(nil), p.entries...)
	for _, e := range entries {
		if e.binding || !e.bound || e.failed {
			p.mu.Unlock()
			return errors.New("prepared directory binding incomplete")
		}
	}
	p.mu.Unlock()
	if len(nodes) != len(entries) {
		return errors.New("prepared directory inventory count mismatch")
	}
	seen := make(map[string]bool)
	for _, e := range entries {
		if err := e.validate(); err != nil {
			return err
		}
		expected := e.owner.snapshot()
		matched := false
		for _, n := range nodes {
			if n.Tag != e.tag {
				continue
			}
			if seen[n.Tag] || n.StateDirectory != expected.StateDirectory || n.RunNonce != expected.RunNonce || n.ConfigDigest != expected.ConfigDigest || n.DirectoryIdentity != expected.DirectoryIdentity || n.Incarnation != expected.Incarnation || n.DirectoryEpoch != expected.DirectoryEpoch {
				return errors.New("prepared directory inventory identity mismatch")
			}
			seen[n.Tag] = true
			matched = true
		}
		if !matched {
			return errors.New("prepared directory inventory entry missing")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aborted || p.committed {
		return errors.New("prepared directory commit lost ownership")
	}
	p.validated = true
	return nil
}

// Commit performs only ownership mutation after lifecycle-owned validation.
func (p *PreparedDirectoryLeases) Commit() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.aborted || p.committed || !p.validated {
		return errors.New("prepared directory commit lacks validated ownership")
	}
	p.committed = true
	return nil
}

// finishDirectoryConstruction is the actual constructor tail. Keeping this
// boundary explicit allows observer panic and immediate Scope cleanup fixtures
// without constructing unrelated dialers or starting the SDK.
func (t *Endpoint) finishDirectoryConstruction(ctx context.Context, tag, stateDirectory string, binding *preparedDirectoryBinding) error {
	success := false
	if binding != nil {
		defer func() { binding.finish(success) }()
	}
	if binding != nil {
		binding.publish(t.closeDirectoryAndStore)
	}
	t.stateStore = makeStateStore(ctx, tag, stateDirectory, t.directory.scope)
	if t.runtimePhysical != nil {
		t.runtimePhysical.observe(t, t.directory, t.stateStore)
	}
	t.stateStore.directoryReady = t.directory.ready
	t.server.Store = t.stateStore
	t.server.NetstackHandler = t
	// All cleanup-visible fields are ready. Finish the constructor token before
	// registration, since a canceled Scope can execute cleanup immediately.
	if binding != nil {
		binding.finish(true)
	}
	err := adapter.DeferConstructionCleanup(ctx, t.closeDirectoryAndStore)
	if err != nil {
		return err
	}
	if binding != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !t.directory.ready() || t.stateStore.isSealed() {
			return os.ErrClosed
		}
		success = true
	}
	return nil
}
