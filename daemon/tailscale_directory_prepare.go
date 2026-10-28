package daemon

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

type preparedDirectoryResources interface {
	Context() context.Context
	Snapshot() []adapter.TailscaleDirectoryNode
	Abort() error
	Validate([]adapter.TailscaleDirectoryNode) error
	Commit() error
}

// The request may cancel preparation, but never owns the successful Instance.
// Cancellation reservation and commit use one guard; the callback itself runs
// outside it. Lease abort remains with the lifecycle coordinator after unwind.
type directoryPreparationCancellation struct {
	mu        sync.Mutex
	reserved  bool
	committed bool
	cancel    context.CancelFunc
	stop      func() bool
}

func watchDirectoryPreparation(request context.Context, cancel context.CancelFunc) *directoryPreparationCancellation {
	w := &directoryPreparationCancellation{cancel: cancel}
	w.stop = context.AfterFunc(request, func() {
		w.mu.Lock()
		if w.committed {
			w.mu.Unlock()
			return
		}
		w.reserved = true
		w.mu.Unlock()
		cancel()
	})
	return w
}

func (w *directoryPreparationCancellation) commit(request context.Context, commit func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reserved || request.Err() != nil {
		return context.Canceled
	}
	// commit must perform only the already validated ownership transfer.
	if err := commit(); err != nil {
		return err
	}
	w.committed = true
	w.stop()
	return nil
}

func (p *preparedInstance) abortDirectories() error {
	if p.directoryPlan == nil {
		if p.runtimeGraph && p.directoryRun != nil && !p.directoryCommitted {
			p.directoryCancel()
		}
		return nil
	}
	if p.directoryCommitted {
		return nil
	}
	p.directoryCancel()
	p.directoryWatch.stop()
	return p.directoryPlan.Abort()
}

func (r *tailscaleRetirementRun) installPreparedDirectories(plan preparedDirectoryResources, domain *adapter.TailscaleDirectoryDomain) {
	r.access.Lock()
	defer r.access.Unlock()
	r.directoryPreparation = plan
	r.directoryAuthority = domain
	r.directoryAuthorityBound = true
	r.directoryScopes = plan.Snapshot
}

func (r *tailscaleRetirementRun) transferPreparedDirectories(plan preparedDirectoryResources, scopes func() []adapter.TailscaleDirectoryNode) error {
	r.access.Lock()
	defer r.access.Unlock()
	if r.directoryPreparation != plan || r.directoryFinal != nil {
		return errors.New("original directory preparation owner changed")
	}
	// Retain the plan as the original owner. Its cleanup callbacks/observed
	// resources are not discarded merely because a Box was constructed.
	r.directoryScopes = func() []adapter.TailscaleDirectoryNode {
		nodes := append([]adapter.TailscaleDirectoryNode(nil), scopes()...)
		for _, original := range plan.Snapshot() {
			present := false
			for _, n := range nodes {
				if n.Tag == original.Tag && n.StateDirectory == original.StateDirectory && n.RunNonce == original.RunNonce && n.ConfigDigest == original.ConfigDigest && n.DirectoryIdentity == original.DirectoryIdentity && n.Incarnation == original.Incarnation && n.DirectoryEpoch == original.DirectoryEpoch {
					present = true
					break
				}
			}
			if !present {
				nodes = append(nodes, original)
			}
		}
		return nodes
	}
	return nil
}

// prepareReloadAdmission is the actual pre-detach path. The passed preparation
// function is the platform helper in production; tests inject acquisition
// failures here without native IO or replacing the old runtime.
func (s *StartedService) prepareReloadAdmission(ctx context.Context, prepared *preparedInstance, beforeStart func(), prepare func(context.Context, *preparedInstance) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = prepared.abortDirectories()
			panic(recovered)
		}
		if err != nil {
			_ = prepared.abortDirectories()
		}
	}()
	if err = prepare(ctx, prepared); err != nil {
		return err
	}
	// This check linearizes preparation admission immediately before callback.
	// Once the callback starts, later failure has no snapshot rollback promise.
	if err = ctx.Err(); err != nil {
		return err
	}
	if prepared.directoryPlan != nil {
		if err = prepared.ctx.Err(); err != nil {
			return err
		}
	}
	if beforeStart != nil {
		beforeStart()
	}
	return nil
}

func (p *preparedInstance) attachPreparedDirectoryRun(i *Instance) error {
	if p.directoryRun == nil || p.directoryFinished == nil || p.directoryRun.closeFinished != p.directoryFinished || i.tailscaleRetirement != p.directoryRun {
		return errors.New("prepared original run completion identity mismatch")
	}
	i.closeFinished = p.directoryFinished
	return nil
}

func (p *preparedInstance) commitDirectories(scopes func() []adapter.TailscaleDirectoryNode) error {
	if err := p.directoryRun.transferPreparedDirectories(p.directoryPlan, scopes); err != nil {
		return err
	}
	if err := p.directoryPlan.Validate(scopes()); err != nil {
		return err
	}
	if err := p.directoryWatch.commit(p.request, p.directoryPlan.Commit); err != nil {
		return err
	}
	p.directoryCommitted = true
	return nil
}
