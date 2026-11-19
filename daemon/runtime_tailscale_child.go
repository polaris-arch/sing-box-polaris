package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// ContextWithRuntimeTailscaleChildren binds one standalone host census to the
// caller's outer lifecycle. Callers must reuse this context across Box reloads;
// creating a fresh census per Box would discard uncertain original children.
// This only installs the existing registrar: it starts no service or child and
// grants no managed-directory authority. Construction and retirement keep the
// same original signals, validation and capacity limits as StartedService.
func ContextWithRuntimeTailscaleChildren(ctx context.Context) context.Context {
	host := &StartedService{}
	return host.runtimeTailscaleContext(ctx, nil)
}

func (s *StartedService) runtimeTailscaleContext(ctx context.Context, parent *tailscaleRetirementRun) context.Context {
	ctx = adapter.ContextWithRuntimeTailscaleChildRegistrar(ctx, func(ctx context.Context, request adapter.RuntimeTailscaleChildRequest) (adapter.RuntimeTailscaleChildRegistration, error) {
		return s.registerRuntimeTailscaleChild(ctx, request, parent)
	})
	return adapter.ContextWithRuntimeTailscaleChildCapacity(ctx, s.runtimeTailscaleChildHasCapacity)
}

// Plan may inspect capacity without reserving or pruning original runs.
func (s *StartedService) runtimeTailscaleChildHasCapacity() bool {
	s.tailscaleRetirementAccess.Lock()
	defer s.tailscaleRetirementAccess.Unlock()
	retained := s.tailscaleReservedRuns
	for _, run := range s.tailscaleRetirementRuns {
		if !run.reclaimableEmptyRun() {
			retained++
		}
	}
	return retained < maxTailscaleRetirementRuns
}

type runtimeChildDirectoryPlan interface {
	preparedDirectoryResources
	Acquire(context.Context) error
}

const runtimeTailscaleNativeCloseTimeout = 2 * time.Second

var errRuntimeTailscaleNativeCloseUnknown = errors.New("original native Tailscale closure is unconfirmed")

type runtimeTailscaleChild struct {
	op                          sync.Mutex // lifecycle operation serialization, never used by context/snapshot callbacks
	mu                          sync.Mutex
	ctx                         context.Context
	run                         *tailscaleRetirementRun
	request                     adapter.RuntimeTailscaleChildRequest
	options                     option.Options
	selected                    option.Endpoint
	plan                        runtimeChildDirectoryPlan
	native                      adapter.RuntimeTailscaleWriterPlatform
	nativeScope                 adapter.RuntimeTailscaleWriterScope
	nativeReservation           *nativeTailscaleRunReservation
	nativeCloseDone             chan struct{}
	nativeCloseResult           error
	nativeCloseWait             sync.Once
	nativeCloseWaitResult       error
	claimKnown, claimed         bool
	directoryEntered            bool
	entered, committed, aborted bool
	abortErr                    error
}

func (s *StartedService) registerRuntimeTailscaleChild(ctx context.Context, request adapter.RuntimeTailscaleChildRequest, parent *tailscaleRetirementRun) (adapter.RuntimeTailscaleChildRegistration, error) {
	canonical, ok := adapter.RuntimeTailscaleConfiguration(ctx)
	if !ok {
		return nil, errors.New("tailscale child lacks captured whole configuration")
	}
	options, err := parseConfig(ctx, string(canonical))
	if err != nil {
		return nil, err
	}
	var selected option.Endpoint
	found := false
	for _, endpoint := range options.Endpoints {
		if endpoint.Tag != request.Tag {
			continue
		}
		if found || endpoint.Type != C.TypeTailscale {
			return nil, errors.New("tailscale physical child identity is ambiguous")
		}
		settings, ok := endpoint.Options.(*option.TailscaleEndpointOptions)
		if !ok || os.ExpandEnv(settings.StateDirectory) != request.StateDirectory || os.ExpandEnv(settings.TaildropDirectory) != request.TaildropDirectory {
			return nil, errors.New("tailscale physical child paths differ from captured configuration")
		}
		if request.NativeWriter != nil && (settings.SystemInterface || settings.StateDirectory == "" || settings.SSHServer != nil && settings.SSHServer.Enabled ||
			!filepath.IsAbs(request.NativeWriter.State) || !filepath.IsAbs(request.NativeWriter.Taildrop)) {
			return nil, errors.New("invalid native Tailscale writer directories")
		}
		selected = endpoint
		found = true
	}
	if !found {
		return nil, errors.New("tailscale child is absent from captured configuration")
	}
	runOptions := option.Options{Endpoints: []option.Endpoint{selected}}
	var run *tailscaleRetirementRun
	if request.NativeWriter != nil {
		digest, ok := adapter.RuntimeTailscalePlanDigest(ctx)
		if !ok {
			return nil, errors.New("original native Tailscale child lacks the authenticated Plan digest")
		}
		run, err = newTailscaleRetirementRunWithDigest(digest, runOptions)
	} else {
		run, err = newTailscaleRetirementRun(string(canonical), runOptions)
	}
	if err != nil {
		return nil, err
	}
	run.closeFinished = request.CloseDone
	child := &runtimeTailscaleChild{run: run, request: request, options: options, selected: selected}
	startupChild := parent != nil && request.NativeWriter == nil && adapter.RuntimeTailscaleStartupChild(ctx)
	if request.NativeWriter != nil {
		child.native = adapter.RuntimeTailscaleWriterFromContext(s.ctx)
		if child.native == nil {
			return nil, errors.New("original native Tailscale writer admission unavailable")
		}
		child.nativeScope = adapter.RuntimeTailscaleWriterScope{
			ResourceID:  request.ResourceID,
			Generation:  request.Generation,
			Binding:     run.binding,
			Tag:         request.Tag,
			Directories: *request.NativeWriter,
		}
		child.nativeCloseDone = make(chan struct{})
	}
	physicalBase := ctx
	if base, ok := adapter.RuntimeTailscaleChildBase(ctx); ok {
		physicalBase = base
	}
	// Preserve original birth bytes while detaching the physical service context
	// from the first logical graph. ResourceID validation remains in the registrar.
	physicalBase = adapter.ContextWithRuntimeTailscaleConfiguration(physicalBase, canonical)
	child.ctx = service.ContextWithPtr(service.ExtendContext(physicalBase), &run.binding)
	// A native claim needs an original identity and a slot before admission.
	// The row is published once the host could have acquired the claim.
	if child.native != nil {
		child.nativeReservation, err = s.reserveNativeTailscaleRetirementRun(run, parent)
	} else if startupChild && parent.startupReservation != nil {
		child.nativeCloseDone = make(chan struct{})
		err = parent.startupReservation.consume(run)
	} else {
		err = s.appendTailscaleRetirementRun(run)
	}
	if err != nil {
		return nil, err
	}
	if startupChild {
		parent.recordStartupChild(run)
	}
	go child.observeActualClose()
	return child, nil
}

func (c *runtimeTailscaleChild) Context() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx
}

func (c *runtimeTailscaleChild) Prepare(request context.Context) error {
	c.op.Lock()
	defer c.op.Unlock()
	c.mu.Lock()
	if c.entered || c.aborted || c.committed {
		c.mu.Unlock()
		return errors.New("tailscale physical preparation replay")
	}
	c.entered = true
	c.mu.Unlock()
	// Lifecycle sequencing owns this method; cancellation never launches an
	// asynchronous plan Abort that could race its actual constructor binding.
	if c.native != nil {
		c.claimKnown = true // guard the no-callback cancellation path
		if err := request.Err(); err != nil {
			return err
		}
		c.claimKnown = false
		defer func() {
			if !c.claimKnown {
				c.nativeReservation.finish(true)
			}
		}()
		claimed, err := c.native.ClaimRuntimeTailscaleWriter(c.nativeScope)
		if err != nil {
			return err // an uncertain host claim stays with this original child
		}
		c.claimKnown, c.claimed = true, claimed
		if !claimed {
			return errors.New("native Tailscale writer is already owned or unavailable")
		}
		c.nativeReservation.finish(true)
		if err := request.Err(); err != nil {
			return err
		}
		c.directoryEntered = true
	}
	ctx, plan, err := prepareRuntimeChildDirectories(c.ctx, c.options, c.selected)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.ctx, c.plan = ctx, plan
	c.mu.Unlock()
	c.run.access.Lock()
	c.run.directoryAuthority = adapter.TailscaleDirectoryDomainFromContext(ctx)
	c.run.directoryAuthorityBound = true
	c.run.access.Unlock()
	if plan != nil {
		c.run.installPreparedDirectories(plan, adapter.TailscaleDirectoryDomainFromContext(ctx))
		return plan.Acquire(request)
	}
	return request.Err()
}

func (c *runtimeTailscaleChild) Constructed() error {
	c.op.Lock()
	defer c.op.Unlock()
	select {
	case <-c.request.ConstructionDone:
	default:
		return errors.New("tailscale constructor is not terminal")
	}
	if err := c.request.ConstructionResult(); err != nil {
		return err
	}
	c.mu.Lock()
	invalid := !c.entered || c.aborted || c.committed
	c.mu.Unlock()
	if invalid {
		return errors.New("tailscale construction commit replay")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.plan != nil {
		if err := c.run.transferPreparedDirectories(c.plan, c.request.DirectoryScopes); err != nil {
			return err
		}
		if err := c.plan.Validate(c.request.DirectoryScopes()); err != nil {
			return err
		}
		if err := c.plan.Commit(); err != nil {
			return err
		}
	} else {
		c.run.captureDirectories(c.request.DirectoryScopes)
	}
	c.run.capture(c.request.StoreScopes())
	c.mu.Lock()
	c.committed = true
	c.mu.Unlock()
	return nil
}

func (c *runtimeTailscaleChild) Abort() error {
	c.op.Lock()
	defer c.op.Unlock()
	c.mu.Lock()
	if c.committed {
		c.mu.Unlock()
		return nil
	}
	if c.aborted {
		err := c.abortErr
		c.mu.Unlock()
		return err
	}
	select {
	case <-c.request.ConstructionDone:
	default:
		c.mu.Unlock()
		return errors.New("tailscale constructor still owns preparation")
	}
	c.aborted = true
	plan := c.plan
	c.mu.Unlock()
	var err error
	if plan != nil {
		err = plan.Abort()
	}
	c.mu.Lock()
	c.abortErr = err
	c.mu.Unlock()
	return err
}

func (c *runtimeTailscaleChild) observeActualClose() {
	result := errRuntimeTailscaleNativeCloseUnknown
	defer func() {
		if recover() != nil {
			c.run.freeze(nil, false)
			c.run.freezeDirectories(nil, false)
		}
		// A definitive no-acquisition close can omit an unpublished row. Missing
		// preparation or close proof retains it as original unknown evidence.
		c.nativeReservation.finish(result != nil)
		if c.nativeCloseDone != nil {
			c.nativeCloseResult = result
			close(c.nativeCloseDone)
		}
	}()
	<-c.request.CloseDone
	proof := c.originalCloseProof()
	if proof.noAcquisition {
		if proof.claimed && c.native.ReleaseRuntimeTailscaleWriter(c.nativeScope, false) != nil {
			return
		}
		c.run.access.Lock()
		c.run.runtimeNoAcquisition = true
		c.run.originalCloseSucceeded = true
		c.run.final = &tailscaleRetirementInstance{RunNonce: c.run.binding.RunNonce, ConfigDigest: c.run.binding.ConfigDigest, Terminal: "NoStoreConstruction", CensusComplete: true, Nodes: []adapter.TailscaleStoreNode{}}
		c.run.directoryFinal = &tailscaleDirectoryInstance{RunNonce: c.run.binding.RunNonce, ConfigDigest: c.run.binding.ConfigDigest, Terminal: "NoDirectoryConstruction", CensusComplete: true, Nodes: []adapter.TailscaleDirectoryNode{}}
		c.run.access.Unlock()
		result = nil
		return
	}
	// The original child operation lock is released before invoking JNI. Host
	// release may use its ownership lock, never a lock that joins this Close.
	if proof.claimed && proof.writerClosed {
		result = c.native.ReleaseRuntimeTailscaleWriter(c.nativeScope, true)
	} else if c.native == nil && c.nativeCloseDone != nil && proof.writerClosed {
		result = nil // exact typed initial child's observer, with no native callback
	}
}

type runtimeTailscaleCloseProof struct {
	noAcquisition, writerClosed, claimed bool
}

func (c *runtimeTailscaleChild) originalCloseProof() runtimeTailscaleCloseProof {
	c.op.Lock()
	defer c.op.Unlock()
	// CloseDone alone cannot supply a missing constructor terminal observation.
	select {
	case <-c.request.ConstructionDone:
	default:
		return runtimeTailscaleCloseProof{}
	}
	constructionErr, closeErr := c.request.ConstructionResult(), c.request.CloseResult()
	c.mu.Lock()
	entered, committed, abortErr := c.entered, c.committed, c.abortErr
	c.mu.Unlock()
	noAcquisition, marker := constructionErr.(interface{ RuntimeTailscaleNoAcquisition() bool })
	neverEntered := !entered && marker && noAcquisition.RuntimeTailscaleNoAcquisition()
	nativeNeverEntered := c.native != nil && c.claimKnown && !c.directoryEntered && constructionErr != nil
	if (neverEntered || nativeNeverEntered) && closeErr == nil && abortErr == nil {
		if c.native == nil || (len(c.request.StoreScopes()) == 0 && len(c.request.DirectoryScopes()) == 0) {
			return runtimeTailscaleCloseProof{noAcquisition: true, claimed: c.claimed}
		}
	}
	c.run.freeze(c.request.StoreScopes(), committed && constructionErr == nil && closeErr == nil && abortErr == nil)
	c.run.freezeDirectories(c.request.DirectoryScopes(), committed && constructionErr == nil && closeErr == nil && abortErr == nil)
	c.run.access.Lock()
	c.run.originalCloseSucceeded = closeErr == nil && abortErr == nil
	// The original physical Close waits for the actual Store, directory scope,
	// Taildrop and detached stack. The two censuses correlate that result with
	// this child. Android's ordinary directory export still has no managed
	// deletion authority and must not be promoted to SealedDrained here.
	writerClosed := c.run.final.CensusComplete && c.run.directoryFinal.CensusComplete
	c.run.access.Unlock()
	return runtimeTailscaleCloseProof{writerClosed: writerClosed, claimed: c.claimed}
}

func (c *runtimeTailscaleChild) WaitOriginalNativeClose() error {
	return c.waitOriginalNativeClose(runtimeTailscaleNativeCloseTimeout)
}

func (c *runtimeTailscaleChild) WaitOriginalStartupClose() error {
	if c.nativeCloseDone == nil {
		return nil // ordinary untyped children retain their existing close behavior
	}
	return c.waitOriginalNativeClose(runtimeTailscaleNativeCloseTimeout)
}

func (c *runtimeTailscaleChild) waitOriginalNativeClose(timeout time.Duration) error {
	c.nativeCloseWait.Do(func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-c.nativeCloseDone:
			c.nativeCloseWaitResult = c.nativeCloseResult
		case <-timer.C:
			// A later callback still belongs to the original host scope. It
			// cannot turn this already timed-out Close into an acknowledgement.
			c.nativeReservation.finish(true)
			c.nativeCloseWaitResult = errRuntimeTailscaleNativeCloseUnknown
		}
	})
	return c.nativeCloseWaitResult
}
