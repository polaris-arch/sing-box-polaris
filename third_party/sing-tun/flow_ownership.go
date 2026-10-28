package tun

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var errFlowOwnershipClosed = errors.New("flow ownership closed")
var errAttachmentPanic = errors.New("return-path acquisition panicked; ownership quarantined")

func retainFlow(owner FlowOwnership) (FlowOwnership, error) {
	if owner == nil {
		return nil, nil
	}
	return owner.Retain()
}

func releaseFlow(owner FlowOwnership) {
	if owner != nil {
		owner.Release()
	}
}

// flowOwnershipSlot serializes a structural handle's release against callers
// taking a continuation. It does not count references: the adapter owns those.
type flowOwnershipSlot struct {
	access sync.Mutex
	owner FlowOwnership
	closed bool
}

func (s *flowOwnershipSlot) retain() (FlowOwnership, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil, errFlowOwnershipClosed
	}
	return retainFlow(s.owner)
}

func (s *flowOwnershipSlot) release() {
	s.access.Lock()
	owner := s.owner
	s.owner = nil
	s.closed = true
	s.access.Unlock()
	releaseFlow(owner)
}

func bindFlow(ctx context.Context, owner FlowOwnership) context.Context {
	if owner != nil {
		return owner.BindContext(ctx)
	}
	return ctx
}

// sealedReturn is a callback admission gate, not another resource counter. Each
// invocation forks the existing resource owner while holding the gate read lock.
// Seal rejects even callbacks copied by a Port before DetachReturn. The write
// lock is acquired only by the detached completion worker, never by a callback.
type sealedReturn struct {
	access sync.RWMutex
	sealed atomic.Bool
	owner PortOwnership
	target Return
}

func (g *sealedReturn) enter() (PortOwnership, bool) {
	g.access.RLock()
	if g.sealed.Load() {
		g.access.RUnlock()
		return nil, false
	}
	if g.owner == nil {
		return nil, true
	}
	owner, err := g.owner.Retain()
	if err != nil {
		g.access.RUnlock()
		return nil, false
	}
	return owner, true
}

func (g *sealedReturn) leave(owner PortOwnership) {
	if owner != nil {
		owner.Release()
	}
	g.access.RUnlock()
}

func (g *sealedReturn) ReturnHeadroom() int {
	owner, ok := g.enter()
	if !ok {
		return 0
	}
	defer g.leave(owner)
	return g.target.ReturnHeadroom()
}

func (g *sealedReturn) ReturnPackets(packets [][]byte) [][]byte {
	owner, ok := g.enter()
	if !ok {
		return packets
	}
	defer g.leave(owner)
	return g.target.ReturnPackets(packets)
}

func (g *sealedReturn) seal() { g.sealed.Store(true) }

func (g *sealedReturn) join() {
	g.access.Lock()
	g.access.Unlock()
}

// attachmentUse reserves existing attachment storage and an actual Port lease.
// uses is only a quiescence census under portsAccess, never a lifetime authority.
type attachmentUse struct {
	returnPath *portReturn
	owner PortOwnership
	once sync.Once
}

func (u *attachmentUse) release() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		r := u.returnPath
		d := r.dispatcher
		d.portsAccess.Lock()
		r.uses--
		d.portsAccess.Unlock()
		if u.owner != nil {
			u.owner.Release()
		}
		d.detachIdle(r)
	})
}

func (r *portReturn) retainUse() (*attachmentUse, error) {
	d := r.dispatcher
	d.portsAccess.Lock()
	defer d.portsAccess.Unlock()
	if r.detaching || d.closed.Load() {
		return nil, errFlowOwnershipClosed
	}
	var owner PortOwnership
	if r.ownership != nil {
		var err error
		owner, err = r.ownership.Retain()
		if err != nil {
			return nil, err
		}
	}
	r.uses++
	return &attachmentUse{returnPath: r, owner: owner}, nil
}

func (d *ForwardDispatcher) detachIdle(r *portReturn) {
	d.portsAccess.Lock()
	retiring := d.closed.Load() || r.failed
	if !retiring && r.ownership != nil {
		select {
		case <-r.ownership.Retiring():
			retiring = true
		default:
		}
	}
	if !retiring || r.detaching || !r.attached || r.uses != 0 {
		d.portsAccess.Unlock()
		return
	}
	r.detaching = true
	r.gate.seal()
	d.portsAccess.Unlock()
	go func() {
		var cleanupErr error
		defer func() {
			if recover() != nil { cleanupErr = errors.Join(cleanupErr, errors.New("return-path cleanup panicked; ownership quarantined")) }
			// Keep this entry visible until the entire cleanup tail has returned.
			// A waiter either snapshots this completion or observes its already
			// completed removal. Errors retain the entry as sticky evidence.
			d.portsAccess.Lock()
			r.detachErr = cleanupErr
			if cleanupErr == nil { close(r.detached) }
			close(r.completion)
			if cleanupErr == nil && d.ports[r.port] == r { delete(d.ports, r.port) }
			d.portsAccess.Unlock()
		}()
		// Neither port methods nor callback joins run under storage locks.
		// Catch native detach panic independently so sealed callback and fragment
		// workers still drain; retain the actual attachment lease on uncertainty.
		func() {
			defer func() { if recover() != nil { cleanupErr = errors.New("return-path detach panicked; ownership quarantined") } }()
			cleanupErr = r.port.DetachReturn(&r.gate)
		}()
		r.gate.join()
		close(r.fragmentStop)
		<-r.fragmentDone
		if cleanupErr != nil { return }
		releasePortNAT(r.nat)
		if r.ownership != nil { r.ownership.Release() }
	}()
}

type forwardUse struct {
	flow *forwardFlow
	ownership FlowOwnership
	attachment *attachmentUse
}

// Caller holds the map lock publishing flow, or an existing forwardUse. The
// source structural handle may not be loaded and then retained after unlocking.
func retainForward(flow *forwardFlow) (*forwardUse, error) {
	owner, err := retainFlow(flow.ownership)
	if err != nil { return nil, err }
	var attachment *attachmentUse
	if flow.attachment != nil {
		attachment, err = flow.attachment.returnPath.retainUse()
		if err != nil { releaseFlow(owner); return nil, err }
	}
	return &forwardUse{flow: flow, ownership: owner, attachment: attachment}, nil
}

func (u *forwardUse) release() {
	if u == nil { return }
	releaseFlow(u.ownership)
	u.attachment.release()
}

func (u *forwardUse) retain() (*forwardUse, error) {
	owner, err := retainFlow(u.ownership)
	if err != nil { return nil, err }
	var attachment *attachmentUse
	if u.attachment != nil {
		attachment, err = u.attachment.returnPath.retainUse()
		if err != nil { releaseFlow(owner); return nil, err }
	}
	return &forwardUse{flow: u.flow, ownership: owner, attachment: attachment}, nil
}

// WaitDetached observes actual attachment cleanup after Close. It is separate
// from the nonjoining Close request so a return callback can request shutdown
// without synchronously joining itself. A failed detach is sticky and retains
// its resource reservation; a canceled waiter does not abandon cleanup.
func (d *ForwardDispatcher) WaitDetached(ctx context.Context) error {
	if d == nil { return nil }
	if !d.closed.Load() { return errors.New("dispatcher admission is not sealed") }
	d.portsAccess.Lock()
	paths := make([]*portReturn, 0, len(d.ports))
	for _, path := range d.ports { paths = append(paths, path) }
	d.portsAccess.Unlock()
	var result error
	for _, path := range paths {
		select { case <-path.ready: case <-ctx.Done(): return ctx.Err() }
		if !path.attached && !path.failed { continue }
		select { case <-path.completion: case <-ctx.Done(): return ctx.Err() }
		result = errors.Join(result, path.detachErr)
	}
	return result
}

func (s *flowOwnershipSlot) present() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.owner != nil || s.closed
}
