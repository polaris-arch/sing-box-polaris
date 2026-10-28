package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	outbound "github.com/sagernet/sing-box/adapter/outbound"
)

// connectionFlow is control-plane bookkeeping for the actual logical pair.
// It is deliberately not an I/O wrapper and never unwraps an ownership fence.
// All fields except immutable manager/cancel are guarded by manager.access.
type connectionFlow struct {
	manager *ConnectionManager
	cancel  context.CancelFunc
	refs    int
	closers [2]finalConnectionCloser
}
type connectionFlowContextKey struct{}

func (m *ConnectionManager) taskDoneLocked(flow *connectionFlow) func() {
	m.tasks.Add(1)
	m.diagnosticTasks.Add(1)
	if flow != nil {
		flow.refs++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			var cancel context.CancelFunc
			if flow != nil {
				m.access.Lock()
				flow.refs--
				if flow.refs == 0 {
					delete(m.flows, flow)
					cancel = flow.cancel
				}
				m.access.Unlock()
			}
			if cancel != nil {
				cancel()
			}
			m.diagnosticTasks.Add(^uint64(0))
			m.tasks.Done()
		})
	}
}

func (m *ConnectionManager) reserveFlow(ctx context.Context, local io.Closer) (context.Context, *connectionFlow, func(), error) {
	ctx = outbound.ContextWithRuntimeInboundClose(ctx, local)
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return ctx, nil, nil, net.ErrClosed
	}
	child, cancel := context.WithCancel(ctx)
	localClose := newFinalConnectionCloser(local)
	if wait, known := outbound.RuntimeInboundCloseFromContext(ctx); known {
		localClose.wait = wait
	}
	flow := &connectionFlow{manager: m, cancel: cancel, closers: [2]finalConnectionCloser{localClose, {}}}
	if m.flows == nil {
		m.flows = make(map[*connectionFlow]struct{})
	}
	m.flows[flow] = struct{}{}
	done := m.taskDoneLocked(flow)
	m.access.Unlock()
	return context.WithValue(child, connectionFlowContextKey{}, flow), flow, done, nil
}

func (m *ConnectionManager) reserveFlowTask(ctx context.Context) (func(), error) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	flow, _ := ctx.Value(connectionFlowContextKey{}).(*connectionFlow)
	if flow != nil {
		if _, live := m.flows[flow]; flow.manager != m || !live || flow.refs <= 0 {
			return nil, net.ErrClosed
		}
	}
	return m.taskDoneLocked(flow), nil
}

// replace publishes the actual outer object, including wrapper-owned cleanup.
// Setup still owns a counted task here. Thus a late dial/wrapper arriving after
// seal can be closed and joined without an Add-after-zero/Wait race.
func (f *connectionFlow) replace(slot int, closer io.Closer) bool {
	return f.publish(slot, closer, false)
}

// wrap is called only immediately after route itself constructs a wrapper over
// this slot. Keep the exact private base completion without unwrapping anything.
func (f *connectionFlow) wrap(slot int, closer io.Closer) bool {
	return f.publish(slot, closer, true)
}

func (f *connectionFlow) publish(slot int, closer io.Closer, wrapped bool) bool {
	m := f.manager
	m.access.Lock()
	target := newFinalConnectionCloser(closer)
	if wrapped && target.wait == nil {
		target.wait = f.closers[slot].wait
	}
	_, live := m.flows[f]
	if !live || f.refs <= 0 {
		m.closeErr = errors.Join(m.closeErr, errors.New("final logical connection attachment after setup retired"))
		m.access.Unlock()
		if err := closeFinalConnection(target); err != nil {
			m.access.Lock()
			m.closeErr = errors.Join(m.closeErr, err)
			m.access.Unlock()
		}
		return false
	}
	if m.closed {
		done := m.taskDoneLocked(nil)
		m.access.Unlock()
		m.launchFinalClose(target, done)
		return false
	}
	f.closers[slot] = target
	m.access.Unlock()
	return true
}

// StopFinal is only the Box's final shutdown, NOT ResetNetwork or HOT retirement.
// Seal registration/task admission and reserve all close workers under the same
// lock; invoke cancellation and Close only outside it. One stuck side must not
// prevent the other side from receiving its close request. Actual completion is
// still joined by the existing manager tasks and resource-owner lease barriers.
func (m *ConnectionManager) StopFinal() {
	m.finalOnce.Do(func() {
		type request struct {
			closer finalConnectionCloser
			done   func()
		}
		var requests []request
		var cancels []context.CancelFunc
		m.access.Lock()
		m.closed = true
		for flow := range m.flows {
			cancels = append(cancels, flow.cancel)
			for _, closer := range flow.closers {
				if closer.closer != nil {
					requests = append(requests, request{closer, m.taskDoneLocked(nil)})
				}
			}
		}
		for e := m.connections.Front(); e != nil; {
			next := e.Next()
			requests = append(requests, request{newFinalConnectionCloser(e.Value), m.taskDoneLocked(nil)})
			m.connections.Remove(e)
			e = next
		}
		m.access.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		for _, request := range requests {
			m.launchFinalClose(request.closer, request.done)
		}
	})
}

func (m *ConnectionManager) launchFinalClose(closer finalConnectionCloser, done func()) {
	go func() {
		defer done()
		if err := closeFinalConnection(closer); err != nil {
			m.access.Lock()
			m.closeErr = errors.Join(m.closeErr, err)
			m.access.Unlock()
		}
	}()
}

type finalConnectionCloser struct {
	closer io.Closer
	wait   func() error
}

func newFinalConnectionCloser(closer io.Closer) finalConnectionCloser {
	wait, _ := outbound.RuntimeConnectionCloseWaiter(closer)
	return finalConnectionCloser{closer, wait}
}

func closeFinalConnection(target finalConnectionCloser) (err error) {
	var completed chan error
	if target.wait != nil {
		completed = make(chan error, 1)
		// An outer protocol Close can wait for native reads to stop. Request
		// the captured private close concurrently, then join BOTH paths. The
		// parent worker remains counted even if either one blocks indefinitely.
		go func() { completed <- waitFinalConnection(target.wait) }()
	}
	defer func() {
		if recover() != nil {
			err = errors.New("final logical connection close panicked; completion unknown")
		}
		if completed != nil {
			waitErr := <-completed
			if err == outbound.ErrRuntimeClosePending {
				err = nil
			}
			err = errors.Join(err, waitErr)
		}
		if err != nil {
			err = fmt.Errorf("final logical connection close incomplete: %v", err)
		}
	}()
	err = target.closer.Close()
	// Only this exact standard TCP type has a known repeated-close result.
	// Custom, wrapped and joined errors are never normalized by this rule.
	if _, knownTCP := target.closer.(*net.TCPConn); knownTCP && errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

func waitFinalConnection(wait func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("final private connection close wait panicked; completion unknown")
		}
	}()
	return wait()
}
