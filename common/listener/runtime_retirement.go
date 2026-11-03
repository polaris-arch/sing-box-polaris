package listener

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ListenerRetirement is a preallocated receipt for physical ingress retirement
// after irreversible publication. It does not use the finished transaction's
// begin/compensation path and never closes an accepted TCP carrier.
type ListenerRetirement struct {
	previous  []*Listener
	committed atomic.Bool
	ready     atomic.Bool
	once      sync.Once
	done      chan struct{}
	err       error
}

func newListenerRetirement(previous []*Listener, held map[*Listener]bool) *ListenerRetirement {
	r := &ListenerRetirement{previous: make([]*Listener, 0, len(previous)), done: make(chan struct{})}
	for _, old := range previous {
		if held[old] {
			r.previous = append(r.previous, old)
		}
	}
	return r
}

func (t *ListenerSetTransaction) Retirement() *ListenerRetirement {
	if t == nil {
		return nil
	}
	return t.retirement
}

// RetirePrevious is called after Finish and outside all graph, selector,
// control-effects and reference pause fences. Only old residual ingress remains:
// Stage has moved transfers out and released ordinary UDP under its policy.
func (r *ListenerRetirement) RetirePrevious() error {
	if r == nil {
		return nil
	}
	if !r.committed.Load() || !r.ready.Load() {
		return ErrRuntimeTransition
	}
	r.once.Do(func() {
		defer close(r.done)
		for _, old := range r.previous {
			// The original listener's closeDone/closeErr is the shared Scope barrier.
			// Recover each call independently so one failure cannot abandon siblings.
			err := retireRuntimeListener(old)
			if r.err == nil {
				r.err = err
			} else if err != nil {
				r.err = errors.Join(r.err, err)
			}
		}
	})
	<-r.done
	return r.err
}

func retireRuntimeListener(old *Listener) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime listener retirement panicked; completion unknown")
		}
	}()
	return old.RuntimeCloseAndWait()
}
