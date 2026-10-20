package lifecycle

import (
	"context"
	"sync"
	"time"
)

// CoalescedRefresh owns at most one worker and one pending latest-state request.
// update reads current desired configuration only after ready proves that the
// previous socket cohort actually retired. No event captures an obsolete list.
// Work and ctx must be component-owned producer lifetime, not a graph self-lease.
type CoalescedRefresh struct {
	access sync.Mutex
	running bool
	pending bool
}

func (r *CoalescedRefresh) Request(work *Work, ctx context.Context, delay time.Duration, ready func(context.Context) error, update func(context.Context) bool) bool {
	r.access.Lock()
	if ctx.Err() != nil || work.Sealed() { r.access.Unlock(); return false }
	r.pending = true
	if r.running { r.access.Unlock(); return true }
	done, ok := work.Reserve()
	if !ok { r.pending = false; r.access.Unlock(); return false }
	r.running = true
	r.access.Unlock()
	go func() {
		defer done()
		for {
			r.access.Lock()
			if !r.pending || ctx.Err() != nil {
				r.pending = false; r.running = false; r.access.Unlock(); return
			}
			r.access.Unlock()
			if delay > 0 {
				timer := time.NewTimer(delay)
				select { case <-ctx.Done(): if !timer.Stop() { select { case <-timer.C: default: } }; case <-timer.C: }
			}
			if err := ready(ctx); err != nil {
				r.access.Lock(); r.pending = false; r.running = false; r.access.Unlock(); return
			}
			// Events before this point are folded into the current-state read;
			// an event arriving during update requests precisely one more pass.
			r.access.Lock(); r.pending = false; r.access.Unlock()
			retry := update(ctx)
			if retry { r.access.Lock(); r.pending = true; r.access.Unlock() }
		}
	}()
	return true
}
