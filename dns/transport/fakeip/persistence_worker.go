package fakeip

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

type persistenceJob struct {
	fn func() error
	result chan error
	started bool
	canceled bool
}
// One worker serializes durability work. Canceled, not-yet-started observations
// are removed rather than leaving one waiting goroutine per timed-out query.
// A started storage operation is never declared completed by caller cancellation.
type persistenceExecutor struct {
	access sync.Mutex
	queue []*persistenceJob
	wake chan struct{}
	done chan struct{}
	closed bool
}
func (e *persistenceExecutor) submit(fn func() error) (*persistenceJob, func() bool) {
	e.access.Lock()
	if e.wake == nil { e.wake = make(chan struct{}, 1); e.done = make(chan struct{}); go e.run() }
	job := &persistenceJob{fn: fn, result: make(chan error, 1)}
	e.queue = append(e.queue, job)
	select { case e.wake <- struct{}{}: default: }
	e.access.Unlock()
	return job, func() bool {
		e.access.Lock(); defer e.access.Unlock()
		if job.started { return false }
		job.canceled = true
		for index, queued := range e.queue { if queued == job { copy(e.queue[index:], e.queue[index+1:]); e.queue[len(e.queue)-1] = nil; e.queue = e.queue[:len(e.queue)-1]; break } }
		return true
	}
}
func (e *persistenceExecutor) run() {
	defer close(e.done)
	for {
		<-e.wake
		for {
			e.access.Lock()
			if len(e.queue) == 0 { closed := e.closed; e.access.Unlock(); if closed { return }; break }
			job := e.queue[0]; e.queue[0] = nil; e.queue = e.queue[1:]; job.started = true
			e.access.Unlock()
			if job.canceled { job.result <- context.Canceled } else { job.result <- lifecycle.CleanupResult("fake-IP persistence worker", job.fn) }
		}
	}
}
func (e *persistenceExecutor) close() {
	e.access.Lock(); e.closed = true
	if e.wake == nil { e.access.Unlock(); return }
	select { case e.wake <- struct{}{}: default: }
	done := e.done; e.access.Unlock(); <-done
}
