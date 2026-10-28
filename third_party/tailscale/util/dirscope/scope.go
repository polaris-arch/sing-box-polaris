// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package dirscope seals and drains filesystem access for one immutable owner.
// It does not claim that control-plane goroutines have stopped. A late callback
// must acquire an operation token before accessing any file in the owner's
// directory. The caller separately owns the cross-process directory lease.
package dirscope

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrSealed = errors.New("directory access sealed")
	ErrIncomplete = errors.New("directory retirement incomplete")
)

// Scope is an instance capability, never a global path registry. Its zero value
// is usable. A nil Scope preserves legacy behavior but cannot be retirement
// evidence. Owners must bind it before constructing any filesystem resource.
type Scope struct {
	mu sync.Mutex
	sealed bool
	active uint64
	done chan struct{}
	failure error
}

// Begin admits one synchronous operation or one retained filesystem handle.
// The returned release must run only after all filesystem activity/Close ends.
// It is idempotent so cancellation and normal completion can share ownership.
func (s *Scope) Begin() (release func(), err error) {
	if s == nil {
		return func() {}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return nil, ErrSealed
	}
	if s.done == nil {
		s.done = make(chan struct{})
	}
	s.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.active--
			if s.sealed && s.active == 0 {
				close(s.done)
			}
		})
	}, nil
}

// Seal permanently closes admission. It never waits for callbacks or IO.
func (s *Scope) Seal() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return
	}
	s.sealed = true
	if s.done == nil {
		s.done = make(chan struct{})
	}
	if s.active == 0 {
		close(s.done)
	}
}

// Fail records a permanent uncertainty without reopening admission.
func (s *Scope) Fail(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure == nil {
		s.failure = fmt.Errorf("%w: %v", ErrIncomplete, err)
	}
}

// Wait bounds only this observation. Deadline/cancellation is sticky failure,
// not permission to delete. Errors deliberately do not unwrap ctx.Err(): generic
// cleanup cancellation filters must not erase incomplete directory retirement.
func (s *Scope) Wait(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("%w: missing scope", ErrIncomplete)
	}
	s.mu.Lock()
	if !s.sealed {
		s.mu.Unlock()
		return fmt.Errorf("%w: admission remains open", ErrIncomplete)
	}
	done, failure := s.done, s.failure
	s.mu.Unlock()
	if failure != nil {
		return failure
	}
	select {
	case <-done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.failure
	case <-ctx.Done():
		s.Fail(ctx.Err())
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.failure
	}
}

// Done is the original actual-IO completion channel, independent of sticky
// observer failure. It closes only after Seal and every admitted release.
// It is not, by itself, a directory receipt or a successful Wait result.
func (s *Scope) Done() <-chan struct{} {
	if s == nil { return nil }
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil { s.done = make(chan struct{}) }
	return s.done
}
