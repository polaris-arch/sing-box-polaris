package tun

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Serialize setup and teardown: no delayed setup command may run after revert.
// Setup cancellation is independent of the operation lock so Close does not
// wait for the setup deadline before it can cancel an in-flight command.
const resolvedRevertTimeout = time.Second

type resolvedLifecycle struct {
	access    sync.Mutex
	state     sync.Mutex
	closed    bool
	cancel    context.CancelFunc
	attempted bool
}

func (r *resolvedLifecycle) configure(parent context.Context, run func(context.Context, ...string) error, name string, servers []string) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.state.Lock()
	if r.closed {
		r.state.Unlock()
		return fmt.Errorf("resolver configuration already closed")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	r.cancel = cancel
	r.state.Unlock()
	defer func() {
		cancel()
		r.state.Lock()
		r.cancel = nil
		r.state.Unlock()
	}()
	for _, args := range [][]string{
		append([]string{"dns", name}, servers...),
		{"domain", name, "~."},
		{"default-route", name, "true"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.attempted = true
		if err := run(ctx, args...); err != nil {
			return fmt.Errorf("resolvectl %s: %w", args[0], err)
		}
	}
	return nil
}

func (r *resolvedLifecycle) stop() {
	r.state.Lock()
	defer r.state.Unlock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *resolvedLifecycle) close(run func(context.Context, ...string) error, name string) error {
	r.stop()
	r.access.Lock()
	defer r.access.Unlock()
	if !r.attempted {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolvedRevertTimeout)
	defer cancel()
	if err := run(ctx, "revert", name); err != nil {
		return fmt.Errorf("resolvectl revert: %w", err)
	}
	r.attempted = false
	return nil
}

func resolvedCommand(path string) func(context.Context, ...string) error {
	return func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, path, args...).Run()
	}
}
