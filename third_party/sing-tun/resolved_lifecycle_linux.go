package tun

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Serialize setup and teardown: no delayed setup command may run after revert.
// Commands share a deadline, so a stuck resolver cannot retain a shutdown forever.
type resolvedLifecycle struct {
	access    sync.Mutex
	closed    bool
	attempted bool
}

func (r *resolvedLifecycle) configure(run func(context.Context, ...string) error, name string, servers []string) error {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return fmt.Errorf("resolver configuration already closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, args := range [][]string{
		append([]string{"dns", name}, servers...),
		{"domain", name, "~."},
		{"default-route", name, "true"},
	} {
		r.attempted = true
		if err := run(ctx, args...); err != nil {
			return fmt.Errorf("resolvectl %s: %w", args[0], err)
		}
	}
	return nil
}

func (r *resolvedLifecycle) close(run func(context.Context, ...string) error, name string) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.closed = true
	if !r.attempted {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
