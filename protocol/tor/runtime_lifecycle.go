package tor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"

	"github.com/cretz/bine/process"
)

func (t *Outbound) initRuntime(ctx context.Context) error {
	t.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	t.runtimeWork = outbound.NewRuntimeIOFence(nil)
	admit, err := outbound.RegisterRuntimeOwnedFence(ctx, t.runtimeWork)
	if err != nil {
		return err
	}
	t.admitRuntime = admit
	ctx = adapter.ContextWithRuntimeOwnership(ctx, context.Background())
	ctx, cancel := context.WithCancel(ctx)
	t.ctx = ctx
	creator := t.startConf.ProcessCreator
	if creator == nil {
		executable := t.startConf.ExePath
		if executable == "" {
			executable = "tor"
		}
		creator = process.NewCreator(executable)
	}
	t.processOwner = &runtimeProcessCreator{creator: creator}
	t.startConf.ProcessCreator = t.processOwner
	t.runtimeStarts = outbound.NewRuntimeIOFence(func() error { cancel(); return nil })
	t.runtimeCleanup = outbound.OnceRuntimeCleanup(func() error {
		// Cancel the process/start operation first. The admitted Start keeps
		// resource publication alive until it has actually returned.
		if err := t.runtimeStarts.RuntimeCloseAndWait(); err != nil {
			return err
		}
		var result []error
		_ = t.runtimeWork.Close()
		if t.proxy != nil {
			result = append(result, t.proxy.RuntimeCloseAndWait())
		}
		result = append(result, t.runtimeWork.Wait())
		processErr := t.processOwner.closeAndWait()
		result = append(result, processErr)
		if t.torInstance != nil && t.torInstance.Control != nil {
			// The process has exited; this only closes the controller socket.
			// Never call bine Tor.Close: its 300ms observer is not completion.
			if err := t.torInstance.Control.Close(); err != nil {
				result = append(result, fmt.Errorf("tor control close incomplete: %v", err))
			}
		}
		// We never call bine HandleEvents/EventWait. All event sends occur
		// within the Start/control methods joined above, so closing is safe.
		if t.eventsDone != nil {
			close(t.events)
			<-t.eventsDone
		}
		if processErr == nil && t.torInstance != nil && t.startConf.DataDir == "" && t.torInstance.DataDir != "" {
			result = append(result, os.RemoveAll(t.torInstance.DataDir))
		}
		return errors.Join(result...)
	})
	return nil
}

// Bine v0.2.0 tor/tor.go starts an unjoined Wait and clears Process after a
// 300ms observation. This local decorator owns the actual Wait exactly once,
// retaining the process even if the upstream error path clears its pointer.
// RetainTempDataDir prevents that upstream error path deleting live files.
type runtimeProcessCreator struct {
	creator   process.Creator
	mu        sync.Mutex
	processes []*runtimeProcess
}

func (c *runtimeProcessCreator) New(ctx context.Context, args ...string) (process.Process, error) {
	ctx, cancel := context.WithCancel(ctx)
	inner, err := c.creator.New(ctx, args...)
	if err != nil {
		cancel()
		return nil, err
	}
	owned := &runtimeProcess{inner: inner, cancel: cancel, done: make(chan struct{})}
	c.mu.Lock()
	c.processes = append(c.processes, owned)
	c.mu.Unlock()
	return owned, nil
}

func (c *runtimeProcessCreator) closeAndWait() error {
	c.mu.Lock()
	processes := append([]*runtimeProcess(nil), c.processes...)
	c.mu.Unlock()
	for _, owned := range processes {
		owned.cancel()
	}
	var result []error
	for _, owned := range processes {
		if owned.started {
			<-owned.done
			result = append(result, owned.uncertainty)
		}
	}
	return errors.Join(result...)
}

type runtimeProcess struct {
	inner       process.Process
	cancel      context.CancelFunc
	started     bool
	done        chan struct{}
	waitErr     error
	uncertainty error
}

func (p *runtimeProcess) Start() error {
	if err := p.inner.Start(); err != nil {
		return err
	}
	p.started = true
	go func() {
		defer close(p.done)
		defer func() {
			if recover() != nil {
				p.uncertainty = errors.New("tor process Wait panicked; completion unknown")
			}
		}()
		p.waitErr = p.inner.Wait()
	}()
	return nil
}
func (p *runtimeProcess) Wait() error { <-p.done; return errors.Join(p.waitErr, p.uncertainty) }
func (p *runtimeProcess) EmbeddedControlConn() (net.Conn, error) {
	return p.inner.EmbeddedControlConn()
}
