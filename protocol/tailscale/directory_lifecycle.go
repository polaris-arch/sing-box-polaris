//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/client/local"
	"github.com/sagernet/tailscale/util/dirscope"
)

type directoryOwner struct {
	scope         *dirscope.Scope
	domain        *adapter.TailscaleDirectoryDomain
	admitted      bool
	managedPaths  bool
	mu            sync.Mutex
	node          adapter.TailscaleDirectoryNode
	lease         *directoryLease
	leaseOnce     sync.Once
	leaseErr      error
	serverStarted bool
	retireOnce    sync.Once
	retired       chan struct{}
	terminal      adapter.TailscaleDirectoryNode
}

func newDirectoryOwner(ctx context.Context, tag, directory string) *directoryOwner {
	node := adapter.TailscaleDirectoryNode{
		Tag: tag, StateDirectory: directory,
		WriterState: "Unknown", CensusVersion: 1,
	}
	if binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx); binding != nil {
		node.RunNonce, node.ConfigDigest = binding.RunNonce, binding.ConfigDigest
	}
	return &directoryOwner{scope: new(dirscope.Scope), domain: adapter.TailscaleDirectoryDomainFromContext(ctx), managedPaths: adapter.TailscaleDirectoryMappingFromContext(ctx) != nil, node: node, retired: make(chan struct{})}
}

// Caller holds a scope token through lease acquisition and its entire Start
// stage, so retiring cannot miss a lease published by a concurrent Start.
func (d *directoryOwner) acquire() error {
	d.leaseOnce.Do(func() {
		// Generic constructors retain their original filesystem behavior and never
		// enter the App managed protocol or issue directory retirement evidence.
		if !d.managedPaths {
			d.mu.Lock()
			d.admitted = true
			d.mu.Unlock()
			return
		}
		lease, err := acquireDirectoryLease(d.node.StateDirectory)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.lease, d.leaseErr = lease, err
		d.admitted = err == nil
		if err != nil {
			d.scope.Fail(err)
			return
		}
		d.node.DirectoryIdentity, d.node.Incarnation, d.node.DirectoryEpoch = lease.Identity, lease.Incarnation, lease.Epoch
	})
	return d.leaseErr
}

func (d *directoryOwner) ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.admitted && d.leaseErr == nil
}

func (t *Endpoint) WithDirectoryAccess(fn func() error) error {
	release, err := t.directory.scope.Begin()
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// NewLocalClient never exposes the mutable Server or its shared LocalClient.
// Dial admission is defense in depth; persistent HTTP connection operations
// are independently protected by the SDK's filesystem-leaf capabilities.
func (t *Endpoint) NewLocalClient() (*local.Client, error) {
	var result *local.Client
	err := t.WithDirectoryAccess(func() error {
		t.directoryStartMu.Lock()
		defer t.directoryStartMu.Unlock()
		if err := t.directory.acquire(); err != nil {
			return err
		}
		original, err := t.server.LocalClient()
		if err != nil {
			t.directory.scope.Fail(err)
			return err
		}
		t.directory.mu.Lock()
		t.directory.serverStarted = true
		t.directory.mu.Unlock()
		result = &local.Client{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			release, err := t.directory.scope.Begin()
			if err != nil {
				return nil, err
			}
			defer release()
			return original.Dial(ctx, network, address)
		}}
		return nil
	})
	return result, err
}

func (t *Endpoint) TailscaleDirectoryScope() adapter.TailscaleDirectoryNode {
	d := t.directory
	d.mu.Lock()
	defer d.mu.Unlock()
	result := d.node
	select {
	case <-d.retired:
		result = d.terminal
	default:
	}
	if d.domain == nil || !d.domain.Active() {
		result.WriterState = "Unknown"
		if result.Failure == "" {
			result.Failure = "directory has no active native-managed domain"
		}
	}
	return result
}

// beginDirectoryRetirement seals before shutdown and uses one original worker.
// It must never block the caller on IO or a callback which invoked Close itself.
func (t *Endpoint) SealTailscaleDirectory() {
	t.directory.scope.Seal()
	t.taildrop.seal()
}

func (t *Endpoint) beginDirectoryRetirement() {
	d := t.directory
	d.retireOnce.Do(func() {
		d.scope.Seal()
		t.taildrop.seal()
		go func() {
			// Existing Start calls can finish after the seal. They hold a scope
			// token; serialize with their publication before deciding Close.
			t.directoryStartMu.Lock()
			d.mu.Lock()
			started := d.serverStarted
			d.mu.Unlock()
			t.directoryStartMu.Unlock()
			var closeErr error
			if started {
				closeErr = t.server.Close()
			}
			if closeErr != nil {
				d.scope.Fail(closeErr)
			}
			// These channels are actual completion, never caller deadlines.
			<-t.taildrop.drainDone
			if err := t.taildrop.waitContext(context.Background()); err != nil {
				d.scope.Fail(err)
			}
			<-d.scope.Done()
			d.mu.Lock()
			lease := d.lease
			d.mu.Unlock()
			if lease != nil {
				failure := d.scope.Wait(context.Background())
				d.mu.Lock()
				if d.node.Failure != "" {
					failure = errors.Join(failure, errors.New(d.node.Failure))
				}
				d.mu.Unlock()
				if err := prepareDirectoryLeaseClose(lease, failure); err != nil {
					// Failed durable revocation retains the original handles. A
					// timeout or Close error cannot create retirement authority.
					d.scope.Fail(err)
				} else if err := lease.Close(); err != nil {
					d.scope.Fail(err)
				}
			}
			result := t.TailscaleDirectoryScope()
			if err := d.scope.Wait(context.Background()); err != nil {
				result.Failure = err.Error()
			} else if result.Failure != "" {
				// Unsupported filesystem capabilities remain Unknown without
				// turning an otherwise successful ordinary Close into an error.
			} else if d.domain == nil || !d.domain.Active() {
				result.Failure = "directory has no active native-managed domain"
			} else if lease == nil || !lease.Managed || result.DirectoryIdentity == "" || result.Incarnation == "" || result.DirectoryEpoch == "" {
				result.Failure = "directory is not bound to a managed incarnation"
			} else {
				result.WriterState = "SealedDrained"
			}
			d.mu.Lock()
			if err := d.scope.Wait(context.Background()); err != nil {
				result.WriterState = "Unknown"
				result.Failure = err.Error()
			}
			d.terminal = result
			close(d.retired)
			d.mu.Unlock()
		}()
	})
}

func (t *Endpoint) RetireTailscaleDirectory(deadline time.Time) adapter.TailscaleDirectoryNode {
	t.beginDirectoryRetirement()
	d := t.directory
	select {
	case <-d.retired:
		return t.TailscaleDirectoryScope()
	default:
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-d.retired:
		return t.TailscaleDirectoryScope()
	case <-timer.C:
		d.scope.Fail(errors.New("original directory owner did not retire before deadline"))
		d.mu.Lock()
		defer d.mu.Unlock()
		result := d.node
		select {
		case <-d.retired:
			result = d.terminal
			// A deadline observation cannot later be erased by the completed
			// worker having raced this branch.
			d.terminal.WriterState = "Unknown"
			d.terminal.Failure = "directory retirement deadline; original owner retained"
		default:
		}
		result.WriterState = "Unknown"
		result.Failure = "directory retirement deadline; original owner retained"
		return result
	}
}

func (t *Endpoint) closeDirectory() error {
	node := t.RetireTailscaleDirectory(time.Now().Add(5 * time.Second))
	if node.WriterState == "SealedDrained" {
		return nil
	}
	select {
	case <-t.directory.retired:
		// Legacy/no-construction remains Unknown for deletion but successful
		// real IO drain is not an ordinary Close failure.
		return t.directory.scope.Wait(context.Background())
	default:
		return fmt.Errorf("directory retirement unknown: %s", node.Failure)
	}
}

func (t *Endpoint) closeDirectoryAndStore() error {
	storeErr := t.retireStateStore()
	directoryErr := t.closeDirectory()
	return errors.Join(storeErr, directoryErr)
}
