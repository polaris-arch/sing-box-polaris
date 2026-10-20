//go:build windows && with_tailscale

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type preparedDirectoryPlatform struct {
	acquisitionStarted bool
}

// NewPreparedDirectoryLeases is allocation-only. The original run must retain
// Snapshot before Acquire, including when a later acquisition fails.
func NewPreparedDirectoryLeases(ctx context.Context, options option.Options) (*PreparedDirectoryLeases, error) {
	if adapter.TailscaleDirectoryMappingFromContext(ctx) == nil || !adapter.TailscaleDirectoryDomainFromContext(ctx).Active() {
		return nil, errors.New("prepared directory activation missing")
	}
	p := &PreparedDirectoryLeases{}
	p.ctx = context.WithValue(ctx, preparedDirectoryKey{}, p)
	seen := make(map[string]bool)
	for index, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		tag := endpoint.Tag
		if tag == "" {
			tag = strconv.Itoa(index)
		}
		if seen[tag] {
			return nil, errors.New("duplicate prepared directory tag")
		}
		seen[tag] = true
		var ts *option.TailscaleEndpointOptions
		switch value := endpoint.Options.(type) {
		case *option.TailscaleEndpointOptions:
			ts = value
		case option.TailscaleEndpointOptions:
			copy := value
			ts = &copy
		}
		if ts == nil {
			return nil, errors.New("missing prepared directory options")
		}
		p.entries = append(p.entries, &preparedDirectoryEntry{tag: tag, originalState: os.ExpandEnv(ts.StateDirectory), originalTaildrop: os.ExpandEnv(ts.TaildropDirectory)})
	}
	return p, nil
}

func (p *PreparedDirectoryLeases) Acquire(request context.Context) error {
	return p.acquire(request, acquireMappedDirectory)
}

func (p *PreparedDirectoryLeases) acquire(request context.Context, acquire func(string, string) (string, *directoryLease, error)) error {
	p.mu.Lock()
	if p.acquisitionStarted || p.aborted || p.committed {
		p.mu.Unlock()
		return errors.New("prepared directory acquisition replay")
	}
	p.acquisitionStarted = true
	p.mu.Unlock()
	mapping := adapter.TailscaleDirectoryMappingFromContext(p.ctx)
	for _, e := range p.entries {
		if err := request.Err(); err != nil {
			return err
		}
		if err := p.ctx.Err(); err != nil {
			return err
		}
		physicalState, physicalTaildrop, ok := mapping.Resolve(e.originalState, e.originalTaildrop)
		if !ok {
			return errors.New("prepared directory mapping lost authority")
		}
		actual, lease, err := acquire(e.originalState, physicalState)
		if err != nil {
			failure := fmt.Errorf("prepare directory %s: %w", e.tag, err)
			p.mu.Lock()
			e.failed = true
			p.mu.Unlock()
			return failure
		}
		d := newDirectoryOwner(p.ctx, e.tag, actual)
		d.leaseOnce.Do(func() {
			d.lease, d.admitted = lease, true
			d.node.DirectoryIdentity, d.node.Incarnation, d.node.DirectoryEpoch = lease.Identity, lease.Incarnation, lease.Epoch
		})
		p.mu.Lock()
		e.owner, e.state, e.taildrop = d, actual, e.originalTaildrop
		if actual == physicalState {
			e.taildrop = physicalTaildrop
		}
		e.validate = func() error {
			if !d.domain.Active() {
				return errors.New("prepared directory domain revoked")
			}
			return lease.checkAnchors()
		}
		p.mu.Unlock()
	}
	if err := request.Err(); err != nil {
		return err
	}
	return p.ctx.Err()
}
