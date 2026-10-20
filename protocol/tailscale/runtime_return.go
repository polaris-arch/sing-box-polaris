//go:build with_tailscale

package tailscale

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-tun"
)

// The existing sing-tun allocator uses this original physical Port as its NAT
// key, while every return attachment still retains its exact logical Port.
func (t *Endpoint) NATIdentity() tun.Port {
	if t.runtime == nil {
		return t
	}
	t.runtime.mu.Lock()
	p := t.runtime.physical
	t.runtime.mu.Unlock()
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.child
}

type (
	runtimeReturnEntry struct {
		target tun.Return
		fence  *outbound.RuntimeIOFence
	}
	runtimeEndpointReturn struct {
		operation   sync.Mutex // native SetReturnPath serialization; callbacks never take it
		mu          sync.Mutex
		physical    *runtimeEndpointPhysical
		entries     map[tun.Return]*runtimeReturnEntry
		installed   bool
		headroom    int
		hasHeadroom bool
	}
)

func (m *runtimeEndpointReturn) attach(child *Endpoint, target tun.Return) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	// Concrete dispatcher writeback headroom is immutable for this attachment.
	// No callback is invoked under the registry lock.
	headroom := target.ReturnHeadroom()
	m.mu.Lock()
	if m.hasHeadroom && headroom != m.headroom {
		m.mu.Unlock()
		return errors.New("Tailscale shared return paths require identical packet headroom")
	}
	if m.entries == nil {
		m.entries = make(map[tun.Return]*runtimeReturnEntry)
	}
	if _, exists := m.entries[target]; exists {
		m.mu.Unlock()
		return nil
	}
	m.headroom = headroom
	m.hasHeadroom = true
	entry := &runtimeReturnEntry{target: target, fence: outbound.NewRuntimeIOFence(nil)}
	m.entries[target] = entry
	installed := m.installed
	m.mu.Unlock()
	if installed {
		return nil
	}
	// Keep one stable native callback object even when the last logical gate
	// detaches. An empty mux owns no retired graph or callback target.
	if err := child.wgEngine.SetReturnPath(m); err != nil {
		m.mu.Lock()
		delete(m.entries, target)
		m.mu.Unlock()
		return errors.Join(err, entry.fence.RuntimeCloseAndWait())
	}
	m.mu.Lock()
	m.installed = true
	m.mu.Unlock()
	child.returnAccess.Lock()
	child.returnPath = m
	child.returnAccess.Unlock()
	return nil
}

func (m *runtimeEndpointReturn) detach(target tun.Return) error {
	m.mu.Lock()
	entry := m.entries[target]
	delete(m.entries, target)
	m.mu.Unlock()
	if entry == nil {
		return nil
	}
	// Original sing-tun detachIdle runs this on its admitted detach goroutine,
	// not inside ReturnPackets. Seal copied callbacks and join before return.
	return entry.fence.RuntimeCloseAndWait()
}

func (m *runtimeEndpointReturn) ReturnHeadroom() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.headroom
}

func (m *runtimeEndpointReturn) ReturnPackets(packets [][]byte) [][]byte {
	leave, err := m.physical.callbacks.Acquire()
	if err != nil {
		return packets
	}
	defer leave()
	m.mu.Lock()
	entries := make([]*runtimeReturnEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	m.mu.Unlock()
	for _, entry := range entries {
		release, err := entry.fence.Acquire()
		if err != nil {
			continue
		}
		packets = func() [][]byte { defer release(); return entry.target.ReturnPackets(packets) }()
		if len(packets) == 0 {
			break
		}
	}
	return packets
}
