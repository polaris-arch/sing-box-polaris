package quic

import (
	"net"

	"github.com/sagernet/sing-box/adapter"
)

var (
	_ adapter.IdleConnectionKeeper = (*Transport)(nil)
	_ adapter.IdleConnectionKeeper = (*HTTP3Transport)(nil)
)

func (t *Transport) SetKeepIdleConnections(keep bool) {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.connection.SetKeepIdleConnections(keep)
}

func (t *Transport) CloseIdleConnections() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.connection.CloseIdle()
}

func (t *HTTP3Transport) SetKeepIdleConnections(keep bool) {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.transportAccess.Lock()
	t.keepIdle = keep
	var idle []*dnsHTTP3Epoch
	if !keep {
		idle = t.detachIdleTransportsLocked()
	}
	t.transportAccess.Unlock()
	t.closeIdleTransports(idle)
}

func (t *HTTP3Transport) CloseIdleConnections() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.transportAccess.Lock()
	idle := t.detachIdleTransportsLocked()
	t.transportAccess.Unlock()
	t.closeIdleTransports(idle)
}

// acquireTransport and releaseTransport run within the exchange's existing
// runtime operation and transport fence. No idle epoch holds a graph lease.
func (t *HTTP3Transport) acquireTransport() (*dnsHTTP3Epoch, error) {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.transport == nil {
		t.transport = t.newTransport()
		t.transports = append(t.transports, t.transport)
	}
	t.transport.active++
	return t.transport, nil
}

func (t *HTTP3Transport) releaseTransport(epoch *dnsHTTP3Epoch) {
	t.transportAccess.Lock()
	epoch.active--
	var idle []*dnsHTTP3Epoch
	if !t.keepIdle && !t.closed && !epoch.retired && epoch.active == 0 {
		t.detachTransportLocked(epoch)
		idle = append(idle, epoch)
	}
	t.transportAccess.Unlock()
	t.closeIdleTransports(idle)
}

// The pinned HTTP/3 transport's useCount ends at response headers, and a
// canceled waiter can leave a dial outstanding after RoundTrip returns. Its
// CloseIdleConnections alone therefore cannot describe a complete DNS
// exchange's lifetime. Retire only epochs with no admitted exchanges, then
// join their existing boundary, including late dials and owned UDP sessions.
// Admission and detachment use the same lock, so a new exchange cannot select
// an epoch that an idle trim is about to close.
func (t *HTTP3Transport) detachIdleTransportsLocked() []*dnsHTTP3Epoch {
	if t.closed {
		return nil
	}
	var idle []*dnsHTTP3Epoch
	for _, epoch := range t.transports {
		if !epoch.retired && epoch.active == 0 {
			t.detachTransportLocked(epoch)
			idle = append(idle, epoch)
		}
	}
	return idle
}

func (t *HTTP3Transport) detachTransportLocked(epoch *dnsHTTP3Epoch) {
	epoch.retired = true
	if t.transport == epoch {
		// Creation remains lazy. Repeated idle trims never allocate transports.
		t.transport = nil
	}
}

func (t *HTTP3Transport) closeIdleTransports(idle []*dnsHTTP3Epoch) {
	for _, epoch := range idle {
		epoch.boundary.StopRuntimeOperations()
	}
	for _, epoch := range idle {
		if err := epoch.RuntimeCloseAndWait(); err != nil {
			// Keep failed cleanup owned and sticky for terminal close.
			t.recordClose(err)
			continue
		}
		t.transportAccess.Lock()
		for index, current := range t.transports {
			if current == epoch {
				copy(t.transports[index:], t.transports[index+1:])
				t.transports[len(t.transports)-1] = nil
				t.transports = t.transports[:len(t.transports)-1]
				break
			}
		}
		t.transportAccess.Unlock()
	}
}
