package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type TCPNat struct {
	stop chan struct{}
	done chan struct{}
	stopOnce sync.Once
	closed bool // protected by addrAccess
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[tcpNatKey]uint16
	portMap    map[uint16]*TCPSession
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
	verdict FlowVerdict
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout:   timeout,
		stop: make(chan struct{}),
		done: make(chan struct{}),
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	defer close(n.done)
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	defer n.clear()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-n.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	type expiredSession struct {
		port    uint16
		session *TCPSession
	}
	var expired []expiredSession
	n.portAccess.RLock()
	for natPort, session := range n.portMap {
		session.Lock()
		timedOut := now.Sub(session.LastActive) > n.timeout
		session.Unlock()
		if timedOut {
			expired = append(expired, expiredSession{port: natPort, session: session})
		}
	}
	n.portAccess.RUnlock()
	if len(expired) == 0 {
		return
	}
	n.addrAccess.Lock()
	n.portAccess.Lock()
	for _, e := range expired {
		e.session.Lock()
		if now.Sub(e.session.LastActive) > n.timeout {
			delete(n.addrMap, tcpNatKey{Source: e.session.Source, Destination: e.session.Destination})
			delete(n.portMap, e.port)
			e.session.verdict.Release()
		}
		e.session.Unlock()
	}
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.refresh()
	}
	return session
}

func (s *TCPSession) refresh() {
	s.Lock()
	if time.Since(s.LastActive) > time.Second {
		s.LastActive = time.Now()
	}
	s.Unlock()
}

func (n *TCPNat) refresh(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.refresh()
	}
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort) uint16 {
	verdict := FlowVerdict{}
	return n.lookupOwned(source, destination, &verdict)
}

func (n *TCPNat) lookupOwned(source netip.AddrPort, destination netip.AddrPort, verdict *FlowVerdict) uint16 {
	defer verdict.Release()
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		n.refresh(port)
		return port
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	if n.closed { return 0 }
	port, loaded = n.addrMap[key]
	if loaded {
		n.refresh(port)
		return port
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, ok := n.allocatePortLocked()
	if !ok {
		return 0
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
		verdict: verdict.Take(),
	}
	n.addrMap[key] = nextPort
	return nextPort
}

func (n *TCPNat) allocatePortLocked() (uint16, bool) {
	for range 65535 - 10000 + 1 {
		nextPort := n.portIndex
		if nextPort == 0 {
			nextPort = 10000
			n.portIndex = 10001
		} else {
			n.portIndex++
		}
		if _, occupied := n.portMap[nextPort]; !occupied {
			return nextPort, true
		}
	}
	return 0, false
}

func (n *TCPNat) lookupBackOwned(port uint16) (*TCPSession, FlowVerdict, bool) {
	n.portAccess.RLock()
	defer n.portAccess.RUnlock()
	session := n.portMap[port]
	if session == nil { return nil, FlowVerdict{}, false }
	session.Lock()
	defer session.Unlock()
	verdict, err := session.verdict.CloneForDelivery()
	if err != nil { return nil, FlowVerdict{}, false }
	return session, verdict, true
}

func (n *TCPNat) clear() {
	n.addrAccess.Lock()
	n.portAccess.Lock()
	n.closed = true
	sessions := n.portMap
	n.portMap = make(map[uint16]*TCPSession)
	n.addrMap = make(map[tcpNatKey]uint16)
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
	for _, session := range sessions { session.Lock(); session.verdict.Release(); session.Unlock() }
}

func (n *TCPNat) Close() error {
	if n == nil { return nil }
	n.stopOnce.Do(func() { close(n.stop) })
	n.clear()
	return nil
}
