package tun

import (
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

const (
	fragmentTimeout       = 30 * time.Second
	fragmentSweepInterval = time.Second
	fragmentTableCapacity = 4096
)

type fragmentKey struct {
	source      netip.Addr
	destination netip.Addr
	protocol    uint8
	id          uint32
}

type fragmentEntry struct {
	use *forwardUse
	flow     *forwardFlow
	rule     *rewriteRule
	deadline int64
	received int
	total    int
}

type fragmentTable struct {
	access    sync.Mutex
	entries   map[fragmentKey]*fragmentEntry
	lastSweep int64
}

func (t *fragmentTable) insert(key fragmentKey, use *forwardUse, rule *rewriteRule, received int, now int64) {
	owned, err := use.retain()
	if err != nil { return }
	t.access.Lock()
	var removed []*fragmentEntry
	if previous := t.entries[key]; previous != nil { delete(t.entries, key); removed = append(removed, previous) }
	if len(t.entries) >= fragmentTableCapacity {
		for existingKey, entry := range t.entries {
			if entry.deadline < now { delete(t.entries, existingKey); removed = append(removed, entry) }
		}
	}
	if len(t.entries) < fragmentTableCapacity {
		// Copy the rewrite rule: a NAT mapping can disappear independently.
		copiedRule := *rule
		t.entries[key] = &fragmentEntry{use: owned, flow: use.flow, rule: &copiedRule, deadline: now+int64(fragmentTimeout), received: received, total: -1}
		owned = nil
	}
	t.access.Unlock()
	for _, entry := range removed { entry.use.release() }
	owned.release()
}

func (t *fragmentTable) remove(key fragmentKey) {
	t.access.Lock()
	entry := t.entries[key]
	delete(t.entries, key)
	t.access.Unlock()
	if entry != nil { entry.use.release() }
}

func (t *fragmentTable) expire(now int64) {
	t.access.Lock()
	var removed []*fragmentEntry
	for key, entry := range t.entries {
		if entry.deadline < now { delete(t.entries, key); removed = append(removed, entry) }
	}
	t.access.Unlock()
	for _, entry := range removed { entry.use.release() }
}

func (t *fragmentTable) clear() {
	t.access.Lock()
	entries := t.entries
	t.entries = make(map[fragmentKey]*fragmentEntry)
	t.access.Unlock()
	for _, entry := range entries { entry.use.release() }
}

func (t *fragmentTable) lookup(key fragmentKey, info fragmentInfo, now int64) *fragmentEntry {
	t.access.Lock()
	entry := t.entries[key]
	if entry == nil { t.access.Unlock(); return nil }
	if entry.deadline < now {
		delete(t.entries, key)
		t.access.Unlock()
		entry.use.release()
		return nil
	}
	use, err := entry.use.retain() // Must precede removal/release under this lock.
	if err != nil { t.access.Unlock(); return nil }
	entry.received += len(info.payload)
	if !info.more { entry.total = info.offset+len(info.payload) }
	remove := entry.total >= 0 && entry.received >= entry.total
	if remove { delete(t.entries, key) }
	copyEntry := *entry
	copyEntry.use = use
	t.access.Unlock()
	if remove { entry.use.release() }
	return &copyEntry
}

type fragmentInfo struct {
	protocol uint8
	id       uint32
	offset   int
	more     bool
	payload  []byte
}

func parseFragment(parsed *forwardPacket) (fragmentInfo, bool) {
	if parsed.ipVersion == 4 {
		ipHdr := header.IPv4(parsed.network)
		return fragmentInfo{
			protocol: parsed.protocol,
			id:       uint32(ipHdr.ID()),
			offset:   int(ipHdr.FragmentOffset()),
			more:     ipHdr.More(),
			payload:  ipHdr.Payload(),
		}, true
	}
	fragmentHeader := header.IPv6Fragment(header.IPv6(parsed.network).Payload())
	if !fragmentHeader.IsValid() {
		return fragmentInfo{}, false
	}
	return fragmentInfo{
		protocol: fragmentHeader.NextHeader(),
		id:       fragmentHeader.ID(),
		offset:   int(fragmentHeader.FragmentOffset()) * 8,
		more:     fragmentHeader.More(),
		payload:  fragmentHeader.Payload(),
	}, true
}

func (r *portReturn) classifyFragment(parsed *forwardPacket, size int, now int64) (returnDecision, ForwardWriteback, *forwardUse) {
	info, ok := parseFragment(parsed)
	if !ok { return returnPass, nil, nil }
	key := fragmentKey{source: parsed.source.Addr(), destination: parsed.destination.Addr(), protocol: info.protocol, id: info.id}
	if info.offset == 0 {
		parsed.protocol = info.protocol
		parsed.parseTransport(info.payload)
		var use *forwardUse
		var rule *rewriteRule
		if parsed.hasFlow { use, rule = r.matchReverse(parsed) }
		if use == nil { r.fragments.remove(key); return returnPass, nil, nil }
		flow := use.flow
		if info.more { r.fragments.insert(key, use, rule, len(info.payload), now) }
		if flow.closed.Load() { return returnDrop, nil, use }
		if flow.tracker != nil { flow.tracker.CountReverse(size) }
		flow.observeReverse(parsed, now)
		applyRewrite(parsed, rule)
		return returnWrite, flow.owner.writeback, use
	}
	entry := r.fragments.lookup(key, info, now)
	if entry == nil { return returnPass, nil, nil }
	if entry.flow.closed.Load() { return returnDrop, nil, entry.use }
	if entry.flow.tracker != nil { entry.flow.tracker.CountReverse(size) }
	entry.flow.lastReverse.Store(now)
	applyRewriteAddresses(parsed, entry.rule)
	return returnWrite, entry.flow.owner.writeback, entry.use
}

func (r *portReturn) expireFragments() {
	defer close(r.fragmentDone)
	ticker := time.NewTicker(fragmentSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := r.dispatcher.now()
			r.fragments.expire(now)
			r.dispatcher.sweepIdle(now)
		case <-r.fragmentStop: return
		}
	}
}
