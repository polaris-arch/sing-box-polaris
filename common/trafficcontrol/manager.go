package trafficcontrol

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	"github.com/sagernet/sing/common/cleanup"
	"github.com/sagernet/sing/common/x/list"

	"github.com/gofrs/uuid/v5"
)

type ConnectionEventType int

const (
	ConnectionEventNew ConnectionEventType = iota
	ConnectionEventClosed
)

type ConnectionEvent struct {
	Type     ConnectionEventType
	ID       uuid.UUID
	Metadata *TrackerMetadata
	ClosedAt time.Time
}

const closedConnectionsLimit = 1000

var (
	_ adapter.ConnectionTracker = (*Manager)(nil)
	_ adapter.LifecycleService  = (*Manager)(nil)
)

type Manager struct {
	connections             compatible.Map[uuid.UUID, Tracker]
	closedConnectionsAccess sync.Mutex
	closedConnections       list.List[TrackerMetadata]
	closedUploadTotal       int64
	closedDownloadTotal     int64

	events connectionEventObserver
}

func NewManager() *Manager {
	return &Manager{
		events: connectionEventObserver{
			events:    make(chan queuedConnectionEvent, 256),
			lossWake:  make(chan struct{}, 1),
			done:      make(chan struct{}),
			listeners: make(map[*ConnectionEventSubscription]struct{}),
		},
	}
}

func (m *Manager) Name() string {
	return "traffic manager"
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		go m.events.run()
		scope.Add(m.events.close)
		cleaner := cleanup.Add(m.Clear)
		scope.Add(func() error {
			cleaner.Close()
			return nil
		})
	}
	return nil
}

func (m *Manager) SubscribeEvents() (*ConnectionEventSubscription, error) {
	o := &m.events
	o.access.Lock()
	defer o.access.Unlock()
	if o.listeners == nil {
		return nil, os.ErrClosed
	}
	subscription := &ConnectionEventSubscription{
		observer:   o,
		generation: o.generation.Add(1),
		events:     make(chan ConnectionEvent, 64),
		done:       make(chan struct{}),
	}
	o.listeners[subscription] = struct{}{}
	return subscription, nil
}

func (m *Manager) join(tracker Tracker) {
	metadata := tracker.Metadata()
	m.connections.Store(metadata.ID, tracker)
	m.events.emit(ConnectionEvent{
		Type:     ConnectionEventNew,
		ID:       metadata.ID,
		Metadata: metadata,
	})
}

func (m *Manager) leave(tracker Tracker) {
	metadata := tracker.Metadata()
	closedAt := time.Now()
	m.closedConnectionsAccess.Lock()
	_, loaded := m.connections.LoadAndDelete(metadata.ID)
	if !loaded {
		m.closedConnectionsAccess.Unlock()
		return
	}
	metadata.ClosedAt = closedAt
	metadataCopy := *metadata
	if m.closedConnections.Len() >= closedConnectionsLimit {
		evicted := m.closedConnections.PopFront()
		m.closedUploadTotal += evicted.Upload.Load()
		m.closedDownloadTotal += evicted.Download.Load()
	}
	m.closedConnections.PushBack(metadataCopy)
	m.closedConnectionsAccess.Unlock()
	m.events.emit(ConnectionEvent{
		Type:     ConnectionEventClosed,
		ID:       metadata.ID,
		Metadata: &metadataCopy,
		ClosedAt: closedAt,
	})
}

func (m *Manager) Total() (uplinkTotal int64, downlinkTotal int64) {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	uplinkTotal = m.closedUploadTotal
	downlinkTotal = m.closedDownloadTotal
	for element := m.closedConnections.Front(); element != nil; element = element.Next() {
		uplinkTotal += element.Value.Upload.Load()
		downlinkTotal += element.Value.Download.Load()
	}
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		metadata := tracker.Metadata()
		uplinkTotal += metadata.Upload.Load()
		downlinkTotal += metadata.Download.Load()
		return true
	})
	return
}

func (m *Manager) ConnectionsLen() int {
	return m.connections.Len()
}

func (m *Manager) Connections() []*TrackerMetadata {
	var connections []*TrackerMetadata
	m.RangeConnections(func(metadata *TrackerMetadata) bool {
		connections = append(connections, metadata)
		return true
	})
	return connections
}

// RangeConnections visits live connections without holding a manager lock during the callback.
func (m *Manager) RangeConnections(visit func(*TrackerMetadata) bool) {
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		return visit(tracker.Metadata())
	})
}

func (m *Manager) ClosedConnections() []*TrackerMetadata {
	m.closedConnectionsAccess.Lock()
	values := m.closedConnections.Array()
	m.closedConnectionsAccess.Unlock()
	if len(values) == 0 {
		return nil
	}
	connections := make([]*TrackerMetadata, len(values))
	for i := range values {
		connections[i] = &values[i]
	}
	return connections
}

func (m *Manager) Connection(id uuid.UUID) Tracker {
	connection, loaded := m.connections.Load(id)
	if !loaded {
		return nil
	}
	return connection
}

func (m *Manager) CloseAllConnections() {
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		tracker.Close()
		return true
	})
}

func (m *Manager) Clear() {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	for element := m.closedConnections.Front(); element != nil; element = element.Next() {
		m.closedUploadTotal += element.Value.Upload.Load()
		m.closedDownloadTotal += element.Value.Download.Load()
	}
	m.closedConnections.Init()
}

type ConnectionEventSubscription struct {
	observer   *connectionEventObserver
	generation uint64
	events     chan ConnectionEvent
	done       chan struct{}
	lost       bool // published by closing done
}

func (s *ConnectionEventSubscription) Events() <-chan ConnectionEvent { return s.events }
func (s *ConnectionEventSubscription) Done() <-chan struct{}          { return s.done }

func (s *ConnectionEventSubscription) Lost() bool {
	// A stream can observe ingress loss before the dispatcher wakes it.
	lost := s.observer.lostGeneration.Load() >= s.generation
	select {
	case <-s.done:
		return s.lost
	default:
		return lost
	}
}

func (s *ConnectionEventSubscription) Close() {
	s.observer.access.Lock()
	defer s.observer.access.Unlock()
	if _, exists := s.observer.listeners[s]; exists {
		delete(s.observer.listeners, s)
		close(s.done)
	}
}

type queuedConnectionEvent struct {
	event      ConnectionEvent
	generation uint64
}

type connectionEventObserver struct {
	events         chan queuedConnectionEvent
	lossWake       chan struct{}
	done           chan struct{}
	generation     atomic.Uint64
	lostGeneration atomic.Uint64

	access    sync.Mutex
	listeners map[*ConnectionEventSubscription]struct{}
}

func (o *connectionEventObserver) emit(event ConnectionEvent) {
	// Tracker state is updated before emit. A later subscriber's census covers
	// earlier generations, even when earlier events are still queued.
	generation := o.generation.Load()
	if generation == 0 {
		return
	}
	select {
	case <-o.done:
		return
	default:
	}
	select {
	case <-o.done:
		return
	case o.events <- queuedConnectionEvent{event: event, generation: generation}:
		return
	default:
	}
	for lost := o.lostGeneration.Load(); lost < generation; lost = o.lostGeneration.Load() {
		if o.lostGeneration.CompareAndSwap(lost, generation) {
			// The wake is independent of the queue that just filled.
			select {
			case o.lossWake <- struct{}{}:
			default:
			}
			return
		}
	}
}

func (o *connectionEventObserver) run() {
	for {
		select {
		case <-o.done:
			return
		case event := <-o.events:
			o.dispatch(&event)
		case <-o.lossWake:
			o.dispatch(nil)
		}
	}
}

func (o *connectionEventObserver) dispatch(event *queuedConnectionEvent) {
	o.access.Lock()
	defer o.access.Unlock()
	lostGeneration := o.lostGeneration.Load()
	for subscription := range o.listeners {
		if lostGeneration < subscription.generation {
			if event == nil || event.generation < subscription.generation {
				continue
			}
			select {
			case subscription.events <- event.event:
				continue
			default:
			}
		}
		subscription.lost = true
		delete(o.listeners, subscription)
		close(subscription.done)
	}
}

func (o *connectionEventObserver) close() error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.listeners == nil {
		return nil
	}
	close(o.done)
	for subscription := range o.listeners {
		close(subscription.done)
	}
	o.listeners = nil
	return nil
}
