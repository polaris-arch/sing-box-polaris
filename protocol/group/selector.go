package group

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup = (*Selector)(nil)
	_ adapter.Referrer      = (*Selector)(nil)
)

type Selector struct {
	runtimeAccess sync.Mutex
	runtimeActive bool
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	ephemeralPoolProbe           bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, nil, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
		ephemeralPoolProbe:           options.EphemeralPoolProbe,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
	}

	if s.Tag() != "" && !s.ephemeralPoolProbe {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := s.outbounds[selected]
				if loaded {
					s.selected.Store(detour)
					return nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.outbounds[s.defaultTag]
		if !loaded {
			return E.New("default outbound not found: ", s.defaultTag)
		}
		s.selected.Store(detour)
		return nil
	}

	s.selected.Store(s.outbounds[s.tags[0]])
	return nil
}

func (s *Selector) All() []string {
	return s.tags
}

func (s *Selector) Selected(network string) adapter.Outbound {
	return s.selected.Load()
}

// PoolProbeMember reads the immutable membership of a started selector.
func (s *Selector) PoolProbeMember(tag string) (adapter.Outbound, bool) {
	member, exists := s.outbounds[tag]
	return member, exists
}

// EphemeralPoolProbe identifies the dedicated App slot resolved at construction.
func (s *Selector) EphemeralPoolProbe() bool { return s.ephemeralPoolProbe }

func (s *Selector) AttachConnection(closer io.Closer) func() {
	return s.interruptGroup.Add(closer, true)
}

func (s *Selector) AttachConnectionForSelection(closer io.Closer, selected adapter.Outbound) (func(), bool) {
	detach := s.AttachConnection(closer)
	// A switch before registration may already have interrupted the old selection.
	if s.interruptExternalConnections && s.selected.Load() != selected {
		detach()
		return nil, false
	}
	return detach, true
}

func (s *Selector) References() []string {
	selected := s.selected.Load()
	if selected == nil {
		return s.tags[:1]
	}
	return []string{selected.Tag()}
}

func (s *Selector) SelectOutbound(tag string) bool {
	if control, ok := adapter.RuntimeControlFromContext(s.ctx); ok {
		source, present := adapter.RuntimeResourceSourceFromContext(s.ctx)
		if !present {
			return false
		}
		return control.SelectRuntimeOutbound(source.ID(), s.Tag(), tag)
	}
	_, accepted, effect := s.RuntimeSelect(tag)
	if effect != nil {
		effect()
	}
	return accepted
}

// RuntimeSelect mutates only the in-memory selection. The coordinator invokes
// its returned effects outside admission/lifecycle guards under ordered control
// persistence. Legacy callers keep identical synchronous effects above.
func (s *Selector) RuntimeSelect(tag string) (changed bool, accepted bool, effect func()) {
	detour, loaded := s.outbounds[tag]
	if !loaded {
		return false, false, nil
	}
	if s.selected.Swap(detour) == detour {
		return false, true, nil
	}
	return true, true, func() {
		if s.Tag() != "" && !s.ephemeralPoolProbe {
			cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
			if cacheFile != nil {
				if err := cacheFile.StoreSelected(s.Tag(), tag); err != nil {
					s.logger.Error("store selected: ", err)
				}
			}
		}
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
		if s.history != nil {
			s.history.NotifyUpdated()
		}
	}
}

// RuntimeSelectInitial is private candidate-state migration, without cache IO,
// notifications or connection interruption. It never mutates a published group.
func (s *Selector) RuntimeSelectInitial(tag string) bool {
	s.runtimeAccess.Lock()
	defer s.runtimeAccess.Unlock()
	if s.ephemeralPoolProbe || !adapter.IsRuntimePreparation(s.ctx) || s.runtimeActive {
		return false
	}
	detour, exists := s.outbounds[tag]
	if !exists {
		return false
	}
	s.selected.Store(detour)
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	selected := s.selected.Load()
	conn, err := selected.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	isExternal := interrupt.IsExternalConnectionFromContext(ctx)
	conn = s.interruptGroup.NewConn(conn, isExternal)
	// Register before checking so a concurrent switch cannot miss this dial.
	if s.selected.Load() != selected && (!isExternal || s.interruptExternalConnections) {
		conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	selected := s.selected.Load()
	conn, err := selected.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	isExternal := interrupt.IsExternalConnectionFromContext(ctx)
	conn = s.interruptGroup.NewPacketConn(conn, isExternal)
	if s.selected.Load() != selected && (!isExternal || s.interruptExternalConnections) {
		conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

func RealTag(detour adapter.Outbound, network string) string {
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return detour.Tag()
		}
		detour = group.Selected(network)
		if detour == nil {
			return ""
		}
	}
}

func (s *Selector) RuntimeActivate() {
	s.runtimeAccess.Lock()
	s.runtimeActive = true
	s.runtimeAccess.Unlock()
}
