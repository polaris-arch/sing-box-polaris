package group

import (
	"context"
	"io"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
	_ adapter.Referrer                = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *URLTest) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		outbounds := make([]adapter.Outbound, 0, len(s.tags))
		for i, tag := range s.tags {
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			outbounds = append(outbounds, detour)
		}
		group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
		if err != nil {
			return err
		}
		s.group = group
		if adapter.IsRuntimePreparation(s.ctx) {
			scope.Add(func() error { err := group.Close(); <-group.Done(); return err })
		} else {
			scope.Add(group.Close)
		}
	case adapter.StartStateStarted:
		if !adapter.IsRuntimePreparation(s.ctx) {
			s.group.PostStart()
		}
	}
	return nil
}

func (s *URLTest) All() []string {
	return s.tags
}

func (s *URLTest) Selected(network string) adapter.Outbound {
	var outbound adapter.Outbound
	if network == N.NetworkUDP {
		outbound = s.group.selected().udp
	} else {
		outbound = s.group.selected().tcp
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	return outbound
}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	selection := group.selected()
	var references []string
	if selection.tcp != nil {
		references = append(references, selection.tcp.Tag())
	}
	if selection.udp != nil && selection.udp != selection.tcp {
		references = append(references, selection.udp.Tag())
	}
	return references
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.CheckOutboundsContext(s.group.ctx)
}

// CheckOutboundsContext transfers any admitted continuation before asynchronous
// dispatch. The native worker, not this facade call, owns its final release.
func (s *URLTest) CheckOutboundsContext(ctx context.Context) {
	_, _ = s.group.requestCheck(ctx, true, false)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) PerformUpdateCheckEpoch(epoch *urltest.HistoryEpoch) {
	s.group.performUpdateCheckEpoch(epoch)
}

func (s *URLTest) performUpdateCheckEpochContext(ctx context.Context, epoch *urltest.HistoryEpoch) {
	s.group.performUpdateCheckEpochContext(ctx, epoch)
}

func (s *URLTest) InterfaceUpdated(_ context.Context) {
	if s.group != nil {
		_, _ = s.group.requestCheck(s.group.ctx, true, false)
	}
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = s.group.selected().tcp
	case N.NetworkUDP:
		outbound = s.group.selected().udp
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	epoch := s.group.history.Epoch()
	historyTag := outbound.Tag()
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.deleteHistory(epoch, historyTag)
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.selected().udp
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	epoch := s.group.history.Epoch()
	historyTag := outbound.Tag()
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.deleteHistory(epoch, historyTag)
	return nil, err
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	selection                    atomic.Pointer[urlTestSelection]
	cancel                       context.CancelFunc
	closed                       bool
	running                      bool
	pendingForce                 bool
	activeCancel                 context.CancelFunc
	workers                      sync.WaitGroup
	done                         chan struct{}
	probe                        func(context.Context, string, N.Dialer) (uint16, error)
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &URLTestGroup{
		ctx:                          ctx,
		cancel:                       cancel,
		done:                         make(chan struct{}),
		probe:                        urltest.URLTest,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}
	g.pauseCallback = g.pause.RegisterCallback(g.pauseChanged)
	return g, nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	epoch := g.history.Epoch()
	histories, _ := g.history.Snapshot(epoch)
	return g.selectSnapshot(network, g.selected(), histories)
}

func (g *URLTestGroup) selectSnapshot(network string, selection *urlTestSelection, histories map[string]*adapter.URLTestHistory) (adapter.Outbound, bool) {
	var minDelay uint16
	var minOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		if selection.tcp != nil {
			if history := histories[RealTag(selection.tcp, N.NetworkTCP)]; history != nil {
				minOutbound = selection.tcp
				minDelay = history.Delay
			}
		}
	case N.NetworkUDP:
		if selection.udp != nil {
			if history := histories[RealTag(selection.udp, N.NetworkUDP)]; history != nil {
				minOutbound = selection.udp
				minDelay = history.Delay
			}
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := histories[RealTag(detour, network)]
		if history == nil {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	return g.requestCheck(ctx, force, true)
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestBatch struct {
	epoch    *urltest.HistoryEpoch
	owner    *URLTestGroup
	ctx      context.Context
	outbound adapter.OutboundManager
	history  *urltest.HistoryStorage
	logger   log.Logger
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, interval, force, history.Epoch(), nil)
}

// URLTestOutboundsEpoch preserves an epoch admitted before asynchronous dispatch.
func URLTestOutboundsEpoch(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, epoch *urltest.HistoryEpoch) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, interval, force, epoch, nil)
}

func urlTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, epoch *urltest.HistoryEpoch, owner *URLTestGroup) map[string]uint16 {
	ctx, cancel, err := history.ProbeContext(ctx, epoch)
	if err != nil {
		return make(map[string]uint16)
	}
	defer cancel()
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		epoch:    epoch,
		owner:    owner,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	histories, valid := history.Snapshot(epoch)
	if !valid || !urlTestCanPublish(ctx) {
		return make(map[string]uint16)
	}
	for _, outboundGroup := range testBatch.groups {
		groupHistory := histories[RealTag(outboundGroup, N.NetworkTCP)]
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	if !history.IsCurrent(epoch) || !urlTestCanPublish(ctx) {
		return make(map[string]uint16)
	}
	for tag := range testBatch.result {
		PerformRuntimeUpdateChecks(ctx, epoch, tag)
	}
	if !urlTestCanPublish(ctx) {
		return make(map[string]uint16)
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case *URLTest:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nestedResult, _ := nested.group.requestCheckEpoch(b.ctx, force, true, b.epoch)
				// A nested native group owns a different private history. Copy its
				// completed epoch values into this parent's captured history; never
				// fall back to root visible projection for native selection.
				if histories, valid := nested.group.history.Snapshot(b.epoch); valid && urlTestCanPublish(b.ctx) {
					for tag, history := range histories {
						b.storeHistory(tag, history)
					}
				}
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
				defer cancel()
				if !urlTestCanPublish(testCtx) {
					return nil, nil
				}
				probe := urltest.URLTest
				if b.owner != nil {
					probe = b.owner.probe
				}
				delay, probeErr := probe(testCtx, link, detour)
				if testCtx.Err() != nil {
					probeErr = testCtx.Err()
				}
				testResult := urlTestResult{delay: delay, err: probeErr}

				if testResult.err != nil {
					if !urlTestCanPublish(b.ctx) {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.deleteHistory(tag)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					stored := b.storeHistory(tag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					if !stored {
						return nil, nil
					}
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	g.performUpdateCheckEpoch(g.history.Epoch())
}

func (g *URLTestGroup) performUpdateCheckEpoch(epoch *urltest.HistoryEpoch) {
	g.performUpdateCheckEpochContext(g.ctx, epoch)
}

func (g *URLTestGroup) performUpdateCheckEpochContext(ctx context.Context, epoch *urltest.HistoryEpoch) {
	g.updateAccess.Lock()
	histories, valid := g.history.Snapshot(epoch)
	if !valid {
		g.updateAccess.Unlock()
		return
	}
	previous := g.selected()
	next := *previous
	updated, selected := false, false
	if outbound, exists := g.selectSnapshot(N.NetworkTCP, previous, histories); outbound != nil && (next.tcp == nil || (exists && outbound != next.tcp)) {
		updated = next.tcp != nil
		next.tcp = outbound
		selected = true
	}
	if outbound, exists := g.selectSnapshot(N.NetworkUDP, previous, histories); outbound != nil && (next.udp == nil || (exists && outbound != next.udp)) {
		updated = updated || next.udp != nil
		next.udp = outbound
		selected = true
	}
	g.access.Lock()
	published := !g.closed && !g.pause.IsDevicePaused() && !g.pause.IsNetworkPaused() && urlTestCanPublish(ctx) && g.history.PublishIfCurrent(epoch, func() { g.selection.Store(&next) })
	g.access.Unlock()
	g.updateAccess.Unlock()
	if !published {
		return
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
}

func (g *URLTestGroup) deleteHistory(epoch *urltest.HistoryEpoch, tag string) bool {
	g.access.Lock()
	defer g.access.Unlock()
	return !g.closed && g.history.DeleteIfCurrent(epoch, tag)
}

func (b *urlTestBatch) deleteHistory(tag string) bool {
	if b.owner != nil {
		b.owner.access.Lock()
		defer b.owner.access.Unlock()
		if b.owner.closed || b.owner.pause.IsDevicePaused() || b.owner.pause.IsNetworkPaused() {
			return false
		}
	}
	if !urlTestCanPublish(b.ctx) {
		return false
	}
	committed := b.history.DeleteIfCurrent(b.epoch, tag)
	if urlTestCanPublish(b.ctx) {
		urltest.PublishRuntimeResult(b.ctx, b.epoch, tag, nil)
	}
	return committed
}

func (b *urlTestBatch) storeHistory(tag string, history *adapter.URLTestHistory) bool {
	if b.owner != nil {
		b.owner.access.Lock()
		defer b.owner.access.Unlock()
		if b.owner.closed || b.owner.pause.IsDevicePaused() || b.owner.pause.IsNetworkPaused() {
			return false
		}
	}
	if !urlTestCanPublish(b.ctx) {
		return false
	}
	committed := b.history.StoreIfCurrent(b.epoch, tag, history)
	if urlTestCanPublish(b.ctx) {
		urltest.PublishRuntimeResult(b.ctx, b.epoch, tag, history)
	}
	return committed
}

// RuntimeActivate is a nonblocking, idempotent producer admission. PostStart
// already arbitrates with Close under the group's existing admission mutex.
func (s *URLTest) RuntimeActivate() {
	if s.group != nil {
		s.group.PostStart()
	}
}
func (s *URLTest) RuntimeStop() {
	if s.group != nil {
		_ = s.group.Close()
	}
}

// PerformRuntimeUpdateChecks uses only fixed actual groups from a retained
// graph and only consumers of the same captured target. Selection still has
// exactly one owner: each native group's epoch/paused/closed guarded method.
func PerformRuntimeUpdateChecks(ctx context.Context, epoch *urltest.HistoryEpoch, tag string) {
	borrowed, ok := adapter.RuntimeLeaseFromContext(ctx)
	if !ok || !urlTestCanPublish(ctx) {
		return
	}
	lease, err := borrowed.Fork()
	if err != nil {
		return
	}
	defer lease.Release()
	view, ok := lease.View().(urltest.RuntimeHistoryView)
	if !ok {
		return
	}
	consumers := make(map[*urltest.HistoryStorage]bool)
	for _, history := range view.RuntimeURLTestConsumers(tag) {
		consumers[history] = true
	}
	for _, outbound := range lease.View().OutboundManager().Outbounds() {
		history, _, exists := view.RuntimeURLTestHistory(outbound.Tag())
		if !exists || !consumers[history] {
			continue
		}
		if native, ok := outbound.(interface {
			performUpdateCheckEpochContext(context.Context, *urltest.HistoryEpoch)
		}); ok {
			native.performUpdateCheckEpochContext(ctx, epoch)
		}
	}
}

// The coordinator orders these locks by group tag while holding its control
// gate, then validates the captured winner path and publishes the new graph.
func (s *URLTest) RuntimeLockSelection() func() {
	s.group.updateAccess.Lock()
	return s.group.updateAccess.Unlock
}
func (s *URLTest) RuntimeSelectionSnapshot() adapter.Outbound { return s.group.selected().tcp }
