package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

type HistoryStorage struct {
	runtimeAdmission adapter.RuntimeAdmission
	runtimeActive map[*HistoryStorage]struct{}
	epoch *HistoryEpoch
	closed bool
	access       *sync.RWMutex
	authority *HistoryStorage
	views map[*HistoryStorage]struct{}
	delayHistory map[string]*adapter.URLTestHistory
	updateHooks  []*observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	root := &HistoryStorage{
		epoch: newHistoryEpoch(true), access: new(sync.RWMutex),
		delayHistory: make(map[string]*adapter.URLTestHistory),
		views: make(map[*HistoryStorage]struct{}),
	}
	root.authority = root
	root.views[root] = struct{}{}
	return root
}

// NewIncarnationHistory shares only network epoch authority. Probe values and
// selection notifications belong to this resource incarnation, never its tag.
func NewIncarnationHistory(parent *HistoryStorage) *HistoryStorage {
	if parent == nil { return NewHistoryStorage() }
	root := parent.authority
	root.access.Lock()
	defer root.access.Unlock()
	view := &HistoryStorage{epoch: root.epoch, access: root.access, authority: root,
		delayHistory: make(map[string]*adapter.URLTestHistory), closed: root.closed}
	if !root.closed { root.views[view] = struct{}{} }
	return view
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.closed && hook != nil { s.updateHooks = append(s.updateHooks, hook) }
}

// RemoveUpdateHook serializes with every in-flight Emit under the same mutex.
// After return only already-buffered payload-free notifications may remain.
// The subscriber itself belongs to its registrant and is not closed here.
func (s *HistoryStorage) RemoveUpdateHook(hook *observable.Subscriber[struct{}]) {
	if s == nil || hook == nil { return }
	s.access.Lock()
	defer s.access.Unlock()
	kept := s.updateHooks[:0]
	for _, current := range s.updateHooks { if current != hook { kept = append(kept, current) } }
	clear(s.updateHooks[len(kept):])
	s.updateHooks = kept
}

func (s *HistoryStorage) NotifyUpdated() {
	s.access.RLock()
	defer s.access.RUnlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil { return nil }
	if result, bound := s.projectedLoad(tag); bound { return result }
	s.access.RLock()
	defer s.access.RUnlock()
	if s.closed { return nil }
	value := s.delayHistory[tag]
	if value == nil { return nil }
	copy := *value
	return &copy
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	if !s.writableLocked() { s.access.Unlock(); return }
	delete(s.delayHistory, tag)
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	if !s.writableLocked() || history == nil { s.access.Unlock(); return }
	copy := *history
	s.delayHistory[tag] = &copy
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) notifyUpdated() {
	if s.closed { return }
	s.notifyLocalLocked()
	root := s.authority
	if root != s { if _, active := root.runtimeActive[s]; active && !root.closed { root.notifyLocalLocked() } }
}

func (s *HistoryStorage) notifyLocalLocked() {
	for _, updateHook := range s.updateHooks {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	if s.closed { s.access.Unlock(); return nil }
	s.closed = true
	root := s.authority
	if root != s {
		delete(root.views, s)
		delete(root.runtimeActive, s)
		s.updateHooks = nil; clear(s.delayHistory)
		s.access.Unlock()
		return nil
	}
	epoch := s.epoch
	for view := range s.views { view.closed = true; view.updateHooks = nil; clear(view.delayHistory) }
	clear(s.views)
	clear(s.runtimeActive)
	s.access.Unlock()
	epoch.cancel()
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (uint16, error) {
	multiplexOutbound, isMultiplexOutbound := common.Cast[adapter.OutboundWithMultiplex](detour)
	if isMultiplexOutbound && multiplexOutbound.MultiplexEnabled() {
		warmContext := adapter.ContextWithKeepSession(ctx)
		warmContext = mux.ContextWithKeepSession(warmContext)
		warmContext = anytls.ContextWithKeepSession(warmContext)
		warmContext = contextWithQUICKeepSession(warmContext)
		warmContext = snell.ContextWithKeepSession(warmContext)
		_, err := urlTest(warmContext, link, detour)
		if err != nil {
			return 0, err
		}
	}
	return urlTest(ctx, link, detour)
}

func urlTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()
	t = uint16(time.Since(start) / time.Millisecond)
	return
}
