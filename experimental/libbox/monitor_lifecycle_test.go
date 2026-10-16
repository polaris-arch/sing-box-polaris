package libbox

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

type monitorTestPlatform struct {
	PlatformInterface
	closeError     error
	startError     error
	onStart        func(InterfaceUpdateListener)
	starts, closes atomic.Int32
}

func (p *monitorTestPlatform) StartDefaultInterfaceMonitor(l InterfaceUpdateListener) error {
	p.starts.Add(1)
	if p.onStart != nil {
		p.onStart(l)
	}
	return p.startError
}
func (p *monitorTestPlatform) CloseDefaultInterfaceMonitor(InterfaceUpdateListener) error {
	p.closes.Add(1)
	return p.closeError
}
func (*monitorTestPlatform) GetInterfaces() (NetworkInterfaceIterator, error) {
	return newIterator([]*NetworkInterface{{Name: "successor", Index: 12}}), nil
}

type monitorTestManager struct {
	adapter.NetworkManager
	monitor         tun.DefaultInterfaceMonitor
	calls           atomic.Int32
	entered, resume chan struct{}
	finder          control.InterfaceFinder
	dnsRead         func() []string
}

func (m *monitorTestManager) NetworkInterfaces() []adapter.NetworkInterface {
	var servers []string
	if m.dnsRead != nil {
		servers = m.dnsRead()
	}
	return []adapter.NetworkInterface{{Interface: control.Interface{Index: 12}, DNSServers: servers}}
}

func (m *monitorTestManager) InterfaceMonitor() tun.DefaultInterfaceMonitor { return m.monitor }
func (m *monitorTestManager) InterfaceFinder() control.InterfaceFinder      { return m.finder }
func (m *monitorTestManager) UpdateInterfaces() error {
	m.calls.Add(1)
	if m.entered != nil {
		close(m.entered)
		<-m.resume
	}
	return nil
}

type monitorTestFinder struct {
	control.InterfaceFinder
	value *control.Interface
}

func (f monitorTestFinder) ByIndex(int) (*control.Interface, error) { return f.value, nil }
func createBoundMonitor(t *testing.T, w *platformInterfaceWrapper, manager *monitorTestManager, start bool) *platformDefaultInterfaceMonitor {
	t.Helper()
	// Actual route.New -> box.New order: Create before Initialize.
	m := w.CreateDefaultInterfaceMonitor(logger.NOP()).(*platformDefaultInterfaceMonitor)
	manager.monitor = m
	if err := w.Initialize(manager); err != nil {
		t.Fatal(err)
	}
	if start {
		if err := m.start(nil); err != nil {
			t.Fatal(err)
		}
	}
	return m
}
func successorMonitor(t *testing.T, w *platformInterfaceWrapper) (*platformDefaultInterfaceMonitor, *monitorTestManager, *control.Interface) {
	expected := &control.Interface{Name: "successor", Index: 12}
	manager := &monitorTestManager{finder: monitorTestFinder{value: expected}}
	m := createBoundMonitor(t, w, manager, true)
	m.UpdateDefaultInterface("successor", 12, true, true)
	manager.calls.Store(0)
	return m, manager, expected
}
func assertSuccessor(t *testing.T, w *platformInterfaceWrapper, m *platformDefaultInterfaceMonitor, b *monitorTestManager, expected *control.Interface) {
	t.Helper()
	if b.calls.Load() != 0 || m.DefaultInterface() != expected {
		t.Fatalf("old A changed B: calls=%d default=%v", b.calls.Load(), m.DefaultInterface())
	}
	defaultInterface, expensive, constrained := w.monitorSnapshot()
	if defaultInterface != expected || !expensive || !constrained {
		t.Fatalf("old A changed B snapshot: default=%v expensive=%v constrained=%v", defaultInterface, expensive, constrained)
	}
	assertSuccessorNetworkProjection(t, w)
}
func TestMonitorClosedAIsolatedFromReloadB(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	a := &monitorTestManager{}
	old := createBoundMonitor(t, w, a, true)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	current, b, expected := successorMonitor(t, w)
	callbacks := 0
	current.RegisterCallback(func(*control.Interface, int) { callbacks++ })
	old.UpdateDefaultInterface("", -1, false, false)
	old.UpdateNetworkPath("old path")
	assertSuccessor(t, w, current, b, expected)
	if a.calls.Load() != 0 || callbacks != 0 {
		t.Fatal("sealed A delivered")
	}
}
func TestMonitorAlreadyDeliveringAIsolatedFromReloadB(t *testing.T) {
	for _, fixStack := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "android-worker"}[fixStack], func(t *testing.T) {
			previous := sFixAndroidStack
			sFixAndroidStack = fixStack
			defer func() { sFixAndroidStack = previous }()
			w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
			a := &monitorTestManager{entered: make(chan struct{}), resume: make(chan struct{})}
			old := createBoundMonitor(t, w, a, true)
			done := make(chan struct{})
			go func() { old.UpdateDefaultInterface("", -1, false, false); close(done) }()
			<-a.entered
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			old.defaultInterfaceAccess.Lock()
			retained := old.inFlight
			old.defaultInterfaceAccess.Unlock()
			if retained != 1 {
				t.Fatalf("in-flight erased at close: %d", retained)
			}
			current, b, expected := successorMonitor(t, w)
			close(a.resume)
			<-done
			assertSuccessor(t, w, current, b, expected)
			if a.calls.Load() != 1 || old.inFlight != 0 {
				t.Fatal("actual-return accounting changed")
			}
		})
	}
}
func TestMonitorPartialConstructionCloseCannotDetachLive(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	live, b, expected := successorMonitor(t, w)
	partial := createBoundMonitor(t, w, &monitorTestManager{}, false)
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}
	assertSuccessor(t, w, live, b, expected)
	if partial.Start() == nil {
		t.Fatal("late Start revived sealed monitor")
	}
	if w.Initialize(&monitorTestManager{monitor: live}) == nil {
		t.Fatal("second bind accepted")
	}
	if (&platformInterfaceWrapper{}).Initialize(&monitorTestManager{monitor: live}) == nil {
		t.Fatal("foreign wrapper bound")
	}
}
func TestMonitorCallbackSelfCloseAndFirstErrors(t *testing.T) {
	closeErr := errors.New("native close")
	platform := &monitorTestPlatform{closeError: closeErr}
	w := &platformInterfaceWrapper{iif: platform}
	m := createBoundMonitor(t, w, &monitorTestManager{}, true)
	var selfError error
	m.RegisterCallback(func(*control.Interface, int) { selfError = m.Close() })
	m.UpdateDefaultInterface("", -1, false, false)
	if selfError != closeErr || m.Close() != closeErr || platform.closes.Load() != 1 || m.inFlight != 0 {
		t.Fatal("close error/self-close changed")
	}
	startErr := errors.New("native start")
	platform = &monitorTestPlatform{startError: startErr, closeError: closeErr}
	w = &platformInterfaceWrapper{iif: platform}
	m = createBoundMonitor(t, w, &monitorTestManager{}, false)
	if m.start(nil) != startErr || w.activeMonitor != nil || !m.sealed || m.closeError != closeErr {
		t.Fatal("partial Start lost original error or remained live")
	}
}
func TestMonitorNativeIdentityAndSynchronousInitialUpdate(t *testing.T) {
	p := &monitorTestPlatform{onStart: func(l InterfaceUpdateListener) { l.UpdateDefaultInterface("", -1, false, false) }}
	w := &platformInterfaceWrapper{iif: p}
	a := &monitorTestManager{}
	first := createBoundMonitor(t, w, a, true)
	second := createBoundMonitor(t, w, &monitorTestManager{}, false)
	if a.calls.Load() != 1 {
		t.Fatal("synchronous initial callback was rejected")
	}
	if InterfaceUpdateListenerIdentity(first) == "" || InterfaceUpdateListenerIdentity(first) == InterfaceUpdateListenerIdentity(second) {
		t.Fatal("native identities reused")
	}
	var nilMonitor *platformDefaultInterfaceMonitor
	if InterfaceUpdateListenerIdentity(nil) != "" || InterfaceUpdateListenerIdentity(nilMonitor) != "" {
		t.Fatal("invalid identity accepted")
	}
}

type monitorForeignListener struct{}

func (monitorForeignListener) UpdateDefaultInterface(string, int32, bool, bool) {}
func (monitorForeignListener) UpdateNetworkPath(string)                         {}
func TestMonitorRejectForeignAndUnbound(t *testing.T) {
	if InterfaceUpdateListenerIdentity(monitorForeignListener{}) != "" {
		t.Fatal("foreign listener gained native identity")
	}
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m := w.CreateDefaultInterfaceMonitor(logger.NOP()).(*platformDefaultInterfaceMonitor)
	if m.Start() == nil {
		t.Fatal("unbound monitor started")
	}
	if w.Initialize(&monitorTestManager{monitor: (*platformDefaultInterfaceMonitor)(nil)}) == nil {
		t.Fatal("typed nil monitor bound")
	}
}

// A joining fake mirrors dnsinfo.Watcher.Close without native DNS/network writes.
type monitorTestDNSWatcher struct {
	callback   func()
	access     sync.Mutex
	closed     bool
	closes     atomic.Int32
	closeError error
}

func (w *monitorTestDNSWatcher) notify() {
	w.access.Lock()
	defer w.access.Unlock()
	if !w.closed {
		w.callback()
	}
}
func (w *monitorTestDNSWatcher) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	w.closes.Add(1)
	return w.closeError
}
func readTestMonitorDNS(manager adapter.NetworkManager, _ int) []string {
	return append([]string(nil), manager.NetworkInterfaces()[0].DNSServers...)
}

func attachTestDNSWatcher(t *testing.T, m *platformDefaultInterfaceMonitor) *monitorTestDNSWatcher {
	t.Helper()
	watcher := &monitorTestDNSWatcher{}
	if err := m.startDNSWatcher(func(callback func()) (io.Closer, error) {
		watcher.callback = callback
		return watcher, nil
	}, func() { m.refreshDNSServers(readTestMonitorDNS) }); err != nil {
		t.Fatal(err)
	}
	return watcher
}
func TestMonitorDNSChangeWithoutInterfaceEvent(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m, manager, expected := successorMonitor(t, w)
	servers := []string{"192.0.2.1"}
	manager.dnsRead = func() []string { return servers }
	callbacks := 0
	m.RegisterCallback(func(value *control.Interface, _ int) {
		if value != nil && value != expected {
			t.Fatal("DNS update changed interface")
		}
		callbacks++
	})
	m.refreshDNSServers(readTestMonitorDNS)
	m.refreshDNSServers(readTestMonitorDNS)
	servers[0] = "192.0.2.2"
	m.publishDefaultInterface(expected, readTestMonitorDNS(manager, 12))
	if callbacks != 2 {
		t.Fatalf("DNS-only changes delivered %d callbacks, want 2", callbacks)
	}
	m.publishDefaultInterface(nil, nil)
	if m.defaultDNSServers != nil {
		t.Fatal("lost interface retained DNS")
	}
}
func TestMonitorDNSWatcherCallbackCanCloseItself(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m, manager, _ := successorMonitor(t, w)
	manager.dnsRead = func() []string { return []string{"192.0.2.1"} }
	watcher := attachTestDNSWatcher(t, m)
	done := make(chan error, 1)
	m.RegisterCallback(func(*control.Interface, int) { done <- m.Close() })
	watcher.notify()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS callback deadlocked closing its own watcher")
	}
	if watcher.closes.Load() != 1 {
		t.Fatal("watcher not closed once")
	}
	if err := m.Close(); err != nil || watcher.closes.Load() != 1 {
		t.Fatal("repeated close reopened watcher")
	}
}
func TestMonitorDNSReadClosedAIsolatedFromB(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	old, manager, _ := successorMonitor(t, w)
	entered, resume := make(chan struct{}), make(chan struct{})
	manager.dnsRead = func() []string { close(entered); <-resume; return []string{"192.0.2.1"} }
	callbacks := 0
	old.RegisterCallback(func(*control.Interface, int) { callbacks++ })
	done := make(chan struct{})
	go func() { old.refreshDNSServers(readTestMonitorDNS); close(done) }()
	<-entered
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	current, next, expected := successorMonitor(t, w)
	close(resume)
	<-done
	old.refreshDNSServers(readTestMonitorDNS)
	assertSuccessor(t, w, current, next, expected)
	if callbacks != 0 || old.inFlight != 0 {
		t.Fatal("sealed DNS read published callbacks or leaked admission")
	}
}
func TestMonitorDNSWatcherCreationRacingClose(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m, _, _ := successorMonitor(t, w)
	entered, resume := make(chan struct{}), make(chan struct{})
	watcher := &monitorTestDNSWatcher{}
	done := make(chan error, 1)
	go func() {
		done <- m.startDNSWatcher(func(callback func()) (io.Closer, error) {
			watcher.callback = callback
			close(entered)
			<-resume
			return watcher, nil
		}, func() { m.refreshDNSServers(readTestMonitorDNS) })
	}()
	<-entered
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	close(resume)
	if err := <-done; err == nil {
		t.Fatal("late watcher revived sealed monitor")
	}
	if watcher.closes.Load() != 1 || m.dnsWatcher != nil || m.dnsStop != nil {
		t.Fatal("late watcher leaked")
	}
}
func TestMonitorDNSWatcherCloseErrorRetained(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m, _, _ := successorMonitor(t, w)
	watcher := attachTestDNSWatcher(t, m)
	watcher.closeError = errors.New("DNS watcher close")
	if err := m.Close(); !errors.Is(err, watcher.closeError) {
		t.Fatal("first DNS watcher close failure lost")
	}
	if err := m.Close(); !errors.Is(err, watcher.closeError) {
		t.Fatal("repeated DNS watcher close failure lost")
	}
	if watcher.closes.Load() != 1 {
		t.Fatal("DNS watcher was closed more than once")
	}
}

func TestMonitorDNSReadCannotOverwriteChangedInterface(t *testing.T) {
	w := &platformInterfaceWrapper{iif: &monitorTestPlatform{}}
	m, manager, _ := successorMonitor(t, w)
	entered, resume := make(chan struct{}), make(chan struct{})
	manager.dnsRead = func() []string { close(entered); <-resume; return []string{"192.0.2.1"} }
	done := make(chan struct{})
	go func() { m.refreshDNSServers(readTestMonitorDNS); close(done) }()
	<-entered
	replacement := &control.Interface{Name: "replacement", Index: 13}
	m.publishDefaultInterface(replacement, []string{"192.0.2.2"})
	callbacks := 0
	m.RegisterCallback(func(*control.Interface, int) { callbacks++ })
	close(resume)
	<-done
	if callbacks != 0 || m.DefaultInterface() != replacement || len(m.defaultDNSServers) != 1 || m.defaultDNSServers[0] != "192.0.2.2" {
		t.Fatal("stale DNS read replaced current interface/DNS")
	}
}
func TestMonitorDNSWatcherStartFailureRevokesProjection(t *testing.T) {
	platform := &monitorTestPlatform{}
	w := &platformInterfaceWrapper{iif: platform}
	m := createBoundMonitor(t, w, &monitorTestManager{}, false)
	failure := errors.New("DNS watcher registration")
	err := m.start(func(func()) (io.Closer, error) { return nil, failure })
	if !errors.Is(err, failure) || !m.sealed || w.activeMonitor != nil || platform.starts.Load() != 0 || platform.closes.Load() != 1 {
		t.Fatal("watcher start failure retained active monitor or started platform")
	}
}
func TestMonitorPlatformStartFailureClosesDNSWatcher(t *testing.T) {
	failure := errors.New("platform start")
	platform := &monitorTestPlatform{startError: failure}
	w := &platformInterfaceWrapper{iif: platform}
	m := createBoundMonitor(t, w, &monitorTestManager{}, false)
	watcher := &monitorTestDNSWatcher{}
	err := m.start(func(callback func()) (io.Closer, error) { watcher.callback = callback; return watcher, nil })
	if err != failure || !m.sealed || w.activeMonitor != nil || watcher.closes.Load() != 1 || platform.closes.Load() != 1 {
		t.Fatal("platform start failure retained watcher or lost error")
	}
}
