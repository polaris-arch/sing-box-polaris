package libbox

import (
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/service/powerreport"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/dnsinfo"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

var (
	_ tun.DefaultInterfaceMonitor = (*platformDefaultInterfaceMonitor)(nil)
	_ InterfaceUpdateListener     = (*platformDefaultInterfaceMonitor)(nil)
)

// The identity is born in Go, independent of the Java proxy created for each call.
// Saturation fails closed rather than recycling an incarnation.
var interfaceMonitorIdentity atomic.Int64

func newInterfaceUpdateListenerIdentity() string {
	for {
		previous := interfaceMonitorIdentity.Load()
		if previous == math.MaxInt64 {
			return ""
		}
		if interfaceMonitorIdentity.CompareAndSwap(previous, previous+1) {
			return strconv.FormatInt(previous+1, 10)
		}
	}
}

// InterfaceUpdateListenerIdentity returns the immutable native monitor incarnation.
// Foreign listeners have no trusted monitor identity.
func InterfaceUpdateListenerIdentity(listener InterfaceUpdateListener) string {
	monitor, ok := listener.(*platformDefaultInterfaceMonitor)
	if !ok || monitor == nil {
		return ""
	}
	return monitor.identity
}

type platformDefaultInterfaceMonitor struct {
	platform                    *platformInterfaceWrapper
	logger                      logger.Logger
	identity                    string
	defaultInterfaceAccess      sync.Mutex
	networkManager              adapter.NetworkManager // assigned exactly once by Initialize
	started                     bool
	sealed                      bool
	inFlight                    int
	closeError                  error
	callbacks                   list.List[tun.DefaultInterfaceUpdateCallback]
	myInterfaces                []string
	defaultInterface            *control.Interface
	isExpensive                 bool
	isConstrained               bool
	defaultInterfaceInitialized bool
	defaultDNSServers           []string
	dnsWatcher                  io.Closer
	dnsStop                     chan struct{}
	lastNetworkPath             string
}

func (m *platformDefaultInterfaceMonitor) bind(manager adapter.NetworkManager) error {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	if m.networkManager != nil || m.sealed {
		return E.New("platform: interface monitor already bound or closed")
	}
	m.networkManager = manager
	return nil
}

func (w *platformInterfaceWrapper) monitorSnapshot() (*control.Interface, bool, bool) {
	w.monitorAccess.Lock()
	defer w.monitorAccess.Unlock()
	m := w.activeMonitor
	if m == nil {
		return nil, false, false
	}
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	return m.defaultInterface, m.isExpensive, m.isConstrained
}

func (m *platformDefaultInterfaceMonitor) Start() error {
	var create func(func()) (io.Closer, error)
	if C.IsDarwin {
		create = func(callback func()) (io.Closer, error) {
			return dnsinfo.NewWatcher(callback, m.logger)
		}
	}
	return m.start(create)
}

func (m *platformDefaultInterfaceMonitor) start(create func(func()) (io.Closer, error)) error {
	w := m.platform
	// Publish and seal use the same lock order. A Close racing Start cannot
	// leave a sealed monitor as the active projection. No platform call is locked.
	w.monitorAccess.Lock()
	m.defaultInterfaceAccess.Lock()
	if m.sealed || m.networkManager == nil || m.identity == "" {
		m.defaultInterfaceAccess.Unlock()
		w.monitorAccess.Unlock()
		return E.New("platform: interface monitor is closed or unbound")
	}
	if m.started {
		m.defaultInterfaceAccess.Unlock()
		w.monitorAccess.Unlock()
		return nil
	}
	m.started = true
	w.activeMonitor = m
	m.defaultInterfaceAccess.Unlock()
	w.monitorAccess.Unlock()
	if create != nil {
		if err := m.startDNSWatcher(create, m.updateDNSServers); err != nil {
			_ = m.Close()
			return E.Cause(err, "watch DNS configuration")
		}
	}
	err := w.iif.StartDefaultInterfaceMonitor(m)
	if err != nil {
		// Revoke partial platform publication; preserve the original start error.
		_ = m.Close()
	}
	return err
}

// The native watcher joins its notification loop on Close. Its callback must
// only enqueue: a consumer callback may close this monitor from the worker.
func (m *platformDefaultInterfaceMonitor) startDNSWatcher(create func(func()) (io.Closer, error), update func()) error {
	updates := make(chan struct{}, 1)
	watcher, err := create(func() {
		select {
		case updates <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return err
	}
	m.defaultInterfaceAccess.Lock()
	if m.sealed {
		m.defaultInterfaceAccess.Unlock()
		return E.Errors(E.New("platform: interface monitor closed while starting DNS watcher"), watcher.Close())
	}
	stop := make(chan struct{})
	m.dnsWatcher = watcher
	m.dnsStop = stop
	m.defaultInterfaceAccess.Unlock()
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-updates:
				update()
			}
		}
	}()
	return nil
}

func (m *platformDefaultInterfaceMonitor) Close() error {
	w := m.platform
	w.monitorAccess.Lock()
	m.defaultInterfaceAccess.Lock()
	if m.sealed {
		err := m.closeError
		m.defaultInterfaceAccess.Unlock()
		w.monitorAccess.Unlock()
		return err
	}
	m.sealed = true
	watcher := m.dnsWatcher
	m.dnsWatcher = nil
	if m.dnsStop != nil {
		close(m.dnsStop)
		m.dnsStop = nil
	}
	if w.activeMonitor == m {
		w.activeMonitor = nil
	}
	m.defaultInterfaceAccess.Unlock()
	w.monitorAccess.Unlock()
	// Even an unstarted monitor must publish its native revocation to Kotlin.
	// Do not join: a delivery callback can call Close itself.
	err := w.iif.CloseDefaultInterfaceMonitor(m)
	if watcher != nil {
		err = E.Errors(err, watcher.Close())
	}
	m.defaultInterfaceAccess.Lock()
	if m.closeError == nil {
		m.closeError = err
	}
	m.defaultInterfaceAccess.Unlock()
	return err
}

func (m *platformDefaultInterfaceMonitor) beginUpdate() adapter.NetworkManager {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	if m.sealed || !m.started || m.networkManager == nil {
		return nil
	}
	m.inFlight++
	return m.networkManager
}

func (m *platformDefaultInterfaceMonitor) finishUpdate() {
	m.defaultInterfaceAccess.Lock()
	m.inFlight--
	m.defaultInterfaceAccess.Unlock()
}

// Reports target a shared CommandServer recorder. Linearize these small local
// writes before successor publication; never read a current recorder after an
// old UpdateInterfaces/platform stack resumes.
func (m *platformDefaultInterfaceMonitor) report(update func(*powerreport.Recorder)) {
	w := m.platform
	w.monitorAccess.Lock()
	defer w.monitorAccess.Unlock()
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	if w.activeMonitor != m || m.sealed || w.powerManager == nil {
		return
	}
	if recorder := w.powerManager.Recorder(); recorder != nil {
		update(recorder)
	}
}

func (m *platformDefaultInterfaceMonitor) DefaultInterface() *control.Interface {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	return m.defaultInterface
}

func (m *platformDefaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return false
}

func (m *platformDefaultInterfaceMonitor) AndroidVPNEnabled() bool {
	return false
}

func (m *platformDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *platformDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	m.callbacks.Remove(element)
}

func (m *platformDefaultInterfaceMonitor) UpdateNetworkPath(networkPath string) {
	if m.beginUpdate() == nil {
		return
	}
	defer m.finishUpdate()
	m.defaultInterfaceAccess.Lock()
	changed := networkPath != m.lastNetworkPath
	m.lastNetworkPath = networkPath
	m.defaultInterfaceAccess.Unlock()
	if changed {
		m.logger.Debug("updated network path: ", networkPath)
	}
	m.report(func(recorder *powerreport.Recorder) { recorder.UpdateNetworkPath(networkPath) })
}

func (m *platformDefaultInterfaceMonitor) UpdateDefaultInterface(interfaceName string, interfaceIndex32 int32, isExpensive bool, isConstrained bool) {
	manager := m.beginUpdate()
	if manager == nil {
		return
	}
	if sFixAndroidStack {
		// Admission precedes the worker. Its actual exit owns the return count.
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer m.finishUpdate()
			m.updateDefaultInterface(manager, interfaceName, interfaceIndex32, isExpensive, isConstrained)
		}()
		<-done
	} else {
		defer m.finishUpdate()
		m.updateDefaultInterface(manager, interfaceName, interfaceIndex32, isExpensive, isConstrained)
	}
}

func (m *platformDefaultInterfaceMonitor) updateDefaultInterface(manager adapter.NetworkManager, interfaceName string, interfaceIndex32 int32, isExpensive bool, isConstrained bool) {
	m.report(func(recorder *powerreport.Recorder) {
		networkType := interfaceName
		if interfaceIndex32 == -1 {
			networkType = "none"
		} else {
			if isExpensive {
				networkType += ",expensive"
			}
			if isConstrained {
				networkType += ",constrained"
			}
		}
		recorder.UpdateNetworkType(networkType)
	})
	m.defaultInterfaceAccess.Lock()
	m.isExpensive = isExpensive
	m.isConstrained = isConstrained
	m.defaultInterfaceAccess.Unlock()
	if err := manager.UpdateInterfaces(); err != nil {
		m.logger.Error(E.Cause(err, "update interfaces"))
	}
	var newInterface *control.Interface
	if interfaceIndex32 != -1 {
		var err error
		newInterface, err = manager.InterfaceFinder().ByIndex(int(interfaceIndex32))
		if err != nil {
			m.logger.Error(E.Cause(err, "find updated interface: ", interfaceName))
			return
		}
	}
	var dnsServers []string
	if newInterface != nil {
		dnsServers = m.readDNSServers(manager, newInterface.Index)
	}
	m.publishDefaultInterface(newInterface, dnsServers)
}

func (m *platformDefaultInterfaceMonitor) publishDefaultInterface(newInterface *control.Interface, dnsServers []string) {
	m.defaultInterfaceAccess.Lock()
	oldDNSServers := m.defaultDNSServers
	m.defaultDNSServers = dnsServers
	oldInterface := m.defaultInterface
	m.defaultInterface = newInterface
	changed := newInterface == nil || !m.defaultInterfaceInitialized || oldInterface == nil || oldInterface.Name != newInterface.Name || oldInterface.Index != newInterface.Index || !slices.Equal(oldDNSServers, dnsServers)
	m.defaultInterfaceInitialized = true
	var callbacks []tun.DefaultInterfaceUpdateCallback
	if changed && !m.sealed {
		callbacks = m.callbacks.Array()
	}
	m.defaultInterfaceAccess.Unlock()
	for _, callback := range callbacks {
		callback(newInterface, 0)
	}
}

func (m *platformDefaultInterfaceMonitor) updateDNSServers() {
	m.refreshDNSServers(m.readDNSServers)
}

func (m *platformDefaultInterfaceMonitor) refreshDNSServers(read func(adapter.NetworkManager, int) []string) {
	manager := m.beginUpdate()
	if manager == nil {
		return
	}
	defer m.finishUpdate()
	m.defaultInterfaceAccess.Lock()
	defaultInterface := m.defaultInterface
	m.defaultInterfaceAccess.Unlock()
	if defaultInterface == nil {
		return
	}
	dnsServers := read(manager, defaultInterface.Index)
	m.defaultInterfaceAccess.Lock()
	// A read admitted before Close or an interface replacement belongs to the
	// captured instance/interface; it cannot publish into its successor.
	if m.sealed || m.defaultInterface != defaultInterface || slices.Equal(m.defaultDNSServers, dnsServers) {
		m.defaultInterfaceAccess.Unlock()
		return
	}
	m.defaultDNSServers = dnsServers
	callbacks := m.callbacks.Array()
	m.defaultInterfaceAccess.Unlock()
	for _, callback := range callbacks {
		callback(defaultInterface, 0)
	}
}

func (m *platformDefaultInterfaceMonitor) readDNSServers(manager adapter.NetworkManager, interfaceIndex int) []string {
	if C.IsDarwin {
		dnsConfiguration := dnsinfo.Copy()
		if dnsConfiguration == nil {
			return nil
		}
		return common.Map(dnsConfiguration.Select(interfaceIndex).Servers, func(it netip.AddrPort) string {
			return it.Addr().String()
		})
	}
	return append([]string(nil), common.Find(manager.NetworkInterfaces(), func(it adapter.NetworkInterface) bool {
		return it.Index == interfaceIndex
	}).DNSServers...)
}

func (m *platformDefaultInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	m.myInterfaces = append(m.myInterfaces, interfaceName)
}

func (m *platformDefaultInterfaceMonitor) MyInterfaces() []string {
	m.defaultInterfaceAccess.Lock()
	defer m.defaultInterfaceAccess.Unlock()
	return append([]string(nil), m.myInterfaces...)
}
