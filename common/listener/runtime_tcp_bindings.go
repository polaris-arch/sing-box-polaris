package listener

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// Runtime TCP custody is independent of the legacy raw tcpListener field.
// A Windows protocol wildcard has exactly two members; all other shapes have
// one. specs is the frozen expected inventory, including missing restored binds.
type runtimeTCPSet struct {
	members  [2]*runtimeTCPMember
	count    int
	specs    [2]runtimeTCPBindSpec
	expected int
}

type runtimeTCPBindSpec struct {
	network         string
	address         netip.Addr
	port            uint16
	netns           string
	v6only          bool
	exclusive       bool
	narrowExclusive bool
}

type runtimeTCPMember struct {
	spec   runtimeTCPBindSpec
	socket net.Listener
	close  runtimeTCPClose
}

type runtimeTCPClose struct {
	once sync.Once
	done chan struct{}
	err  error
}

func newRuntimeTCPMember(spec runtimeTCPBindSpec, socket net.Listener) *runtimeTCPMember {
	return &runtimeTCPMember{spec: spec, socket: socket, close: runtimeTCPClose{done: make(chan struct{})}}
}

func (m *runtimeTCPMember) closeAndWait() error {
	m.close.once.Do(func() {
		defer close(m.close.done)
		defer func() {
			if recover() != nil {
				m.close.err = errors.New("runtime TCP socket close panicked; completion unknown")
			}
		}()
		if m.socket != nil {
			if err := m.socket.Close(); err != nil {
				// Do not let Scope's benign-close normalization erase the first failure.
				m.close.err = fmt.Errorf("runtime TCP socket close completion unknown: %v", err)
			}
		}
	})
	<-m.close.done
	return m.close.err
}

func (l *Listener) runtimeTCPMembers() []*runtimeTCPMember {
	r := l.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*runtimeTCPMember(nil), r.tcp.members[:r.tcp.count]...)
}

func (l *Listener) runtimeTCPExpected() []runtimeTCPBindSpec {
	r := l.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tcp.expected == 0 && common.Contains(l.network, N.NetworkTCP) {
		specs := l.runtimeTCPPlatformSpecs()
		r.tcp.expected = len(specs)
		copy(r.tcp.specs[:], specs)
	}
	return append([]runtimeTCPBindSpec(nil), r.tcp.specs[:r.tcp.expected]...)
}

func (l *Listener) addRuntimeTCPMember(m *runtimeTCPMember) error {
	r := l.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tcp.count == len(r.tcp.members) {
		return errors.New("runtime TCP member capacity exceeded")
	}
	for _, old := range r.tcp.members[:r.tcp.count] {
		if old == m || runtimeTCPSameEndpoint(old.spec, m.spec) {
			return errors.New("runtime TCP member already owned")
		}
	}
	r.tcp.members[r.tcp.count] = m
	r.tcp.count++
	return nil
}

func (l *Listener) removeRuntimeTCPMember(m *runtimeTCPMember) {
	r := l.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, old := range r.tcp.members[:r.tcp.count] {
		if old == m {
			copy(r.tcp.members[i:], r.tcp.members[i+1:r.tcp.count])
			r.tcp.count--
			r.tcp.members[r.tcp.count] = nil
			return
		}
	}
}

func runtimeTCPSameEndpoint(a, b runtimeTCPBindSpec) bool {
	return a.address == b.address && a.port == b.port && a.netns == b.netns &&
		runtimeTCPFamily(a) == runtimeTCPFamily(b) && a.v6only == b.v6only
}

func runtimeTCPFamily(s runtimeTCPBindSpec) int {
	if s.address.Unmap().Is4() {
		return 4
	}
	return 6
}

func runtimeTCPConflict(a, b runtimeTCPBindSpec) bool {
	if a.port == 0 || a.port != b.port || a.netns != b.netns {
		return false
	}
	af, bf := runtimeTCPFamily(a), runtimeTCPFamily(b)
	if af != bf {
		// Only a non-V6ONLY IPv6 wildcard can cover the other physical family.
		return af == 6 && a.address.IsUnspecified() && !a.v6only || bf == 6 && b.address.IsUnspecified() && !b.v6only
	}
	return a.address.IsUnspecified() || b.address.IsUnspecified() || a.address.Unmap() == b.address.Unmap()
}

func sameRuntimeTCPOptions(a, b *Listener, as, bs runtimeTCPBindSpec) bool {
	if !runtimeTCPSameEndpoint(as, bs) || as.exclusive != bs.exclusive || as.narrowExclusive != bs.narrowExclusive {
		return false
	}
	left, right := freezeListenOptions(a.listenOptions), freezeListenOptions(b.listenOptions)
	// Endpoint equality is physical, rather than logical listen-list position.
	left.Listen, right.Listen = nil, nil
	left.ListenPort, right.ListenPort = 0, 0
	left.Detour, right.Detour = "", ""
	left.UDPTimeout, right.UDPTimeout = 0, 0
	left.UDPFragment, right.UDPFragment = nil, nil
	left.UDPFragmentDefault, right.UDPFragmentDefault = false, false
	return reflect.DeepEqual(left, right) && a.exclusive == b.exclusive && a.tproxy == b.tproxy && !a.setSystemProxy && !b.setSystemProxy
}

func runtimeTCPInterruptible(m *runtimeTCPMember) bool {
	_, ok := m.socket.(interface{ SetDeadline(time.Time) error })
	return ok
}

func (l *Listener) hasRuntimeTCPMember(spec runtimeTCPBindSpec) bool {
	for _, m := range l.runtimeTCPMembers() {
		if m.socket != nil && runtimeTCPSameEndpoint(m.spec, spec) && m.spec.exclusive == spec.exclusive && m.spec.narrowExclusive == spec.narrowExclusive {
			return true
		}
	}
	return false
}

func (l *Listener) validateRuntimeTCPComplete() error {
	expected := l.runtimeTCPExpected()
	members := l.runtimeTCPMembers()
	if len(expected) != len(members) {
		return errors.New("runtime TCP binding inventory is incomplete")
	}
	for _, spec := range expected {
		if !l.hasRuntimeTCPMember(spec) {
			return errors.New("runtime TCP binding differs from expected inventory")
		}
	}
	return nil
}

func (l *Listener) prepareRuntimeTCPMember(spec runtimeTCPBindSpec) error {
	if l.hasRuntimeTCPMember(spec) {
		return nil
	}
	member := newRuntimeTCPMember(spec, nil)
	// Reserve custody before the syscall. Once bind succeeds the first action is
	// storing its descriptor; no Addr, readback or callback can precede ownership.
	if err := l.addRuntimeTCPMember(member); err != nil {
		return err
	}
	socket, err := l.listenTCPWithSpec(&spec)
	if err != nil {
		l.removeRuntimeTCPMember(member)
		return err
	}
	member.socket = socket
	// The port chosen by the first real bind is frozen for every sibling.
	actualAddr := socket.Addr()
	actual, ok := actualAddr.(*net.TCPAddr)
	if !ok || actual.Port <= 0 || actual.Port > 65535 {
		return &net.OpError{Op: "listen", Net: spec.network, Addr: actualAddr, Err: errors.New("runtime TCP bind has no actual TCP port")}
	}
	member.spec.port = uint16(actual.Port)
	r := l.runtime
	r.mu.Lock()
	if l.listenOptions.ListenPort == 0 {
		for i := 0; i < r.tcp.expected; i++ {
			r.tcp.specs[i].port = member.spec.port
		}
	}
	r.mu.Unlock()
	// Ownership precedes every fallible readback and the next actual bind.
	if err = l.validateRuntimeTCPMember(member); err != nil {
		return &net.OpError{Op: "listen", Net: spec.network, Addr: socket.Addr(), Err: err}
	}
	l.logger.Debug("candidate tcp socket bound at ", socket.Addr())
	return nil
}

func (l *Listener) prepareRuntimeTCP() error {
	for index := 0; index < len(l.runtimeTCPExpected()); index++ {
		// Re-read after each bind so port0 siblings use the selected actual port.
		spec := l.runtimeTCPExpected()[index]
		if err := l.prepareRuntimeTCPMember(spec); err != nil {
			return err
		}
	}
	return l.validateRuntimeTCPComplete()
}

func moveRuntimeTCPMember(from, to *Listener, m *runtimeTCPMember) error {
	from.runtime.mu.Lock()
	phase := from.runtime.phase
	from.runtime.mu.Unlock()
	if phase != "paused" && phase != "prepared" {
		return ErrRuntimeTransition
	}
	to.runtime.mu.Lock()
	phase = to.runtime.phase
	to.runtime.mu.Unlock()
	if phase != "inert" && phase != "released" && phase != "prepared" && phase != "paused" {
		return ErrRuntimeTransition
	}
	owned := false
	for _, candidate := range from.runtimeTCPMembers() {
		if candidate == m {
			owned = true
		}
	}
	if !owned {
		return errors.New("runtime TCP transfer source does not own member")
	}
	if err := to.addRuntimeTCPMember(m); err != nil {
		return err
	}
	from.removeRuntimeTCPMember(m)
	return nil
}

func (l *Listener) closeRuntimeTCPMembers(includeHeld bool) error {
	var err error
	for _, m := range l.runtimeTCPMembers() {
		if !includeHeld && m.spec.narrowExclusive {
			continue
		}
		closeErr := m.closeAndWait()
		err = errors.Join(err, closeErr)
		if closeErr == nil {
			l.removeRuntimeTCPMember(m)
		}
	}
	return err
}

// Set staging and old restoration already have an owning compensation record.
// On failure keep that partial inventory intact: ordinary Prepare's automatic
// close would destroy transferred members or an old held IPv6 sibling.
func (l *Listener) prepareRuntimeForSet() error {
	if err := l.ValidateRuntime(); err != nil {
		return err
	}
	r := l.runtime
	r.mu.Lock()
	if r.phase != "inert" && r.phase != "released" && r.phase != "prepared" && r.phase != "paused" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	r.phase = "preparing"
	r.mu.Unlock()
	err := runtimePrepareCall(func() error {
		var err error
		if r.prepareSockets != nil {
			err = r.prepareSockets()
		} else {
			if common.Contains(l.network, N.NetworkTCP) {
				err = l.prepareRuntimeTCP()
			}
			if err == nil && common.Contains(l.network, N.NetworkUDP) && l.udpConn == nil {
				_, err = l.listenUDPWithConfig(net.ListenConfig{})
			}
		}
		return err
	})
	if err == nil {
		err = l.validateRuntimeTCPComplete()
	}
	r.mu.Lock()
	if err == nil {
		r.phase = "prepared"
	} else {
		r.phase = "failed"
	}
	r.mu.Unlock()
	return err
}

// Foreign socket failures are non-filterable and remain charged to the owner.
func runtimeSocketCall(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime socket operation panicked; completion unknown")
		}
	}()
	if cause := call(); cause != nil {
		return fmt.Errorf("runtime socket operation failed: %v", cause)
	}
	return nil
}

func runtimePrepareCall(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime listener preparation panicked; owned cleanup required")
		}
	}()
	return call()
}
