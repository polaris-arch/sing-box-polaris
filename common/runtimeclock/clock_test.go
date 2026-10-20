package runtimeclock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type clockFixture struct {
	s               *Service
	owner           *runtimegraph.ResourceOwner
	allowCloseError bool
}

func newClockFixture(t *testing.T, options option.NTPOptions, base logger.Logger, writer func(context.Context, time.Time) error, configure func(context.Context) context.Context) *clockFixture {
	t.Helper()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "ntp-fixture", Sequence: 1}, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	f := &clockFixture{owner: owner}
	t.Cleanup(func() {
		if f.s != nil {
			f.s.RuntimeStop()
		}
		owner.Seal()
		reservation.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := owner.WaitClosed(ctx)
		if f.allowCloseError {
			if err == nil {
				t.Error("expected sticky cleanup error disappeared")
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Error("owner did not reach its actual cleanup result", err)
			}
		} else if err != nil {
			t.Error(err)
		}
	})
	ctx := pause.WithDefaultManager(adapter.ContextWithRuntimePreparation(adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)))
	if configure != nil {
		ctx = configure(ctx)
	}
	f.s, err = New(ctx, base, options, writer)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func awaitClock(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(name + " did not complete")
	}
}

func cleanupClockGate(t *testing.T, gate chan struct{}, done <-chan struct{}) func() {
	t.Helper()
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		release()
		if done != nil {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("blocked fixture did not unwind")
			}
		}
	})
	return release
}

type clockDialer struct {
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d clockDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func (clockDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet-listen path")
}

func clockFactory(d N.Dialer) func(context.Context, option.DialerOptions, bool) (N.Dialer, error) {
	return func(context.Context, option.DialerOptions, bool) (N.Dialer, error) { return d, nil }
}

type clockAddress string

func (clockAddress) Network() string  { return "udp" }
func (a clockAddress) String() string { return string(a) }

type clockConn struct {
	blockRead    bool
	readEntered  chan struct{}
	closeEntered chan struct{}
	closeRelease chan struct{}
	closed       chan struct{}
	readOnce     sync.Once
	closeOnce    sync.Once
	closes       atomic.Int32
	closeErr     error
	response     bytes.Reader
}

func newClockConn(blockRead, blockClose bool) *clockConn {
	c := &clockConn{blockRead: blockRead, readEntered: make(chan struct{}), closeEntered: make(chan struct{}), closeRelease: make(chan struct{}), closed: make(chan struct{})}
	if !blockClose {
		close(c.closeRelease)
	}
	return c
}

func (c *clockConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	if c.blockRead {
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.response.Read(p)
}

func (c *clockConn) Write(p []byte) (int, error) {
	// Exercise the actual public Exchange parser using an in-memory NTP packet.
	// This is protocol fixture data, never a socket, DNS lookup or clock write.
	packet := make([]byte, 48)
	packet[0] = 0x24
	packet[1] = 1
	now := time.Now().Add(2 * time.Second)
	stamp := uint64(now.Unix()+2208988800)<<32 | uint64(now.Nanosecond())*(1<<32)/1000000000
	for _, offset := range []int{16, 32, 40} {
		binary.BigEndian.PutUint64(packet[offset:offset+8], stamp)
	}
	c.response.Reset(packet)
	return len(p), nil
}

func (c *clockConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closeEntered); <-c.closeRelease; close(c.closed) })
	return c.closeErr
}
func (*clockConn) LocalAddr() net.Addr              { return clockAddress("fixture-local:123") }
func (*clockConn) RemoteAddr() net.Addr             { return clockAddress("fixture-server:123") }
func (*clockConn) SetDeadline(time.Time) error      { return nil }
func (*clockConn) SetReadDeadline(time.Time) error  { return nil }
func (*clockConn) SetWriteDeadline(time.Time) error { return nil }

type clockLog struct {
	logger.Logger
	info chan struct{}
	fail chan string
}

func newClockLog() *clockLog {
	return &clockLog{Logger: logger.NOP(), info: make(chan struct{}, 8), fail: make(chan string, 8)}
}

func (l *clockLog) Info(...any) {
	select {
	case l.info <- struct{}{}:
	default:
	}
}

func (l *clockLog) Error(args ...any) {
	select {
	case l.fail <- fmt.Sprint(args...):
	default:
	}
}

type clockPolicy struct {
	calls atomic.Int32
	err   error
}

func (p *clockPolicy) CheckFeature(_ context.Context, feature string) error {
	if feature != "NTP `write_to_system`" {
		return errors.New("wrong security feature")
	}
	p.calls.Add(1)
	return p.err
}

func TestClockConstructorIsInertAndFreezesOptions(t *testing.T) {
	policy := "captured-policy"
	fragment := true
	options := option.NTPOptions{DomainResolver: &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Policy: &policy}, UDPFragment: &fragment, NetworkType: []option.InterfaceType{1}}
	f := newClockFixture(t, options, nil, nil, nil)
	s := f.s
	policy = "mutated"
	fragment = false
	options.NetworkType[0] = 2
	var calls atomic.Int32
	s.newDialer = func(_ context.Context, options option.DialerOptions, domain bool) (N.Dialer, error) {
		calls.Add(1)
		if !domain || *options.DomainResolver.Policy != "captured-policy" || !*options.UDPFragment || options.NetworkType[0] != 1 {
			t.Error("constructor did not freeze effective dialer inputs")
		}
		return clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			t.Error("dial before activation")
			return nil, net.ErrClosed
		}}, nil
	}
	if calls.Load() != 0 || s.prepareDone != nil || s.loopDone != nil || s.pauseCallback != nil {
		t.Fatal("constructor performed preparation")
	}
	if s.server.Fqdn != "time.apple.com" || s.server.Port != 123 || s.interval != 30*time.Minute {
		t.Fatal("default NTP options changed")
	}
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("preparation repeated dialer construction")
	}
	if err := s.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	s.RuntimeActivate()
	if s.activated {
		t.Fatal("closed private candidate activated")
	}
}

func TestClockSecurityCheckOccursOnceInPrivatePreparation(t *testing.T) {
	denied := errors.New("fixture policy denial")
	policy := &clockPolicy{err: denied}
	f := newClockFixture(t, option.NTPOptions{WriteToSystem: true}, nil, func(context.Context, time.Time) error { t.Error("denied writer reached"); return nil }, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.SecurityPolicy](ctx, policy)
	})
	s := f.s
	s.newDialer = func(context.Context, option.DialerOptions, bool) (N.Dialer, error) {
		t.Error("dialer built after policy denial")
		return nil, nil
	}
	if policy.calls.Load() != 0 {
		t.Fatal("constructor invoked security policy")
	}
	for range 2 {
		if err := s.Prepare(); !errors.Is(err, denied) {
			t.Fatal("policy denial not preserved", err)
		}
	}
	if policy.calls.Load() != 1 || s.loopDone != nil {
		t.Fatal("denied preparation started or repeated work")
	}
	if err := s.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestClockCloseWaitsForActualPrepareReturn(t *testing.T) {
	f := newClockFixture(t, option.NTPOptions{}, nil, nil, nil)
	s := f.s
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := cleanupClockGate(t, finish, done)
	s.newDialer = func(context.Context, option.DialerOptions, bool) (N.Dialer, error) {
		close(entered)
		<-finish
		return clockDialer{}, nil
	}
	result := make(chan error, 1)
	go func() { defer close(done); result <- s.Prepare() }()
	awaitClock(t, entered, "private dialer construction")
	s.RuntimeStop()
	closed, closeDone := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { release(); awaitClock(t, closeDone, "close worker") })
	go func() { defer close(closeDone); closed <- s.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("close forgot the admitted prepare call")
	default:
	}
	release()
	awaitClock(t, done, "private prepare")
	if err := <-result; err == nil {
		t.Fatal("canceled preparation succeeded")
	}
	awaitClock(t, closeDone, "close worker")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if s.loopDone != nil || s.pauseCallback != nil {
		t.Fatal("late prepare scheduled an owned loop or callback")
	}
}

func TestClockCancellationClosesAndJoinsActualExchangeCarrier(t *testing.T) {
	f := newClockFixture(t, option.NTPOptions{}, nil, nil, nil)
	s := f.s
	c := newClockConn(true, true)
	closed, closeDone := make(chan error, 1), make(chan struct{})
	release := cleanupClockGate(t, c.closeRelease, nil)
	s.newDialer = clockFactory(clockDialer{dial: func(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
		if network != N.NetworkUDP || address != s.server {
			t.Error("NTP exchange destination changed")
		}
		if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, s.RuntimeResourceID()); !ok {
			t.Error("exchange lost exact owned resource")
		}
		return c, nil
	}})
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	s.RuntimeActivate()
	s.RuntimeActivate()
	awaitClock(t, c.readEntered, "public Exchange read")
	s.RuntimeStop()
	awaitClock(t, c.closeEntered, "actual cancellation close")
	t.Cleanup(func() { release(); awaitClock(t, closeDone, "terminal close") })
	go func() { defer close(closeDone); closed <- s.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("reported completion before actual Close returned")
	default:
	}
	release()
	awaitClock(t, closeDone, "terminal close")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if c.closes.Load() != 1 {
		t.Fatal("exchange carrier had duplicate terminal closes")
	}
	before := len(s.changed)
	s.onPauseEvent(pause.EventNetworkWake)
	if len(s.changed) != before {
		t.Fatal("late pause callback reached retired service")
	}
}

func TestClockJoinsLateDialResultAfterCancellation(t *testing.T) {
	f := newClockFixture(t, option.NTPOptions{}, nil, nil, nil)
	s := f.s
	c := newClockConn(false, false)
	entered, finish := make(chan struct{}), make(chan struct{})
	release := cleanupClockGate(t, finish, nil)
	s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { close(entered); <-finish; return c, nil }})
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	s.RuntimeActivate()
	awaitClock(t, entered, "actual dial")
	s.RuntimeStop()
	closed, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { release(); awaitClock(t, done, "late dial close") })
	go func() { defer close(done); closed <- s.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("close forgot unreturned dial")
	default:
	}
	release()
	awaitClock(t, done, "late dial close")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if c.closes.Load() != 1 {
		t.Fatal("late carrier was not closed exactly once")
	}
}

func TestClockJoinsConnectionReturnedAlongsideDialError(t *testing.T) {
	f := newClockFixture(t, option.NTPOptions{}, nil, nil, nil)
	s := f.s
	c := newClockConn(false, true)
	release := cleanupClockGate(t, c.closeRelease, nil)
	failure := errors.New("fixture dial failed after acquiring carrier")
	s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return c, failure }})
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	s.RuntimeActivate()
	awaitClock(t, c.closeEntered, "conn+error terminal close")
	s.RuntimeStop()
	closed, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { release(); awaitClock(t, done, "conn+error retirement") })
	go func() { defer close(done); closed <- s.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("dial-error carrier was discarded before actual close")
	default:
	}
	release()
	awaitClock(t, done, "conn+error retirement")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if c.closes.Load() != 1 {
		t.Fatal("dial-error carrier did not have one terminal close")
	}
}

func TestClockRetainsIgnoredExchangeCloseFailure(t *testing.T) {
	f := newClockFixture(t, option.NTPOptions{}, nil, nil, nil)
	f.allowCloseError = true
	s := f.s
	c := newClockConn(false, false)
	c.closeErr = errors.New("fixture actual close failure")
	s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return c, nil }})
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	s.RuntimeActivate()
	awaitClock(t, s.loopDone, "failed exchange worker")
	first := s.RuntimeCloseAndWait()
	second := s.RuntimeCloseAndWait()
	var marker interface{ RuntimeCleanupIncomplete() bool }
	if first == nil || second == nil || first.Error() != second.Error() || !errors.As(first, &marker) || !marker.RuntimeCleanupIncomplete() {
		t.Fatal("actual close failure was not sticky and nonfilterable")
	}
	if len(s.failedConnections) != 1 || c.closes.Load() != 1 {
		t.Fatal("failed carrier was forgotten or closed repeatedly")
	}
	if s.offset.Load() != 0 {
		t.Fatal("incomplete exchange published a clock correction")
	}
}

func TestClockSystemWriterIsActivatedOwnedAndActuallyJoined(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var s *Service
	var writes atomic.Int32
	f := newClockFixture(t, option.NTPOptions{WriteToSystem: true}, nil, func(ctx context.Context, _ time.Time) error {
		writes.Add(1)
		if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, s.RuntimeResourceID()); !ok {
			t.Error("writer lost exact owner continuation")
		}
		close(entered)
		<-finish
		return ctx.Err()
	}, nil)
	s = f.s
	release := cleanupClockGate(t, finish, nil)
	s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return newClockConn(false, false), nil }})
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 0 {
		t.Fatal("private candidate wrote system time")
	}
	s.RuntimeActivate()
	awaitClock(t, entered, "system writer")
	s.RuntimeStop()
	closed, done := make(chan error, 1), make(chan struct{})
	// This cleanup is registered after the fixture's owner cleanup, so every
	// early fatal path releases the writer before attempting to join its owner.
	t.Cleanup(func() { release(); awaitClock(t, done, "writer retirement") })
	go func() { defer close(done); closed <- s.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("retirement forgot admitted system writer")
	default:
	}
	release()
	awaitClock(t, done, "writer retirement")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("writer ran more than once")
	}
}

func TestClockSuccessfulWriteClearsAppliedOffsetAndFailedWriteKeepsIt(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			base := newClockLog()
			writerErr := errors.New("fixture clock write failure")
			f := newClockFixture(t, option.NTPOptions{WriteToSystem: true}, base, func(context.Context, time.Time) error {
				if fail {
					return writerErr
				}
				return nil
			}, nil)
			s := f.s
			s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return newClockConn(false, false), nil }})
			if err := s.Prepare(); err != nil {
				t.Fatal(err)
			}
			s.RuntimeActivate()
			awaitClock(t, base.info, "completed update")
			offset := time.Duration(s.offset.Load())
			if fail {
				if offset == 0 || len(base.fail) != 1 {
					t.Fatal("failed writer discarded correction or error")
				}
			} else if offset != 0 {
				t.Fatal("applied system correction was counted twice")
			}
		})
	}
}

func TestClockPauseWakeIsCoalescedAndNeverRunsWriterUnderPauseLock(t *testing.T) {
	base := newClockLog()
	entered, finish := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	f := newClockFixture(t, option.NTPOptions{WriteToSystem: true}, base, func(context.Context, time.Time) error {
		if writes.Add(1) == 2 {
			close(entered)
			<-finish
		}
		return nil
	}, nil)
	s := f.s
	release := cleanupClockGate(t, finish, nil)
	s.newDialer = clockFactory(clockDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return newClockConn(false, false), nil }})
	// Preparation callbacks can only leave one bounded notification and cannot
	// perform the immediate resume operation before the publication gate opens.
	if err := s.Prepare(); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		s.onPauseEvent(pause.EventNetworkWake)
	}
	if len(s.changed) != 1 || writes.Load() != 0 {
		t.Fatal("private wake burst escaped coalescing")
	}
	s.RuntimeActivate()
	awaitClock(t, base.info, "initial update")
	s.pause.DevicePause()
	wakeDone := make(chan struct{})
	t.Cleanup(func() { release(); awaitClock(t, wakeDone, "pause wake callback") })
	go func() { defer close(wakeDone); s.pause.DeviceWake() }()
	awaitClock(t, wakeDone, "pause wake callback")
	awaitClock(t, entered, "resumed owned writer")
	// The writer is still blocked, but pause manager operations remain callable.
	pauseDone := make(chan struct{})
	go func() { defer close(pauseDone); s.pause.NetworkPause() }()
	t.Cleanup(func() { release(); awaitClock(t, pauseDone, "second pause callback") })
	awaitClock(t, pauseDone, "second pause callback")
	if !s.isPaused() {
		t.Fatal("network pause state lost")
	}
	release()
	if err := s.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if s.pauseCallback != nil {
		t.Fatal("retired service kept its registered pause callback")
	}
}

func TestClockTimeFuncUsesItsOwnAtomicOffset(t *testing.T) {
	a := &Service{}
	b := &Service{}
	a.offset.Store(int64(time.Hour))
	b.offset.Store(int64(-time.Hour))
	aTime, bTime := a.TimeFunc(), b.TimeFunc()
	if aTime().Sub(bTime()) < 119*time.Minute {
		t.Fatal("independent clock generations shared an offset")
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 1000 {
				_ = aTime()
			}
		})
	}
	for i := range 1000 {
		a.offset.Store(int64(time.Duration(i)))
	}
	readers.Wait()
}
