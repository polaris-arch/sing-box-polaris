// Package runtimeclock owns one exact graph's NTP sampling and optional clock
// write callback. It uses the pinned public NTP exchange, not its unjoined
// service worker or synchronous-under-pause-lock ticker callback.
package runtimeclock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ ntp.TimeService = (*Service)(nil)

type Service struct {
	ctx         context.Context
	cancel      context.CancelFunc
	source      adapter.RuntimeResourceSource
	logger      logger.Logger
	options     option.NTPOptions
	server      M.Socksaddr
	interval    time.Duration
	writeSystem func(context.Context, time.Time) error
	offset      atomic.Int64
	fence       *outbound.RuntimeIOFence
	callbacks   *outbound.RuntimeIOFence
	beginOwned  func(context.Context) (context.Context, func(), error)
	activate    chan struct{}
	changed     chan struct{}
	pause       pause.Manager
	// The private factory is fixed by New; fixtures replace it before Prepare.
	newDialer          func(context.Context, option.DialerOptions, bool) (N.Dialer, error)
	mu                 sync.Mutex
	stopped            bool
	activated          bool
	bootstrapDone      chan struct{}
	bootstrapErr       error
	bootstrapAttempted bool
	prepared           bool
	prepareDone        chan struct{}
	prepareReturned    bool
	prepareErr         error
	dialer             N.Dialer
	pauseCallback      *list.Element[pause.Callback]
	loopDone           chan struct{}
	cleanupErr         error
	failedConnections  []*exchangeConnection
}

// New is inert: no dialer construction, socket, timer, callback registration,
// goroutine, NTP exchange, security-policy invocation or system-clock write.
// It registers each owned fence once in the constructor's existing Scope.
func New(ctx context.Context, log logger.Logger, options option.NTPOptions, writeSystem func(context.Context, time.Time) error) (*Service, error) {
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok || source.ID() == (adapter.RuntimeResourceID{}) || !adapter.HasConstructionScope(ctx) {
		return nil, errors.New("NTP requires its constructor resource and scope")
	}
	if options.WriteToSystem && writeSystem == nil {
		return nil, errors.New("NTP write_to_system requires its graph owner's clock writer")
	}
	if log == nil {
		log = logger.NOP()
	}
	options = cloneOptions(options)
	server := options.ServerOptions.Build()
	if !server.IsValid() {
		server = M.Socksaddr{Fqdn: "time.apple.com"}
	}
	if server.Port == 0 {
		server.Port = 123
	}
	interval := time.Duration(options.Interval)
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{ctx: ctx, cancel: cancel, source: source, logger: log, options: options, server: server, interval: interval, writeSystem: writeSystem, activate: make(chan struct{}), changed: make(chan struct{}, 1), pause: service.FromContext[pause.Manager](ctx), newDialer: dialer.New}
	s.callbacks = outbound.NewRuntimeIOFence(nil)
	if _, err := outbound.RegisterRuntimeOwnedFence(ctx, s.callbacks); err != nil {
		cancel()
		return nil, err
	}
	s.fence = outbound.NewRuntimeIOFence(s.closeOwned)
	begin, err := outbound.RegisterRuntimeOwnedFence(ctx, s.fence)
	if err != nil {
		cancel()
		return nil, err
	}
	s.beginOwned = begin
	return s, nil
}

// Prepare is shared and sticky. Candidate managers and DNS policies must be
// initialized before this call; their exact handles are captured by the dialer.
// The prepared worker cannot sample time or invoke a writer until activation.
func (s *Service) Prepare() error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.prepareDone != nil {
		done := s.prepareDone
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		err := s.prepareErr
		s.mu.Unlock()
		return err
	}
	s.prepareDone = make(chan struct{})
	done := s.prepareDone
	s.prepareErr = errors.New("NTP preparation did not complete")
	s.mu.Unlock()
	defer close(done)
	if s.options.WriteToSystem {
		err = adapter.CheckSecurityFeature(s.ctx, "NTP `write_to_system`")
	}
	var preparedDialer N.Dialer
	if err == nil {
		err = s.ctx.Err()
	}
	if err == nil {
		preparedDialer, err = s.newDialer(s.ctx, s.options.DialerOptions, s.server.IsDomain())
	}
	if err == nil && preparedDialer == nil {
		err = errors.New("NTP dialer constructor returned nil")
	}
	if err == nil {
		err = s.ctx.Err()
	}
	var callback *list.Element[pause.Callback]
	if err == nil && s.pause != nil {
		callback = s.pause.RegisterCallback(s.onPauseEvent)
	}
	s.mu.Lock()
	s.dialer, s.pauseCallback = preparedDialer, callback
	if err == nil {
		err = s.ctx.Err()
	}
	if err == nil && s.stopped {
		err = net.ErrClosed
	}
	s.prepareErr, s.prepareReturned, s.prepared = err, true, err == nil
	if err == nil {
		s.loopDone = make(chan struct{})
		go s.run(s.loopDone)
	}
	s.mu.Unlock()
	return err
}

func (s *Service) RuntimeResourceID() adapter.RuntimeResourceID { return s.source.ID() }
func (s *Service) RuntimeValidate() error {
	if s.source == nil || s.fence == nil || s.beginOwned == nil {
		return errors.New("NTP lacks its owned runtime boundary")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return net.ErrClosed
	}
	if s.prepareDone != nil && s.prepareReturned {
		return s.prepareErr
	}
	return nil
}

// BootstrapOffset performs the one synchronous sample needed by a staged
// certificate issuer. It never activates periodic work or invokes a system
// writer, and only a fresh prepared clock may make this attempt. Construction,
// Plan and Prepare remain inert. The same exact owner fences/join cover this IO.
// A joined ordinary sample failure preserves the legacy best-effort offset (or
// system time); cancellation, ownership and unknown cleanup still fail staging.
func (s *Service) BootstrapOffset(request context.Context) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	s.mu.Lock()
	if !s.prepared || s.stopped || s.activated || s.options.WriteToSystem {
		s.mu.Unlock()
		return errors.New("clock offset bootstrap requires a private prepared offset-only owner")
	}
	if s.bootstrapDone != nil {
		done := s.bootstrapDone
		s.mu.Unlock()
		select {
		case <-request.Done():
			return request.Err()
		case <-done:
		}
		s.mu.Lock()
		err := s.bootstrapErr
		s.mu.Unlock()
		return err
	}
	s.bootstrapDone = make(chan struct{})
	done := s.bootstrapDone
	s.bootstrapErr = errors.New("clock bootstrap did not complete")
	s.mu.Unlock()
	defer close(done)
	ctx, cancel := context.WithCancel(s.ctx)
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(request, func() { defer close(cancelDone); cancel() })
	defer func() {
		if !stop() {
			<-cancelDone
		}
		cancel()
	}()
	if err = request.Err(); err == nil {
		var release func()
		ctx, release, err = s.beginOwned(ctx)
		if err == nil {
			defer release()
			err = s.updateClock(ctx, request)
		}
	}
	s.mu.Lock()
	s.bootstrapErr, s.bootstrapAttempted = err, err == nil
	s.mu.Unlock()
	return err
}

// RuntimeActivate only opens the preallocated gate. It is safe for the
// publication participant; all effects execute on the already prepared worker.
func (s *Service) RuntimeActivate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.prepared || s.stopped || s.activated {
		return
	}
	s.activated = true
	close(s.activate)
}

func (s *Service) stop() { s.mu.Lock(); s.stopped = true; s.mu.Unlock(); s.cancel() }

func (s *Service) RuntimeStop()               { s.stop(); _ = s.callbacks.Close(); _ = s.fence.Close() }
func (s *Service) RuntimeCloseAndWait() error { return s.fence.RuntimeCloseAndWait() }
func (s *Service) closeOwned() error {
	s.stop()
	_ = s.callbacks.Close()
	s.mu.Lock()
	prepared := s.prepareDone
	s.mu.Unlock()
	if prepared != nil {
		<-prepared
	}
	s.mu.Lock()
	callback, done := s.pauseCallback, s.loopDone
	s.pauseCallback = nil
	s.mu.Unlock()
	// Unregister may take the pause manager lock. Never hold a service lock,
	// perform network I/O, or join a worker while holding that manager lock.
	if callback != nil {
		s.pause.UnregisterCallback(callback)
	}
	callbackErr := s.callbacks.RuntimeCloseAndWait()
	if done != nil {
		<-done
	}
	s.mu.Lock()
	err := errors.Join(s.cleanupErr, callbackErr)
	if s.prepareDone != nil && !s.prepareReturned {
		err = errors.Join(err, errors.New("NTP preparation completion unknown"))
	}
	s.mu.Unlock()
	if err != nil {
		return &cleanupError{cause: err}
	}
	return nil
}

// TimeFunc only reads immutable service state and one atomic offset. Captured
// old-graph readers cannot accidentally consult a replacement NTP service.
func (s *Service) TimeFunc() func() time.Time {
	return func() time.Time { return time.Now().Add(time.Duration(s.offset.Load())) }
}

func (s *Service) onPauseEvent(event int) {
	switch event {
	case pause.EventDevicePaused, pause.EventDeviceWake, pause.EventNetworkPause, pause.EventNetworkWake:
	default:
		return
	}
	leave, err := s.callbacks.Acquire()
	if err != nil {
		return
	}
	defer leave()
	// The pinned manager invokes this under its own lock. Bounded notification
	// is the entire callback: no logger, user callback, timer or manager reentry.
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *Service) isPaused() bool {
	return s.pause != nil && (s.pause.IsDevicePaused() || s.pause.IsNetworkPaused())
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (s *Service) run(done chan struct{}) {
	defer close(done)
	defer func() {
		if value := recover(); value != nil {
			s.recordCleanup(fmt.Errorf("NTP worker panicked; completion unknown: %v", value), nil)
		}
	}()
	select {
	case <-s.ctx.Done():
		return
	case <-s.activate:
	}
	ctx, leave, err := s.beginOwned(s.ctx)
	if err != nil {
		return
	}
	defer leave()
	// Discard preparation notifications. A synchronous certificate effect may
	// already have completed the one initial offset-only attempt. Otherwise
	// preserve the initial sample even if the device was already paused.
	select {
	case <-s.changed:
	default:
	}
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	bootstrapAttempted := s.bootstrapAttempted
	s.mu.Unlock()
	if !bootstrapAttempted {
		s.updateOnce(ctx, true)
	}
	if ctx.Err() != nil || s.hasCleanupError() {
		return
	}
	timer := time.NewTimer(s.interval)
	defer timer.Stop()
	if s.isPaused() {
		stopTimer(timer)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.changed:
			stopTimer(timer)
			// A partial device/network wake cannot resume while the other is paused.
			// Bursts coalesce to the current atomic state, rather than replaying I/O.
			if s.isPaused() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			s.updateOnce(ctx, false)
			if ctx.Err() != nil || s.hasCleanupError() {
				return
			}
			if !s.isPaused() {
				timer.Reset(s.interval)
			}
		case <-timer.C:
			if s.isPaused() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			s.updateOnce(ctx, false)
			if ctx.Err() != nil || s.hasCleanupError() {
				return
			}
			if !s.isPaused() {
				timer.Reset(s.interval)
			}
		}
	}
}

func (s *Service) updateOnce(ctx context.Context, initial bool) {
	err := s.update(ctx)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		if initial {
			s.logger.Error("initialize time: ", err)
		} else {
			s.logger.Error("update time: ", err)
		}
	} else {
		s.logger.Info("updated time: ", s.TimeFunc()().Local().Format(ntp.TimeLayout))
	}
}

func (s *Service) update(ctx context.Context) error { return s.updateClock(ctx, nil) }

func (s *Service) updateClock(ctx context.Context, bootstrapRequest context.Context) error {
	ctx, err := outbound.ContextForRuntimeOwnedSession(ctx, s.source)
	if err != nil {
		return err
	}
	response, err := s.exchange(ctx)
	if bootstrapRequest != nil {
		// Exchange has joined the actual carrier. The original request must be
		// checked synchronously: its AfterFunc may still be forwarding cancel.
		// This lock orders the private offset commit against RuntimeStop. Once
		// committed, a later cancellation cannot turn it into a failed attempt.
		s.mu.Lock()
		cancelErr := errors.Join(bootstrapRequest.Err(), s.ctx.Err(), ctx.Err())
		if cancelErr == nil && s.stopped {
			cancelErr = net.ErrClosed
		}
		if cancelErr == nil && err == nil {
			s.offset.Store(int64(response.ClockOffset))
		}
		s.mu.Unlock()
		if cancelErr != nil {
			return errors.Join(err, cancelErr)
		}
		if err == nil {
			return nil // bootstrap never crosses the system-writer boundary
		}
	}
	if err != nil {
		// Exchange has already joined its sole carrier before this branch. Only
		// identified network IO failures can retain the legacy best-effort time;
		// admission errors above and unknown/closed/canceled owners cannot.
		if bootstrapRequest != nil && ctx.Err() == nil && !s.hasCleanupError() && ordinaryBootstrapSampleFailure(err) {
			s.logger.Error("initialize time (using current offset): ", err)
			return nil
		}
		return err
	}
	var marker interface{ RuntimeCleanupIncomplete() bool }
	if err := ctx.Err(); err != nil {
		return err
	}
	// Keep the pinned service's protocol acceptance behavior. Response.Validate
	// is not newly imposed by the lifecycle migration.
	s.offset.Store(int64(response.ClockOffset))
	if s.options.WriteToSystem {
		if err := ctx.Err(); err != nil {
			return err
		}
		// The supplied owner callback serializes native clock writes with control
		// effects and checks that RuntimeResourceID is still a current member.
		err = s.writeSystem(ctx, s.TimeFunc()())
		if err == nil {
			s.offset.Store(0)
		} else if ctx.Err() == nil {
			s.logger.Error("write time to system: ", err)
		}
		if errors.As(err, &marker) && marker.RuntimeCleanupIncomplete() {
			s.recordCleanup(err, nil)
			return err
		}
	}
	return nil
}

// The deferred terminal join also runs if a carrier method panics. The run
// boundary records panic uncertainty separately; it never treats unwind alone
// as evidence that an unreturned native call completed.
func (s *Service) exchange(ctx context.Context) (response *ntp.Response, err error) {
	d := &exchangeDialer{upstream: s.dialer}
	defer func() {
		closeErr := d.closeAndWait()
		if closeErr != nil {
			s.recordCleanup(closeErr, d.connection)
		}
		var marker interface{ RuntimeCleanupIncomplete() bool }
		if errors.As(err, &marker) && marker.RuntimeCleanupIncomplete() {
			s.recordCleanup(err, d.connection)
		}
		err = errors.Join(err, closeErr)
	}()
	return ntp.Exchange(ctx, d, s.server)
}

// Inspect every wrapped/joined leaf; a network wrapper cannot launder an owner
// identity failure or a sibling cleanup/cancellation error. Pinned Exchange
// only returns dial/write/read failures: parseTime has no error return and the
// legacy service does not call Response.Validate. Do not widen that protocol.
func ordinaryBootstrapSampleFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return false
	}
	var incomplete interface{ RuntimeCleanupIncomplete() bool }
	if errors.As(err, &incomplete) && incomplete.RuntimeCleanupIncomplete() {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !ordinaryBootstrapSampleFailure(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return ordinaryBootstrapSampleFailure(child)
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrShortWrite) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	switch err.(type) {
	case syscall.Errno, *net.DNSError, *net.AddrError, net.InvalidAddrError:
		return true
	default:
		return false
	}
}

func (s *Service) recordCleanup(err error, conn *exchangeConnection) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.cleanupErr = errors.Join(s.cleanupErr, err)
	if conn != nil {
		s.failedConnections = append(s.failedConnections, conn)
	}
	s.mu.Unlock()
}

func (s *Service) hasCleanupError() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupErr != nil
}

type cleanupError struct{ cause error }

func (e *cleanupError) Error() string                { return fmt.Sprintf("NTP cleanup incomplete: %v", e.cause) }
func (*cleanupError) RuntimeCleanupIncomplete() bool { return true }

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneOptions(value option.NTPOptions) option.NTPOptions {
	value.Inet4BindAddress = clonePointer(value.Inet4BindAddress)
	value.Inet6BindAddress = clonePointer(value.Inet6BindAddress)
	value.UDPFragment = clonePointer(value.UDPFragment)
	value.NetworkStrategy = clonePointer(value.NetworkStrategy)
	value.NetworkType = slices.Clone(value.NetworkType)
	value.FallbackNetworkType = slices.Clone(value.FallbackNetworkType)
	value.DomainResolver = clonePointer(value.DomainResolver)
	if resolver := value.DomainResolver; resolver != nil {
		resolver.Policy = clonePointer(resolver.Policy)
		resolver.RewriteTTL = clonePointer(resolver.RewriteTTL)
		resolver.ClientSubnet = clonePointer(resolver.ClientSubnet)
	}
	return value
}
