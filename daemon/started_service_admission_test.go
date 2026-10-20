package daemon

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/observable"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func admissionTestService(t *testing.T) *StartedService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	subscriber := observable.NewSubscriber[*ServiceStatus](4)
	observer := observable.NewObserver(subscriber, 2)
	s := &StartedService{
		ctx: ctx,
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTING},
		serviceStatusSubscriber: subscriber,
		serviceStatusObserver: observer,
	}
	t.Cleanup(func() { cancel(); _ = observer.Close() })
	return s
}

func admissionAwait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("admission operation did not finish")
		return context.DeadlineExceeded
	}
}

func TestStartedAdmissionRejectsDetachedOrHalfStartedSnapshot(t *testing.T) {
	for _, next := range []ServiceStatus_Type{ServiceStatus_STOPPING, ServiceStatus_STARTING, ServiceStatus_STARTED} {
		t.Run(next.String(), func(t *testing.T) {
			old := &Instance{ctx: context.Background()}
			s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}, instance: old}
			if err := s.waitForStarted(context.Background()); err != nil { t.Fatal(err) }
			// Reproduce the lifecycle write between the completed wait and the
			// actual capture. STARTED + nil also fails closed defensively.
			s.serviceAccess.Lock()
			s.serviceStatus = &ServiceStatus{Status: next}
			s.instance = nil
			if next == ServiceStatus_STARTING { s.instance = &Instance{ctx: context.Background()} }
			s.serviceAccess.Unlock()
			instance, err := s.readStartedInstance()
			if instance != nil || status.Code(err) != codes.Unavailable { t.Fatalf("detached instance admitted: %v %v", instance, err) }
		})
	}
}

func TestStartedAdmissionPinsPointerAndAllowsReusableService(t *testing.T) {
	old := &Instance{ctx: context.Background()}
	s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}, instance: old}
	captured, err := s.startedInstance(context.Background())
	if err != nil || captured != old { t.Fatalf("capture: %v %v", captured, err) }
	done := make(chan struct{})
	replacement := &Instance{ctx: context.Background()}
	go func() {
		s.serviceAccess.Lock()
		s.instance = replacement
		s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
		s.serviceAccess.Unlock()
		close(done)
	}()
	select { case <-done: case <-time.After(5*time.Second): t.Fatal("capture retained lifecycle lock") }
	if captured != old { t.Fatal("admitted pointer retargeted") }
	again, err := s.startedInstance(context.Background())
	if err != nil || again != replacement { t.Fatalf("reusable service rejected: %v", err) }
	replacement.closeStarted.Store(true)
	if _, err = s.readStartedInstance(); status.Code(err) != codes.Unavailable { t.Fatal("closing instance admitted") }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if _, err = s.startedInstance(ctx); !errors.Is(err, context.Canceled) { t.Fatalf("request cancellation lost: %v", err) }
}

func TestWaitForStartedRechecksAfterNotificationAlreadyDrained(t *testing.T) {
	s := admissionTestService(t)
	ack, _, err := s.serviceStatusObserver.Subscribe()
	if err != nil { t.Fatal(err) }
	defer s.serviceStatusObserver.UnSubscribe(ack)
	// The first STARTING snapshot has occurred. Finish the transition and drain
	// its notification before entering the exact production subscription phase.
	s.serviceAccess.Lock()
	s.updateStatus(ServiceStatus_STARTED)
	s.serviceAccess.Unlock()
	select { case <-ack: case <-time.After(5*time.Second): t.Fatal("transition not drained") }
	done := make(chan error, 1)
	go func() { done <- s.waitForStartedAfterStarting(context.Background()) }()
	if err = admissionAwait(t, done); err != nil { t.Fatalf("missed completed start: %v", err) }
}

func TestWaitForStartedCancellationAndTerminalSnapshots(t *testing.T) {
	for _, terminal := range []ServiceStatus_Type{ServiceStatus_IDLE, ServiceStatus_STOPPING, ServiceStatus_FATAL} {
		s := admissionTestService(t)
		s.serviceAccess.Lock()
		s.serviceStatus = &ServiceStatus{Status: terminal, ErrorMessage: "start failed"}
		s.serviceAccess.Unlock()
		err := s.waitForStartedAfterStarting(context.Background())
		if terminal == ServiceStatus_FATAL {
			if status.Code(err) != codes.FailedPrecondition { t.Fatal(err) }
		} else if !errors.Is(err, os.ErrInvalid) { t.Fatal(err) }
	}
	s := admissionTestService(t)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if err := s.waitForStartedAfterStarting(ctx); !errors.Is(err, context.Canceled) { t.Fatal(err) }
	serviceCtx, serviceCancel := context.WithCancel(context.Background()); serviceCancel()
	s.ctx = serviceCtx
	if err := s.waitForStartedAfterStarting(context.Background()); !errors.Is(err, context.Canceled) { t.Fatal(err) }
}

type admissionStatusStream struct {
	grpc.ServerStream
	ctx context.Context
	sent chan *ServiceStatus
	release chan struct{}
	first sync.Once
}
func (s *admissionStatusStream) Context() context.Context { return s.ctx }
func (s *admissionStatusStream) Send(value *ServiceStatus) error {
	s.sent <- value
	s.first.Do(func() { <-s.release })
	return nil
}

func TestServiceStatusSnapshotDoesNotRegressToQueuedOldEventOrLockSend(t *testing.T) {
	s := admissionTestService(t)
	s.serviceAccess.Lock()
	s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	s.serviceAccess.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &admissionStatusStream{ctx: ctx, sent: make(chan *ServiceStatus, 4), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(stream.release) }) })
	done := make(chan error, 1)
	go func() { done <- s.SubscribeServiceStatus(&emptypb.Empty{}, stream) }()
	select {
	case initial := <-stream.sent:
		if initial.Status != ServiceStatus_STARTED { t.Fatal(initial) }
	case <-time.After(5*time.Second): t.Fatal("initial snapshot missing")
	}
	// Send is blocked. A lifecycle writer must still acquire the service lock.
	written := make(chan struct{})
	go func() { s.serviceAccess.Lock(); s.serviceAccess.Unlock(); close(written) }()
	select { case <-written: case <-time.After(5*time.Second): t.Fatal("Send holds lifecycle lock") }
	ack, _, err := s.serviceStatusObserver.Subscribe()
	if err != nil { t.Fatal(err) }
	defer s.serviceStatusObserver.UnSubscribe(ack)
	// Force an older queued notification to reach the stream while its newer
	// initial snapshot is in flight. The current immutable state stays STARTED.
	s.serviceStatusSubscriber.Emit(&ServiceStatus{Status: ServiceStatus_STARTING})
	select { case <-ack: case <-time.After(5*time.Second): t.Fatal("old notification not forwarded") }
	release.Do(func() { close(stream.release) })
	select {
	case next := <-stream.sent:
		if next.Status != ServiceStatus_STARTED { t.Fatalf("status regressed: %v", next) }
	case <-time.After(5*time.Second): t.Fatal("notification snapshot missing")
	}
	cancel()
	if err = admissionAwait(t, done); !errors.Is(err, context.Canceled) { t.Fatal(err) }
}

type admissionConnectionStream struct { grpc.ServerStream }
func (*admissionConnectionStream) Context() context.Context { return context.Background() }
func (*admissionConnectionStream) Send(*ConnectionEvents) error { panic("detached RPC reached Send") }

func TestSubscribeConnectionsRejectsMissingInstanceBeforeDereference(t *testing.T) {
	s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}}
	err := s.SubscribeConnections(&SubscribeConnectionsRequest{}, &admissionConnectionStream{})
	if status.Code(err) != codes.Unavailable { t.Fatalf("missing instance result: %v", err) }
}
