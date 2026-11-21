package daemon

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing/common/observable"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func admissionTestService(t *testing.T) *StartedService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	subscriber := observable.NewSubscriber[*ServiceStatus](4)
	observer := observable.NewObserver(subscriber, 2)
	s := &StartedService{
		ctx:                     ctx,
		serviceStatus:           &ServiceStatus{Status: ServiceStatus_STARTING},
		serviceStatusSubscriber: subscriber,
		serviceStatusObserver:   observer,
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
			if err := s.waitForStarted(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Reproduce the lifecycle write between the completed wait and the
			// actual capture. STARTED + nil also fails closed defensively.
			s.serviceAccess.Lock()
			s.serviceStatus = &ServiceStatus{Status: next}
			s.instance = nil
			if next == ServiceStatus_STARTING {
				s.instance = &Instance{ctx: context.Background()}
			}
			s.serviceAccess.Unlock()
			instance, err := s.readStartedInstance()
			if instance != nil || status.Code(err) != codes.Unavailable {
				t.Fatalf("detached instance admitted: %v %v", instance, err)
			}
		})
	}
}

func TestStartedAdmissionPinsPointerAndAllowsReusableService(t *testing.T) {
	old := &Instance{ctx: context.Background()}
	s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}, instance: old}
	captured, err := s.startedInstance(context.Background())
	if err != nil || captured != old {
		t.Fatalf("capture: %v %v", captured, err)
	}
	done := make(chan struct{})
	replacement := &Instance{ctx: context.Background()}
	go func() {
		s.serviceAccess.Lock()
		s.instance = replacement
		s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
		s.serviceAccess.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("capture retained lifecycle lock")
	}
	if captured != old {
		t.Fatal("admitted pointer retargeted")
	}
	again, err := s.startedInstance(context.Background())
	if err != nil || again != replacement {
		t.Fatalf("reusable service rejected: %v", err)
	}
	replacement.closeStarted.Store(true)
	if _, err = s.readStartedInstance(); status.Code(err) != codes.Unavailable {
		t.Fatal("closing instance admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.startedInstance(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("request cancellation lost: %v", err)
	}
}

func TestWaitForStartedRechecksAfterNotificationAlreadyDrained(t *testing.T) {
	s := admissionTestService(t)
	ack, _, err := s.serviceStatusObserver.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer s.serviceStatusObserver.UnSubscribe(ack)
	// The first STARTING snapshot has occurred. Finish the transition and drain
	// its notification before entering the exact production subscription phase.
	s.serviceAccess.Lock()
	s.updateStatus(ServiceStatus_STARTED)
	s.serviceAccess.Unlock()
	select {
	case <-ack:
	case <-time.After(5 * time.Second):
		t.Fatal("transition not drained")
	}
	done := make(chan error, 1)
	go func() { done <- s.waitForStartedAfterStarting(context.Background()) }()
	if err = admissionAwait(t, done); err != nil {
		t.Fatalf("missed completed start: %v", err)
	}
}

func TestWaitForStartedCancellationAndTerminalSnapshots(t *testing.T) {
	for _, terminal := range []ServiceStatus_Type{ServiceStatus_IDLE, ServiceStatus_STOPPING, ServiceStatus_FATAL} {
		s := admissionTestService(t)
		s.serviceAccess.Lock()
		s.serviceStatus = &ServiceStatus{Status: terminal, ErrorMessage: "start failed"}
		s.serviceAccess.Unlock()
		err := s.waitForStartedAfterStarting(context.Background())
		if terminal == ServiceStatus_FATAL {
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatal(err)
			}
		} else if !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	s := admissionTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.waitForStartedAfterStarting(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	serviceCtx, serviceCancel := context.WithCancel(context.Background())
	serviceCancel()
	s.ctx = serviceCtx
	if err := s.waitForStartedAfterStarting(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type admissionStatusStream struct {
	grpc.ServerStream
	ctx     context.Context
	sent    chan *ServiceStatus
	release chan struct{}
	first   sync.Once
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
		if initial.Status != ServiceStatus_STARTED {
			t.Fatal(initial)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initial snapshot missing")
	}
	// Send is blocked. A lifecycle writer must still acquire the service lock.
	written := make(chan ServiceStatus_Type, 1)
	go func() {
		s.serviceAccess.Lock()
		status := s.serviceStatus.Status
		s.serviceAccess.Unlock()
		written <- status
	}()
	select {
	case status := <-written:
		if status != ServiceStatus_STARTED {
			t.Fatal(status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send holds lifecycle lock")
	}
	ack, _, err := s.serviceStatusObserver.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer s.serviceStatusObserver.UnSubscribe(ack)
	// Force an older queued notification to reach the stream while its newer
	// initial snapshot is in flight. The current immutable state stays STARTED.
	s.serviceStatusSubscriber.Emit(&ServiceStatus{Status: ServiceStatus_STARTING})
	select {
	case <-ack:
	case <-time.After(5 * time.Second):
		t.Fatal("old notification not forwarded")
	}
	release.Do(func() { close(stream.release) })
	select {
	case next := <-stream.sent:
		if next.Status != ServiceStatus_STARTED {
			t.Fatalf("status regressed: %v", next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notification snapshot missing")
	}
	cancel()
	if err = admissionAwait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type admissionConnectionStream struct{ grpc.ServerStream }

func (*admissionConnectionStream) Context() context.Context     { return context.Background() }
func (*admissionConnectionStream) Send(*ConnectionEvents) error { panic("detached RPC reached Send") }

func TestSubscribeConnectionsRejectsMissingInstanceBeforeDereference(t *testing.T) {
	s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}}
	err := s.SubscribeConnections(&SubscribeConnectionsRequest{}, &admissionConnectionStream{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("missing instance result: %v", err)
	}
}

type sampleConnectionOutbound struct {
	adapter.Outbound
	tag string
}

func (o sampleConnectionOutbound) Tag() string { return o.tag }
func (sampleConnectionOutbound) Type() string  { return "direct" }

func TestTrafficSampleReconcilesReplacementWithoutChangingConnectionCount(t *testing.T) {
	var service StartedService
	manager := trafficcontrol.NewManager()
	metadata := adapter.InboundContext{OutboundChain: []adapter.Outbound{sampleConnectionOutbound{tag: "direct"}}}
	first, firstPeer := net.Pipe()
	tracked := manager.RoutedConnection(t.Context(), first, metadata, nil, nil)
	t.Cleanup(func() { _ = tracked.Close(); _ = firstPeer.Close() })
	snapshots := make(map[uuid.UUID]connectionSnapshot)
	var events []*ConnectionEvent
	emit := func(event *ConnectionEvent) error {
		events = append(events, event)
		return nil
	}
	if err := service.buildInitialConnectionState(manager, snapshots, emit); err != nil {
		t.Fatal(err)
	}
	initial := events
	if len(initial) != 1 {
		t.Fatalf("initial connections: %d", len(initial))
	}
	events = nil
	if err := service.buildTrafficUpdates(manager, snapshots, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("unchanged sample sent events: %v", events)
	}
	_ = tracked.Close()
	second, secondPeer := net.Pipe()
	replacement := manager.RoutedConnection(t.Context(), second, metadata, nil, nil)
	t.Cleanup(func() { _ = replacement.Close(); _ = secondPeer.Close() })
	// Skip the event stream to exercise recovery of a missed NEW and CLOSED.
	if err := service.buildTrafficUpdates(manager, snapshots, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != ConnectionEventType_CONNECTION_EVENT_NEW ||
		events[1].Type != ConnectionEventType_CONNECTION_EVENT_CLOSED ||
		events[1].Id != initial[0].Id || events[1].Connection == nil || len(snapshots) != 1 {
		t.Fatalf("replacement sample did not reconcile the missed close: %v", events)
	}
}

func snapshotTestConnection(t *testing.T, manager *trafficcontrol.Manager, chain ...string) trafficcontrol.Tracker {
	t.Helper()
	outbounds := make([]adapter.Outbound, len(chain))
	for i, tag := range chain {
		outbounds[len(chain)-1-i] = sampleConnectionOutbound{tag: tag}
	}
	connection, peer := net.Pipe()
	tracked := manager.RoutedConnection(t.Context(), connection, adapter.InboundContext{OutboundChain: outbounds}, nil, nil).(trafficcontrol.Tracker)
	t.Cleanup(func() { _ = tracked.Close(); _ = peer.Close() })
	return tracked
}

func TestStreamConnectionSnapshot(t *testing.T) {
	const chunkLimit = 256 * 1024
	const totalLimit = 4 * 1024 * 1024
	const secret = "snapshot-test-secret"
	// The outer entry, the UUID, and the single long chain tag take 46 bytes beyond the tag contents.
	fullTag := strings.Repeat("x", chunkLimit-46)
	for _, test := range []struct {
		name         string
		connections  int
		chain        []string
		wantCode     codes.Code
		wantFullSize bool
	}{
		{name: "empty"},
		{name: "projection", connections: 2, chain: []string{"proxy", "selector"}},
		{name: "exact_limits", connections: 16, chain: []string{fullTag}, wantFullSize: true},
		{name: "entry_over_limit", connections: 1, chain: []string{fullTag + "x"}, wantCode: codes.ResourceExhausted},
		{name: "total_over_limit", connections: 17, chain: []string{fullTag}, wantCode: codes.ResourceExhausted},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := trafficcontrol.NewManager()
			closed := snapshotTestConnection(t, manager, fullTag+"x")
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			remaining := make(map[string]bool)
			for range test.connections {
				tracked := snapshotTestConnection(t, manager, test.chain...)
				remaining[tracked.Metadata().ID.String()] = true
			}
			s := &StartedService{
				serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
				instance:      &Instance{ctx: t.Context(), trafficManager: manager},
			}
			client := startedServiceClientFixture(t, s, secret)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if test.name == "projection" {
				unauthenticated, err := client.StreamConnectionSnapshot(ctx, &emptypb.Empty{})
				if err == nil {
					_, err = unauthenticated.Recv()
				}
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("unauthenticated snapshot: %v", err)
				}
			}
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+secret)
			stream, err := client.StreamConnectionSnapshot(ctx, &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			var complete bool
			var totalBytes int
			for {
				chunk, err := stream.Recv()
				if err != nil {
					if test.wantCode == codes.OK {
						if !errors.Is(err, io.EOF) || !complete || len(remaining) != 0 {
							t.Fatalf("snapshot completion: complete=%t missing=%d err=%v", complete, len(remaining), err)
						}
					} else if status.Code(err) != test.wantCode || complete {
						t.Fatalf("snapshot failure: complete=%t err=%v", complete, err)
					}
					break
				}
				if complete || chunk.Complete != (len(chunk.Entries) == 0) {
					t.Fatal("invalid snapshot frame sequence")
				}
				complete = chunk.Complete
				if complete {
					continue
				}
				encoded, err := proto.Marshal(chunk)
				if err != nil {
					t.Fatal(err)
				}
				totalBytes += len(encoded)
				if len(encoded) > chunkLimit || totalBytes > totalLimit || (test.wantFullSize && len(encoded) != chunkLimit) {
					t.Fatalf("invalid size: frame=%d total=%d", len(encoded), totalBytes)
				}
				for _, entry := range chunk.Entries {
					if !remaining[entry.Id] || !slices.Equal(entry.ChainList, test.chain) {
						t.Fatalf("wrong or repeated live projection: id=%q chain elements=%d", entry.Id, len(entry.ChainList))
					}
					delete(remaining, entry.Id)
				}
			}
			if test.wantFullSize && totalBytes != totalLimit {
				t.Fatalf("exact total lost: %d", totalBytes)
			}
		})
	}
}

type admissionSendStream[T any] struct {
	grpc.ServerStream
	ctx  context.Context
	send func(*T) error
}

func (s *admissionSendStream[T]) Context() context.Context { return s.ctx }
func (s *admissionSendStream[T]) Send(chunk *T) error {
	return s.send(chunk)
}

func TestSubscribeConnectionsSplitsOnlyWebReset(t *testing.T) {
	manager := trafficcontrol.NewManager()
	scope := adapter.NewScope(t.Context(), nil)
	if err := manager.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scope.Close(); err != nil {
			t.Error(err)
		}
	})
	want := make(map[string]bool)
	wide := strings.Repeat("x", 49*1024)
	for range 128 {
		conn := snapshotTestConnection(t, manager, "selector", "outbound")
		conn.Metadata().Metadata.Domain = wide
		want[conn.Metadata().ID.String()] = false
	}
	service := &StartedService{
		ctx:           t.Context(),
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{ctx: t.Context(), trafficManager: manager},
	}
	for _, web := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		if web {
			ctx = ContextWithBoundedConnectionEvents(ctx)
		}
		got := make(map[string]bool)
		var frames, bytes int
		stream := &admissionSendStream[ConnectionEvents]{ctx: ctx, send: func(frame *ConnectionEvents) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			frames++
			if frame.Reset_ != (frames == 1) {
				t.Fatalf("web=%t frame=%d reset=%t", web, frames, frame.Reset_)
			}
			size := proto.Size(frame)
			bytes += size
			if web && size > webConnectionEventFrameLimit {
				t.Fatalf("oversized Web frame: %d bytes", size)
			}
			for _, event := range frame.Events {
				if _, duplicate := got[event.Id]; duplicate || event.Type != ConnectionEventType_CONNECTION_EVENT_NEW || event.Connection == nil || event.Connection.Id != event.Id {
					t.Fatalf("unexpected initial event for %s", event.Id)
				}
				got[event.Id] = event.Connection.ClosedAt != 0
			}
			if len(got) >= len(want) {
				cancel()
			}
			return nil
		}}
		if err := service.SubscribeConnections(&SubscribeConnectionsRequest{}, stream); !errors.Is(err, context.Canceled) {
			t.Fatalf("web=%t frames=%d records=%d unexpected stream result: %v", web, frames, len(got), err)
		}
		if !maps.Equal(got, want) || (web != (frames > 1)) || bytes < 6*1024*1024 {
			t.Fatalf("web=%t frames=%d records=%d bytes=%d", web, frames, len(got), bytes)
		}
	}
}

func TestWebConnectionBatchRejectsOversizedRecord(t *testing.T) {
	stream := &admissionSendStream[ConnectionEvents]{ctx: t.Context(), send: func(*ConnectionEvents) error {
		t.Fatal("oversized record should fail before sending")
		return nil
	}}
	batch := connectionEventBatch{server: stream, frame: &ConnectionEvents{Reset_: true}, limit: webConnectionEventFrameLimit}
	err := batch.add(&ConnectionEvent{Connection: &Connection{Rule: strings.Repeat("x", webConnectionEventFrameLimit)}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized record returned %v", err)
	}
}

func TestStreamConnectionSnapshotStopsOnCancellation(t *testing.T) {
	manager := trafficcontrol.NewManager()
	for range 2 {
		snapshotTestConnection(t, manager, strings.Repeat("x", 128*1024))
	}
	s := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{ctx: t.Context(), trafficManager: manager},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sent := 0
	stream := &admissionSendStream[ConnectionSnapshotChunk]{ctx: ctx, send: func(chunk *ConnectionSnapshotChunk) error {
		sent++
		if chunk.Complete {
			t.Fatal("unexpected completion after cancellation")
		}
		cancel()
		return nil
	}}
	if err := s.StreamConnectionSnapshot(&emptypb.Empty{}, stream); !errors.Is(err, context.Canceled) || sent != 1 {
		t.Fatalf("snapshot cancellation: sent=%d err=%v", sent, err)
	}
}

func TestStreamConnectionSnapshotWithoutTracking(t *testing.T) {
	s := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{ctx: t.Context()},
	}
	stream := &admissionSendStream[ConnectionSnapshotChunk]{ctx: t.Context()}
	if err := s.StreamConnectionSnapshot(&emptypb.Empty{}, stream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing tracking: %v", err)
	}
}
