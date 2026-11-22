package libbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type failingPrimaryCloseService struct{ failure error }

func (s *failingPrimaryCloseService) Type() string { return "test-primary-close" }
func (s *failingPrimaryCloseService) Tag() string  { return "probe" }

func (s *failingPrimaryCloseService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { return s.failure })
	}
	return nil
}

func TestStrictPrimaryReloadThenFinalCloseIsTerminal(t *testing.T) {
	transientTestSetup(t)
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.transient || server.oomRecorder == nil {
		t.Fatal("strict primary lost the normal host listener/diagnostics shape")
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); err != nil {
		t.Fatalf("ordinary primary reload was blocked: %v", err)
	}
	if err := server.CloseService(); err != nil {
		t.Fatal(err)
	}
	marker := []byte("new-primary-snapshot")
	if err := os.WriteFile(configSnapshotPath(), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late reload after final close = %v, want ErrClosed", err)
	}
	if after, err := os.ReadFile(configSnapshotPath()); err != nil || !bytes.Equal(after, marker) {
		t.Fatalf("closed old host rewrote the newer primary snapshot: %v", err)
	}
}

type primaryPlatformDNS struct{ transientTestPlatform }

func (primaryPlatformDNS) LocalDNSTransport() LocalDNSTransport { return &fakeDNSPlatform{} }

func TestStrictPrimaryCloseWithPlatformDNS(t *testing.T) {
	transientTestSetup(t)
	server, err := NewStrictCommandServer(nil, primaryPlatformDNS{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	const config = `{"dns":{"servers":[{"type":"local","tag":"system"}]}}`
	if err := server.StartOrReloadService(config, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.CloseService(); err != nil {
			t.Error(err)
		}
	})
	box := server.Instance().Box()
	snapshot, err := box.AcquireReferenceSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := snapshot.Lease.View().DNSTransportManager().Transport("system")
	snapshot.Lease.Release()
	if _, ok := transport.(*platformTransport); !ok {
		t.Fatalf("configured platform DNS adapter is %T", transport)
	}
	// Validate the census requirement even if the background observer is delayed.
	if _, ok := transport.(adapter.IdleConnectionKeeper); !ok {
		t.Fatal("runtime DNS reference adapter requires idle-only connection control")
	}
	box.CloseIdleConnections()
}

func TestStrictPrimaryCommandListenerCannotStartAfterClose(t *testing.T) {
	transientTestSetup(t)
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := server.Start(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Start after Close = %v, want ErrClosed", err)
	}
	if server.listener != nil || server.grpcServer != nil {
		t.Fatal("late Start published a command listener")
	}
}

func TestStrictPrimaryCloseWaitsForInFlightCommandStartBeforeAcknowledging(t *testing.T) {
	transientTestSetup(t)
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	server.beforeCommandPublish = func() {
		close(entered)
		<-release
	}
	started := make(chan error, 1)
	go func() { started <- server.Start() }()
	select {
	case <-entered:
	case err := <-started:
		t.Fatalf("Start failed before publish gate: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not reach publish gate")
	}
	closed := make(chan struct{})
	secondClosed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	go func() { server.Close(); close(secondClosed) }()
	select {
	case <-server.commandClosing:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not publish its terminal gate")
	}
	select {
	case <-closed:
		t.Fatal("Close acknowledged while Start still held a local listener")
	case <-secondClosed:
		t.Fatal("concurrent Close acknowledged while Start still held a local listener")
	default:
	}
	close(release)
	if err := <-started; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Start after close request = %v, want ErrClosed", err)
	}
	<-closed
	<-secondClosed
	if server.listener != nil || server.grpcServer != nil {
		t.Fatal("in-flight Start published a command listener after Close")
	}
	newPrimary, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer newPrimary.Close()
	if err := newPrimary.Start(); err != nil {
		t.Fatalf("new primary could not claim the listener: %v", err)
	}
	server.Close()
	if newPrimary.listener == nil || newPrimary.grpcServer == nil {
		t.Fatal("old repeated Close detached the newer primary listener")
	}
}

func TestStrictPrimaryFailedOldCloseBlocksReloadAndRepeatsStickyFailure(t *testing.T) {
	transientTestSetup(t)
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	failure := errors.New("synthetic primary endpoint close failure")
	registry := service.FromContext[adapter.ServiceRegistry](server.ctx).(*boxService.Registry)
	boxService.Register[struct{}](registry, "test-primary-close", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
		return &failingPrimaryCloseService{failure: failure}, nil
	})
	if err := server.StartOrReloadService(`{"services":[{"type":"test-primary-close","tag":"probe"}]}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); !errors.Is(err, failure) {
		t.Fatalf("reload did not surface old identity close failure: %v", err)
	}
	for range 2 {
		if err := server.CloseService(); !errors.Is(err, failure) {
			t.Fatalf("repeated final close cleared primary cleanup failure: %v", err)
		}
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late start after final close = %v, want terminal ErrClosed", err)
	}
}

func TestTransientHTTPInboundRejectsMissingAndWrongSpeedtestCredentials(t *testing.T) {
	transientTestSetup(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	server, err := NewTransientCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	config := fmt.Sprintf(`{"inbounds":[{"type":"http","tag":"probe","listen":"127.0.0.1","listen_port":%d,"users":[{"username":"polaris-temp","password":"0123456789abcdef0123456789abcdef"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, port)
	if err := server.StartOrReloadService(config, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	defer server.CloseService()
	for _, auth := range []string{"", "Proxy-Authorization: Basic cG9sYXJpcy10ZW1wOndyb25n\r\n"} {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(conn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n%s\r\n", auth)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		status, err := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if err != nil || !strings.Contains(status, " 407 ") {
			t.Fatalf("unauthorized CONNECT = %q, err=%v; want 407", status, err)
		}
	}
}

type transientTestPlatform struct{ PlatformInterface }

func (transientTestPlatform) UsePlatformAutoRedirect() bool { return false }

func (transientTestPlatform) LocalDNSTransport() LocalDNSTransport        { return nil }
func (transientTestPlatform) UseProcFS() bool                             { return false }
func (transientTestPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (transientTestPlatform) UnderNetworkExtension() bool                 { return false }

func (transientTestPlatform) GetInterfaces() (NetworkInterfaceIterator, error) {
	return newIterator([]*NetworkInterface{}), nil
}

func (transientTestPlatform) StartDefaultInterfaceMonitor(InterfaceUpdateListener) error { return nil }

func (transientTestPlatform) CloseDefaultInterfaceMonitor(InterfaceUpdateListener) error { return nil }

func transientTestSetup(t *testing.T) {
	t.Helper()
	base, work, temp, power, maxLines, uid, gid := sBasePath, sWorkingPath, sTempPath, sPowerReportEnabled, sLogMaxLines, sUserID, sGroupID
	// The AAR builder's checkout path plus t.TempDir's test-name suffix can
	// exceed Unix's 108-byte socket path limit before CommandServer.Start runs.
	shortDir, err := os.MkdirTemp("", "lb-")
	if err != nil {
		t.Fatal(err)
	}
	sBasePath = shortDir
	sWorkingPath = sBasePath
	sTempPath = sBasePath
	sPowerReportEnabled = true
	sLogMaxLines = 32
	sUserID, sGroupID = os.Getuid(), os.Getgid()
	t.Cleanup(func() {
		sBasePath, sWorkingPath, sTempPath, sPowerReportEnabled, sLogMaxLines, sUserID, sGroupID = base, work, temp, power, maxLines, uid, gid
		os.RemoveAll(shortDir)
	})
}

func TestTransientCommandServerPreservesSharedState(t *testing.T) {
	transientTestSetup(t)
	paths := []string{"configuration.json", "command.sock", filepath.Join(oomkiller.DraftDirectoryName, "metadata.json"), filepath.Join(powerreport.DraftDirectoryName, "metadata.json")}
	marker := []byte(`{"appVersion":"","appMarketingVersion":""}`)
	for _, path := range paths {
		full := filepath.Join(sBasePath, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, marker, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewTransientCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	if server.oomRecorder != nil || service.FromContext[*oomkiller.Recorder](server.ctx) != nil || server.powerManager.Recorder() != nil {
		t.Fatal("transient host created a shared diagnostics recorder")
	}
	if err := server.Start(); err == nil {
		t.Fatal("transient host accepted command listener start")
	}
	if _, err := server.managedService.TriggerOOMReport(context.Background(), &emptypb.Empty{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("transient OOM report must be unavailable: %v", err)
	}
	if err := server.StartOrReloadService("invalid json", &OverrideOptions{}); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	defaultLogger := log.StdLogger()
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	if log.StdLogger() != defaultLogger {
		t.Fatal("transient service replaced the process default logger")
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseService(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if log.StdLogger() != defaultLogger {
		t.Fatal("transient close changed the process default logger")
	}
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Join(sBasePath, path))
		if err != nil || !bytes.Equal(content, marker) {
			t.Fatalf("shared state changed at %s: %v", path, err)
		}
	}
	for _, path := range []string{oomkiller.ReportsDirectoryName, powerreport.ReportsDirectoryName} {
		if _, err := os.Stat(filepath.Join(sBasePath, path)); !os.IsNotExist(err) {
			t.Fatalf("transient created reports at %s: %v", path, err)
		}
	}
}

func TestCommandServerRetainsSharedDiagnostics(t *testing.T) {
	transientTestSetup(t)
	sPowerReportEnabled = false
	server, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.transient || server.oomRecorder == nil || service.FromContext[*oomkiller.Recorder](server.ctx) == nil {
		t.Fatal("normal host lost OOM diagnostics")
	}
	config := "invalid primary configuration"
	if err := server.StartOrReloadService(config, &OverrideOptions{}); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	content, err := os.ReadFile(configSnapshotPath())
	if err != nil || string(content) != config {
		t.Fatalf("normal host did not save configuration snapshot: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	if server.listener == nil {
		t.Fatal("normal host did not start command listener")
	}
}

func TestTransientCommandServerCloseKeepsPrimaryService(t *testing.T) {
	transientTestSetup(t)
	sPowerReportEnabled = false
	defaultLogger := log.StdLogger()
	t.Cleanup(func() { log.SetStdLogger(defaultLogger) })
	primary, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { primary.CloseService(); primary.Close() }()
	if err := primary.StartOrReloadService(`{"experimental":{"cache_file":{"path":"primary-cache.db"}}}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	primaryInstance := primary.Instance()
	primaryLogger := log.StdLogger()
	if primaryLogger == defaultLogger {
		t.Fatal("normal service did not retain default logger replacement")
	}
	sharedBefore, err := os.ReadDir(sBasePath)
	if err != nil {
		t.Fatal(err)
	}
	transient, err := NewTransientCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	if err := transient.StartOrReloadService(`{"experimental":{"cache_file":{"path":"transient-cache.db"}}}`, &OverrideOptions{}); err != nil {
		transient.Close()
		t.Fatal(err)
	}
	if err := transient.CloseService(); err != nil {
		t.Fatal(err)
	}
	transient.Close()
	if primary.Instance() != primaryInstance || primaryInstance.Box() == nil {
		t.Fatal("transient close changed the primary service instance")
	}
	if log.StdLogger() != primaryLogger {
		t.Fatal("transient lifecycle changed the primary default logger")
	}
	sharedAfter, err := os.ReadDir(sBasePath)
	if err != nil {
		t.Fatal(err)
	}
	remaining := make(map[string]bool, len(sharedBefore))
	for _, entry := range sharedBefore {
		remaining[entry.Name()] = true
	}
	for _, entry := range sharedAfter {
		if remaining[entry.Name()] {
			delete(remaining, entry.Name())
		} else if entry.Name() != "transient-cache.db" {
			t.Fatal("transient lifecycle created unexpected shared state", entry.Name())
		}
	}
	if len(remaining) != 0 {
		t.Fatal("transient lifecycle removed primary state", remaining)
	}
}

func TestTransientCloseAfterCleanFailedStartBlocksLateStart(t *testing.T) {
	transientTestSetup(t)
	server, err := NewTransientCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.StartOrReloadService("invalid json", &OverrideOptions{}); err == nil {
		t.Fatal("invalid config unexpectedly started")
	}
	if err := server.CloseService(); err != nil {
		t.Fatalf("failed start with clean teardown must close normally: %v", err)
	}
	if err := server.StartOrReloadService(`{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late start after close = %v, want ErrClosed", err)
	}
}

func TestCommandServerRejectedReloadKeepsSharedDiagnostics(t *testing.T) {
	transientTestSetup(t)
	sPowerReportEnabled = false
	defaultLogger := log.StdLogger()
	t.Cleanup(func() { log.SetStdLogger(defaultLogger) })
	server, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.CloseService(); server.Close() }()
	config := `{}`
	if err := server.StartOrReloadService(config, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	instance := server.Instance()
	if err := server.StartOrReloadService("invalid replacement configuration", &OverrideOptions{}); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if server.Instance() != instance {
		t.Fatal("rejected reload replaced the running instance")
	}
	content, err := os.ReadFile(configSnapshotPath())
	if err != nil || string(content) != config {
		t.Fatalf("rejected reload overwrote live configuration snapshot: %v", err)
	}
}

func TestReadConnectionEventReset(t *testing.T) {
	for _, test := range []struct {
		name     string
		batched  bool
		complete bool
		terminal error
	}{
		{name: "legacy", complete: true},
		{name: "batched", batched: true, complete: true},
		{name: "truncated", batched: true, terminal: io.EOF},
		{name: "overflow", batched: true, terminal: status.Error(codes.Aborted, "connection events lost")},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := &daemon.ConnectionEvent{Id: "first"}
			second := &daemon.ConnectionEvent{Id: "second"}
			reset := &daemon.ConnectionEvents{Reset_: true, Events: []*daemon.ConnectionEvent{first, second}}
			frames := []*daemon.ConnectionEvents{reset}
			if test.batched {
				reset.Events = reset.Events[:1:1]
				reset.SnapshotComplete = proto.Bool(false)
				frames = append(frames, &daemon.ConnectionEvents{
					SnapshotComplete: proto.Bool(false),
					Events:           []*daemon.ConnectionEvent{second},
				})
				if test.complete {
					frames = append(frames, &daemon.ConnectionEvents{SnapshotComplete: proto.Bool(true)})
				}
			}
			recv := func() (*daemon.ConnectionEvents, error) {
				if len(frames) == 0 {
					return nil, test.terminal
				}
				frame := frames[0]
				frames = frames[1:]
				return frame, nil
			}
			frame, err := readConnectionEventReset(recv, nil)
			if !test.complete {
				if frame != nil || !errors.Is(err, test.terminal) {
					t.Fatalf("incomplete reset returned frame %v and error %v", frame, err)
				}
				return
			}
			if err != nil || !frame.Reset_ || frame.SnapshotComplete != nil ||
				len(frame.Events) != 2 || frame.Events[0] != first || frame.Events[1] != second {
				t.Fatalf("invalid completed reset, frame %v and error %v", frame, err)
			}
		})
	}
}

type connectionFrameTestHandler struct {
	CommandClientHandler
	frames  []*ConnectionEvents
	err     string
	onFrame func(*ConnectionEvents)
}

func (h *connectionFrameTestHandler) WriteConnectionEvents(frame *ConnectionEvents) {
	h.frames = append(h.frames, frame)
	if h.onFrame != nil {
		h.onFrame(frame)
	}
}

func (h *connectionFrameTestHandler) Disconnected(message string) { h.err = message }

func TestReceiveConnectionEventFrames(t *testing.T) {
	first := &daemon.ConnectionEvents{
		Reset_: true, SnapshotComplete: proto.Bool(false),
		Events: []*daemon.ConnectionEvent{{Id: "first"}},
	}
	part := &daemon.ConnectionEvents{
		SnapshotComplete: proto.Bool(false), Events: []*daemon.ConnectionEvent{{Id: "part"}},
	}
	complete := &daemon.ConnectionEvents{SnapshotComplete: proto.Bool(true)}
	delta := &daemon.ConnectionEvents{Events: []*daemon.ConnectionEvent{{Id: "delta"}}}
	oversized := status.Error(codes.ResourceExhausted, "connection event exceeds stream frame limit")
	aborted := status.Error(codes.Aborted, "connection events lost")
	type delivery struct {
		state int32
		reset bool
		ids   string
	}
	start := delivery{ConnectionSnapshotPart, true, "first"}
	next := delivery{ConnectionSnapshotPart, false, "part"}
	end := delivery{ConnectionSnapshotComplete, false, ""}
	rejected := delivery{ConnectionSnapshotTooLarge, false, ""}
	for _, test := range []struct {
		name        string
		raw         bool
		frames      []*daemon.ConnectionEvents
		terminal    error
		want        []delivery
		disconnect  string
		incremental bool
	}{
		{
			name: "raw", raw: true, frames: []*daemon.ConnectionEvents{first, part, complete, delta}, terminal: io.EOF,
			want: []delivery{start, next, end, {ConnectionSnapshotNone, false, "delta"}}, disconnect: "EOF", incremental: true,
		},
		{
			name: "empty_snapshot", raw: true, frames: []*daemon.ConnectionEvents{{Reset_: true, SnapshotComplete: proto.Bool(false)}, complete},
			terminal: io.EOF, want: []delivery{{ConnectionSnapshotPart, true, ""}, end}, disconnect: "EOF", incremental: true,
		},
		{
			name: "default", frames: []*daemon.ConnectionEvents{first, part, complete, delta}, terminal: io.EOF,
			want: []delivery{{ConnectionSnapshotNone, true, "first,part"}, {ConnectionSnapshotNone, false, "delta"}}, disconnect: "EOF",
		},
		{
			name: "aborted", raw: true, frames: []*daemon.ConnectionEvents{first}, terminal: aborted,
			want: []delivery{start}, disconnect: "Aborted", incremental: true,
		},
		{
			name: "oversized_reset", raw: true, frames: []*daemon.ConnectionEvents{first}, terminal: oversized,
			want: []delivery{start, rejected}, disconnect: "ResourceExhausted", incremental: true,
		},
		{name: "oversized_first", raw: true, terminal: oversized, want: []delivery{rejected}, disconnect: "ResourceExhausted"},
		{
			name: "oversized_delta", raw: true, frames: []*daemon.ConnectionEvents{first, complete}, terminal: oversized,
			want: []delivery{start, end, rejected}, disconnect: "ResourceExhausted", incremental: true,
		},
		{name: "default_oversized", frames: []*daemon.ConnectionEvents{first}, terminal: oversized, disconnect: "ResourceExhausted"},
		{
			name: "other_limit", raw: true, frames: []*daemon.ConnectionEvents{first}, terminal: status.Error(codes.ResourceExhausted, "admission limit"),
			want: []delivery{start}, disconnect: "ResourceExhausted", incremental: true,
		},
		{name: "legacy_raw", raw: true, frames: []*daemon.ConnectionEvents{{Reset_: true}}, disconnect: "FailedPrecondition"},
		{name: "missing_complete", raw: true, frames: []*daemon.ConnectionEvents{first, delta}, want: []delivery{start}, disconnect: "DataLoss", incremental: true},
		{name: "second_reset", raw: true, frames: []*daemon.ConnectionEvents{first, complete, {Reset_: true}}, want: []delivery{start, end}, disconnect: "DataLoss", incremental: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := new(connectionFrameTestHandler)
			client := &CommandClient{handler: handler, options: CommandClientOptions{ConnectionEventFrames: test.raw}}
			read := 0
			client.receiveConnectionEvents(t.Context(), func() (*daemon.ConnectionEvents, error) {
				if test.incremental && read != len(handler.frames) {
					t.Fatalf("the first %d frames produced %d callbacks before the next read", read, len(handler.frames))
				}
				if read == len(test.frames) {
					if test.terminal == nil {
						t.Fatal("received another frame after a protocol failure")
					}
					return nil, test.terminal
				}
				frame := proto.CloneOf(test.frames[read])
				read++
				return frame, nil
			})
			var got []delivery
			for _, frame := range handler.frames {
				var ids []string
				for _, event := range frame.events {
					ids = append(ids, event.ID)
				}
				got = append(got, delivery{frame.SnapshotState, frame.Reset, strings.Join(ids, ",")})
			}
			if !slices.Equal(got, test.want) || !strings.Contains(handler.err, test.disconnect) {
				t.Fatalf("delivered %v with terminal %q; want %v and %s", got, handler.err, test.want, test.disconnect)
			}
		})
	}
}

func TestReceiveConnectionEventFramesSizeLimit(t *testing.T) {
	start := &daemon.ConnectionEvents{Reset_: true, SnapshotComplete: proto.Bool(false)}
	// Reuse one sub-limit frame to cross the cumulative limit without allocating a large snapshot.
	part := &daemon.ConnectionEvents{
		SnapshotComplete: proto.Bool(false),
		Events:           []*daemon.ConnectionEvent{{Id: strings.Repeat("x", (1<<20)-1024)}},
	}
	partsWithinLimit := ((64 << 20) - proto.Size(start)) / proto.Size(part)
	handler := new(connectionFrameTestHandler)
	client := &CommandClient{handler: handler, options: CommandClientOptions{ConnectionEventFrames: true}}
	reads := 0
	client.receiveConnectionEvents(t.Context(), func() (*daemon.ConnectionEvents, error) {
		reads++
		switch {
		case reads == 1:
			return start, nil
		case reads <= partsWithinLimit+2:
			return part, nil
		default:
			t.Fatal("received another frame after exceeding the cumulative limit")
			return nil, io.EOF
		}
	})
	if len(handler.frames) != partsWithinLimit+2 || !strings.Contains(handler.err, "connection snapshot exceeds its byte limit") {
		t.Fatalf("size limit delivered %d callbacks and terminal %q", len(handler.frames), handler.err)
	}
	for _, frame := range handler.frames[:len(handler.frames)-1] {
		if frame.SnapshotState != ConnectionSnapshotPart {
			t.Fatalf("unexpected state %d before size limit", frame.SnapshotState)
		}
	}
	last := handler.frames[len(handler.frames)-1]
	if last.SnapshotState != ConnectionSnapshotTooLarge || last.Reset || len(last.events) != 0 {
		t.Fatal("oversized snapshot did not end with an empty size-limit marker")
	}
}

func TestReceiveConnectionEventFramesCancellation(t *testing.T) {
	start := &daemon.ConnectionEvents{Reset_: true, SnapshotComplete: proto.Bool(false)}
	complete := &daemon.ConnectionEvents{SnapshotComplete: proto.Bool(true)}
	delta := &daemon.ConnectionEvents{Events: []*daemon.ConnectionEvent{{Id: "buffered"}}}
	for _, test := range []struct {
		name            string
		cancelInReceive bool
		wantReads       int
	}{
		{name: "cancel_from_completion_callback", wantReads: 2},
		{name: "cancel_during_buffered_receive", cancelInReceive: true, wantReads: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			handler := &connectionFrameTestHandler{onFrame: func(frame *ConnectionEvents) {
				if frame.SnapshotState == ConnectionSnapshotComplete && !test.cancelInReceive {
					cancel()
				}
			}}
			client := &CommandClient{handler: handler, options: CommandClientOptions{ConnectionEventFrames: true}}
			reads := 0
			client.receiveConnectionEvents(ctx, func() (*daemon.ConnectionEvents, error) {
				reads++
				switch reads {
				case 1:
					return start, nil
				case 2:
					return complete, nil
				case 3:
					cancel()
					return delta, nil
				default:
					return nil, io.EOF
				}
			})
			if reads != test.wantReads || len(handler.frames) != 2 || handler.err != "" {
				t.Fatalf("after cancellation: %d reads, %d callbacks, terminal %q", reads, len(handler.frames), handler.err)
			}
		})
	}
}
