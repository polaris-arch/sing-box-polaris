package libbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bboltErrors "github.com/sagernet/bbolt/errors"
	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestCommandServerRecoveryRootFollowsHostOwnership(t *testing.T) {
	transientTestSetup(t)
	sPowerReportEnabled = false
	for _, test := range []struct {
		name     string
		newHost  func(CommandServerHandler, PlatformInterface) (*CommandServer, error)
		wantRoot bool
	}{
		{"primary", NewCommandServer, true},
		{"strict-primary", NewStrictCommandServer, true},
		{"transient", NewTransientCommandServer, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := test.newHost(nil, transientTestPlatform{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			root, present := adapter.RuntimeRecoveryRootFromContext(server.ctx)
			if present != test.wantRoot || (test.wantRoot && root != filepath.Clean(sBasePath)) {
				t.Fatalf("host recovery root = %q, present %v, want primary ownership %v", root, present, test.wantRoot)
			}
		})
	}
}

func TestTransientCommandServerPreservesSharedState(t *testing.T) {
	transientTestSetup(t)
	paths := []string{"configuration.json", "command.sock", "sing-box-hot-fakeip-v1.db", filepath.Join(oomkiller.DraftDirectoryName, "metadata.json"), filepath.Join(powerreport.DraftDirectoryName, "metadata.json")}
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
	// The positive journal premise needs native private custody, not only a path.
	// The original short parent remains owned by transientTestSetup cleanup.
	sBasePath = commandServerPrivateRecoveryRoot(t, sBasePath)
	sWorkingPath, sTempPath = sBasePath, sBasePath
	sPowerReportEnabled = false
	defaultLogger := log.StdLogger()
	t.Cleanup(func() { log.SetStdLogger(defaultLogger) })
	primary, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { primary.CloseService(); primary.Close() }()
	if root, present := adapter.RuntimeRecoveryRootFromContext(primary.ctx); !present || root != sBasePath {
		t.Fatalf("primary recovery root premise: got %q, present=%v, want %q", root, present, sBasePath)
	}
	ready, err := cachefile.FakeIPRuntimeRecoveryRootReady(primary.ctx)
	if err != nil {
		t.Fatal("primary recovery root readiness before start:", err)
	}
	if !ready {
		t.Fatal("primary recovery root readiness before start: private root not ready")
	}
	if err := primary.StartOrReloadService(`{"experimental":{"cache_file":{"path":"primary-cache.db"}}}`, &OverrideOptions{}); err != nil {
		t.Fatal(err)
	}
	primaryInstance := primary.Instance()
	primaryLogger := log.StdLogger()
	if primaryLogger == defaultLogger {
		t.Fatal("normal service did not retain default logger replacement")
	}
	journalPath := filepath.Join(sBasePath, "sing-box-hot-fakeip-v1.db")
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	journalInfo, err := os.Lstat(journalPath)
	if err != nil {
		t.Fatal(err)
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
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(journalAfter, journalBefore) {
		t.Fatal("transient lifecycle changed the primary recovery journal", err)
	}
	afterInfo, err := os.Lstat(journalPath)
	if err != nil || !os.SameFile(journalInfo, afterInfo) {
		t.Fatal("transient lifecycle replaced the primary recovery journal", err)
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
	// Successful transient teardown cannot release the still-live primary's
	// original journal lock. A real competing open must retain the bounded
	// writer-lock failure; no larger timeout or shared-handle shortcut is used.
	probe, err := cachefile.OpenFakeIPRuntimeJournal(primary.ctx, primaryLogger)
	if probe != nil {
		_ = probe.Close()
	}
	if !errors.Is(err, bboltErrors.ErrTimeout) {
		t.Fatal("transient lifecycle released or changed primary journal custody", err)
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

// Exercise normal production construction through both configured-cache paths.
// No journal is supplied by this test before the first service starts.
func TestCommandServerFreshJournalSurvivesNormalCloseAndRestart(t *testing.T) {
	transientTestSetup(t)
	sBasePath = commandServerPrivateRecoveryRoot(t, sBasePath)
	sWorkingPath, sTempPath = sBasePath, sBasePath
	sPowerReportEnabled = false
	defaultLogger := log.StdLogger()
	t.Cleanup(func() { log.SetStdLogger(defaultLogger) })
	path := filepath.Join(sBasePath, "sing-box-hot-fakeip-v1.db")
	cachePath := filepath.Join(sBasePath, "primary-cache.db")
	for _, candidate := range []string{path, cachePath} {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("fresh normal service journal or configured cache already exists")
		}
	}
	primary, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal("could not construct normal primary")
	}
	defer func() { primary.CloseService(); primary.Close() }()
	if ready, err := cachefile.FakeIPRuntimeRecoveryRootReady(primary.ctx); err != nil || !ready {
		t.Fatal("normal primary does not have verified root custody")
	}
	const config = `{"experimental":{"cache_file":{"path":"primary-cache.db"}}}`
	if err := primary.StartOrReloadService(config, &OverrideOptions{}); err != nil {
		t.Fatal("normal fresh journal and configured cache failed production Start")
	}
	instance := primary.Instance()
	if instance == nil || instance.Box() == nil || log.StdLogger() == defaultLogger {
		t.Fatal("normal production Start did not publish its instance and logger")
	}
	journalInfo, err := os.Lstat(path)
	if err != nil || !journalInfo.Mode().IsRegular() {
		t.Fatal("normal production Start did not create its journal")
	}
	cacheInfo, err := os.Lstat(cachePath)
	if err != nil || !cacheInfo.Mode().IsRegular() {
		t.Fatal("normal production Start did not create its configured cache")
	}
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatal("normal production journal has no persisted bytes")
	}
	probe, err := cachefile.OpenFakeIPRuntimeJournal(primary.ctx, log.StdLogger())
	if probe != nil {
		_ = probe.Close()
	}
	if probe != nil || !errors.Is(err, bboltErrors.ErrTimeout) {
		t.Fatal("normal production Start did not retain its real journal writer lock")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatal("competing journal open changed live primary journal bytes")
	}
	if primary.Instance() != instance || instance.Box() == nil {
		t.Fatal("competing journal open changed the published primary")
	}
	if err := primary.CloseService(); err != nil {
		t.Fatal("normal primary did not release its production service")
	}
	primary.Close()
	ctx := adapter.ContextWithRuntimeRecoveryRoot(context.Background(), sBasePath)
	journal, err := cachefile.OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal("normal primary close did not release its journal")
	}
	first, err := journal.RuntimeDescriptor(ctx)
	if err != nil || first.DatabaseID == "" {
		_ = journal.Close()
		t.Fatal("normal primary journal has no retained database identity")
	}
	if err := journal.Close(); err != nil {
		t.Fatal("normal primary journal probe did not close")
	}
	next, err := NewCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal("could not construct next normal primary")
	}
	defer func() { next.CloseService(); next.Close() }()
	if err := next.StartOrReloadService(config, &OverrideOptions{}); err != nil {
		t.Fatal("normal existing journal and configured cache failed production restart")
	}
	if next.Instance() == nil || next.Instance().Box() == nil {
		t.Fatal("normal existing-file restart did not publish its instance")
	}
	for _, candidate := range []struct {
		path string
		info os.FileInfo
	}{{path, journalInfo}, {cachePath, cacheInfo}} {
		after, err := os.Lstat(candidate.path)
		if err != nil || !os.SameFile(candidate.info, after) {
			t.Fatal("normal restart replaced a journal or configured cache object")
		}
	}
	probe, err = cachefile.OpenFakeIPRuntimeJournal(next.ctx, log.StdLogger())
	if probe != nil {
		_ = probe.Close()
	}
	if probe != nil || !errors.Is(err, bboltErrors.ErrTimeout) {
		t.Fatal("normal restarted primary did not retain its real journal writer lock")
	}
	if err := next.CloseService(); err != nil {
		t.Fatal("normal restarted primary did not close")
	}
	next.Close()
	journal, err = cachefile.OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal("normal restarted primary did not release its journal")
	}
	defer journal.Close()
	second, err := journal.RuntimeDescriptor(ctx)
	if err != nil || second != first {
		t.Fatal("normal production restart changed the exact journal descriptor")
	}
}
