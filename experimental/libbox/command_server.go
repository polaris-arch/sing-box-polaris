package libbox

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type CommandServer struct {
	transient       bool
	directoryDomain *adapter.TailscaleDirectoryDomain
	*daemon.StartedService
	ctx                  context.Context
	managedService       *daemon.ManagedService
	handler              CommandServerHandler
	platformInterface    PlatformInterface
	platformWrapper      *platformInterfaceWrapper
	powerManager         *powerreport.Manager
	oomRecorder          *oomkiller.Recorder
	grpcServer           *grpc.Server
	listener             net.Listener
	commandAccess        sync.Mutex
	commandStartDone     chan struct{}
	commandCloseOnce     sync.Once
	commandCloseDone     chan struct{}
	commandClosing       chan struct{}
	commandIsClosing     bool
	beforeCommandPublish func() // deterministic lifecycle test seam; nil in production
}

type CommandServerHandler interface {
	ServiceStop() error
	ServiceReload() error
	GetSystemProxyStatus() (*SystemProxyStatus, error)
	SetSystemProxyEnabled(enabled bool) error
	TriggerNativeCrash() error
	WriteDebugMessage(message string)
	ConnectSSHAgent() (int32, error)
}

func NewCommandServer(handler CommandServerHandler, platformInterface PlatformInterface) (*CommandServer, error) {
	return newCommandServer(handler, platformInterface, false, false)
}

// NewStrictCommandServer has the normal primary service's listener and
// diagnostics, but returns a real close acknowledgement for endpoint identity
// ownership. Reload stays available until the final CloseService request.
func NewStrictCommandServer(handler CommandServerHandler, platformInterface PlatformInterface) (*CommandServer, error) {
	return newCommandServer(handler, platformInterface, false, true)
}

// NewTransientCommandServer creates an independent service host without a command
// listener or shared configuration, OOM, and power-report diagnostics.
// StartOrReloadService starts its service; call CloseService before Close.
func NewTransientCommandServer(handler CommandServerHandler, platformInterface PlatformInterface) (*CommandServer, error) {
	return newCommandServer(handler, platformInterface, true, true)
}

func newCommandServer(handler CommandServerHandler, platformInterface PlatformInterface, transient, strictCleanup bool, domains ...*adapter.TailscaleDirectoryDomain) (*CommandServer, error) {
	ctx := baseContext(platformInterface)
	var domain *adapter.TailscaleDirectoryDomain
	if len(domains) != 0 {
		domain = domains[0]
		ctx = adapter.ContextWithTailscaleDirectoryDomain(ctx, domain)
	}
	powerManager := powerreport.NewManager()
	service.MustRegister[*powerreport.Manager](ctx, powerManager)
	platformWrapper := &platformInterfaceWrapper{
		iif:          platformInterface,
		useProcFS:    platformInterface.UseProcFS(),
		powerManager: powerManager,
	}
	service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
	server := &CommandServer{
		transient:         transient,
		directoryDomain:   domain,
		ctx:               ctx,
		handler:           handler,
		platformInterface: platformInterface,
		platformWrapper:   platformWrapper,
		powerManager:      powerManager,
		commandCloseDone:  make(chan struct{}),
		commandClosing:    make(chan struct{}),
	}
	// configuration.json is a diagnostic snapshot, not an established App
	// restart source. Durability remains pending without an App owner contract.
	server.StartedService = daemon.NewStartedService(daemon.ServiceOptions{
		Context: ctx,
		// Platform:         platformWrapper,
		Handler:           (*platformHandler)(server),
		KeepDefaultLogger: transient,
		StrictCleanup:     strictCleanup,
		Debug:             sDebug,
		LogMaxLines:       sLogMaxLines,
		OOMKillerEnabled:  sOOMKillerEnabled,
		OOMKillerDisabled: sOOMKillerDisabled,
		OOMMemoryLimit:    uint64(sOOMMemoryLimit),
		// WorkingDirectory: sWorkingPath,
		// TempDirectory:    sTempPath,
		// UserID:           sUserID,
		// GroupID:          sGroupID,
		// SystemProxyEnabled: false,
	})
	if !transient {
		oomRecorder := oomkiller.NewRecorder(OOMRecorderOptions(server.StartedService))
		service.MustRegister[*oomkiller.Recorder](ctx, oomRecorder)
		oomRecorder.Start()
		server.oomRecorder = oomRecorder
	}
	server.managedService = daemon.NewManagedService(daemon.ManagedServiceOptions{
		Handler:     (*platformHandler)(server),
		Debug:       sDebug,
		OOMRecorder: server.oomRecorder,
	})
	if !transient && sPowerReportEnabled {
		err := powerManager.Start(PowerReportOptions(server.StartedService))
		if err != nil {
			log.StdLogger().Error(E.Cause(err, "start power report recorder"))
		}
	}
	return server, nil
}

func unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if sCommandServerSecret == "" {
		return handler(daemon.ContextWithRuntimeActor(ctx, "libbox:command-owner"), req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get("x-command-secret")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authentication secret")
	}
	if values[0] != sCommandServerSecret {
		return nil, status.Error(codes.Unauthenticated, "invalid authentication secret")
	}
	return handler(daemon.ContextWithRuntimeActor(ctx, "libbox:command-owner"), req)
}

func streamAuthInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if sCommandServerSecret == "" {
		return handler(srv, ss)
	}
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get("x-command-secret")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing authentication secret")
	}
	if values[0] != sCommandServerSecret {
		return status.Error(codes.Unauthenticated, "invalid authentication secret")
	}
	return handler(srv, ss)
}

func (s *CommandServer) Start() error {
	if s.transient {
		return E.New("transient command server cannot start a command listener")
	}
	s.commandAccess.Lock()
	if s.commandIsClosing {
		s.commandAccess.Unlock()
		return os.ErrClosed
	}
	if s.commandStartDone != nil {
		s.commandAccess.Unlock()
		return os.ErrExist
	}
	startDone := make(chan struct{})
	s.commandStartDone = startDone
	s.commandAccess.Unlock()
	defer close(startDone)
	select {
	case <-s.commandClosing:
		return os.ErrClosed
	default:
	}
	var (
		listener net.Listener
		err      error
	)
	if sCommandServerListenPort == 0 {
		sockPath := filepath.Join(sBasePath, "command.sock")
		os.Remove(sockPath)
		for range 30 {
			listener, err = net.ListenUnix("unix", &net.UnixAddr{
				Name: sockPath,
				Net:  "unix",
			})
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.EROFS) {
				break
			}
			select {
			case <-s.commandClosing:
				return os.ErrClosed
			case <-time.After(time.Second):
			}
		}
		if err != nil {
			return E.Cause(err, "listen command server")
		}
		if sUserID != os.Getuid() {
			err = os.Chown(sockPath, sUserID, sGroupID)
			if err != nil {
				listener.Close()
				os.Remove(sockPath)
				return E.Cause(err, "chown")
			}
		}
	} else {
		listener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(sCommandServerListenPort))))
		if err != nil {
			return E.Cause(err, "listen command server")
		}
	}
	serverOptions := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryAuthInterceptor, daemon.UnaryLocaleInterceptor),
		grpc.ChainStreamInterceptor(streamAuthInterceptor, daemon.StreamLocaleInterceptor),
	}
	grpcServer := grpc.NewServer(serverOptions...)
	daemon.RegisterStartedServiceServer(grpcServer, s.StartedService)
	daemon.RegisterRuntimeConfigServiceServer(grpcServer, s.StartedService)
	daemon.RegisterManagedServiceServer(grpcServer, s.managedService)
	healthServer := health.NewServer()
	healthServer.SetServingStatus(daemon.RuntimeConfigService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(daemon.StartedService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(daemon.ManagedService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	if s.beforeCommandPublish != nil {
		s.beforeCommandPublish()
	}
	s.commandAccess.Lock()
	if s.commandIsClosing {
		s.commandAccess.Unlock()
		listener.Close()
		grpcServer.Stop()
		return os.ErrClosed
	}
	s.listener = listener
	s.grpcServer = grpcServer
	s.commandAccess.Unlock()
	go grpcServer.Serve(listener)
	return nil
}

func (s *CommandServer) Close() {
	s.commandCloseOnce.Do(func() {
		s.commandAccess.Lock()
		s.commandIsClosing = true
		close(s.commandClosing)
		startDone := s.commandStartDone
		s.commandAccess.Unlock()
		if startDone != nil {
			<-startDone
		}
		s.commandAccess.Lock()
		grpcServer, listener := s.grpcServer, s.listener
		s.grpcServer, s.listener = nil, nil
		s.commandAccess.Unlock()
		if grpcServer != nil {
			grpcServer.Stop()
		}
		common.Close(listener)
		s.StartedService.Close()
		if s.oomRecorder != nil {
			s.oomRecorder.Close()
		}
		s.powerManager.Close()
		close(s.commandCloseDone)
	})
	<-s.commandCloseDone
}

type OverrideOptions struct {
	AutoRedirect   bool
	IncludePackage StringIterator
	ExcludePackage StringIterator
}

func (s *CommandServer) StartOrReloadService(configContent string, options *OverrideOptions) error {
	return s.startOrReloadServiceWithRuntimePersistence(configContent, options, nil, false)
}

// StartOrReloadServiceWithRuntimePersistence captures this host owner for the
// new instance. A fresh handler must be supplied for each full start/reload.
func (s *CommandServer) StartOrReloadServiceWithRuntimePersistence(configContent string, options *OverrideOptions, handler RuntimePersistenceHandler) error {
	return s.startOrReloadServiceWithRuntimePersistence(configContent, options, handler, false)
}

// StartOrReloadServiceWithRetryableRuntimePersistence explicitly promises that
// this owner safely accepts identical identity/content after partial success or
// an error. The ordinary entry point does not authorize callback replay.
func (s *CommandServer) StartOrReloadServiceWithRetryableRuntimePersistence(configContent string, options *OverrideOptions, handler RuntimePersistenceHandler) error {
	if handler == nil {
		return errors.New("retryable persistence owner is required")
	}
	return s.startOrReloadServiceWithRuntimePersistence(configContent, options, handler, true)
}

func (s *CommandServer) startOrReloadServiceWithRuntimePersistence(configContent string, options *OverrideOptions, handler RuntimePersistenceHandler, retrySafe bool) error {
	if s.directoryDomain != nil && !s.directoryDomain.Activated() {
		return errors.New("managed directory bootstrap has not been activated")
	}
	// Managed profiles stay in the original owner; in particular raw physical
	// paths cannot reach a shared snapshot before the daemon poison gate.
	var beforeStart func()
	if !s.transient && s.directoryDomain == nil {
		beforeStart = func() {
			saveConfigSnapshot(configContent)
			if s.powerManager.Recorder() != nil {
				copyConfigSnapshot(filepath.Join(sWorkingPath, powerreport.DraftDirectoryName))
			}
		}
	}
	startContext := s.ctx
	if handler != nil {
		mode := handler.RuntimePersistenceMode()
		var err error
		startContext, err = daemon.ContextWithRuntimePersistenceOptions(startContext, runtimeHostPersistence(handler, mode), mode, retrySafe)
		if err != nil {
			return err
		}
	}
	if options == nil {
		options = new(OverrideOptions)
	}
	err := s.StartedService.StartOrReloadServiceWithBeforeStart(startContext, configContent, &daemon.OverrideOptions{
		AutoRedirect:   options.AutoRedirect,
		IncludePackage: iteratorToArray(options.IncludePackage),
		ExcludePackage: iteratorToArray(options.ExcludePackage),
	}, beforeStart)
	if err != nil {
		return E.Cause(err, "start or reload service")
	}
	return nil
}

func (s *CommandServer) CloseService() error {
	return s.StartedService.CloseService()
}

func (s *CommandServer) WriteMessage(level int32, message string) {
	s.StartedService.WriteMessage(log.Level(level), message)
}

func (s *CommandServer) SetError(message string) {
	s.StartedService.SetError(E.New(message))
}

func (s *CommandServer) NeedWIFIState() bool {
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil {
		return false
	}
	return instance.Box().Network().NeedWIFIState()
}

func (s *CommandServer) NeedFindProcess() bool {
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil {
		return false
	}
	return instance.Box().Router().NeedFindProcess()
}

// iOS wakes the extension for every push and background task, so wake is ignored there and
// the pause ends on the screen state instead.
func (s *CommandServer) Pause() {
	recorder := s.powerManager.Recorder()
	if recorder != nil {
		recorder.RecordDeviceSleep()
	}
	if !(C.IsAndroid || C.IsIos) || C.IsTvOS {
		return
	}
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil || instance.PauseManager() == nil {
		return
	}
	instance.Box().CloseIdleConnections()
	instance.PauseManager().DevicePause()
}

func (s *CommandServer) Wake() {
	recorder := s.powerManager.Recorder()
	if recorder != nil {
		recorder.RecordDeviceWake()
	}
	if !C.IsAndroid {
		return
	}
	instance := s.StartedService.Instance()
	if instance == nil || instance.PauseManager() == nil {
		return
	}
	instance.PauseManager().DeviceWake()
}

func (s *CommandServer) WakeNow() {
	instance := s.StartedService.Instance()
	if instance == nil || instance.PauseManager() == nil {
		return
	}
	instance.PauseManager().DeviceWake()
}

func (s *CommandServer) RecordScreenState(on bool) {
	recorder := s.powerManager.Recorder()
	if recorder != nil {
		recorder.RecordScreenState(on)
	}
}

func (s *CommandServer) ResetNetwork() {
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil {
		return
	}
	instance.Box().Network().ResetNetwork(context.Background())
}

func (s *CommandServer) UpdateWIFIState() {
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil {
		return
	}
	instance.Box().Network().UpdateWIFIState(context.Background())
}

type platformHandler CommandServer

func (h *platformHandler) ServiceStop() error {
	return (*CommandServer)(h).handler.ServiceStop()
}

func (h *platformHandler) ServiceReload(ctx context.Context) error {
	return (*CommandServer)(h).handler.ServiceReload()
}

func (h *platformHandler) SystemProxyStatus() (*daemon.SystemProxyStatus, error) {
	status, err := (*CommandServer)(h).handler.GetSystemProxyStatus()
	if err != nil {
		return nil, E.Cause(err, "get system proxy status")
	}
	return &daemon.SystemProxyStatus{
		Enabled:   status.Enabled,
		Available: status.Available,
	}, nil
}

func (h *platformHandler) SetSystemProxyEnabled(enabled bool) error {
	return (*CommandServer)(h).handler.SetSystemProxyEnabled(enabled)
}

func (h *platformHandler) TriggerNativeCrash() error {
	return (*CommandServer)(h).handler.TriggerNativeCrash()
}

func (h *platformHandler) WriteDebugMessage(message string) {
	(*CommandServer)(h).handler.WriteDebugMessage(message)
}

func (h *platformHandler) ConnectSSHAgent() (int32, error) {
	return (*CommandServer)(h).handler.ConnectSSHAgent()
}

// ExportTailscaleStoreRetirement returns scoped original StateStore terminals.
// It is not a global cleanup or SDK task-quiescence certificate.
func (s *CommandServer) ExportTailscaleStoreRetirement() string {
	return s.StartedService.ExportTailscaleStoreRetirement()
}

// ExportTailscaleDirectoryRetirement returns original per-run directory IO
// terminals. It is independent of authentication-store retirement.
func (s *CommandServer) ExportTailscaleDirectoryRetirement() string {
	return s.StartedService.ExportTailscaleDirectoryRetirement()
}
