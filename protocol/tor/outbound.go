package tor

import (
	"context"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	tor "github.com/sagernet/sing-box/common/binetor"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/proxybridge"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/cretz/bine/control"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TorOutboundOptions](registry, C.TypeTor, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	runtimeSource       adapter.RuntimeResourceSource
	runtimeStarts       *outbound.RuntimeIOFence
	runtimeCleanup      func() error
	constructionCleanup bool
	processOwner        *runtimeProcessCreator
	torInstance         *tor.Tor
	eventsDone          chan struct{}
	runtimeWork         *outbound.RuntimeIOFence
	admitRuntime        func(context.Context) (context.Context, func(), error)
	ctx                 context.Context
	logger              logger.ContextLogger
	dialer              N.Dialer
	proxy               *proxybridge.Bridge
	startConf           *tor.StartConf
	options             map[string]string
	events              chan control.Event
	socksClient         *socks.Client
	bootstrapDone       chan struct{}
	bootstrapErr        error
	bootstrapUncertain  error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TorOutboundOptions) (adapter.Outbound, error) {
	err := adapter.CheckSecurityFeature(ctx, "Tor outbound")
	if err != nil {
		return nil, err
	}
	options.ExtraArgs = append([]string(nil), options.ExtraArgs...)
	var startConf tor.StartConf
	startConf.DataDir = os.ExpandEnv(options.DataDirectory)
	if startConf.DataDir != "" {
		startConf.DataDir = filemanager.BasePath(ctx, startConf.DataDir)
	}
	startConf.TempDataDirBase = filemanager.TempPath(ctx)
	if startConf.DataDir != "" {
		dataDirAbs, _ := filepath.Abs(startConf.DataDir)
		geoIPPath := filepath.Join(dataDirAbs, "geoip")
		geoIPInfo, err := filemanager.Stat(ctx, geoIPPath)
		if err == nil && !geoIPInfo.IsDir() && !common.Contains(options.ExtraArgs, "--GeoIPFile") {
			options.ExtraArgs = append(options.ExtraArgs, "--GeoIPFile", geoIPPath)
		}
		geoIP6Path := filepath.Join(dataDirAbs, "geoip6")
		geoIP6Info, err := filemanager.Stat(ctx, geoIP6Path)
		if err == nil && !geoIP6Info.IsDir() && !common.Contains(options.ExtraArgs, "--GeoIPv6File") {
			options.ExtraArgs = append(options.ExtraArgs, "--GeoIPv6File", geoIP6Path)
		}
		torrcFile := filepath.Join(startConf.DataDir, "torrc")
		torrcInfo, err := filemanager.Stat(ctx, torrcFile)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		} else if err == nil && torrcInfo.IsDir() {
			return nil, E.New("Tor configuration path is a directory: ", torrcFile)
		}
		startConf.TorrcFile = torrcFile
	}
	startConf.ExtraArgs = options.ExtraArgs
	if options.ExecutablePath != "" {
		startConf.ExePath = options.ExecutablePath
		startConf.ProcessCreator = nil
		startConf.UseEmbeddedControlConn = false
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	instance := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTor, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		dialer:    outboundDialer,
		startConf: &startConf,
		options:   cloneTorOptions(options.Options),
	}
	if err := instance.initRuntime(ctx); err != nil {
		return nil, err
	}
	registered, err := outbound.RegisterRuntimeCleanup(ctx, instance.runtimeCleanup)
	instance.constructionCleanup = registered
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (t *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if err := scope.Context().Err(); err != nil {
		_ = t.runtimeCleanup()
		return err
	}
	if !t.constructionCleanup {
		registered, err := outbound.RegisterRuntimeCleanup(adapter.ContextWithConstructionScope(scope.Context(), scope), t.runtimeCleanup)
		t.constructionCleanup = registered
		if err != nil {
			return err
		}
	}
	release, err := t.runtimeStarts.Acquire()
	if err != nil {
		return err
	}
	defer release()
	switch stage {
	case adapter.StartStateInitialize:
		if t.startConf.DataDir == "" {
			return nil
		}
		err := filemanager.MkdirAll(t.ctx, t.startConf.DataDir, 0o755)
		if err != nil {
			return err
		}
		torrcInfo, err := filemanager.Stat(t.ctx, t.startConf.TorrcFile)
		if os.IsNotExist(err) {
			err = filemanager.WriteFile(t.ctx, t.startConf.TorrcFile, []byte(""), 0o600)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if torrcInfo.IsDir() {
			return E.New("Tor configuration path is a directory: ", t.startConf.TorrcFile)
		}
	case adapter.StartStateStart:
		proxy, err := proxybridge.NewWithRuntimeContinuation(t.ctx, t.logger, "proxy", t.dialer, t.admitRuntime)
		if err != nil {
			return err
		}
		t.proxy = proxy
		err = proxy.Start()
		if err != nil {
			return err
		}
		return t.start(scope)
	}
	return nil
}

var torLogEvents = []control.EventCode{
	control.EventCodeLogDebug,
	control.EventCodeLogErr,
	control.EventCodeLogInfo,
	control.EventCodeLogNotice,
	control.EventCodeLogWarn,
}

func (t *Outbound) start(scope *adapter.Scope) error {
	t.events = make(chan control.Event, 8)
	t.eventsDone = make(chan struct{})
	go func() { defer close(t.eventsDone); t.recvLoop() }()
	// Keep temporary data through upstream error cleanup. The actual process
	// owner removes it only after its sole Wait has really completed.
	t.startConf.RetainTempDataDir = true
	torInstance, err := tor.Start(t.ctx, t.startConf)
	t.torInstance = torInstance
	if err != nil {
		return E.New(strings.ToLower(err.Error()))
	}
	err = torInstance.Control.AddEventListener(t.events, torLogEvents...)
	if err != nil {
		return err
	}
	proxyPort := "127.0.0.1:" + F.ToString(t.proxy.Port())
	proxyUsername := t.proxy.Username()
	proxyPassword := t.proxy.Password()
	t.logger.Trace("created upstream proxy at ", proxyPort)
	t.logger.Trace("upstream proxy username ", proxyUsername)
	t.logger.Trace("upstream proxy password ", proxyPassword)
	confOptions := []*control.KeyVal{
		control.NewKeyVal("Socks5Proxy", proxyPort),
		control.NewKeyVal("Socks5ProxyUsername", proxyUsername),
		control.NewKeyVal("Socks5ProxyPassword", proxyPassword),
	}
	err = torInstance.Control.ResetConf(confOptions...)
	if err != nil {
		return err
	}
	if len(t.options) > 0 {
		for key, value := range t.options {
			switch key {
			case "Socks5Proxy",
				"Socks5ProxyUsername",
				"Socks5ProxyPassword":
				continue
			}
			err = torInstance.Control.SetConf(control.NewKeyVal(key, value))
			if err != nil {
				return E.Cause(err, "set ", key, "=", value)
			}
		}
	}
	// Managed readiness is independent of graph startup. The process and its
	// authenticated control channel already belong to this outbound; selected
	// dials still wait for actual bootstrap and the SOCKS listener.
	release, err := t.runtimeWork.Acquire()
	if err != nil {
		return err
	}
	go func() {
		defer release()
		defer close(t.bootstrapDone)
		defer func() {
			if recover() != nil {
				t.bootstrapUncertain = E.New("tor bootstrap task panicked; completion unknown")
				t.bootstrapErr = t.bootstrapUncertain
			}
		}()
		t.bootstrapErr = t.bootstrap()
		if t.bootstrapErr != nil && t.ctx.Err() == nil {
			t.logger.Error("tor network bootstrap: ", t.bootstrapErr)
		}
	}()
	return nil
}

func (t *Outbound) recvLoop() {
	for rawEvent := range t.events {
		switch event := rawEvent.(type) {
		case *control.LogEvent:
			event.Raw = strings.ToLower(event.Raw)
			switch event.Severity {
			case control.EventCodeLogDebug, control.EventCodeLogInfo:
				t.logger.Trace(event.Raw)
			case control.EventCodeLogNotice:
				if strings.Contains(event.Raw, "disablenetwork") || strings.Contains(event.Raw, "socks listener") {
					t.logger.Trace(event.Raw)
					continue
				}
				t.logger.Info(event.Raw)
			case control.EventCodeLogWarn:
				t.logger.Warn(event.Raw)
			case control.EventCodeLogErr:
				t.logger.Error(event.Raw)
			}
		}
	}
}

func (t *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, t.runtimeSource, func(ctx context.Context) (net.Conn, error) {
		return t.dialContext(ctx, network, destination)
	})
}

func (t *Outbound) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	t.logger.InfoContext(ctx, "outbound connection to ", destination)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	case <-t.bootstrapDone:
	}
	if t.bootstrapErr != nil {
		return nil, E.Cause(t.bootstrapErr, "tor network bootstrap")
	}
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	return t.socksClient.DialContext(ctx, network, destination)
}

func (t *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return outbound.ListenRuntimePacket(ctx, t.runtimeSource, func(ctx context.Context) (net.PacketConn, error) {
		return t.listenPacket(ctx, destination)
	})
}

func (t *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func cloneTorOptions(options map[string]string) map[string]string {
	cloned := make(map[string]string, len(options))
	maps.Copy(cloned, options)
	return cloned
}
