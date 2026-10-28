//go:build with_acme

package tls

import (
	"context"
	"crypto/tls"
	"os"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/acmedns"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type acmeWrapper struct {
	runtime       *RuntimeACME
	ctx           context.Context
	cfg           *certmagic.Config
	cache         *certmagic.Cache
	zapLogger     *zap.Logger
	dataDirectory string
	domain        []string
}

func (w *acmeWrapper) Start() error {
	if w.runtime != nil {
		for _, stage := range adapter.ListStartStages {
			if err := w.runtime.PrepareRuntime(stage, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if w.dataDirectory != "" {
		err := filemanager.MkdirAll(w.ctx, w.dataDirectory, 0o700)
		if err != nil {
			return E.Cause(err, "create ACME data directory")
		}
	}
	config := w.cfg
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certificate certmagic.Certificate) (*certmagic.Config, error) {
			return config, nil
		},
		Logger: w.zapLogger,
	})
	config = certmagic.New(cache, *config)
	err := config.ManageSync(w.ctx, w.domain)
	if err != nil {
		cache.Stop()
		return err
	}
	w.cfg = config
	w.cache = cache
	return nil
}

func (w *acmeWrapper) Close() error {
	if w.runtime != nil {
		return w.runtime.RuntimeCloseAndWait()
	}
	if w.cache != nil {
		w.cache.Stop()
	}
	return nil
}

func (w *acmeWrapper) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if w.runtime != nil {
		return w.runtime.GetCertificate(hello)
	}
	return w.cfg.GetCertificate(hello)
}

func startACME(ctx context.Context, logger logger.Logger, options option.InboundACMEOptions) (*tls.Config, adapter.SimpleLifecycle, error) {
	var acmeServer string
	switch options.Provider {
	case "", "letsencrypt":
		acmeServer = certmagic.LetsEncryptProductionCA
	case "zerossl":
		acmeServer = certmagic.ZeroSSLProductionCA
	default:
		if !strings.HasPrefix(options.Provider, "https://") {
			return nil, nil, E.New("unsupported acme provider: " + options.Provider)
		}
		acmeServer = options.Provider
	}
	var (
		storage       certmagic.Storage
		dataDirectory string
	)
	if options.DataDirectory != "" {
		dataDirectory = filemanager.BasePath(ctx, os.ExpandEnv(options.DataDirectory))
		storage = &certmagic.FileStorage{
			Path: dataDirectory,
		}
	} else {
		storage = certmagic.Default.Storage
	}
	zapLogger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(ACMEEncoderConfig()),
		&ACMELogWriter{Logger: logger},
		zap.DebugLevel,
	))
	config := &certmagic.Config{
		DefaultServerName: options.DefaultServerName,
		Storage:           storage,
		Logger:            zapLogger,
	}
	profile := options.Profile
	if profile == "" && acmeServer == certmagic.LetsEncryptProductionCA && slices.ContainsFunc(options.Domain, certmagic.SubjectIsIP) {
		profile = "shortlived"
	}

	acmeConfig := certmagic.ACMEIssuer{
		CA:                      acmeServer,
		Email:                   options.Email,
		Agreed:                  true,
		Profile:                 profile,
		DisableHTTPChallenge:    options.DisableHTTPChallenge,
		DisableTLSALPNChallenge: options.DisableTLSALPNChallenge,
		AltHTTPPort:             int(options.AlternativeHTTPPort),
		AltTLSALPNPort:          int(options.AlternativeTLSPort),
		Logger:                  zapLogger,
	}
	if dnsOptions := options.DNS01Challenge; dnsOptions != nil && dnsOptions.Provider != "" {
		var solver certmagic.DNS01Solver
		switch dnsOptions.Provider {
		case C.DNSProviderAliDNS:
			solver.DNSProvider = &alidns.Provider{
				AccessKeyID:     dnsOptions.AliDNSOptions.AccessKeyID,
				AccessKeySecret: dnsOptions.AliDNSOptions.AccessKeySecret,
				RegionID:        dnsOptions.AliDNSOptions.RegionID,
				SecurityToken:   dnsOptions.AliDNSOptions.SecurityToken,
			}
		case C.DNSProviderCloudflare:
			solver.DNSProvider = &cloudflare.Provider{
				APIToken:  dnsOptions.CloudflareOptions.APIToken,
				ZoneToken: dnsOptions.CloudflareOptions.ZoneToken,
			}
		case C.DNSProviderACMEDNS:
			solver.DNSProvider = &acmedns.Provider{
				Username:  dnsOptions.ACMEDNSOptions.Username,
				Password:  dnsOptions.ACMEDNSOptions.Password,
				Subdomain: dnsOptions.ACMEDNSOptions.Subdomain,
				ServerURL: dnsOptions.ACMEDNSOptions.ServerURL,
			}
		default:
			return nil, nil, E.New("unsupported ACME DNS01 provider type: " + dnsOptions.Provider)
		}
		acmeConfig.DNS01Solver = &solver
	}
	if options.ExternalAccount != nil && options.ExternalAccount.KeyID != "" {
		acmeConfig.ExternalAccount = (*acme.EAB)(options.ExternalAccount)
	}
	config.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(config, acmeConfig)}
	wrapper := &acmeWrapper{
		ctx:           ctx,
		cfg:           config,
		zapLogger:     zapLogger,
		dataDirectory: dataDirectory,
		domain:        options.Domain,
	}
	if adapter.IsRuntimePreparation(ctx) {
		var err error
		wrapper.runtime, err = NewRuntimeACME(ctx, logger, *config, acmeConfig, nil, options.Domain, dataDirectory, true)
		if err != nil {
			return nil, nil, err
		}
	}
	var tlsConfig *tls.Config
	if acmeConfig.DisableTLSALPNChallenge || acmeConfig.DNS01Solver != nil {
		tlsConfig = &tls.Config{
			GetCertificate: wrapper.GetCertificate,
		}
	} else {
		tlsConfig = &tls.Config{
			GetCertificate: wrapper.GetCertificate,
			NextProtos:     []string{C.ACMETLS1Protocol},
		}
	}
	return tlsConfig, wrapper, nil
}

func (w *acmeWrapper) RuntimeValidate() error {
	if w.runtime == nil {
		return E.New("inline ACME was not privately constructed")
	}
	return w.runtime.RuntimeValidate()
}

func (w *acmeWrapper) RuntimeResourceID() adapter.RuntimeResourceID {
	if w.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return w.runtime.RuntimeResourceID()
}
func (w *acmeWrapper) StageRuntime(ctx context.Context) error { return w.runtime.StageRuntime(ctx) }
func (w *acmeWrapper) CompensateRuntime() error               { return w.runtime.CompensateRuntime() }
func (w *acmeWrapper) RuntimeActivate()                       { w.runtime.RuntimeActivate() }
func (w *acmeWrapper) RuntimeStop()                           { w.runtime.RuntimeStop() }
func (w *acmeWrapper) RuntimeCloseAndWait() error             { return w.Close() }
func (w *acmeWrapper) GetCertificateWithContext(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if w.runtime != nil {
		return w.runtime.GetCertificateWithContext(ctx, hello)
	}
	return w.cfg.GetCertificateWithContext(ctx, hello)
}

func (w *acmeWrapper) RuntimeExternalEffects() bool { return true }
