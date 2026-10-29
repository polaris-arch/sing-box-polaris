package box

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type runtimeBootstrapNTPConn struct {
	bytes.Reader
	target time.Time
}

func (c *runtimeBootstrapNTPConn) Write(request []byte) (int, error) {
	packet := make([]byte, 48)
	packet[0] = 0x24
	packet[1] = 1
	stamp := uint64(c.target.Unix()+2208988800) << 32
	for _, offset := range []int{16, 32, 40} {
		binary.BigEndian.PutUint64(packet[offset:offset+8], stamp)
	}
	copy(packet[24:32], request[40:48])
	c.Reader.Reset(packet)
	return len(request), nil
}
func (*runtimeBootstrapNTPConn) Close() error { return nil }
func (*runtimeBootstrapNTPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (*runtimeBootstrapNTPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}
func (*runtimeBootstrapNTPConn) SetDeadline(time.Time) error      { return nil }
func (*runtimeBootstrapNTPConn) SetReadDeadline(time.Time) error  { return nil }
func (*runtimeBootstrapNTPConn) SetWriteDeadline(time.Time) error { return nil }

func TestRuntimeOriginCATrustedTLSBootstrapsOffsetOnColdStartAndClockReplacement(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed validity independent of the machine's clock. Ordinary TLS validation
	// at an uncorrected 2026 host must fail; there is no Insecure verification.
	ca := &x509.Certificate{SerialNumber: big.NewInt(19), DNSNames: []string{"api.cloudflare.com"}, NotBefore: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2033, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	if _, err = parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.cloudflare.com", CurrentTime: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("fixture did not require clock correction")
	}
	if _, err = parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.cloudflare.com", CurrentTime: time.Now()}); err == nil {
		t.Skip("fixed skew fixture requires the host clock outside the fixed 2030–2033 CA validity")
	}
	server := stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	var samples, issued atomic.Int64
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "bootstrap.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(_ context.Context, network string, address M.Socksaddr) (net.Conn, error) {
			if network == "udp" {
				year := 2031
				if address.Addr.String() == "192.0.2.124" {
					year = 2032
				}
				samples.Add(1)
				return &runtimeBootstrapNTPConn{target: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
			}
			return runtimeCertificateTestPipe(t, key, ca, server, issued.Add(1)+19), nil
		}
		return nil
	})
	originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
	provider := &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"bootstrap.invalid"}, DataDirectory: filepath.Join(t.TempDir(), "cold"), APIToken: "fixture-token", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}
	options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: provider}}
	options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a", TLS: &option.OutboundTLSOptions{Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}}}
	options.NTP = &option.NTPOptions{Enabled: true, Server: "192.0.2.123", Detour: "a"}
	runtimeResourceNew(t, f, options)
	if samples.Load() != 0 || issued.Load() != 0 {
		t.Fatal("New performed clock/certificate effects")
	}
	f.start(t)
	if samples.Load() != 1 || issued.Load() != 1 || !f.box.RuntimeCapabilities().Enabled {
		t.Fatal("trusted first issuance failed to bootstrap/publish exactly once", samples.Load(), issued.Load())
	}
	oldLease, oldView := f.acquire(t)
	oldClock := runtimeTestResource(t, f, oldView.componentIDs["ntp"]).components["ntp"].clock
	if oldClock.TimeFunc()().Year() != 2031 {
		t.Fatal("cold TLS consumer clock was not corrected")
	}
	options.NTP.Server = "192.0.2.124"
	provider.DataDirectory = filepath.Join(t.TempDir(), "replacement")
	provider.Domain = []string{"replacement.invalid"}
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	if samples.Load() != 1 || issued.Load() != 1 {
		t.Fatal("Plan sampled or issued")
	}
	result := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	if result.Active.Revision != apply.Expected.Revision+1 {
		t.Fatal("replacement issuer could not bootstrap its private clock", result)
	}
	newLease, newView := f.acquire(t)
	defer newLease.Release()
	newClock := runtimeTestResource(t, f, newView.componentIDs["ntp"]).components["ntp"].clock
	if oldClock == newClock || oldClock.TimeFunc()().Year() != 2031 || newClock.TimeFunc()().Year() != 2032 || samples.Load() != 2 || issued.Load() != 2 {
		t.Fatal("clock bootstrap crossed epochs or duplicated initial sampling", samples.Load(), issued.Load())
	}
	oldLease.Release()
}

// An actual Exchange binary.Read sees a truncated datagram; terminal Close is
// separately observable and can report uncertainty instead of being discarded.
type runtimeUnavailableNTPConn struct {
	runtimeResourceClockConn
	reply    bytes.Reader
	closeErr error
	closes   atomic.Int32
}

func (c *runtimeUnavailableNTPConn) Read(p []byte) (int, error) { return c.reply.Read(p) }
func (c *runtimeUnavailableNTPConn) Close() error {
	c.closes.Add(1)
	_ = c.runtimeResourceClockConn.Close()
	return c.closeErr
}

func TestRuntimeOriginCANormalTimeAndCacheSurviveJoinedUnavailableNTP(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for _, failure := range []string{"udp-dial", "short-reply"} {
			t.Run(fmt.Sprintf("cache=%t/%s", cached, failure), func(t *testing.T) {
				key, ca, server := runtimeCertificateTestSigner(t)
				directory := filepath.Join(t.TempDir(), "cache")
				var issued, samples atomic.Int64
				var carrier *runtimeUnavailableNTPConn
				construct := func(enableNTP bool) (*runtimeTestFixture, Options) {
					f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "best-effort-time.test"), func(o *runtimeTestSocks) error {
						o.dialHook = func(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
							if network == "udp" {
								samples.Add(1)
								if failure == "udp-dial" {
									return nil, &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}
								}
								carrier = &runtimeUnavailableNTPConn{closed: make(chan struct{})}
								carrier.reply.Reset([]byte{0x24, 1, 0, 0})
								return carrier, nil
							}
							return runtimeCertificateTestPipe(t, key, ca, server, issued.Add(1)+1), nil
						}
						return nil
					})
					originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
					// The current-time CA is actually trusted and hostname checked. A zero
					// offset is valid here, and an NTP outage must not disable TLS or cache use.
					options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a", TLS: &option.OutboundTLSOptions{ServerName: "fixture.invalid", Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]}))}}}}
					options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"best-effort.invalid"}, DataDirectory: directory, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}}}
					if enableNTP {
						options.NTP = &option.NTPOptions{Enabled: true, Server: "192.0.2.123", Detour: "a"}
					}
					return f, options
				}
				if cached {
					seed, options := construct(false)
					runtimeResourceNew(t, seed, options)
					seed.start(t)
					if issued.Load() != 1 {
						t.Fatal("seed did not issue a real cached certificate")
					}
					if err := seed.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
						t.Fatal(err)
					}
					if err := seed.box.CloseWithResult(); err != nil {
						t.Fatal(err)
					}
				}
				beforeIssued := issued.Load()
				f, options := construct(true)
				runtimeResourceNew(t, f, options)
				if samples.Load() != 0 || issued.Load() != beforeIssued {
					t.Fatal("New performed sampling or certificate IO")
				}
				f.start(t)
				wantIssued := beforeIssued
				if !cached {
					wantIssued++
				}
				if samples.Load() != 1 || issued.Load() != wantIssued || !f.box.RuntimeCapabilities().Enabled {
					t.Fatal("ordinary joined NTP failure blocked trusted CA/cache startup", samples.Load(), issued.Load())
				}
				if failure == "short-reply" && (carrier == nil || carrier.closes.Load() != 1) {
					t.Fatal("truncated response was downgraded before actual carrier close")
				}
				lease, view := f.acquire(t)
				defer lease.Release()
				clock := runtimeTestResource(t, f, view.componentIDs["ntp"]).components["ntp"].clock
				if corrected := clock.TimeFunc()(); time.Until(corrected) > time.Second || time.Since(corrected) > time.Second {
					t.Fatal("failed NTP sample changed offset")
				}
			})
		}
	}
}

func TestRuntimeCertificateBootstrapCancellationForeignOwnerAndUnknownCleanupStillAbort(t *testing.T) {
	for _, failure := range []string{"cancel", "foreign-owner", "unknown-cleanup"} {
		t.Run(failure, func(t *testing.T) {
			entered := make(chan struct{})
			var enteredOnce sync.Once
			var foreign adapter.RuntimeResourceSource
			var rejected atomic.Bool
			var httpCalls atomic.Int32
			carrier := &runtimeUnavailableNTPConn{closed: make(chan struct{}), closeErr: errors.New("fixture actual UDP close completion unknown")}
			carrier.reply.Reset([]byte{0x24, 1, 0, 0})
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "bootstrap-fatal.test"), func(o *runtimeTestSocks) error {
				o.dialHook = func(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
					if network != "udp" {
						httpCalls.Add(1)
						return nil, errors.New("certificate HTTP must not start after fatal bootstrap")
					}
					switch failure {
					case "cancel":
						enteredOnce.Do(func() { close(entered) })
						<-ctx.Done()
						return nil, &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}
					case "foreign-owner":
						_, err := outbound.ValidateRuntimeOwnedSession(ctx, foreign)
						rejected.Store(err != nil)
						if err == nil {
							err = errors.New("foreign owner unexpectedly accepted")
						}
						return nil, err
					default:
						return carrier, nil
					}
				}
				return nil
			})
			originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
			instance, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			f.box = instance
			t.Cleanup(func() {
				err := instance.CloseWithResult()
				if failure != "unknown-cleanup" && err != nil {
					t.Error(err)
				}
			})
			f.start(t)
			before := f.identity()
			oldLease, oldView := f.acquire(t)
			defer oldLease.Release()
			foreign = runtimeTestResource(t, f, oldView.componentIDs["outbound:b"]).owner
			options.NTP = &option.NTPOptions{Enabled: true, Server: "192.0.2.123", Detour: "a"}
			options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"fatal.invalid"}, DataDirectory: filepath.Join(t.TempDir(), "new"), APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC}}}
			_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
			ctx, cancel := context.WithCancel(runtimeTestContext(t))
			defer cancel()
			pending := runtimeTestApplyAsync(f, ctx, apply)
			if failure == "cancel" {
				runtimeTestWait(t, entered, "bootstrap entered actual UDP dial")
				cancel()
			}
			operation := runtimeTestReceiveApply(t, pending)
			if operation.Active != before || f.identity() != before || httpCalls.Load() != 0 {
				t.Fatal("fatal bootstrap was downgraded or changed old graph", operation, httpCalls.Load())
			}
			if failure == "foreign-owner" && !rejected.Load() {
				t.Fatal("fixture did not exercise real foreign-owner validation")
			}
			if failure == "unknown-cleanup" {
				var held *runtimeResource
				instance.runtime.access.Lock()
				for _, r := range instance.runtime.catalog {
					if r.components["ntp"] != nil {
						held = r
					}
				}
				instance.runtime.access.Unlock()
				if held == nil {
					t.Fatal("unknown NTP allocation disappeared")
				}
				if err := held.owner.WaitClosed(runtimeTestContext(t)); err == nil {
					t.Fatal("actual close uncertainty was lost")
				}
				instance.runtime.access.Lock()
				instance.runtime.pruneRuntimeCatalogLocked()
				retained := instance.runtime.catalog[held.id] != nil
				instance.runtime.access.Unlock()
				if !retained || carrier.closes.Load() != 1 {
					t.Fatal("unknown carrier owner was released or terminal close was not joined")
				}
			}
		})
	}
}
