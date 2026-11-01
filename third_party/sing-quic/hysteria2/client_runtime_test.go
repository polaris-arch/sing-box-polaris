package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
	"testing"
	"time"
)

func TestClientRuntimeJoinsActualWorkerAndRejectsNewWork(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.initRuntime()
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	if !c.runtime.run(func() { close(entered); <-release }) {
		t.Fatal("initial admission rejected")
	}
	<-entered
	go func() { _ = c.RuntimeCloseAndWait(); close(closed) }()
	select {
	case <-c.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("close did not cancel client lifetime")
	}
	select {
	case <-closed:
		t.Fatal("close certified an unfinished worker")
	default:
	}
	if c.runtime.run(func() { t.Error("sealed worker was dispatched") }) {
		t.Fatal("sealed admission accepted")
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("actual worker completion was not joined")
	}
	if _, err := c.offer(context.Background()); err == nil {
		t.Fatal("terminal client reused")
	}
	if err := c.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
func TestClientRuntimeCancelsPendingOfferBeforeJoin(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.initRuntime()
	ctx, cancel := context.WithCancelCause(c.ctx)
	c.pending = &clientOffer{done: make(chan struct{}), cancel: cancel}
	left := make(chan struct{})
	if !c.runtime.run(func() { <-ctx.Done(); close(left) }) {
		t.Fatal("admission")
	}
	if err := c.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-left:
	default:
		t.Fatal("pending offer was not joined")
	}
	if !c.pending.discarded {
		t.Fatal("late pending offer may publish")
	}
}

func realmRuntimeWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Realm ownership barrier did not finish")
	}
}

type realmRuntimePacket struct {
	closed      chan struct{}
	once        sync.Once
	closeErr    error
	writes      atomic.Int32
	addr        net.Addr
	readEntered chan struct{}
	readSignal  sync.Once
}

func newRealmRuntimePacket(ipv4 bool) *realmRuntimePacket {
	ip := net.ParseIP("::")
	if ipv4 {
		ip = net.IPv4zero
	}
	return &realmRuntimePacket{closed: make(chan struct{}), addr: &net.UDPAddr{IP: ip, Port: 23456}}
}
func (p *realmRuntimePacket) Close() error { p.once.Do(func() { close(p.closed) }); return p.closeErr }
func (p *realmRuntimePacket) ReadFrom([]byte) (int, net.Addr, error) {
	if p.readEntered != nil {
		p.readSignal.Do(func() { close(p.readEntered) })
	}
	<-p.closed
	return 0, nil, net.ErrClosed
}
func (p *realmRuntimePacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.writes.Add(1)
	return len(b), nil
}
func (p *realmRuntimePacket) LocalAddr() net.Addr            { return p.addr }
func (*realmRuntimePacket) SetDeadline(time.Time) error      { return nil }
func (*realmRuntimePacket) SetReadDeadline(time.Time) error  { return nil }
func (*realmRuntimePacket) SetWriteDeadline(time.Time) error { return nil }

type realmRuntimeDialer struct {
	listen func(context.Context, M.Socksaddr) (net.PacketConn, error)
}

func (d realmRuntimeDialer) ListenPacket(ctx context.Context, addr M.Socksaddr) (net.PacketConn, error) {
	return d.listen(ctx, addr)
}
func (realmRuntimeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected connected dial")
}

type realmRuntimeRoundTrip func(*http.Request) (*http.Response, error)

func (f realmRuntimeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Constructor-only TLS seam. An actual QUIC handshake is supplied separately by
// the existing provider adapter; this seam cannot manufacture a connected QUIC.
type realmRuntimeTLS struct{ aTLS.Config }

func (realmRuntimeTLS) NextProtos() []string { return []string{"h3"} }

func realmRuntimeClient(t *testing.T, ipVersion int, transport http.RoundTripper, dialer realmRuntimeDialer) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), Dialer: dialer, TLSConfig: realmRuntimeTLS{},
		RealmOptions: &realm.Options{ServerURL: "https://realm.invalid", RealmID: "test", IPVersion: ipVersion,
			STUNServers: []string{"192.0.2.1:3478", "[2001:db8::1]:3478"},
			Resolver: func(context.Context, string, bool, bool) ([]netip.Addr, error) {
				return nil, errors.New("literal STUN address invoked DNS")
			},
			HTTPClient: &http.Client{Transport: transport}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.RuntimeCloseAndWait() })
	return client
}
func realmConnectResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(
		`{"addresses":["192.0.2.2:4444","[2001:db8::2]:4444"],"nonce":"` + strings.Repeat("00", 16) + `","obfs":"` + strings.Repeat("00", 32) + `"}`))}
}

func TestRealmConstructorIsInertAndCapturesOptions(t *testing.T) {
	var effects atomic.Int32
	options := &realm.Options{ServerURL: "https://realm.invalid", RealmID: "before", IPVersion: 4,
		STUNServers: []string{"192.0.2.1:3478"}, PortMapping: &realm.PortMappingOptions{Lifetime: time.Minute},
		HTTPClient: &http.Client{Transport: realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) { effects.Add(1); return nil, errors.New("unexpected I/O") })}}
	c, err := NewClient(ClientOptions{Context: context.Background(), Logger: logger.NOP(), TLSConfig: realmRuntimeTLS{}, RealmOptions: options,
		Dialer: realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) {
			effects.Add(1)
			return nil, errors.New("unexpected I/O")
		}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.RuntimeCloseAndWait()
	options.RealmID = "after"
	options.STUNServers[0] = "changed.invalid"
	options.PortMapping.Lifetime = time.Hour
	options.HTTPClient.Transport = nil
	if effects.Load() != 0 || c.realmOptions.RealmID != "before" || c.realmOptions.STUNServers[0] != "192.0.2.1:3478" || c.realmOptions.PortMapping.Lifetime != time.Minute || c.realmOptions.HTTPClient.Transport == nil {
		t.Fatal("constructor performed I/O or retained mutable options")
	}
}

func TestRealmActualOfferPreservesFamiliesAndObfuscation(t *testing.T) {
	for _, version := range []int{0, 4, 6} {
		for _, obfs := range []string{"", "salamander", "gecko"} {
			t.Run(strings.Join([]string{map[int]string{0: "dual", 4: "v4", 6: "v6"}[version], obfs}, "/"), func(t *testing.T) {
				var packets []*realmRuntimePacket
				var mu sync.Mutex
				var httpCalls atomic.Int32
				c := realmRuntimeClient(t, version, realmRuntimeRoundTrip(func(r *http.Request) (*http.Response, error) {
					httpCalls.Add(1)
					if r.URL.Path != "/v1/test/connect" {
						t.Error("wrong Realm operation")
					}
					// Mapped IPv4 is a valid numeric control response and belongs to
					// the IPv4 socket, never the IPv6 punch merely due to encoding.
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(
						`{"addresses":["[::ffff:192.0.2.2]:4444","[2001:db8::2]:4444"],"nonce":"` + strings.Repeat("00", 16) + `","obfs":"` + strings.Repeat("00", 32) + `"}`))}, nil
				}), realmRuntimeDialer{listen: func(_ context.Context, addr M.Socksaddr) (net.PacketConn, error) {
					if !addr.Addr.IsUnspecified() || addr.Port != 0 || (version == 4 && !addr.Addr.Is4()) || (version == 6 && !addr.Addr.Is6()) {
						t.Error("family-specific bind request changed", addr)
					}
					p := newRealmRuntimePacket(addr.Addr.Is4())
					mu.Lock()
					packets = append(packets, p)
					mu.Unlock()
					return p, nil
				}})
				if obfs == "gecko" {
					c.geckoPassword = "test"
					c.geckoMinPacketSize = 64
					c.geckoMaxPacketSize = 128
				}
				if obfs == "salamander" {
					c.salamanderPassword = "test"
				}
				stopAtAuth := errors.New("authentication boundary reached")
				c.realmHooks = &realmClientHooks{
					discover: func(_ context.Context, p net.PacketConn, servers []netip.AddrPort) ([]netip.AddrPort, error) {
						// net.IPv4zero is the standard 16-byte mapped IPv4 form.
						// Classify its numeric family, not its slice representation.
						is4 := M.SocksaddrFromNet(p.LocalAddr()).Addr.Unmap().Is4()
						if len(servers) != 1 || servers[0].Addr().Is4() != is4 {
							t.Error("family policy changed")
						}
						return servers, nil
					},
					punch: func(_ context.Context, p net.PacketConn, peers []netip.AddrPort, _ realm.PunchMetadata) (realm.PunchResult, error) {
						if len(peers) != 1 || peers[0].Addr().Is4() != M.SocksaddrFromNet(p.LocalAddr()).Addr.Unmap().Is4() || peers[0].Addr().Is4In6() {
							t.Error("cross-family punch")
						}
						return realm.PunchResult{PeerAddr: peers[0]}, nil
					},
					authenticate: func(_ context.Context, p net.PacketConn, peer net.Addr) (*clientQUICConnection, error) {
						owned, ok := p.(*realmSessionPacketConn)
						if !ok {
							t.Error("session did not own carrier")
							return nil, stopAtAuth
						}
						switch obfs {
						case "gecko":
							if _, ok := owned.PacketConn.(*GeckoPacketConn); !ok {
								t.Error("Gecko bypassed")
							}
						case "salamander":
							if _, ok := owned.PacketConn.(*SalamanderPacketConn); !ok {
								t.Error("Salamander bypassed")
							}
						}
						if peer.String() == "" {
							t.Error("missing selected peer")
						}
						return nil, stopAtAuth
					},
				}
				_, err := c.offer(context.Background())
				if !errors.Is(err, stopAtAuth) || httpCalls.Load() != 1 {
					t.Fatalf("actual offer did not reach authentication: %v", err)
				}
				want := 1
				if version == 0 {
					want = 2
				}
				if len(packets) != want {
					t.Fatal("family listener count")
				}
				for _, p := range packets {
					select {
					case <-p.closed:
					default:
						t.Fatal("failed offer leaked family")
					}
				}
				if err = c.RuntimeCloseAndWait(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestRealmPunchWinnerJoinsLateSuccessfulLoser(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.initRuntime()
	defer c.RuntimeCloseAndWait()
	v4, v6 := newRealmRuntimePacket(true), newRealmRuntimePacket(false)
	families := []*realmFamilyConn{{family: "v4", ipv4: true, conn: &realmOwnedPacketConn{PacketConn: v4, runtime: &c.runtime}}, {family: "v6", conn: &realmOwnedPacketConn{PacketConn: v6, runtime: &c.runtime}}}
	lateEntered, lateReturned, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseNow := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	var v4Calls, v6Calls atomic.Int32
	c.realmHooks = &realmClientHooks{punch: func(_ context.Context, p net.PacketConn, peers []netip.AddrPort, _ realm.PunchMetadata) (realm.PunchResult, error) {
		ipv4 := M.SocksaddrFromNet(p.LocalAddr()).Addr.Unmap().Is4()
		if len(peers) != 1 || peers[0].Addr().Is4() != ipv4 {
			t.Error("punch used another family's peer set", peers)
		}
		if ipv4 {
			if p != families[0].conn || v4Calls.Add(1) != 1 {
				t.Error("IPv4 winner was dispatched more than once or through another carrier")
			}
			<-lateEntered
			return realm.PunchResult{PeerAddr: netip.MustParseAddrPort("192.0.2.2:1")}, nil
		}
		if p != families[1].conn || v6Calls.Add(1) != 1 {
			t.Error("IPv6 loser was dispatched more than once or through another carrier")
		}
		close(lateEntered)
		<-v6.closed
		<-release
		close(lateReturned)
		return realm.PunchResult{PeerAddr: netip.MustParseAddrPort("[2001:db8::2]:1")}, nil
	}}
	done := make(chan struct{})
	var winner *realmFamilyConn
	var err error
	go func() {
		winner, _, err = c.realmRacePunch(context.Background(), families, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:1"), netip.MustParseAddrPort("[2001:db8::2]:1")}, realm.PunchMetadata{})
		close(done)
	}()
	realmRuntimeWait(t, v6.closed)
	select {
	case <-done:
		t.Fatal("winner escaped late loser join")
	default:
	}
	releaseNow()
	realmRuntimeWait(t, done)
	if err != nil || winner != families[0] || v4Calls.Load() != 1 || v6Calls.Load() != 1 {
		t.Fatalf("winner changed: %v", err)
	}
	select {
	case <-lateReturned:
	default:
		t.Fatal("winner returned before the late successful loser actually left")
	}
	select {
	case <-v4.closed:
		t.Fatal("race cancellation closed winner")
	default:
	}
	_ = closeRealmFamilies(families)
}

func TestRealmLateFamilyListenerIsDisposedBeforeRetire(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseNow := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	packet := newRealmRuntimePacket(true)
	c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("late socket reached HTTP")
		return nil, net.ErrClosed
	}), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) {
		close(entered)
		<-release
		return packet, nil
	}})
	t.Cleanup(releaseNow)
	offerDone := make(chan struct{})
	go func() { _, _ = c.offer(context.Background()); close(offerDone) }()
	realmRuntimeWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = c.RuntimeCloseAndWait(); close(closed) }()
	realmRuntimeWait(t, c.ctx.Done())
	select {
	case <-closed:
		t.Fatal("late listener not joined")
	default:
	}
	releaseNow()
	realmRuntimeWait(t, closed)
	realmRuntimeWait(t, offerDone)
	realmRuntimeWait(t, packet.closed)
}

type realmRuntimeBody struct {
	entered   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

func (b *realmRuntimeBody) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *realmRuntimeBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed); close(b.release) })
	return b.closeErr
}

func TestRealmResetCancelsActualControlBodyAndKeepsCloseDebt(t *testing.T) {
	failure := errors.New("control body close failed")
	body := &realmRuntimeBody{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), closeErr: failure}
	packet := newRealmRuntimePacket(true)
	c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	}), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
	c.realmHooks = &realmClientHooks{discover: func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error) {
		return []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}, nil
	}}
	done := make(chan struct{})
	go func() { _, _ = c.offer(context.Background()); close(done) }()
	realmRuntimeWait(t, body.entered)
	_ = c.CloseWithError(errors.New("network reset"))
	realmRuntimeWait(t, done)
	realmRuntimeWait(t, body.closed)
	realmRuntimeWait(t, packet.closed)
	if err := c.RuntimeCloseAndWait(); !errors.Is(err, failure) {
		t.Fatalf("body close debt lost: %v", err)
	}
}

func TestRealmForegroundTimeoutDoesNotCancelSharedControlOffer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	packet := newRealmRuntimePacket(true)
	c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return nil, r.Context().Err()
	}), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
	t.Cleanup(releaseNow)
	c.realmHooks = &realmClientHooks{discover: func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error) {
		return []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _, _ = c.offer(ctx); close(done) }()
	realmRuntimeWait(t, entered)
	cancel()
	realmRuntimeWait(t, done)
	select {
	case <-packet.closed:
		t.Fatal("foreground cancellation destroyed shared offer")
	default:
	}
	closed := make(chan struct{})
	go func() { _ = c.RuntimeCloseAndWait(); close(closed) }()
	realmRuntimeWait(t, c.ctx.Done())
	select {
	case <-closed:
		t.Fatal("retire certified slow HTTP callback")
	default:
	}
	releaseNow()
	realmRuntimeWait(t, closed)
	realmRuntimeWait(t, packet.closed)
}

type realmRuntimeMapper struct {
	entered, stopped, release chan struct{}
	renewErr, deleteErr       error
	once                      sync.Once
}

func (*realmRuntimeMapper) ExternalAddr() netip.AddrPort {
	return netip.MustParseAddrPort("192.0.2.10:23456")
}
func (m *realmRuntimeMapper) KeepAliveContext(ctx context.Context) error {
	close(m.entered)
	<-ctx.Done()
	close(m.stopped)
	<-m.release
	return errors.Join(m.renewErr, m.Close())
}
func (m *realmRuntimeMapper) Close() error { m.once.Do(func() {}); return m.deleteErr }
func TestRealmSessionJoinsMapperAndPreservesRenewDeleteFailures(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.initRuntime()
	t.Cleanup(func() { _ = c.RuntimeCloseAndWait() })
	failure, removeFailure := errors.New("renew failed"), errors.New("delete failed")
	m := &realmRuntimeMapper{entered: make(chan struct{}), stopped: make(chan struct{}), release: make(chan struct{}), renewErr: failure, deleteErr: removeFailure}
	var once sync.Once
	release := func() { once.Do(func() { close(m.release) }) }
	t.Cleanup(release)
	packet := newRealmRuntimePacket(true)
	s := &clientRealmSession{client: c, families: []*realmFamilyConn{{conn: &realmOwnedPacketConn{PacketConn: packet, runtime: &c.runtime}}}}
	if err := s.startMapper(m); err != nil {
		t.Fatal(err)
	}
	realmRuntimeWait(t, m.entered)
	done := make(chan struct{})
	var closeErr error
	go func() { closeErr = s.Close(); close(done) }()
	realmRuntimeWait(t, m.stopped)
	select {
	case <-done:
		t.Fatal("mapping delete not joined")
	default:
	}
	release()
	realmRuntimeWait(t, done)
	if !errors.Is(closeErr, failure) || !errors.Is(closeErr, removeFailure) {
		t.Fatalf("mapping debt lost: %v", closeErr)
	}
	if err := c.RuntimeCloseAndWait(); !errors.Is(err, failure) || !errors.Is(err, removeFailure) {
		t.Fatalf("runtime forgot mapping debt: %v", err)
	}
}

func TestRealmOptionalMappingFailureChargesOnlyUnresolvedCleanup(t *testing.T) {
	failure := errors.New("NAT mapping unavailable")
	for _, test := range []struct {
		name   string
		err    error
		mapper realmPortMapper
		debt   bool
	}{
		{name: "joined-canceled-discovery", err: context.Canceled},
		{name: "confirmed-cleaned-operation", err: failure},
		{name: "unknown-create-or-delete", err: &realmCleanupError{failure}, debt: true},
		{name: "partial-mapper-close-fails", err: failure, mapper: &realmRuntimeMapper{deleteErr: failure}, debt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := newRealmRuntimePacket(true)
			c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
				t.Error("failed STUN reached control HTTP")
				return nil, errors.New("unexpected HTTP")
			}), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
			c.realmOptions.PortMapping = &realm.PortMappingOptions{}
			stopAtSTUN := errors.New("controlled STUN stop")
			c.realmHooks = &realmClientHooks{
				newMapper: func(context.Context, uint16, realm.PortMappingOptions) (realmPortMapper, error) {
					return test.mapper, test.err
				},
				discover: func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error) {
					return nil, stopAtSTUN
				},
			}
			if _, err := c.offer(context.Background()); !errors.Is(err, stopAtSTUN) {
				t.Fatal("optional mapping changed normal STUN fallback", err)
			}
			err := c.RuntimeCloseAndWait()
			var incomplete interface{ RuntimeCleanupIncomplete() bool }
			if (err != nil) != test.debt || (errors.As(err, &incomplete) && incomplete.RuntimeCleanupIncomplete()) != test.debt {
				t.Fatalf("mapping cleanup classification: %v", err)
			}
			select {
			case <-packet.closed:
			default:
				t.Fatal("mapping fallback leaked its family")
			}
		})
	}
}

func TestRealmMappingCapturesExplicitHTTPWithoutConstructorIO(t *testing.T) {
	var calls atomic.Int32
	clientHTTP := &http.Client{Transport: realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	var resolverCalls atomic.Int32
	realmOptions := &realm.Options{ServerURL: "https://realm.invalid", RealmID: "fixture", IPVersion: 4,
		HTTPClient: clientHTTP, PortMapping: &realm.PortMappingOptions{HTTPClient: clientHTTP},
		Resolver: func(context.Context, string, bool, bool) ([]netip.Addr, error) {
			resolverCalls.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
		},
	}
	c, err := NewClient(ClientOptions{
		Context: context.Background(), Logger: logger.NOP(), TLSConfig: realmRuntimeTLS{},
		RealmOptions: realmOptions,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.RuntimeCloseAndWait() })
	clientHTTP.Transport = realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("captured mapping client followed later caller mutation")
		return nil, errors.New("mutated client")
	})
	if calls.Load() != 0 || resolverCalls.Load() != 0 {
		t.Fatal("mapping constructor performed HTTP or DNS")
	}
	realmOptions.Resolver = func(context.Context, string, bool, bool) ([]netip.Addr, error) {
		t.Error("mapping followed later resolver mutation")
		return nil, errors.New("mutated resolver")
	}
	addresses, err := c.realmOptions.PortMapping.Resolver(context.Background(), "localhost", true, false)
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.2") || resolverCalls.Load() != 1 {
		t.Fatal("mapping lost captured resolver", addresses, err)
	}
	response, err := c.realmOptions.PortMapping.HTTPClient.Get("http://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil || calls.Load() != 1 {
		t.Fatal("captured mapping HTTP body was not closed", err)
	}
}

func TestRealmNativeSTUNAndPunchReadsAreCanceledAndJoined(t *testing.T) {
	for _, stage := range []string{"stun", "punch"} {
		t.Run(stage, func(t *testing.T) {
			packet := newRealmRuntimePacket(true)
			packet.readEntered = make(chan struct{})
			c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) { return realmConnectResponse(), nil }), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
			if stage == "punch" {
				c.realmHooks = &realmClientHooks{discover: func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error) {
					return []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}, nil
				}}
			}
			done := make(chan struct{})
			go func() { _, _ = c.offer(context.Background()); close(done) }()
			realmRuntimeWait(t, packet.readEntered)
			if packet.writes.Load() == 0 {
				t.Fatal("native STUN/punch path did not send")
			}
			if err := c.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
			realmRuntimeWait(t, done)
			realmRuntimeWait(t, packet.closed)
		})
	}
}

func TestRealmActualSTUNDNSBatchJoinsLateResolver(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	packet := newRealmRuntimePacket(true)
	c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("late DNS reached control request")
		return nil, net.ErrClosed
	}), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
	t.Cleanup(releaseNow)
	c.realmOptions.STUNServers = []string{"stun.invalid:3478"}
	c.realmOptions.Resolver = func(ctx context.Context, _ string, v4, v6 bool) ([]netip.Addr, error) {
		if !v4 || v6 {
			t.Error("DNS family strategy changed")
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	}
	offerDone := make(chan struct{})
	go func() { _, _ = c.offer(context.Background()); close(offerDone) }()
	realmRuntimeWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = c.RuntimeCloseAndWait(); close(closed) }()
	realmRuntimeWait(t, canceled)
	select {
	case <-closed:
		t.Fatal("native DNS batch was not joined")
	default:
	}
	releaseNow()
	realmRuntimeWait(t, closed)
	realmRuntimeWait(t, offerDone)
	realmRuntimeWait(t, packet.closed)
}

func TestRealmResetDiscardsLateAuthenticationAndRetainsItsCloseFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	packet := newRealmRuntimePacket(true)
	failure := errors.New("late authenticated carrier close failed")
	packet.closeErr = failure
	c := realmRuntimeClient(t, 4, realmRuntimeRoundTrip(func(*http.Request) (*http.Response, error) { return realmConnectResponse(), nil }), realmRuntimeDialer{listen: func(context.Context, M.Socksaddr) (net.PacketConn, error) { return packet, nil }})
	t.Cleanup(releaseNow)
	c.realmHooks = &realmClientHooks{
		discover: func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error) {
			return []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}, nil
		},
		punch: func(context.Context, net.PacketConn, []netip.AddrPort, realm.PunchMetadata) (realm.PunchResult, error) {
			return realm.PunchResult{PeerAddr: netip.MustParseAddrPort("192.0.2.2:443")}, nil
		},
		authenticate: func(_ context.Context, p net.PacketConn, _ net.Addr) (*clientQUICConnection, error) {
			close(entered)
			<-release
			conn := &clientQUICConnection{rawConn: p, connDone: make(chan struct{}), udpConnMap: make(map[uint32]*udpPacketConn)}
			c.runtime.register(conn)
			return conn, nil
		},
	}
	done := make(chan struct{})
	var offerErr error
	go func() { _, offerErr = c.offer(context.Background()); close(done) }()
	realmRuntimeWait(t, entered)
	reset := errors.New("reset generation")
	_ = c.CloseWithError(reset)
	releaseNow()
	realmRuntimeWait(t, done)
	if !errors.Is(offerErr, reset) {
		t.Fatal("discarded offer published", offerErr)
	}
	if err := c.RuntimeCloseAndWait(); !errors.Is(err, failure) {
		t.Fatal("late close debt lost", err)
	}
	realmRuntimeWait(t, packet.closed)
}

type realmRuntimeCloser func() error

func (f realmRuntimeCloser) Close() error { return f() }

type realmRuntimeClosingTransport struct {
	realmRuntimeRoundTrip
	close func() error
}

func (t realmRuntimeClosingTransport) Close() error { return t.close() }
func TestRealmAuthenticationFailureInterruptsAllResourcesBeforeJoin(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.initRuntime()
	defer c.RuntimeCloseAndWait()
	transportEntered, bodyEntered := make(chan struct{}), make(chan struct{})
	var transportOnce, bodyOnce sync.Once
	openTransport := func() { transportOnce.Do(func() { close(transportEntered) }) }
	openBody := func() { bodyOnce.Do(func() { close(bodyEntered) }) }
	t.Cleanup(openTransport)
	t.Cleanup(openBody)
	failure, cause := errors.New("body close failed"), errors.New("authentication failed")
	raw := realmRuntimeCloser(func() error { <-transportEntered; return nil })
	transport := realmRuntimeClosingTransport{close: func() error { openTransport(); <-bodyEntered; return nil }}
	body := &realmRuntimeCloseBody{close: func() error { openBody(); return failure }}
	done := make(chan struct{})
	var err error
	go func() { err = c.closeFailedAuthentication(raw, transport, nil, body, cause); close(done) }()
	realmRuntimeWait(t, done)
	if !errors.Is(err, cause) || !errors.Is(err, failure) {
		t.Fatal("parallel cleanup lost error", err)
	}
}

type realmRuntimeCloseBody struct{ close func() error }

func (*realmRuntimeCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *realmRuntimeCloseBody) Close() error           { return b.close() }
