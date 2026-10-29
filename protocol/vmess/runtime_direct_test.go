package vmess

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coretls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	vm "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type runtimeDirectReadTail struct {
	net.Conn
	armed                                 atomic.Bool
	readOnce, closeOnce                   sync.Once
	readTail, releaseRead, closeRequested chan struct{}
	closes                                atomic.Int32
}

func (c *runtimeDirectReadTail) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.armed.Load() {
		c.readOnce.Do(func() { close(c.readTail); <-c.releaseRead })
	}
	return n, err
}

func (c *runtimeDirectReadTail) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closeRequested) })
	return c.Conn.Close()
}

type runtimeDirectEcho struct {
	payload  []byte
	release  <-chan struct{}
	echoed   chan error
	started  atomic.Bool
	finished chan struct{}
}

func (h *runtimeDirectEcho) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h.started.Store(true)
	defer close(h.finished)
	defer conn.Close()
	got := make([]byte, len(h.payload))
	_, err := io.ReadFull(conn, got)
	if err == nil && !bytes.Equal(got, h.payload) {
		err = errors.New("VMess request payload changed")
	}
	if err == nil {
		_, err = conn.Write(got)
	}
	h.echoed <- err
	if err == nil {
		_, _ = io.Copy(io.Discard, conn) // consume TLS close-notify until physical close
	}
	<-h.release
}

func (h *runtimeDirectEcho) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.started.Store(true)
	defer close(h.finished)
	defer conn.Close()
	if destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), M.Socksaddr{})
	}
	packet := buf.NewPacket()
	packet.Resize(512, 0) // preserve the real mux writer's response headroom
	address, err := conn.ReadPacket(packet)
	if err == nil && !bytes.Equal(packet.Bytes(), h.payload) {
		err = errors.New("VMess packet payload changed")
	}
	if err == nil {
		err = conn.WritePacket(packet, address)
	} else {
		packet.Release()
	}
	h.echoed <- err
	if err == nil {
		packet = buf.NewPacket()
		packet.Resize(512, 0)
		_, _ = conn.ReadPacket(packet)
		packet.Release()
	}
	<-h.release
}

// The actual direct branch receives an ordinary net.Conn, or the production
// common/tls dialer's private TLS conn, never a pre-wrapped simulated parent.
// A real VMess peer supplies valid response headers (including UDP and mux).
func TestRuntimeVMessDirectTCPAndTLSResponseClose(t *testing.T) {
	for _, secured := range []bool{false, true} {
		for _, mode := range []string{"tcp", "udp", "listen", "packetaddr", "xudp"} {
			for _, closeFirstRead := range []bool{false, true} {
				t.Run(fmt.Sprintf("tls=%t/%s/first-read-close=%t", secured, mode, closeFirstRead), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					wait := func(done <-chan struct{}, name string) {
						t.Helper()
						select {
						case <-done:
						case <-ctx.Done():
							t.Fatal(name, ctx.Err())
						}
					}
					a, b := net.Pipe()
					raw := &runtimeDirectReadTail{Conn: a, readTail: make(chan struct{}), releaseRead: make(chan struct{}), closeRequested: make(chan struct{})}
					releaseHandler := make(chan struct{})
					handler := &runtimeDirectEcho{payload: []byte("actual-direct-response"), release: releaseHandler, echoed: make(chan error, 1), finished: make(chan struct{})}
					peerDone := make(chan struct{})
					peerResult := make(chan error, 1)
					peerStarted := false
					var readOnce, handlerOnce sync.Once
					releaseRead := func() { readOnce.Do(func() { close(raw.releaseRead) }) }
					finishHandler := func() { handlerOnce.Do(func() { close(releaseHandler) }) }
					t.Cleanup(func() {
						releaseRead()
						finishHandler()
						_ = a.Close()
						_ = b.Close()
						if peerStarted {
							select {
							case <-peerDone:
							case <-time.After(5 * time.Second):
								t.Error("VMess peer did not join")
							}
						}
						if handler.started.Load() {
							select {
							case <-handler.finished:
							case <-time.After(5 * time.Second):
								t.Error("VMess handler did not join")
							}
						}
					})
					logger := log.NewNOPFactory().Logger()
					dialer := &runtimeDirectProtocolDialer{conn: raw}
					h := &Outbound{logger: logger, dialer: dialer, packetAddr: mode == "packetaddr", xudp: mode == "xudp"}
					peer := b
					if secured {
						key, cert, err := coretls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
						if err != nil {
							t.Fatal(err)
						}
						pair, err := stdtls.X509KeyPair(cert, key)
						if err != nil {
							t.Fatal(err)
						}
						peer = stdtls.Server(b, &stdtls.Config{Certificates: []stdtls.Certificate{pair}, MinVersion: stdtls.VersionTLS13})
						config, err := coretls.NewClient(ctx, logger, "localhost", option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{string(cert)}})
						if err != nil {
							t.Fatal(err)
						}
						h.tlsDialer = coretls.NewDialer(dialer, config)
					}
					const id = "00000000-0000-0000-0000-000000000001"
					srv := vm.NewService[int](handler)
					if err := srv.UpdateUsers([]int{0}, []string{id}, []int{0}); err != nil {
						t.Fatal(err)
					}
					peerStarted = true
					go func() {
						defer close(peerDone)
						defer peer.Close()
						peerResult <- srv.NewConnection(ctx, peer, M.Socksaddr{}, nil)
					}()
					var err error
					h.client, err = vm.NewClient(id, "zero", 0)
					if err != nil {
						t.Fatal(err)
					}
					destination := M.ParseSocksaddr("127.0.0.1:5353")
					var carrier io.Closer
					var write func() error
					var read func() ([]byte, error)
					if mode == "tcp" || mode == "udp" {
						conn, err := h.DialContext(ctx, mode, destination)
						if err != nil {
							t.Fatal(err)
						}
						carrier = conn
						write = func() error { _, err := conn.Write(handler.payload); return err }
						read = func() ([]byte, error) {
							p := make([]byte, len(handler.payload))
							_, err := io.ReadFull(conn, p)
							return p, err
						}
					} else {
						conn, err := h.ListenPacket(ctx, destination)
						if err != nil {
							t.Fatal(err)
						}
						carrier = conn
						write = func() error { _, err := conn.WriteTo(handler.payload, destination); return err }
						read = func() ([]byte, error) {
							p := make([]byte, 256)
							n, address, err := conn.ReadFrom(p)
							if err == nil && M.SocksaddrFromNet(address) != destination {
								err = errors.New("VMess response destination changed")
							}
							return p[:n], err
						}
					}
					closeWait := carrier.Close // the production legacy entry must join, not return Pending
					if err := write(); err != nil {
						t.Fatal(err)
					}
					if closeFirstRead {
						raw.armed.Store(true)
						readDone := make(chan struct{})
						go func() { defer close(readDone); _, _ = read() }()
						wait(raw.readTail, "first response read tail")
						closed := make(chan error, 1)
						go func() { closed <- closeWait() }()
						wait(raw.closeRequested, "actual TCP/TLS interruption")
						select {
						case err := <-closed:
							t.Fatal("protocol close bypassed first Read", err)
						default:
						}
						releaseRead()
						wait(readDone, "protocol first Read join")
						select {
						case err := <-closed:
							if err != nil {
								t.Fatal(err)
							}
						case <-ctx.Done():
							t.Fatal("protocol close did not join")
						}
					} else {
						p, err := read()
						if err != nil || !bytes.Equal(p, handler.payload) {
							t.Fatalf("real response changed: %q %v", p, err)
						}
						if err := <-handler.echoed; err != nil {
							t.Fatal(err)
						}
						if err := closeWait(); err != nil {
							t.Fatal(err)
						}
					}
					if err := closeWait(); err != nil || raw.closes.Load() != 1 {
						t.Fatal("close lost its unique physical result", err, raw.closes.Load())
					}
					finishHandler()
					wait(peerDone, "VMess protocol peer completion")
					if err := <-peerResult; !closeFirstRead && err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
						t.Fatal("VMess protocol peer failed", err)
					}
				})
			}
		}
	}
}
