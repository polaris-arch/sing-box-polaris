package v2raywebsocket_test

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttpupgrade"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	M "github.com/sagernet/sing/common/metadata"
)

type closeBarrierConn struct {
	net.Conn
	entered, proceed chan struct{}
	closes           atomic.Int32
}

func (c *closeBarrierConn) Close() error {
	c.closes.Add(1)
	_ = c.Conn.Close()
	close(c.entered)
	<-c.proceed
	return nil
}

type watchedWriteConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *watchedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

type upgradeDialer struct{ conn net.Conn }

func (d upgradeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (upgradeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func TestRuntimeProductionUpgradesJoinPhysicalClose(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade"} {
		for _, buffered := range []bool{false, true} {
			for _, early := range []string{"none", "before-write", "after-write"} {
				if kind == "httpupgrade" && early != "none" {
					continue
				}
				t.Run(fmt.Sprintf("%s/buffered-%v/early-%s", kind, buffered, early), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					left, right := net.Pipe()
					defer right.Close()
					raw := &closeBarrierConn{Conn: left, entered: make(chan struct{}), proceed: make(chan struct{})}
					var transport adapter.V2RayClientTransport
					owner, err := runtimegraph.NewResourceOwner(ctx, adapter.RuntimeResourceID{Incarnation: "upgrade", Sequence: 1}, nil, func() error { return transport.Close() })
					if err != nil {
						t.Fatal(err)
					}
					construction := adapter.ContextWithRuntimeResourceSource(ctx, owner)
					if kind == "ws" {
						options := option.V2RayWebsocketOptions{Path: "/"}
						if early != "none" {
							options.MaxEarlyData = 8
						}
						transport, err = v2raywebsocket.NewClient(construction, upgradeDialer{raw}, M.ParseSocksaddr("127.0.0.1:80"), options, nil)
					} else {
						transport, err = v2rayhttpupgrade.NewClient(construction, upgradeDialer{raw}, M.ParseSocksaddr("127.0.0.1:80"), option.V2RayHTTPUpgradeOptions{Path: "/"}, nil)
					}
					if err != nil {
						t.Fatal(err)
					}
					peerDone := make(chan error, 1)
					go func() {
						request, err := http.ReadRequest(bufio.NewReader(right))
						if err != nil {
							if early == "before-write" {
								err = nil
							}
							peerDone <- err
							return
						}
						response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
						if kind == "ws" {
							sum := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
							response += "Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
						}
						response += "\r\n"
						if buffered {
							if kind == "ws" {
								response += "\x82\x01x"
							} else {
								response += "x"
							}
						}
						_, err = io.WriteString(right, response)
						if err == nil {
							_, err = io.Copy(io.Discard, right)
						}
						if errors.Is(err, io.ErrClosedPipe) {
							err = nil
						}
						peerDone <- err
					}()
					conn, err := transport.DialContext(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if early == "after-write" {
						if _, err = conn.Write([]byte("early-data")); err != nil {
							t.Fatal(err)
						}
					}
					var lazyRead chan error
					if early == "before-write" {
						lazyRead = make(chan error, 1)
						go func() { _, readErr := conn.Read(make([]byte, 1)); lazyRead <- readErr }()
						for {
							snapshot := owner.CleanupSnapshot()
							if snapshot.Available && snapshot.References >= 2 {
								break
							}
							select {
							case <-ctx.Done():
								t.Fatal("lazy read was not admitted")
							default:
								runtime.Gosched()
							}
						}
					}
					owner.Seal()
					closed := make(chan error, 1)
					go func() { closed <- conn.Close() }()
					select {
					case <-raw.entered:
					case <-ctx.Done():
						t.Fatal("physical close was not requested")
					}
					if snapshot := owner.CleanupSnapshot(); snapshot.Available && snapshot.References == 0 {
						t.Fatal("lease released while physical close was still running")
					}
					select {
					case err = <-closed:
						t.Fatalf("premature close: %v", err)
					default:
					}
					close(raw.proceed)
					select {
					case err = <-closed:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("fixed completion barrier was lost")
					}
					if lazyRead != nil {
						select {
						case readErr := <-lazyRead:
							if readErr == nil {
								t.Fatal("lazy read falsely succeeded")
							}
						case <-ctx.Done():
							t.Fatal("lazy read did not leave on actual close request")
						}
					}
					if err = owner.WaitClosed(ctx); err != nil {
						t.Fatal(err)
					}
					var workers sync.WaitGroup
					for range 8 {
						workers.Go(func() {
							if err := conn.Close(); err != nil {
								t.Error(err)
							}
						})
					}
					workers.Wait()
					if raw.closes.Load() != 1 {
						t.Fatalf("physical closes=%d", raw.closes.Load())
					}
					if err = <-peerDone; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestRuntimeUpgradeFinalStopInterruptsBlockedIO(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			left, right := net.Pipe()
			defer right.Close()
			physical := &watchedWriteConn{Conn: left, entered: make(chan struct{})}
			var transport adapter.V2RayClientTransport
			var err error
			if kind == "ws" {
				transport, err = v2raywebsocket.NewClient(ctx, upgradeDialer{physical}, M.ParseSocksaddr("127.0.0.1:80"), option.V2RayWebsocketOptions{MaxEarlyData: 8}, nil)
			} else {
				transport, err = v2rayhttpupgrade.NewClient(ctx, upgradeDialer{physical}, M.ParseSocksaddr("127.0.0.1:80"), option.V2RayHTTPUpgradeOptions{}, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Never consume the handshake. Final stop must interrupt the physical
			// write/early creation rather than waiting for the protocol timeout.
			done := make(chan error, 1)
			go func() {
				c, err := transport.DialContext(ctx)
				if err == nil {
					_, err = c.Write([]byte("blocked"))
					_ = c.Close()
				}
				done <- err
			}()
			select {
			case <-physical.entered:
			case <-ctx.Done():
				t.Fatal("physical write was not entered")
			}
			transport.(interface{ StopRuntimeOperations() }).StopRuntimeOperations()
			select {
			case err = <-done:
				if err == nil {
					t.Fatal("blocked operation falsely succeeded")
				}
			case <-ctx.Done():
				t.Fatal("final stop did not interrupt physical work")
			}
			if err = transport.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
