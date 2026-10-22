package tfo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bound diagnoses a stalled fixture; it is never a reason to skip a case
// or accept missing data/EOF. Keep the protocol's read/write/half-close order.
const tcpFixtureTimeout = 10 * time.Second

type tcpTestSession struct {
	t         *testing.T
	ctx       context.Context
	cancel    context.CancelFunc
	ln        *net.TCPListener
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	conns     map[*net.TCPConn]string
	done      chan struct{}
	acceptErr error // read only after done
	stop      func() bool
	expired   chan struct{}
}

func newTCPTestSession(t *testing.T, ln *net.TCPListener) *tcpTestSession {
	t.Helper()
	return newTCPTestSessionWithTimeout(t, ln, tcpFixtureTimeout)
}

func newTCPTestSessionWithTimeout(t *testing.T, ln *net.TCPListener, timeout time.Duration) *tcpTestSession {
	t.Helper()
	deadline := time.Now().Add(timeout)
	if outer, ok := t.Deadline(); ok && outer.Before(deadline) {
		deadline = outer.Add(-time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	s := &tcpTestSession{
		t: t, ctx: ctx, cancel: cancel, ln: ln,
		conns: make(map[*net.TCPConn]string), done: make(chan struct{}), expired: make(chan struct{}),
	}
	s.stop = context.AfterFunc(ctx, func() {
		defer close(s.expired)
		t.Errorf("TCP fixture deadline: %v (missing progress is a failure, not a skip)", ctx.Err())
		s.mu.Lock()
		for c, role := range s.conns {
			logTCPTestState(t, role+" at deadline", c)
		}
		s.mu.Unlock()
		s.closeNetwork()
	})
	t.Cleanup(s.close)
	return s
}

func (s *tcpTestSession) track(c *net.TCPConn, role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.conns[c] = role
	logTCPTestState(s.t, role, c)
	return true
}

func (s *tcpTestSession) start(serve func(*net.TCPConn)) {
	go func() {
		defer close(s.done)
		c, err := s.ln.AcceptTCP()
		if err != nil {
			s.acceptErr = err
			return
		}
		defer c.Close()
		if !s.track(c, "server accepted") {
			return
		}
		serve(c)
	}()
}

func (s *tcpTestSession) dial(d Dialer, data []byte) *net.TCPConn {
	s.t.Helper()
	c, err := d.DialContext(s.ctx, "tcp", s.ln.Addr().String(), data)
	if err != nil {
		s.t.Fatalf("client dial: %v", err)
	}
	tc := c.(*net.TCPConn)
	if !s.track(tc, "client dialed") {
		s.t.Fatal("client connected after fixture closed")
	}
	return tc
}

func (s *tcpTestSession) wait() {
	s.t.Helper()
	<-s.done
	if s.acceptErr != nil {
		s.t.Errorf("server accept: %v", s.acceptErr)
	}
	if err := s.ctx.Err(); err != nil {
		s.t.Errorf("TCP fixture incomplete: %v", err)
	}
}

func (s *tcpTestSession) closeNetwork() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.ln.Close() // interrupts accept, including cleanup before a client connects
	for c := range s.conns {
		c.Close()
	} // interrupts every owned read/write
}

func (s *tcpTestSession) close() {
	// Join the deadline callback too: no logger or socket mutator may outlive t.
	s.closeOnce.Do(func() {
		if !s.stop() {
			<-s.expired
		}
		s.cancel()
		s.closeNetwork()
		<-s.done
	})
}

func closeTCPTestWrite(t *testing.T, c *net.TCPConn) bool {
	t.Helper()
	if err := c.CloseWrite(); err != nil {
		logTCPTestState(t, "CloseWrite failed", c)
		t.Errorf("CloseWrite: %v", err)
		return false
	}
	return true
}

func logTCPTestState(t *testing.T, phase string, c *net.TCPConn) {
	t.Helper()
	multipath, err := c.MultipathTCP()
	t.Logf("%s: %s -> %s MultipathTCP=%t error=%v %s", phase, c.LocalAddr(), c.RemoteAddr(), multipath, err, tcpTestSocketState(c))
}

func TestTCPFixtureCleanupJoinsBlockedAccept(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	s := newTCPTestSession(t, ln)
	s.start(func(*net.TCPConn) { t.Error("unexpected connection") })
	s.close()
	select {
	case <-s.done:
	default:
		t.Fatal("accept goroutine not joined")
	}
	if s.acceptErr == nil {
		t.Fatal("closed listener did not report accept error")
	}
}

func TestTCPFixtureCleanupJoinsBlockedRead(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	s := newTCPTestSession(t, ln)
	entered := make(chan struct{})
	readErr := make(chan error, 1)
	s.start(func(c *net.TCPConn) {
		close(entered)
		var b [1]byte
		_, err := c.Read(b[:])
		readErr <- err
	})
	c := s.dial(Dialer{DisableTFO: true}, nil)
	<-entered
	s.close()
	if err := <-readErr; err == nil {
		t.Fatal("blocked read did not fail on cleanup")
	}
	if _, err := c.Write([]byte{1}); err == nil {
		t.Fatal("client socket survived cleanup")
	}
}

func TestTCPFixtureAcceptFailureCompletes(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	s := newTCPTestSession(t, ln)
	ln.Close()
	s.start(func(*net.TCPConn) { t.Error("unexpected connection") })
	<-s.done
	if s.acceptErr == nil {
		t.Fatal("accept error lost")
	}
}

// Run deliberate failures in a child test process so a lost EOF, failed accept,
// or failed half-close cannot silently become a passing parent regression.
func TestTCPFixtureFailureDiagnostics(t *testing.T) {
	const modeEnv = "TFO_FIXTURE_FAILURE_MODE"
	if mode := os.Getenv(modeEnv); mode != "" {
		t.Cleanup(func() { t.Log("fixture cleanup joined") })
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback})
		if err != nil {
			t.Fatal(err)
		}
		s := newTCPTestSessionWithTimeout(t, ln, time.Second)
		if mode == "accept" {
			ln.Close()
			s.start(func(*net.TCPConn) { t.Error("unexpected connection") })
			s.wait()
			return
		}
		s.start(func(c *net.TCPConn) {
			if mode == "half-close" {
				return
			}
			write(c, worldhello, t)
			// Deliberately omit CloseWrite: all response bytes are available but EOF
			// is not, exactly the failure shape the original unbounded fixture hid.
			readUntilEOF(c, helloworld, t)
		})
		c := s.dial(Dialer{DisableTFO: true}, nil)
		if mode == "half-close" {
			c.Close()
			if closeTCPTestWrite(t, c) {
				t.Fatal("closed socket half-close accepted")
			}
		} else {
			// Establish the injected shape before waiting for the absent EOF.
			b := make([]byte, len(worldhello))
			if _, err := io.ReadFull(c, b); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, worldhello) {
				t.Fatalf("wrong response: %v", b)
			}
			t.Log("injected full 10-byte response received; awaiting EOF")
			readUntilEOF(c, nil, t)
		}
		s.wait()
		return
	}
	for _, mode := range []string{"accept", "half-close", "missing-eof"} {
		t.Run(mode, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTCPFixtureFailureDiagnostics$", "-test.v")
			cmd.Env = append(os.Environ(), modeEnv+"="+mode)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("fixture failed to terminate: %v\n%s", ctx.Err(), out)
			}
			if err == nil {
				t.Fatalf("fault %s falsely passed:\n%s", mode, out)
			}
			want := map[string]string{"accept": "server accept:", "half-close": "CloseWrite:", "missing-eof": "TCP fixture deadline:"}[mode]
			if !bytes.Contains(out, []byte(want)) || !bytes.Contains(out, []byte("fixture cleanup joined")) {
				t.Fatalf("missing diagnostic or cleanup completion for %s:\n%s", mode, out)
			}
			if mode == "missing-eof" && !bytes.Contains(out, []byte("injected full 10-byte response received; awaiting EOF")) {
				t.Fatalf("missing-EOF injection did not deliver the full response:\n%s", out)
			}
			if strings.Contains(string(out), "test timed out") || strings.Contains(string(out), "WARNING: DATA RACE") {
				t.Fatalf("fixture relied on global timeout or raced:\n%s", out)
			}
		})
	}
}

func TestDiscardTCPServerCloseJoinsHandlers(t *testing.T) {
	s, err := newDiscardTCPServer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Start(t)
	defer s.Close()
	c, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Wait only for the accepted handler to be owned; leave the client open and
	// silent so Close must interrupt its read rather than depend on client EOF.
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not accept client")
		}
		time.Sleep(time.Millisecond)
	}
	s.Close()
	s.mu.Lock()
	n := len(s.conns)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d handlers survived Close", n)
	}
}

// This control uses only net's listener and dialer (no TFO sockopts or custom
// dialing). It retains server-first payload, EOF, then client payload/EOF.
func TestStandardLibraryServerFirstHalfClose(t *testing.T) {
	for _, listenerMode := range []mptcpStatus{mptcpUseDefault, mptcpEnabled, mptcpDisabled} {
		for _, dialMode := range []mptcpStatus{mptcpUseDefault, mptcpEnabled, mptcpDisabled} {
			t.Run(fmt.Sprintf("listen=%d/dial=%d", listenerMode, dialMode), func(t *testing.T) {
				var lc net.ListenConfig
				var d net.Dialer
				if listenerMode != mptcpUseDefault {
					lc.SetMultipathTCP(listenerMode == mptcpEnabled)
				}
				if dialMode != mptcpUseDefault {
					d.SetMultipathTCP(dialMode == mptcpEnabled)
				}
				t.Logf("requested listener MultipathTCP=%t dialer MultipathTCP=%t", lc.MultipathTCP(), d.MultipathTCP())
				ln, err := lc.Listen(context.Background(), "tcp", "[::1]:")
				if err != nil {
					t.Fatal(err)
				}
				s := newTCPTestSession(t, ln.(*net.TCPListener))
				s.start(func(c *net.TCPConn) {
					write(c, world, t)
					write(c, hello, t)
					if !closeTCPTestWrite(t, c) {
						return
					}
					readUntilEOF(c, helloworld, t)
				})
				c, err := d.DialContext(s.ctx, "tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				tc := c.(*net.TCPConn)
				if !s.track(tc, "native client dialed") {
					t.Fatal("native client connected after fixture closed")
				}
				readUntilEOF(tc, worldhello, t)
				write(tc, hello, t)
				write(tc, world, t)
				if !closeTCPTestWrite(t, tc) {
					return
				}
				s.wait()
			})
		}
	}
}
