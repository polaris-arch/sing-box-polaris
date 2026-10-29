package tor

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type controlSocket struct {
	net.Conn
	closes atomic.Int32
}

func (c *controlSocket) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestRuntimeControlCancellationJoinsBlockedGetInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	left, right := net.Pipe()
	defer right.Close()
	socket := &controlSocket{Conn: left}
	instance := &Tor{}
	instance.bindRuntimeControl(ctx, socket)
	entered := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		_, _ = bufio.NewReader(right).ReadString('\n')
		close(entered)
		_, _ = io.Copy(io.Discard, right)
	}()
	result := make(chan error, 1)
	go func() { _, err := instance.Control.GetInfo("status/bootstrap-phase"); result <- err }()
	<-entered
	cancel()
	if err := instance.InterruptControl(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked controller request succeeded after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control cancellation did not unblock GetInfo")
	}
	<-peerDone
	if err := instance.InterruptControl(); err != nil {
		t.Fatal(err)
	}
	if socket.closes.Load() != 1 {
		t.Fatal("control socket close was not once-only")
	}
}

func TestRuntimeEnableNetworkPreservesSetConfError(t *testing.T) {
	ctx := t.Context()
	left, right := net.Pipe()
	defer right.Close()
	instance := &Tor{}
	instance.bindRuntimeControl(ctx, left)
	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(right)
		line, err := reader.ReadString('\n')
		if err == nil && !strings.HasPrefix(line, "GETCONF DisableNetwork") {
			t.Error("unexpected control request", line)
		}
		if err == nil {
			_, err = io.WriteString(right, "250 DisableNetwork=1\r\n")
		}
		if err == nil {
			line, err = reader.ReadString('\n')
			if !strings.HasPrefix(line, "SETCONF DisableNetwork=") {
				t.Error("missing actual enable request", line)
			}
		}
		if err == nil {
			_, err = io.WriteString(right, "551 unable to enable network\r\n")
		}
		done <- err
	}()
	if err := instance.EnableNetwork(ctx, false); err == nil {
		t.Fatal("SetConf failure was swallowed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := instance.InterruptControl(); err != nil {
		t.Fatal(err)
	}
}

// A failed native socket close cannot turn cancellation into proof of drain.
type panicControlSocket struct{ net.Conn }

func (panicControlSocket) Close() error { panic("foreign controller close") }
func TestRuntimeControlClosePanicRemainsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	instance := &Tor{}
	instance.bindRuntimeControl(ctx, panicControlSocket{left})
	cancel()
	err := instance.InterruptControl()
	if err == nil || !strings.Contains(err.Error(), "completion unknown") {
		t.Fatalf("close panic certified completion: %v", err)
	}
	if next := instance.InterruptControl(); next == nil || next.Error() != err.Error() {
		t.Fatal("close panic was not sticky")
	}
}
