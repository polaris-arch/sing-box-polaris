package snell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

type runtimeCloseDialer struct {
	net.Conn
}

func (d runtimeCloseDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.Conn, nil
}

func (runtimeCloseDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet dial")
}

type runtimeCloseConn struct {
	net.Conn
	entered      chan struct{}
	allow        chan struct{}
	result       error
	panicOnClose bool
	calls        atomic.Int32
}

func (c *runtimeCloseConn) Close() error {
	c.calls.Add(1)
	close(c.entered)
	<-c.allow
	_ = c.Conn.Close()
	if c.panicOnClose {
		panic("physical close failed")
	}
	return c.result
}

type runtimeCloseView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
}

func (v runtimeCloseView) Identity() adapter.RuntimeRevision { return v.identity }

func runtimeCloseWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not make progress")
	}
}

// Use the real protocol clients, the production outer operation carrier, and
// real graph/resource ownership. Only the physical transport is an in-memory
// pipe, so no host network or test credentials are needed.
func runtimeCloseOutbound(t *testing.T, version int, mode int, reuse bool, raw *runtimeCloseConn) (*Outbound, *runtimegraph.ResourceOwner, *runtimegraph.ResourceOwner, adapter.RuntimeResourceLease) {
	t.Helper()
	dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "snell-close", Sequence: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dependencyLease, err := dependency.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	var scope *adapter.Scope
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "snell-close", Sequence: 2}, []adapter.RuntimeResourceLease{dependencyLease}, func() error { return scope.Close() })
	if err != nil {
		t.Fatal(err)
	}
	dependencyLease.Release()
	scope = adapter.NewScope(owner.Context(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(adapter.ContextWithRuntimeResourceSource(scope.Context(), owner), scope)
	dialer := newRuntimeDialer(ctx, runtimeCloseDialer{raw})
	var client snellClient
	if version == 4 {
		client, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("runtime-close-fixture"), ObfsMode: snellprotocol.ObfsMode(mode), Reuse: reuse, Dialer: dialer})
	} else {
		client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("runtime-close-fixture"), Mode: snellv6.Mode(mode), Reuse: reuse, Dialer: dialer})
	}
	if err != nil {
		t.Fatal(err)
	}
	h := &Outbound{runtimeDialer: dialer, client: client, logger: log.NewNOPFactory().Logger()}
	if err := h.initRuntimeCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.finishRuntimeConstruction(ctx); err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	return h, owner, dependency, reservation
}

func runtimeClosePipe(t *testing.T) *runtimeCloseConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	return &runtimeCloseConn{Conn: conn, entered: make(chan struct{}), allow: make(chan struct{})}
}

func TestRuntimeProtocolCloseDrainsGraphAndCapturedDependencies(t *testing.T) {
	for _, version := range []int{4, 6} {
		for mode := 0; mode < 3; mode++ {
			for _, reuse := range []bool{false, true} {
				t.Run(fmt.Sprintf("v%d/mode%d/reuse%t", version, mode, reuse), func(t *testing.T) {
					raw := runtimeClosePipe(t)
					close(raw.allow)
					h, owner, dependency, reservation := runtimeCloseOutbound(t, version, mode, reuse, raw)
					dependencyMember, err := dependency.Acquire()
					if err != nil {
						t.Fatal(err)
					}
					graph, err := runtimegraph.NewGraph(runtimeCloseView{identity: adapter.RuntimeRevision{Incarnation: "snell-close", Revision: 1}}, []adapter.RuntimeResourceLease{reservation, dependencyMember})
					if err != nil {
						t.Fatal(err)
					}
					store, err := runtimegraph.NewStore("snell-close")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: "snell-close"}, graph); err != nil {
						t.Fatal(err)
					}
					reservation.Release()
					dependencyMember.Release()
					lease, err := store.Acquire()
					if err != nil {
						t.Fatal(err)
					}
					conn, err := h.DialContext(adapter.ContextWithRuntimeLease(context.Background(), lease), "tcp", M.ParseSocksaddr("192.0.2.1:443"))
					if err != nil {
						t.Fatal(err)
					}
					lease.Release()
					store.Seal()
					owner.Seal()
					dependency.Seal()
					select {
					case <-graph.Drained():
						t.Fatal("live protocol connection lost graph ownership")
					default:
					}
					if err := conn.Close(); err != nil {
						t.Fatalf("protocol close: %v", err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := owner.WaitClosed(ctx); err != nil {
						t.Fatal(err)
					}
					if err := dependency.WaitClosed(ctx); err != nil {
						t.Fatal(err)
					}
					runtimeCloseWait(t, store.Drained())
					if raw.calls.Load() != 1 {
						t.Fatalf("physical closes = %d", raw.calls.Load())
					}
					if err := conn.Close(); err != nil {
						t.Fatalf("repeated close: %v", err)
					}
				})
			}
		}
	}
}

func TestRuntimeProtocolCloseJoinsPhysicalCompletion(t *testing.T) {
	raw := runtimeClosePipe(t)
	h, owner, dependency, reservation := runtimeCloseOutbound(t, 4, 0, false, raw)
	conn, err := h.DialContext(context.Background(), "tcp", M.ParseSocksaddr("192.0.2.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	reservation.Release()
	owner.Seal()
	dependency.Seal()
	result := make(chan error, 1)
	go func() { result <- conn.Close() }()
	runtimeCloseWait(t, raw.entered)
	select {
	case err := <-result:
		t.Fatalf("close returned before physical completion: %v", err)
	default:
	}
	select {
	case <-owner.Closed():
		t.Fatal("owner closed before physical completion")
	default:
	}
	close(raw.allow)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dependency.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProtocolCloseFailureKeepsOwnership(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic%t", panics), func(t *testing.T) {
			raw := runtimeClosePipe(t)
			raw.result = errors.New("physical close result is unknown")
			raw.panicOnClose = panics
			close(raw.allow)
			h, owner, dependency, reservation := runtimeCloseOutbound(t, 4, 0, false, raw)
			conn, err := h.DialContext(context.Background(), "tcp", M.ParseSocksaddr("192.0.2.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			reservation.Release()
			owner.Seal()
			dependency.Seal()
			if err := conn.Close(); err == nil {
				t.Fatal("physical failure was accepted")
			}
			if err := conn.Close(); err == nil {
				t.Fatal("sticky physical failure was lost")
			}
			if err := h.runtimeCleanup(); err == nil {
				t.Fatal("aggregate cleanup lost physical failure")
			}
			for _, retained := range []*runtimegraph.ResourceOwner{owner, dependency} {
				observed := retained.CleanupSnapshot()
				if !observed.Available || observed.References == 0 {
					t.Fatal("failed cleanup released ownership")
				}
				select {
				case <-retained.Closed():
					t.Fatal("failed cleanup certified owner closed")
				default:
				}
			}
			if raw.calls.Load() != 1 {
				t.Fatalf("physical closes = %d", raw.calls.Load())
			}
		})
	}
}
