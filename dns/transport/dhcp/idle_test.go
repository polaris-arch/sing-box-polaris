package dhcp

import (
	"context"
	"testing"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport"
)

type idleTestTransport struct {
	adapter.DNSTransport
	pool *transport.ConnPool[int]
	closed int
	resets int
	idleEntered chan struct{}
	idleRelease chan struct{}
}
func newIdleTestTransport() *idleTestTransport {
	t := new(idleTestTransport)
	t.pool = transport.NewConnPool(transport.ConnPoolOptions[int]{Mode: transport.ConnPoolSingle, IsAlive: func(int) bool { return true }, Close: func(int, error) { t.closed++ }})
	return t
}
func (t *idleTestTransport) SetKeepIdleConnections(keep bool) { t.pool.SetKeepIdleConnections(keep) }
func (t *idleTestTransport) CloseIdleConnections() {
	if t.idleEntered != nil { close(t.idleEntered); <-t.idleRelease }
	t.pool.CloseIdle()
}
func (t *idleTestTransport) Reset() { t.resets++; t.pool.Reset() }
func (t *idleTestTransport) acquire(test *testing.T) int {
	conn, _, err := t.pool.Acquire(context.Background(), func(context.Context) (int, error) { return 1, nil })
	if err != nil { test.Fatal(err) }; return conn
}

func TestDHCPIdleControlsPreserveQueriesAndLazyPolicy(t *testing.T) {
	resolver := &Transport{ctx: context.Background()}
	child := newIdleTestTransport(); defer child.pool.Close()
	resolver.storeState(&transportState{serverTransports: []adapter.DNSTransport{child}})
	conn := child.acquire(t)
	resolver.CloseIdleConnections()
	resolver.SetKeepIdleConnections(false)
	if child.closed != 0 || child.resets != 0 { t.Fatal("DHCP idle control disrupted an active query") }
	child.pool.Release(conn, true)
	if child.closed != 1 { t.Fatal("DHCP child retained idle connection") }
	lazy := newIdleTestTransport(); defer lazy.pool.Close()
	resolver.storeState(&transportState{serverTransports: []adapter.DNSTransport{lazy}})
	conn = lazy.acquire(t); lazy.pool.Release(conn, true)
	if lazy.closed != 1 { t.Fatal("new DHCP server cohort lost idle policy") }
	resolver.SetKeepIdleConnections(true)
	conn = lazy.acquire(t); lazy.pool.Release(conn, true)
	if lazy.closed != 1 { t.Fatal("DHCP retention could not be re-enabled") }
	resolver.CloseIdleConnections()
	if lazy.closed != 2 || lazy.resets != 0 { t.Fatal("DHCP idle trim reset or missed the idle child") }
}

func TestDHCPIdleEffectSerializesCohortPublication(t *testing.T) {
	resolver := &Transport{ctx: context.Background()}
	child := newIdleTestTransport(); defer child.pool.Close()
	child.idleEntered, child.idleRelease = make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(child.idleRelease) }) }; defer unblock()
	resolver.storeState(&transportState{serverTransports: []adapter.DNSTransport{child}})
	idleDone := make(chan struct{})
	go func() { resolver.CloseIdleConnections(); close(idleDone) }()
	select { case <-child.idleEntered: case <-time.After(5*time.Second): t.Fatal("idle effect did not enter child") }
	published := make(chan struct{})
	go func() { resolver.storeState(&transportState{}); close(published) }()
	select { case <-published: t.Fatal("cohort publication bypassed its prior idle effect"); default: }
	unblock()
	select { case <-idleDone: case <-time.After(5*time.Second): t.Fatal("idle effect did not finish") }
	select { case <-published: case <-time.After(5*time.Second): t.Fatal("replacement cohort remained blocked") }
}
