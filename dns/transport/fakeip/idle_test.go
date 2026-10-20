package fakeip

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	mDNS "github.com/miekg/dns"
)

type idleStore struct {
	adapter.FakeIPStore
	address netip.Addr
	domain string
	resets int
	closes int
}
func (s *idleStore) Create(domain string, _ bool) (netip.Addr, error) { s.domain = domain; return s.address, nil }
func (s *idleStore) Lookup(address netip.Addr) (string, bool) { return s.domain, address == s.address && s.domain != "" }
func (s *idleStore) Reset() error { s.resets++; s.domain = ""; return nil }
func (s *idleStore) Close() error { s.closes++; return nil }

func TestFakeIPIdleControlPreservesMappingsAndCallback(t *testing.T) {
	store := &idleStore{address: netip.MustParseAddr("198.18.0.2")}
	transport := &Transport{store: store, inet4Enabled: true}
	request := new(mDNS.Msg); request.SetQuestion("kept.example.", mDNS.TypeA)
	transport.ExchangeAsync(context.Background(), request, func(response *mDNS.Msg, err error) {
		if err != nil || len(response.Answer) != 1 { t.Fatal("allocation failed before idle effect", err) }
		transport.SetKeepIdleConnections(false)
		transport.CloseIdleConnections()
		transport.SetKeepIdleConnections(true)
		if transport.work.Sealed() { t.Fatal("idle effect stopped an admitted fake-IP callback") }
	})
	if domain, loaded := store.Lookup(store.address); !loaded || domain != "kept.example" { t.Fatal("idle control lost recognition mapping") }
	if transport.Store() != store || store.resets != 0 || store.closes != 0 { t.Fatal("idle control changed the allocator owner") }
}
