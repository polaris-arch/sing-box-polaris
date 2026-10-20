package fakeip

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	mDNS "github.com/miekg/dns"
)

func protectionManager(t *testing.T, prefix string) *Manager {
	t.Helper()
	m, err := NewManager(context.Background(), log.NewNOPFactory().Logger(), netip.MustParsePrefix(prefix), netip.Prefix{})
	if err != nil { t.Fatal(err) }
	if err := m.Start(); err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = m.Close() })
	return m
}
func fakeAnswer(address netip.Addr, domain string, ttl uint32) *mDNS.Msg {
	return &mDNS.Msg{Answer: []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: domain+".", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: ttl}, A: net.IP(address.AsSlice())}}}
}

func TestFinalTTLStartsAfterActualDelayedDelivery(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/15")
	now := time.Unix(100, 0); m.now = func() time.Time { return now }
	address, err := m.create("answer.example", false); if err != nil { t.Fatal(err) }
	answer, err := m.ProtectAnswer(fakeAnswer(address, "answer.example", 1234)); if err != nil { t.Fatal(err) }
	record := m.protection.current[address]
	if record.pending != 1 || !record.expires.IsZero() { t.Fatal("pending answer was prematurely expired") }
	now = now.Add(time.Hour)
	answer.Delivered(now)
	if record.pending != 0 || !record.expires.Equal(now.Add(1234*time.Second)) { t.Fatal("final rewritten TTL was not anchored to delivery") }
	answer.Abort()
	if record.pending != 0 { t.Fatal("terminal answer call was not idempotent") }
}

func TestMappingForkSurvivesManagerSealAndBaselineReuse(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/30")
	address, err := m.create("first.example", false); if err != nil { t.Fatal(err) }
	mapping, found, err := m.AcquireMapping(address); if err != nil || !found { t.Fatal("mapping admission failed", err) }
	if _, err := m.create("second.example", false); err != nil { t.Fatal(err) }
	if mapping.Domain() != "first.example" { t.Fatal("active mapping identity was reinterpreted") }
	m.work.Seal()
	fork, err := mapping.Fork(); if err != nil { t.Fatal("live continuation rejected after seal", err) }
	mapping.Release()
	if _, err := mapping.Fork(); !errors.Is(err, ErrMappingReleased) { t.Fatal("released source resurrected") }
	closed := make(chan struct{})
	go func() { _ = m.Close(); close(closed) }()
	select { case <-closed: t.Fatal("manager closed with active fork"); default: }
	fork.Release()
	select { case <-closed: case <-time.After(5*time.Second): t.Fatal("mapping completion not joined") }
}

func TestCandidatePermitDoesNotAnswerOrMutateBeforeCommit(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/15")
	permit := NewAnswerPermit()
	candidate, err := m.BorrowCandidate(m.store.inet4Range, netip.Prefix{}, permit); if err != nil { t.Fatal(err) }
	defer candidate.Close()
	before := m.store.inet4Current
	if _, err := candidate.Create("candidate.example", false); !errors.Is(err, ErrCandidateNotCommitted) { t.Fatal("candidate answered during prepare") }
	if m.store.inet4Current != before { t.Fatal("candidate prepare moved live cursor") }
	if err := permit.Commit(); err != nil { t.Fatal(err) }
	if _, err := candidate.Create("candidate.example", false); err != nil { t.Fatal(err) }
	aborted := NewAnswerPermit(); aborted.Abort()
	if err := aborted.Commit(); err == nil { t.Fatal("aborted candidate was published") }
}

func TestOrdinaryReuseDoesNotResurrectStaleAnswerTTL(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/30")
	address, err := m.create("first.example", false); if err != nil { t.Fatal(err) }
	answer, err := m.ProtectAnswer(fakeAnswer(address, "first.example", 600)); if err != nil { t.Fatal(err) }
	old := m.protection.current[address]
	if _, err := m.create("second.example", false); err != nil { t.Fatal(err) }
	answer.Delivered(time.Now())
	if old.current || !old.expires.IsZero() { t.Fatal("normal allocator reuse was undone by delayed completion") }
	if _, err := m.ProtectAnswer(fakeAnswer(address, "first.example", 600)); !errors.Is(err, ErrAnswerIdentityChanged) { t.Fatal("stale finalized answer was recognized as current") }
}
