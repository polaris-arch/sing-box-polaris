package urltest

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestHistoryEpochAdmissionAndLatePublication(t *testing.T) {
	s := NewHistoryStorage()
	defer s.Close()
	first := s.Epoch()
	ctx, cancel, err := s.ProbeContext(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if !s.StoreIfCurrent(first, "node", &adapter.URLTestHistory{Delay: 12}) {
		t.Fatal("initial store")
	}
	snapshot, ok := s.Snapshot(first)
	if !ok || snapshot["node"].Delay != 12 {
		t.Fatal("snapshot")
	}
	next := s.AdvanceNetworkEpoch()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old probe not canceled")
	}
	if s.LoadURLTestHistory("node") != nil {
		t.Fatal("old history visible")
	}
	if _, _, err := s.ProbeContext(context.Background(), next); err == nil {
		t.Fatal("unready admission")
	}
	if s.StoreIfCurrent(first, "node", &adapter.URLTestHistory{Delay: 1}) || s.DeleteIfCurrent(first, "node") {
		t.Fatal("old writer admitted")
	}
	published := false
	if s.PublishIfCurrent(first, func() { published = true }) || published {
		t.Fatal("old snapshot publication")
	}
	if !s.MarkReady(next) {
		t.Fatal("ready")
	}
	if !s.StoreIfCurrent(next, "node", &adapter.URLTestHistory{Delay: 23}) {
		t.Fatal("fresh store")
	}
	if s.DeleteIfCurrent(first, "node") || s.LoadURLTestHistory("node").Delay != 23 {
		t.Fatal("old failure erased fresh result")
	}
	if s.MarkReady(first) {
		t.Fatal("old preparation woke new epoch")
	}
}

func TestHistorySnapshotCopiesAndClosedAdmission(t *testing.T) {
	s := NewHistoryStorage()
	epoch := s.Epoch()
	value := &adapter.URLTestHistory{Delay: 10}
	s.StoreIfCurrent(epoch, "node", value)
	value.Delay = 99
	snapshot, _ := s.Snapshot(epoch)
	snapshot["node"].Delay = 88
	if s.LoadURLTestHistory("node").Delay != 10 {
		t.Fatal("mutable snapshot")
	}
	s.Close()
	s.Close()
	if s.Epoch() != nil || s.MarkReady(epoch) || s.StoreIfCurrent(epoch, "node", value) {
		t.Fatal("closed admission")
	}
}

func TestHistoryEpochCannotCrossStorage(t *testing.T) {
	first, second := NewHistoryStorage(), NewHistoryStorage()
	defer first.Close()
	defer second.Close()
	token := first.Epoch()
	if second.IsCurrent(token) || second.MarkReady(token) || second.StoreIfCurrent(token, "node", &adapter.URLTestHistory{Delay: 1}) || second.DeleteIfCurrent(token, "node") {
		t.Fatal("foreign storage token accepted")
	}
	if _, _, err := second.ProbeContext(context.Background(), token); err == nil {
		t.Fatal("foreign probe admitted")
	}
	if _, ok := second.Snapshot(token); ok {
		t.Fatal("foreign snapshot accepted")
	}
	called := false
	if second.PublishIfCurrent(token, func() { called = true }) || called {
		t.Fatal("foreign publication")
	}
}
