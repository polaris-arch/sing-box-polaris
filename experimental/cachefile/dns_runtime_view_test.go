package cachefile

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// Authored source fixtures only. No test or native filesystem execution was
// performed while preparing this unit.
func runtimeDNSFixture(t *testing.T) *CacheFile {
	t.Helper()
	c := New(context.Background(), logger.NOP(), option.CacheFileOptions{Path: filepath.Join(t.TempDir(), "cache.db"), StoreDNS: true})
	db, err := bbolt.Open(c.path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.DB = db
	t.Cleanup(func() { _ = db.Close() })
	return c
}

func newRuntimeDNSFixtureView(t *testing.T, c *CacheFile, namespace string) *DNSRuntimeView {
	t.Helper()
	v, err := c.NewDNSRuntimeView(context.Background(), DNSRuntimeViewOptions{Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Prepare(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	return v
}

func TestDNSRuntimeViewDormantBeforePhysicalOpen(t *testing.T) {
	c := New(context.Background(), logger.NOP(), option.CacheFileOptions{StoreDNS: true})
	v, err := c.NewDNSRuntimeView(context.Background(), DNSRuntimeViewOptions{Namespace: "semantic-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Prepare(); err == nil {
		t.Fatal("unopened physical DB accepted")
	}
	v.Activate()
	if err = v.SaveDNSCache("dns", "a.example", 1, []byte{1}, time.Now()); err == nil {
		t.Fatal("unprepared view wrote")
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.closeRuntimeDatabase(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRuntimeViewPrepareDoesNotClearOrWrite(t *testing.T) {
	c := runtimeDNSFixture(t)
	a := newRuntimeDNSFixtureView(t, c, "semantic-a")
	a.Activate()
	expiry := time.Now().Add(time.Hour)
	if err := a.SaveDNSCache("dns", "a.example", 1, []byte{7}, expiry); err != nil {
		t.Fatal(err)
	}
	before := c.DB.Stats().TxStats.Write
	b := newRuntimeDNSFixtureView(t, c, "semantic-b")
	if err := b.ClearDNSCache(); err == nil {
		t.Fatal("private candidate cleared persistence")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if after := c.DB.Stats().TxStats.Write; after != before {
		t.Fatal("candidate preparation mutated database", before, after)
	}
	if value, _, ok := a.LoadDNSCache("dns", "a.example", 1); !ok || len(value) != 1 || value[0] != 7 {
		t.Fatal("active cohort lost entry")
	}
}

func TestDNSRuntimeViewNamespaceIsolationAndScopedClear(t *testing.T) {
	c := runtimeDNSFixture(t)
	a := newRuntimeDNSFixtureView(t, c, "semantic-a")
	a.Activate()
	b := newRuntimeDNSFixtureView(t, c, "semantic-b")
	b.Activate()
	expiry := time.Now().Add(time.Hour)
	if err := a.SaveDNSCache("dns", "a.example", 1, []byte{1}, expiry); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveDNSCache("dns", "a.example", 1, []byte{2}, expiry); err != nil {
		t.Fatal(err)
	}
	if err := a.ClearDNSCache(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := a.LoadDNSCache("dns", "a.example", 1); ok {
		t.Fatal("cleared cohort still loaded")
	}
	if value, _, ok := b.LoadDNSCache("dns", "a.example", 1); !ok || value[0] != 2 {
		t.Fatal("clear touched another cohort")
	}
}

func TestDNSRuntimeViewRetainsPhysicalDatabaseUntilClose(t *testing.T) {
	c := runtimeDNSFixture(t)
	v := newRuntimeDNSFixtureView(t, c, "semantic-a")
	done := make(chan error, 1)
	go func() { done <- c.closeRuntimeDatabase() }()
	deadline := time.Now().Add(time.Second)
	for {
		c.runtimeClients.Lock()
		closing := c.runtimeClientsClosing
		c.runtimeClients.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("physical close did not seal admission")
		}
		runtime.Gosched()
	}
	// Reservation is made synchronously during construction. Closing the actual
	// owner cannot finish while this dormant view still holds that reservation.
	select {
	case err := <-done:
		t.Fatal("owner closed before view", err)
	default:
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not join released view")
	}
	if _, err := c.NewDNSRuntimeView(context.Background(), DNSRuntimeViewOptions{Namespace: "late"}); err == nil {
		t.Fatal("sealed owner admitted view")
	}
}

func TestDNSRuntimeViewFinalFlushFailureRetainsWrites(t *testing.T) {
	c := runtimeDNSFixture(t)
	v, err := c.NewDNSRuntimeView(context.Background(), DNSRuntimeViewOptions{Namespace: "semantic-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Prepare(); err != nil {
		t.Fatal(err)
	}
	v.Activate()
	if err = c.DB.Close(); err != nil {
		t.Fatal(err)
	}
	v.SaveDNSCacheAsync("dns", "a.example", 1, []byte{9}, time.Now().Add(time.Hour), logger.NOP())
	if err = v.Close(); err == nil {
		t.Fatal("failed flush reported successful release")
	}
	v.store.pendingAccess.RLock()
	count := len(v.store.pending.dnsCache)
	v.store.pendingAccess.RUnlock()
	if count != 1 {
		t.Fatal("failed flush dropped DNS write", count)
	}
	if again := v.Close(); again != err {
		t.Fatal("close lost sticky failure")
	}
}
