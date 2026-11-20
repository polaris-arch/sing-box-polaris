//go:build linux && !android

package tun

import (
	"github.com/sagernet/sing/common/control"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func iptablesReceiptFixture(t *testing.T) (*autoRedirect, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "iptables")
	trace := filepath.Join(dir, "trace")
	failure := filepath.Join(dir, "failure")
	t.Setenv("RECEIPT_TRACE", trace)
	t.Setenv("RECEIPT_FAIL", failure)
	body := `#!/bin/sh
printf '%s\n' "$*" >> "$RECEIPT_TRACE"
if [ -f "$RECEIPT_FAIL" ]; then
 IFS= read -r failure < "$RECEIPT_FAIL"
 case "$*" in *"$failure"*) exit 1;; esac
fi
`
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return &autoRedirect{}, script, trace, failure
}
func TestIPTablesReceiptCleanup(t *testing.T) {
	r, path, trace, failure := iptablesReceiptFixture(t)
	for _, args := range [][]string{{"-t", "nat", "-N", "own"}, {"-t", "nat", "-A", "own", "-j", "RETURN"}, {"-t", "nat", "-I", "OUTPUT", "-j", "own"}} {
		if err := r.installIPTables(path, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(failure, []byte("-N foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.installIPTables(path, "-t", "nat", "-N", "foreign"); err == nil {
		t.Fatal("expected failed acquisition")
	}
	os.Remove(failure)
	if err := r.cleanupIPTables(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(trace)
	want := "-w -t nat -D OUTPUT -j own\n-w -t nat -D own -j RETURN\n-w -t nat -X own\n"
	if !strings.HasSuffix(string(got), want) || strings.Contains(string(got), "-F ") || strings.Contains(string(got), "-X foreign") {
		t.Fatalf("unexpected cleanup: %s", got)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.cleanupIPTables(); err != nil {
				t.Error(err)
			}
			if err := r.updateIPTablesNetwork(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	again, _ := os.ReadFile(trace)
	if string(again) != string(got) {
		t.Fatal("closed owner issued new commands")
	}
}
func TestIPTablesFailedDeleteRetainsReceipt(t *testing.T) {
	r, path, trace, failure := iptablesReceiptFixture(t)
	if err := r.installIPTables(path, "-t", "nat", "-A", "own", "-j", "RETURN"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(failure, []byte("-D own"), 0600)
	if err := r.cleanupIPTables(); err == nil || len(r.iptablesReceipts) != 1 {
		t.Fatalf("err=%v receipts=%d", err, len(r.iptablesReceipts))
	}
	os.Remove(failure)
	if err := r.cleanupIPTables(); err != nil || len(r.iptablesReceipts) != 0 {
		t.Fatalf("retry err=%v", err)
	}
	got, _ := os.ReadFile(trace)
	if strings.Count(string(got), "-D own") != 2 {
		t.Fatalf("unexpected retry: %s", got)
	}
}

type iptablesReceiptFinder struct {
	control.InterfaceFinder
	prefixes []netip.Prefix
}

func (f iptablesReceiptFinder) Update() error { return nil }
func (f iptablesReceiptFinder) Interfaces() []control.Interface {
	return []control.Interface{{Name: "test", Addresses: f.prefixes}}
}
func TestIPTablesLocalUpdateRollback(t *testing.T) {
	r, path, trace, failure := iptablesReceiptFixture(t)
	old := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	next := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	r.localAddresses = old
	r.interfaceFinder = iptablesReceiptFinder{prefixes: next}
	chain := iptablesLocalChain{family: &iptablesFamily{path: path}, table: "nat", name: "own", next: "continue"}
	r.iptablesLocalChains = []iptablesLocalChain{chain}
	if err := r.iptablesFillLocalChain(chain, old); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(failure, []byte("-A own -d 198.51.100.0/24"), 0600)
	if err := r.updateIPTablesLocalAddresses(); err == nil {
		t.Fatal("expected update failure")
	}
	if r.localAddresses[0] != old[0] || len(r.iptablesReceipts) != 2 {
		t.Fatal("old configuration not restored")
	}
	got, _ := os.ReadFile(trace)
	if !strings.HasSuffix(string(got), "-w -t nat -A own -d 192.0.2.0/24 -j RETURN\n-w -t nat -A own -j continue\n") || strings.Contains(string(got), "-F ") {
		t.Fatalf("unexpected rollback: %s", got)
	}
}

func TestIPTablesPartialUpdateDoesNotTrustOldCache(t *testing.T) {
	r, path, trace, failure := iptablesReceiptFixture(t)
	old := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	next := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	r.localAddresses = old
	r.interfaceFinder = iptablesReceiptFinder{prefixes: next}
	for _, name := range []string{"first", "second"} {
		chain := iptablesLocalChain{family: &iptablesFamily{path: path}, table: "nat", name: name, next: "continue"}
		r.iptablesLocalChains = append(r.iptablesLocalChains, chain)
		if err := r.iptablesFillLocalChain(chain, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(failure, []byte("-A second -d 198.51.100.0/24"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.updateIPTablesLocalAddresses(); err == nil || !r.iptablesLocalDirty {
		t.Fatal("partial update not marked dirty")
	}
	os.Remove(failure)
	r.interfaceFinder = iptablesReceiptFinder{prefixes: old}
	if err := os.WriteFile(trace, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.updateIPTablesLocalAddresses(); err != nil {
		t.Fatal(err)
	}
	if r.iptablesLocalDirty {
		t.Fatal("successful rebuild still dirty")
	}
	got, _ := os.ReadFile(trace)
	for _, name := range []string{"first", "second"} {
		if !strings.Contains(string(got), "-A "+name+" -d 192.0.2.0/24 -j RETURN") {
			t.Fatalf("chain not rebuilt: %s", got)
		}
	}
}
