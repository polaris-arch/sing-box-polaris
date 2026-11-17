//go:build linux

package tun

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type dockerTxnFixture struct {
	gen                    uint32
	snapshots              map[nftables.TableFamily]dockerNFTSnapshot
	inserts, deletes       []*nftables.Rule
	flushes, probes, reads int
	fail                   error
	restartCount           int
	missingEcho            bool
}

func newDockerTxnFixture() (*autoRedirect, *dockerTxnFixture) {
	r := &autoRedirect{enableIPv4: true, tunOptions: &Options{Name: "tun0"}, tableName: "test"}
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: "DOCKER-USER", Table: table}
	return r, &dockerTxnFixture{gen: 10, snapshots: map[nftables.TableFamily]dockerNFTSnapshot{nftables.TableFamilyIPv4: {table: table, chain: chain, tableHandle: 77, chainHandle: 88}}}
}

func (f *dockerTxnFixture) io() dockerNFTIO {
	return dockerNFTIO{
		generation: func() (uint32, error) { return f.gen, nil },
		probe: func(wrong uint32) error {
			f.probes++
			if wrong == 0 || wrong == f.gen {
				return errors.New("wrong probe value")
			}
			return nil
		},
		snapshot: func(family nftables.TableFamily) (dockerNFTSnapshot, error) {
			f.reads++
			return f.snapshots[family], nil
		},
		insert: func(rule *nftables.Rule) *nftables.Rule { f.inserts = append(f.inserts, rule); return rule },
		remove: func(rule *nftables.Rule) error { f.deletes = append(f.deletes, rule); return nil },
		flush: func(gen uint32) error {
			f.flushes++
			if f.restartCount > 0 {
				f.restartCount--
				f.gen++
				f.inserts = nil
				f.deletes = nil
				return syscall.ERESTART
			}
			if gen != f.gen {
				return syscall.ERESTART
			}
			if f.fail != nil {
				f.inserts = nil
				f.deletes = nil
				return f.fail
			}
			for _, rule := range f.deletes {
				snap := f.snapshots[rule.Table.Family]
				var kept []*nftables.Rule
				for _, existing := range snap.rules {
					if existing.Handle != rule.Handle {
						kept = append(kept, existing)
					}
				}
				snap.rules = kept
				f.snapshots[rule.Table.Family] = snap
			}
			for i, rule := range f.inserts {
				if !f.missingEcho {
					rule.Handle = uint64(100 + f.flushes*10 + i)
				}
				snap := f.snapshots[rule.Table.Family]
				snap.rules = append(snap.rules, rule)
				f.snapshots[rule.Table.Family] = snap
			}
			f.inserts = nil
			f.deletes = nil
			f.gen++
			return nil
		},
	}
}

func TestDockerTxnReceiptStableAndPreciseCleanup(t *testing.T) {
	r, f := newDockerTxnFixture()
	if err := r.transactDockerFirewall(f.io(), false); err != nil || len(r.dockerFirewallState.receipts) != 2 {
		t.Fatal(err)
	}
	snapshot := f.snapshots[nftables.TableFamilyIPv4]
	foreign := nftablesDockerCompatibilityRule(snapshot.table, snapshot.chain, "other", expr.MetaKeyIIFNAME, "foreign")
	foreign.Handle = 999
	snapshot.rules = append(snapshot.rules, foreign)
	f.snapshots[nftables.TableFamilyIPv4] = snapshot
	for _, rule := range snapshot.rules[:2] {
		rule.Exprs[2].(*expr.Counter).Packets = 900
	}
	if err := r.transactDockerFirewall(f.io(), false); err != nil || f.flushes != 1 {
		t.Fatal("churn", err)
	}
	if err := r.transactDockerFirewall(f.io(), true); err != nil || len(r.dockerFirewallState.receipts) != 0 {
		t.Fatal("cleanup", err)
	}
	if got := f.snapshots[nftables.TableFamilyIPv4].rules; len(got) != 1 || got[0].Handle != 999 {
		t.Fatal("foreign touched")
	}
}

func TestDockerTxnUnknownHistoryNotAdopted(t *testing.T) {
	r, f := newDockerTxnFixture()
	snap := f.snapshots[nftables.TableFamilyIPv4]
	rule := nftablesDockerCompatibilityRule(snap.table, snap.chain, "tun0", expr.MetaKeyIIFNAME, r.nftablesDockerCompatibilityComment("input from tun"))
	rule.Handle = 55
	snap.rules = []*nftables.Rule{rule}
	f.snapshots[nftables.TableFamilyIPv4] = snap
	if err := r.transactDockerFirewall(f.io(), false); err == nil || f.flushes != 0 || len(r.dockerFirewallState.receipts) != 0 {
		t.Fatal("history adopted")
	}
}

func TestDockerTxnReplacementOrChangedRuleRefused(t *testing.T) {
	for _, kind := range []string{"expr", "userdata"} {
		t.Run(kind, func(t *testing.T) {
			r, f := newDockerTxnFixture()
			if err := r.transactDockerFirewall(f.io(), false); err != nil {
				t.Fatal(err)
			}
			snap := f.snapshots[nftables.TableFamilyIPv4]
			switch kind {
			case "expr":
				snap.rules[0].Exprs[0].(*expr.Meta).SourceRegister = true
			case "userdata":
				snap.rules[0].UserData = append(snap.rules[0].UserData, 0)
			}
			f.snapshots[nftables.TableFamilyIPv4] = snap
			if err := r.transactDockerFirewall(f.io(), true); err == nil || f.flushes != 1 || len(r.dockerFirewallState.receipts) != 2 {
				t.Fatal("changed ownership deleted")
			}
		})
	}
}

func TestDockerTxnRestartRebuildBounded(t *testing.T) {
	for _, restarts := range []int{1, 4} {
		r, f := newDockerTxnFixture()
		f.restartCount = restarts
		err := r.transactDockerFirewall(f.io(), false)
		if restarts == 1 && (err != nil || f.flushes != 2 || f.reads != 2 || len(r.dockerFirewallState.receipts) != 2) {
			t.Fatal("did not rebuild", err)
		}
		if restarts == 4 && (err == nil || f.flushes != 3 || len(r.dockerFirewallState.receipts) != 0 || r.dockerFirewallState.uncertain) {
			t.Fatal("unbounded restart or false receipts")
		}
	}
}

func TestDockerTxnUncertainAddNoReplay(t *testing.T) {
	for _, missingEcho := range []bool{false, true} {
		r, f := newDockerTxnFixture()
		f.missingEcho = missingEcho
		if !missingEcho {
			f.fail = syscall.ETIMEDOUT
		}
		if err := r.transactDockerFirewall(f.io(), false); err == nil || !r.dockerFirewallState.uncertain || len(r.dockerFirewallState.receipts) != 0 {
			t.Fatal("uncertain success claimed")
		}
		f.fail = nil
		if err := r.transactDockerFirewall(f.io(), false); err == nil || f.flushes != 1 {
			t.Fatal("uncertain add replayed")
		}
		if err := r.transactDockerFirewall(f.io(), true); err == nil || f.flushes != 1 {
			t.Fatal("unknown committed rules reported clean")
		}
	}
}

func TestDockerTxnCleanupFailureRetainsAndRetriesKnown(t *testing.T) {
	r, f := newDockerTxnFixture()
	if err := r.transactDockerFirewall(f.io(), false); err != nil {
		t.Fatal(err)
	}
	f.fail = syscall.EPERM
	if err := r.transactDockerFirewall(f.io(), true); err == nil || len(r.dockerFirewallState.receipts) != 2 {
		t.Fatal("debt dropped")
	}
	f.fail = nil
	if err := r.transactDockerFirewall(f.io(), true); err != nil || len(r.dockerFirewallState.receipts) != 0 {
		t.Fatal("safe cleanup retry failed", err)
	}
}

func TestDockerTxnZeroProbeAndSnapshotFailureNoWrite(t *testing.T) {
	for _, kind := range []string{"zero", "probe", "snapshot", "race"} {
		t.Run(kind, func(t *testing.T) {
			r, f := newDockerTxnFixture()
			io := f.io()
			switch kind {
			case "zero":
				f.gen = 0
			case "probe":
				io.probe = func(uint32) error { return syscall.EOPNOTSUPP }
			case "snapshot":
				io.snapshot = func(nftables.TableFamily) (dockerNFTSnapshot, error) { return dockerNFTSnapshot{}, syscall.EPERM }
			case "race":
				io.generation = func() (uint32, error) { f.gen++; return f.gen, nil }
			}
			if err := r.transactDockerFirewall(io, false); err == nil || f.flushes != 0 || len(f.inserts) != 0 {
				t.Fatal("unsafe write")
			}
		})
	}
}

func TestDockerClosedNoNewWrite(t *testing.T) {
	r, _ := newDockerTxnFixture()
	r.stopDockerFirewallMonitor()
	if err := r.configureDockerFirewall(false); err != nil {
		t.Fatal(err)
	}
	r.startDockerFirewallMonitor()
	if r.dockerFirewallMonitor != nil {
		t.Fatal("restarted monitor after close")
	}
}

func TestDockerTxnTableRebuildNeverDeletesReusedRuleHandle(t *testing.T) {
	r, f := newDockerTxnFixture()
	if err := r.transactDockerFirewall(f.io(), false); err != nil {
		t.Fatal(err)
	}
	snap := f.snapshots[nftables.TableFamilyIPv4]
	oldHandle := snap.rules[0].Handle
	snap.tableHandle++
	foreign := nftablesDockerCompatibilityRule(snap.table, snap.chain, "other", expr.MetaKeyIIFNAME, "unrelated")
	foreign.Handle = oldHandle
	snap.rules = []*nftables.Rule{foreign}
	f.snapshots[nftables.TableFamilyIPv4] = snap
	if err := r.transactDockerFirewall(f.io(), false); err != nil {
		t.Fatal("rebuild", err)
	}
	if len(r.dockerFirewallState.receipts) != 2 || len(f.snapshots[nftables.TableFamilyIPv4].rules) != 3 {
		t.Fatal("old receipts kept or foreign removed")
	}
	for _, receipt := range r.dockerFirewallState.receipts {
		if receipt.tableHandle != snap.tableHandle {
			t.Fatal("old identity retained")
		}
	}
	if err := r.transactDockerFirewall(f.io(), true); err != nil {
		t.Fatal(err)
	}
	if rules := f.snapshots[nftables.TableFamilyIPv4].rules; len(rules) != 1 || rules[0] != foreign {
		t.Fatal("foreign reused handle deleted")
	}
}

func TestDockerTxnMissingTableVsRenamedChain(t *testing.T) {
	for _, tableGone := range []bool{false, true} {
		r, f := newDockerTxnFixture()
		if err := r.transactDockerFirewall(f.io(), false); err != nil {
			t.Fatal(err)
		}
		snap := f.snapshots[nftables.TableFamilyIPv4]
		snap.chain = nil
		if tableGone {
			snap.table = nil
		}
		f.snapshots[nftables.TableFamilyIPv4] = snap
		err := r.transactDockerFirewall(f.io(), true)
		if tableGone && (err != nil || len(r.dockerFirewallState.receipts) != 0) {
			t.Fatal("gone table not reconciled", err)
		}
		if !tableGone && (err == nil || len(r.dockerFirewallState.receipts) != 2) {
			t.Fatal("possibly renamed chain lost debt")
		}
		if f.flushes != 1 {
			t.Fatal("deletion attempted against missing object")
		}
	}
}

func TestDockerTxnMissingRuleMayBeInRenamedChain(t *testing.T) {
	r, f := newDockerTxnFixture()
	if err := r.transactDockerFirewall(f.io(), false); err != nil {
		t.Fatal(err)
	}
	snap := f.snapshots[nftables.TableFamilyIPv4]
	snap.rules = nil
	snap.chainHandle++
	f.snapshots[nftables.TableFamilyIPv4] = snap
	if err := r.transactDockerFirewall(f.io(), true); err == nil || len(r.dockerFirewallState.receipts) != 2 || f.flushes != 1 {
		t.Fatal("missing rule falsely closed")
	}
}
