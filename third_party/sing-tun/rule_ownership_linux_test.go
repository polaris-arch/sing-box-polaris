package tun

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func ownershipRule(priority, table int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = priority
	rule.Table = table
	rule.Family = unix.AF_INET
	rule.IifName = "owned-tun"
	return rule
}

func TestOwnedRulesPartialAddOnlyRemovesAcquiredRules(t *testing.T) {
	var owned ownedLinuxRules
	rules := []*netlink.Rule{ownershipRule(9000, 200), ownershipRule(9001, 200)}
	failure := errors.New("add failed")
	err := owned.install(rules, func(rule *netlink.Rule) error {
		if rule.Priority == 9001 {
			return failure
		}
		return nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("lost add failure: %v", err)
	}
	var removed []*netlink.Rule
	if err := owned.clear(func(rule *netlink.Rule) error {
		removed = append(removed, rule)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].Priority != 9000 || removed[0].Table != 200 || removed[0].IifName != "owned-tun" {
		t.Fatalf("cleanup did not use exact acquired rule: %+v", removed)
	}
}

func TestOwnedRulesCleanupContinuesAndRetriesFailures(t *testing.T) {
	var owned ownedLinuxRules
	rules := []*netlink.Rule{ownershipRule(9000, 200), ownershipRule(9001, 200), ownershipRule(9002, 200)}
	if err := owned.install(rules, func(*netlink.Rule) error { return nil }); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("delete failed")
	calls := 0
	err := owned.clear(func(rule *netlink.Rule) error {
		calls++
		if rule.Priority == 9000 {
			return failure
		}
		if rule.Priority == 9001 {
			return unix.ENOENT
		}
		return nil
	})
	if !errors.Is(err, failure) || calls != 3 || len(owned.rules) != 1 {
		t.Fatalf("cleanup err=%v calls=%d retained=%d", err, calls, len(owned.rules))
	}
	if err := owned.install(rules, func(*netlink.Rule) error {
		t.Fatal("reinstalled before cleanup")
		return nil
	}); err == nil {
		t.Fatal("failed cleanup did not block reinstall")
	}
	calls = 0
	if err := owned.clear(func(rule *netlink.Rule) error {
		calls++
		if rule.Priority != 9000 {
			t.Fatal("retried an already removed rule")
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("retry err=%v calls=%d", err, calls)
	}
	if err := owned.clear(func(*netlink.Rule) error {
		t.Fatal("repeated delete")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedRulesUnstartedDoesNotTouchForeignRules(t *testing.T) {
	var owned ownedLinuxRules
	if err := owned.clear(func(*netlink.Rule) error {
		t.Fatal("unstarted instance deleted a rule")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedRulesKeepFullSelectorAtSamePriority(t *testing.T) {
	var owned ownedLinuxRules
	if err := owned.install([]*netlink.Rule{ownershipRule(9000, 200)}, func(*netlink.Rule) error { return nil }); err != nil {
		t.Fatal(err)
	}
	foreignPresent := true
	if err := owned.clear(func(rule *netlink.Rule) error {
		// A foreign rule shares priority/family but not table/interface.
		if rule.Table != 200 || rule.IifName != "owned-tun" {
			foreignPresent = false
		}
		return nil
	}); err != nil || !foreignPresent {
		t.Fatalf("foreign selector was not preserved: %v", err)
	}
}

func TestOwnedRulesRejectUnboundPriority(t *testing.T) {
	var owned ownedLinuxRules
	if err := owned.install([]*netlink.Rule{ownershipRule(-1, 200)}, func(*netlink.Rule) error {
		t.Fatal("kernel-assigned priority cannot be safely tracked")
		return nil
	}); err == nil {
		t.Fatal("missing priority accepted")
	}
}

func TestOwnedRulesClosedOwnerCannotInstall(t *testing.T) {
	var owned ownedLinuxRules
	owned.closed = true
	if err := owned.install([]*netlink.Rule{ownershipRule(9000, 200)}, func(*netlink.Rule) error {
		t.Fatal("closed owner installed rules")
		return nil
	}); err == nil {
		t.Fatal("closed owner accepted install")
	}
}

func TestNativeTunClosedOwnerRejectsLateRouteUpdate(t *testing.T) {
	// Model a callback captured before UnregisterCallback. The default options
	// deliberately have no interface monitor: rejection must precede any rule
	// builder or netlink call.
	tun := &NativeTun{}
	tun.ruleAccess.Lock()
	tun.ownedRules.closed = true
	tun.ruleAccess.Unlock()
	if err := tun.resetRules(); err == nil {
		t.Fatal("late reset accepted")
	}
}

func TestNativeTunQueuedResetCannotCrossCloseBoundary(t *testing.T) {
	tun := &NativeTun{}
	tun.ruleAccess.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- tun.resetRules()
	}()
	<-started
	// Close seals under this same lock, while a previously captured callback
	// is waiting to enter. Its default options must never reach netlink.
	tun.ownedRules.closed = true
	tun.ruleAccess.Unlock()
	if err := <-done; err == nil {
		t.Fatal("queued reset reinstalled after close boundary")
	}
	if err := tun.setRules(); err == nil {
		t.Fatal("start reinstalled after close boundary")
	}
}

func TestOwnedRulesResetRollsBackPartialInstallAndRetainsFailedCleanup(t *testing.T) {
	var owned ownedLinuxRules
	addFailure, cleanupFailure := errors.New("add failure"), errors.New("cleanup failure")
	err := owned.reset(func() []*netlink.Rule {
		return []*netlink.Rule{ownershipRule(9000, 200), ownershipRule(9001, 200)}
	}, func(rule *netlink.Rule) error {
		if rule.Priority == 9001 {
			return addFailure
		}
		return nil
	}, func(rule *netlink.Rule) error {
		if rule.Priority != 9000 {
			t.Fatal("rollback targeted rule that was never installed")
		}
		return cleanupFailure
	})
	if !errors.Is(err, addFailure) || !errors.Is(err, cleanupFailure) || len(owned.rules) != 1 {
		t.Fatalf("rollback errors or receipt lost: err=%v receipts=%d", err, len(owned.rules))
	}
	owned.closed = true
	if err := owned.clear(func(*netlink.Rule) error { return nil }); err != nil || len(owned.rules) != 0 {
		t.Fatalf("final close cleanup failed: %v", err)
	}
}
