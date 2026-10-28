//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The executable fake is the only available iptables implementation. It keeps
// A's live rules in a file and changes them if B issues any cleanup mutation.
// No listener, NFQueue, route, namespace, or real firewall operation is needed.
func redirectCleanupFixture(t *testing.T) (*autoRedirect, string, string, string) {
	t.Helper()
	directory := t.TempDir()
	state := filepath.Join(directory, "active-a")
	trace := filepath.Join(directory, "commands")
	active := "-N cleanup-test-output\n-A OUTPUT -j cleanup-test-output\n"
	if err := os.WriteFile(state, []byte(active), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$REDIRECT_CLEANUP_TRACE"
case " $* " in
  *" -S "*)
    while IFS= read -r line; do printf '%s\n' "$line"; done < "$REDIRECT_CLEANUP_STATE"
    ;;
  *" -D "*|*" -F "*|*" -X "*)
    printf '%s\n' 'changed by cleanup' > "$REDIRECT_CLEANUP_STATE"
    ;;
esac
`
	for _, name := range []string{"iptables", "ip6tables"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	t.Setenv("REDIRECT_CLEANUP_STATE", state)
	t.Setenv("REDIRECT_CLEANUP_TRACE", trace)
	redirect, err := NewAutoRedirect(AutoRedirectOptions{
		TunOptions: &Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/30")},
		},
		Context:            context.Background(),
		TableName:          "cleanup-test",
		DisableNFTables:    true,
		CustomRedirectPort: func() int { return 12345 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return redirect.(*autoRedirect), state, trace, active
}

func redirectCleanupRead(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestAutoRedirectCloseBeforeFirewallSetupPreservesRunningInstance(t *testing.T) {
	for _, stage := range []string{"unstarted", "initialize-error", "nfqueue-error"} {
		t.Run(stage, func(t *testing.T) {
			r, state, trace, active := redirectCleanupFixture(t)
			switch stage {
			case "initialize-error":
				r.tunOptions.ExcludeMPTCP = true
				if err := r.Start(); err == nil {
					t.Fatal("expected initialization rejection before any acquisition")
				}
			case "nfqueue-error":
				failure := errors.New("injected NFQueue start failure")
				called := false
				err := r.startWithNFQueue(func() error { called = true; return failure })
				if !called || !errors.Is(err, failure) {
					t.Fatalf("NFQueue failure was not reached: called=%v err=%v", called, err)
				}
				if r.redirectServer != nil {
					t.Fatal("custom redirect port unexpectedly acquired a listener")
				}
			}
			for range 2 {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if got := redirectCleanupRead(t, state); got != active {
				t.Fatalf("B changed A's active rules: %q", got)
			}
			commands := redirectCleanupRead(t, trace)
			for _, line := range strings.Split(strings.TrimSpace(commands), "\n") {
				if line != "" && line != "-w -t nat -S" {
					t.Fatalf("unexpected command before firewall setup: %q", line)
				}
			}
			if stage == "nfqueue-error" && commands != "-w -t nat -S\n" {
				t.Fatalf("expected only the original read-only capability probe: %q", commands)
			}
			if stage != "nfqueue-error" && commands != "" {
				t.Fatalf("unstarted/initialization failure invoked iptables: %q", commands)
			}
		})
	}
}

func TestAutoRedirectAttemptedFirewallRetainsLegacyCleanup(t *testing.T) {
	r, _, trace, _ := redirectCleanupFixture(t)
	// Model partial setup: an attempt must retain legacy cleanup eligibility even
	// when setup has not returned success. This flag is not an ownership receipt.
	r.firewallSetupAttempted.Store(true)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	first := redirectCleanupRead(t, trace)
	if !strings.Contains(first, " -D ") || !strings.Contains(first, " -F ") || !strings.Contains(first, " -X ") {
		t.Fatalf("attempted firewall did not retain legacy cleanup: %q", first)
	}

}

func TestAutoRedirectNFTCloseWithoutSetupDoesNotEnterCleanup(t *testing.T) {
	// Nil options are a tripwire: entering the NFT cleanup branch would fail
	// before any namespace or firewall call. An unstarted close needs neither.
	r := &autoRedirect{useNFTables: true}
	for range 2 {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
