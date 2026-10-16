//go:build linux

package libbox

import (
	"os"
	"path/filepath"
	"testing"
)

// auto_redirect and iptables ownership are Linux-specific. Keep this actual
// constructor/cleanup regression on Linux; other platforms reject that option.
func TestUnstartedTUNValidationCannotDeleteOtherInstanceRules(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "unexpected-command")
	// Any cleanup command would be captured, never sent to the system firewall.
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$POLARIS_TUN_TRACE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("POLARIS_TUN_TRACE", trace)
	config := `{"log":{"disabled":true},"inbounds":[{"type":"tun","tag":"validation-B","address":["172.19.0.1/30"],"auto_route":true,"auto_redirect":true}]}`
	result := CheckConfigWithResult(config, "unstarted-tun-B", 1000)
	if result.validation != "Accepted" || result.cleanup != "CleanupUnknown" {
		t.Fatalf("result = %+v", result)
	}
	if err := CheckConfig(config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(trace); !os.IsNotExist(err) {
		t.Fatalf("unstarted TUN touched another instance's firewall: %v", err)
	}
}
