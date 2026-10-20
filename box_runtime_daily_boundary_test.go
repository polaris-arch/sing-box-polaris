package box

import (
	stdjson "encoding/json"
	"testing"
)
func runtimeBoundaryJSON(t *testing.T, value string) map[string]stdjson.RawMessage {
	t.Helper(); var result map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal([]byte(value), &result); err != nil { t.Fatal(err) }
	return result
}
func TestDailyBoundaryDoesNotRejectUnchangedStructuralPresence(t *testing.T) {
	before:=runtimeBoundaryJSON(t,`{"inbounds":[{"type":"tun","tag":"tun"}],"services":[{"type":"derp"}],"experimental":{"cache_file":{"enabled":true}},"route":{"final":"a"}}`)
	after:=runtimeBoundaryJSON(t,`{"inbounds":[{"type":"tun","tag":"tun"}],"services":[{"type":"derp"}],"experimental":{"cache_file":{"enabled":true}},"route":{"final":"b"}}`)
	if impacts, problems:=runtimeDailyStructuralChanges(before,after);len(impacts)!=0||len(problems)!=0{t.Fatal("unchanged structural presence was classified as a restart")}
}
func TestDailyBoundaryReportsExactChangedPathWithoutValues(t *testing.T) {
	before:=runtimeBoundaryJSON(t,`{"experimental":{"clash_api":{"secret":"old-secret","external_controller":"127.0.0.1:1"}}}`)
	after:=runtimeBoundaryJSON(t,`{"experimental":{"clash_api":{"secret":"new-secret","external_controller":"127.0.0.1:1"}}}`)
	impacts,problems:=runtimeDailyStructuralChanges(before,after)
	if len(problems)!=1||problems[0].Path!="experimental.clash_api.secret"||problems[0].Code!="RESTART_REQUIRED"{t.Fatalf("incorrect paths: %+v",problems)}
	if len(impacts)!=1||impacts[0].UpdateClass!="RESTART_REQUIRED"{t.Fatal("missing structured restart impact")}
}
func TestDailyBoundaryAllowsNodeAndRuleChangesForAdapterValidation(t *testing.T) {
	before:=runtimeBoundaryJSON(t,`{"outbounds":[],"endpoints":[],"dns":{},"route":{"rules":[],"final":"a"}}`)
	after:=runtimeBoundaryJSON(t,`{"outbounds":[{"type":"hysteria2"}],"endpoints":[{"type":"wireguard"}],"dns":{"final":"resolver"},"route":{"rules":[{"outbound":"b"}],"final":"b"}}`)
	if _,problems:=runtimeDailyStructuralChanges(before,after);len(problems)!=0{t.Fatal("ordinary protocol nodes classified as structural before concrete validation")}
}
