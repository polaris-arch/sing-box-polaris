package box

import (
	"context"
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestRuntimeTruncatedDHCPPublicApplyKeepsSelectedGraph(t *testing.T) {
	if !(C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos) {
		t.Skip("no independent native neighbor reader")
	}
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "provision.test"), nil)
	f.start(t)
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	if err := os.WriteFile(path, []byte("0 02:00:00:00:00:01 192.0.2.7 partial *\n"+strings.Repeat("x", 65536)+"\n0 02:00:00:00:00:02 192.0.2.8 omitted *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _ := stdjson.Marshal([]string{path})
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"find_neighbor": []byte("true"), "dhcp_lease_files": paths})
	_, request := runtimeClientPlan(t, f, content)
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active != request.Expected || len(operation.Errors) == 0 {
		t.Fatal("first truncated DHCP sample published", operation, err)
	}
	if f.box.Router().NeedFindNeighbor() || f.box.Router().NeighborResolver() != nil {
		t.Fatal("failed first sample escaped through stable gateway")
	}
}
