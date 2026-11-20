package option

import (
	"encoding/json"
	"testing"
)

func TestTunExternalResolvedJSONContract(t *testing.T) {
	var options TunInboundOptions
	if err := json.Unmarshal([]byte(`{"dns_mode":"hijack","linux_resolved_external":true}`), &options); err != nil {
		t.Fatal(err)
	}
	if !options.LinuxResolvedExternal || options.DNSMode != "hijack" {
		t.Fatal("external resolved flag changed hijack mode")
	}
	var defaults TunInboundOptions
	if err := json.Unmarshal([]byte(`{}`), &defaults); err != nil {
		t.Fatal(err)
	}
	if defaults.LinuxResolvedExternal {
		t.Fatal("external owner must be opt-in")
	}
}
