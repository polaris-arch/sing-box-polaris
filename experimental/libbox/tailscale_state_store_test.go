package libbox

import (
	"encoding/json"
	"testing"
)

// Compile the exact gomobile-compatible no-argument method signature.
var _ interface{ ExportTailscaleStoreRetirement() string } = (*CommandServer)(nil)

func TestTailscaleStoreNativeExportIsReadOnlyWithoutInstance(t *testing.T) {
	transientTestSetup(t)
	server, err := NewTransientCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	payload := server.ExportTailscaleStoreRetirement()
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	if string(document["contractVersion"]) != `"polaris-ts-auth-writer-retirement-v1"` || string(document["globalCleanupEvidence"]) != `"CleanupUnknown"` || string(document["instances"]) != "[]" {
		t.Fatalf("invalid ABI document: %s", payload)
	}
	if err := server.CloseService(); err != nil {
		t.Fatal(err)
	}
	if after := server.ExportTailscaleStoreRetirement(); after != payload {
		t.Fatalf("ordinary nil close created evidence: %s", after)
	}
	if server.listener != nil || server.grpcServer != nil {
		t.Fatal("export started native service")
	}
}

// The validation extension has one exact, no-argument gomobile getter.
var _ interface{ GetTailscaleStoreRetirement() string } = (*ConfigValidationResult)(nil)

// Membership is a separate read-only getter on that same validation result.
var _ interface{ GetTailscaleStoreMembership() string } = (*ConfigValidationResult)(nil)
