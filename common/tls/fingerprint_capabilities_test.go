package tls

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestFingerprintCapabilitiesDescribeLoadedCore(t *testing.T) {
	raw, err := FingerprintCapabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	var actual FingerprintCapabilities
	if err := json.Unmarshal([]byte(raw), &actual); err != nil {
		t.Fatal(err)
	}
	enabled, profiles, aliases := fingerprintProfiles()
	if actual.Schema != "polaris-tls-fingerprint-capabilities-v1" || actual.Enabled != enabled || actual.GoVersion != runtime.Version() || actual.RequiredGoVersion != C.ForkGoVersion || actual.OS != runtime.GOOS || actual.Arch != runtime.GOARCH || actual.CoreVersion != C.Version {
		t.Fatalf("wrong runtime identity: %+v", actual)
	}
	if len(actual.Profiles) != len(profiles) || len(actual.LegacyChromeAliases) != len(aliases) {
		t.Fatal("capability mapping drift")
	}
	if !enabled && (len(actual.Profiles) != 0 || len(actual.LegacyChromeAliases) != 0) {
		t.Fatal("stub advertised uTLS support")
	}
	if actual.CurvePreferencesSupported || actual.NegotiationEvidence == "" || actual.RandomSemantics == "" || actual.RandomizedSemantics == "" {
		t.Fatal("capabilities lost semantics/boundaries")
	}
}

func TestFingerprintCapabilitiesRejectConflictingOrInvalidSourceStamps(t *testing.T) {
	original, directory := C.SourceRevision, C.DirectoryRetirementSourceIdentity
	defer func() { C.SourceRevision, C.DirectoryRetirementSourceIdentity = original, directory }()
	for _, pair := range [][2]string{{"not-a-commit", ""}, {strings.Repeat("A", 40), ""}, {"", "bad-mobile"}, {strings.Repeat("1", 40), strings.Repeat("2", 40)}} {
		C.SourceRevision, C.DirectoryRetirementSourceIdentity = pair[0], pair[1]
		if _, err := FingerprintCapabilitiesJSON(); err == nil {
			t.Fatal("invalid/conflicting source stamps accepted", pair)
		}
	}
}
