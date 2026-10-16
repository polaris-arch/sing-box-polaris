package libbox

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func TestDirectorySourceIdentityExact(t *testing.T) {
	for _, value := range []string{"", "unknown", "577d4b9a089b71d2f0a4ca334b87264b55c10478-dirty", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if directorySourceIdentityValid(value) {
			t.Fatalf("accepted invalid producer identity %q", value)
		}
	}
	if !directorySourceIdentityValid("577d4b9a089b71d2f0a4ca334b87264b55c10478") {
		t.Fatal("rejected clean SHA")
	}
}

func TestLegacyCommandServerCannotActivateDirectoryProof(t *testing.T) {
	s := &CommandServer{}
	if err := s.ActivateTailscaleDirectoryDomain("owner", "577d4b9a089b71d2f0a4ca334b87264b55c10478"); err == nil {
		t.Fatal("legacy server activated")
	}
	var capability map[string]any
	if err := json.Unmarshal([]byte(s.ExportTailscaleDirectoryCapability()), &capability); err != nil {
		t.Fatal(err)
	}
	if capability["participating"] != false {
		t.Fatal("legacy participation")
	}
}

func TestPreparedCommandServerRequiresOriginalOwnerAndSource(t *testing.T) {
	if !tailscaleDirectoryDomainSupported {
		t.Skip("requires tailscale build")
	}
	old := C.DirectoryRetirementSourceIdentity
	C.DirectoryRetirementSourceIdentity = "577d4b9a089b71d2f0a4ca334b87264b55c10478"
	defer func() { C.DirectoryRetirementSourceIdentity = old }()
	d, err := adapter.NewTailscaleDirectoryDomain(t.TempDir(), "original-owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	s := &CommandServer{directoryDomain: d}
	if err := s.StartOrReloadService("{}", nil); err == nil {
		t.Fatal("prepared ordinary start bypassed handshake")
	}
	if err := s.ActivateTailscaleDirectoryDomain("wrong-owner", C.DirectoryRetirementSourceIdentity); err == nil {
		t.Fatal("wrong owner")
	}
	if err := s.ActivateTailscaleDirectoryDomain("original-owner", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("wrong source")
	}
	if d.Activated() {
		t.Fatal("rejected request activated domain")
	}
	if err := s.ActivateTailscaleDirectoryDomain("original-owner", C.DirectoryRetirementSourceIdentity); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateTailscaleDirectoryDomain("original-owner", C.DirectoryRetirementSourceIdentity); err == nil {
		t.Fatal("replayed activation")
	}
}
