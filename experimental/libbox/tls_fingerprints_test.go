package libbox

import (
	"testing"

	"github.com/sagernet/sing-box/common/tls"
)

func TestTLSFingerprintCapabilitiesMatchCoreContract(t *testing.T) {
	mobile, err := TLSFingerprintCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	core, err := tls.FingerprintCapabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	if mobile != core {
		t.Fatal("mobile capability projection changed the core contract")
	}
}
