package adapter_test

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsspoof"
)

// Importing both packages also guards the metadata/implementation boundary:
// adapter must not import the socket implementation that depends on outbound.
func TestMethodMetadataCompatibility(t *testing.T) {
	tests := []struct {
		name   string
		method tlsspoof.Method
		value  int
	}{
		{"wrong-sequence", tlsspoof.MethodWrongSequence, 0},
		{"wrong-checksum", tlsspoof.MethodWrongChecksum, 1},
		{"wrong-ack", tlsspoof.MethodWrongAcknowledgment, 2},
		{"wrong-md5", tlsspoof.MethodWrongMD5Sig, 3},
		{"wrong-timestamp", tlsspoof.MethodWrongTimestamp, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := tlsspoof.ParseMethod(test.name)
			if err != nil {
				t.Fatal(err)
			}
			metadata := adapter.InboundContext{TLSSpoofMethod: parsed}
			var originalAPI tlsspoof.Method
			if originalAPI = metadata.TLSSpoofMethod; originalAPI != test.method || int(originalAPI) != test.value || originalAPI.String() != test.name {
				t.Fatalf("method identity changed: %v (%d)", originalAPI, originalAPI)
			}
		})
	}
	if method, err := tlsspoof.ParseMethod(""); err != nil || method != tlsspoof.MethodWrongSequence {
		t.Fatalf("default method changed: %v, %v", method, err)
	}
	if tlsspoof.Method(99).String() != "unknown" {
		t.Fatal("unknown method formatting changed")
	}
}
