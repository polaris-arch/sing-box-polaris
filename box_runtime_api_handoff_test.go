package box

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestRuntimeAPIHandoffStructuralBoundary(t *testing.T) {
	before := runtimeBoundaryJSON(t, `{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old"}]}`)
	for _, row := range []struct {
		content string
		allowed bool
	}{
		{`{"services":[{"type":"api","tag":"control","listen":"::1","listen_port":3002,"secret":"new"}]}`, true},
		{`{"services":[{"type":"api","tag":"changed","listen":"127.0.0.1","listen_port":3001,"secret":"old"}]}`, false},
		{`{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old","dashboard":{"enabled":true}}]}`, false},
		{`{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old","tls":{"enabled":true}}]}`, false},
		{`{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old","reuse_addr":true}]}`, false},
		{`{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old","dashboard":{"enabled":true,"http_client":{"tag":"named"}}}]}`, false},
		{`{"services":[]}`, false},
		{`{"services":[{"type":"api","tag":"control","listen":"127.0.0.1","listen_port":3001,"secret":"old"},{"type":"api","listen":"127.0.0.1"}]}`, false},
	} {
		after := runtimeBoundaryJSON(t, row.content)
		if got := runtimeAPIHandoffChanges(before["services"], after["services"]); got != row.allowed {
			t.Fatalf("boundary=%v want=%v for %s", got, row.allowed, row.content)
		}
	}
}

func TestRuntimeAPIListenerCanonicalizationAndCredentialBoundary(t *testing.T) {
	addr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	mapped := badoption.Addr(netip.MustParseAddr("::ffff:127.0.0.1"))
	a := option.APIServiceOptions{ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: 3001}, Secret: "safe"}
	b := a
	b.Listen = &mapped
	da, _ := adapter.RuntimeAPIConfigDigest(a)
	db, _ := adapter.RuntimeAPIConfigDigest(b)
	if da != db || !runtimeStableAPIService(option.Service{Type: C.TypeAPI, Options: &b}) {
		t.Fatal("mapped alias created a different physical owner")
	}
	zoned := badoption.Addr(netip.MustParseAddr("::1%lo"))
	b.Listen = &zoned
	if runtimeStableAPIService(option.Service{Type: C.TypeAPI, Options: &b}) {
		t.Fatal("scoped address admitted")
	}
	if netip.Addr(*adapter.NormalizeRuntimeAPIOptions(b).Listen).Zone() == "" {
		t.Fatal("normalization erased a rejected scope")
	}
	for _, secret := range []string{"", "safe-!~"} {
		if !adapter.RuntimeAPISecretValid(secret) {
			t.Fatal("valid secret rejected")
		}
	}
	for _, secret := range []string{" leading", "line\nbreak", "unicode-密钥", string(make([]byte, 4097))} {
		if adapter.RuntimeAPISecretValid(secret) {
			t.Fatal("unsafe metadata credential admitted")
		}
	}
}
