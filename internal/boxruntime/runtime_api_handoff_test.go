package boxruntime

import "testing"

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
