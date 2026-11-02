//go:build windows && amd64

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Parser/control fixtures are synthetic rejection inputs, never native facts.
// No test creates a cohort, elevates, installs, or executes the final Core.
func requestFixture() request {
	r := request{Schema: requestSchema, SourceCommit: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), Version: "1.15.0-polaris-alpha.12.9", Target: "windows/amd64", GoVersion: "go1.27.2", CronetVersion: "fixture", RunID: 123, RunAttempt: 1}
	r.Core = pin{"sing-box.exe", 2, strings.Repeat("c", 64)}
	r.Sidecar = pin{"libcronet.dll", 3, strings.Repeat("d", 64)}
	r.Archive = archivePin{"sing-box-fixture-windows-amd64", 4, strings.Repeat("e", 64), map[string]string{"sing-box-fixture-windows-amd64/sing-box.exe": r.Core.SHA256, "sing-box-fixture-windows-amd64/libcronet.dll": r.Sidecar.SHA256}}
	return r
}

func TestNativeRequestRejectsUnsupportedSourceAndArchiveIdentity(t *testing.T) {
	if err := validateRequest(requestFixture()); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*request){func(r *request) { r.Schema = "diagnostic" }, func(r *request) { r.Target = "windows/arm64" }, func(r *request) { r.SourceCommit = strings.Repeat("A", 40) }, func(r *request) { r.SourceTree = "" }, func(r *request) { r.RunID = 0 }, func(r *request) { r.RunAttempt = 0 }, func(r *request) { r.Core.Member = "other.exe" }, func(r *request) { r.Sidecar.Member = "other.dll" }, func(r *request) { r.Core.Bytes = 0 }, func(r *request) { r.Sidecar.SHA256 = "bad" }, func(r *request) { r.Archive.Bytes = objectLimit + 1 }, func(r *request) { r.Archive.Root = "../outside" }, func(r *request) { delete(r.Archive.Members, r.Archive.Root+"/sing-box.exe") }}
	for index, mutate := range mutations {
		r := requestFixture()
		mutate(&r)
		if err := validateRequest(r); err == nil {
			t.Fatalf("mutation %d was admitted", index)
		}
	}
}

func TestNativeJSONRejectsDuplicateTrailingAndDeepDocuments(t *testing.T) {
	for _, raw := range []string{`{"runId":1,"runId":2}`, `{"a":{"source":"a","source":"b"}}`, `{} {}`, `[1,]`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)} {
		if err := uniqueJSON([]byte(raw)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %q", raw)
		}
	}
	for _, raw := range []string{`{"a":1,"b":[{"a":2}]}`, `[]`} {
		if err := uniqueJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"true", "1.0", "-1"} {
		var r request
		raw := `{"runId":` + value + `}`
		if err := json.Unmarshal([]byte(raw), &r); err == nil {
			t.Fatalf("non-uint run identity accepted: %s", value)
		}
	}
}

func TestNativeConfigurationControlsKeepExpectedErrorsAndCanonicalStdin(t *testing.T) {
	doc := tlsDocument{Enabled: true, Aliases: []string{"chrome_legacy"}}
	doc.Profiles = append(doc.Profiles, struct {
		ID string `json:"id"`
	}{"chrome"})
	cases := configurationCases(doc)
	if len(cases) != 13 {
		t.Fatalf("finite controls=%d", len(cases))
	}
	unknown := cases[5]
	if unknown.expectedError != "unknown uTLS fingerprint" || unknown.expected["expectedPass"] != false {
		t.Fatal("bad configuration lacks source error classification")
	}
	ech := cases[len(cases)-1]
	if ech.expectedError != "cannot be combined with real ECH" || ech.expected["expectedPass"] != false {
		t.Fatal("real ECH rejection lost")
	}
	raw, err := json.Marshal(cases[0].config)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"log":{"level":"error"},"outbounds":[{"password":"local-config-admission-only","server":"127.0.0.1","server_port":443,"tag":"probe","tls":{"enabled":true,"server_name":"tls.invalid","utls":{"enabled":true,"fingerprint":"chrome"}},"type":"trojan"}]}`
	if string(raw) != expected {
		t.Fatal("fixed CheckConfig stdin changed")
	}
}

func TestNativeOutputAndExplicitAdmissionFailClosedWithoutExecution(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write(make([]byte, outputBound+1)); err == nil || !output.truncated || output.Len() != outputBound {
		t.Fatal("native output bound not enforced")
	}
	t.Setenv("POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED", "false")
	if err := sourceAdmission(requestFixture()); err == nil {
		t.Fatal("unrequested producer admitted")
	}
	if _, err := executeSuite(requestFixture(), "never-opened.zip"); err == nil {
		t.Fatal("unrequested suite crossed native boundary")
	}
}
