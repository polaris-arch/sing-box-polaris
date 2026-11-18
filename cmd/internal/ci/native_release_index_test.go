package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

func TestNativeIndexRetainsProducerBindings(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	const version, runID, attempt, workflow = "1.15.0-polaris-alpha.12.32", 42, 1, ".github/workflows/build.yml"
	source, tree, object := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	hash := strings.Repeat("1", 64)
	jobs := []map[string]any{}
	for i, name := range []string{"linux-amd64-purego", "windows-amd64", "darwin-amd64", "darwin-arm64", "linux-arm64-purego"} {
		jobs = append(jobs, map[string]any{
			"name": "Native final-package Cronet and gVisor smoke (" + name + ")", "id": json.Number(fmt.Sprint(i + 1)),
			"run_id": json.Number("42"), "run_attempt": json.Number("1"), "conclusion": "success", "status": "completed", "head_sha": source,
		})
	}
	producerJobs, err := selectNativeJobs(jobs, source, json.Number("42"), json.Number("1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(producerJobs) != 4 {
		t.Fatalf("unexpected proof-producing jobs: %#v", producerJobs)
	}
	var rows []any
	for _, platform := range []struct{ target, linkage, suffix string }{
		{"darwin/amd64", "static-cgo", ".tar.gz"},
		{"darwin/arm64", "static-cgo", ".tar.gz"},
		{"linux/amd64", "shared-purego", ".tar.gz"},
		{"linux/arm64", "shared-purego", ".tar.gz"},
		{"windows/amd64", "shared-purego", ".zip"},
	} {
		id := "sing-box-" + version + "-" + strings.ReplaceAll(platform.target, "/", "-")
		rows = append(rows, map[string]any{
			"schema": "polaris-upstream-native-receipt-v1", "id": id, "target": platform.target,
			"variant": map[string]any{"linkage": platform.linkage, "libc": "", "goarm": "", "gomips": "", "go386": "", "legacy": false},
			"version": version, "tag": "v" + version, "sourceCommit": source, "sourceTree": tree, "goVersion": "go1.27.4",
			"tags": "fixture", "buildID": "", "rawBuildInfo": "fixture",
			"buildGraph":     map[string]any{"settings": map[string]any{}, "normalModules": []any{}, "prebuiltAcquisitionModules": []any{}, "localReplacements": []any{}},
			"sourceIdentity": map[string]any{"sourceOverlay": json.Number("0"), "goModSha256": hash, "goSumSha256": hash, "replacements": []any{}},
			"archive": map[string]any{
				"name": id + platform.suffix, "releaseName": "sing-box-polaris-" + strings.TrimPrefix(id, "sing-box-") + platform.suffix,
				"bytes": json.Number("1"), "sha256": hash, "root": id, "members": map[string]any{id + "/sing-box": hash},
			},
			"core":    map[string]any{"member": "sing-box", "bytes": json.Number("1"), "sha256": hash},
			"sidecar": nil, "signatureObservation": nil, "finalPackageCronetSmoke": nil,
		})
	}
	document := map[string]any{
		"schema": "polaris-upstream-native-assets-v1", "repository": repository, "repositoryId": json.Number(repositoryID),
		"version": version, "tag": "v" + version, "tagObject": object, "sourceCommit": source, "sourceTree": tree,
		"producer": map[string]any{
			"repository": repository, "repositoryId": json.Number(repositoryID), "workflow": workflow, "workflowCommit": source,
			"runId": json.Number("42"), "runAttempt": json.Number("1"), "nativeJobs": producerJobs,
		},
		"legalFiles":    []any{map[string]any{"path": "licenses/LICENSE", "content": "x", "bytes": json.Number("1"), "sha256": hash}},
		"sourceArchive": map[string]any{"name": "sing-box-polaris-source-" + source + ".tar.gz", "bytes": json.Number("1"), "sha256": hash},
		"platforms":     rows,
	}
	encode := func(value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var materialJSON bytes.Buffer
	if err := distributionMaterialsCommand([]string{"--source-root", root}, bytes.NewReader(encode(document)), &materialJSON); err != nil {
		t.Fatal(err)
	}
	var material map[string]any
	if err := uniqueJSON(&materialJSON, &material); err != nil {
		t.Fatal(err)
	}
	document["distributionMaterials"] = material
	valid := encode(document)
	parseJobs := func() ([]map[string]any, error) { return jobs, nil }
	check := func(input []byte, sourceRoot string, fetch func() ([]map[string]any, error)) error {
		return validateFinalNativeIndex(bytes.NewReader(input), sourceRoot, source, tree, "v"+version, object, runID, attempt, workflow, fetch)
	}
	if err := check(valid, root, parseJobs); err != nil {
		t.Fatal(err)
	}
	duplicatedJobs := append(append([]map[string]any{}, jobs...), jobs[0])
	if err := check(valid, root, func() ([]map[string]any, error) { return duplicatedJobs, nil }); err == nil {
		t.Fatal("accepted duplicate native job evidence")
	}
	if err := check(valid, t.TempDir(), parseJobs); err == nil {
		t.Fatal("accepted unavailable original source")
	}

	for _, control := range []struct {
		field, stringValue string
		path               []string
	}{
		{"tagObject", strings.Repeat("d", 40), nil},
		{"workflowCommit", strings.Repeat("d", 40), []string{"producer"}},
		{"name", "other.tar.gz", []string{"sourceArchive"}},
		{"sourceTree", strings.Repeat("d", 40), []string{"distributionMaterials"}},
		{"sha256", strings.Repeat("d", 64), []string{"distributionMaterials", "noticeSelection"}},
		{"cmd/internal/ci/cronet_overlay.go", hash, []string{"distributionMaterials", "inputs"}},
	} {
		t.Run(control.field, func(t *testing.T) {
			var candidate map[string]any
			if err := uniqueJSON(bytes.NewReader(valid), &candidate); err != nil {
				t.Fatal(err)
			}
			ledger := candidate
			for _, key := range control.path {
				ledger = ledger[key].(map[string]any)
			}
			ledger[control.field] = control.stringValue
			if err := check(encode(candidate), root, parseJobs); err == nil {
				t.Fatal("accepted changed producer identity or source materials")
			}
		})
	}
}

func TestDistributionAssessmentAndUnknownModuleRemainUnapproved(t *testing.T) {
	catalog := map[string]any{"schema": json.Number("1"), "status": "reviewed-current-scope", "openItems": []any{}}
	approved, err := validateDistributionAssessment(catalog)
	if err != nil || !approved {
		t.Fatalf("expected reviewed empty catalog: %v", err)
	}
	for _, invalid := range []any{nil, false, "", map[string]any{}, json.Number("0"), []any{map[string]any{"id": "open"}}} {
		catalog["openItems"] = invalid
		if _, err := validateDistributionAssessment(catalog); err == nil {
			t.Fatalf("accepted malformed assessment items: %#v", invalid)
		}
	}
	catalog["openItems"] = []any{map[string]any{"id": "review", "detail": "materials pending"}}
	if approved, err := validateDistributionAssessment(catalog); err != nil || approved {
		t.Fatal("open assessment was approved")
	}

	materials := distributionModuleRecords{modules: make(map[string]any), missing: make(map[string]any)}
	original := map[string]any{"module": "example.org/original", "version": "v1.0.0", "h1": ""}
	id, err := materials.module(map[string]any{
		"module": original["module"], "version": original["version"], "h1": original["h1"],
		"replacement": map[string]any{"module": "github.com/SomeOwner/fork", "version": "v2.0.0", "h1": "h1:fixture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	record := materials.modules[id].(map[string]any)
	if !nativeFieldsMatch(record, map[string]any{
		"replaces": original, "availabilityVerified": false, "sourceURL": "https://proxy.golang.org/github.com/!some!owner/fork/@v/v2.0.0.zip",
	}) || len(materials.missing) != 2 {
		t.Fatal("an unknown replacement lost its source or notice gaps")
	}
}

func TestOwnedReplacementRequiresPinnedSourceAndUnchangedNotices(t *testing.T) {
	root := t.TempDir()
	original := materialIdentity{module: originalOpenConnect, version: "v1.0.0"}
	owned := materialIdentity{module: ownedOpenConnect, version: "v1.0.1"}
	license := "unchanged historical license\n"
	archive := func(license, additional, code string) []byte {
		t.Helper()
		var data bytes.Buffer
		z := zip.NewWriter(&data)
		members := map[string]string{"client.go": code}
		if license != "" {
			members["LICENSE"] = license
		}
		if additional != "" {
			members["licenses/third-party.txt"] = additional
		}
		for name, content := range members {
			w, err := z.Create(owned.module + "@" + owned.version + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprint(w, content); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return data.Bytes()
	}
	verified := archive(license, "", "package openconnect")
	filename := filepath.Join(root, "source.zip")
	if err := os.WriteFile(filename, verified, 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.HashZip(filename, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	owned.h1 = h1
	fixtureFile(t, root, "go.mod", "module example.org/core\n\ngo 1.27.4\n\nrequire "+original.module+" "+original.version+"\nreplace "+original.module+" => "+owned.module+" "+owned.version+"\n")
	fixtureFile(t, root, "go.sum", owned.module+" "+owned.version+" "+owned.h1+"\n")
	item := map[string]any{"module": original.module, "version": original.version, "h1": original.h1}
	var offset int64
	size := int64(len(license))
	notice := distributionNotices{
		Components: []map[string]any{{"module": original.module, "version": original.version, "noticeRecordIndexes": []any{json.Number("0")}}},
		Records:    []noticeRecord{{SourcePath: original.module + "@" + original.version + "/LICENSE", ByteOffset: &offset, Bytes: &size}},
		data:       []byte(license),
	}
	for _, control := range []struct {
		name string
		zip  []byte
		want string
	}{
		{"unchanged", verified, ""},
		{"changed notice", archive("changed", "", "package openconnect"), "notices differ"},
		{"missing notice", archive("", "", "package openconnect"), "notices differ"},
		{"additional notice", archive(license, "new terms", "package openconnect"), "notices differ"},
		{"changed module bytes", archive(license, "", "package altered"), "ZIP h1 differs"},
		{"download failure", nil, "download unavailable"},
	} {
		t.Run(control.name, func(t *testing.T) {
			result, err := ownedReplacementMaterials(item, owned, root, notice, "1.27.4", func(path, version string, id materialIdentity) ([]byte, error) {
				if path != root || version != "1.27.4" || id != owned {
					t.Fatal("download escaped immutable owned source selection")
				}
				if control.zip == nil {
					return nil, fmt.Errorf("download unavailable")
				}
				return control.zip, nil
			})
			if control.want == "" {
				if err != nil || result["availabilityVerified"] != true {
					t.Fatalf("valid source not verified: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), control.want) {
				t.Fatalf("wanted %q, got %v", control.want, err)
			}
		})
	}
	wrong := owned
	wrong.h1 = "h1:wrong"
	if _, err := ownedReplacementMaterials(item, wrong, root, notice, "1.27.4", func(string, string, materialIdentity) ([]byte, error) {
		t.Fatal("mismatched source go.sum reached the download")
		return nil, nil
	}); err == nil {
		t.Fatal("mismatched source go.sum was accepted")
	}
}
