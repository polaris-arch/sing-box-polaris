package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Reuse the repository's fake gh test binary. Test requests have no network path.
func publisherFixtureGitHub() int {
	root := os.Getenv("POLARIS_PUBLISHER_FIXTURE")
	args := os.Args[1:]
	if len(args) < 4 || args[0] != "api" {
		return 3
	}
	get := args[1] == "--include"
	var method, endpoint string
	if get {
		if len(args) != 5 || args[2] != "--method" || args[3] != "GET" {
			return 4
		}
		method, endpoint = "GET", args[4]
	} else {
		method, endpoint = args[2], args[3]
	}
	log, err := os.OpenFile(filepath.Join(root, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 5
	}
	fmt.Fprintln(log, method, endpoint)
	log.Close()
	var routes map[string]string
	if err := publisherReadJSON(filepath.Join(root, "routes.json"), &routes); err != nil {
		return 6
	}
	draft := filepath.Join(root, "draft")
	_, draftErr := os.Stat(draft)
	switch {
	case get && endpoint == publisherRepositoryPath+"/releases?per_page=100&page=1" && draftErr == nil:
		endpoint = "listed-draft"
	case get && endpoint == publisherRepositoryPath+"/releases/9" && draftErr == nil:
		payload, err := os.ReadFile(draft)
		if err != nil {
			return 7
		}
		if bytes.Contains(payload, []byte(`"draft":false`)) {
			if reply := routes["final-get"]; reply != "" {
				payload = []byte(reply)
			}
		} else if reply := routes["draft-get"]; reply != "" {
			payload = []byte(reply)
		}
		fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\n\r\n")
		fmt.Fprint(os.Stdout, string(payload))
		return 0
	case get && draftErr == nil && endpoint == publisherRepositoryPath+"/actions/artifacts/31/zip" && routes["GET second-zip"] != "":
		endpoint = "second-zip"
	case !get && method == "POST" && endpoint == publisherRepositoryPath+"/releases":
		var request map[string]any
		if err := uniqueJSON(os.Stdin, &request); err != nil || request["draft"] != true || request["prerelease"] != true {
			return 8
		}
		if err := os.WriteFile(draft, []byte(routes["draft-record"]), 0o600); err != nil {
			return 9
		}
	case !get && method == "PATCH" && endpoint == publisherRepositoryPath+"/releases/9":
		var request map[string]any
		if err := uniqueJSON(os.Stdin, &request); err != nil || request["draft"] != false || request["make_latest"] != "false" {
			return 10
		}
		if err := os.WriteFile(draft, []byte(routes["finalized"]), 0o600); err != nil {
			return 11
		}
		if _, err := os.Stat(filepath.Join(root, "cancel-patch")); err == nil {
			if err := os.WriteFile(filepath.Join(root, "patch-entered"), nil, 0o600); err != nil {
				return 12
			}
			time.Sleep(30 * time.Second)
			return 19
		}
	case !get && method == "POST" && strings.HasPrefix(endpoint, "https://uploads.github.com/"):
		if len(args) != 8 || args[6] != "--input" {
			return 13
		}
		if _, err := os.Stat(filepath.Join(root, "lose-upload")); err == nil {
			return 14
		}
		if err := os.WriteFile(filepath.Join(root, "uploaded"), []byte(endpoint), 0o600); err != nil {
			return 15
		}
		data, err := os.ReadFile(args[7])
		if err != nil || string(data) != "fixture public bytes" {
			return 16
		}
		return 0
	}
	reply, found := routes[method+" "+endpoint]
	if !found {
		return 17
	}
	if get {
		fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\nx-github-request-id: fixture\r\n\r\n")
	}
	if strings.HasPrefix(reply, "@") {
		raw, err := os.ReadFile(filepath.Join(root, reply[1:]))
		if err != nil {
			return 18
		}
		os.Stdout.Write(raw)
	} else {
		fmt.Fprint(os.Stdout, reply)
	}
	return 0
}

func TestPublisherModesShareBoundedArtifactFlow(t *testing.T) {
	stub := fixtureSourceCLI(t)
	root := t.TempDir()
	runner := t.TempDir()
	producer := t.TempDir()
	scriptRoot := t.TempDir()
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "publisher")
	t.Setenv("POLARIS_PUBLISHER_FIXTURE", root)
	t.Setenv("RUNNER_TEMP", runner)
	t.Setenv("GITHUB_REPOSITORY", repository)
	t.Setenv("GITHUB_REPOSITORY_ID", repositoryID)
	t.Setenv("GITHUB_SHA", strings.Repeat("4", 40))
	t.Setenv("GITHUB_RUN_ID", "111")
	t.Setenv("POLARIS_GITHUB_PUBLISH_ENABLED", "true")
	t.Setenv("GH_TOKEN", "offline-fixture-only")
	t.Setenv("PATH", filepath.Dir(stub)+string(os.PathListSeparator)+os.Getenv("PATH"))
	fixtureSourceGit(t, producer, "init")
	fixtureFile(t, producer, "source.txt", "source bytes")
	fixtureSourceGit(t, producer, "add", "source.txt")
	fixtureSourceGit(t, producer, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
	source := fixtureSourceGit(t, producer, "rev-parse", "HEAD")
	tree := fixtureSourceGit(t, producer, "rev-parse", "HEAD^{tree}")
	tagObject := strings.Repeat("c", 40)
	const version, runID, reviewedRun = "1.15.0-polaris-alpha.12.22", "42", "45"
	tag := "v" + version
	const artifactName = "binary-linux_amd64-purego"
	publicPayload := "sing-box-" + version + "-linux-amd64.tar.gz"
	publicName := "sing-box-polaris-1.15.0-alpha.12.22-linux-amd64.tar.gz"
	sourceFile := "sing-box-polaris-source-" + source + ".tar.gz"

	encode := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	repo := map[string]any{"id": 1421657509}
	fixtureFile(t, scriptRoot, "release/ci/github-release.json", encode(map[string]any{
		"repository": repository, "repositoryId": 1421657509, "publication": "github-only-unsigned-prerelease",
	}))
	fixtureFile(t, scriptRoot, publisherScopeFile, encode(map[string]any{"all": map[string]any{
		"workflow": ".github/workflows/build.yml", "payloadRules": map[string]any{
			artifactName:            []map[string]any{{"pattern": "sing-box-{version}-linux-amd64\\.tar\\.gz", "count": 1}},
			publisherIndexArtifact:  []map[string]any{{"pattern": "polaris-upstream-native-assets\\.json", "count": 1}, {"pattern": "sing-box-polaris-source-[0-9a-f]{40}\\.tar\\.gz", "count": 1}},
			"publisher-run-receipt": []map[string]any{{"pattern": "publisher-run-receipt\\.json", "count": 1}},
		},
	}}))
	t.Chdir(scriptRoot)
	api := publisherRepositoryPath
	releases := api + "/releases"
	routes := map[string]string{
		"GET " + api: encode(repo),
		"GET " + api + "/actions/runs/" + runID: encode(map[string]any{"repository": repo, "head_repository": repo,
			"head_branch": tag, "head_sha": source, "path": ".github/workflows/build.yml", "status": "completed", "conclusion": "success",
			"event": "workflow_dispatch", "run_attempt": 1, "run_started_at": "2026-11-18T00:00:00Z"}),
		"GET " + api + "/actions/runs/" + reviewedRun: encode(map[string]any{"repository": repo, "head_repository": repo,
			"head_sha": os.Getenv("GITHUB_SHA"), "path": publisherWorkflow, "status": "completed", "conclusion": "success"}),
		"GET " + api + "/git/ref/tags/" + tag:                                 encode(map[string]any{"object": map[string]any{"type": "tag", "sha": tagObject}}),
		"GET " + api + "/git/tags/" + tagObject:                               encode(map[string]any{"sha": tagObject, "tag": tag, "object": map[string]any{"type": "commit", "sha": source}}),
		"GET " + api + "/actions/runs/42/attempts/1/jobs?per_page=100&page=1": `{"jobs":[{"id":39}]}`,
		"GET " + releases + "?per_page=100&page=1":                            "[]",
	}
	draft := encode(map[string]any{"id": 9, "tag_name": tag, "draft": true,
		"upload_url": "https://uploads.github.com/" + releases + "/9/assets{?name,label}"})
	finalized := encode(map[string]any{"id": 9, "tag_name": tag, "draft": false, "html_url": "https://fixture.invalid/release/9"})
	routes["POST "+releases], routes["PATCH "+releases+"/9"] = draft, finalized
	routes["draft-record"], routes["finalized"] = draft, finalized
	routes["GET listed-draft"] = "[" + draft + "]"
	routes["GET "+releases+"/9/assets?per_page=100&page=1"] = encode([]map[string]any{{"name": publicName, "state": "uploaded",
		"size": len("fixture public bytes"), "digest": "sha256:" + sha256Hex([]byte("fixture public bytes"))}})

	artifact := func(id int64, name string, entries [][2]string) publisherArtifactMetadata {
		t.Helper()
		var data bytes.Buffer
		archive := zip.NewWriter(&data)
		for _, entry := range entries {
			file, err := archive.Create(entry[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, entry[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		idString := fmt.Sprint(id)
		fixtureFile(t, root, idString+".zip", data.String())
		expired := false
		metadata := publisherArtifactMetadata{ID: id, Name: name, Size: int64(data.Len()),
			Digest: "sha256:" + sha256Hex(data.Bytes()), Expired: &expired, CreatedAt: "2026-11-18T00:01:00Z"}
		metadata.WorkflowRun.ID, metadata.WorkflowRun.HeadSHA = 42, source
		routes["GET "+api+"/actions/artifacts/"+idString+"/zip"] = "@" + idString + ".zip"
		routes["GET "+api+"/actions/artifacts/"+idString] = encode(metadata)
		return metadata
	}
	index := encode(map[string]any{"schema": "polaris-upstream-native-assets-v1", "sourceCommit": source, "sourceTree": tree,
		"tag": tag, "tagObject": tagObject, "sourceArchive": map[string]any{"name": sourceFile, "sha256": sha256Hex([]byte("archive")),
			"bytes": 7}, "platforms": []any{map[string]any{"archive": map[string]any{"name": publicPayload,
			"sha256": sha256Hex([]byte("fixture public bytes")), "bytes": len("fixture public bytes")}}},
		"distributionMaterials": map[string]any{"publicationEligible": true}})
	producerReceipt := encode(map[string]any{"repository": repository, "repositoryId": 1421657509, "sourceCommit": source,
		"runId": runID, "attempt": 1, "version": version, "build": "All", "role": "all"})
	routes["GET "+api+"/actions/runs/42/artifacts?per_page=100&page=1"] = encode(map[string]any{"artifacts": []publisherArtifactMetadata{
		artifact(31, artifactName, [][2]string{{publicPayload, "fixture public bytes"}}),
		artifact(32, publisherIndexArtifact, [][2]string{{publisherIndexFile, index}, {sourceFile, "archive"}}),
		artifact(33, "publisher-run-receipt", [][2]string{{"publisher-run-receipt.json", producerReceipt}}),
	}})
	writeRoutes := func() { fixtureFile(t, root, "routes.json", encode(routes)) }
	writeRoutes()
	checkNative := func(input io.Reader, sourceRoot, boundSource, boundTree, boundTag, boundObject string, run int64, attempt int, workflow string, jobs func() ([]map[string]any, error)) error {
		raw, err := io.ReadAll(input)
		if err != nil {
			return err
		}
		if string(raw) != index || sourceRoot != producer || boundSource != source || boundTree != tree ||
			boundTag != tag || boundObject != tagObject || run != 42 || attempt != 1 || workflow != ".github/workflows/build.yml" {
			return fmt.Errorf("unexpected native validator inputs")
		}
		result, err := jobs()
		if err == nil && !reflect.DeepEqual(result, []map[string]any{{"id": json.Number("39")}}) {
			return fmt.Errorf("native jobs differ: %v", result)
		}
		return err
	}
	runContext := func(ctx context.Context, mode, nickname, reviewedSHA string) error {
		args := []string{mode, "--source", source, "--source-dir", producer, "--all-run", runID,
			"--output", filepath.Join(root, nickname+"-output"), "--audit", filepath.Join(root, nickname+"-audit")}
		if mode != "inventory" {
			args = append(args, "--inventory-run", reviewedRun, "--inventory-sha256", reviewedSHA)
		}
		err := runPublisher(ctx, args, checkNative)
		files, readErr := os.ReadDir(runner)
		if readErr != nil || len(files) != 0 {
			t.Fatalf("publisher scratch survived %s: %v %v", nickname, files, readErr)
		}
		return err
	}
	run := func(mode, nickname, reviewedSHA string) error {
		return runContext(t.Context(), mode, nickname, reviewedSHA)
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	if err := run("inventory", "inventory", ""); err != nil {
		t.Fatal(err)
	}
	proposal := read("inventory-output")
	if strings.Contains(string(proposal), "fixture public bytes") || !strings.Contains(string(proposal), publicName) {
		t.Fatal("inventory output lost provenance or exposed payload")
	}
	routes["GET "+api+"/actions/runs/45/artifacts?per_page=100&page=1"] = encode(map[string]any{"artifacts": []publisherArtifactMetadata{
		artifact(37, "github-release-validation", [][2]string{{"release-inventory-proposal.json", string(proposal)}, {"private-evidence", strings.Repeat("x", 1<<20)}}),
	}})
	writeRoutes()
	if err := run("validate", "wrong-sha", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "reviewed hash") {
		t.Fatalf("wrong reviewed inventory SHA: %v", err)
	}
	if err := run("validate", "validate", sha256Hex(proposal)); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(root, "validate-output"))
	if err != nil || len(files) != 0 {
		t.Fatalf("validation created public payloads: %v %v", files, err)
	}
	if strings.Contains(string(read("calls")), "POST ") {
		t.Fatal("read-only phase wrote remotely")
	}
	if err := run("publish", "publish", sha256Hex(proposal)); err != nil {
		t.Fatal(err)
	}
	upload := "https://uploads.github.com/" + releases + "/9/assets?name=" + publicName
	if string(read("uploaded")) != upload {
		t.Fatal("upload used an unexpected release or asset name")
	}
	status := string(read("publish-audit/storage-status.json"))
	if !strings.Contains(status, `"remoteWriteState": "published"`) {
		t.Fatalf("missing confirmed publication receipt: %s", status)
	}
	if err := os.Remove(filepath.Join(root, "draft")); err != nil {
		t.Fatal(err)
	}
	fixtureFile(t, root, "lose-upload", "")
	if err := run("publish", "upload-failure", sha256Hex(proposal)); err == nil {
		t.Fatal("lost upload reported success")
	}
	log := strings.Split(strings.TrimSpace(string(read("calls"))), "\n")
	if !strings.HasPrefix(log[len(log)-1], "POST https://uploads.github.com/") {
		t.Fatalf("an uncertain upload triggered further writes: %v", log[len(log)-3:])
	}
	if status := string(read("upload-failure-audit/storage-status.json")); !strings.Contains(status, `"remoteWriteState": "upload-outcome-unknown"`) {
		t.Fatalf("missing uncertain upload receipt: %s", status)
	}
	if err := run("publish", "existing-draft", sha256Hex(proposal)); err == nil || !strings.Contains(err.Error(), "existing Release") {
		t.Fatalf("existing release was not rejected: %v", err)
	}
	resetAttempt := func() {
		t.Helper()
		for _, name := range []string{"draft", "lose-upload", "cancel-patch", "patch-entered"} {
			if err := os.Remove(filepath.Join(root, name)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	normalRoutes := maps.Clone(routes)
	wrongDraft := strings.Replace(draft, `"id":9`, `"id":90`, 1)
	wrongResult := strings.Replace(finalized, `"id":9`, `"id":90`, 1)
	metadataRoute := "GET " + api + "/actions/artifacts/31"
	var changedMetadata publisherArtifactMetadata
	if err := json.Unmarshal([]byte(normalRoutes[metadataRoute]), &changedMetadata); err != nil {
		t.Fatal(err)
	}
	changedMetadata.Digest = "sha256:" + strings.Repeat("f", 64)
	changedZIP := read("31.zip")
	changedZIP[len(changedZIP)-1] ^= 1
	fixtureFile(t, root, "changed.zip", string(changedZIP))
	assertReadback := func(t *testing.T, name, calls, state string) {
		t.Helper()
		if strings.Count(calls, "PATCH ") != 1 || !strings.HasSuffix(calls, "PATCH "+releases+"/9\nGET "+releases+"/9\n") {
			t.Fatalf("uncertain finalization did not read back only the target: %s", calls)
		}
		status := string(read(name + "-audit/storage-status.json"))
		if !strings.Contains(status, `"remoteWriteState": "`+state+`"`) ||
			(state == "finalization-readback") != strings.Contains(status, `"observedDraft": false`) {
			t.Fatalf("unbound publication status: %s", status)
		}
	}
	for _, test := range []struct {
		name, message, finalState string
		override                  map[string]string
		noUpload                  bool
	}{
		{"wrong-draft-tag", "draft creation response", "", map[string]string{"POST " + releases: strings.Replace(draft, tag, "different", 1)}, true},
		{"wrong-draft-id", "draft identity or state changed", "", map[string]string{"draft-get": wrongDraft}, false},
		{"lost-final-reply", "PATCH failed", "finalization-readback", map[string]string{"PATCH " + releases + "/9": "@absent"}, false},
		{"wrong-final-id", "finalization response", "finalization-readback", map[string]string{"PATCH " + releases + "/9": wrongResult}, false},
		{"unbound-readback", "finalization response", "finalization-outcome-unknown", map[string]string{"PATCH " + releases + "/9": "{}", "final-get": wrongResult}, false},
		{"changed-second-metadata", "public ZIP identity changed", "", map[string]string{metadataRoute: encode(changedMetadata)}, true},
		{"short-second-download", "Actions artifact ZIP size differs", "", map[string]string{"GET second-zip": "short"}, true},
		{"changed-second-download", "Actions artifact digest missing or mismatched", "", map[string]string{"GET second-zip": "@changed.zip"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetAttempt()
			routes = maps.Clone(normalRoutes)
			maps.Copy(routes, test.override)
			writeRoutes()
			start := len(read("calls"))
			if err := run("publish", test.name, sha256Hex(proposal)); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("publication result differs: %v", err)
			}
			calls := string(read("calls")[start:])
			if test.noUpload && strings.Contains(calls, "POST https://uploads.github.com/") {
				t.Fatal("asset written without matching release or bytes")
			}
			if test.finalState != "" {
				assertReadback(t, test.name, calls, test.finalState)
			} else if strings.Contains(calls, "PATCH ") {
				t.Fatalf("unconfirmed draft reached finalization: %s", calls)
			}
		})
	}
	resetAttempt()
	routes = normalRoutes
	writeRoutes()
	fixtureFile(t, root, "cancel-patch", "")
	start := len(read("calls"))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Stat(filepath.Join(root, "patch-entered")); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	err = runContext(ctx, "publish", "cancelled", sha256Hex(proposal))
	cancel()
	<-done
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "PATCH failed") {
		t.Fatalf("original cancelled PATCH error lost: %v", err)
	}
	assertReadback(t, "cancelled", string(read("calls")[start:]), "finalization-readback")
}

func TestPublisherScratchAdmissionPrecedesDownloadAndKeepsExistingEvidence(t *testing.T) {
	root := t.TempDir()
	storage := &publisherStorage{root: root, limit: 1, state: map[string]any{}}
	if err := storage.temporary(2, "bounded ZIP", func(*os.File) error {
		t.Fatal("opened a ZIP before reserving the complete compressed size")
		return nil
	}); err == nil {
		t.Fatal("oversized allocation admitted")
	}
	filename := filepath.Join(root, fixtureFile(t, root, "audit", "existing"))
	if err := storage.retained(filename, 1, "audit copy", func(io.Writer) error {
		t.Fatal("overwrote existing evidence")
		return nil
	}); !os.IsExist(err) {
		t.Fatalf("exclusive destination failure differs: %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil || string(data) != "existing" || storage.live != 0 {
		t.Fatalf("existing evidence or accounting changed: %q (%d) %v", data, storage.live, err)
	}
	const note = "partial retained file cleanup also failed"
	primary := errors.New("injected partial write")
	partial := filepath.Join(root, "partial")
	err = storage.retained(partial, 1, "failed audit copy", func(file io.Writer) error {
		if _, err := io.WriteString(file, "x"); err != nil {
			return err
		}
		return primary
	})
	if !errors.Is(err, primary) || storage.live != 0 {
		t.Fatalf("partial write error or accounting changed: %v (%d)", err, storage.live)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("partial destination survived cleanup: %v", err)
	}
	var annotated *publisherCleanupError
	err = publisherCleanup(primary, os.ErrPermission, note)
	if !errors.Is(err, primary) || !errors.As(err, &annotated) || !strings.HasPrefix(annotated.note, note) {
		t.Fatalf("cleanup failure replaced the primary failure or lost its note: %v", err)
	}
}

func TestReviewedPublisherFileRequiresExplicitSizeAndName(t *testing.T) {
	for _, document := range []string{`{"bytes":0}`, `{"releaseName":null}`} {
		var file publisherFile
		if err := json.Unmarshal([]byte(document), &file); err == nil {
			t.Fatalf("incomplete reviewed record admitted: %s", document)
		}
	}
	var file publisherFile
	if err := json.Unmarshal([]byte(`{"bytes":0,"releaseName":null}`), &file); err != nil {
		t.Fatalf("valid private zero-byte record rejected: %v", err)
	}
}

func TestPublisherUploadEndpointBindsExactReleaseAndAsset(t *testing.T) {
	path := "/" + publisherRepositoryPath + "/releases/12/assets"
	allowed := "https://uploads.github.com" + path
	endpoint, err := publisherUploadEndpoint(publisherRelease{ID: 12, UploadURL: allowed + "{?name,label}"}, "asset +.zip")
	if err != nil || endpoint != allowed+"?name=asset%20%2B.zip" {
		t.Fatalf("asset endpoint differs: %s %v", endpoint, err)
	}
	for _, endpoint := range []string{
		"http://uploads.github.com" + path,
		"https://uploads.github.com.evil.invalid" + path,
		"https://user@uploads.github.com" + path,
		"https://uploads.github.com:443" + path,
		allowed + "?replace=true",
		allowed + "#fragment",
		allowed + "/extra",
		strings.Replace(allowed, "/12/assets", "/13/assets", 1),
	} {
		if _, err := publisherUploadEndpoint(publisherRelease{ID: 12, UploadURL: endpoint}, "asset.zip"); err == nil {
			t.Fatalf("unapproved asset endpoint admitted: %s", endpoint)
		}
	}
	if _, err := publisherUploadEndpoint(publisherRelease{ID: 12, UploadURL: allowed}, "subdir/asset.zip"); err == nil {
		t.Fatal("non-basename asset admitted")
	}
}
