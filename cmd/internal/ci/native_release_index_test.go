package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/dirhash"
)

func readNativeArchive(filename string) (string, map[string][]byte, error) {
	archive, err := os.Open(filename)
	if err != nil {
		return "", nil, err
	}
	defer archive.Close()
	return readNativeArchiveFile(archive)
}

func TestNativeArchiveRejectsOversizedMemberBeforeExpansion(t *testing.T) {
	var data bytes.Buffer
	compressed := gzip.NewWriter(&data)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{
		Name: "sing-box-fixture/sing-box",
		Mode: 0o755,
		Size: 1 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "fixture.tar.gz")
	if err := os.WriteFile(file, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readNativeArchive(file); err == nil || !strings.Contains(err.Error(), "expanded byte budget") {
		t.Fatalf("oversized member was not rejected before reading its bytes: %v", err)
	}
}

func TestNativeReleaseArchiveMemberContract(t *testing.T) {
	const root = "sing-box-fixture"
	const member = root + "/sing-box"
	core := []byte{0, 0xff, 0x7f}
	for _, test := range []struct {
		name    string
		members []string
		pass    bool
	}{
		{"original bytes", []string{root + "/LICENSE", member}, true},
		{"traversal", []string{root + "/../evil"}, false},
		{"duplicate", []string{member, member}, false},
		{"case-fold collision", []string{root + "/LICENSE", root + "/license"}, false},
		{"backslash", []string{root + `/..\evil`}, false},
		{"Windows drive", []string{root + `/C:\evil`}, false},
		{"Windows device", []string{root + "/CON"}, false},
		{"Windows device with extension", []string{root + "/NUL.txt"}, false},
		{"trailing dot", []string{root + "/endsdot."}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data bytes.Buffer
			compressed := gzip.NewWriter(&data)
			archive := tar.NewWriter(compressed)
			for _, name := range test.members {
				raw := core
				if name == root+"/LICENSE" {
					raw = []byte("license text\n")
				}
				if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(raw))}); err != nil {
					t.Fatal(err)
				}
				if _, err := archive.Write(raw); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := compressed.Close(); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "fixture.tar.gz")
			if err := os.WriteFile(filename, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			archiveRoot, members, err := readNativeArchive(filename)
			if !test.pass {
				if err == nil {
					t.Fatalf("admitted unsafe native members: %q", test.members)
				}
				return
			}
			want := map[string][]byte{"LICENSE": []byte("license text\n"), "sing-box": core}
			if err != nil || archiveRoot != root || !reflect.DeepEqual(members, want) {
				t.Fatalf("native archive did not return the original members: %q %v %v", archiveRoot, members, err)
			}
		})
	}
	t.Run("ZIP symlink", func(t *testing.T) {
		header := zip.FileHeader{Name: member, Method: zip.Deflate}
		header.SetMode(os.ModeSymlink | 0o777)
		filename := filepath.Join(t.TempDir(), "fixture.zip")
		if err := os.WriteFile(filename, fixtureZIP(t, header), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readNativeArchive(filename); err == nil {
			t.Fatal("admitted a native archive symlink")
		}
	})
}

func TestNativeBuildInfoPartitionsRealLinkedModules(t *testing.T) {
	const acquisition = "github.com/sagernet/cronet-go/lib/linux_amd64"
	const tags = "with_gvisor,with_naive_outbound"
	root := t.TempDir()
	fixtureFile(t, root, "go.mod", "module example.org/native\ngo 1.27.0\n"+
		"require (\nexample.org/first v1.0.0\nexample.org/second v1.0.0\n"+acquisition+" v1.2.3\n)\n"+
		"replace example.org/first => ./first\nreplace example.org/second => ./second\n")
	for _, name := range []string{"first", "second"} {
		fixtureFile(t, root, name+"/go.mod", "module example.org/"+name+"\ngo 1.27.0\n")
		fixtureFile(t, root, name+"/value.go", "package "+name+"\nconst Value = 1\n")
	}
	fixtureFile(t, root, "main.go", fmt.Sprintf(`package main
import (
	"example.org/first"
	"example.org/second"
	%q
)
func main() { println(first.Value + second.Value + acquisition.Value) }
`, acquisition))

	// A file-only module proxy makes the acquisition record a genuine
	// downloaded dependency without a network or a pre-populated cache.
	proxy := filepath.Join(root, "proxy")
	moduleFile := "module " + acquisition + "\ngo 1.27.0\n"
	base := acquisition + "/@v/v1.2.3"
	fixtureFile(t, proxy, base+".mod", moduleFile)
	fixtureFile(t, proxy, base+".info", `{"Version":"v1.2.3","Time":"2000-01-01T00:00:00Z"}`)
	var data bytes.Buffer
	moduleArchive := zip.NewWriter(&data)
	for _, file := range []struct{ name, contents string }{
		{"go.mod", moduleFile}, {"value.go", "package acquisition\nconst Value = 1\n"},
	} {
		member, err := moduleArchive.Create(acquisition + "@v1.2.3/" + file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(member, file.contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := moduleArchive.Close(); err != nil {
		t.Fatal(err)
	}
	moduleZip := fixtureFile(t, proxy, base+".zip", data.String())
	moduleSum, err := dirhash.HashZip(filepath.Join(proxy, moduleZip), dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.ToSlash(proxy)
	if !strings.HasPrefix(proxyPath, "/") {
		proxyPath = "/" + proxyPath
	}
	proxyURL := url.URL{Scheme: "file", Path: proxyPath}
	t.Setenv("GOPROXY", proxyURL.String())
	t.Setenv("GONOPROXY", "none")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOVCS", "*:off")
	t.Setenv("GOMODCACHE", filepath.Join(root, "module-cache"))
	t.Setenv("GOENV", "off")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOOS", runtime.GOOS)
	t.Setenv("GOARCH", runtime.GOARCH)
	t.Setenv("CGO_ENABLED", "0")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	executable := filepath.Join(root, "core-fixture")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	_, diagnostic, code, err := sourceCommandOutput(ctx, root, nil, 1<<20, goTool,
		"build", "-mod=mod", "-modcacherw", "-buildvcs=false", "-p=1", "-tags="+tags, "-o", executable, ".")
	if err != nil || code == nil || *code != 0 {
		t.Fatalf("compile offline native buildinfo fixture: %v\n%s", err, diagnostic)
	}
	version, raw, graph, err := nativeBuildInfo(executable)
	if err != nil || version != runtime.Version() || graph.Settings["CGO_ENABLED"] != "0" || graph.Settings["-tags"] != tags {
		t.Fatalf("actual native settings differ: %s %#v %v", version, graph.Settings, err)
	}
	if len(graph.NormalModules) != 0 || !reflect.DeepEqual(graph.LocalReplacements, []moduleRecord{
		{Module: "example.org/first", Version: "v1.0.0", Replacement: &moduleRecord{Module: "./first", Version: "(devel)"}},
		{Module: "example.org/second", Version: "v1.0.0", Replacement: &moduleRecord{Module: "./second", Version: "(devel)"}},
	}) || !reflect.DeepEqual(graph.AcquisitionModules, []moduleRecord{
		{Module: acquisition, Version: "v1.2.3", H1: moduleSum},
	}) {
		t.Fatalf("native module partitions differ: %#v", graph)
	}
	expected, diagnostic, code, err := sourceCommandOutput(ctx, root, nil, 1<<20, goTool, "version", "-m", executable)
	if err != nil || code == nil || *code != 0 || raw != expected {
		t.Fatalf("native raw buildinfo differs from go version -m: %v\n%s\n%s\n%s", err, diagnostic, raw, expected)
	}
}

func TestDistributionLicenseFilesAreSourceText(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	err := fs.WalkDir(os.DirFS(root), "release/licenses", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := readNativeSource(root, path)
		if err != nil {
			return err
		}
		if !utf8.Valid(data) || strings.EqualFold(filepath.Ext(path), ".class") {
			return fmt.Errorf("shared notice file must be UTF-8 text: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDistributionProducerInputsUseCommittedRoster(t *testing.T) {
	root := t.TempDir()
	fixtureSourceGit(t, root, "init", "-q")
	commit := func() {
		t.Helper()
		fixtureSourceGit(t, root, "add", "-A")
		fixtureSourceGit(t, root, "-c", "commit.gpgsign=false", "commit", "-qm", "producer roster")
	}
	check := func(trusted bool, expected ...string) {
		t.Helper()
		actual, err := distributionProducerInputs(root, trusted)
		if err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("producer roster = %q, %v; want %q", actual, err, expected)
		}
	}
	const producer = "cmd/internal/ci/main.go"
	const overlay = "scripts/ci/cronet_windows_overlay.py"
	const publisher = "scripts/ci/github_release.py"
	const index = "scripts/ci/native_release_index.py"
	const identity = "scripts/ci/release_identity.py"
	const tls = "scripts/ci/tls_fingerprint_probe.py"
	for _, name := range []string{producer, "cmd/internal/ci/main_test.go", "cmd/internal/ci/sub/nested.go", overlay, publisher, index, identity, tls} {
		fixtureFile(t, root, name, "committed producer fixture\n")
	}
	commit()
	check(true, producer, index, overlay, publisher, tls, nativeIndexSchema)
	check(false, producer, index, overlay, publisher)

	fixtureSourceGit(t, root, "rm", "--", overlay, publisher)
	commit()
	check(true, producer, index, identity, tls, nativeIndexSchema)

	fixtureSourceGit(t, root, "rm", "--", identity)
	commit()
	if _, err := distributionProducerInputs(root, true); err == nil {
		t.Fatal("accepted a partial historical Python roster")
	}

	fixtureSourceGit(t, root, "rm", "--", index, tls)
	commit()
	for _, name := range []string{overlay, publisher, index, identity, tls, "cmd/internal/ci/untracked.go"} {
		fixtureFile(t, root, name, "untracked producer fixture\n")
	}
	check(true, producer, nativeIndexSchema)
	check(false, producer)
}

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
	material, err := distributionMaterials(document, root, downloadOwnedReplacement)
	if err != nil {
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

func TestNativeCollectorBindsExactSourceBeforeProductWork(t *testing.T) {
	root := t.TempDir()
	modules := map[string]string{
		"go.mod": "module example.org/kernel\n\ngo 1.27.4\n" +
			"replace example.org/local => ./third_party/local\nreplace example.org/remote => example.org/fork v1.1.0\n",
		"go.sum": "example.org/dependency v1.0.0 h1:baseline\n",
	}
	for name, contents := range modules {
		fixtureFile(t, root, name, contents)
	}
	fixtureFile(t, root, "third_party/local/source", "pinned replacement")
	fixtureSourceGit(t, root, "init", "-q")
	fixtureSourceGit(t, root, "config", "core.autocrlf", "false")
	fixtureSourceGit(t, root, "add", ".")
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "native source")
	source := fixtureSourceGit(t, root, "rev-parse", "HEAD")
	tree := fixtureSourceGit(t, root, "rev-parse", "HEAD^{tree}")
	replacement := fixtureSourceGit(t, root, "rev-parse", "HEAD:third_party/local")
	t.Setenv("GITHUB_SHA", source)
	t.Setenv("GITHUB_REPOSITORY_ID", repositoryID)
	t.Setenv("GITHUB_REPOSITORY", "other/repository")
	args := []string{"cronet-overlay", "--source-root", root, "--native-source-identity"}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "wrong producer repository") {
		t.Fatalf("collector did not reject the repository before validating the overlay: %v", err)
	}
	t.Setenv("GITHUB_REPOSITORY", repository)
	if err := run(args); err == nil || !strings.Contains(err.Error(), "Cronet Windows overlay") {
		t.Fatalf("collector did not reject the overlay before product work: %v", err)
	}
	fixtureCronetOverlay(t, root)
	got, err := nativeCollectorSource(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"sourceCommit": source, "sourceTree": tree,
		"sourceIdentity": map[string]any{
			"sourceOverlay": 0, "goModSha256": sha256Hex([]byte(modules["go.mod"])), "goSumSha256": sha256Hex([]byte(modules["go.sum"])),
			"replacements": []nativeLocalReplacement{{"example.org/local", "./third_party/local", replacement}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collector's exact source identity differs: %v", got)
	}
	for _, module := range nativeSourceModules {
		original := modules[module.name]
		for _, changed := range []string{strings.ReplaceAll(original, "\n", "\r\n"), original + "\x00", original[:len(original)-1], "X" + original[1:]} {
			fixtureFile(t, root, module.name, changed)
			raw, _, err := nativeSourceModuleBytes(root, source)
			if raw != nil || err == nil || !strings.Contains(err.Error(), module.name+" working-tree bytes differ") {
				t.Fatalf("changed %s became available for parsing: %v", module.name, err)
			}
		}
		fixtureFile(t, root, module.name, original)
	}
}

func TestNativeAssemblyBindsArchivedModuleBytesAndPreservesPreviousOutput(t *testing.T) {
	root, destination, stage := t.TempDir(), t.TempDir(), t.TempDir()
	modules := map[string]string{"go.mod": "module example.org/kernel\n\ngo 1.27.4\n", "go.sum": "example.org/dependency v1.0.0 h1:baseline\n"}
	identity := make(map[string]any)
	expected := make(map[string]string)
	for _, module := range nativeSourceModules {
		fixtureFile(t, root, module.name, modules[module.name])
		expected[module.field] = sha256Hex([]byte(modules[module.name]))
		identity[module.field] = expected[module.field]
	}
	fixtureSourceGit(t, root, "init", "-q")
	fixtureSourceGit(t, root, "config", "core.autocrlf", "false")
	fixtureSourceGit(t, root, "add", "go.mod", "go.sum")
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
	source := fixtureSourceGit(t, root, "rev-parse", "HEAD")
	prefix := "sing-box-polaris-source-" + source
	var platforms []any
	for i := range 5 {
		platforms = append(platforms, map[string]any{"id": fmt.Sprint(i), "sourceIdentity": identity})
	}
	record, err := stageNativeSourceArchive(t.Context(), root, stage, source, platforms)
	if err != nil {
		t.Fatal(err)
	}
	filename := record["name"].(string)
	file, err := os.ReadFile(filepath.Join(stage, filename))
	if err != nil {
		t.Fatal(err)
	}
	if record["sha256"] != sha256Hex(file) || record["bytes"] != json.Number(fmt.Sprint(len(file))) {
		t.Fatal("source index does not identify the compressed bytes")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(compressed)
	compressed.Close()
	if err != nil {
		t.Fatal(err)
	}
	want, err := git(root, "archive", "--format=tar", "--prefix="+prefix+"/", source)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("staged gzip changed the committed tar stream: %v", err)
	}
	fixtureFile(t, stage, publisherIndexFile, "assembled")
	if err := installNativeIndex(stage, destination, filename); err != nil {
		t.Fatal(err)
	}

	for i, item := range platforms {
		row := item.(map[string]any)
		for _, key := range []string{"goModSha256", "goSumSha256", ""} {
			changed := map[string]any{"goModSha256": identity["goModSha256"], "goSumSha256": identity["goSumSha256"]}
			if key == "" {
				delete(row, "sourceIdentity")
			} else {
				changed[key] = strings.Repeat("0", 64)
				row["sourceIdentity"] = changed
			}
			if _, err := stageNativeSourceArchive(t.Context(), root, stage, source, platforms); err == nil ||
				!strings.Contains(err.Error(), "native row module identity differs") {
				t.Fatalf("row %d accepted changed/missing %s: %v", i, key, err)
			}
			row["sourceIdentity"] = identity
			retained, err := os.ReadFile(filepath.Join(destination, filename))
			if err != nil || !bytes.Equal(file, retained) {
				t.Fatalf("failed assembly changed the previously issued archive: %v", err)
			}
		}
	}
	for _, module := range nativeSourceModules {
		for _, change := range []string{strings.ReplaceAll(modules[module.name], "\n", "\r\n"), modules[module.name] + "\x00"} {
			var fixture bytes.Buffer
			z := gzip.NewWriter(&fixture)
			archive := tar.NewWriter(z)
			for _, entry := range nativeSourceModules {
				data := modules[entry.name]
				if entry.name == module.name {
					data = change
				}
				if err := archive.WriteHeader(&tar.Header{Name: prefix + "/" + entry.name, Mode: 0o644, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(archive, data); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			err := validateNativeSourceArchive(&fixture, prefix, platforms, expected)
			if err == nil || !strings.Contains(err.Error(), "archived module bytes differ") {
				t.Fatalf("changed archived %s accepted: %v", module.name, err)
			}
		}
	}
	fixtureFile(t, stage, filename, "replacement")
	if err := installNativeIndex(stage, destination, filename); err == nil {
		t.Fatal("a missing staged index was reported as assembled")
	}
	retained, err := os.ReadFile(filepath.Join(destination, filename))
	if err != nil || !bytes.Equal(file, retained) {
		t.Fatalf("index install failure failed to restore the previous archive: %v", err)
	}
}

func TestNativeAssemblyChecksOverlayBeforeReadingReleaseEvidence(t *testing.T) {
	root := t.TempDir()
	fixtureFile(t, root, "README", "checked out")
	fixtureSourceGit(t, root, "init", "-q")
	fixtureSourceGit(t, root, "add", ".")
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
	t.Setenv("GITHUB_REPOSITORY", repository)
	t.Setenv("GITHUB_REPOSITORY_ID", repositoryID)
	t.Setenv("GITHUB_SHA", fixtureSourceGit(t, root, "rev-parse", "HEAD"))
	err := assembleNativeIndex(t.Context(), root, filepath.Join(root, "absent"), nativeIndexSchema, func(path string, _ any) error {
		t.Fatalf("invalid checkout reached GitHub: %s", path)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "Cronet Windows overlay") {
		t.Fatalf("assembly did not reject the overlay before release/artifact work: %v", err)
	}
}

func TestNativeSmokeChecksOverlayBeforeReadingReleaseEvidence(t *testing.T) {
	root := t.TempDir()
	err := smokeNativeIndex(t.Context(), root, []string{filepath.Join(root, "absent")})
	if err == nil || !strings.Contains(err.Error(), "Cronet Windows overlay") {
		t.Fatalf("smoke did not reject the overlay before artifact work: %v", err)
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

func TestPeerMetadataFailureWritesControlledPeerReceipt(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	directory := t.TempDir()
	admission := filepath.Join(directory, "private", "admission.json")
	output := filepath.Join(directory, "public", "receipt.json")
	args := []string{"--mode", "acquire", "--native", directory, "--admission", admission, "--failure", output}
	if err := peerMetadata(args); err == nil || !strings.Contains(err.Error(), "approved repository") {
		t.Fatalf("unexpected acquisition result: %v", err)
	}
	if _, err := os.Stat(admission); !os.IsNotExist(err) {
		t.Fatalf("failed acquisition produced admission: %v", err)
	}
	var schedule []map[string]any
	if err := json.Unmarshal(peerCaseSchedule, &schedule); err != nil {
		t.Fatal(err)
	}
	for _, item := range schedule {
		item["status"], item["reason"] = "NOT_RUN", "artifact_metadata_admission_failed"
	}
	var receipt map[string]any
	if err := readNativeSourceJSON(filepath.Dir(output), filepath.Base(output), &receipt); err != nil {
		t.Fatal(err)
	}
	cases := make([]any, len(schedule))
	for i, item := range schedule {
		cases[i] = item
	}
	expected := map[string]any{
		"schema": "polaris-native-controlled-peer-v1", "status": "FAIL", "stage": "artifact_metadata_admission",
		"publicationEligible": false, "cases": cases, "context": map[string]any{}, "metadataReads": []any{},
		"errorType": "MetadataError", "error": "metadata admission requires Linux Actions in the approved repository",
	}
	if !reflect.DeepEqual(receipt, expected) {
		t.Fatalf("controlled peer receipt differs: %#v", receipt)
	}
}
