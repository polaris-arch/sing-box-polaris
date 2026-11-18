package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(tests *testing.M) {
	mode := os.Getenv("POLARIS_CI_TEST_GH_MODE")
	if mode == "" || !strings.HasPrefix(filepath.Base(os.Args[0]), "gh") {
		os.Exit(tests.Run())
	}
	if mode == "publisher" {
		os.Exit(publisherFixtureGitHub())
	}
	// Exercise the actual subprocess/pipes without network access or a Python fixture.
	if mode == "tls" {
		if len(os.Args) == 3 && slices.Equal(os.Args[1:], []string{"tools", "tls-fingerprints"}) {
			fmt.Fprint(os.Stdout, os.Getenv("POLARIS_CI_TEST_TLS_DOCUMENT"))
			os.Exit(0)
		}
		if len(os.Args) != 4 || os.Args[1] != "check" || os.Args[2] != "-c" {
			os.Exit(2)
		}
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			os.Exit(3)
		}
		var configuration map[string]any
		if err := json.Unmarshal(data, &configuration); err != nil {
			os.Exit(3)
		}
		outbound := configuration["outbounds"].([]any)[0].(map[string]any)
		settings := outbound["tls"].(map[string]any)["utls"].(map[string]any)
		if settings["enabled"] == true {
			fmt.Fprint(os.Stderr, "stub uTLS unavailable")
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) != 6 || !slices.Equal(os.Args[1:5], []string{"api", "--include", "--method", "GET"}) {
		os.Exit(2)
	}
	if mode == "peer" {
		key := "POLARIS_CI_TEST_PEER_RUN"
		if strings.HasSuffix(os.Args[5], "/artifacts?per_page=100&page=1") {
			key = "POLARIS_CI_TEST_PEER_ARTIFACTS"
		} else if !strings.HasSuffix(os.Args[5], "/actions/runs/123") {
			os.Exit(4)
		}
		fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\nX-GitHub-Request-Id: fixture\r\n\r\n", os.Getenv(key))
		os.Exit(0)
	}
	if mode == "release-tag" {
		key := "POLARIS_CI_TEST_TAG_OBJECT"
		if strings.Contains(os.Args[5], "/git/ref/tags/") {
			key = "POLARIS_CI_TEST_TAG_REF"
		}
		fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\n\r\n", os.Getenv(key))
		os.Exit(0)
	}
	if mode == "idle" {
		os.Stdout.Close()
		os.Stderr.Close()
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if mode == "retry" {
		counter := os.Getenv("POLARIS_CI_TEST_GH_COUNTER")
		if _, err := os.Stat(counter); os.IsNotExist(err) {
			if err := os.WriteFile(counter, []byte("first"), 0o600); err != nil {
				os.Exit(3)
			}
			delay := os.Getenv("POLARIS_CI_TEST_GH_RETRY_AFTER")
			if delay == "" {
				delay = "0"
			}
			fmt.Fprintf(os.Stdout, "HTTP/2 503 unavailable\r\nRetry-After: %s\r\n\r\nsecret", delay)
			os.Exit(1)
		}
		mode = "success"
	}
	if strings.HasPrefix(mode, "status-") {
		fmt.Fprintf(os.Stdout, "HTTP/2 %s error\r\nRetry-After: 0\r\n\r\nsecret", strings.TrimPrefix(mode, "status-"))
		os.Exit(1)
	}
	if mode == "malformed" {
		fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\nRetry-After: 1\r\nRetry-After: 2\r\n\r\nbody")
		os.Exit(0)
	}
	if mode == "stderr-flood" {
		fmt.Fprint(os.Stderr, strings.Repeat("secret", 50000))
	}
	fmt.Fprint(os.Stdout, "HTTP/2 200 OK\r\nLocation: https://secret.invalid/?sig=secret\r\nX-GitHub-Request-Id: safe\r\n\r\nhello")
	os.Exit(0)
}

func fixtureSourceCLI(t *testing.T) string {
	t.Helper()
	// A copied race test binary is the child fixture, so avoid the race
	// runtime's default one-second delay before its successful exit.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "gh"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	filename := filepath.Join(t.TempDir(), name)
	if err := os.Link(executable, filename); err != nil {
		source, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		target, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(target, source)
		if err := errors.Join(copyErr, target.Close()); err != nil {
			t.Fatal(err)
		}
	}
	return filename
}

func fixtureTLSCapabilities(version, source, goVersion string) map[string]any {
	return map[string]any{
		"schema":      "polaris-tls-fingerprint-capabilities-v1",
		"coreVersion": version, "sourceCommit": source, "goVersion": goVersion, "requiredGoVersion": goVersion,
		"buildTags": "stub", "os": runtime.GOOS, "arch": runtime.GOARCH,
		"enabled": false, "sourceModified": false, "defaultFingerprint": "chrome",
		"randomSemantics": "process browser selection", "randomizedSemantics": "process seeded generator",
		"realityX25519MLKEM768": "offer only", "negotiationEvidence": "runtime handshake is separate",
		"shadowTLSSessionIDWithECHSupported": false, "curvePreferencesSupported": false,
		"modules": []any{}, "profiles": []any{}, "legacyChromeAliases": []any{},
	}
}

func TestSourceCommandBoundsRetirementAndRealTestExecution(t *testing.T) {
	child := fixtureSourceCLI(t)
	args := []string{child, "api", "--include", "--method", "GET", "repos/polaris-arch/sing-box-polaris"}
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "success")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	stdout, _, code, err := sourceCommandOutput(ctx, "", nil, 4096, args...)
	cancel()
	if err != nil || code == nil || *code != 0 || !strings.HasSuffix(stdout, "hello") {
		t.Fatalf("owned child failed: %v, %v", code, err)
	}
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "stderr-flood")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, stderr, _, err := sourceCommandOutput(ctx, "", nil, 4096, args...)
	cancel()
	if err == nil || len(stderr) > 4096 || !strings.Contains(err.Error(), "byte bound") {
		t.Fatalf("diagnostic flood admitted: %d, %v", len(stderr), err)
	}
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "idle")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	code, err = runSourceProcess(ctx, command)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || code != nil || command.ProcessState == nil {
		t.Fatalf("idle child was not retired: %v, %v", code, err)
	}
	logfile := filepath.Join(t.TempDir(), "tests.jsonl")
	for _, record := range []struct {
		data  string
		valid bool
	}{
		{"unframed diagnostic\n{\"Action\":\"pass\",\"Test\":\"TestOwned\"}\n", true},
		{"", false},
		{"{\"Action\":\"pass\",\"Test\":\"AnotherTest\"}\n", false},
		{"{\"Action\":\"pass\",\"Test\":\"TestOwned\"}\n{\"Action\":\"skip\",\"Test\":\"TestOwned\"}\n", false},
	} {
		if err := os.WriteFile(logfile, []byte(record.data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := requireSourceTests(logfile, []string{"TestOwned"}); (err == nil) != record.valid {
			t.Fatalf("terminal test execution differs: %v", err)
		}
	}
}

func TestSourceInputReceiptsAndIncompleteCostCannotClaimMeasurements(t *testing.T) {
	root := moduleFixture(t)
	fixtureSourceGit(t, root, "init", "-q")
	fixtureSourceGit(t, root, "add", ".")
	fixtureSourceGit(t, root, "commit", "-qm", "source input fixture")
	source := fixtureSourceGit(t, root, "rev-parse", "HEAD")
	for key, value := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": repository, "GITHUB_REPOSITORY_ID": repositoryID,
		"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_JOB": "utls_gate", "GITHUB_SHA": source,
		"GITHUB_RUN_ID": "99999999999999999999", "GITHUB_RUN_ATTEMPT": "1",
		"SOURCE_BUILD": "Source", "SOURCE_GENERATE_ONLY": "false", "SOURCE_RUNNER": "fixture",
		"RUNNER_TEMP": t.TempDir(), "RUNNER_OS": "Linux",
	} {
		t.Setenv(key, value)
	}
	t.Setenv("TMPDIR", os.Getenv("TMPDIR"))
	for _, changed := range []struct{ key, value string }{
		{"GITHUB_RUN_ID", "0"}, {"SOURCE_BUILD", "Binary"}, {"SOURCE_GENERATE_ONLY", "true"}, {"GITHUB_JOB", "other"}, {"GITHUB_REPOSITORY_ID", "1"},
	} {
		t.Run(changed.key, func(t *testing.T) {
			t.Setenv(changed.key, changed.value)
			if _, err := sourceGateContext(); err == nil {
				t.Fatal("unowned Source observation admitted")
			}
		})
	}
	if _, err := sourceGateContext(); err != nil {
		t.Fatal(err)
	}
	read := func(filename string) map[string]any {
		t.Helper()
		file, err := os.Open(filename)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		var value map[string]any
		if err := uniqueJSON(file, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	output := t.TempDir()
	if err := retainSourceInput(root, output); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(output, "source-ci-input.json")
	actual := read(filename)
	if actual["runId"] != json.Number("99999999999999999999") || actual["checkoutIdentityVerified"] != true || actual["testOrNativePASS"] != false || actual["measurementsComplete"] != false {
		t.Fatalf("input receipt changed authority or number identity: %v", actual)
	}
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := retainSourceInput(root, output); err == nil {
		t.Fatal("exclusive input receipt overwritten")
	}
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("retained source receipt changed: %v", err)
	}
	fixtureFile(t, root, "untracked-input", "dirty")
	failed := t.TempDir()
	if err := retainSourceInput(root, failed); err == nil {
		t.Fatal("dirty Source checkout admitted")
	}
	actual = read(filepath.Join(failed, "source-ci-input.json"))
	if actual["checkoutIdentityVerified"] != false || actual["error"] == nil {
		t.Fatalf("failed source identity not retained: %v", actual)
	}
	if runtime.GOOS == "linux" {
		cost := t.TempDir()
		if err := measureTLSCost(root, cost); err == nil {
			t.Fatal("dirty source reached cost measurement")
		}
		actual = read(filepath.Join(cost, "cost.json"))
		if actual["measurementsComplete"] != false || actual["status"] != "incomplete" || actual["delta"] != nil || actual["baselineWorktreeRetired"] != false {
			t.Fatalf("incomplete observation claimed a measurement: %v", actual)
		}
	} else if err := measureTLSCost(root, t.TempDir()); err == nil || !strings.Contains(err.Error(), "restricted to the existing owned Linux CI job") {
		t.Fatalf("non-Linux cost observation admitted: %v", err)
	}
}

func TestSourceCostRetiresOnlyItsOwnedWorkspaceAndReportsDebt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cost workspaces are only created by the Linux Source observation")
	}
	for _, kind := range []string{"clean", "dirty", "partial", "foreign-file"} {
		t.Run(kind, func(t *testing.T) {
			root := moduleFixture(t)
			fixtureSourceGit(t, root, "init", "-q")
			fixtureSourceGit(t, root, "add", ".")
			fixtureSourceGit(t, root, "commit", "-qm", "baseline fixture")
			owner, err := os.MkdirTemp(t.TempDir(), "cost-owner-")
			if err != nil {
				t.Fatal(err)
			}
			slot := filepath.Join(owner, "baseline")
			if kind == "partial" {
				if err := os.Mkdir(slot, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				fixtureSourceGit(t, root, "worktree", "add", "--detach", slot, "HEAD")
			}
			if kind == "dirty" {
				fixtureFile(t, slot, "untracked", "preserve")
			}
			if kind == "foreign-file" {
				fixtureFile(t, owner, "foreign", "preserve")
			}
			err = retireTLSWorkspace(root, owner, slot, nil)
			if (err == nil) != (kind == "clean") {
				t.Fatalf("%s retirement result differs: %v", kind, err)
			}
			if kind == "clean" {
				if _, err := os.Stat(owner); !os.IsNotExist(err) {
					t.Fatalf("owned workspace retained after success: %v", err)
				}
			} else {
				if _, err := os.Stat(owner); err != nil {
					t.Fatalf("cleanup debt path lost: %v", err)
				}
				if kind == "dirty" {
					data, err := os.ReadFile(filepath.Join(slot, "untracked"))
					if err != nil || string(data) != "preserve" {
						t.Fatalf("unowned bytes removed: %v", err)
					}
				}
				if kind == "foreign-file" {
					data, err := os.ReadFile(filepath.Join(owner, "foreign"))
					if err != nil || string(data) != "preserve" {
						t.Fatalf("unknown owner bytes removed: %v", err)
					}
				}
			}
		})
	}
}

func TestTLSRuntimeCapabilityAdmission(t *testing.T) {
	root := "../../.."
	pin, err := os.ReadFile(filepath.Join(root, "release/GO_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version, source, goVersion := "1.15.0-polaris-alpha.12", strings.Repeat("a", 40), "go"+strings.TrimSpace(string(pin))
	document := func() map[string]any { return fixtureTLSCapabilities(version, source, goVersion) }
	check := func(value map[string]any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = validateTLSCapabilities(root, raw, source, version, goVersion, runtime.GOOS+"/"+runtime.GOARCH, false)
		return err
	}
	if err := check(document()); err != nil {
		t.Fatalf("valid stub rejected: %v", err)
	}
	for _, change := range []func(map[string]any){
		func(value map[string]any) { value["sourceModified"] = nil },
		func(value map[string]any) { value["sourceModified"] = true },
		func(value map[string]any) { value["sourceModified"] = "false" },
		func(value map[string]any) { value["sourceCommit"] = strings.Repeat("b", 40) },
		func(value map[string]any) { value["legacyChromeAliases"] = []string{"chrome_133"} },
	} {
		value := document()
		change(value)
		if err := check(value); err == nil {
			t.Fatalf("invalid runtime binding admitted: %v", value)
		}
	}
	if modules, err := linkedTLSModules(root); err != nil || modules[metaModule].Replace == nil {
		t.Fatalf("source-owned linked module identities differ: %v, %v", modules, err)
	}
}

func TestTLSRuntimeProbeOwnsQueryControlsAndFailureEvidence(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(root, "release/GO_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	version, source, goVersion := tlsGateVersion, strings.Repeat("a", 40), "go"+strings.TrimSpace(string(pin))
	document := fixtureTLSCapabilities(version, source, goVersion)
	child := fixtureSourceCLI(t)
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "tls")
	publish := func() {
		t.Helper()
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("POLARIS_CI_TEST_TLS_DOCUMENT", string(raw))
	}
	publish()
	probe := func() (map[string]any, error) {
		return probeTLSRuntime(context.Background(), root, child, nil, source, version, goVersion, runtime.GOOS+"/"+runtime.GOARCH, false)
	}
	receipt, err := probe()
	if err != nil {
		t.Fatal(err)
	}
	if receipt["networkHandshakeValidated"] != false || receipt["coreSHA256"] == "" {
		t.Fatalf("probe scope or identity changed: %v", receipt)
	}
	admitted := false
	for _, observation := range receipt["configurationChecks"].([]map[string]any) {
		if observation["expectedPass"] == true {
			if observation["enabled"] != false || observation["exitCode"] != 0 {
				t.Fatalf("stub admitted enabled uTLS: %v", observation)
			}
			admitted = true
		}
	}
	if !admitted {
		t.Fatal("disabled uTLS control was not executed")
	}
	query := child + "-capability-query.json"
	if _, err := os.Stat(query); err != nil {
		t.Fatal("original capability query missing")
	}
	document["sourceModified"] = nil
	publish()
	if _, err := probe(); err == nil {
		t.Fatal("nullable source identity entered actual runtime controls")
	}
	document["sourceModified"] = false
	publish()
	if err := os.Remove(query); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(query, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := probe(); err == nil {
		t.Fatal("probe succeeded without retaining its original query")
	}
}

func fixtureSourceGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	output, err := git(root, append([]string{"-c", "user.name=Source fixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func fixtureVisionSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	original, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", ".gitattributes", visionBinding, "release/dependency-sources/sing-vmess-vision.patch", "release/licenses/CURRENT44-NOTICE-CANDIDATE.txt"} {
		data, err := os.ReadFile(filepath.Join(original, name))
		if err != nil {
			t.Fatal(err)
		}
		fixtureFile(t, root, name, string(data))
	}
	nested := filepath.Join(root, "third_party/sing-vmess")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(nested, os.DirFS(filepath.Join(original, "third_party/sing-vmess"))); err != nil {
		t.Fatal(err)
	}
	fixtureSourceGit(t, root, "init", "-q")
	fixtureSourceGit(t, root, "config", "core.autocrlf", "false")
	fixtureSourceGit(t, root, "add", "--all")
	fixtureSourceGit(t, root, "update-index", "--chmod=+x", "third_party/sing-vmess/.github/update_dependencies.sh")
	fixtureSourceGit(t, root, "commit", "-qm", "exact source fixture")
	return root
}

func TestVisionSourceByteModeAndCheckoutBoundaries(t *testing.T) {
	for _, kind := range []string{"valid", "bytes", "mode", "extra", "missing", "link", "root-replace", "provider-version", "patch", "notice", "tree", "crlf", "old-attributes"} {
		t.Run(kind, func(t *testing.T) {
			root := fixtureVisionSource(t)
			target := filepath.Join(root, "third_party/sing-vmess/vless/vision.go")
			replace := func(name, old, new string) {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), old) {
					t.Fatalf("fixture input missing: %s", old)
				}
				fixtureFile(t, root, name, strings.ReplaceAll(string(data), old, new))
			}
			switch kind {
			case "bytes":
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, append(data, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if runtime.GOOS == "windows" {
					fixtureSourceGit(t, root, "update-index", "--chmod=+x", "third_party/sing-vmess/vless/vision.go")
				} else if err := os.Chmod(target, 0o755); err != nil {
					t.Fatal(err)
				}
			case "extra":
				fixtureFile(t, root, "third_party/sing-vmess/foreign.go", "package vmess\n")
			case "missing":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			case "link":
				if runtime.GOOS == "windows" {
					// A private junction exercises real reparse metadata without symlink privileges.
					directory := filepath.Dir(target)
					foreign := filepath.Join(t.TempDir(), "provider-files")
					if err := os.Rename(directory, foreign); err != nil {
						t.Fatal(err)
					}
					if output, err := exec.Command("cmd", "/c", "mklink", "/J", directory, foreign).CombinedOutput(); err != nil {
						t.Fatalf("private junction: %s: %v", output, err)
					}
				} else {
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
					foreign := filepath.Join(t.TempDir(), "vision.go")
					fixtureFile(t, filepath.Dir(foreign), filepath.Base(foreign), "package vless\n")
					if err := os.Symlink(foreign, target); err != nil {
						t.Fatal(err)
					}
				}
			case "root-replace":
				replace("go.mod", "=> ./third_party/sing-vmess", "=> ../foreign")
			case "provider-version":
				replace("go.mod", refractionVersion, "v0.0.1")
			case "patch":
				fixtureFile(t, root, "release/dependency-sources/sing-vmess-vision.patch", "different patch")
			case "notice":
				fixtureFile(t, root, "release/licenses/CURRENT44-NOTICE-CANDIDATE.txt", "different notice")
			case "tree":
				replace(visionBinding, `"replacementTree": "c06c20c35da9997e56b5f6169143e3c0261da672"`, `"replacementTree": "0000000000000000000000000000000000000000"`)
			}
			if kind == "crlf" || kind == "old-attributes" {
				if kind == "old-attributes" {
					attributes, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
					if err != nil {
						t.Fatal(err)
					}
					marker := bytes.Index(attributes, []byte("# Source-owned Vision closure"))
					if marker < 0 {
						t.Fatal("Vision attribute section missing")
					}
					fixtureFile(t, root, ".gitattributes", string(attributes[:marker]))
					fixtureSourceGit(t, root, "add", ".gitattributes")
					fixtureSourceGit(t, root, "commit", "-qm", "old checkout attributes")
				}
				fixtureSourceGit(t, root, "config", "core.autocrlf", "true")
				paths := []string{"third_party/sing-vmess", visionBinding, "release/dependency-sources/sing-vmess-vision.patch", "release/licenses/CURRENT44-NOTICE-CANDIDATE.txt"}
				for _, name := range paths {
					if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
						t.Fatal(err)
					}
				}
				fixtureSourceGit(t, root, append([]string{"checkout", "HEAD", "--"}, paths...)...)
				if kind == "old-attributes" {
					data, err := os.ReadFile(target)
					if err != nil || !bytes.Contains(data, []byte("\r\n")) {
						t.Fatalf("old attribute fixture did not produce CRLF: %v", err)
					}
				}
			}
			diagnostics := map[string]any{}
			actual, err := validateVisionSource(root, diagnostics)
			if good := kind == "valid" || kind == "crlf"; (err == nil) != good {
				t.Fatalf("Vision %s boundary differs: %v", kind, err)
			}
			if err == nil && actual["replacementTree"] != "c06c20c35da9997e56b5f6169143e3c0261da672" {
				t.Fatalf("raw checkout tree changed: %v", actual)
			}
		})
	}
}

func TestVisionGitInventoryAndTrustedExecutableMetadata(t *testing.T) {
	for _, kind := range []string{"valid", "index-mode", "index-blob", "unmerged", "head-index-tamper", "missing-git"} {
		t.Run(kind, func(t *testing.T) {
			root := fixtureVisionSource(t)
			path := "third_party/sing-vmess/vless/vision.go"
			switch kind {
			case "index-mode":
				fixtureSourceGit(t, root, "update-index", "--chmod=-x", "third_party/sing-vmess/.github/update_dependencies.sh")
			case "index-blob", "head-index-tamper":
				data, err := os.ReadFile(filepath.Join(root, path))
				if err != nil {
					t.Fatal(err)
				}
				fixtureFile(t, root, path, string(data)+"\n")
				fixtureSourceGit(t, root, "add", path)
				if kind == "head-index-tamper" {
					fixtureSourceGit(t, root, "commit", "-qm", "changed source")
				}
			case "unmerged":
				blob := fixtureSourceGit(t, root, "rev-parse", "HEAD:"+path)
				fixtureSourceGit(t, root, "update-index", "--force-remove", path)
				command := exec.Command("git", "update-index", "--index-info")
				command.Dir = root
				command.Stdin = strings.NewReader("100644 " + blob + " 1\t" + path + "\n")
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("index stage fixture: %v: %s", err, output)
				}
			case "missing-git":
				if err := os.Rename(filepath.Join(root, ".git"), filepath.Join(root, "disabled-git-metadata")); err != nil {
					t.Fatal(err)
				}
			}
			diagnostics := map[string]any{}
			_, err := visionGitInventory(root, diagnostics)
			good := kind == "valid" || kind == "head-index-tamper"
			if (err == nil) != good {
				t.Fatalf("Git inventory %s boundary differs: %v", kind, err)
			}
			if runtime.GOOS == "windows" {
				if kind == "valid" {
					executable := filepath.Join(root, "third_party/sing-vmess/.github/update_dependencies.sh")
					if err := os.Chmod(executable, 0o644); err != nil {
						t.Fatal(err)
					}
					if _, err := validateVisionSource(root, map[string]any{}); err != nil {
						t.Fatalf("trusted executable Git mode rejected: %v", err)
					}
				} else {
					full := map[string]any{}
					if _, err := validateVisionSource(root, full); err == nil {
						t.Fatal("invalid Windows source metadata admitted")
					}
					if kind == "unmerged" && (full["actualTree"] != nil || full["treeUnavailableReason"] == nil || full["invalidGitEntry"] == nil) {
						t.Fatalf("invalid executable metadata claimed a tree: %v", full)
					}
				}
			}
		})
	}
}

func TestGitHubReadOwnsStreamsErrorsAndRetryBudget(t *testing.T) {
	child := fixtureSourceCLI(t)
	directory := filepath.Dir(child)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	path := "repos/polaris-arch/sing-box-polaris/actions/artifacts/31/zip"
	for _, mode := range []string{"success", "stderr-flood", "malformed", "idle", "status-400", "status-403", "status-404", "status-429", "status-500", "status-503"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("POLARIS_CI_TEST_GH_MODE", mode)
			sink, err := os.CreateTemp(t.TempDir(), "body")
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			result, err := githubAttempt(context.Background(), path, sink, 10, 2*time.Second)
			good := mode == "success" || mode == "stderr-flood"
			if (err == nil) != good {
				t.Fatalf("%s: %v", mode, err)
			}
			if good {
				encoded, err := json.Marshal(result)
				if err != nil || strings.Contains(string(encoded), "secret") {
					t.Fatalf("private response headers retained: %s, %v", encoded, err)
				}
				if result.Bytes != 5 || result.SHA256 != sha256Hex([]byte("hello")) || result.Headers["x-github-request-id"] != "safe" {
					t.Fatalf("stream identity differs: %+v", result)
				}
			} else {
				var failure *readFailure
				if !errors.As(err, &failure) || failure.Cleanup || strings.Contains(err.Error(), "secret") {
					t.Fatalf("unsafe or unreaped failure: %v", err)
				}
				if strings.HasPrefix(mode, "status-") {
					status, _ := strconv.Atoi(strings.TrimPrefix(mode, "status-"))
					if failure.Retryable != retryStatus(status) || result.Bytes != 0 {
						t.Fatalf("HTTP failure retained bytes or changed retry class: %+v", result)
					}
				}
			}
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		t.Setenv("POLARIS_CI_TEST_GH_MODE", "idle")
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if _, err := githubAttempt(ctx, path, io.Discard, 10, 6*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancelled transport failure differs: %v", err)
		}
	})
	if _, err := retryDelay(map[string]string{"retry-after": "Mon, 01 Jan 2001 00:00:00 -0000"}, 1, time.Now()); err == nil {
		t.Fatal("Retry-After with unspecified time zone admitted")
	}

	t.Setenv("POLARIS_CI_TEST_GH_MODE", "success")
	sink, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	sink.Close()
	if _, err := githubAttempt(context.Background(), path, sink, 10, 2*time.Second); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("primary sink error lost: %v", err)
	}
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "retry")
	t.Setenv("POLARIS_CI_TEST_GH_COUNTER", filepath.Join(directory, "attempt"))
	sink, err = os.CreateTemp(t.TempDir(), "retry")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if _, err := sink.WriteString("old"); err != nil {
		t.Fatal(err)
	}
	budget := retryBudget{}
	result, err := readGitHub(path, sink, 10, &budget, readLimits{2 * time.Second, 6 * time.Second, time.Second}, nil)
	if err != nil || budget.ExtraGETs != 1 || result.SHA256 != sha256Hex([]byte("hello")) {
		t.Fatalf("retry body/hash/budget differs: %+v, %v", result, err)
	}
	if _, err := sink.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(sink)
	if err != nil || string(body) != "hello" {
		t.Fatalf("partial body survived retry: %q, %v", body, err)
	}
	budget = retryBudget{}
	for round := 1; round <= 9; round++ {
		t.Setenv("POLARIS_CI_TEST_GH_COUNTER", filepath.Join(directory, fmt.Sprintf("budget-%d", round)))
		_, err := readGitHub(path, sink, 10, &budget, readLimits{2 * time.Second, 6 * time.Second, time.Second}, nil)
		if round <= 8 && err != nil || round == 9 && (err == nil || !strings.Contains(err.Error(), "HTTP 503")) {
			t.Fatalf("request %d shared budget: %v", round, err)
		}
	}
	if budget.ExtraGETs != 8 {
		t.Fatalf("shared GET budget changed: %v", budget)
	}
	t.Setenv("POLARIS_CI_TEST_GH_COUNTER", filepath.Join(directory, "budget-tag"))
	publisher := publisher{ctx: t.Context(), tag: "v1.15.0-polaris-alpha.12.22", source: strings.Repeat("a", 40), reads: budget}
	if _, err := publisher.currentTag(); err == nil || !strings.Contains(err.Error(), "HTTP 503") || publisher.reads.ExtraGETs != 8 {
		t.Fatalf("tag read escaped the shared GET budget: %v", err)
	}
	t.Setenv("POLARIS_CI_TEST_GH_COUNTER", filepath.Join(directory, "budget-wait"))
	t.Setenv("POLARIS_CI_TEST_GH_RETRY_AFTER", "1")
	budget = retryBudget{Wait: time.Second}
	if _, err := readGitHub(path, sink, 10, &budget, readLimits{2 * time.Second, 6 * time.Second, time.Second}, nil); err == nil ||
		!strings.Contains(err.Error(), "retry budget exhausted") || budget.ExtraGETs != 0 {
		t.Fatalf("retry escaped accumulated wait budget: %v (%+v)", err, budget)
	}
}

func TestPeerAdmissionBindsActualCheckoutAndArtifact(t *testing.T) {
	root := t.TempDir()
	fixtureSourceGit(t, root, "init", "-q")
	fixtureCronetOverlay(t, root)
	const goMod = "module example.org/kernel\n\ngo 1.27.4\n" +
		"replace example.org/a => ./third_party/a\nreplace example.org/b => ./third_party/b\n"
	const goSum = "example.org/dependency v1.0.0 h1:baseline\n"
	fixtureFile(t, root, "go.mod", goMod)
	fixtureFile(t, root, "go.sum", goSum)
	fixtureFile(t, root, "release/GO_VERSION", "1.27.4\n")
	fixtureFile(t, root, "third_party/a/source", "pinned a")
	fixtureFile(t, root, "third_party/b/source", "pinned b")
	fixtureSourceGit(t, root, "config", "core.autocrlf", "false")
	fixtureSourceGit(t, root, "add", ".")
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "peer source")
	source := fixtureSourceGit(t, root, "rev-parse", "HEAD")
	tree := fixtureSourceGit(t, root, "rev-parse", "HEAD^{tree}")
	t.Chdir(root)
	for key, value := range map[string]string{
		"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": repository,
		"GITHUB_REPOSITORY_ID": repositoryID, "GITHUB_EVENT_NAME": "workflow_dispatch",
		"GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
		"GITHUB_REF": "refs/tags/v1.15.0-polaris-alpha.12.31", "GH_TOKEN": "inert-fixture-token",
		"GITHUB_WORKFLOW_REF": repository + "/.github/workflows/build.yml@refs/tags/v1.15.0-polaris-alpha.12.31",
	} {
		t.Setenv(key, value)
	}
	child := fixtureSourceCLI(t)
	t.Setenv("PATH", filepath.Dir(child)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "peer")
	native := t.TempDir()
	rowFile := "native-row-fixture.json"
	const version = "1.15.0-polaris-alpha.12.31"
	identities := []nativeLocalReplacement{
		{"example.org/b", "./third_party/b", fixtureSourceGit(t, root, "rev-parse", "HEAD:third_party/b")},
		{"example.org/a", "./third_party/a", fixtureSourceGit(t, root, "rev-parse", "HEAD:third_party/a")},
	}
	sourceIdentity := map[string]any{
		"sourceOverlay": 0, "goModSha256": sha256Hex([]byte(goMod)), "goSumSha256": sha256Hex([]byte(goSum)), "replacements": identities,
	}
	fields := map[string]any{
		"sourceCommit": source, "sourceTree": tree, "version": version, "tag": "v" + version, "goVersion": "go1.27.4",
		"target": "linux/amd64", "variant": map[string]any{"linkage": "shared-purego"}, "sourceIdentity": sourceIdentity,
	}
	writeRow := func() string {
		t.Helper()
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		fixtureFile(t, native, rowFile, string(data))
		return string(data)
	}
	row := writeRow()
	context := map[string]any{}
	if err := peerLocalContext(root, native, context, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reference := "v1.15.0-polaris-alpha.12.31"
	repo := map[string]any{"id": json.Number(repositoryID), "full_name": repository}
	runRow := map[string]any{
		"id": 123, "run_attempt": 2, "head_sha": source, "head_branch": reference,
		"event": "workflow_dispatch", "path": ".github/workflows/build.yml", "repository": repo, "head_repository": repo,
		"run_started_at": now.Add(-time.Minute).Format(time.RFC3339),
	}
	item := map[string]any{
		"id": 31, "name": peerArtifactName, "digest": "sha256:" + strings.Repeat("0", 64), "size_in_bytes": 5,
		"created_at": now.Add(-time.Second).Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339), "expired": false,
		"workflow_run": map[string]any{
			"id": 123, "repository_id": json.Number(repositoryID),
			"head_repository_id": json.Number(repositoryID), "head_sha": source, "head_branch": reference,
		},
	}
	fixtureReply := func(key string, payload any) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, string(raw))
	}
	fixtureReply("POLARIS_CI_TEST_PEER_RUN", runRow)
	fixtureReply("POLARIS_CI_TEST_PEER_ARTIFACTS", map[string]any{"total_count": 1, "artifacts": []any{item}})
	out := t.TempDir()
	admission := filepath.Join(out, "admission.json")
	failure := filepath.Join(out, "failure.json")
	args := []string{"peer-metadata", "--mode", "acquire", "--native", native, "--admission", admission, "--failure", failure}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	artifact, err := verifyPeerAdmission(admission, context)
	if err != nil || artifact["id"] != json.Number("31") || artifact["digest"] != item["digest"] || len(artifact) != 6 {
		t.Fatalf("exact same-run artifact verification: %v, %v", artifact, err)
	}
	if _, err := os.Stat(failure); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected acquisition failure facts: %v", err)
	}
	t.Setenv("GH_TOKEN", "")
	verify := []string{"peer-metadata", "--mode", "verify", "--native", native, "--admission", admission}
	if err := run(verify); err != nil {
		t.Fatalf("exact source and order-independent replacements were not admitted: %v", err)
	}
	// The credential-free consumer freshly binds the native row's raw bytes.
	fixtureFile(t, native, rowFile, row+"\n")
	if err := run(verify); err == nil || !strings.Contains(err.Error(), "metadata admission context differs") {
		t.Fatalf("changed native row retained metadata authority: %v", err)
	}
	for _, check := range []struct {
		field string
		value any
		error string
	}{
		{"goModSha256", strings.Repeat("0", 64), "producer source module bytes differ"},
		{"goSumSha256", strings.Repeat("0", 64), "producer source module bytes differ"},
		{"sourceOverlay", false, "native producer source module identity differs"},
		{"replacements", identities[:1], "complete source-owned replacement closure missing"},
		{"replacements", []nativeLocalReplacement{identities[0], identities[0]}, "replacement closure differs"},
	} {
		saved := sourceIdentity[check.field]
		sourceIdentity[check.field] = check.value
		writeRow()
		if err := run(verify); err == nil || !strings.Contains(err.Error(), check.error) {
			t.Fatalf("invalid %s reached metadata admission: %v", check.field, err)
		}
		sourceIdentity[check.field] = saved
	}
	fixtureFile(t, native, rowFile, row)
	t.Setenv("GH_TOKEN", "inert-fixture-token")
	for _, item := range []struct {
		name     string
		response map[string]any
	}{
		{"duplicate", map[string]any{"total_count": 2, "artifacts": []any{item, item}}},
		{"incomplete", map[string]any{"total_count": 2, "artifacts": []any{item}}},
	} {
		t.Run(item.name, func(t *testing.T) {
			fixtureReply("POLARIS_CI_TEST_PEER_ARTIFACTS", item.response)
			if _, err := acquirePeerAdmission(context, func(map[string]any) {}); err == nil {
				t.Fatal("unsafe inventory admitted")
			}
		})
	}
}

func TestReleaseDispatchBindsExactVersionAndAnnotatedSource(t *testing.T) {
	const contractFile = "../../../scripts/ci/testdata/polaris-versions.json"
	var versions struct {
		Valid   []string
		Invalid []string
	}
	raw, err := os.ReadFile(contractFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &versions); err != nil {
		t.Fatal(err)
	}
	t.Run("native index version and tag canonicality", func(t *testing.T) {
		const schema = "../../../release/ci/native-release-index.schema.json"
		for _, location := range []string{"/properties", "/properties/platforms/items/properties"} {
			for field, prefix := range map[string]string{"version": "", "tag": "v"} {
				fragment := "#" + location + "/" + field
				for _, version := range versions.Valid {
					if err := validateDocument(schema, fragment, prefix+version); err != nil {
						t.Fatalf("%s rejects %q: %v", fragment, prefix+version, err)
					}
				}
				for _, version := range versions.Invalid {
					if err := validateDocument(schema, fragment, prefix+version); err == nil {
						t.Fatalf("%s admits %q", fragment, prefix+version)
					}
				}
				for _, value := range []any{nil, 12, true} {
					if err := validateDocument(schema, fragment, value); err == nil {
						t.Fatalf("%s admits nonstring %#v", fragment, value)
					}
				}
			}
		}
	})

	root := t.TempDir()
	fixtureSourceGit(t, root, "init", "-q")
	fixtureFile(t, root, "source", "tracked bytes")
	fixtureSourceGit(t, root, "add", ".")
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "release source")
	const version = "1.15.0-polaris-alpha.12.31"
	tag := "v" + version
	fixtureSourceGit(t, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "tag", "-a", "-m", "release", tag)
	source := fixtureSourceGit(t, root, "rev-parse", "HEAD")
	object := fixtureSourceGit(t, root, "rev-parse", "refs/tags/"+tag)
	t.Chdir(root)
	t.Setenv("GITHUB_REPOSITORY", repository)
	t.Setenv("GITHUB_REPOSITORY_ID", repositoryID)
	t.Setenv("GITHUB_SHA", source)
	t.Setenv("GITHUB_REF_TYPE", "tag")
	t.Setenv("GITHUB_REF_NAME", tag)
	child := fixtureSourceCLI(t)
	t.Setenv("PATH", filepath.Dir(child)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("POLARIS_CI_TEST_GH_MODE", "release-tag")
	t.Setenv("POLARIS_CI_TEST_TAG_REF", fmt.Sprintf(`{"object":{"type":"tag","sha":"%s"}}`, object))
	t.Setenv("POLARIS_CI_TEST_TAG_OBJECT", fmt.Sprintf(`{"sha":"%s","tag":"%s","object":{"type":"commit","sha":"%s"}}`, object, tag, source))
	output := filepath.Join(t.TempDir(), "github-output")
	command := []string{"release-identity", "--tag", tag, "--github-output", output}
	if err := run(command); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(output)
	want := "version=" + version + "\ntag_object=" + object + "\n"
	if err != nil || string(raw) != want {
		t.Fatalf("unexpected release outputs: %s, %v", raw, err)
	}
	t.Run("invalid tags cannot read release metadata", func(t *testing.T) {
		read := func(endpoint string, _ any) error {
			t.Fatalf("malformed tag reached GitHub: %s", endpoint)
			return nil
		}
		for _, invalid := range versions.Invalid {
			if _, err := remoteTagIdentity("v"+invalid, source, object, read); err == nil {
				t.Fatalf("malformed annotated tag %q admitted", "v"+invalid)
			}
		}
	})
	t.Run("publisher observes the exact remote object", func(t *testing.T) {
		t.Chdir(t.TempDir())
		remote := []string{"release-identity", "--scope", "remote", "--source", source, "--tag", tag, "--expected-tag-object", object}
		if err := run(remote); err != nil {
			t.Fatal(err)
		}
		if err := run(append(remote, "--expected-tag-object", strings.Repeat("f", 40))); err == nil {
			t.Fatal("changed tag object admitted")
		}
		for _, response := range []struct {
			tag, kind, target string
		}{
			{tag, "commit", strings.Repeat("f", 40)},
			{tag, "tag", source},
			{tag + ".1", "commit", source},
		} {
			reply, err := json.Marshal(map[string]any{"sha": object, "tag": response.tag, "object": gitObject{Type: response.kind, SHA: response.target}})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("POLARIS_CI_TEST_TAG_OBJECT", string(reply))
			if err := run(remote); err == nil {
				t.Fatal("tag name or target mismatch admitted", response)
			}
		}
	})
	t.Run("assembler needs the original local annotation", func(t *testing.T) {
		clone := t.TempDir()
		fixtureSourceGit(t, clone, "clone", "--no-local", root, ".")
		t.Chdir(clone)
		t.Setenv("GITHUB_REF_TYPE", "branch")
		checkout := []string{"release-identity", "--scope", "checkout", "--source", source, "--tag", tag, "--expected-tag-object", object}
		if err := run(checkout); err != nil {
			t.Fatal(err)
		}
		fixtureSourceGit(t, clone, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "different checkout")
		if err := run(checkout); err == nil {
			t.Fatal("checkout at another commit admitted")
		}
		fixtureSourceGit(t, clone, "checkout", "--detach", source)
		if err := run(checkout); err != nil {
			t.Fatal(err)
		}
		fixtureSourceGit(t, clone, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "tag", "-fa", tag, "-m", "different annotation")
		if err := run(checkout); err == nil {
			t.Fatal("recreated local annotation admitted")
		}
		fixtureSourceGit(t, clone, "fetch", "--no-tags", "origin", "+"+source+":refs/tags/"+tag)
		if err := run(checkout); err == nil {
			t.Fatal("checkout with a peeled local tag admitted")
		}
		if err := run(append(checkout, "--github-output", output)); err == nil {
			t.Fatal("assembler wrote dispatch outputs")
		}
	})
	t.Setenv("POLARIS_CI_TEST_TAG_REF", fmt.Sprintf(`{"object":{"type":"commit","sha":"%s"}}`, source))
	if err := run(command); err == nil {
		t.Fatal("lightweight tag admitted")
	}
	raw, err = os.ReadFile(output)
	if err != nil || string(raw) != want {
		t.Fatalf("refused tag changed existing output: %s, %v", raw, err)
	}
}

func TestPatchGitHistoryRequiresMergedBaseline(t *testing.T) {
	root := moduleFixture(t)
	t.Chdir(root)
	commit := func(args ...string) string {
		t.Helper()
		output, err := git(root, append([]string{"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(output))
	}
	commit("init", "-q")
	commit("add", ".")
	commit("commit", "-qm", "common")
	common := commit("rev-parse", "HEAD")
	fixtureFile(t, root, "official.go", "package fixture\n")
	commit("add", ".")
	commit("commit", "-qm", "official")
	official := commit("rev-parse", "HEAD")
	commit("checkout", "-q", "--detach", common)
	fixtureFile(t, root, "changed.go", "package fixture\n")
	commit("add", ".")
	commit("commit", "-qm", "rewritten")
	output := filepath.Join(t.TempDir(), "plan")
	if err := patchPackages([]string{"--base", official, "--output-directory", output}); err == nil {
		t.Fatal("divergent baseline admitted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("rejected history wrote an output plan")
	}
	commit("merge", "--no-ff", "--no-edit", official)
	if err := patchPackages([]string{"--base", official, "--output-directory", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan patchPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.BaseCommit != official || plan.MergeBase != official || !plan.BaseIsAncestor ||
		plan.SourceCommit != commit("rev-parse", "HEAD") || !slices.Equal(plan.Modules["."].ChangedPaths, []string{"changed.go"}) {
		t.Fatalf("merged history differs: %+v", plan)
	}
}

func TestScopedProtoArchiveAdmission(t *testing.T) {
	original := runtimeProtoc
	t.Cleanup(func() { runtimeProtoc = original })
	for _, fault := range []string{"", "digest", "size", "missing", "duplicate", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			var buffer bytes.Buffer
			archive := zip.NewWriter(&buffer)
			members := append([]string{}, protocMembers...)
			if fault == "missing" {
				members = members[:1]
			} else if fault == "duplicate" {
				members = append(members, protocMembers[0])
			}
			members = append(members, "../unrequested")
			for _, name := range members {
				header := &zip.FileHeader{Name: name}
				header.SetMode(0o644)
				if fault == "symlink" && name == protocMembers[0] {
					header.SetMode(os.ModeSymlink | 0o777)
				}
				writer, err := archive.CreateHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte("fixture")); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			data := buffer.Bytes()
			runtimeProtoc.Bytes, runtimeProtoc.SHA256 = int64(len(data)), sha256Hex(data)
			if fault == "digest" {
				data = bytes.Clone(data)
				data[0] ^= 1
			} else if fault == "size" {
				data = append(data, 'x')
			}
			directory := t.TempDir()
			tools := filepath.Join(directory, "tools")
			err := extractProtoc(data, tools)
			if fault != "" {
				if err == nil {
					t.Fatal("invalid archive admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range protocMembers {
				data, err := os.ReadFile(filepath.Join(tools, filepath.FromSlash(name)))
				if err != nil || string(data) != "fixture" {
					t.Fatalf("fixed member differs: %s: %v", name, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(directory, "unrequested")); !os.IsNotExist(err) {
				t.Fatal("unrequested ZIP path extracted")
			}
		})
	}
}

func TestScopedProtoOutputAndSourceAdmission(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	t.Setenv("PATH", t.TempDir())
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeProtoIdentity(root); err == nil || !strings.Contains(err.Error(), "GitHub-hosted") {
		t.Fatal("non-CI invocation reached subprocess execution")
	}
	for _, name := range []string{root, filepath.Join(root, "daemon/generated"), "relative", root + "/../aliased"} {
		if _, err := outsideSource(root, name); err == nil {
			t.Fatalf("unsafe output admitted: %s", name)
		}
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "fresh/output")
	if actual, err := outsideSource(root, outside); err != nil || actual != outside {
		t.Fatalf("fresh external output rejected: %v", err)
	}
	for _, fault := range []string{"", "different", "missing", "extra", "header", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			generated, checked := t.TempDir(), t.TempDir()
			for _, name := range runtimeProtoOutputs {
				fixtureFile(t, generated, name, "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage daemon\n")
				fixtureFile(t, checked, name, "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage daemon\n")
			}
			name := runtimeProtoOutputs[0]
			switch fault {
			case "different":
				fixtureFile(t, checked, name, "different")
			case "missing":
				if err := os.Remove(filepath.Join(generated, filepath.FromSlash(name))); err != nil {
					t.Fatal(err)
				}
			case "extra":
				fixtureFile(t, generated, "unrelated.pb.go", "unrelated")
			case "header":
				fixtureFile(t, generated, name, "package daemon\n")
			case "symlink":
				if err := os.Symlink(checked, filepath.Join(generated, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			inventory, err := runtimeGenerated(generated, checked)
			if fault != "" {
				if err == nil {
					t.Fatal("invalid generated source admitted")
				}
			} else if err != nil || len(inventory) != len(runtimeProtoOutputs) {
				t.Fatalf("valid output rejected: %v", err)
			}
		})
	}
}

func TestSDKSelectionRequiresBoundedLocalCarrier(t *testing.T) {
	root := moduleFixture(t)
	t.Chdir(root)
	for _, fault := range []string{"", "packages", "full-validation", "missing-validation", "directory", "remote"} {
		t.Run(fault, func(t *testing.T) {
			name := fixtureFile(t, root, "third_party/tailscale/fixture.go", "package fixture\n")
			plan, err := selectPatchPackages(root, []string{name})
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(t.TempDir(), "plan")
			if err := writePatchPlan(directory, plan); err != nil {
				t.Fatal(err)
			}
			module := goModule{Path: tailscaleModule, Replace: &goModule{Path: localSDK, Dir: filepath.Join(root, "third_party/tailscale")}}
			switch fault {
			case "packages":
				fixtureFile(t, directory, "tailscale-packages.txt", tailscaleModule+"/unbounded\n")
			case "full-validation":
				plan.Modules["third_party/tailscale"].FullValidation = true
				if err := writeJSONFile(filepath.Join(directory, "selection.json"), plan); err != nil {
					t.Fatal(err)
				}
			case "missing-validation":
				if err := writeJSONFile(filepath.Join(directory, "selection.json"), map[string]any{
					"modules": map[string]any{"third_party/tailscale": map[string]any{"module": tailscaleModule, "packages": sdkTestPackages()}},
				}); err != nil {
					t.Fatal(err)
				}
			case "directory":
				module.Replace.Dir = root
			case "remote":
				module.Replace = &goModule{Path: ownedSDK, Version: "v1.0.0", Sum: "h1:fixture"}
			}
			if err := writeJSONFile(filepath.Join(directory, "tailscale-module.json"), module); err != nil {
				t.Fatal(err)
			}
			err = checkSDKSelection([]string{directory})
			if fault != "" && err == nil || fault == "" && err != nil {
				t.Fatalf("SDK selection %q: %v", fault, err)
			}
		})
	}
}

func TestFormatScopeUsesTrackedModulesAndGoGeneratedMarker(t *testing.T) {
	root := t.TempDir()
	fixtureFile(t, root, "go.mod", "module fixture\n\ngo 1.27.0\n")
	fixtureFile(t, root, "owned.go", "package fixture\n")
	fixtureFile(t, root, "marked.go", "// Code generated by fixture. DO NOT EDIT.\npackage fixture\n")
	fixtureFile(t, root, "false-marker.go", "/* // Code generated by fixture. DO NOT EDIT. */\npackage fixture\n")
	fixtureFile(t, root, "nested/go.mod", "module nested\n\ngo 1.27.0\n")
	fixtureFile(t, root, "nested/independent.go", "package nested\n")
	fixtureFile(t, root, "testdata/fixture.go", "package fixture\n")
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}} {
		if _, err := git(root, args...); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := ownedFormatScope(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope) != 2 || scope["owned.go"] != sha256Hex([]byte("package fixture\n")) || scope["false-marker.go"] == "" {
		t.Fatalf("owned format scope differs: %v", scope)
	}
	fixtureFile(t, root, "go.mod", "module changed\n\ngo 1.27.0\n")
	if _, err := ownedFormatScope(root); err == nil {
		t.Fatal("changed tracked module boundary admitted")
	}
}

func fixtureFile(t *testing.T, root, name, contents string) string {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func moduleFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for owner, runner := range moduleRunners {
		fixtureFile(t, root, filepath.ToSlash(filepath.Join(owner, "go.mod")), "module "+runner.module+"\n\ngo 1.27.0\n")
	}
	return root
}

func TestPatchPackagesPartitionActualModuleBoundaries(t *testing.T) {
	root := moduleFixture(t)
	paths := []string{}
	for owner := range moduleRunners {
		paths = append(paths, fixtureFile(t, root, filepath.ToSlash(filepath.Join(owner, "fixture.go")), "package fixture\n"))
	}
	paths = append(paths, fixtureFile(t, root, "common/tls/client.go", "package fixture\n"))
	paths = append(paths, fixtureFile(t, root, "third_party/helper/helper.go", "package fixture\n"))
	plan, err := selectPatchPackages(root, append(slices.Clone(paths), paths[0], "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	accounted := []string{}
	for owner, entry := range plan.Modules {
		if entry.Module != moduleRunners[owner].module {
			t.Fatalf("wrong identity for %s", owner)
		}
		accounted = append(accounted, entry.ChangedPaths...)
		if owner == "." {
			if entry.FullValidation || !slices.Equal(entry.Packages, []string{".", "./common/tls", "./third_party/helper"}) {
				t.Fatalf("root partition: %+v", entry)
			}
		} else if owner == "third_party/tailscale" {
			for i, name := range sdkPackages {
				if entry.Packages[i] != tailscaleModule+"/"+name {
					t.Fatal("SDK package selection differs")
				}
			}
			if entry.FullValidation {
				t.Fatal("SDK must retain the bounded runtime selection")
			}
		} else if !entry.FullValidation || !slices.Equal(entry.Packages, []string{"./..."}) {
			t.Fatalf("nested module lost full validation: %s", owner)
		}
	}
	slices.Sort(paths)
	slices.Sort(accounted)
	if !slices.Equal(accounted, paths) {
		t.Fatalf("lost or duplicated paths: %v", accounted)
	}
	directory := filepath.Join(root, "plan")
	if err := writePatchPlan(directory, plan); err != nil {
		t.Fatal(err)
	}
	for owner, runner := range moduleRunners {
		if runner.marker == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, runner.marker))
		if err != nil || string(data) != plan.Modules[owner].Module+"\n" {
			t.Fatalf("marker does not identify actual module: %s: %v", owner, err)
		}
	}
	if err := writePatchPlan(directory, plan); !os.IsExist(err) {
		t.Fatalf("stale plan directory reused: %v", err)
	}
}

func TestPatchMetadataAndDeletedPackagesRetainValidation(t *testing.T) {
	root := moduleFixture(t)
	paths := []string{"go.sum"}
	for owner := range moduleRunners {
		if owner != "." {
			paths = append(paths, owner+"/go.mod")
		}
	}
	plan, err := selectPatchPackages(root, paths)
	if err != nil {
		t.Fatal(err)
	}
	for owner, entry := range plan.Modules {
		if owner != "third_party/tailscale" && (!entry.FullValidation || !slices.Equal(entry.Packages, []string{"./..."})) {
			t.Fatalf("metadata lost full validation: %s", owner)
		}
	}
	plan, err = selectPatchPackages(root, []string{"removed/package/file.go"})
	if err != nil || !slices.Equal(plan.Modules["."].Packages, []string{"./..."}) {
		t.Fatalf("removed package was not accounted for: %v", err)
	}
	fixtureFile(t, root, "daemon/runtime_config.proto", "syntax = \"proto3\";\n")
	plan, err = selectPatchPackages(root, []string{"daemon/runtime_config.proto"})
	if err != nil || plan.Modules["."].FullValidation || !slices.Equal(plan.Modules["."].Packages, []string{"./daemon"}) {
		t.Fatalf("schema input lost generated package: %v", err)
	}
}

func TestPatchUnknownAndChangedModuleIdentitiesAreRejected(t *testing.T) {
	root := moduleFixture(t)
	fixtureFile(t, root, "third_party/unknown/go.mod", "module unknown\n")
	for _, name := range []string{"third_party/unknown/conn.go", "third_party/unknown/go.mod"} {
		if _, err := selectPatchPackages(root, []string{name}); err == nil || !strings.Contains(err.Error(), "no approved test runner") {
			t.Fatalf("unknown module admitted: %s: %v", name, err)
		}
	}
	for owner, runner := range moduleRunners {
		mod := filepath.ToSlash(filepath.Join(owner, "go.mod"))
		fixtureFile(t, root, mod, "module wrong/identity\n")
		if _, err := selectPatchPackages(root, []string{mod}); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
			t.Fatalf("changed identity admitted: %s: %v", owner, err)
		}
		fixtureFile(t, root, mod, "module "+runner.module+"\n\ngo 1.27.0\n")
	}
}

func TestPatchRemovedAndDeeperBoundariesAreRejected(t *testing.T) {
	root := moduleFixture(t)
	for owner, runner := range moduleRunners {
		if runner.marker == "" {
			continue
		}
		mod := filepath.Join(root, filepath.FromSlash(owner), "go.mod")
		if err := os.Remove(mod); err != nil {
			t.Fatal(err)
		}
		if _, err := selectPatchPackages(root, []string{owner + "/fixture.go"}); err == nil || !strings.Contains(err.Error(), "nested module boundary") {
			t.Fatalf("removed boundary admitted: %s: %v", owner, err)
		}
		fixtureFile(t, root, owner+"/go.mod", "module "+runner.module+"\n")
	}
	fixtureFile(t, root, "third_party/sing-tun/deeper/go.mod", "module another/module\n")
	if _, err := selectPatchPackages(root, []string{"third_party/sing-tun/deeper/fixture.go"}); err == nil {
		t.Fatal("new deeper module admitted")
	}
	if _, err := selectPatchPackages(root, []string{"third_party/sing-tun/missing/go.sum"}); err == nil {
		t.Fatal("unowned metadata boundary admitted")
	}
}

func TestPatchUnsafePathsAndSymlinksAreRejected(t *testing.T) {
	root := moduleFixture(t)
	for _, name := range []string{"../box.go", "/box.go", "common/../box.go", "common//box.go", "box\n.go", "common\\box.go", "bad\x00.go"} {
		if _, err := selectPatchPackages(root, []string{name}); err == nil {
			t.Fatalf("unsafe path admitted: %q", name)
		}
	}
	if err := os.Symlink(filepath.Join(root, "third_party/sing-tun"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := selectPatchPackages(root, []string{"linked/fixture.go"}); err == nil {
		t.Fatal("symlinked source boundary admitted")
	}
}

func TestPatchReleaseModuleOnlyAdmitsLicenseEvidence(t *testing.T) {
	root := moduleFixture(t)
	fixtureFile(t, root, "release/go.mod", "module github.com/polaris-arch/sing-box-polaris/release\n\ngo 1.27.0\n")
	plan, err := selectPatchPackages(root, []string{"release/go.mod", "release/licenses/archived/license_test.go"})
	if err != nil || len(plan.Modules) != 0 {
		t.Fatalf("license evidence partition: %v", err)
	}
	if _, err := selectPatchPackages(root, []string{"release/unowned.go"}); err == nil {
		t.Fatal("non-license release package admitted")
	}
}

func TestArtifactArchiveChecksMetadataBeforeAllocationAndOriginalMemberBytes(t *testing.T) {
	for _, fault := range []string{"", "stored", "zip64", "zip64-count", "count", "directory-size", "local-name", "overlap", "crc", "inflated-size", "trailing-deflate", "duplicate", "case", "prefix", "symlink", "encrypted", "method"} {
		t.Run(fault, func(t *testing.T) {
			headers := []zip.FileHeader{{Name: "parent/file", Method: zip.Deflate}, {Name: "parent/other", Method: zip.Deflate}}
			switch fault {
			case "stored":
				headers[0].Method = zip.Store
			case "duplicate":
				headers[1].Name = headers[0].Name
			case "case":
				headers[1].Name = "parent/FILE"
			case "prefix":
				headers[1].Name = "parent/file/child"
			case "symlink":
				headers[0].SetMode(os.ModeSymlink | 0o777)
			}
			data := fixtureZIP(t, headers...)
			order := binary.LittleEndian
			end := len(data) - 22
			central := int(order.Uint32(data[end+16:]))
			switch fault {
			case "zip64", "zip64-count":
				record := make([]byte, 76)
				copy(record, "PK\x06\x06")
				order.PutUint64(record[4:], 44)
				order.PutUint16(record[12:], 45)
				order.PutUint16(record[14:], 45)
				count := uint64(2)
				if fault == "zip64-count" {
					count = 16385
				}
				order.PutUint64(record[24:], count)
				order.PutUint64(record[32:], count)
				order.PutUint64(record[40:], uint64(order.Uint32(data[end+12:])))
				order.PutUint64(record[48:], uint64(central))
				copy(record[56:], "PK\x06\x07")
				order.PutUint64(record[64:], uint64(end))
				order.PutUint32(record[72:], 1)
				ending := bytes.Clone(data[end:])
				order.PutUint16(ending[8:], 65535)
				order.PutUint16(ending[10:], 65535)
				order.PutUint32(ending[12:], 0xffffffff)
				order.PutUint32(ending[16:], 0xffffffff)
				data = append(append(data[:end], record...), ending...)
			case "count":
				order.PutUint16(data[end+8:], 16385)
				order.PutUint16(data[end+10:], 16385)
			case "directory-size":
				order.PutUint32(data[end+12:], 32<<20+1)
			case "local-name":
				data[30] = 'X'
			case "overlap":
				order.PutUint32(data[central+20:], uint32(len(data)))
			case "crc":
				data[central+16] ^= 1
			case "inflated-size":
				order.PutUint32(data[central+24:], 1)
			case "trailing-deflate":
				order.PutUint32(data[central+20:], order.Uint32(data[central+20:])+1)
			case "encrypted":
				order.PutUint16(data[6:], order.Uint16(data[6:])|1)
				order.PutUint16(data[central+8:], order.Uint16(data[central+8:])|1)
			case "method":
				order.PutUint16(data[8:], 99)
				order.PutUint16(data[central+10:], 99)
			}
			filename := filepath.Join(t.TempDir(), "artifact.zip")
			if err := os.WriteFile(filename, data, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(filename)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			archive, err := openArtifactZIP(file)
			var copied bytes.Buffer
			if err == nil {
				_, err = archive.copyMember(archive.members[0], &copied)
			}
			valid := fault == "" || fault == "stored" || fault == "zip64"
			if valid {
				if err != nil || copied.String() != "fixture" {
					t.Fatalf("valid archive changed: %q: %v", copied.String(), err)
				}
			} else if err == nil {
				t.Fatal("invalid archive admitted")
			}
			if fault == "inflated-size" && copied.Len() > 1 {
				t.Fatal("undeclared bytes reached the destination")
			}
		})
	}
}

func fixtureZIP(t *testing.T, headers ...zip.FileHeader) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, header := range headers {
		writer, err := archive.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestWorkflowReceiptsBindFilesSourceAndCompleteNativeScope(t *testing.T) {
	root := moduleFixture(t)
	t.Chdir(root)
	fixtureFile(t, root, "release/ci/github-release.json", `{"repository":"polaris-arch/sing-box-polaris","repositoryId":1421657509}`)
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "receipt source"}} {
		if _, err := git(root, args...); err != nil {
			t.Fatal(err)
		}
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(string(head))
	version := "1.15.0-polaris-alpha.12.31"
	for name, value := range map[string]string{
		"GITHUB_REPOSITORY": repository, "GITHUB_REPOSITORY_ID": repositoryID, "GITHUB_JOB": "build",
		"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": source,
		"PUBLISHER_ROLE": "all", "GITHUB_EVENT_NAME": "workflow_dispatch", "RELEASE_BUILD": "All",
		"RELEASE_VERSION": version, "GITHUB_REF": "refs/tags/v" + version,
		"RECEIPT_SOURCE_GENERATE_ONLY": "false", "NEEDS_JSON": `{"build":{"result":"success","outputs":{}}}`,
		"CANDIDATE_MATRIX_KEY": "linux-amd64",
	} {
		t.Setenv(name, value)
	}
	artifacts := t.TempDir()
	fixtureFile(t, artifacts, "nested/core", "actual bytes")
	fixtureFile(t, artifacts, "polaris-candidate-manifest-old.json", "old receipt")
	if err := run([]string{"record-candidate", artifacts}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(artifacts, "polaris-candidate-manifest-build-linux-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	var candidate struct {
		SourceCommit, SourceTree, WorkflowRunID, WorkflowAttempt, MatrixKey, SignatureState string
		RepositoryID                                                                        int64
		ReleasePublication, RuntimeAcceptance                                               *bool
		Files                                                                               []candidateFile
	}
	if err := json.Unmarshal(data, &candidate); err != nil {
		t.Fatal(err)
	}
	tree, err := git(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.SourceCommit != source || candidate.SourceTree != strings.TrimSpace(string(tree)) ||
		candidate.WorkflowRunID != "123" || candidate.WorkflowAttempt != "1" || candidate.RepositoryID != 1421657509 ||
		candidate.MatrixKey != "linux-amd64" || candidate.SignatureState != "unsigned-candidate" ||
		candidate.ReleasePublication == nil || *candidate.ReleasePublication || candidate.RuntimeAcceptance == nil || *candidate.RuntimeAcceptance ||
		!slices.Equal(candidate.Files, []candidateFile{{"nested/core", 12, sha256Hex([]byte("actual bytes"))}}) {
		t.Fatalf("candidate receipt lost its actual identity: %+v", candidate)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "selected-root")
		if err := os.Symlink(artifacts, link); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"record-candidate", link}); err != nil {
			t.Fatalf("selected directory symlink no longer supported: %v", err)
		}
		member := filepath.Join(artifacts, "linked-member")
		if err := os.Symlink(filepath.Join(artifacts, "nested/core"), member); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"record-candidate", artifacts}); err == nil {
			t.Fatal("candidate followed a member symlink")
		}
		if err := os.Remove(member); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"record-candidate", t.TempDir()}); err == nil {
		t.Fatal("empty candidate published a receipt")
	}
	for _, version := range []string{version, "1.15.0-polaris-alpha.12.2"} {
		t.Setenv("RELEASE_VERSION", version)
		t.Setenv("GITHUB_REF", "refs/tags/v"+version)
		if err := run([]string{"publisher-receipt"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile("publisher-run-receipt.json")
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := uniqueJSON(bytes.NewReader(data), &record); err != nil {
			t.Fatal(err)
		}
		if record["version"] != version || record["sourceCommit"] != source || record["role"] != "all" ||
			record["runId"] != "123" || record["attempt"] != json.Number("1") || record["repositoryId"] != json.Number(repositoryID) {
			t.Fatalf("publisher receipt identity differs: %v", record)
		}
	}
	for _, invalid := range [][2]string{
		{"RELEASE_VERSION", "v1.15.0-polaris-alpha.12.2"},
		{"RELEASE_VERSION", "1.15.0-polaris-alpha.12.20"},
		{"GITHUB_REF", "refs/heads/v1.15.0-polaris-alpha.12.2"},
		{"GITHUB_SHA", strings.Repeat("f", 40)},
		{"PUBLISHER_ROLE", "source"},
		{"GITHUB_EVENT_NAME", "push"},
		{"RELEASE_BUILD", "Binary"},
		{"GITHUB_REPOSITORY", "other/repository"},
		{"GITHUB_REPOSITORY_ID", "1"},
		{"RECEIPT_SOURCE_GENERATE_ONLY", "true"},
		{"RECEIPT_SOURCE_GENERATE_ONLY", "False"},
		{"NEEDS_JSON", `{}`},
		{"NEEDS_JSON", `[]`},
		{"NEEDS_JSON", `{"build":{"result":"success","outputs":[]}}`},
		{"NEEDS_JSON", `{"build":{"result":"success","outputs":{},"extra":true}}`},
		{"NEEDS_JSON", `{"build":{"result":"success","outputs":{"x":1,"x":2}}}`},
		{"NEEDS_JSON", `{"build":{"result":"success","outputs":{}},"build":{"result":"failure","outputs":{}}}`},
	} {
		t.Run(invalid[0]+"="+invalid[1], func(t *testing.T) {
			t.Setenv(invalid[0], invalid[1])
			if err := run([]string{"publisher-receipt"}); err == nil {
				t.Fatal("invalid native producer scope admitted")
			}
		})
	}
	for _, status := range []string{"failure", "cancelled", "skipped", ""} {
		if err := validateNeeds("false", fmt.Sprintf(`{"build":{"result":%q,"outputs":{}}}`, status)); err == nil {
			t.Fatalf("nonterminal producer result admitted: %s", status)
		}
	}
	t.Run("missing-native-context", func(t *testing.T) {
		t.Setenv("GITHUB_RUN_ID", "placeholder")
		if err := os.Unsetenv("GITHUB_RUN_ID"); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"publisher-receipt"}); err == nil {
			t.Fatal("missing native context admitted")
		}
		if err := run([]string{"record-candidate", artifacts}); err == nil {
			t.Fatal("candidate receipt lost required native context")
		}
	})
}
