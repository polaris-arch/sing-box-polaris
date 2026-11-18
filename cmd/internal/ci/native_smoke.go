package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type nativeSmokeExecution struct {
	command  func(context.Context, ...string) *exec.Cmd
	proofKey string
	observe  func() (map[string]any, error)
	close    func() error
}

func smokeNativeIndex(ctx context.Context, root string, args []string) (err error) {
	if len(args) != 1 {
		return fmt.Errorf("expected one directory for smoke-native-index")
	}
	if _, err := validateCronetOverlay(root); err != nil {
		return err
	}
	directory := args[0]
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var name string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "native-row-") && strings.HasSuffix(entry.Name(), ".json") {
			if name != "" {
				return fmt.Errorf("smoke requires exactly one native row")
			}
			name = entry.Name()
		}
	}
	if name == "" {
		return fmt.Errorf("smoke requires exactly one native row")
	}
	var row map[string]any
	if err := readNativeSourceJSON(directory, name, &row); err != nil {
		return err
	}
	policy := filepath.Join(root, nativeIndexSchema)
	archive, _ := row["archive"].(map[string]any)
	filename, _ := archive["name"].(string)
	releaseName, err := publicProductName(filename)
	if err != nil {
		return err
	}
	// The index assembler adds releaseName to the producer row. Use the
	// same schema here while retaining the original producer row encoding.
	if _, present := archive["releaseName"]; present {
		return fmt.Errorf("native smoke requires the original producer row")
	}
	archive["releaseName"] = releaseName
	delete(row, "trustedExecution")
	row["finalPackageCronetSmoke"] = nil
	if err := validateDocument(policy, "#/properties/platforms/items", row); err != nil {
		return fmt.Errorf("invalid native producer row: %w", err)
	}
	if name != "native-row-"+row["id"].(string)+".json" {
		return fmt.Errorf("native row filename differs from receipt identity")
	}

	var pins struct{ CronetVersion, WrapperCommit string }
	if err := readNativeSourceJSON(root, "release/polaris-candidate-inputs.json", &pins); err != nil {
		return err
	}
	wrapper, err := readNativeSource(root, ".github/CRONET_GO_VERSION")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(wrapper)) != pins.WrapperCommit {
		return fmt.Errorf("Cronet smoke pin mismatch")
	}

	members, err := loadNativeSmokeArchive(directory, archive)
	if err != nil {
		return err
	}
	if err := executeNativeSmoke(ctx, root, row, members, pins.CronetVersion); err != nil {
		return err
	}
	if err := validateDocument(policy, "#/properties/platforms/items", row); err != nil {
		return fmt.Errorf("invalid native smoke receipt: %w", err)
	}
	delete(archive, "releaseName")
	size, _ := nativePositiveInteger(archive["bytes"])
	if err := checkNativeArchive(directory, filename, size, archive["sha256"].(string)); err != nil {
		return fmt.Errorf("archive changed during native smoke: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".native-smoke-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if remove := os.Remove(temp.Name()); !errors.Is(remove, os.ErrNotExist) {
			err = errors.Join(err, remove)
		}
	}()
	if err := temp.Close(); err != nil {
		return err
	}
	if err := sourceReceipt(temp.Name(), row, false, 32<<20); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), filepath.Join(directory, name))
}

func loadNativeSmokeArchive(directory string, archive map[string]any) (map[string][]byte, error) {
	size, exact := nativePositiveInteger(archive["bytes"])
	if !exact || size > publisherScratchLimit {
		return nil, fmt.Errorf("missing or unbounded native archive")
	}
	input, err := openNativeSource(directory, archive["name"].(string))
	if err != nil {
		return nil, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != size {
		return nil, fmt.Errorf("native smoke archive size differs")
	}
	digest := sha256.New()
	measured, err := io.Copy(digest, io.NewSectionReader(input, 0, size+1))
	if err != nil {
		return nil, err
	}
	if measured != size || fmt.Sprintf("%x", digest.Sum(nil)) != archive["sha256"] {
		return nil, fmt.Errorf("native smoke archive hash differs")
	}
	root, members, err := readNativeArchiveFile(input)
	if err != nil {
		return nil, err
	}
	hashes := archive["members"].(map[string]any)
	if root != archive["root"] || len(members) != len(hashes) {
		return nil, fmt.Errorf("archive member inventory changed")
	}
	for name, data := range members {
		if sha256Hex(data) != hashes[root+"/"+name] {
			return nil, fmt.Errorf("native smoke member changed: %s", name)
		}
	}
	return members, nil
}

func executeNativeSmoke(ctx context.Context, root string, row map[string]any, members map[string][]byte, version string) (err error) {
	target := row["target"].(string)
	goos, goarch, _ := strings.Cut(target, "/")
	variant := row["variant"].(map[string]any)
	linkage := variant["linkage"]
	if goos != runtime.GOOS || goarch != runtime.GOARCH || !nativeTagSet(row["tags"].(string))["with_naive_outbound"] {
		return fmt.Errorf("native smoke requires the producer host and Naive build tag")
	}
	corePin := row["core"].(map[string]any)
	sidecar, _ := row["sidecar"].(map[string]any)
	coreName := "sing-box"
	if goos == "windows" {
		coreName = "sing-box.exe"
	}
	for _, pin := range []map[string]any{corePin, sidecar} {
		if pin == nil {
			continue
		}
		name := pin["member"].(string)
		size, exact := nativePositiveInteger(pin["bytes"])
		if !exact || int64(len(members[name])) != size || !nativeArchiveMember(row["archive"].(map[string]any), pin, name) {
			return fmt.Errorf("native smoke selected member differs: %s", name)
		}
	}
	if corePin["member"] != coreName || (sidecar != nil) != (linkage == "shared-purego") {
		return fmt.Errorf("native smoke Core or sidecar differs from platform")
	}
	scratch, err := os.MkdirTemp("", "polaris-native-smoke-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, removeNativeSmokeDirectory(scratch)) }()
	core := filepath.Join(scratch, coreName)
	for name, data := range members {
		mode := os.FileMode(0o600)
		if name == coreName {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(scratch, name), data, mode); err != nil {
			return err
		}
	}
	execution := nativeSmokeExecution{
		command: func(ctx context.Context, args ...string) *exec.Cmd {
			command := exec.CommandContext(ctx, core, args...)
			command.Dir = scratch
			return command
		},
	}
	if err := prepareNativeSmoke(ctx, core, row, members, &execution); err != nil {
		return err
	}
	if execution.close != nil {
		defer func() { err = errors.Join(err, execution.close()) }()
	}

	var producer map[string]any
	if execution.proofKey != "" {
		producer = make(map[string]any, 2)
		for _, pair := range []struct{ field, env string }{{"runId", "GITHUB_RUN_ID"}, {"runAttempt", "GITHUB_RUN_ATTEMPT"}} {
			raw := os.Getenv(pair.env)
			value, exact := nativePositiveInteger(json.Number(raw))
			if !exact || strconv.FormatInt(value, 10) != raw {
				return fmt.Errorf("native execution requires actual workflow run/attempt")
			}
			producer[pair.field] = json.Number(raw)
		}
	}

	tls, err := observeTLSRuntime(ctx, core, corePin["sha256"].(string), execution.command, func(raw []byte) (tlsCapabilities, error) {
		capabilities, err := validateTLSCapabilities(root, raw, row["sourceCommit"].(string), row["version"].(string), row["goVersion"].(string), target, true)
		if err != nil {
			return capabilities, err
		}
		return capabilities, verifyNativeTLSModules(row, capabilities)
	})
	if err != nil {
		return err
	}

	cronetArgs := []string{"tools", "cronet", "--expected-version", version}
	var sidecarHash any
	if sidecar != nil {
		sidecarHash = sidecar["sha256"]
		if execution.proofKey != "sealedExecution" {
			cronetArgs = append(cronetArgs, "--library", filepath.Join(scratch, sidecar["member"].(string)))
		}
		cronetArgs = append(cronetArgs, "--sha256", sidecarHash.(string))
	}
	cronetContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	stdout, stderr, code, err := sourceCaptureOutput(cronetContext, execution.command(cronetContext, cronetArgs...), 1<<20)
	cancel()
	if err != nil {
		return err
	}
	if code == nil || *code != 0 {
		return fmt.Errorf("Cronet native smoke failed: %s", strings.TrimSpace(stderr))
	}
	var observed map[string]any
	if err := decodeNativeJSON(strings.NewReader(stdout), &observed); err != nil {
		return fmt.Errorf("native Cronet observation: %w", err)
	}
	expected := map[string]any{"os": goos, "arch": goarch, "go": row["goVersion"], "linkage": linkage, "gvisorCompiled": true, "version": version}
	if !nativeFieldsMatch(observed, expected) || sidecar != nil && observed["sha256"] != sidecarHash {
		return fmt.Errorf("Cronet native smoke differs from producer row")
	}
	smoke := expected
	maps.Copy(smoke, map[string]any{"status": "passed", "naiveOutbound": true, "librarySha256": sidecarHash, "coreSha256": corePin["sha256"]})
	row["finalPackageCronetSmoke"] = smoke
	if execution.proofKey == "" {
		return nil
	}

	proof, err := execution.observe()
	if err != nil {
		return err
	}
	maps.Copy(proof, producer)
	for _, key := range []string{"sourceCommit", "sourceTree", "version", "target", "core"} {
		proof[key] = row[key]
	}
	proof["archiveSha256"], proof["tlsProbe"], proof["cronet"] = row["archive"].(map[string]any)["sha256"], tls, observed
	encoded, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	// Publisher validation expects the same exact JSON number and array types it
	// sees on the wire. Use that representation at the producer boundary too.
	if err := decodeNativeJSON(strings.NewReader(string(encoded)), &proof); err != nil {
		return err
	}
	smoke[execution.proofKey] = proof
	row["trustedExecution"] = nativeExecutionPolicy(row, execution.proofKey == "macosExecution")
	fragment := "#/$defs/" + execution.proofKey
	if err := validateDocument(filepath.Join(root, nativeIndexSchema), fragment, proof); err != nil {
		return fmt.Errorf("invalid native execution proof: %w", err)
	}
	return validateTrustedNativeExecution(row, producer, root)
}

func removeNativeSmokeDirectory(directory string) error {
	start := time.Now()
	for attempt, delay := 1, 100*time.Millisecond; ; attempt++ {
		err := os.RemoveAll(directory)
		if err == nil {
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("smoke temporary directory remains after cleanup")
			}
			return nil
		}
		elapsed := time.Since(start)
		var code syscall.Errno
		retry := runtime.GOOS == "windows" && errors.As(err, &code) && (code == 32 || code == 33) && elapsed < 5*time.Second
		fmt.Fprintf(os.Stderr, "smoke cleanup attempt=%d winerror=%d elapsed=%.3fs retry=%t\n", attempt, code, elapsed.Seconds(), retry)
		if !retry {
			return fmt.Errorf("remove native smoke temporary directory: %w", err)
		}
		time.Sleep(min(delay, 5*time.Second-elapsed))
		delay = min(2*delay, 400*time.Millisecond)
	}
}
