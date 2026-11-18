package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/badversion"
)

const nativeIndexSchema = "release/ci/native-release-index.schema.json"

// validateFinalNativeIndex verifies the index against the selected immutable
// source and the publisher's fresh view of the Actions attempt. The publisher
// separately checks the indexed archive hashes and sizes against artifact bytes.
func validateFinalNativeIndex(index io.Reader, sourceRoot, source, tree, tag, tagObject string, runID int64, attempt int, workflow string, fetchJobs func() ([]map[string]any, error)) error {
	return validateNativeIndex(index, nativeIndexSchema, sourceRoot, source, tree, tag, tagObject, runID, attempt, workflow, fetchJobs, downloadOwnedReplacement)
}

func validateNativeIndex(index io.Reader, schema, sourceRoot, source, tree, tag, tagObject string, runID int64, attempt int, workflow string, fetchJobs func() ([]map[string]any, error), download ownedModuleDownload) error {
	var document map[string]any
	if err := decodeNativeJSON(index, &document); err != nil {
		return fmt.Errorf("final native index JSON: %w", err)
	}
	if err := validateDocument(schema, "", document); err != nil {
		return fmt.Errorf("final native index schema: %w", err)
	}
	version := strings.TrimPrefix(tag, "v")
	if tag == version || !badversion.IsCanonicalPolaris(version) || !nativeFieldsMatch(document, map[string]any{
		"repository": repository, "repositoryId": json.Number(repositoryID), "version": version, "tag": tag,
		"sourceCommit": source, "sourceTree": tree, "tagObject": tagObject,
	}) {
		return fmt.Errorf("final native index binding mismatch")
	}
	producer := document["producer"].(map[string]any)
	if runID <= 0 || attempt <= 0 || !nativeFieldsMatch(producer, map[string]any{
		"repository": repository, "repositoryId": json.Number(repositoryID), "workflow": workflow,
		"workflowCommit": source, "runId": json.Number(strconv.FormatInt(runID, 10)), "runAttempt": json.Number(strconv.Itoa(attempt)),
	}) {
		return fmt.Errorf("final native producer identity mismatch")
	}

	// Like the publisher schema, the expected build matrix belongs to the publisher checkout.
	expected, err := expectedNativeArchives(filepath.Dir(schema), version)
	if err != nil {
		return err
	}
	rows := document["platforms"].([]any)
	if len(rows) != len(expected) {
		return fmt.Errorf("exact native identities required")
	}
	for _, item := range rows {
		row := item.(map[string]any)
		id := row["id"].(string)
		target, exists := expected[id]
		if !exists {
			return fmt.Errorf("unexpected or duplicate native identity %s", id)
		}
		delete(expected, id)
		if err := validateNativePlatform(row, target, sourceRoot, source, tree, version, tag, producer); err != nil {
			return err
		}
	}
	jobs, err := fetchJobs()
	if err != nil {
		return fmt.Errorf("native producer API job evidence: %w", err)
	}
	selected, err := selectNativeJobs(jobs, source, producer["runId"], producer["runAttempt"])
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(producer["nativeJobs"], selected) {
		return fmt.Errorf("native producer job mapping differs from retained proof/API evidence")
	}
	if document["sourceArchive"].(map[string]any)["name"] != "sing-box-polaris-source-"+source+".tar.gz" {
		return fmt.Errorf("immutable source archive basename required")
	}
	materials, err := distributionMaterials(document, sourceRoot, download)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(document["distributionMaterials"], materials) {
		return fmt.Errorf("source/notice bindings differ from actual index or committed inputs")
	}
	return nil
}

func validateNativePlatform(row map[string]any, target nativeTarget, sourceRoot, source, tree, version, tag string, producer map[string]any) error {
	id := row["id"].(string)
	if !nativeFieldsMatch(row, map[string]any{
		"target": target.target, "sourceCommit": source, "sourceTree": tree, "version": version, "tag": tag,
		"variant": map[string]any{"linkage": target.linkage, "libc": "", "goarm": "", "gomips": "", "go386": "", "legacy": false},
	}) {
		return fmt.Errorf("native source or matrix binding differs: %s", id)
	}
	suffix := ".tar.gz"
	if strings.HasPrefix(target.target, "windows/") {
		suffix = ".zip"
	}
	filename := id + suffix
	publicName, err := publicProductName(filename)
	if err != nil {
		return err
	}
	archive := row["archive"].(map[string]any)
	if !nativeFieldsMatch(archive, map[string]any{
		"root": id, "name": filename, "releaseName": publicName,
	}) {
		return fmt.Errorf("native archive identity mismatch: %s", id)
	}
	if err := validateTrustedNativeExecution(row, producer, sourceRoot); err != nil {
		return fmt.Errorf("native execution proof for %s: %w", id, err)
	}
	return nil
}

type nativeTarget struct {
	target  string
	linkage string
}

func expectedNativeArchives(configDir, version string) (map[string]nativeTarget, error) {
	var config struct {
		Matrices map[string]map[string]struct {
			Include []struct {
				OS, Arch, Variant string
				Naive             bool
			}
		}
	}
	if err := readNativeSourceJSON(configDir, "upstream-matrices.json", &config); err != nil {
		return nil, err
	}
	result := make(map[string]nativeTarget)
	for _, lane := range []struct{ job, defaultOS string }{
		{"build", ""}, {"build_darwin", "darwin"}, {"build_windows", "windows"},
	} {
		matrix := config.Matrices["build.yml"][lane.job]
		if len(matrix.Include) == 0 {
			return nil, fmt.Errorf("missing native matrix: %s", lane.job)
		}
		for _, entry := range matrix.Include {
			os := entry.OS
			if os == "" {
				os = lane.defaultOS
			}
			linkage := "other"
			if entry.Naive || os == "darwin" {
				linkage = "static-cgo"
				if entry.Variant == "purego" || os == "windows" {
					linkage = "shared-purego"
				}
			}
			id := "sing-box-" + version + "-" + os + "-" + entry.Arch
			if _, exists := result[id]; exists || os == "" || entry.Arch == "" {
				return nil, fmt.Errorf("invalid or duplicate expected archive identity: %s", id)
			}
			result[id] = nativeTarget{os + "/" + entry.Arch, linkage}
		}
	}
	return result, nil
}

func selectNativeJobs(jobs []map[string]any, source string, runID, attempt any) (map[string]any, error) {
	if jobs == nil || len(jobs) > 1000 {
		return nil, fmt.Errorf("native job API evidence scope differs")
	}
	expected := map[string]string{"linux": "linux-amd64-purego", "win": "windows-amd64", "mac-x64": "darwin-amd64", "mac-arm64": "darwin-arm64"}
	selected := make(map[string]any, len(expected))
	ids := make(map[any]bool, len(expected))
	for key, target := range expected {
		name := "Native final-package Cronet and gVisor smoke (" + target + ")"
		for _, job := range jobs {
			if job["name"] != name {
				continue
			}
			if _, exists := selected[key]; exists {
				return nil, fmt.Errorf("duplicate native producer API evidence: %s", name)
			}
			if _, valid := nativePositiveInteger(job["id"]); !valid || !nativeFieldsMatch(job, map[string]any{
				"conclusion": "success", "status": "completed", "head_sha": source, "run_id": runID, "run_attempt": attempt,
			}) {
				return nil, fmt.Errorf("native producer API source/run/attempt/status differs: %s", name)
			}
			if ids[job["id"]] {
				return nil, fmt.Errorf("native producer job IDs collide")
			}
			ids[job["id"]] = true
			selected[key] = map[string]any{"id": job["id"], "name": name}
		}
		if _, exists := selected[key]; !exists {
			return nil, fmt.Errorf("missing native producer API evidence: %s", name)
		}
	}
	return selected, nil
}

func nativeFieldsMatch(actual, expected map[string]any) bool {
	for name, want := range expected {
		if actual, present := actual[name]; !present || !reflect.DeepEqual(actual, want) {
			return false
		}
	}
	return true
}

func readNativeSourceJSON(root, name string, target any) error {
	input, err := openNativeSource(root, name)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := decodeNativeJSON(input, target); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func decodeNativeJSON(input io.Reader, target any) error {
	const limit = 32 << 20
	bounded := &io.LimitedReader{R: input, N: limit + 1}
	if err := uniqueJSON(bounded, target); err != nil {
		return err
	}
	if bounded.N == 0 {
		return fmt.Errorf("native JSON exceeds byte bound")
	}
	return nil
}
