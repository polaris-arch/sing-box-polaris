package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/sagernet/sing-box/common/badversion"
)

const nativeBuildWorkflow = ".github/workflows/build.yml"

func assembleNativeIndexCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("assemble-native-index requires the artifact directory")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var reads retryBudget
	return assembleNativeIndex(ctx, ".", args[0], nativeIndexSchema, func(endpoint string, target any) error {
		return publisherRemoteJSON(ctx, endpoint, target, &reads)
	})
}

func assembleNativeIndex(ctx context.Context, root, artifacts, schemaPath string, read githubReader) error {
	source := os.Getenv("GITHUB_SHA")
	if err := verifyProducerCheckout(root, source); err != nil {
		return err
	}
	treeBytes, err := git(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	tree := strings.TrimSpace(string(treeBytes))
	if _, err := validateCronetOverlay(root); err != nil {
		return err
	}
	env, err := nativeEnvironment("VERSION", "EXPECTED_RELEASE_TAG_OBJECT", "GITHUB_RUN_ID",
		"GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA")
	if err != nil {
		return err
	}
	version, tagObject := env["VERSION"], env["EXPECTED_RELEASE_TAG_OBJECT"]
	if !sourceCommit.MatchString(tagObject) || !badversion.IsCanonicalPolaris(version) {
		return fmt.Errorf("final index requires the preflight version and annotated tag object")
	}
	tag := "v" + version
	if _, err := verifyCheckoutTag(root, tag, source, tagObject, read); err != nil {
		return err
	}
	runID, attempt := json.Number(env["GITHUB_RUN_ID"]), json.Number(env["GITHUB_RUN_ATTEMPT"])
	validRun, runOK := nativePositiveInteger(runID)
	validAttempt, attemptOK := nativePositiveInteger(attempt)
	if !runOK || !attemptOK || strconv.FormatInt(validRun, 10) != string(runID) || strconv.FormatInt(validAttempt, 10) != string(attempt) ||
		!strings.HasPrefix(env["GITHUB_WORKFLOW_REF"], repository+"/"+nativeBuildWorkflow+"@") || env["GITHUB_WORKFLOW_SHA"] != source {
		return fmt.Errorf("final native producer workflow/source/run/attempt identity differs")
	}
	producer := map[string]any{
		"repository": repository, "repositoryId": json.Number(repositoryID), "workflow": nativeBuildWorkflow,
		"workflowCommit": source, "runId": runID, "runAttempt": attempt,
	}
	policyDir := filepath.Dir(schemaPath)
	var schema map[string]any
	if err := readNativeSourceJSON(policyDir, filepath.Base(schemaPath), &schema); err != nil {
		return err
	}
	expected, err := expectedNativeArchives(policyDir, version)
	if err != nil {
		return err
	}
	platformSchema, err := compileSchema(schema, "#/properties/platforms/items")
	if err != nil {
		return err
	}
	rows := make(map[string]map[string]any, len(expected))
	archives := make(map[string][]string, len(expected))
	err = fs.WalkDir(os.DirFS(artifacts), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "native-row-") || !strings.HasSuffix(name, ".json") {
			if strings.HasPrefix(name, "sing-box-") && (strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".tar.gz")) {
				archives[name] = append(archives[name], relative)
			}
			return nil
		}
		var row map[string]any
		if err := readNativeSourceJSON(artifacts, relative, &row); err != nil {
			return err
		}
		id, _ := row["id"].(string)
		target, found := expected[id]
		if !found {
			return fmt.Errorf("unexpected native receipt identity: %s", id)
		}
		archive, _ := row["archive"].(map[string]any)
		name, _ = archive["name"].(string)
		public, err := publicProductName(name)
		if err != nil {
			return err
		}
		if retained, present := archive["releaseName"]; present && retained != public {
			return fmt.Errorf("native archive release name differs: %s", id)
		}
		archive["releaseName"] = public
		if err := platformSchema.Validate(row); err != nil {
			return fmt.Errorf("native producer row %s: %w", id, err)
		}
		if err := validateNativePlatform(row, target, root, source, tree, version, tag, producer); err != nil {
			return err
		}
		if previous := rows[id]; previous != nil {
			if reflect.DeepEqual(row, previous) {
				return nil
			}
			old := maps.Clone(previous)
			current := maps.Clone(row)
			for _, field := range []string{"trustedExecution", "finalPackageCronetSmoke"} {
				delete(old, field)
				delete(current, field)
			}
			if !reflect.DeepEqual(old, current) {
				return fmt.Errorf("conflicting native receipt: %s", id)
			}
			if row["finalPackageCronetSmoke"] == nil {
				return nil
			}
			if previous["finalPackageCronetSmoke"] != nil {
				return fmt.Errorf("conflicting native smoke receipt: %s", id)
			}
		}
		rows[id] = row
		return nil
	})
	if err != nil {
		return err
	}
	if len(rows) != len(expected) {
		return fmt.Errorf("full upstream native index differs from exact expected archive identities")
	}
	platforms := make([]any, 0, len(rows))
	for _, id := range slices.Sorted(maps.Keys(rows)) {
		row := rows[id]
		archive := row["archive"].(map[string]any)
		name := archive["name"].(string)
		size, ok := nativePositiveInteger(archive["bytes"])
		if !ok || size > publisherScratchLimit || len(archives[name]) == 0 {
			return fmt.Errorf("missing or unbounded native archive: %s", name)
		}
		for _, filename := range archives[name] {
			if err := checkNativeArchive(artifacts, filename, size, archive["sha256"].(string)); err != nil {
				return err
			}
		}
		platforms = append(platforms, row)
	}

	scratch, err := os.MkdirTemp(artifacts, ".native-index-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	sourceArchive, err := stageNativeSourceArchive(ctx, root, scratch, source, platforms)
	if err != nil {
		return err
	}
	legal, err := nativeLegalFiles(root)
	if err != nil {
		return err
	}
	jobsPath := fmt.Sprintf("repos/%s/actions/runs/%s/attempts/%s/jobs", repository, runID, attempt)
	jobs, err := githubPages[map[string]any](read, jobsPath, "jobs", 1000)
	if err != nil {
		return err
	}
	producer["nativeJobs"], err = selectNativeJobs(jobs, source, runID, attempt)
	if err != nil {
		return err
	}
	index := map[string]any{
		"schema": "polaris-upstream-native-assets-v1", "repository": repository, "repositoryId": json.Number(repositoryID),
		"version": version, "tag": tag, "tagObject": tagObject, "sourceCommit": source, "sourceTree": tree,
		"producer": producer, "legalFiles": legal, "sourceArchive": sourceArchive, "platforms": platforms,
	}
	index["distributionMaterials"], err = distributionMaterials(index, root, downloadOwnedReplacement)
	if err != nil {
		return err
	}
	if _, err := verifyCheckout(root, tag, source, tagObject, read); err != nil {
		return err
	}
	if err := validateSchema(schema, "", index); err != nil {
		return err
	}
	var document bytes.Buffer
	if err := writeJSON(&document, index); err != nil {
		return err
	}
	if document.Len() > publisherJSONLimit {
		return fmt.Errorf("final native index exceeds byte bound")
	}
	if err := os.WriteFile(filepath.Join(scratch, publisherIndexFile), document.Bytes(), 0o644); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return installNativeIndex(scratch, artifacts, sourceArchive["name"].(string))
}

func checkNativeArchive(root, name string, size int64, hash string) error {
	file, err := openNativeSource(root, name)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("native archive size mismatch: %s", name)
	}
	digest := sha256.New()
	measured, err := io.Copy(digest, io.LimitReader(file, size+1))
	if err != nil {
		return err
	}
	if measured != size || hex.EncodeToString(digest.Sum(nil)) != hash {
		return fmt.Errorf("native archive hash mismatch: %s", name)
	}
	return nil
}

func nativeLegalFiles(root string) ([]any, error) {
	legal := []any{}
	add := func(source, name string) error {
		data, err := readNativeSource(root, source)
		if err != nil {
			return err
		}
		if !utf8.Valid(data) {
			return fmt.Errorf("native legal file is not UTF-8: %s", source)
		}
		legal = append(legal, map[string]any{
			"path": name, "content": string(data), "bytes": json.Number(strconv.Itoa(len(data))), "sha256": sha256Hex(data),
		})
		return nil
	}
	if err := add("LICENSE", "licenses/LICENSE"); err != nil {
		return nil, err
	}
	if err := add("release/licenses/NOTICE", "licenses/NOTICE"); err != nil {
		return nil, err
	}
	// The signed array order is the old Path sorting order. WalkDir orders
	// siblings, which also keeps each directory's contents next to each other.
	err := fs.WalkDir(os.DirFS(root), "release/licenses", func(filename string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() == "NOTICE" {
			return err
		}
		return add(filename, strings.TrimPrefix(filename, "release/"))
	})
	return legal, err
}

var nativeSourceModules = [...]struct{ name, field string }{
	{"go.mod", "goModSha256"}, {"go.sum", "goSumSha256"},
}

func stageNativeSourceArchive(ctx context.Context, root, stage, source string, platforms []any) (map[string]any, error) {
	expected := make(map[string]string, len(nativeSourceModules))
	for _, module := range nativeSourceModules {
		actual, err := readNativeSource(root, module.name)
		if err != nil {
			return nil, err
		}
		committed, err := git(root, "show", source+":"+module.name)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(actual, committed) {
			return nil, fmt.Errorf("%s working-tree bytes differ from HEAD blob", module.name)
		}
		expected[module.field] = sha256Hex(committed)
	}
	prefix := "sing-box-polaris-source-" + source
	name := prefix + ".tar.gz"
	file, err := os.Create(filepath.Join(stage, name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	digest := sha256.New()
	command := exec.CommandContext(ctx, "git", "-c", "tar.tar.gz.command=git archive gzip", "archive",
		"--format=tar.gz", "-9", "--prefix="+prefix+"/", source)
	command.Dir = root
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	copyErr := copyNativeGzip(io.MultiWriter(file, digest), stream)
	stream.Close()
	if err := errors.Join(copyErr, command.Wait()); err != nil {
		return nil, fmt.Errorf("git archive: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := validateNativeSourceArchive(file, prefix, platforms, expected); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return map[string]any{"name": name, "bytes": json.Number(strconv.FormatInt(info.Size(), 10)), "sha256": hex.EncodeToString(digest.Sum(nil))}, nil
}

func copyNativeGzip(output io.Writer, input io.Reader) error {
	var header [10]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return err
	}
	if !bytes.Equal(header[:9], []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2}) {
		return fmt.Errorf("unexpected git archive gzip header")
	}
	// Both producers use zlib level 9 without a filename or timestamp.
	// Keep the canonical OS=unknown byte so the archive has no host marker.
	header[9] = 255
	size, err := io.Copy(output, io.LimitReader(io.MultiReader(bytes.NewReader(header[:]), input), publisherScratchLimit+1))
	if err != nil {
		return err
	}
	if size > publisherScratchLimit {
		return fmt.Errorf("native source gzip exceeds byte bound")
	}
	return nil
}

func validateNativeSourceArchive(input io.Reader, prefix string, platforms []any, expected map[string]string) error {
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer compressed.Close()
	bounded := &io.LimitedReader{R: compressed, N: publisherScratchLimit + 1}
	archive := tar.NewReader(bounded)
	archived := make(map[string]string, len(nativeSourceModules))
	for {
		entry, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		for _, module := range nativeSourceModules {
			if entry.Name != prefix+"/"+module.name {
				continue
			}
			if _, duplicate := archived[module.field]; duplicate || entry.Typeflag != tar.TypeReg || entry.Size > publisherJSONLimit {
				return fmt.Errorf("ambiguous or unbounded archived source module: %s", entry.Name)
			}
			digest := sha256.New()
			if _, err := io.Copy(digest, archive); err != nil {
				return err
			}
			archived[module.field] = hex.EncodeToString(digest.Sum(nil))
		}
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return err
	}
	if bounded.N == 0 {
		return fmt.Errorf("native source tar exceeds byte bound")
	}
	if !maps.Equal(archived, expected) {
		return fmt.Errorf("archived module bytes differ from checked source")
	}
	for _, item := range platforms {
		row := item.(map[string]any)
		identity, _ := row["sourceIdentity"].(map[string]any)
		for key, digest := range archived {
			if identity[key] != digest {
				return fmt.Errorf("native row module identity differs from archived source: %s", row["id"])
			}
		}
	}
	return nil
}

func installNativeIndex(stage, destination, sourceName string) error {
	source := filepath.Join(destination, sourceName)
	previous := filepath.Join(stage, "previous-source")
	_, statErr := os.Lstat(source)
	if statErr == nil {
		if err := os.Link(source, previous); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := os.Rename(filepath.Join(stage, sourceName), source); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(stage, publisherIndexFile), filepath.Join(destination, publisherIndexFile)); err != nil {
		if statErr == nil {
			return errors.Join(err, os.Rename(previous, source))
		}
		return errors.Join(err, os.Remove(source))
	}
	return nil
}
