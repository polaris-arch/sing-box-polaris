package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/badversion"
)

type candidateFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

var matrixKey = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func recordCandidate(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("record-candidate requires one artifact directory")
	}
	env, err := nativeEnvironment("GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
	if err != nil {
		return err
	}
	root := args[0]
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("missing artifact directory: %s", root)
	}
	// Follow the selected directory, while rejecting symlinks among its members.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	files := []candidateFile{}
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected artifact symlink: %s", filename)
		}
		if !entry.Type().IsRegular() || strings.HasPrefix(entry.Name(), "polaris-candidate-manifest-") {
			return nil
		}
		hash, err := fileSHA256(filename)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		files = append(files, candidateFile{filepath.ToSlash(name), info.Size(), hash})
		return nil
	})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no candidate files")
	}
	if env["GITHUB_REPOSITORY"] != repository || env["GITHUB_REPOSITORY_ID"] != repositoryID {
		return fmt.Errorf("candidate repository identity mismatch")
	}
	job := env["GITHUB_JOB"]
	suffix, set := os.LookupEnv("CANDIDATE_MATRIX_KEY")
	if !set {
		suffix = "default"
	}
	if !matrixKey.MatchString(suffix) {
		return fmt.Errorf("invalid artifact matrix key")
	}
	head, err := git(".", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	tree, err := git(".", "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(repositoryID, 10, 64)
	record := map[string]any{
		"schema": "polaris-upstream-candidate-files-v1", "repository": repository, "repositoryId": id,
		"sourceCommit": strings.TrimSpace(string(head)), "sourceTree": strings.TrimSpace(string(tree)),
		"workflowRunId": env["GITHUB_RUN_ID"], "workflowAttempt": env["GITHUB_RUN_ATTEMPT"],
		"job": job, "matrixKey": suffix, "signatureState": "unsigned-candidate",
		"releasePublication": false, "runtimeAcceptance": false, "files": files,
	}
	return writeJSONFile(filepath.Join(root, "polaris-candidate-manifest-"+job+"-"+suffix+".json"), record)
}

func validateNeeds(generate, source string) error {
	if generate != "true" && generate != "false" {
		return fmt.Errorf("invalid native receipt selection: RECEIPT_SOURCE_GENERATE_ONLY")
	}
	if generate == "true" {
		return fmt.Errorf("source generation is not a complete producer role")
	}
	var value any
	if err := uniqueJSON(strings.NewReader(source), &value); err != nil {
		return err
	}
	needs, ok := value.(map[string]any)
	if !ok || len(needs) == 0 {
		return fmt.Errorf("native direct needs missing")
	}
	for name, value := range needs {
		entry, ok := value.(map[string]any)
		if !ok || len(entry) != 2 {
			return fmt.Errorf("invalid native needs entry: %s", name)
		}
		if _, ok := entry["outputs"].(map[string]any); !ok {
			return fmt.Errorf("invalid native job outputs: %s", name)
		}
		if entry["result"] != "success" {
			return fmt.Errorf("producer job did not reach selected terminal result: %s", name)
		}
	}
	return nil
}

func publisherReceipt(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("publisher-receipt takes native workflow environment only")
	}
	env, err := nativeEnvironment("PUBLISHER_ROLE", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "RELEASE_BUILD",
		"RELEASE_VERSION", "GITHUB_REF", "RECEIPT_SOURCE_GENERATE_ONLY", "NEEDS_JSON", "GITHUB_SHA", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID")
	if err != nil {
		return err
	}
	for name, expected := range map[string]string{
		"PUBLISHER_ROLE": "all", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": repository,
		"GITHUB_REPOSITORY_ID": repositoryID, "RELEASE_BUILD": "All",
	} {
		if env[name] != expected {
			return fmt.Errorf("publisher native context differs: %s", name)
		}
	}
	data, err := os.ReadFile("release/ci/github-release.json")
	if err != nil {
		return err
	}
	var plan struct {
		Repository   string `json:"repository"`
		RepositoryID int64  `json:"repositoryId"`
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return err
	}
	if plan.Repository != repository || strconv.FormatInt(plan.RepositoryID, 10) != repositoryID {
		return fmt.Errorf("publisher repository plan differs")
	}
	version := env["RELEASE_VERSION"]
	if !badversion.IsCanonicalPolaris(version) {
		return fmt.Errorf("expected a canonical Polaris release version")
	}
	if env["GITHUB_REF"] != "refs/tags/v"+version {
		return fmt.Errorf("producer ref must be the release version tag")
	}
	if err := validateNeeds(env["RECEIPT_SOURCE_GENERATE_ONLY"], env["NEEDS_JSON"]); err != nil {
		return err
	}
	head, err := git(".", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	source := strings.TrimSpace(string(head))
	if source != env["GITHUB_SHA"] {
		return fmt.Errorf("producer checkout differs from native dispatch")
	}
	attempt, err := strconv.Atoi(env["GITHUB_RUN_ATTEMPT"])
	if err != nil {
		return err
	}
	return writeJSONFile("publisher-run-receipt.json", map[string]any{
		"repository": repository, "repositoryId": plan.RepositoryID, "sourceCommit": source,
		"runId": env["GITHUB_RUN_ID"], "attempt": attempt,
		"version": version, "build": "All", "role": "all",
	})
}
