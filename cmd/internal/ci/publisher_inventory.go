package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type publisherRunMetadata struct {
	Repository struct {
		ID int64 `json:"id"`
	} `json:"repository"`
	HeadRepository struct {
		ID int64 `json:"id"`
	} `json:"head_repository"`
	HeadSHA      string `json:"head_sha"`
	Path         string `json:"path"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	Event        string `json:"event"`
	Attempt      int    `json:"run_attempt"`
	RunStartedAt string `json:"run_started_at"`
}

type publisherArtifactMetadata struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size_in_bytes"`
	Digest      string `json:"digest"`
	Expired     *bool  `json:"expired"`
	CreatedAt   string `json:"created_at"`
	WorkflowRun struct {
		ID      int64  `json:"id"`
		HeadSHA string `json:"head_sha"`
	} `json:"workflow_run"`
}

type publisherFile struct {
	Bytes                 int64          `json:"bytes"`
	SHA256                string         `json:"sha256"`
	ReleaseName           *string        `json:"releaseName"`
	Disposition           string         `json:"publicationDisposition"`
	DistributionMaterials map[string]any `json:"distributionMaterials,omitempty"`
}

// A reviewed private record has an explicit null name. Keep missing fields
// distinguishable from that null and from a genuine zero-length member.
func (file *publisherFile) UnmarshalJSON(raw []byte) error {
	type equivalent publisherFile
	input := struct {
		*equivalent
		Length *int64          `json:"bytes"`
		Name   json.RawMessage `json:"releaseName"`
	}{equivalent: (*equivalent)(file)}
	if err := uniqueJSON(bytes.NewReader(raw), &input); err != nil {
		return err
	}
	if input.Length == nil || input.Name == nil {
		return fmt.Errorf("reviewed file size or release name missing")
	}
	file.Bytes = *input.Length
	return json.Unmarshal(input.Name, &file.ReleaseName)
}

type publisherArtifact struct {
	ID            int64                     `json:"id"`
	ArchiveBytes  int64                     `json:"archiveBytes"`
	ArchiveSHA256 string                    `json:"archiveSha256"`
	Files         map[string]*publisherFile `json:"files"`
	fileOrder     []string
}

type publisherRun struct {
	ID            string                        `json:"id"`
	Attempt       int                           `json:"attempt"`
	Workflow      string                        `json:"workflow"`
	Artifacts     map[string]*publisherArtifact `json:"artifacts"`
	artifactOrder []string
}

type publisherInventory struct {
	Repository            string                   `json:"repository"`
	RepositoryID          int64                    `json:"repositoryId"`
	Version               string                   `json:"version"`
	SourceCommit          string                   `json:"sourceCommit"`
	ScopeSHA256           string                   `json:"scopeSha256"`
	Reviewed              bool                     `json:"reviewed"`
	Runs                  map[string]*publisherRun `json:"runs"`
	SourceTree            string                   `json:"sourceTree"`
	Tag                   string                   `json:"tag"`
	TagObject             string                   `json:"tagObject"`
	DistributionMaterials map[string]any           `json:"distributionMaterials"`
}

type publisherNativeArchive struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type publisherScope struct {
	Workflow string `json:"workflow"`
	Rules    map[string][]struct {
		Pattern string `json:"pattern"`
		Count   int    `json:"count"`
		match   *regexp.Regexp
	} `json:"payloadRules"`
}

var (
	publisherLiteralVersion = regexp.MustCompile(`polaris\\?-(?:alpha|beta|rc)\\?\.\d+`)
	publisherTemplateToken  = regexp.MustCompile(`\{[A-Za-z_]\w*\}`)
)

func publisherReleaseScope(version string) (publisherScope, string, error) {
	var scopes map[string]publisherScope
	data, err := os.ReadFile(publisherScopeFile)
	if err != nil {
		return publisherScope{}, "", err
	}
	if err := uniqueJSON(bytes.NewReader(data), &scopes); err != nil {
		return publisherScope{}, "", err
	}
	scope, ok := scopes["all"]
	if !ok || scope.Workflow == "" || len(scope.Rules) == 0 {
		return publisherScope{}, "", fmt.Errorf("all producer scope missing")
	}
	for _, current := range scopes {
		for _, rules := range current.Rules {
			for i := range rules {
				rule := &rules[i]
				if strings.Count(rule.Pattern, "{version}") > 1 || publisherLiteralVersion.MatchString(rule.Pattern) ||
					publisherTemplateToken.MatchString(strings.ReplaceAll(rule.Pattern, "{version}", "")) || rule.Count <= 0 {
					return publisherScope{}, "", fmt.Errorf("invalid producer scope version template or count")
				}
				pattern := strings.ReplaceAll(rule.Pattern, "{version}", regexp.QuoteMeta(version))
				rule.match, err = regexp.Compile("^(?:" + pattern + ")$")
				if err != nil {
					return publisherScope{}, "", err
				}
			}
		}
	}
	return scope, sha256Hex(data), nil
}

func producerEvidenceFile(member string) bool {
	basename := path.Base(member)
	return strings.HasPrefix(basename, "polaris-candidate-manifest-") || strings.HasPrefix(basename, "native-row-")
}

func (p *publisher) publication(artifact, member string) (*string, string, error) {
	if producerEvidenceFile(member) || artifact == "publisher-run-receipt" || artifact == "native-controlled-peer" {
		return nil, "producer-evidence", nil
	}
	if artifact == publisherIndexArtifact {
		return nil, "audited-source-and-index", nil
	}
	if !strings.HasPrefix(artifact, "binary-") {
		return nil, "", fmt.Errorf("unknown public artifact: %s", artifact)
	}
	name, err := publicProductName(path.Base(member))
	if err != nil {
		return nil, "", err
	}
	if !strings.HasPrefix(name, "sing-box-polaris-") || strings.Count(name, p.version) != 1 {
		return nil, "", fmt.Errorf("unknown public product filename or exact Polaris version: %s", name)
	}
	name = strings.Replace(name, p.version, p.publicVersion, 1)
	return &name, "upstream-public-product", nil
}

func (scope publisherScope) verifyFiles(artifact string, files map[string]*publisherFile) error {
	payloads := make(map[string]bool)
	for member := range files {
		if !producerEvidenceFile(member) {
			payloads[member] = false
		}
	}
	if strings.HasPrefix(artifact, "smoke-") {
		if len(payloads) != 0 || len(files) != 1 {
			return fmt.Errorf("smoke evidence scope mismatch")
		}
		return nil
	}
	matched := 0
	for _, rule := range scope.Rules[artifact] {
		count := 0
		for member, alreadyMatched := range payloads {
			if rule.match.MatchString(member) {
				if alreadyMatched {
					return fmt.Errorf("overlapping package/file scope: %s", artifact)
				}
				payloads[member] = true
				count++
			}
		}
		if count != rule.Count {
			return fmt.Errorf("required package/file scope mismatch: %s", artifact)
		}
		matched += count
	}
	if matched != len(payloads) {
		return fmt.Errorf("unlisted payload file in %s", artifact)
	}
	return nil
}

func (p *publisher) artifactInventory(metadata publisherArtifactMetadata, attempt int, producerReceipt *map[string]any) (*publisherArtifact, error) {
	record := &publisherArtifact{
		ID: metadata.ID, ArchiveBytes: metadata.Size, ArchiveSHA256: metadata.Digest,
		Files: make(map[string]*publisherFile),
	}
	err := p.withArchive(metadata, func(archive *artifactZIP) error {
		for _, member := range archive.members {
			relative := member.Name
			if strings.HasSuffix(relative, "/") {
				if _, err := publisherMember(archive, member, nil, 0, nil); err != nil {
					return err
				}
				continue
			}
			p.storage.state["member"] = relative
			name, disposition, err := p.publication(metadata.Name, relative)
			if err != nil {
				return err
			}
			var provenance map[string]any
			var evidence any
			candidate := strings.HasPrefix(path.Base(relative), "polaris-candidate-manifest-")
			isReceipt := metadata.Name == "publisher-run-receipt" && relative == "publisher-run-receipt.json"
			if candidate || isReceipt || metadata.Name == publisherIndexArtifact && relative == publisherIndexFile {
				evidence = &provenance
			}
			var measured readResult
			measure := func(destination io.Writer) error {
				var err error
				measured, err = publisherMember(archive, member, destination, publisherJSONLimit, evidence)
				return err
			}
			if metadata.Name == publisherIndexArtifact {
				target := p.retainedNative(relative)
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return err
				}
				if err := p.storage.retained(target, int64(member.UncompressedSize64), "retained "+relative, measure); err != nil {
					return err
				}
			} else if err := measure(nil); err != nil {
				return err
			}
			if candidate && (provenance["sourceCommit"] != p.source || fmt.Sprint(provenance["workflowRunId"]) != p.allRun ||
				fmt.Sprint(provenance["workflowAttempt"]) != strconv.Itoa(attempt)) {
				return fmt.Errorf("candidate manifest source/run mismatch")
			}
			if isReceipt {
				*producerReceipt = provenance
			}
			record.Files[relative] = &publisherFile{Bytes: measured.Bytes, SHA256: measured.SHA256, ReleaseName: name, Disposition: disposition}
			record.fileOrder = append(record.fileOrder, relative)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(record.Files) == 0 {
		return nil, fmt.Errorf("empty artifact")
	}
	return record, nil
}

func (p *publisher) inventory() (*publisherInventory, error) {
	scope, scopeSHA, err := publisherReleaseScope(p.version)
	if err != nil {
		return nil, err
	}
	runPath := publisherRepositoryPath + "/actions/runs/" + p.allRun
	var run publisherRunMetadata
	if err := p.get(runPath, &run); err != nil {
		return nil, err
	}
	if strconv.FormatInt(run.Repository.ID, 10) != repositoryID || strconv.FormatInt(run.HeadRepository.ID, 10) != repositoryID {
		return nil, fmt.Errorf("foreign run")
	}
	if run.HeadSHA != p.source || run.Path != scope.Workflow {
		return nil, fmt.Errorf("wrong source or workflow")
	}
	if run.Status != "completed" || run.Conclusion != "success" || run.Event != "workflow_dispatch" || run.Attempt < 1 {
		return nil, fmt.Errorf("unsuccessful or non-dispatched input run")
	}
	artifacts, err := publisherPages[publisherArtifactMetadata](p, runPath+"/artifacts", "artifacts", 0)
	if err != nil {
		return nil, err
	}
	names, ids := map[string]bool{}, map[int64]bool{}
	for _, artifact := range artifacts {
		if _, exists := scope.Rules[artifact.Name]; !exists || names[artifact.Name] || artifact.ID <= 0 || ids[artifact.ID] {
			return nil, fmt.Errorf("duplicate or unexpected Actions artifact: %s", artifact.Name)
		}
		names[artifact.Name], ids[artifact.ID] = true, true
	}
	if len(names) != len(scope.Rules) {
		return nil, fmt.Errorf("incomplete Actions artifact scope")
	}
	start, err := time.Parse(time.RFC3339Nano, run.RunStartedAt)
	if err != nil {
		return nil, err
	}
	runID, err := strconv.ParseInt(p.allRun, 10, 64)
	if err != nil {
		return nil, err
	}
	entry := &publisherRun{ID: p.allRun, Attempt: run.Attempt, Workflow: run.Path, Artifacts: make(map[string]*publisherArtifact)}
	var receipt map[string]any
	for _, artifact := range artifacts {
		created, err := time.Parse(time.RFC3339Nano, artifact.CreatedAt)
		if artifact.Expired == nil || *artifact.Expired || err != nil || created.Before(start) ||
			artifact.WorkflowRun.ID != runID || artifact.WorkflowRun.HeadSHA != p.source {
			return nil, fmt.Errorf("expired, stale or foreign artifact: %s", artifact.Name)
		}
		record, err := p.artifactInventory(artifact, run.Attempt, &receipt)
		if err != nil {
			return nil, err
		}
		if err := scope.verifyFiles(artifact.Name, record.Files); err != nil {
			return nil, err
		}
		entry.Artifacts[artifact.Name] = record
		entry.artifactOrder = append(entry.artifactOrder, artifact.Name)
	}

	expected := map[string]any{
		"repository": repository, "repositoryId": json.Number(repositoryID), "sourceCommit": p.source,
		"runId": p.allRun, "attempt": json.Number(strconv.Itoa(run.Attempt)), "version": p.version, "build": "All", "role": "all",
	}
	if !reflect.DeepEqual(receipt, expected) {
		return nil, fmt.Errorf("producer scope/input receipt missing or inconsistent")
	}
	repoID, _ := strconv.ParseInt(repositoryID, 10, 64)
	result := &publisherInventory{
		Repository: repository, RepositoryID: repoID, Version: p.version, SourceCommit: p.source,
		ScopeSHA256: scopeSHA, Runs: map[string]*publisherRun{"all": entry}, SourceTree: p.sourceTree, Tag: p.tag, TagObject: p.tagObject,
	}
	jobs := func() ([]map[string]any, error) {
		return publisherPages[map[string]any](p, fmt.Sprintf("%s/attempts/%d/jobs", runPath, run.Attempt), "jobs", 1000)
	}
	if err := p.bindNativeIndex(result, runID, jobs); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *publisher) retainedNative(name string) string {
	return filepath.Join(p.storage.root, "all", publisherIndexArtifact, filepath.FromSlash(name))
}

func (p *publisher) copyNativeAudit() error {
	files, err := os.ReadDir(p.retainedNative(""))
	if err != nil {
		return err
	}
	for _, file := range files {
		if !file.IsDir() {
			if err := p.storage.copy(p.retainedNative(file.Name()), filepath.Join(p.audit, file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *publisher) bindNativeIndex(result *publisherInventory, runID int64, jobs func() ([]map[string]any, error)) error {
	filename := p.retainedNative(publisherIndexFile)
	input, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer input.Close()
	run := result.Runs["all"]
	if err := p.validateNative(input, p.sourceRoot, p.source, p.sourceTree, p.tag, p.tagObject, runID, run.Attempt, run.Workflow, jobs); err != nil {
		return err
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var index struct {
		Platforms             []struct{ Archive publisherNativeArchive } `json:"platforms"`
		SourceArchive         map[string]any                             `json:"sourceArchive"`
		DistributionMaterials map[string]any                             `json:"distributionMaterials"`
	}
	if err := uniqueJSON(input, &index); err != nil {
		return err
	}
	records := make([]publisherNativeArchive, 0, len(index.Platforms)+1)
	for _, row := range index.Platforms {
		records = append(records, row.Archive)
	}
	sourceSize, ok := index.SourceArchive["bytes"].(json.Number)
	if !ok {
		return fmt.Errorf("source archive byte count missing")
	}
	bytes, err := sourceSize.Int64()
	if err != nil {
		return err
	}
	sourceName, _ := index.SourceArchive["name"].(string)
	sourceSHA, _ := index.SourceArchive["sha256"].(string)
	records = append(records, publisherNativeArchive{sourceName, sourceSHA, bytes})
	seen := make(map[string]bool)
	for _, record := range records {
		if seen[record.Name] {
			return fmt.Errorf("duplicate native index name")
		}
		seen[record.Name] = true
		var matches []*publisherFile
		for _, artifact := range run.Artifacts {
			if file := artifact.Files[record.Name]; file != nil {
				matches = append(matches, file)
			}
		}
		if len(matches) != 1 || matches[0].SHA256 != record.SHA256 || matches[0].Bytes != record.Bytes {
			return fmt.Errorf("native index actual hash mismatch")
		}
	}
	indexSHA := run.Artifacts[publisherIndexArtifact].Files[publisherIndexFile].SHA256
	binding, err := nativeCanonicalJSON(index.DistributionMaterials)
	if err != nil {
		return err
	}
	result.DistributionMaterials = map[string]any{
		"sourceArchive": index.SourceArchive,
		"noticeIndex":   map[string]any{"name": publisherIndexFile, "sha256": indexSHA}, "bindingSHA256": sha256Hex(binding),
	}
	for _, artifact := range run.Artifacts {
		for _, file := range artifact.Files {
			if file.ReleaseName != nil {
				file.DistributionMaterials = result.DistributionMaterials
			}
		}
	}
	return nil
}

func (p *publisher) reviewedInventory() (*publisherInventory, error) {
	if !publisherPositiveID.MatchString(p.inventoryRun) || !cronetSHA256.MatchString(p.inventorySHA) {
		return nil, fmt.Errorf("inventory run ID and explicit reviewed inventory SHA-256 required")
	}
	endpoint := publisherRepositoryPath + "/actions/runs/" + p.inventoryRun
	var run publisherRunMetadata
	if err := p.get(endpoint, &run); err != nil {
		return nil, err
	}
	if strconv.FormatInt(run.Repository.ID, 10) != repositoryID || strconv.FormatInt(run.HeadRepository.ID, 10) != repositoryID ||
		run.Path != publisherWorkflow || run.HeadSHA != os.Getenv("GITHUB_SHA") || run.Status != "completed" || run.Conclusion != "success" {
		return nil, fmt.Errorf("foreign, failed or mismatched inventory run")
	}
	artifacts, err := publisherPages[publisherArtifactMetadata](p, endpoint+"/artifacts", "artifacts", 0)
	if err != nil {
		return nil, err
	}
	matches := slices.DeleteFunc(artifacts, func(artifact publisherArtifactMetadata) bool { return artifact.Name != "github-release-validation" })
	if len(matches) != 1 || matches[0].Expired == nil || *matches[0].Expired {
		return nil, fmt.Errorf("inventory artifact missing, ambiguous or expired")
	}
	var proposal *publisherInventory
	err = p.withArchive(matches[0], func(archive *artifactZIP) error {
		for _, member := range archive.members {
			var evidence any
			if member.Name == "release-inventory-proposal.json" {
				evidence = &proposal
			}
			measured, err := publisherMember(archive, member, nil, publisherProposalLimit, evidence)
			if err != nil {
				return err
			}
			if evidence != nil && measured.SHA256 != p.inventorySHA {
				return fmt.Errorf("inventory differs from explicitly reviewed hash")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if proposal == nil || proposal.SourceCommit != p.source {
		return nil, fmt.Errorf("reviewed proposal missing or source differs")
	}
	proposal.Reviewed = true
	return proposal, nil
}
