package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type publisherAsset struct {
	publisherFile
	Role           string `json:"role"`
	Artifact       string `json:"artifact"`
	ArtifactPath   string `json:"artifactPath"`
	SignatureState string `json:"signatureState"`
}

type publisherReceiptDocument struct {
	*publisherInventory
	SignatureState    string           `json:"signatureState"`
	FullSignedRelease bool             `json:"fullSignedRelease"`
	Assets            []publisherAsset `json:"assets"`
}

func (p *publisher) assemble(actual, review *publisherInventory) (*publisherReceiptDocument, error) {
	if !review.Reviewed || !reflect.DeepEqual(actual.DistributionMaterials, review.DistributionMaterials) {
		return nil, fmt.Errorf("public release scope or reviewed shared materials differ")
	}
	if actual.Repository != review.Repository || actual.RepositoryID != review.RepositoryID || actual.Version != review.Version ||
		actual.SourceCommit != review.SourceCommit || actual.SourceTree != review.SourceTree || actual.Tag != review.Tag ||
		actual.TagObject != review.TagObject || actual.ScopeSHA256 != review.ScopeSHA256 {
		return nil, fmt.Errorf("release contract identity differs")
	}
	run, reviewedRun := actual.Runs["all"], review.Runs["all"]
	if len(review.Runs) != 1 || reviewedRun == nil || run.ID != reviewedRun.ID || run.Attempt != reviewedRun.Attempt ||
		len(run.Artifacts) != len(reviewedRun.Artifacts) {
		return nil, fmt.Errorf("reviewed run identity or artifact scope differs")
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(p.output))
	if err != nil {
		return nil, err
	}
	output, err := filepath.Abs(filepath.Join(outputParent, filepath.Base(p.output)))
	if err != nil {
		return nil, err
	}
	audit, err := filepath.EvalSymlinks(p.audit)
	if err != nil {
		return nil, err
	}
	audit, err = filepath.Abs(audit)
	if err != nil {
		return nil, err
	}
	if contains, err := filepath.Rel(output, audit); err != nil || contains == "." || contains != ".." && !strings.HasPrefix(contains, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("audit must be outside public dist")
	}
	if err := os.Mkdir(p.output, 0o755); err != nil {
		return nil, err
	}

	receipt := &publisherReceiptDocument{publisherInventory: actual, SignatureState: "unsigned-builds"}
	destinations := make(map[string]bool)
	for _, artifactName := range run.artifactOrder {
		artifact, expected := run.Artifacts[artifactName], reviewedRun.Artifacts[artifactName]
		if expected == nil || artifact.ID != expected.ID || artifact.ArchiveSHA256 != expected.ArchiveSHA256 ||
			artifact.ArchiveBytes != expected.ArchiveBytes || len(artifact.Files) != len(expected.Files) {
			return nil, fmt.Errorf("reviewed artifact identity or file scope differs: %s", artifactName)
		}
		for _, relative := range artifact.fileOrder {
			file, reviewed := artifact.Files[relative], expected.Files[relative]
			if reviewed == nil || file.Bytes != reviewed.Bytes || file.SHA256 != reviewed.SHA256 {
				return nil, fmt.Errorf("actual file hash differs: %s", relative)
			}
			if !reflect.DeepEqual(file.DistributionMaterials, reviewed.DistributionMaterials) {
				return nil, fmt.Errorf("reviewed per-payload materials differ: %s", relative)
			}
			name, disposition, err := p.publication(artifactName, relative)
			if err != nil {
				return nil, err
			}
			if !reflect.DeepEqual(name, file.ReleaseName) || !reflect.DeepEqual(name, reviewed.ReleaseName) {
				return nil, fmt.Errorf("public filename differs from source-owned mapping: %s", relative)
			}
			if disposition != file.Disposition || disposition != reviewed.Disposition {
				return nil, fmt.Errorf("publication disposition differs from source-owned mapping: %s", relative)
			}
			if name == nil {
				if disposition == "audited-source-and-index" {
					if err := p.storage.copy(p.retainedNative(relative), filepath.Join(p.audit, path.Base(relative))); err != nil {
						return nil, err
					}
				}
				continue
			}
			portable, err := portableArtifactPath(*name)
			key := strings.ToLower(*name)
			if err != nil || path.Base(portable) != portable || destinations[key] || !strings.Contains(*name, p.publicVersion) || *name == p.receiptFile {
				return nil, fmt.Errorf("invalid or duplicate release filename: %s", *name)
			}
			destinations[key] = true
			receipt.Assets = append(receipt.Assets, publisherAsset{publisherFile: *file, Role: "all", Artifact: artifactName,
				ArtifactPath: relative, SignatureState: "unsigned-candidate"})
		}
	}
	if len(receipt.Assets) == 0 {
		return nil, fmt.Errorf("empty release")
	}
	if err := p.storage.writeJSON(filepath.Join(p.audit, p.receiptFile), receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

type publisherRelease struct {
	ID        int64  `json:"id"`
	Tag       string `json:"tag_name"`
	Draft     *bool  `json:"draft"`
	UploadURL string `json:"upload_url"`
	HTMLURL   string `json:"html_url"`
}

func publisherUploadEndpoint(release publisherRelease, name string) (string, error) {
	if release.ID <= 0 {
		return "", fmt.Errorf("invalid release ID")
	}
	endpoint, err := url.Parse(strings.TrimSuffix(release.UploadURL, "{?name,label}"))
	required := "/" + publisherRepositoryPath + "/releases/" + strconv.FormatInt(release.ID, 10) + "/assets"
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Host != "uploads.github.com" ||
		endpoint.EscapedPath() != required || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.ForceQuery {
		return "", fmt.Errorf("unexpected release upload endpoint")
	}
	basename, err := portableArtifactPath(name)
	if err != nil || basename != path.Base(basename) {
		return "", fmt.Errorf("upload filename must be a basename")
	}
	endpoint.RawQuery = "name=" + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
	return endpoint.String(), nil
}

func (p *publisher) uploadAssets(actual *publisherInventory, send func(string, string) error) error {
	run := actual.Runs["all"]
	runID, err := strconv.ParseInt(run.ID, 10, 64)
	if err != nil {
		return err
	}
	for _, name := range run.artifactOrder {
		expected := run.Artifacts[name]
		hasPublic := false
		for _, relative := range expected.fileOrder {
			file := expected.Files[relative]
			mapped, disposition, err := p.publication(name, relative)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(mapped, file.ReleaseName) || disposition != file.Disposition {
				return fmt.Errorf("public ZIP mapping changed")
			}
			hasPublic = hasPublic || file.ReleaseName != nil
		}
		if !hasPublic {
			continue
		}
		var metadata publisherArtifactMetadata
		if err := p.get(publisherRepositoryPath+"/actions/artifacts/"+strconv.FormatInt(expected.ID, 10), &metadata); err != nil {
			return err
		}
		if metadata.ID != expected.ID || metadata.Name != name || metadata.Digest != expected.ArchiveSHA256 || metadata.Size != expected.ArchiveBytes {
			return fmt.Errorf("public ZIP identity changed")
		}
		if metadata.Expired == nil || *metadata.Expired || metadata.WorkflowRun.ID != runID || metadata.WorkflowRun.HeadSHA != actual.SourceCommit {
			return fmt.Errorf("public ZIP expired or source changed")
		}
		if err := p.withArchive(metadata, func(archive *artifactZIP) error {
			files := 0
			for _, member := range archive.members {
				if !strings.HasSuffix(member.Name, "/") {
					if expected.Files[member.Name] == nil {
						return fmt.Errorf("public ZIP member scope changed")
					}
					files++
				}
			}
			if files != len(expected.Files) {
				return fmt.Errorf("public ZIP member scope changed")
			}
			for _, member := range archive.members {
				p.storage.state["member"] = member.Name
				if strings.HasSuffix(member.Name, "/") {
					if _, err := publisherMember(archive, member, nil, 0, nil); err != nil {
						return err
					}
					continue
				}
				file := expected.Files[member.Name]
				measure := func(destination io.Writer) error {
					measured, err := publisherMember(archive, member, destination, 0, nil)
					if err != nil {
						return err
					}
					if measured.Bytes != file.Bytes || measured.SHA256 != file.SHA256 {
						return fmt.Errorf("reviewed ZIP member bytes changed: %s", member.Name)
					}
					return nil
				}
				if file.ReleaseName == nil {
					if err := measure(nil); err != nil {
						return err
					}
					continue
				}
				if err := p.storage.temporary(int64(member.UncompressedSize64), "upload "+*file.ReleaseName, func(staged *os.File) error {
					if err := measure(staged); err != nil {
						return err
					}
					return send(*file.ReleaseName, staged.Name())
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (p *publisher) publish(actual *publisherInventory, receipt *publisherReceiptDocument) error {
	before, err := p.currentTag()
	if err != nil {
		return err
	}
	var index map[string]any
	if err := publisherReadJSON(filepath.Join(p.audit, publisherIndexFile), &index); err != nil {
		return err
	}
	if err := validatePublicationIndex(index, p.source, p.tag, before, ""); err != nil {
		return err
	}
	releasesPath := publisherRepositoryPath + "/releases"
	releases, err := publisherPages[publisherRelease](p, releasesPath, "", 0)
	if err != nil {
		return err
	}
	for _, release := range releases {
		if release.Tag == p.tag {
			return fmt.Errorf("existing Release (including draft) will never be changed")
		}
	}
	expected := make(map[string]publisherAsset, len(receipt.Assets))
	var stagingPeak int64
	for _, asset := range receipt.Assets {
		if asset.ReleaseName == nil || expected[*asset.ReleaseName].ReleaseName != nil {
			return fmt.Errorf("empty or duplicate public receipt")
		}
		expected[*asset.ReleaseName] = asset
		archiveSize := actual.Runs["all"].Artifacts[asset.Artifact].ArchiveBytes
		if asset.Bytes > p.storage.limit-archiveSize {
			return fmt.Errorf("scratch budget exceeded: maximum single ZIP plus public member before draft creation")
		}
		stagingPeak = max(stagingPeak, archiveSize+asset.Bytes)
	}
	if len(expected) == 0 {
		return fmt.Errorf("empty public receipt")
	}
	if err := p.storage.admit(stagingPeak, "maximum single ZIP plus public member before draft creation"); err != nil {
		return err
	}
	p.storage.live -= stagingPeak
	notes := "GitHub-only unsigned native core prerelease from " + p.source + ".\n\n" +
		"sing-box-polaris is a derivative of the fixed SagerNet upstream, not an official SagerNet release. Original authors and license texts are retained. The validated producer inventory, source index and publication mapping are retained in the publisher Actions audit artifact.\n\n" +
		"Audit: https://github.com/" + repository + "/actions/runs/" + os.Getenv("GITHUB_RUN_ID")
	p.storage.record(map[string]any{"phase": "draft", "remoteWriteState": "draft-create-outcome-unknown"})
	var release publisherRelease
	if err := publisherWriteRelease(p.ctx, "POST", releasesPath, map[string]any{
		"tag_name": p.tag, "target_commitish": p.source, "name": p.tag, "body": notes, "draft": true, "prerelease": true,
	}, &release); err != nil {
		return err
	}
	p.storage.record(map[string]any{"phase": "upload", "remoteWriteState": "draft-created", "releaseId": release.ID})
	if err := p.uploadAssets(actual, func(name, filename string) error {
		if err := p.requireTag("tag changed before upload; retained as draft"); err != nil {
			return err
		}
		endpoint, err := publisherUploadEndpoint(release, name)
		if err != nil {
			return err
		}
		p.storage.record(map[string]any{"remoteWriteState": "upload-outcome-unknown", "member": name})
		command := exec.CommandContext(p.ctx, "gh", "api", "--method", "POST", endpoint,
			"-H", "Content-Type: application/octet-stream", "--input", filename)
		if err := command.Run(); err != nil {
			return fmt.Errorf("release asset upload failed: %w", err)
		}
		p.storage.record(map[string]any{"remoteWriteState": "draft-uploaded-member", "member": name})
		return nil
	}); err != nil {
		return err
	}

	releasePath := releasesPath + "/" + strconv.FormatInt(release.ID, 10)
	var checked publisherRelease
	if err := p.get(releasePath, &checked); err != nil {
		return err
	}
	type uploadedAsset struct {
		Name   string
		State  string
		Digest string
		Size   int64
	}
	assets, err := publisherPages[uploadedAsset](p, releasePath+"/assets", "", 0)
	if err != nil {
		return err
	}
	if checked.Draft == nil || !*checked.Draft || checked.Tag != p.tag {
		return fmt.Errorf("draft state changed")
	}
	if len(assets) != len(expected) {
		return fmt.Errorf("remote asset scope mismatch; retained as draft")
	}
	seen := make(map[string]bool, len(assets))
	for _, asset := range assets {
		planned, found := expected[asset.Name]
		if !found || seen[asset.Name] || asset.State != "uploaded" || asset.Size != planned.Bytes || asset.Digest != "sha256:"+planned.SHA256 {
			return fmt.Errorf("remote bytes, hash or scope mismatch; retained as draft")
		}
		seen[asset.Name] = true
	}
	if err := p.requireTag("tag changed; retained as draft"); err != nil {
		return err
	}
	releases, err = publisherPages[publisherRelease](p, releasesPath, "", 0)
	if err != nil {
		return err
	}
	count := 0
	for _, item := range releases {
		if item.Tag == p.tag {
			if item.ID != release.ID {
				return fmt.Errorf("competing release; retained as draft")
			}
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("competing release; retained as draft")
	}
	p.storage.record(map[string]any{"phase": "finalize", "remoteWriteState": "finalization-outcome-unknown"})
	var finalized publisherRelease
	if err := publisherWriteRelease(p.ctx, "PATCH", releasePath, map[string]any{"draft": false, "make_latest": "false"}, &finalized); err != nil {
		var observed publisherRelease
		if readErr := p.get(releasePath, &observed); readErr == nil {
			p.storage.record(map[string]any{"remoteWriteState": "finalization-readback", "observedDraft": observed.Draft, "observedTag": observed.Tag})
		}
		return err
	}
	if finalized.Draft == nil || *finalized.Draft {
		return fmt.Errorf("publication not confirmed")
	}
	p.storage.record(map[string]any{"phase": "complete", "remoteWriteState": "published"})
	fmt.Println(finalized.HTMLURL)
	return nil
}
