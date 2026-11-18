package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/common/badversion"
)

const (
	publisherRepositoryPath = "repos/" + repository
	publisherWorkflow       = ".github/workflows/publish-github.yml"
	publisherIndexFile      = "polaris-upstream-native-assets.json"
	publisherIndexArtifact  = "binary-native-index"
	publisherScopeFile      = "release/ci/publisher-upstream-scope.json"
	publisherJSONLimit      = 32 << 20
	publisherProposalLimit  = 64 << 20
)

var publisherPositiveID = regexp.MustCompile(`^[1-9][0-9]*$`)

type publisherIndexValidator func(io.Reader, string, string, string, string, string, int64, int, string, func() ([]map[string]any, error)) error

type publisher struct {
	ctx                                                                         context.Context
	mode, source, sourceRoot, allRun, inventoryRun, inventorySHA, output, audit string
	tag, version, publicVersion, receiptFile, sourceTree, tagObject             string
	reads                                                                       retryBudget
	storage                                                                     *publisherStorage
	validateNative                                                              publisherIndexValidator
}

func publishGitHub(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runPublisher(ctx, args, validateFinalNativeIndex)
}

func runPublisher(ctx context.Context, args []string, validateNative publisherIndexValidator) error {
	if len(args) == 0 || args[0] != "inventory" && args[0] != "validate" && args[0] != "publish" {
		return fmt.Errorf("expected publish-github inventory, validate or publish")
	}
	p := publisher{ctx: ctx, mode: args[0], validateNative: validateNative}
	flags := flag.NewFlagSet("publish-github "+p.mode, flag.ContinueOnError)
	flags.StringVar(&p.source, "source", "", "exact producer source SHA")
	flags.StringVar(&p.sourceRoot, "source-dir", "reviewed-source", "reviewed producer checkout")
	flags.StringVar(&p.allRun, "all-run", "", "exact producer workflow run")
	flags.StringVar(&p.inventoryRun, "inventory-run", "", "reviewed inventory workflow run")
	flags.StringVar(&p.inventorySHA, "inventory-sha256", "", "reviewed inventory SHA256")
	flags.StringVar(&p.output, "output", "github-release-dist", "inventory proposal or public destination")
	flags.StringVar(&p.audit, "audit", "github-release-audit", "publication audit destination")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected publisher arguments")
	}
	if err := p.identity(); err != nil {
		return err
	}
	if !publisherPositiveID.MatchString(p.allRun) {
		return fmt.Errorf("invalid run ID")
	}
	var run struct {
		HeadBranch string `json:"head_branch"`
	}
	if err := p.get(publisherRepositoryPath+"/actions/runs/"+p.allRun, &run); err != nil {
		return err
	}
	if !strings.HasPrefix(run.HeadBranch, "v") || !badversion.IsCanonicalPolaris(run.HeadBranch[1:]) {
		return fmt.Errorf("build run must be dispatched on a version tag")
	}
	p.tag, p.version = run.HeadBranch, run.HeadBranch[1:]
	p.publicVersion = strings.Replace(p.version, "-polaris-", "-", 1)
	p.receiptFile = "polaris-github-release-receipt-" + p.version + ".json"
	return p.execute()
}

func publisherReadJSON(filename string, result any) error {
	input, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer input.Close()
	return uniqueJSON(input, result)
}

func publisherRemoteJSON(ctx context.Context, endpoint string, result any, budget *retryBudget) error {
	var body bytes.Buffer
	reset := func() error { body.Reset(); return nil }
	if _, err := readGitHubSink(ctx, endpoint, &body, reset, publisherJSONLimit, budget, defaultReadLimits, nil); err != nil {
		return err
	}
	if len(bytes.TrimSpace(body.Bytes())) == 0 {
		return fmt.Errorf("GitHub GET returned no JSON: %s", endpoint)
	}
	return uniqueJSON(&body, result)
}

func (p *publisher) get(endpoint string, result any) error {
	return publisherRemoteJSON(p.ctx, endpoint, result, &p.reads)
}

func publisherPages[T any](p *publisher, endpoint, key string, maximum int) ([]T, error) {
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	var results []T
	for page := 1; page <= 10000; page++ {
		request := fmt.Sprintf("%s%sper_page=100&page=%d", endpoint, separator, page)
		var batch []T
		if key == "" {
			if err := p.get(request, &batch); err != nil {
				return nil, err
			}
		} else {
			// Other envelope fields can hold unrelated scalar values.
			var fields map[string]json.RawMessage
			if err := p.get(request, &fields); err != nil {
				return nil, err
			}
			if fields[key] == nil {
				return nil, fmt.Errorf("GitHub listing did not include %s", key)
			}
			if err := uniqueJSON(bytes.NewReader(fields[key]), &batch); err != nil {
				return nil, err
			}
		}
		results = append(results, batch...)
		if maximum != 0 && len(results) > maximum {
			return nil, fmt.Errorf("pagination item bound exceeded")
		}
		if len(batch) < 100 {
			return results, nil
		}
	}
	return nil, fmt.Errorf("pagination bound exceeded")
}

func (p *publisher) identity() error {
	var config map[string]any
	if err := publisherReadJSON("release/ci/github-release.json", &config); err != nil {
		return err
	}
	if !reflect.DeepEqual(config, map[string]any{
		"repository": repository, "repositoryId": json.Number(repositoryID), "publication": "github-only-unsigned-prerelease",
	}) {
		return fmt.Errorf("public GitHub release configuration mismatch")
	}
	if !sourceCommit.MatchString(p.source) {
		return fmt.Errorf("full source SHA required")
	}
	if os.Getenv("GITHUB_REPOSITORY") != repository || os.Getenv("GITHUB_REPOSITORY_ID") != repositoryID {
		return fmt.Errorf("wrong workflow repository")
	}
	var remote struct {
		ID int64 `json:"id"`
	}
	if err := p.get(publisherRepositoryPath, &remote); err != nil {
		return err
	}
	if strconv.FormatInt(remote.ID, 10) != repositoryID {
		return fmt.Errorf("remote repository ID mismatch")
	}
	head, err := git(p.sourceRoot, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(head)) != p.source {
		return fmt.Errorf("publisher checkout differs from source")
	}
	dirty, err := git(p.sourceRoot, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(dirty)) != 0 {
		return fmt.Errorf("tracked source is dirty")
	}
	const owned = "release/ci/owned-distribution.json"
	local, localErr := fileSHA256(owned)
	ownedSource, sourceErr := fileSHA256(filepath.Join(p.sourceRoot, owned))
	if os.IsNotExist(localErr) && os.IsNotExist(sourceErr) {
		return nil
	}
	if localErr != nil || sourceErr != nil || local != ownedSource {
		return fmt.Errorf("publisher owned identity configuration differs from source")
	}
	return nil
}

func (p *publisher) currentTag() (string, error) {
	return remoteTagIdentity(p.tag, p.source, "", p.get)
}

func (p *publisher) requireTag(message string) error {
	actual, err := p.currentTag()
	if err != nil {
		return err
	}
	if actual != p.tagObject {
		return fmt.Errorf("%s", message)
	}
	return nil
}

func (p *publisher) execute() error {
	if err := os.MkdirAll(filepath.Dir(p.audit), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(p.audit, 0o755); err != nil {
		return err
	}
	return withPublisherStorage(p.audit, func(storage *publisherStorage) error {
		p.storage = storage
		if err := storage.admit(16<<10, "bounded storage diagnostic"); err != nil {
			return err
		}
		storage.record(map[string]any{"phase": "inventory"})
		tree, err := git(p.sourceRoot, "rev-parse", "HEAD^{tree}")
		if err != nil {
			return err
		}
		p.sourceTree = strings.TrimSpace(string(tree))
		p.tagObject, err = p.currentTag()
		if err != nil {
			return err
		}
		var reviewed *publisherInventory
		if p.mode != "inventory" {
			storage.record(map[string]any{"phase": "reviewed-contract"})
			reviewed, err = p.reviewedInventory()
			if err != nil {
				return err
			}
			run := reviewed.Runs["all"]
			if len(reviewed.Runs) != 1 || run == nil || run.ID != p.allRun {
				return fmt.Errorf("reviewed inventory producer inputs differ")
			}
		}
		storage.record(map[string]any{"phase": "inventory"})
		actual, err := p.inventory()
		if err != nil {
			return err
		}
		if err := p.requireTag("tag changed while collecting release inventory"); err != nil {
			return err
		}
		if p.mode == "inventory" {
			if _, err := os.Lstat(p.output); err == nil {
				return fmt.Errorf("inventory output already exists")
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := p.copyNativeAudit(); err != nil {
				return err
			}
			if err := storage.writeJSON(p.output, actual); err != nil {
				return err
			}
			digest, err := fileSHA256(p.output)
			if err != nil {
				return err
			}
			storage.record(map[string]any{"phase": "complete", "result": "inventory"})
			fmt.Println("Inventory SHA-256:", digest)
			return nil
		}
		storage.record(map[string]any{"phase": "reviewed-contract"})
		receipt, err := p.assemble(actual, reviewed)
		if err != nil {
			return err
		}
		if err := p.requireTag("tag changed while validating release contract"); err != nil {
			return err
		}
		if p.mode == "publish" {
			if os.Getenv("POLARIS_GITHUB_PUBLISH_ENABLED") != "true" {
				return fmt.Errorf("GitHub publication disabled")
			}
			return p.publish(actual, receipt)
		}
		storage.record(map[string]any{"phase": "complete", "result": "validated-without-public-payload-copy"})
		return nil
	})
}

func publisherWriteRelease(ctx context.Context, method, endpoint string, payload any, result any) error {
	if method != "POST" && method != "PATCH" {
		return fmt.Errorf("unsupported publication operation: %s", method)
	}
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(payload); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "gh", "api", "--method", method, endpoint, "--input", "-")
	command.Stdin = &input
	// Writes are issued once; the caller owns finalization readback.
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("GitHub release %s failed: %w", method, errors.Join(err, ctx.Err()))
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return io.ErrUnexpectedEOF
	}
	return uniqueJSON(bytes.NewReader(output), result)
}
