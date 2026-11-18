package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/badversion"
)

const (
	peerAdmissionSchema = "polaris-native-peer-artifact-admission-v1"
	peerArtifactName    = "binary-linux_amd64-purego"
	peerMetadataLimit   = 2 << 20
)

var (
	peerRef    = regexp.MustCompile(`^refs/(heads|tags)/[A-Za-z0-9_./-]+$`)
	peerNumber = regexp.MustCompile(`^[1-9][0-9]*$`)
	peerDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	peerTime   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

func peerLocalContext(root, native string, context map[string]any) error {
	env, err := nativeEnvironment("GITHUB_ACTIONS", "RUNNER_OS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID",
		"GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
		"GITHUB_REF", "GITHUB_WORKFLOW_REF")
	if err != nil || env["GITHUB_ACTIONS"] != "true" || env["RUNNER_OS"] != "Linux" ||
		env["GITHUB_REPOSITORY"] != repository || env["GITHUB_REPOSITORY_ID"] != repositoryID ||
		env["GITHUB_EVENT_NAME"] != "workflow_dispatch" {
		return fmt.Errorf("metadata admission requires Linux Actions in the approved repository")
	}
	source, ref := env["GITHUB_SHA"], env["GITHUB_REF"]
	if !sourceCommit.MatchString(source) || env["GITHUB_WORKFLOW_SHA"] != source ||
		!peerRef.MatchString(ref) || env["GITHUB_WORKFLOW_REF"] != repository+"/.github/workflows/build.yml@"+ref ||
		!peerNumber.MatchString(env["GITHUB_RUN_ID"]) || !peerNumber.MatchString(env["GITHUB_RUN_ATTEMPT"]) {
		return fmt.Errorf("metadata admission workflow identity differs")
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != source {
		return fmt.Errorf("metadata admission checkout source differs")
	}
	status, err := git(root, "status", "--porcelain", "--untracked-files=no")
	if err != nil || len(status) != 0 {
		return fmt.Errorf("metadata admission tracked checkout is dirty or unavailable")
	}
	context["repository"], context["repositoryId"] = repository, json.Number(repositoryID)
	context["sourceCommit"], context["workflowCommit"] = source, source
	context["runId"], context["runAttempt"] = json.Number(env["GITHUB_RUN_ID"]), json.Number(env["GITHUB_RUN_ATTEMPT"])
	context["ref"] = ref

	rows, err := filepath.Glob(filepath.Join(native, "native-row-*.json"))
	if err != nil || len(rows) != 1 {
		return fmt.Errorf("metadata admission requires one bounded native row")
	}
	raw, err := peerReadFile(rows[0])
	if err != nil {
		return err
	}
	var row struct {
		Source  string `json:"sourceCommit"`
		Tree    string `json:"sourceTree"`
		Tag     string `json:"tag"`
		Version string `json:"version"`
		Target  string `json:"target"`
		Variant struct {
			Linkage string `json:"linkage"`
		} `json:"variant"`
	}
	if err := uniqueJSON(bytes.NewReader(raw), &row); err != nil {
		return fmt.Errorf("metadata admission native row JSON differs")
	}
	tree, err := git(root, "rev-parse", "HEAD^{tree}")
	if err != nil || row.Source != source || row.Tree != strings.TrimSpace(string(tree)) ||
		!badversion.IsCanonicalPolaris(row.Version) || row.Tag != "v"+row.Version ||
		row.Target != "linux/amd64" || row.Variant.Linkage != "shared-purego" {
		return fmt.Errorf("metadata admission native row identity differs")
	}
	context["sourceTree"], context["version"], context["tag"] = row.Tree, row.Version, row.Tag
	context["producerRowSHA256"] = sha256Hex(raw)
	return nil
}

func peerReadFile(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > peerMetadataLimit {
		return nil, fmt.Errorf("metadata admission file missing or unsafe")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("metadata admission file unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, peerMetadataLimit+1))
	if err != nil || len(raw) > peerMetadataLimit {
		return nil, fmt.Errorf("metadata admission file exceeds byte bound or could not be read")
	}
	return raw, nil
}

func peerTimestamp(value any) (time.Time, error) {
	date, _ := value.(string)
	if peerTime.MatchString(date) {
		if parsed, err := time.Parse(time.RFC3339, date); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("metadata timestamp invalid")
}

func peerRunBinding(run, context map[string]any, now time.Time) (map[string]any, time.Time, error) {
	branch := strings.SplitN(context["ref"].(string), "/", 3)[2]
	binding := map[string]any{
		"id": context["runId"], "run_attempt": context["runAttempt"], "head_sha": context["sourceCommit"],
		"head_branch": branch, "event": "workflow_dispatch", "path": ".github/workflows/build.yml",
	}
	for key, value := range binding {
		if !reflect.DeepEqual(run[key], value) {
			return nil, time.Time{}, fmt.Errorf("metadata producer run differs")
		}
	}
	for _, key := range []string{"repository", "head_repository"} {
		observed, _ := run[key].(map[string]any)
		if observed["id"] != json.Number(repositoryID) || observed["full_name"] != repository {
			return nil, time.Time{}, fmt.Errorf("metadata producer repository differs")
		}
		binding[key] = map[string]any{"id": json.Number(repositoryID), "full_name": repository}
	}
	start, err := peerTimestamp(run["run_started_at"])
	if err != nil || start.After(now) {
		return nil, time.Time{}, fmt.Errorf("metadata producer attempt start differs")
	}
	binding["run_started_at"] = run["run_started_at"]
	return binding, start, nil
}

func peerInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func peerArtifactBinding(item, context map[string]any, start, now time.Time) (map[string]any, error) {
	id, validID := peerInteger(item["id"])
	size, validSize := peerInteger(item["size_in_bytes"])
	digest, _ := item["digest"].(string)
	if item["name"] != peerArtifactName || !validID || id <= 0 || !validSize || size <= 0 || size > 512<<20 ||
		item["expired"] != false || !peerDigest.MatchString(digest) {
		return nil, fmt.Errorf("metadata artifact numeric, name or digest identity differs")
	}
	created, createdErr := peerTimestamp(item["created_at"])
	expires, expiresErr := peerTimestamp(item["expires_at"])
	if createdErr != nil || expiresErr != nil || created.Before(start) || created.After(now) || !now.Before(expires) {
		return nil, fmt.Errorf("metadata artifact creation or expiry differs")
	}
	binding := map[string]any{
		"id": context["runId"], "repository_id": json.Number(repositoryID), "head_repository_id": json.Number(repositoryID),
		"head_sha": context["sourceCommit"], "head_branch": strings.SplitN(context["ref"].(string), "/", 3)[2],
	}
	if !reflect.DeepEqual(item["workflow_run"], binding) {
		return nil, fmt.Errorf("metadata artifact producer binding differs")
	}
	artifact := map[string]any{}
	for _, key := range []string{"id", "name", "digest", "size_in_bytes", "created_at", "expires_at", "expired", "workflow_run"} {
		artifact[key] = item[key]
	}
	return artifact, nil
}

func readPeerAdmission(context map[string]any, get func(string, string) (map[string]any, error), now func() time.Time) (map[string]any, error) {
	run, err := get("", "producer_run_metadata")
	if err != nil {
		return nil, err
	}
	binding, start, err := peerRunBinding(run, context, now())
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var selected map[string]any
	var total int64
	for page := 1; page <= 4; page++ {
		result, err := get(fmt.Sprintf("/artifacts?per_page=100&page=%d", page), "artifact_inventory")
		if err != nil {
			return nil, err
		}
		count, valid := peerInteger(result["total_count"])
		artifacts, list := result["artifacts"].([]any)
		if !valid || count < 0 || count > 400 || !list || len(artifacts) > 100 || page > 1 && count != total {
			return nil, fmt.Errorf("metadata artifact inventory shape or total differs")
		}
		total = count
		for _, entry := range artifacts {
			item, _ := entry.(map[string]any)
			id, valid := peerInteger(item["id"])
			if !valid || seen[id] {
				return nil, fmt.Errorf("metadata artifact inventory duplicate or invalid")
			}
			seen[id] = true
			if item["name"] == peerArtifactName {
				if selected != nil {
					return nil, fmt.Errorf("same-run Linux artifact is not unique")
				}
				selected = item
			}
		}
		if len(artifacts) < 100 {
			break
		}
	}
	if int64(len(seen)) != total || selected == nil {
		return nil, fmt.Errorf("metadata artifact inventory incomplete or Linux artifact unavailable")
	}
	artifact, err := peerArtifactBinding(selected, context, start, now())
	if err != nil {
		return nil, err
	}
	return map[string]any{"schema": peerAdmissionSchema, "context": context, "producerRun": binding, "artifact": artifact}, nil
}

func verifyPeerAdmission(path string, context map[string]any) (map[string]any, error) {
	raw, err := peerReadFile(path)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := uniqueJSON(bytes.NewReader(raw), &document); err != nil ||
		len(document) != 4 || document["schema"] != peerAdmissionSchema || !reflect.DeepEqual(document["context"], context) {
		return nil, fmt.Errorf("metadata admission context differs")
	}
	run, _ := document["producerRun"].(map[string]any)
	item, _ := document["artifact"].(map[string]any)
	now := time.Now()
	binding, start, err := peerRunBinding(run, context, now)
	if err != nil || !reflect.DeepEqual(run, binding) || len(item) != 8 {
		return nil, fmt.Errorf("metadata admission producer run or artifact shape differs")
	}
	artifact, err := peerArtifactBinding(item, context, start, now)
	if err != nil {
		return nil, err
	}
	delete(artifact, "expired")
	delete(artifact, "workflow_run")
	return artifact, nil
}

func acquirePeerAdmission(context map[string]any, record func(map[string]any)) (map[string]any, error) {
	if os.Getenv("GH_TOKEN") == "" {
		return nil, fmt.Errorf("metadata acquisition requires existing read-only Actions token")
	}
	sink, err := os.CreateTemp("", "polaris-peer-metadata-")
	if err != nil {
		return nil, fmt.Errorf("metadata acquisition scratch unavailable")
	}
	defer os.Remove(sink.Name())
	defer sink.Close()
	deadline := time.Now().Add(120 * time.Second)
	var budget retryBudget
	return readPeerAdmission(context, func(suffix, phase string) (map[string]any, error) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("metadata admission total deadline exhausted")
		}
		endpoint := fmt.Sprintf("repos/%s/actions/runs/%s%s", repository, context["runId"], suffix)
		_, err := readGitHub(endpoint, sink, peerMetadataLimit, &budget,
			readLimits{min(15*time.Second, remaining), min(45*time.Second, remaining), 4 * time.Second},
			func(event map[string]any) {
				event["phase"] = phase
				record(event)
			})
		if err != nil {
			return nil, err
		}
		if _, err := sink.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("metadata response scratch could not be read")
		}
		var value map[string]any
		if err := uniqueJSON(sink, &value); err != nil {
			return nil, fmt.Errorf("metadata response is not a unique JSON object")
		}
		return value, nil
	}, time.Now)
}

func peerMetadata(args []string) error {
	flags := flag.NewFlagSet("peer-metadata", flag.ContinueOnError)
	native := flags.String("native", "", "downloaded same-run native row directory")
	admission := flags.String("admission", "", "exact metadata admission")
	failure := flags.String("failure", "", "private acquisition failure facts")
	mode := flags.String("mode", "", "acquire, verify or describe")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *native == "" || (*mode != "describe" && *admission == "") ||
		(*mode != "acquire" && *mode != "verify" && *mode != "describe") {
		return fmt.Errorf("invalid peer metadata arguments")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	context := map[string]any{}
	err = peerLocalContext(root, *native, context)
	if *mode == "describe" {
		return writeJSON(os.Stdout, context)
	}
	if *mode == "verify" {
		if err != nil {
			return err
		}
		artifact, err := verifyPeerAdmission(*admission, context)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, artifact)
	}
	records := []map[string]any{}
	if err == nil {
		var document map[string]any
		document, err = acquirePeerAdmission(context, func(event map[string]any) { records = append(records, event) })
		if err == nil {
			err = os.MkdirAll(filepath.Dir(*admission), 0o700)
		}
		if err == nil {
			err = sourceReceipt(*admission, document, true, peerMetadataLimit)
		}
	}
	if err != nil && *failure != "" {
		facts := map[string]any{"context": context, "metadataReads": records, "errorType": "MetadataError"}
		message := err.Error()
		var failed *readFailure
		if errors.As(err, &failed) {
			facts["errorType"] = "ReadFailure"
			var status any
			if failed.Status != 0 {
				status = failed.Status
			}
			headers := failed.Headers
			if headers == nil {
				headers = map[string]string{}
			}
			facts["transportFailure"] = map[string]any{"kind": failed.Kind, "status": status, "headers": headers}
		} else {
			var fileErr *os.PathError
			if errors.As(err, &fileErr) {
				message = "metadata admission could not save evidence"
			}
		}
		facts["error"] = message
		if failureErr := sourceReceipt(*failure, facts, true, peerMetadataLimit); failureErr != nil {
			return fmt.Errorf("metadata admission and failure receipt both failed")
		}
	}
	return err
}
