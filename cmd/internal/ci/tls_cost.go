package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	tlsCostBaseline     = "55300c55560bcc604fd9675c5526b5713db81cc1"
	tlsCostBaselineTree = "7767ba9a9901a061ff07db7716baed7896cfefbc"
	tlsCostWork         = 20 * time.Minute
)

var sourceRunNumber = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func sourceGateContext() (map[string]any, error) {
	values, err := nativeEnvironment("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_EVENT_NAME", "GITHUB_JOB", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "SOURCE_BUILD", "SOURCE_GENERATE_ONLY", "SOURCE_RUNNER")
	if err != nil {
		return nil, err
	}
	if values["GITHUB_ACTIONS"] != "true" || values["GITHUB_REPOSITORY"] != repository || values["GITHUB_REPOSITORY_ID"] != repositoryID || values["GITHUB_EVENT_NAME"] != "workflow_dispatch" || values["GITHUB_JOB"] != "utls_gate" || values["SOURCE_BUILD"] != "Source" || values["SOURCE_GENERATE_ONLY"] != "false" {
		return nil, fmt.Errorf("observation requires the existing owned non-generation Source CI job")
	}
	if !sourceCommit.MatchString(values["GITHUB_SHA"]) || !sourceRunNumber.MatchString(values["GITHUB_RUN_ID"]) || !sourceRunNumber.MatchString(values["GITHUB_RUN_ATTEMPT"]) {
		return nil, fmt.Errorf("exact source/run/attempt missing or out of bound")
	}
	inputs := map[string]string{"build": values["SOURCE_BUILD"], "sourceGenerateOnly": values["SOURCE_GENERATE_ONLY"], "runner": values["SOURCE_RUNNER"]}
	for _, value := range inputs {
		if len(value) > 128 {
			return nil, fmt.Errorf("source diagnostic input exceeds bound")
		}
	}
	return map[string]any{"repository": repository, "repositoryId": json.Number(repositoryID), "sourceCommit": values["GITHUB_SHA"], "runId": json.Number(values["GITHUB_RUN_ID"]), "runAttempt": json.Number(values["GITHUB_RUN_ATTEMPT"]), "inputs": inputs, "diagnosticOnly": true, "testOrNativePASS": false, "executionAuthority": false}, nil
}

func sourceGitResult(parent context.Context, root string, environment []string, args ...string) (string, string, *int, error) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	command := append([]string{"git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}, args...)
	return sourceCommandOutput(ctx, root, environment, 65536, command...)
}

func sourceGitText(parent context.Context, root string, environment []string, args ...string) (string, error) {
	output, diagnostic, code, err := sourceGitResult(parent, root, environment, args...)
	if err != nil {
		return "", err
	}
	if code == nil || *code != 0 {
		return "", fmt.Errorf("bounded Git query failed: %s", diagnostic)
	}
	return strings.TrimSpace(output), nil
}

func retainSourceInput(root, output string) (err error) {
	document, err := sourceGateContext()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	document["schema"], document["stage"] = "polaris-source-ci-input-diagnostic-v1", "before-compatibility-gates"
	document["testExecutionStatus"], document["measurementsComplete"] = "not-started", false
	filename := filepath.Join(output, "source-ci-input.json")
	if err := sourceReceipt(filename, document, true, 16384); err != nil {
		return err
	}
	defer func() {
		document["checkoutIdentityVerified"] = err == nil
		if err != nil {
			document["error"] = sourceErrorText(err)
		}
		err = errors.Join(err, sourceReceipt(filename, document, false, 16384))
	}()
	ctx := context.Background()
	source, err := sourceGitText(ctx, root, nil, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	document["observedSourceCommit"] = source
	tree, err := sourceGitText(ctx, root, nil, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	document["sourceTree"] = tree
	status, err := sourceGitText(ctx, root, nil, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if source != document["sourceCommit"] || !sourceCommit.MatchString(tree) || status != "" {
		return fmt.Errorf("source diagnostic checkout differs from exact clean dispatch")
	}
	return nil
}

func sourceErrorText(err error) string {
	text := err.Error()
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text
}

func tlsCost(args []string) error {
	output, retain, err := sourceOutputArguments(args, true)
	if err != nil {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if retain {
		return retainSourceInput(root, output)
	}
	return measureTLSCost(root, output)
}

func sourceObjectStorage(directory string) (int64, error) {
	var total int64
	count := 0
	err := filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			return walkError
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if redirectedSource(info) {
			return fmt.Errorf("Git object storage has a link")
		}
		if info.IsDir() {
			return nil
		}
		count++
		if count > 20000 {
			return fmt.Errorf("Git object storage member budget exceeded")
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func acquireTLSBaseline(ctx context.Context, root, output string, environment []string, record map[string]any) (err error) {
	objects, err := sourceGitText(ctx, root, environment, "rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil {
		return err
	}
	before, err := sourceObjectStorage(objects)
	if err != nil {
		return err
	}
	url := "https://github.com/" + repository + ".git"
	for key, value := range map[string]any{"attempted": true, "url": url, "commit": tlsCostBaseline, "timeoutSeconds": 90, "maxChildFileBytes": 256 << 20, "maxObjectGrowthBytes": 512 << 20, "processReaped": false} {
		record[key] = value
	}
	defer func() {
		after, observeError := sourceObjectStorage(objects)
		if observeError != nil {
			err = errors.Join(err, observeError)
			return
		}
		growth := max(int64(0), after-before)
		record["objectGrowthBytes"] = growth
		if growth > 512<<20 {
			err = errors.Join(err, fmt.Errorf("fixed baseline acquisition exceeded object storage growth budget"))
		}
	}()
	commandContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// Reuse the owned Linux runner's prlimit to apply RLIMIT_FSIZE before Git starts.
	command := exec.CommandContext(commandContext, "prlimit", "--fsize=268435456:268435456", "--", "git", "-c", "gc.auto=0", "-c", "fetch.unpackLimit=1", "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", "-c", "protocol.file.allow=never", "fetch", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", "--no-progress", "--depth=1", url, tlsCostBaseline)
	command.Dir, command.Env = root, environment
	log, err := os.OpenFile(filepath.Join(output, "baseline-fetch.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, log.Close()) }()
	command.Stdout, command.Stderr = log, log
	code, err := runSourceProcess(commandContext, command)
	record["exitCode"], record["processReaped"] = code, command.ProcessState != nil
	if err != nil {
		return err
	}
	if code == nil || *code != 0 || command.ProcessState == nil {
		return fmt.Errorf("fixed baseline acquisition failed; original bounded log retained")
	}
	return nil
}

func ensureTLSBaseline(ctx context.Context, root, output string, environment []string, record map[string]any) error {
	_, _, code, err := sourceGitResult(ctx, root, environment, "rev-parse", "--verify", "--quiet", tlsCostBaseline+"^{commit}")
	if err != nil {
		return err
	}
	if code != nil && *code == 1 {
		if err := acquireTLSBaseline(ctx, root, output, environment, record); err != nil {
			return err
		}
	} else if code == nil || *code != 0 {
		return fmt.Errorf("baseline lookup failed independently of object absence")
	}
	commit, err := sourceGitText(ctx, root, environment, "rev-parse", "--verify", tlsCostBaseline+"^{commit}")
	if err != nil {
		return err
	}
	tree, err := sourceGitText(ctx, root, environment, "rev-parse", "--verify", tlsCostBaseline+"^{tree}")
	if err != nil {
		return err
	}
	if commit != tlsCostBaseline || tree != tlsCostBaselineTree {
		return fmt.Errorf("fixed baseline commit/tree differs")
	}
	record["verifiedCommit"], record["verifiedTree"] = commit, tree
	return nil
}

func retireTLSWorkspace(root, owner, slot string, environment []string) error {
	listing, err := sourceGitText(context.Background(), root, environment, "worktree", "list", "--porcelain")
	if err != nil {
		return err
	}
	registered := false
	for _, line := range strings.Split(listing, "\n") {
		if strings.HasPrefix(line, "worktree ") && strings.TrimPrefix(line, "worktree ") == slot {
			registered = true
		}
	}
	if registered {
		if _, err := sourceGitText(context.Background(), root, environment, "worktree", "remove", slot); err != nil {
			return err
		}
	} else if _, err := os.Stat(slot); err == nil {
		return fmt.Errorf("unregistered partial checkout retained inside owned workspace")
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Remove(owner)
}

func tlsIdleSamples(ctx context.Context, core, config, filename string) (result map[string]any, err error) {
	log, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, log.Close()) }()
	command := exec.CommandContext(ctx, core, "run", "-c", config)
	command.Stdout, command.Stderr = log, log
	sourceProcessGroup(command)
	command.Cancel = func() error { return terminateSourceProcess(command, true) }
	command.WaitDelay = 10 * time.Second
	if err := command.Start(); err != nil {
		return nil, err
	}
	pid := command.Process.Pid
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	finished := false
	defer func() {
		if finished {
			return
		}
		stopError := terminateSourceProcess(command, false)
		if errors.Is(stopError, os.ErrProcessDone) {
			stopError = nil
		}
		select {
		case <-waited:
			finished = true
		case <-time.After(10 * time.Second):
			forceError := terminateSourceProcess(command, true)
			if errors.Is(forceError, os.ErrProcessDone) {
				forceError = nil
			}
			stopError = errors.Join(stopError, forceError)
			select {
			case <-waited:
				finished = true
			case <-time.After(10 * time.Second):
				stopError = errors.Join(stopError, fmt.Errorf("idle fixture process retirement remains incomplete"))
			}
		}
		err = errors.Join(err, stopError)
	}()
	samples := []uint64{}
	for range 5 {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < time.Second {
			return nil, fmt.Errorf("idle sample work budget exhausted")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waited:
			finished = true
			return nil, fmt.Errorf("idle fixture exited before sampling: %s", filename)
		case <-time.After(time.Second):
		}
		contents, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			return nil, err
		}
		found := false
		for _, line := range strings.Split(string(contents), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[2] != "kB" {
				return nil, fmt.Errorf("idle RSS observation malformed")
			}
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return nil, err
			}
			samples = append(samples, value*1024)
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("idle RSS observation missing")
		}
	}
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	return map[string]any{"samplesBytes": samples, "medianBytes": ordered[2], "sampledMaxBytes": ordered[4], "scope": "idle process, one uTLS outbound constructed, no inbound or remote handshake"}, nil
}

func measureTLSCost(root, output string) (err error) {
	receipt, err := sourceGateContext()
	if err != nil {
		return err
	}
	input := maps.Clone(receipt)
	input["baselineSource"], input["baselineTree"], input["workBudgetSeconds"] = tlsCostBaseline, tlsCostBaselineTree, 1200
	if runtime.GOOS != "linux" || os.Getenv("RUNNER_OS") != "Linux" {
		return fmt.Errorf("cost measurement is restricted to the existing owned Linux CI job")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	for key, value := range map[string]any{"schema": "polaris-utls-migration-cost-v1", "baselineSource": tlsCostBaseline, "baselineTree": tlsCostBaselineTree, "candidateSource": receipt["sourceCommit"], "phase": "preflight", "status": "not-measured", "measurementsComplete": false, "workBudgetSeconds": 1200, "retirementGraceSeconds": 60, "results": map[string]map[string]any{}, "errors": []string{}, "baselineAcquisition": map[string]any{"attempted": false}, "baselineWorktree": map[string]any{"creationAttempted": false, "retirementAttempted": false, "retired": nil}, "tags": "with_utls,badlinkname", "attribution": "whole source/dependency migration at the same Go, not isolated second-library cost", "handshakePeakRSSValidated": false, "appOrMobileSizeValidated": false, "productionDefaultTags": false} {
		receipt[key] = value
	}
	if err := sourceReceipt(filepath.Join(output, "cost.json"), receipt, true, 1024*1024); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), tlsCostWork)
	defer cancel()
	owner, slot := "", ""
	var environment []string
	results := receipt["results"].(map[string]map[string]any)
	problem := func(value error) { receipt["errors"] = append(receipt["errors"].([]string), sourceErrorText(value)) }
	defer func() {
		if err != nil {
			problem(err)
		}
		workspace := receipt["baselineWorktree"].(map[string]any)
		if owner != "" {
			workspace["retirementAttempted"] = true
			cleanupError := retireTLSWorkspace(root, owner, slot, environment)
			workspace["retired"] = cleanupError == nil
			if cleanupError != nil {
				problem(fmt.Errorf("owned baseline workspace retirement failed: %w", cleanupError))
			}
		}
		retired := workspace["retired"] == true
		receipt["baselineWorktreeRetired"] = retired
		_, baselineOK := results["baseline"]["idleRSS"]
		_, candidateOK := results["candidate"]["idleRSS"]
		complete := len(receipt["errors"].([]string)) == 0 && retired && baselineOK && candidateOK
		receipt["measurementsComplete"], receipt["status"] = complete, "incomplete"
		if complete {
			a, b := results["baseline"], results["candidate"]
			receipt["delta"] = map[string]any{"binaryBytes": b["bytes"].(int64) - a["bytes"].(int64), "medianIdleRSSBytes": int64(b["idleRSS"].(map[string]any)["medianBytes"].(uint64)) - int64(a["idleRSS"].(map[string]any)["medianBytes"].(uint64))}
			receipt["status"] = "complete"
		}
		free, observeError := sourceDiskFree(output)
		if observeError != nil {
			problem(observeError)
			receipt["measurementsComplete"], receipt["status"] = false, "incomplete"
			delete(receipt, "delta")
		} else {
			receipt["diskFreeBytesAfter"] = free
		}
		err = errors.Join(err, sourceReceipt(filepath.Join(output, "cost.json"), receipt, false, 1024*1024))
		if receipt["measurementsComplete"] != true && err == nil {
			err = fmt.Errorf("comparison incomplete: %s", strings.Join(receipt["errors"].([]string), "; "))
		}
	}()
	environment, err = sourceGateEnvironment()
	if err != nil {
		return err
	}
	if err := sourceReceipt(filepath.Join(output, "cost-input.json"), input, true, 16384); err != nil {
		return err
	}
	free, err := sourceDiskFree(output)
	if err != nil {
		return err
	}
	if free < 10*1024*1024*1024 {
		return fmt.Errorf("comparison lacks 4GiB additional growth plus 6GiB headroom")
	}
	source, err := sourceGitText(ctx, root, environment, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	receipt["observedCandidateSource"] = source
	tree, err := sourceGitText(ctx, root, environment, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	receipt["candidateTree"] = tree
	status, err := sourceGitText(ctx, root, environment, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if source != receipt["sourceCommit"] || status != "" {
		return fmt.Errorf("candidate source is not the exact clean dispatch")
	}
	goVersion, err := sourceGoVersion(ctx, root, environment)
	if err != nil {
		return err
	}
	receipt["goVersion"] = goVersion
	receipt["phase"] = "baseline-acquisition"
	if err := ensureTLSBaseline(ctx, root, output, environment, receipt["baselineAcquisition"].(map[string]any)); err != nil {
		return err
	}
	free, err = sourceDiskFree(output)
	if err != nil {
		return err
	}
	if free < 10*1024*1024*1024 {
		return fmt.Errorf("baseline acquisition left insufficient comparison disk headroom")
	}
	owner, err = os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "polaris-utls-cost-")
	if err != nil {
		return err
	}
	slot = filepath.Join(owner, "baseline")
	workspace := receipt["baselineWorktree"].(map[string]any)
	workspace["ownerDirectory"], workspace["path"], workspace["creationAttempted"] = owner, slot, true
	if err := sourceReceipt(filepath.Join(output, "cost.json"), receipt, false, 1024*1024); err != nil {
		return err
	}
	if _, err := sourceGitText(ctx, root, environment, "worktree", "add", "--detach", slot, tlsCostBaseline); err != nil {
		return err
	}
	commit, err := sourceGitText(ctx, slot, environment, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	baselineTree, err := sourceGitText(ctx, slot, environment, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	if commit != tlsCostBaseline || baselineTree != tlsCostBaselineTree {
		return fmt.Errorf("baseline worktree identity differs")
	}
	baselineFlags, err := os.ReadFile(filepath.Join(slot, "release/LDFLAGS"))
	if err != nil {
		return err
	}
	candidateFlags, err := os.ReadFile(filepath.Join(root, "release/LDFLAGS"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(baselineFlags)) != strings.TrimSpace(string(candidateFlags)) {
		return fmt.Errorf("comparison linker contract changed")
	}
	flags := strings.TrimSpace(string(baselineFlags)) + " -s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=" + tlsGateVersion
	receipt["ldflags"] = flags
	config := filepath.Join(output, "idle-config.json")
	fingerprint := "chrome"
	if err := sourceReceipt(config, tlsOutbound(&fingerprint, true), true, 1024*1024); err != nil {
		return err
	}
	for _, item := range []struct{ label, directory string }{{"baseline", slot}, {"candidate", root}} {
		receipt["phase"] = item.label + "-build-and-idle"
		core := filepath.Join(output, item.label+"-core")
		code, buildError := sourceLogged(ctx, item.directory, environment, filepath.Join(output, item.label+"-build.log"), "go", "build", "-p=2", "-trimpath", "-tags=with_utls,badlinkname", "-ldflags="+flags, "-o", core, "./cmd/sing-box")
		if buildError != nil {
			problem(buildError)
			continue
		}
		if code == nil || *code != 0 {
			problem(fmt.Errorf("%s: comparison build failed/timed out; original log retained", item.label))
			continue
		}
		query, cancel := context.WithTimeout(ctx, 20*time.Second)
		info, _, code, readError := sourceCommandOutput(query, item.directory, environment, 1024*1024, "go", "version", "-m", core)
		cancel()
		if readError != nil {
			return readError
		}
		if code == nil || *code != 0 {
			return fmt.Errorf("comparison native build info unavailable")
		}
		query, cancel = context.WithTimeout(ctx, 20*time.Second)
		buildID, _, code, readError := sourceCommandOutput(query, item.directory, environment, 16384, "go", "tool", "buildid", core)
		cancel()
		if readError != nil {
			return readError
		}
		if code == nil || *code != 0 {
			return fmt.Errorf("comparison native build ID unavailable")
		}
		tree, err := sourceGitText(ctx, item.directory, environment, "rev-parse", "HEAD^{tree}")
		if err != nil {
			return err
		}
		hash, err := fileSHA256(core)
		if err != nil {
			return err
		}
		stat, err := os.Stat(core)
		if err != nil {
			return err
		}
		identity := map[string]any{"sourceCommit": source, "sourceTree": tree, "bytes": stat.Size(), "sha256": hash, "buildID": strings.TrimSpace(buildID), "rawBuildInfo": info}
		if item.label == "baseline" {
			identity["sourceCommit"] = tlsCostBaseline
		}
		idle, idleError := tlsIdleSamples(ctx, core, config, filepath.Join(output, item.label+"-idle.log"))
		if idleError != nil {
			problem(fmt.Errorf("%s: %w", item.label, idleError))
		} else {
			identity["idleRSS"] = idle
		}
		results[item.label] = identity
	}
	return nil
}
