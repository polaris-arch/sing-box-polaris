package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	localNativeTarget  = "linux/amd64"
	localNativeRecipe  = "polaris-local-development-source-v1"
	localNativeInputs  = "polaris-local-development-inputs-v1"
	localNativeContext = "polaris-local-development-execution-context-v1"
	localNativeSelect  = "polaris-local-development-selection-v1"
	localNativeLimit   = 96 << 20
	localReceiptLimit  = 2 << 20
)

type localNativeSource struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

type localNativeRecipeData struct {
	Schema         string            `json:"schema"`
	CoreSource     localNativeSource `json:"coreSource"`
	ProducerSource localNativeSource `json:"producerSource"`
	Target         string            `json:"target"`
	GoVersion      string            `json:"goVersion"`
	Tags           []string          `json:"tags"`
	Version        string            `json:"version"`
	Sidecar        struct {
		Bytes   int64  `json:"bytes"`
		SHA256  string `json:"sha256"`
		Version string `json:"version"`
	} `json:"sidecar"`
}

type localNativePaths struct {
	Schema             string `json:"schema"`
	CoreSourceRoot     string `json:"coreSourceRoot"`
	ProducerSourceRoot string `json:"producerSourceRoot"`
}

var (
	localNativeVersion = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,128}$`)
	localNativeTag     = regexp.MustCompile(`^[a-z0-9_]+$`)
	localNativeSHA256  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func localNative(ctx context.Context, args []string) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("local native execution requires Linux amd64")
	}
	if len(args) == 0 || (args[0] != "collect" && args[0] != "verify") {
		return fmt.Errorf("expected local-native collect or verify")
	}
	flags := flag.NewFlagSet("local-native "+args[0], flag.ContinueOnError)
	recipePath := flags.String("recipe", "", "reviewed local source recipe")
	expectedRecipe := flags.String("recipe-sha256", "", "SHA-256 of the admitted recipe bytes")
	slot := flags.String("output", "", "local selection directory")
	coreSource := flags.String("core-source", "", "reviewed Core checkout")
	core := flags.String("core", "", "new Core compiler output")
	sidecar := flags.String("sidecar", "", "pinned Cronet library")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *recipePath == "" || *slot == "" {
		return fmt.Errorf("local native execution requires an explicit recipe and slot")
	}
	if !localNativeSHA256.MatchString(*expectedRecipe) {
		return fmt.Errorf("local native execution requires a lowercase --recipe-sha256")
	}
	recipe, recipeHash, err := readLocalNativeRecipe(*recipePath, *expectedRecipe)
	if err != nil {
		return err
	}
	producer, err := os.Getwd()
	if err != nil {
		return err
	}
	if args[0] == "verify" {
		if *coreSource != "" || *core != "" || *sidecar != "" {
			return fmt.Errorf("local verify takes sources and members from the selected slot")
		}
		if err := verifyLocalNative(ctx, producer, *slot, recipeHash, recipe); err != nil {
			return err
		}
		return writeJSON(os.Stdout, map[string]any{"schema": localNativeSelect, "verified": true})
	}
	for _, name := range []string{"GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "POLARIS_NATIVE_DNS_CANDIDATE", "CORE_CANDIDATE"} {
		if _, present := os.LookupEnv(name); present {
			return fmt.Errorf("local producer refuses workflow/candidate mode")
		}
	}
	paths := localNativePaths{localNativeInputs, *coreSource, producer}
	return collectLocalNative(ctx, paths, *core, *sidecar, *slot, recipeHash, recipe)
}

func readLocalNativeRecipe(path, expectedHash string) (recipe localNativeRecipeData, hash string, err error) {
	raw, err := readLocalNativeFile(path, localReceiptLimit)
	if err != nil {
		return recipe, "", err
	}
	hash = sha256Hex(raw)
	if hash != expectedHash {
		return recipe, "", fmt.Errorf("local compiler recipe SHA-256 differs from admitted bytes")
	}
	var record map[string]any
	if err := uniqueJSON(bytes.NewReader(raw), &record); err != nil {
		return recipe, "", err
	}
	if !localNativeClosed(record, "schema", "coreSource", "producerSource", "target", "goVersion", "tags", "version", "sidecar") ||
		!localNativeClosed(record["coreSource"], "commit", "tree") || !localNativeClosed(record["producerSource"], "commit", "tree") ||
		!localNativeClosed(record["sidecar"], "bytes", "sha256", "version") {
		return recipe, "", fmt.Errorf("local compiler configuration shape differs")
	}
	if err := json.Unmarshal(raw, &recipe); err != nil {
		return recipe, "", err
	}
	if recipe.Schema != localNativeRecipe || recipe.Target != localNativeTarget || recipe.GoVersion != runtime.Version() ||
		!localNativeVersion.MatchString(recipe.Version) || !strings.Contains(recipe.Version, "-polaris-dev.") ||
		recipe.Sidecar.Bytes <= 0 || recipe.Sidecar.Bytes > localNativeLimit ||
		!localNativeSHA256.MatchString(recipe.Sidecar.SHA256) || !localNativeVersion.MatchString(recipe.Sidecar.Version) {
		return recipe, "", fmt.Errorf("local compiler configuration differs")
	}
	tags := nativeTagSet(strings.Join(recipe.Tags, ","))
	if len(recipe.Tags) != len(tags) || slices.ContainsFunc(recipe.Tags, func(tag string) bool { return !localNativeTag.MatchString(tag) }) {
		return recipe, "", fmt.Errorf("invalid local tags")
	}
	for _, tag := range []string{"with_purego", "with_naive_outbound", "with_utls", "with_gvisor"} {
		if !tags[tag] {
			return recipe, "", fmt.Errorf("local native configuration lacks required tag %s", tag)
		}
	}
	return recipe, hash, nil
}

func localNativeClosed(value any, fields ...string) bool {
	record, ok := value.(map[string]any)
	if !ok || len(record) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := record[field]; !exists {
			return false
		}
	}
	return true
}

func localNativeCanonical(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("local input requires an absolute canonical path")
	}
	actual, err := filepath.EvalSymlinks(path)
	if err != nil || actual != path {
		return fmt.Errorf("local input is missing or redirected: %s", path)
	}
	return nil
}

func readLocalNativeFile(path string, limit int64) ([]byte, error) {
	if err := localNativeCanonical(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after, named unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Getuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > limit {
		return nil, fmt.Errorf("unsafe or oversized owned local input: %s", path)
	}
	data := make([]byte, before.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	match := func(actual unix.Stat_t) bool {
		return actual.Dev == before.Dev && actual.Ino == before.Ino && actual.Mode == before.Mode && actual.Uid == before.Uid &&
			actual.Nlink == before.Nlink && actual.Size == before.Size && actual.Mtim == before.Mtim && actual.Ctim == before.Ctim
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || !match(after) || !match(named) {
		return nil, fmt.Errorf("local input changed while reading: %s", path)
	}
	return data, nil
}

func localNativeOwnedDirectory(path string) error {
	if err := localNativeCanonical(path); err != nil {
		return err
	}
	var info unix.Stat_t
	if err := unix.Lstat(path, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("local source or slot is not an owned directory: %s", path)
	}
	return nil
}

func localNativeMissing(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("local output requires an absolute canonical path")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("local output already exists or is unsafe: %s", path)
	}
	parent := filepath.Dir(path)
	for existing := parent; ; existing = filepath.Dir(existing) {
		if _, err := os.Lstat(existing); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := localNativeCanonical(existing); err != nil {
			return err
		}
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		return localNativeCanonical(parent)
	}
}

func localNativeEnvironment() []string {
	env := []string{}
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(name, "GIT_") || name == "CGO_ENABLED" {
			continue
		}
		if strings.HasPrefix(name, "GO") {
			switch name {
			case "GOCACHE", "GOMODCACHE", "GOPATH", "GOMAXPROCS", "GOMEMLIMIT", "GOTMPDIR":
			default:
				continue
			}
		}
		env = append(env, value)
	}
	return append(env, "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off",
		"GOSUMDB=off", "GONOPROXY=none", "GOVCS=*:off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
}

func admitLocalNativeSource(ctx context.Context, path string, pin localNativeSource, version string) error {
	if err := localNativeOwnedDirectory(path); err != nil {
		return err
	}
	if !sourceCommit.MatchString(pin.Commit) || !sourceCommit.MatchString(pin.Tree) {
		return fmt.Errorf("invalid compiled local source identity")
	}
	window, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	env := localNativeEnvironment()
	git := func(limit int, args ...string) (string, error) {
		command := append([]string{
			"git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
			"-c", "core.untrackedCache=false", "-c", "core.ignoreStat=false", "-c", "core.filemode=true", "-c", "core.attributesFile=/dev/null",
		}, args...)
		raw, _, code, err := sourceCommandOutput(window, path, env, limit, command...)
		if err != nil {
			return "", err
		}
		if code == nil || *code != 0 {
			return "", fmt.Errorf("bounded local Git query failed: %s", args[0])
		}
		return raw, nil
	}
	identity, err := git(localReceiptLimit, "rev-parse", "--show-toplevel", "HEAD", "HEAD^{tree}")
	if err != nil {
		return err
	}
	if identity != path+"\n"+pin.Commit+"\n"+pin.Tree+"\n" {
		return fmt.Errorf("local source commit/tree differs: %s", path)
	}
	config, err := git(localReceiptLimit, "config", "--name-only", "--null", "--list")
	if err != nil {
		return err
	}
	for key := range strings.SplitSeq(config, "\x00") {
		if strings.HasPrefix(strings.ToLower(key), "filter.") {
			return fmt.Errorf("local source enables a Git clean filter: %s", path)
		}
	}
	tracked, err := git(32<<20, "ls-files", "-v", "-z")
	if err != nil {
		return err
	}
	tracked, ended := strings.CutSuffix(tracked, "\x00")
	for entry := range strings.SplitSeq(tracked, "\x00") {
		if !ended || !strings.HasPrefix(entry, "H ") || len(entry) <= 2 {
			return fmt.Errorf("local source has hidden or skipped tracked entries: %s", path)
		}
	}
	status, err := git(localReceiptLimit, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none")
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("local source has tracked, untracked or ignored changes: %s", path)
	}
	raw, err := readLocalNativeFile(filepath.Join(path, "release/GO_VERSION"), localReceiptLimit)
	if err != nil || "go"+strings.TrimSpace(string(raw)) != version {
		return fmt.Errorf("local source Go pin differs: %s", path)
	}
	return nil
}

func localNativeExecutionContext(recipe localNativeRecipeData) map[string]any {
	return map[string]any{
		"schema":         localNativeContext,
		"coreSource":     map[string]any{"commit": recipe.CoreSource.Commit, "tree": recipe.CoreSource.Tree},
		"producerSource": map[string]any{"commit": recipe.ProducerSource.Commit, "tree": recipe.ProducerSource.Tree},
		"host":           map[string]any{"os": "linux", "arch": "amd64"},
	}
}

func localNativeVariant() map[string]any {
	return map[string]any{"linkage": "shared-purego", "libc": "", "goarm": "", "gomips": "", "go386": "", "legacy": false}
}

func localNativeMember(name string, raw []byte) map[string]any {
	return map[string]any{"member": name, "bytes": json.Number(fmt.Sprint(len(raw))), "sha256": sha256Hex(raw)}
}

func localNativeObservedBuild(path string, data []byte, recipe localNativeRecipeData) (string, map[string]any, error) {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return "", nil, err
	}
	version, raw, graph := describeNativeBuildInfo(path, info)
	if version != recipe.GoVersion || graph.Settings["vcs.revision"] != recipe.CoreSource.Commit ||
		graph.Settings["vcs.modified"] != "false" || graph.Settings["GOOS"] != "linux" ||
		graph.Settings["GOARCH"] != "amd64" || graph.Settings["CGO_ENABLED"] != "0" ||
		!maps.Equal(nativeTagSet(graph.Settings["-tags"]), nativeTagSet(strings.Join(recipe.Tags, ","))) {
		return "", nil, fmt.Errorf("actual local Core build settings differ")
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		return "", nil, err
	}
	var observed map[string]any
	if err := uniqueJSON(bytes.NewReader(encoded), &observed); err != nil {
		return "", nil, err
	}
	return raw, observed, nil
}

func collectLocalNative(ctx context.Context, paths localNativePaths, coreOutput, sidecar, slot, recipeHash string, recipe localNativeRecipeData) (err error) {
	if paths.CoreSourceRoot == "" || coreOutput == "" || sidecar == "" || coreOutput == slot ||
		strings.HasPrefix(coreOutput, slot+string(os.PathSeparator)) || strings.HasPrefix(slot, coreOutput+string(os.PathSeparator)) {
		return fmt.Errorf("local collect requires separate explicit sources and outputs")
	}
	if err := admitLocalNativeSource(ctx, paths.CoreSourceRoot, recipe.CoreSource, recipe.GoVersion); err != nil {
		return err
	}
	if err := admitLocalNativeSource(ctx, paths.ProducerSourceRoot, recipe.ProducerSource, recipe.GoVersion); err != nil {
		return err
	}
	library, err := readLocalNativeFile(sidecar, localNativeLimit)
	if err != nil {
		return err
	}
	libraryPin := localNativeMember("libcronet.so", library)
	if int64(len(library)) != recipe.Sidecar.Bytes || libraryPin["sha256"] != recipe.Sidecar.SHA256 {
		return fmt.Errorf("sidecar bytes are not the compiled known input")
	}
	for _, path := range []string{coreOutput, slot} {
		if err := localNativeMissing(path); err != nil {
			return err
		}
	}

	private, err := os.MkdirTemp(filepath.Dir(coreOutput), ".polaris-local-native-*")
	if err != nil {
		return err
	}
	createdSlot := false
	defer func() {
		err = errors.Join(err, os.RemoveAll(private))
		if err != nil && createdSlot {
			err = errors.Join(err, os.RemoveAll(slot))
		}
	}()
	built := filepath.Join(private, "sing-box")
	command := []string{
		"go", "build", "-mod=readonly", "-buildvcs=true", "-trimpath", "-p=1", "-tags=" + strings.Join(recipe.Tags, ","),
		"-ldflags=-s -w -checklinkname=0 -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -X github.com/sagernet/sing-box/constant.Version=" +
			recipe.Version + " -X github.com/sagernet/sing-box/constant.SourceRevision=" + recipe.CoreSource.Commit,
		"-o", built, "./cmd/sing-box",
	}
	fmt.Fprintf(os.Stderr, "LOCAL_CORE_BUILD %s\n", strings.Join(command, " "))
	buildContext, cancel := context.WithTimeout(ctx, 20*time.Minute)
	stdout, stderr, status, err := sourceCommandOutput(buildContext, paths.CoreSourceRoot, localNativeEnvironment(), 2<<20, command...)
	cancel()
	if err != nil || status == nil || *status != 0 {
		return fmt.Errorf("local Core compiler failed: %v\n%s%s", err, stdout, stderr)
	}

	data, err := readLocalNativeFile(built, localNativeLimit)
	if err != nil {
		return err
	}
	raw, graph, err := localNativeObservedBuild(built, data, recipe)
	if err != nil {
		return err
	}
	if err := os.Mkdir(slot, 0o700); err != nil {
		return err
	}
	createdSlot = true
	localCore := filepath.Join(slot, "sing-box")
	if err := os.WriteFile(localCore, data, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(slot, "libcronet.so"), library, 0o600); err != nil {
		return err
	}
	corePin := localNativeMember("sing-box", data)
	archive, members, err := createLocalNativeArchive(private, paths.CoreSourceRoot, recipe.Version, data, library)
	if err != nil {
		return err
	}
	row := map[string]any{
		"version": recipe.Version, "target": localNativeTarget, "sourceCommit": recipe.CoreSource.Commit, "sourceTree": recipe.CoreSource.Tree,
		"goVersion": recipe.GoVersion, "tags": strings.Join(recipe.Tags, ","), "variant": localNativeVariant(), "buildGraph": graph, "rawBuildInfo": raw,
		"archive": archive, "core": corePin, "sidecar": libraryPin,
	}
	execution := nativeSmokeExecution{}
	if err := prepareNativeSmoke(ctx, localCore, row, members, &execution); err != nil {
		return err
	}
	if execution.proofKey != "sealedExecution" {
		return fmt.Errorf("local native product requires sealed Core and sidecar execution")
	}
	proof, err := observeNativeSmokeRuntime(ctx, paths.CoreSourceRoot, localCore, recipe.Sidecar.Version, row, execution,
		os.Stderr, filepath.Join(slot, "cronet-observation.json"))
	if err := errors.Join(err, execution.close()); err != nil {
		return err
	}
	policy := nativeExecutionPolicy(row, false)
	if err := validateLocalNativeFacts(paths, recipe, row, proof, policy); err != nil {
		return err
	}
	if err := sourceReceipt(filepath.Join(slot, "inputs.json"), paths, true, localReceiptLimit); err != nil {
		return err
	}
	for _, pin := range []map[string]any{corePin, libraryPin} {
		name := pin["member"].(string)
		actual, err := readLocalNativeFile(filepath.Join(slot, name), localNativeLimit)
		if err != nil || !reflect.DeepEqual(pin, localNativeMember(name, actual)) {
			return fmt.Errorf("local native member changed after observation: %s", name)
		}
	}
	if err := admitLocalNativeSource(ctx, paths.CoreSourceRoot, recipe.CoreSource, recipe.GoVersion); err != nil {
		return err
	}
	if err := admitLocalNativeSource(ctx, paths.ProducerSourceRoot, recipe.ProducerSource, recipe.GoVersion); err != nil {
		return err
	}
	var draft bytes.Buffer
	if err := writeJSON(&draft, map[string]any{
		"schema": localNativeSelect, "configurationSha256": recipeHash, "context": localNativeExecutionContext(recipe),
		"row": row, "proof": proof, "policy": policy,
	}); err != nil {
		return err
	}
	if draft.Len() > localReceiptLimit {
		return fmt.Errorf("local selection draft exceeds byte bound")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := draft.WriteTo(os.Stdout); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, built, unix.AT_FDCWD, coreOutput, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("could not publish fresh local Core output: %w", err)
	}
	return nil
}

func createLocalNativeArchive(directory, source, version string, core, library []byte) (_ map[string]any, _ map[string][]byte, err error) {
	root := "sing-box-" + version + "-linux-amd64"
	name := root + ".tar.gz"
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	license, err := readLocalNativeFile(filepath.Join(source, "LICENSE"), localNativeLimit)
	if err != nil {
		return nil, nil, err
	}
	notices, err := readLocalNativeFile(filepath.Join(source, "release/licenses/TLS-DEPENDENCY-NOTICES.txt"), localNativeLimit)
	if err != nil {
		return nil, nil, err
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	for _, member := range []struct {
		name string
		data []byte
		mode int64
	}{
		{"sing-box", core, 0o755},
		{"libcronet.so", library, 0o644},
		{"LICENSE", license, 0o644},
		{"TLS-DEPENDENCY-NOTICES.txt", notices, 0o644},
	} {
		if err := archive.WriteHeader(&tar.Header{
			Name: root + "/" + member.name, Mode: member.mode,
			Size: int64(len(member.data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}); err != nil {
			return nil, nil, errors.Join(err, archive.Close(), compressed.Close())
		}
		if _, err := archive.Write(member.data); err != nil {
			return nil, nil, errors.Join(err, archive.Close(), compressed.Close())
		}
	}
	if err := errors.Join(archive.Close(), compressed.Close()); err != nil {
		return nil, nil, err
	}
	raw, err := readLocalNativeFile(file.Name(), localNativeLimit)
	if err != nil {
		return nil, nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return nil, nil, err
	}
	actualRoot, members, err := readNativeArchiveFile(file)
	if err != nil || actualRoot != root || len(members) != 4 {
		return nil, nil, fmt.Errorf("local release-shaped archive differs: %v", err)
	}
	hashes := make(map[string]any, len(members))
	for member, data := range members {
		hashes[root+"/"+member] = sha256Hex(data)
	}
	return map[string]any{
		"name": name, "bytes": json.Number(fmt.Sprint(len(raw))), "sha256": sha256Hex(raw),
		"root": root, "members": hashes,
	}, members, nil
}

func readLocalNativeJSON(path string, target any) error {
	raw, err := readLocalNativeFile(path, localReceiptLimit)
	if err != nil {
		return err
	}
	return uniqueJSON(bytes.NewReader(raw), target)
}

func verifyLocalNative(ctx context.Context, producer, slot, recipeHash string, recipe localNativeRecipeData) error {
	if err := localNativeOwnedDirectory(slot); err != nil {
		return err
	}
	var input map[string]any
	if err := readLocalNativeJSON(filepath.Join(slot, "inputs.json"), &input); err != nil {
		return err
	}
	coreSource, _ := input["coreSourceRoot"].(string)
	if !localNativeClosed(input, "schema", "coreSourceRoot", "producerSourceRoot") ||
		input["schema"] != localNativeInputs || input["producerSourceRoot"] != producer || coreSource == "" {
		return fmt.Errorf("local producer paths differ")
	}
	paths := localNativePaths{localNativeInputs, coreSource, producer}
	if err := admitLocalNativeSource(ctx, paths.CoreSourceRoot, recipe.CoreSource, recipe.GoVersion); err != nil {
		return err
	}
	if err := admitLocalNativeSource(ctx, paths.ProducerSourceRoot, recipe.ProducerSource, recipe.GoVersion); err != nil {
		return err
	}
	var selection map[string]any
	if err := readLocalNativeJSON(filepath.Join(slot, "selection.json"), &selection); err != nil {
		return err
	}
	fingerprint, _ := selection["providerFingerprint"].(string)
	contract, _ := selection["contractSha256"].(string)
	if !localNativeClosed(selection, "schema", "configurationSha256", "context", "row", "proof", "policy", "providerFingerprint", "contractSha256") ||
		!nativeFieldsMatch(selection, map[string]any{"schema": localNativeSelect, "configurationSha256": recipeHash, "context": localNativeExecutionContext(recipe)}) ||
		!localNativeSHA256.MatchString(fingerprint) || !localNativeSHA256.MatchString(contract) {
		return fmt.Errorf("local selection or execution context differs")
	}
	row, _ := selection["row"].(map[string]any)
	proof, _ := selection["proof"].(map[string]any)
	if err := verifyLocalNativeMembers(slot, row, recipe); err != nil {
		return err
	}
	if err := validateLocalNativeFacts(paths, recipe, row, proof, selection["policy"]); err != nil {
		return err
	}
	return ctx.Err()
}

func verifyLocalNativeMembers(slot string, row map[string]any, recipe localNativeRecipeData) error {
	core := filepath.Join(slot, "sing-box")
	data, err := readLocalNativeFile(core, localNativeLimit)
	if err != nil {
		return err
	}
	library, err := readLocalNativeFile(filepath.Join(slot, "libcronet.so"), localNativeLimit)
	if err != nil {
		return err
	}
	if !nativeFieldsMatch(row, map[string]any{"core": localNativeMember("sing-box", data), "sidecar": localNativeMember("libcronet.so", library)}) {
		return fmt.Errorf("final local member differs")
	}
	raw, graph, err := localNativeObservedBuild(core, data, recipe)
	if err != nil {
		return err
	}
	recorded, _ := row["rawBuildInfo"].(string)
	first, recorded, _ := strings.Cut(recorded, "\n")
	_, actual, _ := strings.Cut(raw, "\n")
	if !strings.HasSuffix(first, ": "+recipe.GoVersion) || recorded != actual || !reflect.DeepEqual(row["buildGraph"], graph) {
		return fmt.Errorf("local actual buildinfo differs")
	}
	return nil
}

func validateLocalNativeFacts(paths localNativePaths, recipe localNativeRecipeData, row, proof map[string]any, policy any) error {
	if !localNativeClosed(row, "version", "target", "sourceCommit", "sourceTree", "goVersion", "tags", "variant",
		"buildGraph", "rawBuildInfo", "archive", "core", "sidecar", "finalPackageCronetSmoke") ||
		!nativeFieldsMatch(row, map[string]any{
			"sourceCommit": recipe.CoreSource.Commit, "sourceTree": recipe.CoreSource.Tree, "version": recipe.Version,
			"target": recipe.Target, "goVersion": recipe.GoVersion, "tags": strings.Join(recipe.Tags, ","), "variant": localNativeVariant(),
			"sidecar": map[string]any{"member": "libcronet.so", "bytes": json.Number(fmt.Sprint(recipe.Sidecar.Bytes)), "sha256": recipe.Sidecar.SHA256},
		}) || !reflect.DeepEqual(policy, nativeExecutionPolicy(row, false)) {
		return fmt.Errorf("local protected row, sidecar or policy differs")
	}
	archive, _ := row["archive"].(map[string]any)
	root := "sing-box-" + recipe.Version + "-linux-amd64"
	archiveHash, _ := archive["sha256"].(string)
	archiveBytes, exact := nativePositiveInteger(archive["bytes"])
	members, _ := archive["members"].(map[string]any)
	if !localNativeClosed(archive, "name", "root", "bytes", "sha256", "members") ||
		!nativeFieldsMatch(archive, map[string]any{"name": root + ".tar.gz", "root": root}) ||
		!exact || archiveBytes > localNativeLimit || !localNativeSHA256.MatchString(archiveHash) ||
		!localNativeClosed(members, root+"/sing-box", root+"/libcronet.so", root+"/LICENSE", root+"/TLS-DEPENDENCY-NOTICES.txt") {
		return fmt.Errorf("local archive identity differs")
	}
	for _, member := range []string{"LICENSE", "release/licenses/TLS-DEPENDENCY-NOTICES.txt"} {
		raw, err := readLocalNativeFile(filepath.Join(paths.CoreSourceRoot, member), localNativeLimit)
		if err != nil || members[root+"/"+filepath.Base(member)] != sha256Hex(raw) {
			return fmt.Errorf("local archive source notice differs: %s", member)
		}
	}
	var schema map[string]any
	if err := readLocalNativeJSON(filepath.Join(paths.ProducerSourceRoot, nativeIndexSchema), &schema); err != nil {
		return err
	}
	definitions, _ := schema["$defs"].(map[string]any)
	sealed, _ := definitions["sealedExecution"].(map[string]any)
	properties, _ := sealed["properties"].(map[string]any)
	if len(properties) == 0 || properties["runId"] == nil || properties["runAttempt"] == nil {
		return fmt.Errorf("source-pinned sealed evidence schema differs")
	}
	// The local lane admits the same facts without transport run identity.
	delete(properties, "runId")
	delete(properties, "runAttempt")
	fields := make([]string, 0, len(properties))
	for key := range properties {
		fields = append(fields, key)
	}
	slices.Sort(fields)
	if !localNativeClosed(proof, fields...) {
		return fmt.Errorf("local proof facts differ or carry workflow identity")
	}
	required := make([]any, 0, len(fields))
	for _, name := range fields {
		required = append(required, name)
	}
	sealed["required"] = required
	if err := validateSchema(schema, "#/$defs/sealedExecution", proof); err != nil {
		return fmt.Errorf("local sealed execution proof: %w", err)
	}
	core, _ := row["core"].(map[string]any)
	if !nativeArchiveMember(archive, core, "sing-box") || !nativeFieldsMatch(proof, map[string]any{
		"sourceCommit": row["sourceCommit"], "sourceTree": row["sourceTree"], "version": row["version"], "target": row["target"],
		"archiveSha256": archiveHash, "core": core, "sidecar": row["sidecar"],
	}) {
		return fmt.Errorf("local sealed execution source, target or package differs")
	}
	smoke, _ := row["finalPackageCronetSmoke"].(map[string]any)
	if proof["cronet"].(map[string]any)["version"] != recipe.Sidecar.Version ||
		!localNativeClosed(smoke, "status", "os", "arch", "go", "gvisorCompiled", "naiveOutbound", "linkage", "version", "librarySha256", "coreSha256") {
		return fmt.Errorf("local sealed Cronet facts differ")
	}
	if err := verifyLinuxNativeEvidence(row, archive, proof, smoke); err != nil {
		return err
	}
	return verifyNativeTLS(paths.CoreSourceRoot, row, proof["tlsProbe"].(map[string]any))
}
