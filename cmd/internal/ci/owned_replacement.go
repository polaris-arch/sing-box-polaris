package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/sumdb/dirhash"
)

const (
	originalOpenConnect = "github.com/sagernet/sing-openconnect"
	ownedOpenConnect    = "github.com/polaris-arch/sing-openconnect"
	ownedZIPLimit       = 32 << 20
)

var immutableModuleVersion = regexp.MustCompile("^v[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$")

type ownedModuleDownload func(root, goVersion string, id materialIdentity) ([]byte, error)

// Owned module bytes are acquired in a fresh Go cache through the public proxy
// and checksum database. The caller can then independently verify the returned
// ZIP against the checked-out pin and retained historical notices.
func downloadOwnedReplacement(root, goVersion string, id materialIdentity) ([]byte, error) {
	temporary, err := os.MkdirTemp("", "polaris-module-source-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temporary)
	env := append(os.Environ(),
		"GOENV=off", "GO111MODULE=on", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly",
		"GOPROXY="+moduleProxy, "GOSUMDB=sum.golang.org", "GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=", "GOINSECURE=",
		"GOMODCACHE="+filepath.Join(temporary, "modules"), "GOPATH="+filepath.Join(temporary, "gopath"),
	)
	goEnv, err := sourceGoEnvironment(context.Background(), root, env, "GOVERSION")
	if err != nil {
		return nil, err
	}
	if goEnv[0] != "go"+goVersion {
		return nil, fmt.Errorf("source acquisition requires the source-owned Go version")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	output, _, exit, err := sourceCommandOutput(ctx, temporary, env, 64<<10, "go", "mod", "download", "-json", id.module+"@"+id.version)
	if err != nil {
		return nil, err
	}
	var download struct{ Path, Version, Sum, Zip, Error string }
	if err := uniqueJSON(strings.NewReader(output), &download); err != nil {
		return nil, fmt.Errorf("invalid owned module download receipt: %w", err)
	}
	if exit == nil || *exit != 0 || download.Error != "" || download.Path != id.module || download.Version != id.version ||
		download.Sum != id.h1 || download.Zip == "" {
		return nil, fmt.Errorf("downloaded module identity or Go h1 differs")
	}
	relative, err := filepath.Rel(temporary, download.Zip)
	if err != nil {
		return nil, err
	}
	archive, err := openNativeSource(temporary, filepath.ToSlash(relative))
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	return readNativeBytes(archive, ownedZIPLimit)
}

func ownedReplacementMaterials(item map[string]any, id materialIdentity, root string, notice distributionNotices, goVersion string, download ownedModuleDownload) (map[string]any, error) {
	original := materialID(item)
	if original.module != originalOpenConnect || id.module != ownedOpenConnect || !immutableModuleVersion.MatchString(id.version) {
		return nil, fmt.Errorf("replacement is not the immutable owned OpenConnect source")
	}
	if err := validateOwnedSourcePins(root, original, id); err != nil {
		return nil, err
	}
	indexes, expected, err := ownedExpectedNotices(notice, original)
	if err != nil {
		return nil, err
	}
	archive, err := download(root, goVersion, id)
	if err != nil {
		return nil, err
	}
	if err := verifyOwnedArchive(archive, id, expected); err != nil {
		return nil, err
	}
	url, err := goModuleZipURL(id)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"availabilityVerified": true,
		"sourceArchive":        map[string]any{"zipUrl": url, "zipBytes": json.Number(strconv.Itoa(len(archive))), "zipSha256": sha256Hex(archive)},
		"noticeRecordIndexes":  indexes,
		"sourceEvidence":       "Go module download verified against source go.mod/go.sum and BuildInfo; unchanged historical notice bytes",
	}, nil
}

func validateOwnedSourcePins(root string, original, owned materialIdentity) error {
	content, err := readNativeSource(root, "go.mod")
	if err != nil {
		return err
	}
	mod, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return err
	}
	requirements, replacements := 0, 0
	for _, require := range mod.Require {
		if require.Mod.Path == original.module {
			if require.Mod.Version != original.version {
				return fmt.Errorf("BuildInfo requirement differs from source go.mod")
			}
			requirements++
		}
	}
	for _, replace := range mod.Replace {
		if replace.Old.Path == original.module && (replace.Old.Version == "" || replace.Old.Version == original.version) {
			if replace.New.Path != owned.module || replace.New.Version != owned.version {
				return fmt.Errorf("BuildInfo replacement differs from source go.mod")
			}
			replacements++
		}
	}
	if requirements != 1 || replacements != 1 {
		return fmt.Errorf("BuildInfo has no unique source go.mod requirement and replacement")
	}
	sums, err := readNativeSource(root, "go.sum")
	if err != nil {
		return err
	}
	count := 0
	for line := range strings.SplitSeq(string(sums), "\n") {
		split := strings.Fields(line)
		if len(split) == 3 && split[0] == owned.module && split[1] == owned.version {
			if split[2] != owned.h1 {
				return fmt.Errorf("BuildInfo replacement h1 differs from source go.sum")
			}
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("BuildInfo replacement needs one exact source go.sum receipt")
	}
	return nil
}

func ownedExpectedNotices(notice distributionNotices, original materialIdentity) ([]any, map[string][]byte, error) {
	var component map[string]any
	for _, item := range notice.Components {
		if item["module"] != original.module || item["version"] != original.version {
			continue
		}
		if component != nil || (original.h1 != "" && item["h1"] != original.h1) {
			return nil, nil, fmt.Errorf("original module has no exact historical notice component")
		}
		component = item
	}
	indexes, _ := component["noticeRecordIndexes"].([]any)
	if len(indexes) == 0 {
		return nil, nil, fmt.Errorf("original module has no notice records")
	}
	expected := make(map[string][]byte, len(indexes))
	prefix := original.module + "@" + original.version + "/"
	for _, index := range indexes {
		listIndex, ok := index.(json.Number)
		position, err := listIndex.Int64()
		if !ok || err != nil || position < 0 || position >= int64(len(notice.Records)) {
			return nil, nil, fmt.Errorf("invalid historical notice record offset")
		}
		record := notice.Records[position]
		name, matches := strings.CutPrefix(record.SourcePath, prefix)
		if !matches || !checkedRelative(name) {
			return nil, nil, fmt.Errorf("original notice source path differs")
		}
		if _, exists := expected[name]; exists {
			return nil, nil, fmt.Errorf("duplicate historical notice path")
		}
		expected[name] = notice.slice(record)
	}
	return indexes, expected, nil
}

func verifyOwnedArchive(data []byte, id materialIdentity, expected map[string][]byte) error {
	if len(data) > ownedZIPLimit {
		return fmt.Errorf("owned module ZIP exceeds byte bound")
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	prefix := id.module + "@" + id.version + "/"
	files := make(map[string]*zip.File, len(archive.File))
	names := make([]string, 0, len(archive.File))
	seen := make(map[string]bool, len(expected))
	remaining := uint64(ownedZIPLimit)
	for _, entry := range archive.File {
		if files[entry.Name] != nil || entry.UncompressedSize64 > remaining {
			return fmt.Errorf("duplicate or oversized module ZIP member")
		}
		remaining -= entry.UncompressedSize64
		files[entry.Name] = entry
		names = append(names, entry.Name)
		if entry.FileInfo().IsDir() {
			continue
		}
		name, match := strings.CutPrefix(entry.Name, prefix)
		if !match || !checkedRelative(name) || !entry.Mode().IsRegular() {
			return fmt.Errorf("downloaded module ZIP member path or type differs")
		}
		want, known := expected[name]
		if !known && !ownedNoticePath(name) {
			continue
		}
		if !known || entry.UncompressedSize64 != uint64(len(want)) {
			return fmt.Errorf("downloaded module notices differ from the historical bundle")
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		actual, err := readNativeBytes(input, int64(len(want)))
		input.Close()
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, want) {
			return fmt.Errorf("downloaded module notices differ from the historical bundle")
		}
		seen[name] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("downloaded module notices differ from the historical bundle")
	}
	h1, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) { return files[name].Open() })
	if err != nil {
		return err
	}
	if h1 != id.h1 {
		return fmt.Errorf("downloaded module ZIP h1 differs")
	}
	return nil
}

func ownedNoticePath(name string) bool {
	historical := strings.ToLower(path.Base(name))
	for _, prefix := range []string{"license", "licence", "copying", "notice", "copyright", "patents"} {
		if strings.HasPrefix(historical, prefix) {
			return true
		}
	}
	for parent := range strings.SplitSeq(path.Dir(name), "/") {
		switch strings.ToLower(parent) {
		case "licenses", "licences", "notices":
			return true
		}
	}
	return false
}
