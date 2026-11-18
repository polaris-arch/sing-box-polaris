package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	cronetOverlayManifest = "release/dependency-sources/cronet-go-windows-native-observation.json"
	cronetOverlayPatch    = "release/dependency-sources/cronet-go-windows-native-observation.patch"
	cronetVendor          = "third_party/cronet-go"
	cronetBaseCommit      = "c7960c2020904d90aebb74ad6320bb3701f6041e"
	cronetBaseTree        = "42f8717ff0a1ae0329d5825f14e4b75e3f66a713"
	cronetBaseVendorTree  = "444994a3a06f5a6c184060448b9ea00e4d59ec27"
	cronetMaxFileBytes    = 4 * 1024 * 1024
	cronetMaxTotalBytes   = 16 * 1024 * 1024
	cronetMaxEntries      = 256
)

type cronetMaterial struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

var cronetHistory = map[string]cronetMaterial{
	"release/dependency-sources/cronet-go-replacement.json":       {54745, "d0835f0590a179b43c560bc4c348a627f6d7af4bcffeb1bd33b8febfe23757d1"},
	"release/dependency-sources/cronet-go-client-admission.patch": {19010, "8595a6da43ef8241cedec593bccf07ab81a0afa8281de21567fc8920445699d4"},
}

var (
	cronetPathChars = regexp.MustCompile(`^[A-Za-z0-9_.+/-]+$`)
	cronetSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type cronetOverlayFile struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Bytes  *int   `json:"bytes"`
	SHA256 string `json:"sha256"`
	Blob   string `json:"gitBlob"`
}

type cronetOverlayChange struct {
	Path      string         `json:"path"`
	Operation string         `json:"operation"`
	Before    jsontext.Value `json:"before"`
	After     jsontext.Value `json:"after"`
}

type cronetOverlayManifestData struct {
	Schema          string `json:"schema"`
	Module          string `json:"module"`
	ReplacementPath string `json:"replacementPath"`
	BaseCommit      string `json:"baseCommit"`
	BaseTree        string `json:"baseTree"`
	BaseVendorTree  string `json:"baseVendorTree"`
	BaseTreeProof   []struct {
		Path      *string `json:"path"`
		Tree      string  `json:"gitTree"`
		RawBase64 string  `json:"rawBase64"`
	} `json:"baseTreeProof"`
	BaseFiles             []*cronetOverlayFile      `json:"baseFiles"`
	UnchangedGitlinks     []jsontext.Value          `json:"unchangedGitlinks"`
	Changes               []cronetOverlayChange     `json:"changes"`
	Patch                 string                    `json:"patch"`
	PatchSHA256           string                    `json:"patchSHA256"`
	HistoricalMaterials   map[string]cronetMaterial `json:"historicalMaterials"`
	NativeBinaryValidated *bool                     `json:"nativeBinaryValidated"`
	Scope                 string                    `json:"scope"`
	PatchContextLines     *int                      `json:"patchContextLines"`
}

func cronetOverlayCommand(args []string) error {
	if len(args) < 2 || args[0] != "--source-root" || args[1] == "" {
		return fmt.Errorf("expected cronet-overlay --source-root DIRECTORY [--native-source-identity]")
	}
	if len(args) == 3 && args[2] == "--native-source-identity" {
		source, err := nativeCollectorSource(args[1])
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, source)
	}
	if len(args) != 2 {
		return fmt.Errorf("unexpected cronet-overlay arguments")
	}
	inputs, err := validateCronetOverlay(args[1])
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, inputs)
}

func cronetOverlayPath(name string) bool {
	return len(name) <= 240 && name != "." && checkedRelative(name) && cronetPathChars.MatchString(name)
}

func (record *cronetOverlayFile) valid() bool {
	return record != nil && cronetOverlayPath(record.Path) && (record.Mode == "100644" || record.Mode == "100755") &&
		record.Bytes != nil && *record.Bytes >= 0 && *record.Bytes <= cronetMaxFileBytes &&
		cronetSHA256.MatchString(record.SHA256) && sourceCommit.MatchString(record.Blob)
}

func (record *cronetOverlayFile) verify(raw []byte, digest string) error {
	if len(raw) != *record.Bytes || digest != record.SHA256 || gitObjectHash("blob", raw) != record.Blob {
		return fmt.Errorf("file bytes/blob differ: %s", record.Path)
	}
	return nil
}

func cronetProofChild(raw []byte, child string) (string, error) {
	var previous, tree string
	seen := make(map[string]bool)
	for len(raw) != 0 {
		header, rest, found := bytes.Cut(raw, []byte{0})
		if !found || len(rest) < 20 {
			return "", fmt.Errorf("truncated tree proof")
		}
		mode, name, found := strings.Cut(string(header), " ")
		if !found || !cronetOverlayPath(name) || strings.Contains(name, "/") || seen[name] {
			return "", fmt.Errorf("duplicate/invalid tree entry")
		}
		seen[name] = true
		key := name
		switch mode {
		case "40000":
			key += "/"
			if name == child {
				tree = hex.EncodeToString(rest[:20])
			}
		case "100644", "100755", "120000", "160000":
		default:
			return "", fmt.Errorf("invalid tree entry mode")
		}
		if key <= previous {
			return "", fmt.Errorf("noncanonical tree order")
		}
		previous, raw = key, rest[20:]
	}
	if tree == "" {
		return "", fmt.Errorf("missing vendor ancestor: %s", child)
	}
	return tree, nil
}

func cronetInventoryTree(files map[string]*cronetOverlayFile) (string, error) {
	trees := map[string]map[string]indexEntry{".": {}}
	for name, record := range files {
		for dir := path.Dir(name); trees[dir] == nil; dir = path.Dir(dir) {
			trees[dir] = make(map[string]indexEntry)
		}
		trees[path.Dir(name)][path.Base(name)] = indexEntry{record.Mode, record.Blob}
	}
	for _, dir := range slices.Backward(slices.Sorted(maps.Keys(trees))) {
		if dir == "." {
			continue
		}
		parent, name := trees[path.Dir(dir)], path.Base(dir)
		if _, found := parent[name]; found {
			return "", fmt.Errorf("file/directory collision: %s", dir)
		}
		digest, err := gitTreeHash(trees[dir])
		if err != nil {
			return "", err
		}
		parent[name] = indexEntry{"40000", digest}
	}
	return gitTreeHash(trees["."])
}

func validateCronetOverlay(root string) (map[string]string, error) {
	inputs, err := readCronetOverlay(root)
	if err != nil {
		return nil, fmt.Errorf("Cronet Windows overlay: %w", err)
	}
	return inputs, nil
}

func readCronetOverlay(root string) (map[string]string, error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || redirectedSource(info) {
		return nil, fmt.Errorf("source root is not a real directory")
	}
	inputs := make(map[string]string)
	remaining := cronetMaxTotalBytes
	read := func(name string) ([]byte, error) {
		filename, err := regularSource(root, name)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > cronetMaxFileBytes {
			return nil, fmt.Errorf("nonregular/oversized data file: %s", name)
		}
		limit := min(cronetMaxFileBytes, remaining)
		raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > limit {
			return nil, fmt.Errorf("data byte budget exceeded: %s", name)
		}
		remaining -= len(raw)
		inputs[name] = sha256Hex(raw)
		return raw, nil
	}

	raw, err := read(cronetOverlayManifest)
	if err != nil {
		return nil, err
	}
	var manifest cronetOverlayManifestData
	if err := json.Unmarshal(raw, &manifest, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("invalid manifest JSON: %w", err)
	}
	if manifest.Schema != "polaris-source-bound-module-overlay-v1" || manifest.Module != "github.com/sagernet/cronet-go" ||
		manifest.ReplacementPath != cronetVendor || manifest.BaseCommit != cronetBaseCommit || manifest.BaseTree != cronetBaseTree ||
		manifest.BaseVendorTree != cronetBaseVendorTree || manifest.UnchangedGitlinks == nil || len(manifest.UnchangedGitlinks) != 0 ||
		manifest.Patch != cronetOverlayPatch || !cronetSHA256.MatchString(manifest.PatchSHA256) || !maps.Equal(manifest.HistoricalMaterials, cronetHistory) ||
		manifest.NativeBinaryValidated == nil || *manifest.NativeBinaryValidated || manifest.PatchContextLines == nil || *manifest.PatchContextLines != 0 ||
		manifest.Scope == "" || utf8.RuneCountInString(manifest.Scope) > 512 {
		return nil, fmt.Errorf("fixed version/base/history/scope differs")
	}
	if len(manifest.BaseTreeProof) != 2 || len(manifest.BaseFiles) != 135 || len(manifest.Changes) != 6 {
		return nil, fmt.Errorf("tree proof, base or delta count differs")
	}
	parent := cronetBaseTree
	for index, proof := range manifest.BaseTreeProof {
		ancestor := [...]string{"", "third_party"}[index]
		child := [...]string{"third_party", "cronet-go"}[index]
		if proof.Path == nil || *proof.Path != ancestor || proof.Tree != parent || len(proof.RawBase64) > 65536 || strings.ContainsAny(proof.RawBase64, "\r\n") {
			return nil, fmt.Errorf("tree proof binding differs")
		}
		raw, err := base64.StdEncoding.DecodeString(proof.RawBase64)
		if err != nil || gitObjectHash("tree", raw) != parent {
			return nil, fmt.Errorf("tree encoding or Merkle identity differs")
		}
		parent, err = cronetProofChild(raw, child)
		if err != nil {
			return nil, err
		}
	}
	if parent != cronetBaseVendorTree {
		return nil, fmt.Errorf("vendor Merkle binding differs")
	}
	expected := make(map[string]*cronetOverlayFile)
	for _, record := range manifest.BaseFiles {
		if !record.valid() || expected[record.Path] != nil {
			return nil, fmt.Errorf("invalid or duplicate base file record")
		}
		expected[record.Path] = record
	}
	if tree, err := cronetInventoryTree(expected); err != nil || tree != cronetBaseVendorTree {
		return nil, fmt.Errorf("complete base Merkle identity differs")
	}

	changes := make(map[string]cronetPatchChange)
	for _, item := range manifest.Changes {
		name := item.Path
		if _, duplicate := changes[name]; duplicate || !cronetOverlayPath(name) {
			return nil, fmt.Errorf("invalid or duplicate delta path: %s", name)
		}
		var change cronetPatchChange
		for _, record := range []struct {
			raw    jsontext.Value
			target **cronetOverlayFile
		}{{item.Before, &change.before}, {item.After, &change.after}} {
			if err := json.Unmarshal(record.raw, record.target, json.RejectUnknownMembers(true)); err != nil {
				return nil, fmt.Errorf("invalid delta record %s: %w", name, err)
			}
			if file := *record.target; file != nil && (!file.valid() || file.Path != name) {
				return nil, fmt.Errorf("delta record identity differs: %s", name)
			}
		}
		if !reflect.DeepEqual(change.before, expected[name]) || reflect.DeepEqual(change.before, change.after) {
			return nil, fmt.Errorf("duplicate/mismatched delta: %s", name)
		}
		operation := "modify"
		switch {
		case change.before == nil:
			operation = "add"
		case change.after == nil:
			operation = "delete"
		}
		if item.Operation != operation {
			return nil, fmt.Errorf("delta operation differs: %s", name)
		}
		changes[name] = change
		if change.after == nil {
			delete(expected, name)
		} else {
			expected[name] = change.after
		}
	}
	if len(expected) != 137 {
		return nil, fmt.Errorf("current file count differs")
	}
	current, err := readCronetVendor(root, expected, changes, inputs, read)
	if err != nil {
		return nil, err
	}
	for name, pin := range cronetHistory {
		raw, err := read(name)
		if err != nil {
			return nil, err
		}
		if len(raw) != pin.Bytes || inputs[name] != pin.SHA256 {
			return nil, fmt.Errorf("historical material differs: %s", name)
		}
	}
	patch, err := read(cronetOverlayPatch)
	if err != nil {
		return nil, err
	}
	if inputs[cronetOverlayPatch] != manifest.PatchSHA256 {
		return nil, fmt.Errorf("patch SHA256 differs")
	}
	if err := replayCronetPatch(patch, changes, current); err != nil {
		return nil, err
	}
	return inputs, nil
}

func readCronetVendor(root string, expected map[string]*cronetOverlayFile, changes map[string]cronetPatchChange, inputs map[string]string, read func(string) ([]byte, error)) (map[string][]byte, error) {
	dirs := make(map[string]bool)
	for name := range expected {
		for dir := path.Dir(name); dir != "." && !dirs[dir]; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	for _, name := range []string{"third_party", cronetVendor} {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || !info.IsDir() || redirectedSource(info) {
			return nil, fmt.Errorf("vendor directory differs: %s", name)
		}
	}
	current := make(map[string][]byte)
	remaining, files := cronetMaxEntries, 0
	var walk func(string) error
	walk = func(directory string) error {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(path.Join(cronetVendor, directory))))
		if err != nil {
			return err
		}
		entries, err := file.ReadDir(remaining + 1)
		file.Close()
		if err != nil && err != io.EOF {
			return err
		}
		remaining -= len(entries)
		if remaining < 0 {
			return fmt.Errorf("vendor entry budget exceeded")
		}
		for _, entry := range entries {
			name := path.Join(directory, entry.Name())
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if redirectedSource(info) {
				return fmt.Errorf("vendor link: %s", name)
			}
			if info.IsDir() && dirs[name] {
				if err := walk(name); err != nil {
					return err
				}
				continue
			}
			record := expected[name]
			if record == nil || !info.Mode().IsRegular() {
				return fmt.Errorf("extra or nonregular vendor member: %s", name)
			}
			mode := "100644"
			if info.Mode()&0o100 != 0 {
				mode = "100755"
			}
			if mode != record.Mode {
				return fmt.Errorf("current file mode differs: %s", name)
			}
			filename := cronetVendor + "/" + name
			raw, err := read(filename)
			if err != nil {
				return err
			}
			if err := record.verify(raw, inputs[filename]); err != nil {
				return err
			}
			files++
			if _, changed := changes[name]; changed {
				current[name] = raw
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	if files != len(expected) {
		return nil, fmt.Errorf("missing current vendor members")
	}
	return current, nil
}
