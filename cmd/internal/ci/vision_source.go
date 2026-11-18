package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
)

const (
	visionModule      = "github.com/sagernet/sing-vmess"
	visionVersion     = "v0.2.9-0.20260929152519-9b95ab8c9478"
	visionPrefix      = "third_party/sing-vmess/"
	visionBinding     = "release/dependency-sources/sing-vmess-replacement.json"
	refractionVersion = "v1.8.3-0.20261006222701-ff1b50fbbe9a"
)

type sourceRow struct {
	SHA256  string `json:"afterSHA256"`
	GitBlob string `json:"gitBlob"`
	Mode    string `json:"mode"`
	Bytes   int64  `json:"bytes"`
}

type replacementManifest struct {
	Schema               string               `json:"schema"`
	Module               string               `json:"module"`
	UpstreamVersion      string               `json:"upstreamVersion"`
	UpstreamH1           string               `json:"upstreamH1"`
	UpstreamCommit       string               `json:"upstreamCommit"`
	UpstreamTree         string               `json:"upstreamTree"`
	ReplacementPath      string               `json:"replacementPath"`
	ReplacementTree      string               `json:"replacementTree"`
	ReplacementFileCount int                  `json:"replacementFileCount"`
	UpstreamFileCount    int                  `json:"upstreamFileCount"`
	Files                map[string]sourceRow `json:"files"`
	Patch                string               `json:"patch"`
	PatchSHA256          string               `json:"patchSHA256"`
	Notice               struct {
		Path              string `json:"path"`
		UnchangedUpstream bool   `json:"unchangedUpstream"`
		SHA256            string `json:"sha256"`
		Bytes             int64  `json:"bytes"`
		ExistingBundle    string `json:"existingBundle"`
		ExistingOffset    int64  `json:"existingByteOffset"`
	} `json:"notice"`
}

func visionGitInventory(root string, diagnostics map[string]any) (map[string]indexEntry, error) {
	read := func(args ...string) ([]byte, error) {
		output, _, code, err := sourceGitResult(context.Background(), root, nil, args...)
		if err != nil {
			return nil, err
		}
		if code == nil || *code != 0 {
			return nil, fmt.Errorf("Vision Windows Git source metadata unavailable")
		}
		return []byte(output), nil
	}
	top, err := read("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	actual, err := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	if err != nil {
		return nil, err
	}
	expectedPath, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	expected, err := filepath.EvalSymlinks(expectedPath)
	if err != nil {
		return nil, err
	}
	actual, expected = filepath.Clean(actual), filepath.Clean(expected)
	same := actual == expected
	if runtime.GOOS == "windows" {
		same = strings.EqualFold(actual, expected)
	}
	if !same {
		return nil, fmt.Errorf("Vision Windows source root is not Git top level")
	}
	inventories := map[string]map[string]indexEntry{}
	stages := map[string]string{}
	diagnostics["git"], diagnostics["indexStages"] = inventories, stages
	for _, kind := range []string{"head", "index"} {
		args := []string{"ls-tree", "-r", "-z", "HEAD", "--", visionPrefix}
		if kind == "index" {
			args = []string{"ls-files", "--stage", "-z", "--", visionPrefix}
		}
		data, err := read(args...)
		if err != nil {
			return nil, err
		}
		rows := map[string]indexEntry{}
		inventories[kind] = rows
		for _, raw := range bytes.Split(data, []byte{0}) {
			if len(raw) == 0 {
				continue
			}
			header, filename, found := bytes.Cut(raw, []byte{'\t'})
			if !found || !utf8.Valid(filename) || !strings.HasPrefix(string(filename), visionPrefix) {
				return nil, fmt.Errorf("Vision Git inventory escaped module")
			}
			name := strings.TrimPrefix(string(filename), visionPrefix)
			fields := strings.Split(string(header), " ")
			valid := len(fields) == 3
			mode, blob := "", ""
			if valid {
				mode = fields[0]
				if kind == "head" {
					valid = fields[1] == "blob"
					blob = fields[2]
				} else {
					blob = fields[1]
					stages[name] = fields[2]
					valid = fields[2] == "0"
				}
			}
			_, duplicate := rows[name]
			if !valid || mode != "100644" && mode != "100755" || !sourceCommit.MatchString(blob) || duplicate {
				diagnostics["invalidGitEntry"] = map[string]any{"kind": kind, "path": name, "header": string(header)}
				return nil, fmt.Errorf("Vision Git inventory is not unique regular stage zero source")
			}
			rows[name] = indexEntry{mode, blob}
		}
	}
	if len(inventories["head"]) == 0 || !reflect.DeepEqual(inventories["head"], inventories["index"]) {
		return nil, fmt.Errorf("Vision HEAD/index source identity differs")
	}
	return inventories["index"], nil
}

func requireModulePin(filename string, contents []byte, module, version string) error {
	parsed, err := modfile.Parse(filename, contents, nil)
	if err != nil {
		return err
	}
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == module && requirement.Mod.Version == version {
			return nil
		}
	}
	return fmt.Errorf("source module pin differs: %s", module)
}

func validateVisionSource(root string, diagnostics map[string]any) (map[string]any, error) {
	if diagnostics == nil {
		diagnostics = map[string]any{}
	}
	windows := runtime.GOOS == "windows"
	modeSource := "posix-filesystem"
	if windows {
		modeSource = "git-head-and-index"
	}
	diagnostics["modeSource"] = modeSource
	manifestBytes, err := os.ReadFile(filepath.Join(root, visionBinding))
	if err != nil {
		return nil, err
	}
	var manifest replacementManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	if manifest.Schema != "polaris-repository-module-replacement-v1" || manifest.Module != visionModule || manifest.UpstreamVersion != visionVersion || manifest.UpstreamCommit != "9b95ab8c9478f8e8ebe5758d325ec8cda8197c5c" || manifest.UpstreamTree != "a06b7a8c92405026f307860c7172765924209470" || manifest.ReplacementPath != "./third_party/sing-vmess" {
		return nil, fmt.Errorf("Vision source baseline differs")
	}
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	if err := requireModulePin("go.mod", module, visionModule, visionVersion); err != nil {
		return nil, err
	}
	parsed, err := modfile.Parse("go.mod", module, nil)
	if err != nil {
		return nil, err
	}
	replaced := false
	for _, replacement := range parsed.Replace {
		if replacement.Old.Path == visionModule && replacement.New.Path == "./third_party/sing-vmess" && replacement.New.Version == "" {
			replaced = true
		}
	}
	if !replaced {
		return nil, fmt.Errorf("Vision root replacement differs")
	}
	nested := filepath.Join(root, "third_party/sing-vmess")
	for _, directory := range []string{filepath.Dir(nested), nested} {
		info, err := os.Lstat(directory)
		if err != nil || redirectedSource(info) || !info.IsDir() {
			return nil, fmt.Errorf("Vision replacement root redirected")
		}
	}
	metadata := map[string]indexEntry{}
	var metadataError error
	if windows {
		metadata, metadataError = visionGitInventory(root, diagnostics)
		if metadataError != nil {
			diagnostics["metadataError"] = metadataError.Error()
		}
	}
	observed := map[string]sourceRow{}
	diagnostics["observed"], diagnostics["expected"] = observed, manifest.Files
	filesystemModes, statModes := map[string]string{}, map[string]string{}
	diagnostics["filesystemModes"], diagnostics["filesystemStatModes"] = filesystemModes, statModes
	var tree func(string) (string, error)
	tree = func(directory string) (string, error) {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return "", err
		}
		type treeRow struct {
			key  string
			data []byte
		}
		rows := []treeRow{}
		for _, entry := range entries {
			filename := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(filename)
			if err != nil {
				return "", err
			}
			if redirectedSource(info) {
				return "", fmt.Errorf("Vision replacement link")
			}
			mode, blob, key := "40000", "", entry.Name()+"/"
			if info.IsDir() {
				blob, err = tree(filename)
				if err != nil {
					return "", err
				}
			} else if info.Mode().IsRegular() {
				data, err := os.ReadFile(filename)
				if err != nil {
					return "", err
				}
				mode = "100644"
				if info.Mode().Perm()&0o111 != 0 {
					mode = "100755"
				}
				name, err := filepath.Rel(nested, filename)
				if err != nil {
					return "", err
				}
				name = filepath.ToSlash(name)
				filesystemModes[name] = mode
				statMode := uint32(info.Mode().Perm()) | 0o100000
				for flag, bits := range map[os.FileMode]uint32{os.ModeSetuid: 0o4000, os.ModeSetgid: 0o2000, os.ModeSticky: 0o1000} {
					if info.Mode()&flag != 0 {
						statMode |= bits
					}
				}
				statModes[name] = fmt.Sprintf("0o%o", statMode)
				if windows {
					mode = metadata[name].Mode
					if mode == "" {
						mode = "untracked"
					}
				}
				blob, key = gitObjectHash("blob", data), entry.Name()
				observed[name] = sourceRow{sha256Hex(data), blob, mode, int64(len(data))}
			} else {
				return "", fmt.Errorf("Vision non-regular source")
			}
			oid, err := hex.DecodeString(blob)
			if err != nil {
				return "", err
			}
			row := append([]byte(mode+" "+entry.Name()+"\x00"), oid...)
			rows = append(rows, treeRow{key, row})
		}
		slices.SortFunc(rows, func(a, b treeRow) int { return strings.Compare(a.key, b.key) })
		var raw bytes.Buffer
		for _, row := range rows {
			raw.Write(row.data)
		}
		return gitObjectHash("tree", raw.Bytes()), nil
	}
	actualTree, err := tree(nested)
	if err != nil {
		return nil, err
	}
	missing, extra := []string{}, []string{}
	for name := range manifest.Files {
		if _, found := observed[name]; !found {
			missing = append(missing, name)
		}
	}
	knownModes := true
	for name, row := range observed {
		if _, found := manifest.Files[name]; !found {
			extra = append(extra, name)
		}
		if row.Mode != "100644" && row.Mode != "100755" {
			knownModes = false
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	diagnostics["missing"], diagnostics["extra"] = missing, extra
	diagnostics["actualTree"], diagnostics["expectedTree"] = actualTree, manifest.ReplacementTree
	if !knownModes {
		diagnostics["actualTree"] = nil
		diagnostics["treeUnavailableReason"] = "one or more actual files lack trusted executable metadata"
	}
	if metadataError != nil {
		return nil, metadataError
	}
	if windows {
		if len(metadata) != len(observed) {
			return nil, fmt.Errorf("Vision actual worktree paths differ from HEAD/index")
		}
		for name, row := range observed {
			if metadata[name] != (indexEntry{row.Mode, row.GitBlob}) {
				return nil, fmt.Errorf("Vision actual worktree bytes differ from HEAD/index")
			}
		}
	}
	if !reflect.DeepEqual(observed, manifest.Files) || actualTree != manifest.ReplacementTree || len(observed) != manifest.ReplacementFileCount || manifest.UpstreamFileCount != 33 {
		return nil, fmt.Errorf("Vision complete source bytes/modes/tree differ")
	}
	nestedModule, err := os.ReadFile(filepath.Join(nested, "go.mod"))
	if err != nil {
		return nil, err
	}
	for _, source := range [][]byte{module, nestedModule} {
		if err := requireModulePin("go.mod", source, "github.com/refraction-networking/utls", refractionVersion); err != nil {
			return nil, err
		}
	}
	if manifest.Patch != "release/dependency-sources/sing-vmess-vision.patch" {
		return nil, fmt.Errorf("Vision patch identity differs")
	}
	patch, err := os.ReadFile(filepath.Join(root, manifest.Patch))
	if err != nil || sha256Hex(patch) != manifest.PatchSHA256 {
		return nil, fmt.Errorf("Vision patch identity differs")
	}
	notice := manifest.Notice
	license, err := os.ReadFile(filepath.Join(nested, "LICENSE"))
	if err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(filepath.Join(root, notice.ExistingBundle))
	if err != nil {
		return nil, err
	}
	start, end := notice.ExistingOffset, notice.ExistingOffset+int64(len(license))
	if notice.Path != "third_party/sing-vmess/LICENSE" || !notice.UnchangedUpstream || sha256Hex(license) != notice.SHA256 || int64(len(license)) != notice.Bytes || start < 0 || end < start || end > int64(len(bundle)) || !bytes.Equal(bundle[start:end], license) {
		return nil, fmt.Errorf("Vision upstream notice differs from existing bundle")
	}
	return map[string]any{
		"module": visionModule, "version": visionVersion, "replacementTree": actualTree,
		"replacementFileCount": len(observed), "bindingSHA256": sha256Hex(manifestBytes), "modeSource": modeSource,
	}, nil
}
