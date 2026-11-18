package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/badversion"
)

type moduleRecord struct {
	Module      string        `json:"module"`
	Version     string        `json:"version"`
	H1          string        `json:"h1"`
	Replacement *moduleRecord `json:"replacement,omitempty"`
}

type moduleGraph struct {
	Settings           map[string]string `json:"settings"`
	NormalModules      []moduleRecord    `json:"normalModules"`
	AcquisitionModules []moduleRecord    `json:"prebuiltAcquisitionModules"`
	LocalReplacements  []moduleRecord    `json:"localReplacements"`
}

func nativeBuildInfo(filename string) (string, string, moduleGraph, error) {
	graph := moduleGraph{map[string]string{}, []moduleRecord{}, []moduleRecord{}, []moduleRecord{}}
	info, err := buildinfo.ReadFile(filename)
	if err != nil {
		return "", "", graph, err
	}
	for _, setting := range info.Settings {
		graph.Settings[setting.Key] = setting.Value
	}
	for _, dependency := range info.Deps {
		module := moduleRecord{Module: dependency.Path, Version: dependency.Version, H1: dependency.Sum}
		if replacement := dependency.Replace; replacement != nil {
			module.Replacement = &moduleRecord{Module: replacement.Path, Version: replacement.Version, H1: replacement.Sum}
			graph.LocalReplacements = append(graph.LocalReplacements, module)
		} else if strings.HasPrefix(module.Module, "github.com/sagernet/cronet-go/lib/") {
			graph.AcquisitionModules = append(graph.AcquisitionModules, module)
		} else {
			graph.NormalModules = append(graph.NormalModules, module)
		}
	}
	version := info.GoVersion
	info.GoVersion = ""
	raw := fmt.Sprintf("%s: %s\n", filename, version)
	if module := info.String(); len(module) > 0 {
		raw += "\t" + strings.ReplaceAll(module[:len(module)-1], "\n", "\n\t") + "\n"
	}
	return version, raw, graph, nil
}

var (
	nativeArchivePart = regexp.MustCompile(`^[A-Za-z0-9_+.-]+$`)
	windowsDevicePart = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$`)
	nativeCDHash      = regexp.MustCompile(`(?m)^CDHash=([a-f0-9]{40})\r?$`)
)

func readNativeArchiveFile(input *os.File) (string, map[string][]byte, error) {
	const expandedBudget = 256 << 20
	members, roots, folded := map[string][]byte{}, map[string]bool{}, map[string]bool{}
	var expanded int64
	add := func(name string, size int64, extract func(io.Writer) error) error {
		clean, err := portableArtifactPath(name)
		parts := strings.Split(clean, "/")
		if err != nil || len(parts) != 2 || !strings.HasPrefix(parts[0], "sing-box-") {
			return fmt.Errorf("unsafe/non-native archive member: %s", name)
		}
		for _, part := range parts {
			if !nativeArchivePart.MatchString(part) || part == "." || part == ".." ||
				strings.HasSuffix(part, ".") || windowsDevicePart.MatchString(part) {
				return fmt.Errorf("unsafe portable archive member: %s", name)
			}
		}
		key := strings.ToLower(clean)
		_, duplicate := members[parts[1]]
		if folded[key] || duplicate {
			return fmt.Errorf("duplicate archive member: %s", name)
		}
		if size < 0 || size > expandedBudget-expanded {
			return fmt.Errorf("native archive exceeds expanded byte budget")
		}
		var data bytes.Buffer
		if err := extract(&data); err != nil {
			return err
		}
		if int64(data.Len()) != size {
			return fmt.Errorf("native archive member length differs: %s", name)
		}
		expanded += size
		members[parts[1]], roots[parts[0]], folded[key] = data.Bytes(), true, true
		return nil
	}
	if strings.HasSuffix(input.Name(), ".zip") {
		archive, err := openArtifactZIP(input)
		if err != nil {
			return "", nil, err
		}
		for _, member := range archive.members {
			if member.FileInfo().IsDir() {
				continue
			}
			if err := add(member.Name, int64(member.UncompressedSize64), func(destination io.Writer) error {
				_, err := archive.copyMember(member, destination)
				return err
			}); err != nil {
				return "", nil, err
			}
		}
	} else {
		compressed, err := gzip.NewReader(input)
		if err != nil {
			return "", nil, err
		}
		defer compressed.Close()
		bounded := &io.LimitedReader{R: compressed, N: expandedBudget + 1}
		archive := tar.NewReader(bounded)
		for {
			member, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", nil, err
			}
			if member.Typeflag == tar.TypeDir {
				continue
			}
			if member.Typeflag != tar.TypeReg && member.Typeflag != tar.TypeRegA {
				return "", nil, fmt.Errorf("archive non-regular member: %s", member.Name)
			}
			if err := add(member.Name, member.Size, func(destination io.Writer) error {
				_, err := io.Copy(destination, archive)
				return err
			}); err != nil {
				return "", nil, err
			}
		}
		// The tar reader stops at its end marker. Finish gzip validation and
		// account for any remaining compressed stream before accepting it.
		if _, err := io.Copy(io.Discard, bounded); err != nil {
			return "", nil, err
		}
		if bounded.N == 0 {
			return "", nil, fmt.Errorf("native tar exceeds expanded byte budget")
		}
	}
	if len(roots) != 1 {
		return "", nil, fmt.Errorf("native archive must contain one root")
	}
	for root := range roots {
		return root, members, nil
	}
	panic("unreachable native archive root")
}

func collectNativeIndex(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected one directory for collect-native-index")
	}
	source, err := nativeCollectorSource(".")
	if err != nil {
		return err
	}
	env, err := nativeEnvironment("VERSION", "NATIVE_OS", "NATIVE_ARCH")
	if err != nil {
		return err
	}
	version := env["VERSION"]
	if !badversion.IsCanonicalPolaris(version) {
		return fmt.Errorf("invalid native archive version")
	}
	target := env["NATIVE_OS"] + "/" + env["NATIVE_ARCH"]
	expected, err := expectedNativeArchives("release/ci", version)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(args[0])
	if err != nil {
		return err
	}
	var filename string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "sing-box-") || !(strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip")) {
			continue
		}
		if filename != "" {
			return fmt.Errorf("expected exactly one native archive")
		}
		filename = name
	}
	id := strings.TrimSuffix(strings.TrimSuffix(filename, ".tar.gz"), ".zip")
	lane, found := expected[id]
	suffix := ".tar.gz"
	if env["NATIVE_OS"] == "windows" {
		suffix = ".zip"
	}
	if !found || lane.target != target || filename != id+suffix {
		return fmt.Errorf("native archive differs from exact upstream matrix: %s", filename)
	}
	input, err := openNativeSource(args[0], filename)
	if err != nil {
		return err
	}
	defer input.Close()
	row, err := collectNativeArchive(input, id, version, lane)
	if err != nil {
		return err
	}
	for key, value := range source {
		row[key] = value
	}
	return sourceReceipt(filepath.Join(args[0], "native-row-"+id+".json"), row, true, 32<<20)
}

func collectNativeArchive(input *os.File, id, version string, lane nativeTarget) (map[string]any, error) {
	before, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > publisherScratchLimit {
		return nil, fmt.Errorf("missing or unbounded native archive")
	}
	root, members, err := readNativeArchiveFile(input)
	if err != nil {
		return nil, err
	}
	if root != id {
		return nil, fmt.Errorf("native archive root differs from filename")
	}
	coreName, sidecarName := "sing-box", "libcronet.so"
	if strings.HasPrefix(lane.target, "windows/") {
		coreName, sidecarName = "sing-box.exe", "libcronet.dll"
	}
	expectedCount := 3
	if lane.linkage == "shared-purego" {
		expectedCount++
	}
	if len(members) != expectedCount || len(members[coreName]) == 0 || len(members["LICENSE"]) == 0 ||
		len(members["TLS-DEPENDENCY-NOTICES.txt"]) == 0 ||
		(expectedCount == 4 && len(members[sidecarName]) == 0) {
		return nil, fmt.Errorf("native archive member inventory differs")
	}
	scratch, err := os.MkdirTemp("", "polaris-native-inspect-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	coreFile := filepath.Join(scratch, coreName)
	if err := os.WriteFile(coreFile, members[coreName], 0o600); err != nil {
		return nil, err
	}
	goVersion, raw, graph, err := nativeBuildInfo(coreFile)
	if err != nil {
		return nil, err
	}
	settings := graph.Settings
	linkage := "other"
	if expectedCount == 4 {
		linkage = "shared-purego"
	} else if settings["CGO_ENABLED"] == "1" && nativeTagSet(settings["-tags"])["with_naive_outbound"] {
		linkage = "static-cgo"
	}
	if settings["GOOS"]+"/"+settings["GOARCH"] != lane.target || linkage != lane.linkage {
		return nil, fmt.Errorf("native binary GOOS/GOARCH or linkage differs from matrix")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	buildID, diagnostic, status, err := sourceCommandOutput(ctx, "", nil, 1<<20, "go", "tool", "buildid", coreFile)
	if err != nil {
		return nil, err
	}
	if status == nil || *status != 0 {
		return nil, fmt.Errorf("native build ID command failed: %s", strings.TrimSpace(diagnostic))
	}
	var signature any
	if runtime.GOOS == "darwin" && settings["GOOS"] == "darwin" {
		_, diagnostic, status, err := sourceCommandOutput(ctx, "", nil, 1<<20, "codesign", "-d", "--verbose=4", coreFile)
		if err != nil {
			return nil, err
		}
		state, hash := "unsigned", any(nil)
		if status != nil && *status == 0 {
			state = "signed"
		}
		if match := nativeCDHash.FindStringSubmatch(diagnostic); match != nil {
			hash = match[1]
		}
		signature = map[string]any{"state": state, "cdHash": hash, "trustValidated": false}
	}
	digest := sha256.New()
	size, err := io.Copy(digest, io.NewSectionReader(input, 0, before.Size()+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Stat(input.Name())
	if err != nil {
		return nil, err
	}
	if size != before.Size() || !os.SameFile(before, after) || after.Size() != size || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("native archive changed while inspecting")
	}
	hashes := make(map[string]string, len(members))
	for name, data := range members {
		hashes[root+"/"+name] = sha256Hex(data)
	}
	fact := func(name string) map[string]any {
		return map[string]any{"member": name, "bytes": len(members[name]), "sha256": hashes[root+"/"+name]}
	}
	var sidecar any
	if expectedCount == 4 {
		sidecar = fact(sidecarName)
	}
	return map[string]any{
		"schema": "polaris-upstream-native-receipt-v1", "id": id, "target": lane.target,
		"variant": map[string]any{"linkage": linkage, "libc": "", "goarm": "", "gomips": "", "go386": "", "legacy": false},
		"version": version, "tag": "v" + version, "goVersion": goVersion, "tags": settings["-tags"],
		"buildID": strings.TrimSpace(buildID), "rawBuildInfo": raw, "buildGraph": graph,
		"archive": map[string]any{"name": filepath.Base(input.Name()), "bytes": size, "sha256": fmt.Sprintf("%x", digest.Sum(nil)), "root": root, "members": hashes},
		"core":    fact(coreName), "sidecar": sidecar, "signatureObservation": signature, "finalPackageCronetSmoke": nil,
	}, nil
}
