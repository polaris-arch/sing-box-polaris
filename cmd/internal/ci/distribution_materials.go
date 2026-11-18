package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"

	"golang.org/x/mod/module"
)

const distributionNoticeSelection = "release/ci/current44-notice-mappings.json"
const moduleProxy = "https://proxy.golang.org"

// The assembler passes its existing index document before adding the derived
// materials. Keep its input under the same schema as the final publisher.
func distributionMaterialsCommand(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("distribution-materials", flag.ContinueOnError)
	root := flags.String("source-root", "", "verified producer source directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *root == "" {
		return fmt.Errorf("distribution-materials requires a source root")
	}
	var index, schema map[string]any
	if err := decodeNativeJSON(input, &index); err != nil {
		return err
	}
	if err := readNativeSourceJSON(".", nativeIndexSchema, &schema); err != nil {
		return err
	}
	if _, final := index["distributionMaterials"]; !final {
		required, ok := schema["required"].([]any)
		if !ok || !slices.Contains(required, any("distributionMaterials")) {
			return fmt.Errorf("native index schema no longer requires distribution materials")
		}
		schema["required"] = slices.DeleteFunc(required, func(key any) bool { return key == "distributionMaterials" })
	}
	if err := validateSchema(schema, "", index); err != nil {
		return err
	}
	materials, err := distributionMaterials(index, *root, downloadOwnedReplacement)
	if err != nil {
		return err
	}
	return writeJSON(output, materials)
}

func openNativeSource(root, name string) (*os.File, error) {
	filename, err := regularSource(root, name)
	if err != nil {
		return nil, err
	}
	return os.Open(filename)
}

func readNativeSource(root, name string) ([]byte, error) {
	input, err := openNativeSource(root, name)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	return readNativeBytes(input, 32<<20)
}

func readNativeBytes(input io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("native source exceeds byte bound")
	}
	return data, nil
}

func validateDistributionAssessment(catalog map[string]any) (bool, error) {
	status, items := catalog["status"], catalog["openItems"]
	open, ok := items.([]any)
	if catalog["schema"] != json.Number("1") || (status != "current-scope-review-required" && status != "reviewed-current-scope") || !ok {
		return false, fmt.Errorf("invalid current distribution assessment")
	}
	for _, item := range open {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(string)
		detail, _ := row["detail"].(string)
		if id == "" || detail == "" {
			return false, fmt.Errorf("invalid current distribution open item")
		}
	}
	return status == "reviewed-current-scope" && len(open) == 0, nil
}

type distributionNotices struct {
	Bundle     map[string]any   `json:"noticeBundle"`
	Records    []noticeRecord   `json:"noticeRecords"`
	Components []map[string]any `json:"components"`
	data       []byte
}

type noticeRecord struct {
	SourcePath string
	ByteOffset *int64
	Bytes      *int64
	SHA256     string
}

func readDistributionNotices(root string) (distributionNotices, error) {
	var notice distributionNotices
	if err := readNativeSourceJSON(root, distributionNoticeSelection, &notice); err != nil {
		return notice, err
	}
	if notice.Records == nil || notice.Components == nil {
		return notice, fmt.Errorf("missing historical notice records or components")
	}
	name, _ := notice.Bundle["path"].(string)
	data, err := readNativeSource(root, name)
	if err != nil {
		return notice, err
	}
	if notice.Bundle["sha256"] != sha256Hex(data) {
		return notice, fmt.Errorf("current notice bundle hash mismatch")
	}
	notice.data = data
	for _, record := range notice.Records {
		if record.Bytes == nil || record.ByteOffset == nil || *record.ByteOffset < 0 || *record.Bytes < 0 ||
			*record.ByteOffset > int64(len(data)) || *record.Bytes > int64(len(data))-*record.ByteOffset ||
			sha256Hex(notice.slice(record)) != record.SHA256 {
			return notice, fmt.Errorf("current notice slice hash mismatch")
		}
	}
	return notice, nil
}

func (notice distributionNotices) slice(record noticeRecord) []byte {
	return notice.data[*record.ByteOffset : *record.ByteOffset+*record.Bytes]
}

func distributionInputHashes(root, iosPatch string, trusted bool) (map[string]any, error) {
	overlay, err := validateCronetOverlay(root)
	if err != nil {
		return nil, err
	}
	paths := []string{
		"go.mod", "go.sum", ".gitmodules", ".github/go-toolchains.json",
		"release/dependency-sources/sing-vmess-replacement.json",
		"release/dependency-sources/sing-vmess-vision.patch",
		"release/ci/distribution-materials.json",
		"release/ci/current-module-sources.json", "release/polaris-public-source-inputs.json",
		distributionNoticeSelection, "release/licenses/CURRENT44-NOTICE-CANDIDATE.txt",
		"release/dependency-sources/ACQUIRE-AND-BUILD-CURRENT.md",
		"release/ci/current44-static-cronet-origin-bindings.json",
		"release/dependency-sources/windivert/current44-inclusion-proof.json",
		"release/dependency-sources/windivert/fixed-source-availability-proof.json",
		"release/dependency-sources/windivert/upstream-release-driver-proof.json",
		"release/polaris-cronet-materials.json", "release/polaris-cronet-graph-kernel-materials.json",
		"scripts/ci/native_release_index.py",
		"release/GO_VERSION", "common/badversion/version.go", "common/badversion/version_json.go",
		".github/workflows/build.yml", iosPatch,
	}
	// Select the producer's source inputs from the immutable source. Older
	// indexes pin the Python overlay verifier, which preceded the Go verifier.
	const (
		historicalOverlay   = "scripts/ci/cronet_windows_overlay.py"
		historicalPublisher = "scripts/ci/github_release.py"
	)
	if _, err := os.Lstat(filepath.Join(root, historicalOverlay)); err == nil {
		paths = append(paths, historicalOverlay)
	} else if errors.Is(err, os.ErrNotExist) {
		paths = append(paths, "scripts/ci/release_identity.py")
	} else {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(root, historicalPublisher)); err == nil {
		paths = append(paths, historicalPublisher)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	goFiles, err := filepath.Glob(filepath.Join(root, "cmd", "internal", "ci", "*.go"))
	if err != nil {
		return nil, err
	}
	for _, name := range goFiles {
		if !strings.HasSuffix(name, "_test.go") {
			paths = append(paths, "cmd/internal/ci/"+filepath.Base(name))
		}
	}
	if trusted {
		paths = append(paths, "scripts/ci/tls_fingerprint_probe.py", nativeIndexSchema)
	}
	inputs := make(map[string]any)
	for path, hash := range overlay {
		inputs[path] = hash
	}
	for _, path := range paths {
		if _, exists := inputs[path]; exists {
			continue
		}
		data, err := readNativeSource(root, path)
		if err != nil {
			return nil, err
		}
		inputs[path] = sha256Hex(data)
	}
	return inputs, nil
}

type materialIdentity struct{ module, version, h1 string }

func materialID(record map[string]any) materialIdentity {
	name, _ := record["module"].(string)
	version, _ := record["version"].(string)
	hash, _ := record["h1"].(string)
	return materialIdentity{name, version, hash}
}

func materialRecords(rows []map[string]any) map[materialIdentity]map[string]any {
	result := make(map[materialIdentity]map[string]any, len(rows))
	for _, row := range rows {
		result[materialID(row)] = row
	}
	return result
}

func distributionMaterials(index map[string]any, root string, download ownedModuleDownload) (map[string]any, error) {
	var toolchain, catalog map[string]any
	var baseline struct{ Modules []map[string]any }
	var current struct{ Delta []map[string]any }
	for _, file := range []struct {
		name string
		json any
	}{
		{".github/go-toolchains.json", &toolchain},
		{"release/ci/distribution-materials.json", &catalog},
		{"release/polaris-public-source-inputs.json", &baseline},
		{"release/ci/current-module-sources.json", &current},
	} {
		if err := readNativeSourceJSON(root, file.name, file.json); err != nil {
			return nil, err
		}
	}
	if baseline.Modules == nil || current.Delta == nil {
		return nil, fmt.Errorf("missing source module acquisition catalogs")
	}
	eligible, err := validateDistributionAssessment(catalog)
	if err != nil {
		return nil, err
	}
	notice, err := readDistributionNotices(root)
	if err != nil {
		return nil, err
	}
	ios, _ := toolchain["iosCPU"].(map[string]any)
	iosPatch, _ := ios["patch"].(string)
	version, _ := toolchain["version"].(string)
	rows := slices.Clone(index["platforms"].([]any))
	trusted := slices.ContainsFunc(rows, func(row any) bool {
		_, present := row.(map[string]any)["trustedExecution"]
		return present
	})
	inputs, err := distributionInputHashes(root, iosPatch, trusted)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(rows, func(a, b any) int {
		return strings.Compare(a.(map[string]any)["id"].(string), b.(map[string]any)["id"].(string))
	})
	materials := distributionModuleRecords{
		root: root, goVersion: version, notice: notice, download: download,
		baseline: materialRecords(baseline.Modules), current: materialRecords(current.Delta),
		modules: make(map[string]any), missing: make(map[string]any), acquired: make(map[ownedMaterialIdentity]map[string]any),
	}
	materials.noticeComponents = make(map[materialIdentity]map[string]any)
	for _, item := range notice.Components {
		if _, present := item["version"]; present {
			materials.noticeComponents[materialID(item)] = item
		}
	}
	native := make([]any, 0, len(rows))
	for _, item := range rows {
		row := item.(map[string]any)
		if row["sourceCommit"] != index["sourceCommit"] || row["sourceTree"] != index["sourceTree"] {
			return nil, fmt.Errorf("mixed source material binding")
		}
		if row["goVersion"] != "go"+version {
			if err := materials.addMissing(map[string]any{"toolchain": row["goVersion"], "reason": "actual toolchain differs from source-owned current material version"}); err != nil {
				return nil, err
			}
		}
		record, err := materials.nativeArchive(row)
		if err != nil {
			return nil, err
		}
		native = append(native, record)
	}
	missing := make([]any, 0, len(materials.missing))
	for _, key := range slices.Sorted(maps.Keys(materials.missing)) {
		missing = append(missing, materials.missing[key])
	}
	legal := make(map[string]any)
	for _, item := range index["legalFiles"].([]any) {
		file := item.(map[string]any)
		legal[file["path"].(string)] = file["sha256"]
	}
	return map[string]any{
		"schema": "polaris-distribution-materials-v1", "sourceCommit": index["sourceCommit"],
		"sourceTree": index["sourceTree"], "sourceArchive": index["sourceArchive"],
		"sourceURL": "https://github.com/" + repository + "/tree/" + index["sourceCommit"].(string),
		"toolchain": toolchain, "inputs": inputs, "legalFiles": legal, "modules": materials.modules, "nativeArchives": native,
		"noticeSelection": map[string]any{"path": distributionNoticeSelection, "sha256": inputs[distributionNoticeSelection], "bundle": notice.Bundle},
		"assessment":      catalog, "unmappedMaterialIdentities": missing, "publicationEligible": eligible && len(missing) == 0,
		"limitations": []any{
			"This binding proves identity and association, not license/source closure.",
			"The kernel source archive does not expand client gitlinks.",
			"Module h1 is a Go directory checksum, not a downloaded ZIP SHA256.",
			"Historical source/notice evidence remains historical.",
		},
	}, nil
}

type ownedMaterialIdentity struct{ original, replacement materialIdentity }

type distributionModuleRecords struct {
	root, goVersion                     string
	notice                              distributionNotices
	download                            ownedModuleDownload
	baseline, current, noticeComponents map[materialIdentity]map[string]any
	acquired                            map[ownedMaterialIdentity]map[string]any
	modules, missing                    map[string]any
}

func (materials distributionModuleRecords) addMissing(item map[string]any) error {
	// Unknown material fields consist of string values. Compact JSON preserves
	// the ordering of the sorted Python output for these fixed field sets.
	key, err := nativeCanonicalJSON(item)
	if err != nil {
		return err
	}
	materials.missing[string(key)] = item
	return nil
}

func (materials distributionModuleRecords) nativeArchive(row map[string]any) (map[string]any, error) {
	moduleIDs := make(map[string]bool)
	graph := row["buildGraph"].(map[string]any)
	for _, group := range []string{"normalModules", "prebuiltAcquisitionModules", "localReplacements"} {
		for _, item := range graph[group].([]any) {
			id, err := materials.module(item.(map[string]any))
			if err != nil {
				return nil, err
			}
			moduleIDs[id] = true
		}
	}
	ids := make([]any, 0, len(moduleIDs))
	for _, id := range slices.Sorted(maps.Keys(moduleIDs)) {
		ids = append(ids, id)
	}
	archive := row["archive"].(map[string]any)
	record := map[string]any{
		"archive": archive["name"], "archiveSHA256": archive["sha256"], "coreSHA256": row["core"].(map[string]any)["sha256"],
		"goVersion": row["goVersion"], "modules": ids, "localSourceIdentity": row["sourceIdentity"], "cronetSidecar": row["sidecar"],
		"windivertSourceEvidence": nil, "repositoryNoticePaths": []any{"licenses/repository-components/JA3-LICENSE"},
	}
	if row["target"] == "windows/amd64" && !nativeTagSet(row["tags"].(string))["with_external_windivert"] {
		record["windivertSourceEvidence"] = "release/dependency-sources/windivert/"
		record["repositoryNoticePaths"] = append(record["repositoryNoticePaths"].([]any), "licenses/repository-components/WINDIVERT-LICENSE.txt")
	}
	if policy, trusted := row["trustedExecution"]; trusted {
		smoke := row["finalPackageCronetSmoke"].(map[string]any)
		sealed, hasSealed := smoke["sealedExecution"]
		mac, hasMac := smoke["macosExecution"]
		if hasSealed == hasMac {
			return nil, fmt.Errorf("distribution native execution proof is ambiguous")
		}
		proofKey, proof := "sealedExecution", sealed
		if hasMac {
			proofKey, proof = "macosExecution", mac
		}
		for key, value := range map[string]any{"trustedExecution": policy, proofKey: proof} {
			data, err := nativeCanonicalJSON(value)
			if err != nil {
				return nil, err
			}
			record[key+"SHA256"] = sha256Hex(data)
		}
	}
	return record, nil
}

func (materials distributionModuleRecords) module(item map[string]any) (string, error) {
	replacement, replaced := item["replacement"].(map[string]any)
	actual := item
	if replaced {
		actual = replacement
	}
	record := maps.Clone(actual)
	id := materialID(actual)
	if strings.HasPrefix(id.module, "./") {
		record["delivery"] = "tracked-source-archive"
	} else {
		if id.version == "" || id.h1 == "" {
			return "", fmt.Errorf("unbound external module source: %s", id.module)
		}
		url, err := goModuleZipURL(id)
		if err != nil {
			return "", err
		}
		record["sourceURL"], record["delivery"], record["availabilityVerified"] = url, "fixed-module-source-location", false
		if replaced && item["module"] == originalOpenConnect && id.module == ownedOpenConnect {
			// The original identity is stable across all rows; the exact fork
			// identity must still be checked independently if any row differs.
			original := materialID(item)
			key := ownedMaterialIdentity{original: original, replacement: id}
			if materials.acquired[key] == nil {
				acquired, err := ownedReplacementMaterials(item, id, materials.root, materials.notice, materials.goVersion, materials.download)
				if err != nil {
					return "", err
				}
				materials.acquired[key] = acquired
			}
			maps.Copy(record, materials.acquired[key])
		} else if err := materials.externalModule(record, id); err != nil {
			return "", err
		}
	}
	if replaced {
		original := maps.Clone(item)
		delete(original, "replacement")
		record["replaces"] = original
	}
	data, err := nativeCanonicalJSON(record)
	if err != nil {
		return "", err
	}
	key := sha256Hex(data)
	materials.modules[key] = record
	return key, nil
}

func (materials distributionModuleRecords) externalModule(record map[string]any, id materialIdentity) error {
	markMissing := func(reason string) error {
		return materials.addMissing(map[string]any{"module": id.module, "version": id.version, "h1": id.h1, "reason": reason})
	}
	historical, current := materials.baseline[id], materials.current[id]
	if historical == nil && current == nil {
		if err := markMissing("no exact source acquisition input"); err != nil {
			return err
		}
	}
	if notice := materials.noticeComponents[id]; notice != nil {
		record["noticeRecordIndexes"] = materialField(notice, "noticeRecordIndexes", []any{})
	} else if err := markMissing("no exact notice component mapping"); err != nil {
		return err
	}
	if historical != nil {
		source, err := materialZipRecord(historical)
		if err != nil {
			return err
		}
		record["sourceArchive"] = source
		record["sourceEvidence"] = "release/polaris-public-source-inputs.json (exact module/version/h1 match; historical acquisition)"
	}
	if current != nil {
		record["sourceEvidence"] = "release/ci/current-module-sources.json"
		verified := current["verifiedH1"] == id.h1
		record["availabilityVerified"] = verified
		metadata, _ := current["publicInfo"].(map[string]any)
		record["publicMetadataAvailable"] = materialField(metadata, "fullGetVerified", false)
		if verified {
			source, err := materialZipRecord(current)
			if err != nil {
				return err
			}
			record["sourceArchive"] = source
			record["noticeFiles"] = materialField(current, "noticeFiles", []any{})
		}
	}
	return nil
}

func materialField(row map[string]any, field string, fallback any) any {
	if value, present := row[field]; present {
		return value
	}
	return fallback
}

func materialZipRecord(row map[string]any) (map[string]any, error) {
	result := make(map[string]any, 3)
	for _, field := range []string{"zipUrl", "zipBytes", "zipSha256"} {
		value, present := row[field]
		if !present {
			return nil, fmt.Errorf("incomplete module ZIP receipt for %v: %s", row["module"], field)
		}
		result[field] = value
	}
	return result, nil
}

func goModuleZipURL(id materialIdentity) (string, error) {
	path, err := module.EscapePath(id.module)
	if err != nil {
		return "", err
	}
	version, err := module.EscapeVersion(id.version)
	if err != nil {
		return "", err
	}
	return moduleProxy + "/" + path + "/@v/" + version + ".zip", nil
}

// The existing release digests use sorted, compact JSON with Python's default
// ASCII escapes. Keep those identities when the publisher recomputes them in Go.
func nativeCanonicalJSON(value any) ([]byte, error) {
	var text bytes.Buffer
	encoder := json.NewEncoder(&text)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	var ascii bytes.Buffer
	for _, r := range strings.TrimSuffix(text.String(), "\n") {
		switch {
		case r < 0x7f:
			ascii.WriteByte(byte(r))
		case r <= 0xffff:
			fmt.Fprintf(&ascii, "\\u%04x", r)
		default:
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", high, low)
		}
	}
	return ascii.Bytes(), nil
}
