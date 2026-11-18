package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

const metaModule = "github.com/metacubex/utls"

var fingerprintEnum = regexp.MustCompile("Fingerprint\\s+string\\s+`[^`]*enum:\"([^\"]+)\"")

type tlsModule struct {
	Path    string     `json:"path"`
	Version string     `json:"version"`
	Sum     string     `json:"sum"`
	Replace *tlsModule `json:"replace,omitempty"`
}

type tlsCapabilities struct {
	Source     string `json:"sourceCommit"`
	Version    string `json:"coreVersion"`
	GoVersion  string `json:"goVersion"`
	RequiredGo string `json:"requiredGoVersion"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Enabled    bool   `json:"enabled"`
	Modified   *bool  `json:"sourceModified"`
	Profiles   []struct {
		ID        string `json:"id"`
		Template  string `json:"templateVersion"`
		Selection string `json:"selection"`
		PQ        *bool  `json:"templateOffersX25519MLKEM768"`
	} `json:"profiles"`
	Aliases     []string    `json:"legacyChromeAliases"`
	Default     string      `json:"defaultFingerprint"`
	Random      string      `json:"randomSemantics"`
	Randomized  string      `json:"randomizedSemantics"`
	Negotiation string      `json:"negotiationEvidence"`
	Modules     []tlsModule `json:"modules"`
}

func linkedTLSModules(root string) (map[string]tlsModule, error) {
	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	module, err := modfile.Parse("go.mod", contents, nil)
	if err != nil {
		return nil, err
	}
	sums, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return nil, err
	}
	checksums := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid source module checksum")
		}
		checksums[fields[0]+" "+fields[1]] = fields[2]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	expected := map[string]tlsModule{}
	for _, requirement := range module.Require {
		name := requirement.Mod.Path
		if requirement.Indirect || name != metaModule && name != "github.com/refraction-networking/utls" {
			continue
		}
		sum := checksums[name+" "+requirement.Mod.Version]
		if sum == "" {
			return nil, fmt.Errorf("direct uTLS source checksum missing: %s", name)
		}
		expected[name] = tlsModule{Path: name, Version: requirement.Mod.Version, Sum: sum}
	}
	if len(expected) != 2 {
		return nil, fmt.Errorf("direct uTLS source pins missing")
	}
	data, err := os.ReadFile(filepath.Join(root, "release/dependency-sources/metacubex-utls-replacement.json"))
	if err != nil {
		return nil, err
	}
	var manifest replacementManifest
	if err := uniqueJSON(bytes.NewReader(data), &manifest); err != nil {
		return nil, err
	}
	pin := expected[metaModule]
	const local = "./third_party/metacubex-utls"
	if manifest.Schema != "polaris-repository-module-replacement-v1" || manifest.Module != metaModule || manifest.UpstreamVersion != pin.Version || manifest.UpstreamH1 != pin.Sum || manifest.ReplacementPath != local {
		return nil, fmt.Errorf("source-owned Meta baseline/replacement differs from direct source pins")
	}
	replaced := false
	for _, replacement := range module.Replace {
		if replacement.Old.Path == metaModule && replacement.Old.Version == "" && replacement.New.Path == local && replacement.New.Version == "" {
			replaced = true
		}
	}
	if !replaced {
		return nil, fmt.Errorf("missing exact source-owned Meta replacement")
	}
	directory := filepath.Join(root, local)
	observed := map[string]bool{}
	err = filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if redirectedSource(info) {
			return fmt.Errorf("source-owned Meta file redirected: %s", filename)
		}
		if info.IsDir() {
			return nil
		}
		name, err := filepath.Rel(directory, filename)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		row, exists := manifest.Files[name]
		if !exists || !info.Mode().IsRegular() || info.Size() != row.Bytes {
			return fmt.Errorf("source-owned Meta file inventory differs: %s", name)
		}
		hash, err := fileSHA256(filename)
		if err != nil {
			return err
		}
		if hash != row.SHA256 {
			return fmt.Errorf("source-owned Meta bytes differ: %s", name)
		}
		observed[name] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(observed) != len(manifest.Files) {
		return nil, fmt.Errorf("source-owned Meta file inventory differs")
	}
	patch, err := fileSHA256(filepath.Join(root, manifest.Patch))
	if err != nil {
		return nil, err
	}
	if patch != manifest.PatchSHA256 {
		return nil, fmt.Errorf("source-owned Meta delta digest differs")
	}
	pin.Sum, pin.Replace = "", &tlsModule{Path: local, Version: "(devel)"}
	expected[metaModule] = pin
	return expected, nil
}

func validateTLSCapabilities(root string, document []byte, source, version, goVersion, target string, enabled bool) (tlsCapabilities, error) {
	var actual tlsCapabilities
	var value any
	if err := uniqueJSON(bytes.NewReader(document), &value); err != nil {
		return actual, err
	}
	if err := validateDocument(filepath.Join(root, "release/ci/tls-fingerprint-capabilities.schema.json"), "", value); err != nil {
		return actual, err
	}
	if err := json.Unmarshal(document, &actual); err != nil {
		return actual, err
	}
	goPin, err := os.ReadFile(filepath.Join(root, "release/GO_VERSION"))
	if err != nil {
		return actual, err
	}
	if actual.Source != source || actual.Version != version || actual.GoVersion != goVersion || actual.RequiredGo != "go"+strings.TrimSpace(string(goPin)) || actual.OS+"/"+actual.Arch != target || actual.Enabled != enabled || actual.Modified == nil || *actual.Modified {
		return actual, fmt.Errorf("selected-core capability binding mismatch")
	}
	ids := append([]string{}, actual.Aliases...)
	profiles := map[string]int{}
	for index, profile := range actual.Profiles {
		profiles[profile.ID] = index
		ids = append(ids, profile.ID)
	}
	slices.Sort(ids)
	for index := 1; index < len(ids); index++ {
		if ids[index] == ids[index-1] {
			return actual, fmt.Errorf("duplicate/ambiguous runtime profile IDs")
		}
	}
	if enabled {
		contents, err := os.ReadFile(filepath.Join(root, "option/tls.go"))
		if err != nil {
			return actual, err
		}
		match := fingerprintEnum.FindSubmatch(contents)
		if match == nil {
			return actual, fmt.Errorf("source-owned fingerprint enum missing")
		}
		accepted := strings.Split(string(match[1]), ",")
		slices.Sort(accepted)
		if !slices.Equal(ids, accepted) {
			return actual, fmt.Errorf("actual capabilities differ from source-owned accepted IDs")
		}
	} else if len(ids) != 0 {
		return actual, fmt.Errorf("stub advertises fingerprint support")
	}
	if actual.Default != "chrome" || actual.Random == "" || actual.Randomized == "" || actual.Negotiation == "" {
		return actual, fmt.Errorf("selection/negotiation boundary missing")
	}
	if !enabled {
		return actual, nil
	}
	for name, template := range map[string]string{"chrome": "155", "chrome_155": "155", "chrome_133": "133", "firefox": "148", "firefox_148": "148", "firefox_120": "120", "safari": "26.3", "safari_26_3": "26.3", "safari_16_0": "16.0"} {
		index, ok := profiles[name]
		if !ok || actual.Profiles[index].Template != template {
			return actual, fmt.Errorf("actual template version mismatch: %s", name)
		}
	}
	for name, selection := range map[string]string{"random": "process-browser", "randomized": "process-seeded-generator"} {
		index, ok := profiles[name]
		if !ok || actual.Profiles[index].Selection != selection {
			return actual, fmt.Errorf("random/randomized meanings changed")
		}
	}
	if actual.Profiles[profiles["randomized"]].PQ != nil {
		return actual, fmt.Errorf("random generator cannot promise a concrete PQ offer")
	}
	modules := map[string]tlsModule{}
	for _, module := range actual.Modules {
		if _, ok := modules[module.Path]; ok {
			return actual, fmt.Errorf("duplicate uTLS module")
		}
		modules[module.Path] = module
	}
	pins, err := linkedTLSModules(root)
	if err != nil {
		return actual, err
	}
	if !reflect.DeepEqual(modules, pins) {
		return actual, fmt.Errorf("actual linked uTLS module identities differ from source pins")
	}
	return actual, nil
}

func tlsOutbound(fingerprint *string, enabled bool) map[string]any {
	settings := map[string]any{"enabled": enabled}
	if fingerprint != nil {
		settings["fingerprint"] = *fingerprint
	}
	return map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{map[string]any{
		"type": "trojan", "tag": "probe", "server": "127.0.0.1", "server_port": 443, "password": "local-config-admission-only",
		"tls": map[string]any{"enabled": true, "server_name": "tls.invalid", "utls": settings},
	}}}
}

type tlsConfigurationCase struct {
	expected      map[string]any
	configuration map[string]any
	errorText     string
}

func tlsConfigurationCases(document tlsCapabilities) []tlsConfigurationCase {
	cases := []tlsConfigurationCase{}
	add := func(name *string, enabled, passes bool) {
		var fingerprint any
		if name != nil {
			fingerprint = *name
		}
		errorText := ""
		if !passes && document.Enabled {
			errorText = "unknown uTLS fingerprint"
		}
		cases = append(cases, tlsConfigurationCase{map[string]any{"fingerprint": fingerprint, "enabled": enabled, "expectedPass": passes}, tlsOutbound(name, enabled), errorText})
	}
	if document.Enabled {
		for _, profile := range document.Profiles {
			add(&profile.ID, true, true)
		}
		for _, name := range document.Aliases {
			add(&name, true, true)
		}
	}
	empty := ""
	add(nil, true, document.Enabled)
	add(&empty, true, document.Enabled)
	add(nil, false, true)
	for _, name := range []string{"polaris_unknown_profile", "default", "disabled", "follow", "safari_15_3", "safari_15_5"} {
		add(&name, true, false)
	}
	if document.Enabled {
		for _, ech := range []bool{false, true} {
			name := "chrome"
			config := tlsOutbound(&name, true)
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			outbound["type"], outbound["version"] = "shadowtls", 3
			errorText := ""
			if ech {
				outbound["tls"].(map[string]any)["ech"] = map[string]any{"enabled": true}
				errorText = "cannot be combined with real ECH"
			}
			cases = append(cases, tlsConfigurationCase{map[string]any{"outbound": "shadowtls", "version": 3, "realECH": ech, "expectedPass": !ech}, config, errorText})
		}
	}
	return cases
}

func probeTLSRuntime(parent context.Context, root, core string, environment []string, source, version, goVersion, target string, enabled bool) (receipt map[string]any, err error) {
	core, err = filepath.Abs(core)
	if err != nil {
		return nil, err
	}
	hash, err := fileSHA256(core)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	stdout, stderr, code, queryError := sourceCommandOutput(ctx, root, environment, 1024*1024, core, "tools", "tls-fingerprints")
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	cancel()
	query := map[string]any{"command": []string{core, "tools", "tls-fingerprints"}, "exitCode": code, "stdout": stdout, "stderr": stderr, "timedOut": timedOut}
	if saveError := sourceReceipt(core+"-capability-query.json", query, false, 8*1024*1024); saveError != nil {
		return nil, errors.Join(queryError, saveError)
	}
	if queryError != nil {
		return nil, queryError
	}
	if code == nil || *code != 0 {
		return nil, fmt.Errorf("actual core capability query failed; original query retained")
	}
	document, err := validateTLSCapabilities(root, []byte(stdout), source, version, goVersion, target, enabled)
	if err != nil {
		return nil, err
	}
	temporary, err := os.MkdirTemp("", "tls-admission-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(temporary)) }()
	config := filepath.Join(temporary, "config.json")
	observations := []map[string]any{}
	for _, control := range tlsConfigurationCases(document) {
		if err := sourceReceipt(config, control.configuration, false, 1024*1024); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		output, code, checkError := sourceCombinedOutput(ctx, root, environment, 1024*1024, core, "check", "-c", config)
		cancel()
		if checkError != nil {
			return nil, checkError
		}
		if code == nil || *code < 0 || (*code == 0) != control.expected["expectedPass"].(bool) || control.errorText != "" && !strings.Contains(output, control.errorText) {
			return nil, fmt.Errorf("actual core configuration admission mismatch: %v", control.expected)
		}
		observation := control.expected
		observation["exitCode"], observation["output"] = *code, output
		observations = append(observations, observation)
	}
	finalHash, err := fileSHA256(core)
	if err != nil {
		return nil, err
	}
	if finalHash != hash {
		return nil, fmt.Errorf("selected core changed during capability/configuration probe")
	}
	info, err := os.Stat(core)
	if err != nil {
		return nil, err
	}
	receipt = map[string]any{"schema": "polaris-tls-fingerprint-runtime-probe-v1", "coreSHA256": hash, "coreBytes": info.Size(), "capabilities": json.RawMessage(stdout), "configurationChecks": observations, "networkHandshakeValidated": false}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	fmt.Println("TLS_FINGERPRINT_PROBE " + string(encoded))
	return receipt, nil
}
