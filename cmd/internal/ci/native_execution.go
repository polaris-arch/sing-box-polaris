package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"strings"
)

var nativeSealedFD = regexp.MustCompile("^/proc/self/fd/[0-9]+$")

func nativePositiveInteger(value any) (int64, bool) {
	number, present := value.(json.Number)
	if !present {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil && integer > 0
}

// The enclosing native index schema has checked the shape of each proof.
// Only a proof for the actual producing attempt can support an execution policy.
func validateTrustedNativeExecution(row, producer map[string]any, root string) error {
	smoke, _ := row["finalPackageCronetSmoke"].(map[string]any)
	sealed, hasSealed := smoke["sealedExecution"]
	mac, hasMac := smoke["macosExecution"]
	policy, hasPolicy := row["trustedExecution"]
	if !hasSealed && !hasMac && !hasPolicy {
		return nil
	}
	if hasSealed == hasMac || !hasPolicy {
		return fmt.Errorf("trusted execution requires one proof and its policy")
	}
	proof := sealed
	if hasMac {
		proof = mac
	}
	evidence := proof.(map[string]any)
	for _, field := range []string{"runId", "runAttempt"} {
		if _, exact := nativePositiveInteger(evidence[field]); !exact || evidence[field] != producer[field] {
			return fmt.Errorf("sealed execution workflow run/attempt differs")
		}
	}
	if !nativeFieldsMatch(evidence, map[string]any{
		"sourceCommit": row["sourceCommit"], "sourceTree": row["sourceTree"], "version": row["version"], "target": row["target"],
	}) {
		return fmt.Errorf("execution proof source/target binding differs")
	}
	archive := row["archive"].(map[string]any)
	core := row["core"].(map[string]any)
	if !nativeFieldsMatch(evidence, map[string]any{"archiveSha256": archive["sha256"], "core": core}) || !nativeArchiveMember(archive, core, "sing-box") {
		return fmt.Errorf("execution proof final archive/Core bytes differ")
	}
	if hasMac {
		if err := verifyMacNativeEvidence(row, archive, evidence, smoke, root); err != nil {
			return err
		}
	} else if err := verifyLinuxNativeEvidence(row, archive, evidence, smoke); err != nil {
		return err
	}
	if err := verifyNativeTLS(root, row, evidence["tlsProbe"].(map[string]any)); err != nil {
		return err
	}
	if !reflect.DeepEqual(policy, nativeExecutionPolicy(row, hasMac)) {
		return fmt.Errorf("trusted execution policy differs from native proof")
	}
	return nil
}

func nativeExecutionPolicy(row map[string]any, mac bool) map[string]any {
	loader := "linux-sealed-fd-v1"
	purposes := []any{"check-config-v1", "tls-inventory-v1", "run-main-v1", "run-login-v1", "run-speedtest-v1"}
	if mac {
		loader = "macos-root-private-v1"
		purposes = []any{"check-config-v1", "run-main-v1"}
	}
	return map[string]any{
		"schema": "polaris-trusted-execution-v1", "sourceCommit": row["sourceCommit"], "sourceTree": row["sourceTree"],
		"loader": loader, "purposes": purposes,
	}
}

func nativeArchiveMember(archive, pin map[string]any, name string) bool {
	_, exact := nativePositiveInteger(pin["bytes"])
	return exact && pin["member"] == name && archive["members"].(map[string]any)[archive["root"].(string)+"/"+name] == pin["sha256"]
}

func nativeBuildSettings(row map[string]any, os, arch, cgo string) (map[string]any, map[string]bool, error) {
	settings := row["buildGraph"].(map[string]any)["settings"].(map[string]any)
	tags := nativeTagSet(row["tags"].(string))
	buildTags, _ := settings["-tags"].(string)
	if !nativeFieldsMatch(settings, map[string]any{"GOOS": os, "GOARCH": arch, "CGO_ENABLED": cgo}) ||
		!maps.Equal(tags, nativeTagSet(buildTags)) || !tags["with_naive_outbound"] || !tags["with_utls"] || !tags["with_gvisor"] {
		return nil, nil, fmt.Errorf("execution proof actual Go target/tags differ")
	}
	if revision, found := settings["vcs.revision"]; found && revision != row["sourceCommit"] {
		return nil, nil, fmt.Errorf("execution proof Go source differs")
	}
	if modified, found := settings["vcs.modified"]; found && modified != "false" {
		return nil, nil, fmt.Errorf("execution proof Go source is dirty")
	}
	return settings, tags, nil
}

func nativeTagSet(value string) map[string]bool {
	result := make(map[string]bool)
	for tag := range strings.SplitSeq(value, ",") {
		result[tag] = true
	}
	return result
}

func verifyLinuxNativeEvidence(row, archive, evidence, smoke map[string]any) error {
	variant := row["variant"].(map[string]any)
	if row["target"] != "linux/amd64" || !nativeFieldsMatch(variant, map[string]any{"linkage": "shared-purego", "legacy": false, "libc": ""}) {
		return fmt.Errorf("trusted execution exact-object platform is unsupported")
	}
	_, tags, err := nativeBuildSettings(row, "linux", "amd64", "0")
	if err != nil {
		return err
	}
	if !tags["with_purego"] {
		return fmt.Errorf("sealed execution requires the purego runtime")
	}
	sidecar, _ := row["sidecar"].(map[string]any)
	if !nativeArchiveMember(archive, sidecar, "libcronet.so") || !reflect.DeepEqual(evidence["sidecar"], sidecar) {
		return fmt.Errorf("sealed execution final package sidecar bytes differ")
	}
	for _, key := range []string{"coreSeals", "sidecarSeals"} {
		if _, exact := nativePositiveInteger(evidence[key]); !exact {
			return fmt.Errorf("sealed execution exact seal type differs")
		}
	}
	cronet := evidence["cronet"].(map[string]any)
	expected := map[string]any{"os": "linux", "arch": "amd64", "go": row["goVersion"], "gvisorCompiled": true, "linkage": "shared-purego"}
	if !nativeFieldsMatch(cronet, expected) || !nativeFieldsMatch(cronet, map[string]any{
		"sha256": sidecar["sha256"], "libraryBytes": sidecar["bytes"], "librarySelection": "captured-sealed-fd",
	}) || !nativeSealedFD.MatchString(cronet["library"].(string)) {
		return fmt.Errorf("captured sealed Cronet observation differs")
	}
	return verifyNativeSmoke(row, smoke, expected, cronet["version"], sidecar["sha256"])
}

func validateMacNativeRow(row, archive map[string]any) error {
	target := row["target"].(string)
	arch := strings.TrimPrefix(target, "darwin/")
	variant := row["variant"].(map[string]any)
	if (target != "darwin/amd64" && target != "darwin/arm64") || row["sidecar"] != nil ||
		!nativeFieldsMatch(variant, map[string]any{"linkage": "static-cgo", "libc": "", "goarm": "", "gomips": "", "go386": "", "legacy": false}) {
		return fmt.Errorf("Mac execution requires a modern thin static-CGO Core without sidecar")
	}
	if _, exact := nativePositiveInteger(archive["bytes"]); !exact {
		return fmt.Errorf("Mac exact archive byte type differs")
	}
	settings, tags, err := nativeBuildSettings(row, "darwin", arch, "1")
	if err != nil {
		return err
	}
	if len(tags) != strings.Count(row["tags"].(string), ",")+1 || tags["with_purego"] || tags["with_cronet_purego"] {
		return fmt.Errorf("Mac actual Go tags differ")
	}
	if flags, found := settings["-ldflags"]; found {
		if err := verifyMacSourceFlags(flags.(string), row["sourceCommit"].(string), row["version"].(string)); err != nil {
			return err
		}
	}
	return nil
}

func verifyMacNativeEvidence(row, archive, evidence, smoke map[string]any, root string) error {
	if err := validateMacNativeRow(row, archive); err != nil {
		return err
	}
	arch := strings.TrimPrefix(row["target"].(string), "darwin/")
	core := row["core"].(map[string]any)
	post := evidence["postSign"].(map[string]any)
	native := post["nativeLoader"].(map[string]any)
	if !nativeFieldsMatch(post, map[string]any{"coreSHA256": core["sha256"], "coreBytes": core["bytes"]}) ||
		!reflect.DeepEqual(row["signatureObservation"], map[string]any{"state": "signed", "cdHash": post["cdHash"], "trustValidated": false}) ||
		native["arch"] != arch {
		return fmt.Errorf("Mac post-sign Core/signature/native architecture differs")
	}
	coreSize, _ := nativePositiveInteger(core["bytes"])
	offset, exactOffset := nativePositiveInteger(native["signatureOffset"])
	length, exactSize := nativePositiveInteger(native["signatureBytes"])
	if !exactOffset || !exactSize || offset > coreSize || length > coreSize-offset {
		return fmt.Errorf("Mac post-sign exact signature range differs")
	}
	for _, item := range native["libraries"].([]any) {
		if !nativeMacSystemLibrary(item.(string)) {
			return fmt.Errorf("Mac dependency closure differs")
		}
	}

	var inputs struct{ CronetVersion string }
	if err := readNativeSourceJSON(root, "release/polaris-candidate-inputs.json", &inputs); err != nil {
		return err
	}
	cronet := evidence["cronet"].(map[string]any)
	expected := map[string]any{"os": "darwin", "arch": arch, "go": row["goVersion"], "gvisorCompiled": true, "linkage": "static-cgo"}
	if !nativeFieldsMatch(cronet, expected) || cronet["version"] != inputs.CronetVersion {
		return fmt.Errorf("Mac source-owned Cronet version/native observation differs")
	}
	return verifyNativeSmoke(row, smoke, expected, cronet["version"], nil)
}

func nativeMacSystemLibrary(library string) bool {
	if !strings.HasPrefix(library, "/usr/lib/") && !strings.HasPrefix(library, "/System/Library/") {
		return false
	}
	for segment := range strings.SplitSeq(library[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func verifyNativeSmoke(row, smoke, expected map[string]any, version, sidecarHash any) error {
	maps.Copy(expected, map[string]any{
		"status": "passed", "naiveOutbound": true, "version": version, "librarySha256": sidecarHash,
		"coreSha256": row["core"].(map[string]any)["sha256"],
	})
	if !nativeFieldsMatch(smoke, expected) {
		return fmt.Errorf("execution proof and native smoke differ")
	}
	return nil
}

func verifyNativeTLS(root string, row, receipt map[string]any) error {
	core := row["core"].(map[string]any)
	facts := receipt["capabilities"].(map[string]any)
	tags, _ := facts["buildTags"].(string)
	if !nativeFieldsMatch(receipt, map[string]any{"coreSHA256": core["sha256"], "coreBytes": core["bytes"]}) ||
		!maps.Equal(nativeTagSet(tags), nativeTagSet(row["tags"].(string))) {
		return fmt.Errorf("execution proof TLS Core/tag binding differs")
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	capabilities, err := validateTLSCapabilities(root, raw, row["sourceCommit"].(string), row["version"].(string), row["goVersion"].(string), row["target"].(string), true)
	if err != nil {
		return err
	}
	if err := verifyNativeTLSModules(row, capabilities); err != nil {
		return err
	}

	cases := tlsConfigurationCases(capabilities)
	checks := receipt["configurationChecks"].([]any)
	if len(checks) != len(cases) {
		return fmt.Errorf("incomplete native TLS configuration controls")
	}
	for i, c := range cases {
		check, _ := checks[i].(map[string]any)
		code, integer := check["exitCode"].(json.Number)
		exitCode, err := code.Int64()
		output, text := check["output"].(string)
		for k, value := range c.expected {
			if integer, ok := value.(int); ok {
				c.expected[k] = json.Number(fmt.Sprint(integer))
			}
		}
		if len(check) != len(c.expected)+2 || !nativeFieldsMatch(check, c.expected) || !integer || err != nil || !text ||
			(exitCode == 0) != c.expected["expectedPass"] || !strings.Contains(output, c.errorText) {
			return fmt.Errorf("native TLS configuration observation %d differs", i)
		}
	}
	return nil
}

func verifyNativeTLSModules(row map[string]any, capabilities tlsCapabilities) error {
	graph := row["buildGraph"].(map[string]any)
	expected := make(map[string]tlsModule, len(capabilities.Modules))
	for _, module := range capabilities.Modules {
		expected[module.Path] = module
	}
	producer := make(map[string]tlsModule, len(expected))
	for _, key := range []string{"normalModules", "localReplacements"} {
		for _, item := range graph[key].([]any) {
			module := item.(map[string]any)
			path := module["module"].(string)
			if _, linked := expected[path]; !linked {
				continue
			}
			if _, exists := producer[path]; exists {
				return fmt.Errorf("duplicate actual producer uTLS module")
			}
			entry := nativeTLSModule(module)
			if replacement, exists := module["replacement"]; exists {
				converted := nativeTLSModule(replacement.(map[string]any))
				entry.Replace = &converted
			}
			producer[path] = entry
		}
	}
	if !reflect.DeepEqual(producer, expected) {
		return fmt.Errorf("producer uTLS module graph differs from source-owned direct pins")
	}

	return nil
}

func nativeTLSModule(module map[string]any) tlsModule {
	return tlsModule{Path: module["module"].(string), Version: module["version"].(string), Sum: module["h1"].(string)}
}

func verifyMacSourceFlags(value, source, version string) error {
	flags, err := splitNativeLinkerFlags(value)
	if err != nil {
		return err
	}
	stamps := make(map[string]string)
	for i := 0; i < len(flags); i++ {
		token := flags[i]
		if token == "-X" {
			i++
			if i == len(flags) {
				return fmt.Errorf("Mac truncated Go source flags")
			}
			token = flags[i]
		} else if strings.HasPrefix(token, "-X=") {
			token = strings.TrimPrefix(token, "-X=")
		} else {
			continue
		}
		key, value, assignment := strings.Cut(token, "=")
		if _, duplicate := stamps[key]; !assignment || duplicate {
			return fmt.Errorf("Mac ambiguous Go source flags")
		}
		stamps[key] = value
	}
	const prefix = "github.com/sagernet/sing-box/constant."
	if stamps[prefix+"SourceRevision"] != source || stamps[prefix+"Version"] != version {
		return fmt.Errorf("Mac compiled source/version binding differs")
	}
	if identity, present := stamps[prefix+"DirectoryRetirementSourceIdentity"]; present && identity != source {
		return fmt.Errorf("Mac compiled directory retirement binding differs")
	}
	return nil
}

// Match the producer's POSIX shlex tokenization for Go BuildInfo -ldflags.
func splitNativeLinkerFlags(input string) ([]string, error) {
	var flags []string
	var word strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(input); i++ {
		c := input[i]
		if quote == 0 && strings.ContainsRune(" \t\r\n", rune(c)) {
			if started {
				flags = append(flags, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		started = true
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == '\\' && quote != '\'':
			i++
			if i == len(input) {
				return nil, fmt.Errorf("Mac truncated Go source flag escape")
			}
			if quote == '"' && input[i] != '"' && input[i] != '\\' {
				word.WriteByte(c)
			}
			word.WriteByte(input[i])
		default:
			word.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("Mac unterminated Go source flag")
	}
	if started {
		flags = append(flags, word.String())
	}
	return flags, nil
}
