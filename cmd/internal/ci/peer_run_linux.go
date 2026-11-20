package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	peerResultFile  = "receipt.json"
	peerResultLimit = 16 << 20
)

func peerRun(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("peer-run", flag.ContinueOnError)
	native := flags.String("native", "", "downloaded same-run native row directory")
	admission := flags.String("admission", "", "exact metadata admission")
	output := flags.String("output", "", "sanitized controlled-peer receipt directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" {
		return fmt.Errorf("invalid peer execution arguments")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	nativePath, err := filepath.Abs(*native)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		return fmt.Errorf("controlled peer receipt parent unavailable")
	}
	if err := os.Mkdir(*output, 0o700); err != nil {
		return fmt.Errorf("controlled peer receipt directory already exists or is unavailable")
	}
	filename := filepath.Join(*output, peerResultFile)
	result, err := runPeerSuite(ctx, root, nativePath, *native != "", *admission)
	if err != nil {
		described := map[string]any{}
		if *native != "" {
			describe, cancel := context.WithTimeout(ctx, peerMetadataWindow)
			_ = peerLocalContextWithin(describe, root, nativePath, described, false)
			cancel()
		}
		kind, message := peerPublicError(err)
		result = map[string]any{"context": described, "errorType": kind, "error": message}
		if failureErr := writePeerFailure(filename, "native_execution_preflight", result); failureErr != nil {
			return fmt.Errorf("controlled peer preflight and failure receipt both failed")
		}
		return fmt.Errorf("controlled native peer preflight failed; sanitized receipt retained")
	}
	if err := sourceReceipt(filename, result, true, peerResultLimit); err != nil {
		return fmt.Errorf("controlled peer receipt could not be saved")
	}
	if result["status"] != "PASS" {
		return fmt.Errorf("controlled native peer matrix failed; sanitized receipt retained")
	}
	return nil
}

func runPeerSuite(parent context.Context, root, native string, nativeProvided bool, admission string) (map[string]any, error) {
	if !nativeProvided || admission == "" {
		return nil, &peerDiagnosticError{"ValueError", "peer execution needs native directory and metadata admission"}
	}
	if os.Getenv("GH_TOKEN") != "" || os.Getenv("GITHUB_TOKEN") != "" {
		return nil, &peerDiagnosticError{"ValueError", "native peer execution cannot inherit repository credentials"}
	}
	if os.Geteuid() == 0 {
		return nil, &peerDiagnosticError{"ValueError", "controlled peer execution must be nonroot Linux"}
	}
	rows, err := filepath.Glob(filepath.Join(native, "native-row-*.json"))
	if err != nil || len(rows) != 1 {
		return nil, &peerDiagnosticError{"ValueError", "requires one exact same-run native row"}
	}
	raw, err := peerReadFile(rows[0])
	if err != nil {
		return nil, err
	}
	var row map[string]any
	if err := uniqueJSON(bytes.NewReader(raw), &row); err != nil {
		return nil, err
	}
	proved := map[string]any{}
	metadata, finishMetadata := context.WithTimeout(parent, peerMetadataWindow)
	err = peerLocalContextWithin(metadata, root, native, proved, true)
	var artifact map[string]any
	if err == nil {
		artifact, err = verifyPeerAdmission(admission, proved)
	}
	metadataErr := metadata.Err()
	finishMetadata()
	if metadataErr != nil {
		return nil, metadataErr
	}
	if err != nil {
		return nil, &peerDiagnosticError{"ValueError", "non-public exception details withheld"}
	}
	rawHash := sha256Hex(raw)
	if proved["producerRowSHA256"] != rawHash {
		return nil, &peerDiagnosticError{"ValueError", "native row changed during source admission"}
	}
	contextFacts := make(map[string]any, 5)
	for _, key := range []string{"sourceCommit", "sourceTree", "runId", "runAttempt", "workflowCommit"} {
		contextFacts[key] = proved[key]
	}

	schedule, err := decodePeerCaseSchedule()
	if err != nil {
		return nil, err
	}
	workspace, err := os.MkdirTemp("", "polaris-peer-*")
	if err != nil {
		return nil, err
	}
	product, err := stagePeerProduct(native, workspace, row)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(workspace))
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 480*time.Second)
	defer cancel()
	result := map[string]any{
		"schema": "polaris-native-controlled-peer-v1", "context": contextFacts, "producerRowSHA256": rawHash,
		"archive": row["archive"], "artifact": artifact, "publicationEligible": false,
		"outerArtifactDigestObservation":       "API metadata and same-run download action; independently verified inner archive/member hashes",
		"coverage":                             "Linux native peer process-level IPv4; not App GUI, in-process HOT, IPv6 or other platforms",
		"privateOriginalConfigurationArchived": false,
	}
	bodyErr := executePeerSuite(ctx, root, workspace, product, row, schedule, result)
	deleteErr := os.RemoveAll(workspace)
	_, statErr := os.Lstat(workspace)
	result["privateWorkspaceDeleted"] = deleteErr == nil && errors.Is(statErr, os.ErrNotExist)
	if result["privateWorkspaceDeleted"] != true {
		bodyErr = errors.Join(bodyErr, &peerDiagnosticError{"RuntimeError", "private key/config workspace was not deleted"})
	}
	if bodyErr != nil {
		result["errorType"], result["error"] = peerPublicError(bodyErr)
	}
	if current, err := peerReadFile(rows[0]); err != nil || !bytes.Equal(raw, current) {
		result["originalProducerRowImmutable"], result["error"] = false, "original native row changed during QA"
		bodyErr = errors.Join(bodyErr, fmt.Errorf("original native row unavailable or changed"))
	}
	cases, _ := result["cases"].([]map[string]any)
	for _, entry := range schedule[len(cases):] {
		cases = append(cases, map[string]any{
			"kind": entry.Kind, "mutation": entry.Mutation, "status": "NOT_RUN", "reason": "suite_preflight_or_safety_failure",
		})
	}
	result["cases"] = cases
	result["status"] = "PASS"
	if bodyErr != nil || slices.ContainsFunc(cases, func(entry map[string]any) bool { return entry["status"] != "PASS" }) {
		result["status"] = "FAIL"
	}
	result["elapsedSeconds"] = time.Since(started).Seconds()
	return result, nil
}

func executePeerSuite(ctx context.Context, root, workspace string, product peerProduct, row map[string]any, schedule []peerScheduledCase, result map[string]any) (err error) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return &peerDiagnosticError{"RuntimeError", "existing runner OpenSSL is required; no dependency installation"}
	}
	hash, err := fileSHA256(openssl)
	if err != nil {
		return err
	}
	environment := peerCoreEnvironment(workspace, "")
	opensslVersion, err := peerSuiteCommand(ctx, 10*time.Second, workspace, environment, openssl, "version")
	if err != nil {
		return err
	}
	result["certificateTool"] = map[string]any{"sha256": hash, "version": strings.TrimSpace(opensslVersion)}

	scope, err := openPeerProcessScope()
	if err != nil {
		return err
	}
	defer func() {
		retirement, closeErr := scope.close()
		if retirement.Remaining == nil {
			result["descendantRetirement"] = map[string]any{"status": "UNKNOWN", "errorType": peerErrorName(closeErr)}
		} else {
			result["descendantRetirement"] = retirement
		}
		err = errors.Join(err, closeErr)
	}()

	version, err := peerSuiteCommand(ctx, 15*time.Second, workspace, environment, product.core, "version")
	if err != nil {
		return err
	}
	lines := strings.Split(version, "\n")
	if !slices.Contains(lines, "Revision: "+row["sourceCommit"].(string)) || !slices.Contains(lines, "sing-box version "+row["version"].(string)) {
		return &peerDiagnosticError{"ValueError", "actual executable identity differs"}
	}
	rowDigest, err := peerSortedRowHash(row)
	if err != nil {
		return err
	}
	result["identity"] = map[string]any{
		"source": row["sourceCommit"], "version": row["version"], "coreSHA256": product.corePin["sha256"], "nativeRowSHA256": rowDigest,
		"profile": row["variant"], "sidecar": row["sidecar"], "runtimeVersionOutputSHA256": sha256Hex([]byte(version)),
	}
	var pins struct{ CronetVersion string }
	if err := readNativeSourceJSON(root, "release/polaris-candidate-inputs.json", &pins); err != nil {
		return err
	}
	cronet, err := peerSuiteCommand(ctx, 30*time.Second, workspace, environment,
		product.core, "tools", "cronet", "--expected-version", pins.CronetVersion,
		"--library", product.sidecar, "--sha256", product.sidecarPin["sha256"].(string))
	if err != nil {
		return err
	}
	var observed map[string]any
	if err := uniqueJSON(strings.NewReader(cronet), &observed); err != nil || observed["version"] != pins.CronetVersion ||
		observed["sha256"] != product.sidecarPin["sha256"] || observed["gvisorCompiled"] != true {
		return &peerDiagnosticError{"ValueError", "actual final native Cronet library smoke differs"}
	}
	result["nativeCronetObservation"] = observed
	result["cases"] = executePeerCaseSchedule(ctx, schedule, func(scheduled peerScheduledCase) (map[string]any, error) {
		return runPeerCase(ctx, scope, product, workspace, root, openssl, scheduled)
	})
	if err := product.verify(); err != nil {
		return &peerDiagnosticError{"ValueError", "native bytes changed during peer execution"}
	}
	return nil
}

func peerSuiteCommand(parent context.Context, timeout time.Duration, directory string, environment []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	stdout, _, code, err := sourceCommandOutput(ctx, directory, environment, 1<<20, args...)
	if err == nil && (code == nil || *code != 0) {
		err = &peerDiagnosticError{"CalledProcessError", "non-public exception details withheld"}
	}
	return stdout, err
}

func peerPublicError(err error) (string, string) {
	var diagnostic *peerDiagnosticError
	if errors.As(err, &diagnostic) {
		return diagnostic.kind, diagnostic.message
	}
	return peerErrorName(err), "non-public exception details withheld"
}

// Preserve the existing receipt digest over sorted keys, ASCII escapes, and
// spaces between tokens. Admission independently checks the raw row digest.
func peerSortedRowHash(row map[string]any) (string, error) {
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(row); err != nil {
		return "", err
	}
	value := jsontext.Value(raw.Bytes())
	if err := value.Format(jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true)); err != nil {
		return "", err
	}
	var ascii strings.Builder
	for _, r := range string(value) {
		switch {
		case r < 0x7f:
			ascii.WriteByte(byte(r))
		case r <= 0xffff:
			fmt.Fprintf(&ascii, "\\u%04x", r)
		default:
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", a, b)
		}
	}
	return sha256Hex([]byte(ascii.String())), nil
}
