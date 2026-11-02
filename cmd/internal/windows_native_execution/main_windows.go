//go:build windows && amd64

// This bounded verification producer never installs a service, acquires SYSTEM,
// or issues App execution authority. Its only children are the held final Core.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

var producerSource, producerTree string // exact clean workflow compile stamps
const (
	requestSchema = "polaris-windows-native-execution-request-v1"
	proofSchema   = "polaris-windows-native-execution-proof-v1"
	objectLimit   = 256 << 20
)

type pin struct {
	Member string `json:"member"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type archivePin struct {
	Root    string            `json:"root"`
	Bytes   int64             `json:"bytes"`
	SHA256  string            `json:"sha256"`
	Members map[string]string `json:"members"`
}
type request struct {
	Schema        string     `json:"schema"`
	SourceCommit  string     `json:"sourceCommit"`
	SourceTree    string     `json:"sourceTree"`
	Version       string     `json:"version"`
	Target        string     `json:"target"`
	GoVersion     string     `json:"goVersion"`
	CronetVersion string     `json:"cronetVersion"`
	RunID         uint64     `json:"runId"`
	RunAttempt    uint64     `json:"runAttempt"`
	Archive       archivePin `json:"archive"`
	Core          pin        `json:"core"`
	Sidecar       pin        `json:"sidecar"`
}
type actorFact struct {
	SID                 string `json:"sid"`
	TokenType           string `json:"tokenType"`
	ThreadImpersonation bool   `json:"threadImpersonation"`
	ProcessID           uint32 `json:"processId"`
	CreationTime        string `json:"creationTime"`
}
type objectFact struct {
	Path           string `json:"path"`
	NativePath     string `json:"nativePath"`
	VolumeSerial   string `json:"volumeSerial"`
	FileID         string `json:"fileId"`
	OwnerSID       string `json:"ownerSid"`
	ProtectedDACL  bool   `json:"protectedDacl"`
	SystemOnlyDACL bool   `json:"systemOnlyDacl"`
	ReparsePoint   bool   `json:"reparsePoint"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	LinkCount      uint32 `json:"linkCount"`
	ShareReadOnly  bool   `json:"shareReadOnly"`
}
type cohortFact struct {
	ID             string `json:"id"`
	Path           string `json:"path"`
	NativePath     string `json:"nativePath"`
	VolumeSerial   string `json:"volumeSerial"`
	FileID         string `json:"fileId"`
	FileSystem     string `json:"fileSystem"`
	OwnerSID       string `json:"ownerSid"`
	ProtectedDACL  bool   `json:"protectedDacl"`
	SystemOnlyDACL bool   `json:"systemOnlyDacl"`
	ReparsePoint   bool   `json:"reparsePoint"`
	CreatedNew     bool   `json:"createdNew"`
}
type processFact struct {
	Purpose               string    `json:"purpose"`
	Argv                  []string  `json:"argv"`
	StdinSHA256           string    `json:"stdinSHA256"`
	StdinBytes            int       `json:"stdinBytes"`
	ProcessID             uint32    `json:"processId"`
	CreationTime          string    `json:"creationTime"`
	Actor                 actorFact `json:"actor"`
	ImageNativePath       string    `json:"imageNativePath"`
	ImageLoadPolicy       uint32    `json:"imageLoadPolicy"`
	InheritedHandleCount  int       `json:"inheritedHandleCount"`
	JobAssignedAtCreation bool      `json:"jobAssignedAtCreation"`
	ExitCode              uint32    `json:"exitCode"`
	ActualWait            bool      `json:"actualWait"`
	StdoutEOF             bool      `json:"stdoutEOF"`
	StderrEOF             bool      `json:"stderrEOF"`
	Stdout                string    `json:"stdout"`
	Stderr                string    `json:"stderr"`
	OutputTruncated       bool      `json:"outputTruncated"`
	TimedOut              bool      `json:"timedOut"`
	ForcedKill            bool      `json:"forcedKill"`
	JobActiveAfterWait    uint32    `json:"jobActiveAfterWait"`
	HandlesClosed         bool      `json:"handlesClosed"`
}
type mappingFact struct {
	NativePath string `json:"nativePath"`
	ModuleBase string `json:"moduleBase"`
	MemoryType uint32 `json:"memoryType"`
}
type runFact struct {
	ListenAddress string      `json:"listenAddress"`
	Port          int         `json:"port"`
	OwnerPID      uint32      `json:"ownerPid"`
	Ready         bool        `json:"ready"`
	DLLModule     mappingFact `json:"dllModule"`
}
type cleanupFact struct {
	AllChildrenWaited     bool   `json:"allChildrenWaited"`
	ReadersJoined         bool   `json:"readersJoined"`
	JobActiveProcesses    uint32 `json:"jobActiveProcesses"`
	HeldObjectsClosed     bool   `json:"heldObjectsClosed"`
	CohortRemoved         bool   `json:"cohortRemoved"`
	ConfigurationRetained bool   `json:"configurationRetained"`
	ForcedTermination     bool   `json:"forcedTermination"`
}
type producerFact struct {
	SourceCommit string `json:"sourceCommit"`
	SourceTree   string `json:"sourceTree"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	GoVersion    string `json:"goVersion"`
}
type nativeFacts struct {
	Actor      actorFact     `json:"actor"`
	Producer   producerFact  `json:"producer"`
	Cohort     cohortFact    `json:"cohort"`
	Core       objectFact    `json:"coreObject"`
	Sidecar    objectFact    `json:"sidecarObject"`
	Executions []processFact `json:"executions"`
	RunMain    runFact       `json:"runMain"`
	Cleanup    cleanupFact   `json:"cleanup"`
}
type proof struct {
	custodyClosed bool
	Schema        string          `json:"schema"`
	SourceCommit  string          `json:"sourceCommit"`
	SourceTree    string          `json:"sourceTree"`
	Version       string          `json:"version"`
	Target        string          `json:"target"`
	RunID         uint64          `json:"runId"`
	RunAttempt    uint64          `json:"runAttempt"`
	ArchiveSHA256 string          `json:"archiveSha256"`
	Core          pin             `json:"core"`
	Sidecar       pin             `json:"sidecar"`
	TLSProbe      map[string]any  `json:"tlsProbe"`
	Cronet        json.RawMessage `json:"cronet"`
	Native        nativeFacts     `json:"native"`
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func exactHex(value string, length int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw)*2 == length && strings.ToLower(value) == value
}

func validateRequest(r request) error {
	if r.Schema != requestSchema || r.Target != "windows/amd64" || r.Core.Member != "sing-box.exe" || r.Sidecar.Member != "libcronet.dll" || !exactHex(r.SourceCommit, 40) || !exactHex(r.SourceTree, 40) || r.RunID == 0 || r.RunAttempt == 0 || r.Version == "" || r.CronetVersion == "" {
		return errors.New("native request identity differs")
	}
	if r.Archive.Bytes <= 0 || r.Archive.Bytes > objectLimit || !exactHex(r.Archive.SHA256, 64) || r.Archive.Root == "" || strings.ContainsAny(r.Archive.Root, "\\/\x00") || len(r.Archive.Members) < 2 || len(r.Archive.Members) > 1024 {
		return errors.New("native archive identity/bound differs")
	}
	for _, p := range []pin{r.Core, r.Sidecar} {
		if p.Bytes <= 0 || p.Bytes > objectLimit || !exactHex(p.SHA256, 64) || r.Archive.Members[r.Archive.Root+"/"+p.Member] != p.SHA256 {
			return errors.New("final member identity differs")
		}
	}
	return nil
}

// Reject duplicate JSON members as well as trailing documents; a caller's
// expected identity is data and cannot alias another request field.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	depth := 0
	var value func() error
	value = func() error {
		depth++
		defer func() { depth-- }()
		if depth > 64 {
			return errors.New("native JSON nesting bound")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON member")
				}
				seen[name] = true
				if err = value(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON document")
	}
	return nil
}

func sourceAdmission(r request) error {
	if os.Getenv("POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_EVENT_NAME") != "workflow_dispatch" || os.Getenv("GITHUB_REPOSITORY") != "polaris-arch/sing-box-polaris" || os.Getenv("GITHUB_REPOSITORY_ID") != "1421657509" || os.Getenv("GITHUB_SHA") != r.SourceCommit || os.Getenv("GITHUB_WORKFLOW_SHA") != r.SourceCommit || os.Getenv("GITHUB_RUN_ID") != fmt.Sprint(r.RunID) || os.Getenv("GITHUB_RUN_ATTEMPT") != fmt.Sprint(r.RunAttempt) || os.Getenv("GITHUB_REF") != "refs/tags/v"+r.Version || os.Getenv("GITHUB_WORKFLOW_REF") != "polaris-arch/sing-box-polaris/.github/workflows/build.yml@refs/tags/v"+r.Version {
		return errors.New("explicit same-source formal Windows proof dispatch required")
	}
	// This receipt is job-bound metadata, not a replacement for SYSTEM/kernel
	// observations. The token-free adapter validates its entire closed contract.
	rawAdmission := []byte(os.Getenv("POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT"))
	if len(rawAdmission) == 0 || len(rawAdmission) > 65536 || uniqueJSON(rawAdmission) != nil {
		return errors.New("native protection admission receipt missing/ambiguous")
	}
	var admission struct {
		Schema  string `json:"schema"`
		Context struct {
			SourceCommit   string `json:"sourceCommit"`
			WorkflowCommit string `json:"workflowCommit"`
			RunID          uint64 `json:"runId"`
			RunAttempt     uint64 `json:"runAttempt"`
			Ref            string `json:"ref"`
		} `json:"context"`
	}
	if json.Unmarshal(rawAdmission, &admission) != nil || admission.Schema != "polaris-windows-native-admission-v1" || admission.Context.SourceCommit != r.SourceCommit || admission.Context.WorkflowCommit != r.SourceCommit || admission.Context.RunID != r.RunID || admission.Context.RunAttempt != r.RunAttempt || admission.Context.Ref != os.Getenv("GITHUB_REF") {
		return errors.New("native protection admission context differs")
	}
	if producerSource != r.SourceCommit || producerTree != r.SourceTree || runtime.Version() != r.GoVersion {
		return errors.New("native producer source/tree/toolchain differs")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("native producer BuildInfo missing")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["vcs.revision"] != r.SourceCommit || settings["vcs.modified"] != "false" || settings["GOOS"] != "windows" || settings["GOARCH"] != "amd64" || settings["CGO_ENABLED"] != "0" {
		return errors.New("native producer actual clean source/target differs")
	}
	return nil
}

func copyFinalArchive(filename string, r request, c *cohort) (failure error) {
	file, err := openReadOnlyObject(filename)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, file.Close()) }()
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() != r.Archive.Bytes {
		return errors.New("actual archive byte count differs")
	}
	h := sha256.New()
	if _, err = io.Copy(h, file); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != r.Archive.SHA256 {
		return errors.New("actual final archive digest differs")
	}
	z, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return err
	}
	if len(z.File) > 2048 {
		return errors.New("archive member bound")
	}
	seen := map[string]bool{}
	total := uint64(0)
	for _, member := range z.File {
		name := strings.TrimSuffix(member.Name, "/")
		if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.Contains("/"+name+"/", "/../") || !(name == r.Archive.Root || strings.HasPrefix(name, r.Archive.Root+"/")) {
			return errors.New("unsafe final archive member")
		}
		if member.FileInfo().IsDir() {
			continue
		}
		if seen[strings.ToLower(name)] || member.Mode()&os.ModeType != 0 || member.UncompressedSize64 > objectLimit {
			return errors.New("duplicate/special/oversized final member")
		}
		seen[strings.ToLower(name)] = true
		total += member.UncompressedSize64
		if total > 384<<20 {
			return errors.New("final archive expansion bound")
		}
		expected, ok := r.Archive.Members[name]
		if !ok {
			return errors.New("unindexed final member")
		}
		reader, err := member.Open()
		if err != nil {
			return err
		}
		hash := sha256.New()
		var written int64
		if name == r.Archive.Root+"/"+r.Core.Member || name == r.Archive.Root+"/"+r.Sidecar.Member {
			p := r.Core
			if strings.HasSuffix(name, "/"+r.Sidecar.Member) {
				p = r.Sidecar
			}
			written, err = c.copyObject(p, io.TeeReader(reader, hash))
		} else {
			written, err = io.Copy(hash, io.LimitReader(reader, objectLimit+1))
		}
		closeErr := reader.Close()
		if err = errors.Join(err, closeErr); err != nil {
			return err
		}
		if written != int64(member.UncompressedSize64) || hex.EncodeToString(hash.Sum(nil)) != expected {
			return errors.New("actual final member digest differs")
		}
	}
	if len(seen) != len(r.Archive.Members) {
		return errors.New("missing final archive member")
	}
	return c.holdObjects(r.Core, r.Sidecar)
}

type tlsDocument struct {
	Schema         string `json:"schema"`
	Enabled        bool   `json:"enabled"`
	SourceCommit   string `json:"sourceCommit"`
	SourceModified *bool  `json:"sourceModified"`
	CoreVersion    string `json:"coreVersion"`
	GoVersion      string `json:"goVersion"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Profiles       []struct {
		ID string `json:"id"`
	} `json:"profiles"`
	Aliases []string `json:"legacyChromeAliases"`
}
type checkCase struct {
	expected      map[string]any
	config        map[string]any
	expectedError string
}

func outboundConfig(name *string, enabled bool) map[string]any {
	u := map[string]any{"enabled": enabled}
	if name != nil {
		u["fingerprint"] = *name
	}
	return map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{map[string]any{"type": "trojan", "tag": "probe", "server": "127.0.0.1", "server_port": 443, "password": "local-config-admission-only", "tls": map[string]any{"enabled": true, "server_name": "tls.invalid", "utls": u}}}}
}

func configurationCases(document tlsDocument) []checkCase {
	var cases []checkCase
	add := func(name *string, enabled, passes bool) {
		var value any
		if name != nil {
			value = *name
		}
		expectedError := ""
		if !passes && document.Enabled {
			expectedError = "unknown uTLS fingerprint"
		}
		cases = append(cases, checkCase{map[string]any{"fingerprint": value, "enabled": enabled, "expectedPass": passes}, outboundConfig(name, enabled), expectedError})
	}
	if document.Enabled {
		for _, profile := range document.Profiles {
			name := profile.ID
			add(&name, true, true)
		}
		for _, alias := range document.Aliases {
			name := alias
			add(&name, true, true)
		}
	}
	empty := ""
	add(nil, true, document.Enabled)
	add(&empty, true, document.Enabled)
	add(nil, false, true)
	for _, name := range []string{"polaris_unknown_profile", "default", "disabled", "follow", "safari_15_3", "safari_15_5"} {
		name := name
		add(&name, true, false)
	}
	if document.Enabled {
		for _, ech := range []bool{false, true} {
			name := "chrome"
			config := outboundConfig(&name, true)
			out := config["outbounds"].([]any)[0].(map[string]any)
			out["type"] = "shadowtls"
			out["version"] = 3
			if ech {
				out["tls"].(map[string]any)["ech"] = map[string]any{"enabled": true}
			}
			expectedError := ""
			if ech {
				expectedError = "cannot be combined with real ECH"
			}
			cases = append(cases, checkCase{map[string]any{"outbound": "shadowtls", "version": 3, "realECH": ech, "expectedPass": !ech}, config, expectedError})
		}
	}
	return cases
}

func executeSuite(r request, filename string, parents ...context.Context) (result proof, failure error) {
	if err := sourceAdmission(r); err != nil {
		return result, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	actor, err := currentActor()
	if err != nil {
		return result, err
	}
	console, _, _ := kernel.NewProc("GetConsoleWindow").Call()
	if console == 0 {
		if err = nativeBool(kernel.NewProc("AllocConsole")); err != nil {
			return result, err
		}
		defer func() { failure = errors.Join(failure, nativeBool(kernel.NewProc("FreeConsole"))) }()
	}
	parent := context.Background()
	if len(parents) > 0 {
		parent = parents[0]
	}
	deadline, cancelDeadline := context.WithTimeout(parent, 8*time.Minute)
	defer cancelDeadline()
	ctx, stopSignals := signal.NotifyContext(deadline, os.Interrupt)
	defer stopSignals()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	journal, err := openCustody(r, actor)
	if err != nil {
		return result, err
	}
	defer func() {
		closeErr := journal.close()
		if closeErr != nil {
			result.custodyClosed = false
		}
		failure = errors.Join(failure, closeErr)
	}()
	c, err := newCohort(journal.record.CohortID)
	if err != nil {
		return result, err
	}
	c.ctx = ctx
	c.custody = journal
	result = proof{Schema: proofSchema, SourceCommit: r.SourceCommit, SourceTree: r.SourceTree, Version: r.Version, Target: r.Target, RunID: r.RunID, RunAttempt: r.RunAttempt, ArchiveSHA256: r.Archive.SHA256, Core: r.Core, Sidecar: r.Sidecar}
	result.Native.Actor = actor
	result.Native.Cohort = c.fact
	defer func() {
		cleanup, err := c.close()
		result.Native.Cleanup = cleanup
		failure = errors.Join(failure, err)
		var custodyErr error
		for _, record := range result.Native.Executions {
			if !record.ActualWait || !record.StdoutEOF || !record.StderrEOF || !record.HandlesClosed || record.JobActiveAfterWait != 0 {
				custodyErr = errors.New("native child handle/readers closure is not complete")
			}
		}
		if custodyErr == nil {
			custodyErr = journal.finish(cleanup)
		}
		result.custodyClosed = custodyErr == nil
		failure = errors.Join(failure, custodyErr)
		if ctx.Err() != nil {
			failure = errors.Join(failure, ctx.Err())
		}
	}()
	if err = journal.bindCohort(c.fact); err != nil {
		return result, err
	}
	if err = copyFinalArchive(filename, r, c); err != nil {
		return result, err
	}
	result.Native.Core = c.coreFact
	result.Native.Sidecar = c.sidecarFact
	if err = journal.bindObjects(c.coreFact, c.sidecarFact); err != nil {
		return result, err
	}
	producerPath, err := os.Executable()
	if err != nil {
		return result, err
	}
	producer, err := openReadOnlyObject(producerPath)
	if err != nil {
		return result, err
	}
	h := sha256.New()
	size, err := io.Copy(h, producer)
	err = errors.Join(err, producer.Close())
	if err != nil {
		return result, err
	}
	result.Native.Producer = producerFact{r.SourceCommit, r.SourceTree, hex.EncodeToString(h.Sum(nil)), size, runtime.Version()}
	run := func(purpose string, args []string, input []byte, live func(*nativeChild) error) (processFact, error) {
		record, err := c.execute(purpose, args, input, live)
		result.Native.Executions = append(result.Native.Executions, record)
		return record, err
	}
	capabilities, err := run("capabilities", []string{"tools", "tls-fingerprints"}, nil, nil)
	if err != nil {
		return result, err
	}
	if capabilities.ExitCode != 0 {
		return result, errors.New("actual TLS capability query failed")
	}
	raw := []byte(capabilities.Stdout)
	if err = uniqueJSON(raw); err != nil {
		return result, err
	}
	var doc tlsDocument
	if err = json.Unmarshal(raw, &doc); err != nil {
		return result, err
	}
	if doc.Schema != "polaris-tls-fingerprint-capabilities-v1" || doc.SourceCommit != r.SourceCommit || doc.SourceModified == nil || *doc.SourceModified || doc.CoreVersion != r.Version || doc.GoVersion != r.GoVersion || doc.OS != "windows" || doc.Arch != "amd64" {
		return result, errors.New("actual running Core capabilities differ")
	}
	if !doc.Enabled || len(doc.Profiles) == 0 || len(doc.Profiles) > 64 || len(doc.Aliases) > 64 {
		return result, errors.New("actual native TLS profile inventory/bound differs")
	}
	var fullDocument any
	if err = json.Unmarshal(raw, &fullDocument); err != nil {
		return result, err
	}
	checks := []any{}
	for _, control := range configurationCases(doc) {
		config, err := json.Marshal(control.config)
		if err != nil {
			return result, err
		}
		record, err := run("check-config-v1", []string{"--disable-color", "check", "-c", "stdin"}, config, nil)
		if err != nil {
			return result, err
		}
		expectedExit := uint32(1)
		if control.expected["expectedPass"].(bool) {
			expectedExit = 0
		}
		if record.ExitCode != expectedExit || (control.expectedError != "" && !strings.Contains(record.Stdout+record.Stderr, control.expectedError)) {
			return result, errors.New("actual fixed configuration control failed")
		}
		observation := control.expected
		observation["exitCode"] = record.ExitCode
		observation["output"] = record.Stdout + record.Stderr
		checks = append(checks, observation)
	}
	result.TLSProbe = map[string]any{"schema": "polaris-tls-fingerprint-runtime-probe-v1", "coreSHA256": r.Core.SHA256, "coreBytes": r.Core.Bytes, "capabilities": fullDocument, "configurationChecks": checks, "networkHandshakeValidated": false}
	cronet, err := run("cronet-observation", []string{"tools", "cronet", "--expected-version", r.CronetVersion, "--sha256", r.Sidecar.SHA256}, nil, nil)
	if err != nil {
		return result, err
	}
	if cronet.ExitCode != 0 || uniqueJSON([]byte(cronet.Stdout)) != nil {
		return result, errors.New("actual selected Cronet observation failed")
	}
	result.Cronet = json.RawMessage(cronet.Stdout)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return result, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		return result, err
	}
	config := map[string]any{"log": map[string]any{"level": "error"}, "inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "naive", "tag": "module-only", "server": "127.0.0.1", "server_port": 9, "username": "native-proof", "password": "native-proof", "tls": map[string]any{"enabled": true, "server_name": "tls.invalid"}}}, "route": map[string]any{"final": "direct"}}
	input, err := json.Marshal(config)
	if err != nil {
		return result, err
	}
	main, err := run("run-main-v1", []string{"run", "-c", "stdin"}, input, func(child *nativeChild) error {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if owned, err := listenerOwnedBy(port, child.pid); err != nil {
				return err
			} else if owned {
				connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
				if err != nil {
					return err
				}
				if err = connection.Close(); err != nil {
					return err
				}
				module, err := mappedDLL(child.process, c.sidecarFact.NativePath)
				if err != nil {
					return err
				}
				result.Native.RunMain = runFact{"127.0.0.1", port, child.pid, true, module}
				return child.interrupt()
			}
			time.Sleep(20 * time.Millisecond)
		}
		return errors.New("native RunMain readiness deadline")
	})
	if err != nil {
		return result, err
	}
	if main.ExitCode != 0 {
		return result, errors.New("native RunMain did not exit successfully")
	}
	return result, nil
}

func readNativeRequest(reader *bufio.Reader) ([]byte, error) {
	raw, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	if len(raw) > 1<<20 {
		return nil, errors.New("native request framing bound")
	}
	return raw, nil
}

func watchNativeCancellation(reader *bufio.Reader, cancel context.CancelFunc) {
	// Only cancel is a valid control frame. EOF, malformed/oversized or any
	// other frame also fails closed by cancelling, never selecting an operation.
	_, _ = reader.ReadSlice('\n')
	cancel()
}

func main() {
	archive := flag.String("archive", "", "exact same-run final ZIP data")
	flag.Parse()
	if flag.NArg() != 0 || *archive == "" || !filepath.IsAbs(*archive) {
		fmt.Fprintln(os.Stderr, "fixed absolute archive input required")
		os.Exit(2)
	}
	reader := bufio.NewReaderSize(os.Stdin, (1<<20)+1)
	raw, err := readNativeRequest(reader)
	var r request
	if err == nil && len(raw) <= 1<<20 {
		err = uniqueJSON(raw)
	} else if err == nil {
		err = errors.New("request byte bound")
	}
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&r)
	}
	if err == nil {
		err = validateRequest(r)
	}
	var result proof
	if err == nil {
		ctx, cancel := context.WithCancel(context.Background())
		// Exactly one fixed cancellation frame, or loss of the adapter pipe,
		// cancels the original owner. No command/path is accepted on this channel.
		go watchNativeCancellation(reader, cancel)
		result, err = executeSuite(r, *archive, ctx)
		cancel()
	}
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "polaris-windows-native-execution-diagnostic-v1", "publicationEligible": false, "executionAuthority": false, "custodyReconciled": result.custodyClosed, "error": err.Error(), "native": result.Native})
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
