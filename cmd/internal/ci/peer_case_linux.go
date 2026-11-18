package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type peerProduct struct {
	core, sidecar string
	corePin       map[string]any
	sidecarPin    map[string]any
}

func stagePeerProduct(directory, workspace string, row map[string]any) (peerProduct, error) {
	corePin, _ := row["core"].(map[string]any)
	sidecarPin, _ := row["sidecar"].(map[string]any)
	archive, _ := row["archive"].(map[string]any)
	smoke, _ := row["finalPackageCronetSmoke"].(map[string]any)
	variant, _ := row["variant"].(map[string]any)
	tagsText, _ := row["tags"].(string)
	tags := nativeTagSet(tagsText)
	if row["schema"] != "polaris-upstream-native-receipt-v1" || row["target"] != "linux/amd64" ||
		variant["linkage"] != "shared-purego" || smoke["status"] != "passed" ||
		!tags["with_naive_outbound"] || !tags["with_quic"] || !tags["with_gvisor"] ||
		corePin["member"] != "sing-box" || sidecarPin["member"] != "libcronet.so" || archive == nil {
		return peerProduct{}, fmt.Errorf("requires already smoked Linux native producer row")
	}
	for _, name := range []string{"name", "sha256", "root"} {
		if _, ok := archive[name].(string); !ok {
			return peerProduct{}, fmt.Errorf("native archive identity missing")
		}
	}
	if _, ok := archive["members"].(map[string]any); !ok {
		return peerProduct{}, fmt.Errorf("native archive member identities missing")
	}
	members, err := loadNativeSmokeArchive(directory, archive)
	if err != nil {
		return peerProduct{}, err
	}
	product := peerProduct{filepath.Join(workspace, "sing-box"), filepath.Join(workspace, "libcronet.so"), corePin, sidecarPin}
	for name, raw := range members {
		if err := writePeerPrivate(filepath.Join(workspace, name), raw); err != nil {
			return peerProduct{}, err
		}
	}
	if err := product.verify(); err != nil {
		return peerProduct{}, err
	}
	return product, os.Chmod(product.core, 0o700)
}

func (product peerProduct) verify() error {
	for path, pin := range map[string]map[string]any{product.core: product.corePin, product.sidecar: product.sidecarPin} {
		info, err := os.Lstat(path)
		size, exact := nativePositiveInteger(pin["bytes"])
		if err != nil || !exact || !info.Mode().IsRegular() || info.Size() != size {
			return fmt.Errorf("native executable or sidecar identity unavailable before case")
		}
		hash, err := fileSHA256(path)
		if err != nil || hash != pin["sha256"] {
			return fmt.Errorf("native executable or sidecar bytes changed before case")
		}
	}
	return nil
}

var peerMapping = regexp.MustCompile(`^[[:xdigit:]]+-[[:xdigit:]]+ +([^ ]+) +[[:xdigit:]]+ +([[:xdigit:]]+):([[:xdigit:]]+) +([0-9]+) +(.*)$`)

func (product peerProduct) mappedLibrary(process *peerNativeProcess) (map[string]any, error) {
	unlock, err := process.inspect()
	if err != nil {
		return nil, err
	}
	defer unlock()
	pid := process.identity.PID
	if process.exited() != nil {
		return nil, fmt.Errorf("actual core identity no longer live")
	}
	proc, err := readPeerProc(pid)
	if err != nil || proc.peerProcessIdentity != process.identity {
		return nil, fmt.Errorf("actual core identity no longer live")
	}
	procDir := fmt.Sprintf("/proc/%d/", pid)
	coreHash, err := fileSHA256(procDir + "exe")
	if err != nil || coreHash != product.corePin["sha256"] {
		return nil, fmt.Errorf("actual executing ELF changed")
	}
	sidecar, err := filepath.EvalSymlinks(product.sidecar)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Stat(sidecar, &stat); err != nil {
		return nil, err
	}
	major, minor := unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev))
	mapped, err := os.ReadFile(procDir + "maps")
	if err != nil {
		return nil, err
	}
	executable := false
	for _, line := range bytes.Split(mapped, []byte{10}) {
		fields := peerMapping.FindSubmatch(line)
		if len(fields) == 0 || string(fields[5]) != sidecar {
			continue
		}
		wantMajor, _ := strconv.ParseUint(string(fields[2]), 16, 32)
		wantMinor, _ := strconv.ParseUint(string(fields[3]), 16, 32)
		inode, _ := strconv.ParseUint(string(fields[4]), 10, 64)
		if wantMajor != uint64(major) || wantMinor != uint64(minor) || inode != stat.Ino {
			return nil, fmt.Errorf("mapped Cronet file identity differs")
		}
		executable = executable || bytes.Contains(fields[1], []byte{'x'})
	}
	hash, err := fileSHA256(sidecar)
	if err != nil || hash != product.sidecarPin["sha256"] || !executable {
		return nil, fmt.Errorf("actual native Cronet mapping not proven")
	}
	return map[string]any{"linkage": "shared-purego", "pid": pid, "startIdentity": process.identity,
		"sha256": hash, "device": [2]uint32{major, minor}, "inode": stat.Ino, "mappedExecutable": true}, nil
}

type peerCaseFixture struct {
	cert                       peerCertificate
	password                   string
	peerPort, tcpEcho, udpEcho int
}

type peerProtocol struct {
	kind string
}

func (protocol peerProtocol) masque() bool   { return strings.HasPrefix(protocol.kind, "masque-") }
func (protocol peerProtocol) udp() bool      { return protocol.kind != "naive-h2" }
func (protocol peerProtocol) onDemand() bool { return protocol.kind == "masque-h3-on-demand" }
func (protocol peerProtocol) target() string {
	if protocol.masque() {
		return "198.18.0.1"
	}
	return peerLoopback
}

func (fixture peerCaseFixture) configs(protocol peerProtocol, relayPort, mixed int, mutation *string, otherCA string) (peer, client map[string]any) {
	alpn, network := "h2", "tcp"
	if protocol.udp() {
		alpn, network = "h3", "udp"
	}
	tls := map[string]any{"enabled": true, "certificate": []string{fixture.cert.leaf},
		"key": []string{fixture.cert.key}, "alpn": []string{alpn}}
	const user = "controlled-peer"
	ports := []int{fixture.tcpEcho, fixture.udpEcho}
	common := func(inbound, outbound, destination string) map[string]any {
		return map[string]any{
			"log": map[string]any{"level": "debug"},
			"route": map[string]any{"rules": []map[string]any{
				{"inbound": []string{inbound}, "ip_cidr": []string{destination + "/32"}, "port": ports, "action": "route", "outbound": outbound},
				{"action": "reject"},
			}},
			"dns": map[string]any{"servers": []map[string]any{
				{"type": "hosts", "tag": "test-hosts", "predefined": map[string][]string{"controlled.invalid": {peerLoopback}}},
			}, "final": "test-hosts"},
		}
	}
	peer = common("peer", "echo-only", peerLoopback)
	peer["outbounds"] = []map[string]any{{"type": "direct", "tag": "echo-only"}}
	password, serverName, ca, requestPath := fixture.password, "controlled.invalid", fixture.cert.ca, "/controlled-ip/"
	if mutation != nil {
		switch *mutation {
		case "wrong-auth":
			password += "-wrong"
		case "wrong-ca":
			ca = otherCA
		case "wrong-sni":
			serverName = "wrong.invalid"
		case "wrong-path":
			requestPath = "/wrong-ip/"
		}
	}
	users := []map[string]string{{"username": user, "password": fixture.password}}
	client = common("mixed-test", "controlled-peer", protocol.target())
	client["inbounds"] = []map[string]any{{"type": "mixed", "tag": "mixed-test", "listen": peerLoopback, "listen_port": mixed}}
	outbound := map[string]any{"tag": "controlled-peer", "server": peerLoopback,
		"server_port": relayPort, "username": user, "password": password,
		"tls": map[string]any{"enabled": true, "server_name": serverName, "certificate": []string{ca}}, "connect_timeout": "5s"}
	if protocol.masque() {
		peer["endpoints"] = []map[string]any{{"type": "masque-server", "tag": "peer", "listen": peerLoopback, "listen_port": fixture.peerPort,
			"system": false, "mtu": 1280, "path": "/controlled-ip/", "address": []string{"198.18.0.1/24"}, "advertise_routes": []string{"198.18.0.1/32"},
			"version": []int{3}, "users": users, "tls": tls}}
		outbound["type"], outbound["system"], outbound["mtu"], outbound["version"] = "masque-client", false, 1280, 3
		outbound["path"], outbound["disable_version_fallback"], outbound["on_demand"] = requestPath, true, protocol.onDemand()
		client["endpoints"] = []map[string]any{outbound}
	} else {
		peer["inbounds"] = []map[string]any{{"type": "naive", "tag": "peer", "listen": peerLoopback,
			"listen_port": fixture.peerPort, "network": network, "users": users, "tls": tls}}
		outbound["type"], outbound["quic"] = "naive", protocol.udp()
		client["outbounds"] = []map[string]any{outbound}
	}
	return
}

func peerMutationProof(healthy, negative map[string]any, mutation string) (map[string]any, error) {
	healthyRaw, err := json.Marshal(healthy)
	if err != nil {
		return nil, err
	}
	actualRaw, err := json.Marshal(negative)
	if err != nil {
		return nil, err
	}
	healthyInbound, actualInbound := healthy["inbounds"].([]map[string]any)[0], negative["inbounds"].([]map[string]any)[0]
	bucket := "outbounds"
	if healthy[bucket] == nil {
		bucket = "endpoints"
	}
	healthyOutbound, actualOutbound := healthy[bucket].([]map[string]any)[0], negative[bucket].([]map[string]any)[0]
	healthyTLS, actualTLS := healthyOutbound["tls"].(map[string]any), actualOutbound["tls"].(map[string]any)
	before, _ := json.Marshal(healthyTLS["certificate"])
	after, _ := json.Marshal(actualTLS["certificate"])
	old, changed, field := healthyTLS, actualTLS, "certificate"
	switch mutation {
	case "wrong-sni":
		field = "server_name"
		if old[field] != "controlled.invalid" || changed[field] != "wrong.invalid" {
			return nil, fmt.Errorf("negative SNI differs from fixed fixture")
		}
	case "wrong-auth":
		old, changed, field = healthyOutbound, actualOutbound, "password"
	case "wrong-ca":
	case "wrong-path":
		old, changed, field = healthyOutbound, actualOutbound, "path"
		if old[field] != "/controlled-ip/" || changed[field] != "/wrong-ip/" {
			return nil, fmt.Errorf("negative path differs from fixed fixture")
		}
	default:
		return nil, fmt.Errorf("negative mutation is not modeled")
	}
	observed := changed[field]
	if reflect.DeepEqual(old[field], observed) {
		return nil, fmt.Errorf("negative mutation did not change its field")
	}
	port, relayPort := actualInbound["listen_port"], actualOutbound["server_port"]
	actualInbound["listen_port"], actualOutbound["server_port"], changed[field] = healthyInbound["listen_port"], healthyOutbound["server_port"], old[field]
	equal := reflect.DeepEqual(healthy, negative)
	actualInbound["listen_port"], actualOutbound["server_port"], changed[field] = port, relayPort, observed
	if !equal {
		return nil, fmt.Errorf("negative changed more than its one controlled field")
	}
	return map[string]any{"singleFieldMutation": mutation, "healthyTrustSHA256": sha256Hex(before),
		"negativeTrustSHA256": sha256Hex(after), "healthyConfigurationSHA256": sha256Hex(healthyRaw),
		"negativeConfigurationSHA256": sha256Hex(actualRaw), "operationalPortChangesOnly": true}, nil
}

type peerCase struct {
	protocol    peerProtocol
	relay       *peerRelay
	relayClosed bool
	reservedTCP int
	receipt     map[string]any
	trace       peerTrace
	owners      []*peerNativeProcess
	configs     []map[string]any
	privateLogs []string
	ports       []int
	fixture     *peerEcho
	peerPort    int
	tcpEcho     int
	udpEcho     int
	oldStream   net.Conn
	scope       *peerProcessScope
	directory   string
	sourceRoot  string
}

type peerDiagnosticError struct{ kind, message string }

func (err *peerDiagnosticError) Error() string { return err.message }

func executePeerCaseSchedule(ctx context.Context, schedule []peerScheduledCase, execute func(peerScheduledCase) (map[string]any, error)) []map[string]any {
	results := make([]map[string]any, 0, len(schedule))
	var blocked map[string]any
	for index, scheduled := range schedule {
		item := map[string]any{"kind": scheduled.Kind, "mutation": scheduled.Mutation}
		if blocked != nil {
			item["status"], item["reason"], item["blockedByCase"] = "NOT_RUN", "blocked_by_cleanup_or_identity", blocked
		} else if ctx.Err() != nil {
			item["status"], item["reason"] = "NOT_RUN", "bounded_suite_budget_exhausted"
		} else {
			result, err := execute(scheduled)
			if err != nil {
				item["status"], item["identityUncertain"], item["continuationSafe"] = "FAIL", true, false
				item["errorType"], item["error"] = peerErrorName(err), "non-public exception details withheld"
			} else {
				item = result
			}
			if item["continuationSafe"] != true {
				item["status"] = "FAIL"
				blocked = map[string]any{"kind": scheduled.Kind, "mutation": scheduled.Mutation, "index": index}
			}
		}
		results = append(results, item)
	}
	return results
}

func runPeerCase(ctx context.Context, scope *peerProcessScope, product peerProduct, workspace, sourceRoot, openssl string, scheduled peerScheduledCase) (map[string]any, error) {
	protocol := peerProtocol{scheduled.Kind}
	work, err := os.MkdirTemp(workspace, protocol.kind+"-")
	if err != nil {
		return nil, err
	}
	state := &peerCase{protocol: protocol, reservedTCP: -1, directory: work, sourceRoot: sourceRoot, scope: scope, receipt: map[string]any{
		"kind": protocol.kind, "mutation": scheduled.Mutation, "status": "RUNNING", "cleanup": []any{},
		"expectedCoreSHA256": product.corePin["sha256"], "configurationChecks": []map[string]any{},
		"fixturesJoined": false, "identityUncertain": false, "rawConfigurationPubliclyRetained": false,
		"privateFilesDeletedAtSuiteEnd": true, "controlledPeerQUICErrorLogLevel": "error",
	}}
	bodyErr := state.execute(ctx, product, openssl, scheduled.Mutation)
	if bodyErr != nil {
		kind, message := peerPublicError(bodyErr)
		state.receipt["status"], state.receipt["errorType"], state.receipt["error"] = "FAIL", kind, message
		failed := []any{}
		for _, event := range state.trace.events {
			if event["status"] == "FAIL" {
				failed = append(failed, event["stage"])
			}
		}
		last := any("case.setup")
		if n := len(state.trace.events); n > 0 {
			last = state.trace.events[n-1]["stage"]
		}
		state.receipt["failedOperationStages"], state.receipt["observedStageAtException"] = failed, last
		state.receipt["observedStageIsUniqueRootCause"] = false
	} else {
		state.receipt["status"] = "PASS"
	}
	state.retire()
	return state.receipt, nil
}

func (state *peerCase) start(ctx context.Context, product peerProduct, role string, config map[string]any) (*peerNativeProcess, error) {
	trace := &state.trace
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(state.directory, role+".private.json")
	if err := writePeerPrivate(configPath, data); err != nil {
		return nil, err
	}
	fact := peerFileFact{sha256Hex(data), len(data)}
	trace.event(role+".configuration.check", nil)
	check := map[string]any{"role": role, "configurationSHA256": fact.SHA256, "configurationBytes": fact.Bytes, "status": "RUNNING"}
	state.receipt["configurationChecks"] = append(state.receipt["configurationChecks"].([]map[string]any), check)
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	output, exit, err := sourceCombinedOutput(checkCtx, filepath.Dir(product.core), peerCoreEnvironment(state.directory, ""),
		1<<20, product.core, "check", "-c", configPath)
	cancel()
	if err != nil {
		return nil, err
	}
	if err := writePeerPrivate(filepath.Join(state.directory, role+"-check.private.log"), []byte(output)); err != nil {
		return nil, err
	}
	log := peerFileFact{sha256Hex([]byte(output)), len(output)}
	state.privateLogs = append(state.privateLogs, role+"-check.private.log")
	check["privateLog"], check["exitCode"], check["status"] = log, exit, "PASS"
	if exit == nil || *exit != 0 {
		check["status"] = "FAIL"
		return nil, &peerDiagnosticError{"RuntimeError", "generated controlled configuration failed actual core check"}
	}
	if role == "peer" {
		state.receipt["peerCheck"] = log
	}
	verified, err := readNativeSource(state.directory, filepath.Base(configPath))
	if err != nil || !bytes.Equal(verified, data) {
		check["status"], state.receipt["identityUncertain"] = "FAIL", true
		return nil, &peerDiagnosticError{"IdentityFailure", "configuration bytes changed between native check and execution"}
	}
	trace.event(role+".process.spawn", nil)
	logName := role + ".private.log"
	owner, err := state.scope.start(product.core, role, filepath.Join(state.directory, logName),
		product.corePin["sha256"].(string), "--disable-color", "run", "-c", configPath)
	if _, logErr := os.Lstat(filepath.Join(state.directory, logName)); logErr == nil {
		state.privateLogs = append(state.privateLogs, logName)
	}
	if err != nil {
		state.receipt["identityUncertain"] = true
		return nil, &peerDiagnosticError{"IdentityFailure", "actual native process identity unavailable"}
	}
	state.owners = append(state.owners, owner)
	state.configs = append(state.configs, map[string]any{"role": role, "pid": owner.identity.PID,
		"startIdentity": owner.identity, "sha256": fact.SHA256, "bytes": fact.Bytes})
	trace.event(role+".process.identity", map[string]any{"pid": owner.identity.PID, "startTicks": owner.identity.StartTicks, "coreSHA256": owner.core})
	return owner, nil
}

func (state *peerCase) closeOwner(owner *peerNativeProcess) (*peerProcessCleanup, error) {
	if owner.result != nil {
		return owner.result, owner.cleanupErr
	}
	begin := state.trace.event(owner.role+".process.close.begin", map[string]any{"pid": owner.identity.PID})
	result, err := owner.close()
	begin["exitBeforeTerminate"] = result.ExitBeforeTerminate
	for _, action := range result.TerminationActions {
		fields := map[string]any{"signal": action.Signal, "pidfdBound": action.PIDFDBound}
		if action.Signal == "SIGTERM" {
			fields["pid"], fields["startTicks"], fields["coreSHA256"] = action.PID, action.StartTicks, action.CoreSHA256
		}
		fact := state.trace.event(owner.role+".process.signal", fields)
		if action.MonotonicSec != 0 {
			fact["monotonicSeconds"] = action.MonotonicSec
		}
	}
	state.trace.event(owner.role+".process.close.observed", map[string]any{"exitCode": result.ExitCode,
		"forcedKill": result.ForcedKill, "cleanupErrorLog": result.CleanupErrorLog})
	return result, err
}

func (state *peerCase) execute(ctx context.Context, product peerProduct, openssl string, mutation *string) error {
	receipt, trace, protocol := state.receipt, &state.trace, state.protocol
	target := protocol.target()
	identity := trace.event("case.native_identity.verify", map[string]any{"status": "RUNNING"})
	if err := product.verify(); err != nil {
		identity["status"], identity["errorType"], receipt["identityUncertain"] = "FAIL", "IdentityFailure", true
		return &peerDiagnosticError{"IdentityFailure", "native executable or sidecar identity unavailable before case"}
	}
	identity["status"] = "PASS"
	trace.event("case.certificate", nil)
	cert, err := createPeerCertificate(ctx, openssl, state.directory, "controlled.invalid")
	if err != nil {
		return err
	}
	receipt["certificateFixture"] = map[string]any{"peerLeafSHA256": sha256Hex([]byte(cert.leaf)),
		"healthyTrustSHA256": sha256Hex([]byte(cert.ca)), "fixedHealthySNI": "controlled.invalid", "fixedNegativeSNI": "wrong.invalid"}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	snapshot, err := peerProcSnapshot()
	if err != nil || len(peerDescendants(snapshot, os.Getpid())) != 0 {
		receipt["identityUncertain"] = true
		return &peerDiagnosticError{"RuntimeError", "unexpected children before isolated case"}
	}
	trace.event("case.fixtures.start", nil)
	state.fixture, err = startPeerEcho()
	if err != nil {
		return err
	}
	state.tcpEcho, state.udpEcho = state.fixture.ports()
	if protocol.udp() {
		state.peerPort, err = peerFreeUDPPort()
		if err == nil {
			err = state.startRelay()
		}
	} else {
		state.peerPort, err = peerFreeTCPPort()
	}
	if err != nil {
		return err
	}
	fixture := peerCaseFixture{cert: cert, password: hex.EncodeToString(secret), peerPort: state.peerPort,
		tcpEcho: state.tcpEcho, udpEcho: state.udpEcho}
	peerConfig, _ := fixture.configs(protocol, state.clientPeerPort(), 1, nil, "")
	peer, err := state.start(ctx, product, "peer", peerConfig)
	if err != nil {
		return err
	}
	if protocol.udp() {
		err = peerReadUDPReady(ctx, peer, state.peerPort, trace)
	} else {
		err = peerReadReady(ctx, peer, state.peerPort, trace)
	}
	if err != nil {
		return err
	}
	receipt["udpObservers"] = []any{}
	var healthyConfig map[string]any
	startClient := func(role string, alter *string) (*peerNativeProcess, int, error) {
		mixed, err := peerFreeTCPPort()
		if err != nil {
			return nil, 0, err
		}
		state.ports = append(state.ports, mixed)
		var ca string
		if alter != nil && *alter == "wrong-ca" {
			wrong, err := createPeerCertificate(ctx, openssl, state.directory, role+"-wrong-ca")
			if err != nil {
				return nil, 0, err
			}
			ca = wrong.ca
		}
		_, config := fixture.configs(protocol, state.clientPeerPort(), mixed, alter, ca)
		if role == "healthy" {
			healthyConfig = config
		}
		var proof map[string]any
		if alter != nil {
			proof, err = peerMutationProof(healthyConfig, config, *alter)
			if err != nil {
				return nil, 0, err
			}
			receipt["mutationProof"] = proof
		}
		client, err := state.start(ctx, product, role, config)
		if err != nil {
			return nil, 0, err
		}
		if proof != nil {
			hash, err := fileSHA256(filepath.Join(state.directory, role+".private.json"))
			if err != nil || hash != proof["negativeConfigurationSHA256"] {
				receipt["identityUncertain"] = true
				return nil, 0, &peerDiagnosticError{"IdentityFailure", "actual negative configuration differs from mutation proof"}
			}
		}
		if state.relay != nil {
			if err := state.relay.bind(client); err != nil {
				receipt["identityUncertain"] = true
				return nil, 0, &peerDiagnosticError{"IdentityFailure", "UDP observer exact child identity unavailable"}
			}
		}
		if err := peerReadReady(ctx, client, mixed, trace); err != nil {
			return nil, 0, err
		}
		if protocol.masque() && alter == nil && !protocol.onDemand() {
			if err := peerReadAssignment(ctx, client, trace); err != nil {
				return nil, 0, err
			}
		}
		return client, mixed, nil
	}
	healthy, mixed, err := startClient("healthy", nil)
	if err != nil {
		return err
	}
	facts, old, err := peerTCPExchange(ctx, mixed, state.tcpEcho, target, []int{1, 4096, 131071}, true, trace, "healthy")
	state.oldStream, receipt["healthyTCP"] = old, facts
	if err != nil {
		return err
	}
	if protocol.onDemand() {
		if err := peerReadAssignment(ctx, healthy, trace); err != nil {
			return err
		}
		receipt["onDemandAssignmentAfterFirstFlow"] = true
	}
	if !protocol.masque() {
		libraryEvent := trace.event("healthy.native_identity.verify", map[string]any{"status": "RUNNING"})
		library, err := product.mappedLibrary(healthy)
		if err != nil {
			libraryEvent["status"], libraryEvent["errorType"], receipt["identityUncertain"] = "FAIL", "IdentityFailure", true
			return &peerDiagnosticError{"IdentityFailure", "actual native executable or Cronet mapping identity not proven"}
		}
		receipt["loadedNativeLibrary"], libraryEvent["status"] = library, "PASS"
		protocolEvent := trace.event("healthy.native_protocol.verify", map[string]any{"status": "RUNNING"})
		log, err := readPeerLog(healthy.log.Name())
		if err != nil {
			return err
		}
		expected := "h2"
		if protocol.udp() {
			expected = "quic/1+spdy/3"
		}
		observation := observePeerNativeProtocol(log, expected)
		receipt["nativeProtocolObservation"], receipt["negotiatedProtocolAndStatus"] = observation, observation["observedAllowlistedProtocolAndStatus"]
		if observation["successfulExpectedProtocolObserved"] != true {
			protocolEvent["status"] = "FAIL"
			return &peerDiagnosticError{"RuntimeError", "actual successful negotiated Naive protocol not proven"}
		}
		if protocol.udp() {
			carrier, err := state.h3OnlyCarrier(peerConfig)
			if err != nil {
				return err
			}
			receipt["h3OnlyCarrierObservation"] = carrier
		}
		protocolEvent["status"] = "PASS"
	}
	if protocol.masque() {
		counts := state.relay.datagrams()
		if counts[0] == 0 || counts[1] == 0 {
			return &peerDiagnosticError{"RuntimeError", "actual two-way QUIC carrier missing"}
		}
	}

	if mutation == nil {
		outcomes := make([][]map[string]any, 2)
		failures := make([]error, len(outcomes))
		var workers sync.WaitGroup
		for i := range outcomes {
			workers.Go(func() {
				outcomes[i], _, failures[i] = peerTCPExchange(ctx, mixed, state.tcpEcho, target, []int{16384}, false, trace, "concurrent"+strconv.Itoa(i))
			})
		}
		workers.Wait()
		receipt["concurrentTCP"] = outcomes
		if err := errors.Join(failures...); err != nil {
			return err
		}
		if protocol.masque() {
			receipt["applicationUDP"], err = peerUDPExchange(ctx, mixed, state.udpEcho, target, trace, "healthy")
			if err != nil {
				return err
			}
		}
	}
	if err := state.prepareRelayRetirement(); err != nil {
		return err
	}
	if _, err := state.closeOwner(healthy); err != nil {
		return err
	}
	before := state.fixture.counters().TCPBytes
	retired, err := retirePeerStream(ctx, state.oldStream, trace)
	state.oldStream = nil
	if err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	if state.fixture.counters().TCPBytes != before {
		return &peerDiagnosticError{"RuntimeError", "retired process old stream still carried new payload"}
	}
	receipt["oldStreamRetired"] = retired
	retired["noNewEchoBytes"] = true
	if state.relay != nil {
		receipt["firstCarrierDatagrams"] = state.relay.datagrams()
		if err := state.closeRelay(); err != nil {
			return err
		}
		if err := state.startRelay(); err != nil {
			return err
		}
	}
	if mutation == nil {
		client, port, err := startClient("reconnected", nil)
		if err != nil {
			return err
		}
		receipt["freshProcessTCP"], _, err = peerTCPExchange(ctx, port, state.tcpEcho, target, []int{4096}, false, trace, "reconnected")
		if err == nil && protocol.onDemand() {
			err = peerReadAssignment(ctx, client, trace)
			if err == nil {
				receipt["onDemandFreshAssignmentAfterFirstFlow"] = true
			}
		}
		return errors.Join(err, state.fixture.error())
	}

	peerBefore, err := readPeerLog(peer.log.Name())
	if err != nil {
		return err
	}
	if len(peerBefore) != 0 && !bytes.HasSuffix(peerBefore, []byte{10}) {
		return &peerDiagnosticError{"RuntimeError", "negative peer window starts inside incomplete log line"}
	}
	client, port, err := startClient("negative", mutation)
	if err != nil {
		return err
	}
	baseline := state.fixture.counters()
	attempt, _, decline := peerTCPExchange(ctx, port, state.tcpEcho, target, []int{32}, false, trace, "negative")
	receipt["negativeAttemptTCP"] = attempt
	var netFailure net.Error
	failed := errors.Is(decline, io.EOF) || errors.Is(decline, io.ErrUnexpectedEOF) ||
		errors.Is(decline, errPeerSOCKSRejected) || errors.As(decline, &netFailure)
	time.Sleep(250 * time.Millisecond)
	if !failed || state.fixture.counters() != baseline {
		return &peerDiagnosticError{"RuntimeError", "negative reached echo or did not reject"}
	}
	clientLog, err := readPeerLog(client.log.Name())
	if err != nil {
		return err
	}
	peerLog, err := readPeerLog(peer.log.Name())
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(peerLog, peerBefore) {
		receipt["identityUncertain"] = true
		return &peerDiagnosticError{"IdentityFailure", "negative evidence window is unavailable"}
	}
	negative, err := observePeerRejection(protocol, *mutation, clientLog, peerLog, len(peerBefore))
	if err != nil {
		return err
	}
	negative["peerIdentity"] = map[string]any{"pid": peer.identity.PID, "startTicks": peer.identity.StartTicks, "coreSHA256": peer.core}
	negative["peerWindowBeforeSHA256"] = sha256Hex(peerBefore)
	negative["tcpAcceptDelta"], negative["tcpByteDelta"], negative["udpNegativeAttempted"] = 0, 0, false
	receipt["negative"] = negative
	if protocol.masque() {
		nonce, err := peerNegativeUDP(ctx, port, state.udpEcho, target, trace)
		if err != nil {
			return err
		}
		negative["udpNegativeAttempted"], negative["udpNonceSHA256"] = true, nonce
	}
	if err := state.prepareRelayRetirement(); err != nil {
		return err
	}
	if _, err := state.closeOwner(client); err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	if state.fixture.counters() != baseline {
		return &peerDiagnosticError{"RuntimeError", "negative late fallback reached echo before complete retirement"}
	}
	negative["afterCompleteClientRetirementZeroEchoDelta"] = true
	return state.fixture.error()
}

func (state *peerCase) clientPeerPort() int {
	if state.relay != nil {
		return state.relay.port
	}
	return state.peerPort
}

func (state *peerCase) startRelay() error {
	relay, err := startPeerRelay(state.peerPort)
	if err != nil {
		return err
	}
	state.relay, state.relayClosed = relay, false
	state.reservedTCP, _, err = peerBoundSocket(unix.SOCK_STREAM, relay.port)
	return err
}

func (state *peerCase) prepareRelayRetirement() error {
	if state.relay == nil || state.relayClosed {
		return nil
	}
	if err := state.relay.prepareRetirement(); err != nil {
		state.receipt["identityUncertain"] = true
		identity := &peerDiagnosticError{"IdentityFailure", "UDP observer owner retirement identity unknown"}
		revokeErr := state.relay.revokeSockets()
		return errors.Join(identity, revokeErr, state.closeRelay())
	}
	return nil
}

func (state *peerCase) closeRelay() error {
	if state.relay == nil || state.relayClosed {
		return nil
	}
	observation, err := state.relay.close(3 * time.Second)
	state.relayClosed = true
	recorded, _ := state.receipt["udpObservers"].([]any)
	state.receipt["udpObservers"] = append(recorded, observation)
	if state.reservedTCP >= 0 {
		err = errors.Join(err, unix.Close(state.reservedTCP))
		state.reservedTCP = -1
	}
	previous, _ := state.receipt["observerCleanupErrors"].([]string)
	if previous == nil {
		previous = []string{}
	}
	state.receipt["observerCleanupErrors"] = previous
	if err != nil {
		state.receipt["observerCleanupErrors"] = append(previous, "UDP observer close or transport failed")
		return &peerDiagnosticError{"RuntimeError", "UDP observer first epoch retirement failed"}
	}
	return nil
}

func (state *peerCase) h3OnlyCarrier(config map[string]any) (map[string]any, error) {
	inbound := config["inbounds"].([]map[string]any)[0]
	tls := inbound["tls"].(map[string]any)
	if inbound["type"] != "naive" || inbound["network"] != "udp" || inbound["listen"] != peerLoopback ||
		!reflect.DeepEqual(tls["alpn"], []string{"h3"}) {
		return nil, &peerDiagnosticError{"RuntimeError", "controlled Naive H3 peer is not the exact H3-only listener"}
	}
	address, err := unix.Getsockname(state.reservedTCP)
	actual, _ := address.(*unix.SockaddrInet4)
	listening, optErr := unix.GetsockoptInt(state.reservedTCP, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	counts := state.relay.datagrams()
	if err != nil || optErr != nil || actual == nil || actual.Port != state.relay.port || actual.Addr != peerLoopbackIP ||
		listening != 0 || counts[0] == 0 || counts[1] == 0 {
		return nil, &peerDiagnosticError{"RuntimeError", "controlled Naive H3 fallback block or two-way QUIC carrier not proven"}
	}
	return map[string]any{"listenerNetwork": "udp", "serverALPN": []string{"h3"}, "tcpFallbackBoundNonListening": true, "carrierDatagrams": counts}, nil
}

func (state *peerCase) retire() {
	receipt := state.receipt
	if state.oldStream != nil {
		state.oldStream.Close()
	}
	counters := peerEchoCounters{}
	if state.fixture != nil {
		counters = state.fixture.counters()
	}
	receipt["echoCounters"], receipt["carrierDatagrams"] = counters, nil
	if state.relay != nil {
		receipt["carrierDatagrams"] = state.relay.datagrams()
	}
	if state.configs == nil {
		state.configs = []map[string]any{}
	}
	receipt["configs"] = state.configs
	observation := make(map[string]map[string]any, len(state.privateLogs))

	cleanup := []any{}
	prepareErr := state.prepareRelayRetirement()
	cleanupErrors, _ := receipt["observerCleanupErrors"].([]string)
	if prepareErr != nil {
		cleanupErrors = append(cleanupErrors, "UDP observer owner retirement identity unknown")
	}
	closeOwner := func(owner *peerNativeProcess) {
		result, err := state.closeOwner(owner)
		if err != nil {
			cleanupErrors = append(cleanupErrors, "RuntimeError: core graceful cleanup not proven")
		}
		var log any = map[string]any{"unavailable": true}
		if raw, err := readPeerLog(owner.log.Name()); err == nil {
			fact := safePeerLog(raw, state.sourceRoot)
			observation[filepath.Base(owner.log.Name())] = fact
			log = fact
		}
		cleanup = append(cleanup, struct {
			*peerProcessCleanup
			SafeLog any `json:"safeLog"`
		}{result, log})
	}
	for i := len(state.owners) - 1; i >= 0; i-- {
		if owner := state.owners[i]; owner.role != "peer" {
			closeOwner(owner)
		}
	}
	if err := state.closeRelay(); err != nil {
		cleanupErrors = append(cleanupErrors, "UDP observer close or transport failed")
	}
	for _, owner := range state.owners {
		if owner.role == "peer" {
			closeOwner(owner)
		}
	}
	receipt["cleanup"] = cleanup
	retirement, err := state.scope.drain()
	if err != nil {
		cleanupErrors = append(cleanupErrors, "owned descendant cleanup unknown")
	} else if len(retirement.Retired) != 0 || retirement.ForcedKill {
		cleanupErrors = append(cleanupErrors, "owned descendants required recovery; graceful cleanup failed")
	}
	receipt["descendantRetirement"] = retirement
	if state.fixture != nil {
		if err := state.fixture.close(); err != nil {
			cleanupErrors = append(cleanupErrors, "RuntimeError: echo worker did not join")
		}
		counters = state.fixture.counters()
	}
	receipt["fixturesJoined"] = len(cleanupErrors) == 0
	receipt["echoCountersAfterRetirement"], receipt["carrierDatagramsAfterRetirement"] = counters, nil
	if state.relay != nil {
		receipt["carrierDatagramsAfterRetirement"] = state.relay.datagrams()
	}
	ports := []map[string]any{}
	type portEvidence struct {
		port int
		udp  bool
	}
	var candidates []portEvidence
	for _, port := range state.ports {
		candidates = append(candidates, portEvidence{port, false})
	}
	if state.fixture != nil {
		candidates = append(candidates, portEvidence{state.tcpEcho, false}, portEvidence{state.udpEcho, true})
	}
	if state.relay != nil {
		candidates = append(candidates, portEvidence{state.relay.port, true})
	}
	if state.peerPort != 0 {
		candidates = append(candidates, portEvidence{state.peerPort, state.protocol.udp()})
	}
	for _, candidate := range candidates {
		fact, err := peerReleased(candidate.port, candidate.udp)
		if err != nil {
			cleanupErrors = append(cleanupErrors, "owned listening port not released")
			break
		}
		ports = append(ports, fact)
	}
	receipt["portsReleased"] = ports
	privateLogs := []map[string]any{}
	for _, name := range state.privateLogs {
		fact := observation[name]
		if fact == nil {
			raw, err := readPeerLog(filepath.Join(state.directory, name))
			if err != nil {
				cleanupErrors = append(cleanupErrors, "private log observation unavailable")
				continue
			}
			fact = safePeerLog(raw, state.sourceRoot)
		}
		copied := maps.Clone(fact)
		copied["name"] = name
		privateLogs = append(privateLogs, copied)
	}
	receipt["privateLogs"] = privateLogs
	if len(cleanupErrors) != 0 {
		receipt["status"], receipt["cleanupErrors"] = "FAIL", cleanupErrors
	}
	markIncomplete := func(facts []map[string]any) {
		for _, fact := range facts {
			if fact["status"] == "RUNNING" {
				fact["status"] = "INCOMPLETE_AT_CASE_RETIREMENT"
			}
		}
	}
	markIncomplete(state.trace.events)
	for _, name := range []string{"healthyTCP", "applicationUDP", "freshProcessTCP", "negativeAttemptTCP"} {
		facts, _ := receipt[name].([]map[string]any)
		markIncomplete(facts)
	}
	if exchanges, ok := receipt["concurrentTCP"].([][]map[string]any); ok {
		for _, facts := range exchanges {
			markIncomplete(facts)
		}
	}
	receipt["events"] = state.trace.events
	receipt["continuationSafe"] = receipt["identityUncertain"] == false && len(cleanupErrors) == 0 && len(ports) != 0 && len(retirement.Remaining) == 0
}
