package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
)

var peerNativeProtocol = regexp.MustCompile(`(?m)response received, protocol: ([^,\r\n]{1,64}), status: ([0-9]{3})[ \t]*\r?$`)

func observePeerNativeProtocol(raw []byte, expected string) map[string]any {
	observed, unknown, success := [][]any{}, 0, false
	for _, item := range peerNativeProtocol.FindAllSubmatch(raw, -1) {
		protocol := string(item[1])
		status, _ := strconv.Atoi(string(item[2]))
		if protocol != "h2" && protocol != "quic/1+spdy/3" || status < 100 || status > 599 {
			unknown++
			continue
		}
		observed = append(observed, []any{protocol, status})
		success = success || protocol == expected && status == 200
	}
	return map[string]any{
		"expectedNativeCallbackProtocol": expected, "observedAllowlistedProtocolAndStatus": observed,
		"unrecognizedObservationCount": unknown, "successfulExpectedProtocolObserved": success,
		"privateRawLogSHA256": sha256Hex(raw), "privateRawLogBytes": len(raw),
	}
}

var peerRejections = map[string]*regexp.Regexp{
	"wrong-auth": regexp.MustCompile(`(?i)authorization failed|authentication required|status: 407|407 Proxy Authentication`),
	"wrong-ca":   regexp.MustCompile(`(?i)ERR_CERT_AUTHORITY_INVALID|cert authority invalid|certificate signed by unknown authority|unknown certificate authority`),
	"wrong-sni":  regexp.MustCompile(`(?i)ERR_CERT_COMMON_NAME_INVALID|cert common name invalid|certificate is valid for controlled\.invalid(?:, 127\.0\.0\.1)?, not wrong\.invalid`),
	"wrong-path": regexp.MustCompile(`(?i)unexpected path: /wrong-ip/|unexpected status: 404`),
}

var peerMasqueAuthRejection = regexp.MustCompile(`(?i)authentication failed: (?:username=|missing or malformed)|unexpected status: 401`)

func observePeerRejection(protocol peerProtocol, mutation string, client, peer []byte, peerOffset int) (map[string]any, error) {
	matcher := peerRejections[mutation]
	if mutation == "wrong-auth" && protocol.masque() {
		matcher = peerMasqueAuthRejection
	}
	if matcher == nil || peerOffset > len(peer) {
		return nil, &peerDiagnosticError{"RuntimeError", "negative evidence window is unavailable"}
	}
	for _, log := range []struct {
		role   string
		raw    []byte
		offset int
	}{{"client", client, 0}, {"peer", peer, peerOffset}} {
		index := matcher.FindIndex(log.raw[log.offset:])
		if index == nil {
			continue
		}
		start, end := log.offset+index[0], log.offset+index[1]
		if end-start > 256 {
			return nil, &peerDiagnosticError{"RuntimeError", "rejection evidence fragment exceeded bound"}
		}
		return map[string]any{
			"category": mutation, "specificRejectionObserved": true, "logRole": log.role,
			"privateRawLogSHA256": sha256Hex(log.raw), "privateRawLogBytes": len(log.raw), "windowStartByte": log.offset,
			"byteOffset": start, "matchedAllowlistedFragment": string(log.raw[start:end]),
			"matcher": strings.TrimPrefix(matcher.String(), "(?i)"),
		}, nil
	}
	return nil, &peerDiagnosticError{"RuntimeError", "negative lacks actual peer TLS/auth/path rejection evidence"}
}

var peerLogCategories = []struct{ name, text string }{
	{"go_nil_pointer", "panic: runtime error: invalid memory address or nil pointer dereference"},
	{"go_index_bounds", "panic: runtime error: index out of range"},
	{"go_slice_bounds", "panic: runtime error: slice bounds out of range"},
	{"go_concurrent_map", "fatal error: concurrent map writes"},
	{"go_deadlock", "fatal error: all goroutines are asleep - deadlock!"},
	{"native_close_incomplete", "sing-box did not closed properly"},
	{"runtime_graph_cleanup_incomplete", "runtime resource cleanup remains unconfirmed"},
	{"close_observer_deadline", "context deadline exceeded"},
	{"close_context_canceled", "context canceled"},
	{"runtime_reference_cleanup_incomplete", "runtime reference observer cleanup incomplete"},
	{"runtime_owned_cleanup_incomplete", "completion unknown"},
	{"runtime_device_close_incomplete", "device shutdown did not complete"},
	{"runtime_scope_close_panic", "panic during close:"},
	{"runtime_owner_close_panic", "panic during close:"},
	{"cleanup_snapshot_encoding_unavailable", "runtime cleanup snapshot encoding unavailable"},
	{"native_close_timeout", "sing-box did not close!"},
	{"tls_unknown_ca", "certificate signed by unknown authority"},
	{"http_auth407", "status: 407"},
	{"http_auth401", "unexpected status: 401"},
	{"http_path404", "unexpected status: 404"},
	{"quic_idle_timeout", "timeout: no recent network activity"},
	{"connection_refused", "connection refused"},
	{"connection_reset", "connection reset by peer"},
}

var (
	peerCronetCategory = regexp.MustCompile(`\{NetError\w+, "(ERR_[A-Z0-9_]+)", "([a-z0-9 -]+)"`)
	peerPanicMarker    = regexp.MustCompile(`(?m)^panic:`)
	peerFatalMarker    = regexp.MustCompile(`(?m)^fatal error:`)
	peerFrameTypeArgs  = regexp.MustCompile(`\[[^\[\]\r\n]*\]`)
	peerFrameName      = regexp.MustCompile(`^(github\.com/[A-Za-z0-9_./-]+\.(?:(?:\(\*?[A-Za-z_]\w*(?:\[[^\[\]\r\n]*\])?\)|[A-Za-z_]\w*(?:\[[^\[\]\r\n]*\])?)\.)?[A-Za-z_]\w*(?:\[[^\[\]\r\n]*\])?(?:\.func\d+)*)\(`)
	peerFramePath      = regexp.MustCompile(`^\s+[^\r\n]*[/\\]([A-Za-z_][A-Za-z0-9_]*\.go):(\d+)(?:\s+\+0x[0-9a-f]+)?$`)
	peerFrameClosure   = regexp.MustCompile(`(?:\.func\d+)+$`)
)

func peerFixedCategory(raw, text []byte) int {
	if len(text) < 8 {
		return -1
	}
	for from := 0; from < len(raw); {
		at := bytes.Index(raw[from:], text)
		if at < 0 {
			return -1
		}
		at += from
		end := at + len(text)
		left := at == 0 || !bytes.ContainsRune([]byte("abcdefghijklmnopqrstuvwxyz0123456789_"), rune(raw[at-1]))
		right := end == len(raw) || bytes.ContainsRune([]byte("\r\n.,;:)"), rune(raw[end])) || bytes.HasPrefix(raw[end:], []byte(" ("))
		if left && right {
			return at
		}
		from = at + 1
	}
	return -1
}

func readPeerLog(path string) ([]byte, error) {
	return readNativeSource(filepath.Dir(path), filepath.Base(path))
}

func peerASCIILower(raw []byte) []byte {
	lower := bytes.Clone(raw)
	for index, c := range lower {
		if 'A' <= c && c <= 'Z' {
			lower[index] = c + ('a' - 'A')
		}
	}
	return lower
}

func safePeerLog(raw []byte, root string) map[string]any {
	categories := []map[string]any{}
	lower := peerASCIILower(raw)
	for _, category := range peerLogCategories {
		if offset := bytes.Index(lower, []byte(category.text)); offset >= 0 {
			categories = append(categories, map[string]any{"category": category.name, "byteOffset": offset})
		}
	}
	if source, err := os.ReadFile(filepath.Join(root, "third_party/cronet-go/net_error_generated.go")); err == nil {
		for _, category := range peerCronetCategory.FindAllSubmatch(source, -1) {
			for _, text := range category[1:] {
				if offset := peerFixedCategory(lower, peerASCIILower(text)); offset >= 0 {
					categories = append(categories, map[string]any{"category": string(category[1]), "byteOffset": offset})
					break
				}
			}
		}
	}
	panicMarker, fatalMarker := peerPanicMarker.Match(raw), peerFatalMarker.Match(raw)
	frames := []map[string]any{}
	if panicMarker || fatalMarker {
		frames = safePeerFrames(raw, root)
	}
	snapshots, rejected := peerCleanupSnapshots(raw)
	return map[string]any{
		"sha256": sha256Hex(raw), "bytes": len(raw), "categories": categories, "goFrames": frames,
		"panicMarker": panicMarker, "fatalMarker": fatalMarker, "cleanupSnapshots": snapshots,
		"cleanupSnapshotsRejected": rejected, "unknownTextRetained": false,
	}
}

func safePeerFrames(raw []byte, root string) []map[string]any {
	type candidate struct {
		symbol, name, file string
		line               int
	}
	found := []map[string]any{}
	var candidates []candidate
	var current string
	for line := range bytes.SplitSeq(raw, []byte{10}) {
		if match := peerFrameName.FindSubmatch(line); match != nil {
			current = peerFrameTypeArgs.ReplaceAllString(string(match[1]), "")
			if len(current) <= 192 {
				continue
			}
			current = ""
		}
		if match := peerFramePath.FindSubmatch(line); match != nil && current != "" {
			if number, err := strconv.Atoi(string(match[2])); err == nil {
				candidates = append(candidates, candidate{current, peerFrameClosure.ReplaceAllString(current, ""), string(match[1]), number})
			}
		}
		current = ""
	}
	if len(candidates) == 0 {
		return found
	}
	names := map[[2]string]bool{}
	modules := map[string]string{}
	basenames := map[string]bool{}
	var paths []string
	for _, item := range candidates {
		names[[2]string{item.name, item.file}] = false
		basenames[item.file] = true
	}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if entry.Name() == "go.mod" {
			if data, err := os.ReadFile(path); err == nil {
				modules[filepath.Dir(path)] = modfile.ModulePath(data)
			}
		}
		if basenames[entry.Name()] {
			paths = append(paths, path)
		}
		return nil
	})
	for _, path := range paths {
		directory := filepath.Dir(path)
		module := ""
		for parent := directory; ; parent = filepath.Dir(parent) {
			if name := modules[parent]; name != "" {
				module = name
				if relative, err := filepath.Rel(parent, directory); err == nil && relative != "." {
					module += "/" + filepath.ToSlash(relative)
				}
				break
			}
			if parent == root || parent == filepath.Dir(parent) {
				break
			}
		}
		if module == "" {
			continue
		}
		source, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, node := range source.Decls {
			function, ok := node.(*ast.FuncDecl)
			if !ok {
				continue
			}
			verify := func(symbol string) {
				key := [2]string{symbol, filepath.Base(path)}
				if _, wanted := names[key]; wanted {
					names[key] = true
				}
			}
			if function.Recv == nil {
				verify(module + "." + function.Name.Name)
				continue
			}
			if len(function.Recv.List) != 1 {
				continue
			}
			receiver := ast.Unparen(function.Recv.List[0].Type)
			prefix := ""
			if pointer, ok := receiver.(*ast.StarExpr); ok {
				prefix = "*"
				receiver = ast.Unparen(pointer.X)
			}
			switch generic := receiver.(type) {
			case *ast.IndexExpr:
				receiver = ast.Unparen(generic.X)
			case *ast.IndexListExpr:
				receiver = ast.Unparen(generic.X)
			}
			name, ok := receiver.(*ast.Ident)
			if !ok {
				continue
			}
			verify(module + ".(" + prefix + name.Name + ")." + function.Name.Name)
			if prefix == "" {
				verify(module + "." + name.Name + "." + function.Name.Name)
			}
		}
	}
	for _, item := range candidates {
		if names[[2]string{item.name, item.file}] {
			found = append(found, map[string]any{"symbol": item.symbol, "file": item.file, "line": item.line})
			if len(found) == 48 {
				break
			}
		}
	}
	return found
}

func peerCleanupSnapshots(raw []byte) ([]map[string]any, int) {
	observations, rejected := []map[string]any{}, 0
	for line := range bytes.SplitSeq(raw, []byte{10}) {
		_, data, found := bytes.Cut(line, []byte("runtime cleanup snapshot: "))
		if !found {
			continue
		}
		var value map[string]any
		if len(data) > 16384 || len(observations) >= 4 ||
			uniqueJSON(bytes.NewReader(data), &value) != nil || !validPeerCleanupSnapshot(value) {
			rejected++
			continue
		}
		observations = append(observations, value)
	}
	return observations, min(rejected, 1_000_000)
}

func validPeerCleanupSnapshot(value map[string]any) bool {
	object := func(raw any, keys string) (map[string]any, bool) {
		v, _ := raw.(map[string]any)
		columns := strings.Fields(keys)
		if len(v) != len(columns) {
			return nil, false
		}
		for _, key := range columns {
			if _, ok := v[key]; !ok {
				return nil, false
			}
		}
		return v, true
	}
	count := func(raw any, maximum int64) bool {
		number, ok := raw.(json.Number)
		parsed, err := number.Int64()
		return ok && err == nil && parsed >= 0 && parsed <= maximum
	}
	flags := func(record map[string]any, keys string) bool {
		for _, key := range strings.Fields(keys) {
			if _, ok := record[key].(bool); !ok {
				return false
			}
		}
		return true
	}
	counts := func(record map[string]any, keys string) bool {
		for _, key := range strings.Fields(keys) {
			if !count(record[key], 1_000_000) {
				return false
			}
		}
		return true
	}
	if _, ok := object(value, "schema atomic available preparing phase done failed truncated resourceCount resources connections reference"); !ok ||
		value["schema"] != "runtime-cleanup-v1" || value["atomic"] != false ||
		!flags(value, "available preparing done failed truncated") || !count(value["phase"], 8) || !count(value["resourceCount"], 1_000_000) {
		return false
	}
	resources, _ := value["resources"].([]any)
	if len(resources) != 10 {
		return false
	}
	for _, raw := range resources {
		item, ok := object(raw, "owners unavailable states references dependencies endpointPhases endpointFailures ownerFailures")
		if !ok || !counts(item, "owners unavailable references dependencies endpointFailures ownerFailures") {
			return false
		}
		for key, length := range map[string]int{"states": 4, "endpointPhases": 8} {
			array, _ := item[key].([]any)
			if len(array) != length {
				return false
			}
			for _, raw := range array {
				if !count(raw, 1_000_000) {
					return false
				}
			}
		}
	}
	connections, ok := object(value["connections"], "available closed tasks physical")
	if !ok || !flags(connections, "available closed") || !counts(connections, "tasks physical") {
		return false
	}
	reference, ok := object(value["reference"], "available started stopping busy pauses quarantined failed setupDone workerDone stoppedDone")
	return ok && flags(reference, "available started stopping busy failed setupDone workerDone stoppedDone") &&
		counts(reference, "pauses quarantined")
}
