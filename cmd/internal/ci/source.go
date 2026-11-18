package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var sourceCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

type indexEntry struct {
	Mode string `json:"mode"`
	Blob string `json:"gitBlob"`
}

func gitObjectHash(kind string, data []byte) string {
	// Git blob/tree identities use this repository's SHA-1 object format.
	hash := sha1.New()
	fmt.Fprintf(hash, "%s %d\x00", kind, len(data))
	hash.Write(data)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func gitTreeHash(entries map[string]indexEntry) (string, error) {
	order := func(name string) string {
		if entries[name].Mode == "40000" {
			return name + "/"
		}
		return name
	}
	names := slices.SortedFunc(maps.Keys(entries), func(left, right string) int {
		return strings.Compare(order(left), order(right))
	})
	var raw bytes.Buffer
	for _, name := range names {
		entry := entries[name]
		oid, err := hex.DecodeString(entry.Blob)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&raw, "%s %s\x00", entry.Mode, name)
		raw.Write(oid)
	}
	return gitObjectHash("tree", raw.Bytes()), nil
}

func sha256Hex(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func fileSHA256(filename string) (string, error) {
	input, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer input.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, input); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func pinnedGoVersion(root string, env []string) (string, error) {
	return sourceGoVersion(context.Background(), root, env)
}

func sourceGoVersion(parent context.Context, root string, env []string) (string, error) {
	version, err := os.ReadFile(filepath.Join(root, "release/GO_VERSION"))
	if err != nil {
		return "", err
	}
	actual, err := sourceGoEnvironment(parent, root, env, "GOVERSION")
	if err != nil {
		return "", err
	}
	required := "go" + strings.TrimSpace(string(version))
	if actual[0] != required {
		return "", fmt.Errorf("source gates require pinned %s", required)
	}
	return required, nil
}

func sourceGoEnvironment(parent context.Context, root string, env []string, keys ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	args := append([]string{"go", "env"}, keys...)
	output, _, code, err := sourceCommandOutput(ctx, root, env, 16384, args...)
	if err != nil {
		return nil, err
	}
	values := strings.Split(strings.TrimSpace(output), "\n")
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
	}
	if code == nil || *code != 0 || len(values) != len(keys) {
		return nil, fmt.Errorf("source Go environment query failed")
	}
	return values, nil
}

func checkedRelative(name string) bool {
	return name != "" && utf8.ValidString(name) && !path.IsAbs(name) && path.Clean(name) == name &&
		name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00\r\n")
}

func trackedIndex(root string) (map[string]indexEntry, error) {
	read := func(args ...string) ([]byte, error) {
		command := exec.Command("git", args...)
		command.Dir = root
		var output, diagnostics bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostics
		if err := command.Run(); err != nil || diagnostics.Len() != 0 {
			return nil, fmt.Errorf("cannot establish tracked source index: %v", err)
		}
		return output.Bytes(), nil
	}
	top, err := read("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	actual, err := filepath.EvalSymlinks(strings.TrimSuffix(string(top), "\n"))
	if err != nil {
		return nil, err
	}
	expected, err := filepath.EvalSymlinks(root)
	if err != nil || actual != expected {
		return nil, fmt.Errorf("tracked source root differs")
	}
	data, err := read("ls-files", "--stage", "-z")
	if err != nil || !bytes.HasSuffix(data, []byte{0}) {
		return nil, fmt.Errorf("cannot establish tracked source index: %v", err)
	}
	entries := map[string]indexEntry{}
	for _, record := range bytes.Split(data, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, filename, found := bytes.Cut(record, []byte{'\t'})
		fields := strings.Split(string(header), " ")
		name := string(filename)
		if !found || len(fields) != 3 || !checkedRelative(name) || fields[2] != "0" || !sourceCommit.MatchString(fields[1]) {
			return nil, fmt.Errorf("invalid tracked index record")
		}
		switch fields[0] {
		case "100644", "100755", "120000", "160000":
		default:
			return nil, fmt.Errorf("invalid tracked index mode: %s", name)
		}
		if _, found := entries[name]; found {
			return nil, fmt.Errorf("conflicting tracked index path: %s", name)
		}
		entries[name] = indexEntry{fields[0], fields[1]}
	}
	if _, found := entries["go.mod"]; !found {
		return nil, fmt.Errorf("missing tracked root module")
	}
	return entries, nil
}

func regularSource(root, name string) (string, error) {
	if !checkedRelative(name) {
		return "", fmt.Errorf("invalid owned source path: %s", name)
	}
	for current := name; current != "."; current = path.Dir(current) {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(current)))
		if err != nil || redirectedSource(info) || current == name && !info.Mode().IsRegular() {
			return "", fmt.Errorf("missing or unsafe owned source: %s", name)
		}
	}
	return filepath.Join(root, filepath.FromSlash(name)), nil
}
