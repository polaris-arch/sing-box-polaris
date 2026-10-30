//go:build with_naive_outbound && with_purego && linux && !android

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These controlled ELF libraries exercise actual dlopen, symbol registration,
// Engine.Version/Destroy and the real command. They are not native Cronet
// acceptance or protected producer receipts for a released payload.
func TestCronetCommandReportsTheObjectItActuallyExecutes(t *testing.T) {
	a := buildCronetDiagnosticELF(t, "A")
	b := buildCronetDiagnosticELF(t, "B")
	aBytes, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bBytes, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	aHash, bHash := fmt.Sprintf("%x", sha256.Sum256(aBytes)), fmt.Sprintf("%x", sha256.Sum256(bBytes))
	if aHash == bHash {
		t.Fatal("same-version controlled objects must have different bytes")
	}
	fd, err := unix.MemfdCreate("cronet-command-B", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	selected := os.NewFile(uintptr(fd), "cronet-command-B")
	defer selected.Close()
	if _, err := selected.Write(bBytes); err != nil {
		t.Fatal(err)
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(selected.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, selector, library, hash, selection, marker, wantError string
		selected, reuseIncoming                                     bool
	}{
		{name: "standalone-path", library: a, hash: aHash, selection: "standalone-path", marker: "A"},
		{name: "selected-owned-object", selected: true, selector: "3", hash: bHash, selection: "captured-sealed-fd", marker: "B"},
		{name: "selected-proc-path", selected: true, selector: "3", library: "/proc/self/fd/3", hash: bHash, selection: "captured-sealed-fd", marker: "B"},
		{name: "selected-after-incoming-reuse", selected: true, selector: "3", hash: bHash, selection: "captured-sealed-fd", marker: "B", reuseIncoming: true},
		{name: "same-version-foreign-object", selected: true, selector: "3", library: a, hash: aHash, wantError: "conflicts with the captured sealed object"},
		{name: "foreign-path-correct-selected-hash", selected: true, selector: "3", library: a, hash: bHash, wantError: "conflicts with the captured sealed object"},
		{name: "wrong-selected-hash", selected: true, selector: "3", hash: aHash, wantError: "captured library SHA-256 mismatch"},
		{name: "empty-selector-no-fallback", selected: true, library: a, hash: aHash, wantError: "explicit sealed library FD rejected"},
		{name: "closed-selector-no-fallback", selected: true, selector: "999999", library: a, hash: aHash, wantError: "explicit sealed library FD rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "destroyed")
			args := []string{"tools", "cronet", "--sha256", test.hash, "--expected-version", "diagnostic-cronet-v1"}
			if test.library != "" {
				args = append(args, "--library", test.library)
			}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCronetCommandProcess$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "POLARIS_CRONET_") && !strings.HasPrefix(value, "POLARIS_CORE_STORE_LEASE_FD=") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "POLARIS_CRONET_COMMAND_PROBE="+string(encoded), "POLARIS_CRONET_DESTROY_MARKER="+marker)
			if test.selected {
				command.ExtraFiles = []*os.File{selected}
				command.Env = append(command.Env, "POLARIS_CRONET_LIBRARY_FD="+test.selector)
			}
			if test.reuseIncoming {
				command.Env = append(command.Env, "POLARIS_CRONET_REUSE_INCOMING="+a)
			}
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("controlled command did not join", ctx.Err())
			}
			actualMarker, markerErr := os.ReadFile(marker)
			if test.wantError != "" {
				if err == nil || !os.IsNotExist(markerErr) || !strings.Contains(string(output), test.wantError) {
					t.Fatalf("mismatched/invalid selection executed an engine: %v %q %s", err, actualMarker, output)
				}
				if strings.Contains(string(output), `"version":`) {
					t.Fatalf("failed pairing emitted successful identity: %s", output)
				}
				return
			}
			if err != nil || markerErr != nil || string(actualMarker) != test.marker {
				t.Fatalf("Version/Destroy did not use the expected object: %v %v %q %s", err, markerErr, actualMarker, output)
			}
			var result struct {
				Library          string `json:"library"`
				SHA256           string `json:"sha256"`
				LibraryBytes     int64  `json:"libraryBytes"`
				LibrarySelection string `json:"librarySelection"`
				Version          string `json:"version"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("command did not emit one JSON identity: %v %s", err, output)
			}
			size := len(aBytes)
			if test.selected {
				size = len(bBytes)
				if !strings.HasPrefix(result.Library, "/proc/self/fd/") {
					t.Fatal("selected diagnostic reported a normal path", result)
				}
			} else if result.Library != a {
				t.Fatal("standalone diagnostic lost its path", result)
			}
			if result.SHA256 != test.hash || result.LibraryBytes != int64(size) || result.LibrarySelection != test.selection || result.Version != "diagnostic-cronet-v1" {
				t.Fatalf("command reported identity other than its executed object: %+v", result)
			}
		})
	}
}

func TestCronetCommandProcess(t *testing.T) {
	value := os.Getenv("POLARIS_CRONET_COMMAND_PROBE")
	if value == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(value), &args); err != nil {
		t.Fatal(err)
	}
	var replacement *os.File
	if path := os.Getenv("POLARIS_CRONET_REUSE_INCOMING"); path != "" {
		if err := unix.Close(3); err != nil {
			t.Fatal(err)
		}
		var err error
		replacement, err = os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if replacement.Fd() != 3 {
			if err := unix.Dup3(int(replacement.Fd()), 3, unix.O_CLOEXEC); err != nil {
				t.Fatal(err)
			}
		}
		runtime.GC()
	}
	mainCommand.SetArgs(args)
	mainCommand.SetOut(os.Stdout)
	mainCommand.SetErr(os.Stderr)
	err := mainCommand.Execute()
	runtime.KeepAlive(replacement)
	if err != nil {
		os.Exit(2)
	}
	// The command's deferred Engine.Destroy has completed before Execute returns.
	// Suppress the test driver's PASS text so stdout is the actual CLI JSON.
	os.Exit(0)
}

func buildCronetDiagnosticELF(t *testing.T, identity string) string {
	t.Helper()
	registry, err := os.ReadFile(filepath.Join("..", "..", "third_party", "cronet-go", "internal", "cronet", "loader_unix.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Include the complete registry, including bidirectional_stream exports;
	// do not duplicate a maintained ABI list in the controlled ELF fixture.
	exports := regexp.MustCompile(`registerFunc\([^\n]+, "([A-Za-z_][A-Za-z0-9_]*)"\)`).FindAllSubmatch(registry, -1)
	if len(exports) == 0 {
		t.Fatal("controlled library has no symbol registry")
	}
	var source strings.Builder
	source.WriteString("#include <stdio.h>\n#include <stdlib.h>\n")
	seen := make(map[string]bool)
	for _, match := range exports {
		name := string(match[1])
		if seen[name] {
			continue
		}
		seen[name] = true
		switch name {
		case "Cronet_Engine_Create":
			source.WriteString("void *Cronet_Engine_Create(void) { return malloc(1); }\n")
		case "Cronet_Engine_GetVersionString":
			source.WriteString("const char *Cronet_Engine_GetVersionString(void *p) { return \"diagnostic-cronet-v1\"; }\n")
		case "Cronet_Engine_Destroy":
			source.WriteString("void Cronet_Engine_Destroy(void *p) { const char *m = getenv(\"POLARIS_CRONET_DESTROY_MARKER\"); FILE *f = m ? fopen(m, \"a\") : NULL; if (f) { fputs(" + strconv.Quote(identity) + ", f); fclose(f); } free(p); }\n")
		default:
			source.WriteString("void " + name + "(void) {}\n")
		}
	}
	path := filepath.Join(t.TempDir(), "libdiagnostic-"+identity+".so")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "cc", "-shared", "-fPIC", "-x", "c", "-", "-o", path)
	command.Stdin = strings.NewReader(source.String())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile controlled ELF (not native acceptance): %v %s", err, output)
	}
	return path
}
