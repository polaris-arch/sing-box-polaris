package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestCronetOverlayColdSource(t *testing.T) {
	checkout := "../../.."
	vendor := os.DirFS(filepath.Join(checkout, cronetVendor))
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, cronetVendor), vendor); err != nil {
		t.Fatal(err)
	}
	read := func(root, name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	materials := append(slices.Sorted(maps.Keys(cronetHistory)), cronetOverlayManifest, cronetOverlayPatch)
	for _, name := range materials {
		fixtureFile(t, root, name, string(read(checkout, name)))
	}
	t.Setenv("PATH", t.TempDir())
	inputs, err := validateCronetOverlay(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]string)
	err = filepath.WalkDir(filepath.Join(root, cronetVendor), func(filename string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		name, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		materials = append(materials, filepath.ToSlash(name))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range materials {
		expected[name] = sha256Hex(read(root, name))
	}
	if !maps.Equal(inputs, expected) {
		t.Fatal("provenance omits or changes validated source data")
	}

	original := read(root, cronetOverlayManifest)
	patch := read(root, cronetOverlayPatch)
	changeAt := func(doc map[string]any, i int) map[string]any {
		return doc["changes"].([]any)[i].(map[string]any)
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema":            func(m map[string]any) { m["schema"] = "future" },
		"unknown-key":       func(m map[string]any) { m["extra"] = true },
		"binary-claim":      func(m map[string]any) { m["nativeBinaryValidated"] = true },
		"context-boolean":   func(m map[string]any) { m["patchContextLines"] = false },
		"baseline":          func(m map[string]any) { m["baseTree"] = strings.Repeat("f", 40) },
		"replacement-path":  func(m map[string]any) { m["replacementPath"] = "../elsewhere" },
		"base-count":        func(m map[string]any) { m["baseFiles"] = m["baseFiles"].([]any)[1:] },
		"delta-count":       func(m map[string]any) { m["changes"] = m["changes"].([]any)[1:] },
		"duplicate-base":    func(m map[string]any) { m["baseFiles"].([]any)[0] = m["baseFiles"].([]any)[1] },
		"record-path":       func(m map[string]any) { changeAt(m, 0)["after"].(map[string]any)["path"] = "../escape" },
		"operation":         func(m map[string]any) { changeAt(m, 0)["operation"] = "add" },
		"size-type":         func(m map[string]any) { m["baseFiles"].([]any)[0].(map[string]any)["bytes"] = true },
		"file-type":         func(m map[string]any) { m["baseFiles"].([]any)[0].(map[string]any)["mode"] = "120000" },
		"required-null-key": func(m map[string]any) { delete(changeAt(m, 5), "before") },
		"forged-gitlink":    func(m map[string]any) { m["unchangedGitlinks"] = []string{"foreign"} },
		"proof-encoding":    func(m map[string]any) { m["baseTreeProof"].([]any)[0].(map[string]any)["rawBase64"] = "AA==" },
		"proof-object": func(m map[string]any) {
			m["baseTreeProof"].([]any)[1].(map[string]any)["gitTree"] = strings.Repeat("f", 40)
		},
		"proof-path": func(m map[string]any) { m["baseTreeProof"].([]any)[0].(map[string]any)["path"] = "wrong" },
		"base-blob": func(m map[string]any) {
			m["baseFiles"].([]any)[0].(map[string]any)["gitBlob"] = strings.Repeat("f", 40)
		},
		"before-digest":  func(m map[string]any) { changeAt(m, 0)["before"].(map[string]any)["sha256"] = strings.Repeat("f", 64) },
		"current-digest": func(m map[string]any) { changeAt(m, 0)["after"].(map[string]any)["sha256"] = strings.Repeat("f", 64) },
		"current-blob":   func(m map[string]any) { changeAt(m, 0)["after"].(map[string]any)["gitBlob"] = strings.Repeat("f", 40) },
		"current-mode":   func(m map[string]any) { changeAt(m, 0)["after"].(map[string]any)["mode"] = "100755" },
	} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(original, &doc); err != nil {
				t.Fatal(err)
			}
			mutate(doc)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			fixtureFile(t, root, cronetOverlayManifest, string(raw))
			if _, err := validateCronetOverlay(root); err == nil {
				t.Fatal("mutated manifest admitted")
			}
		})
	}

	t.Run("duplicate-key", func(t *testing.T) {
		fixtureFile(t, root, cronetOverlayManifest, strings.Replace(string(original), `"schema":`, `"schema":"ignored","schema":`, 1))
		if _, err := validateCronetOverlay(root); err == nil {
			t.Fatal("duplicate JSON key admitted")
		}
	})
	t.Run("oversized-data", func(t *testing.T) {
		if err := os.Truncate(filepath.Join(root, cronetOverlayManifest), cronetMaxFileBytes+1); err != nil {
			t.Fatal(err)
		}
		if _, err := validateCronetOverlay(root); err == nil || !strings.Contains(err.Error(), "oversized") {
			t.Fatalf("per-file byte limit: %v", err)
		}
	})
	fixtureFile(t, root, cronetOverlayManifest, string(original))

	for name, tampered := range map[string][]byte{
		"duplicate":   bytes.Repeat(patch, 2),
		"missing":     patch[:bytes.LastIndex(patch, []byte("--- /dev/null"))],
		"coordinates": bytes.Replace(patch, []byte("@@ -1,2 +0,0 @@"), []byte("@@ -2,2 +0,0 @@"), 1),
		"body":        bytes.Replace(patch, []byte("-//go:build with_purego"), []byte("-//go:build with_bogusx"), 1),
		"context":     bytes.Replace(patch, []byte("-//go:build with_purego"), []byte(" //go:build with_purego"), 1),
	} {
		t.Run("patch-"+name, func(t *testing.T) {
			if bytes.Equal(tampered, patch) {
				t.Fatal("fixture did not change patch")
			}
			fixtureFile(t, root, cronetOverlayPatch, string(tampered))
			fixtureFile(t, root, cronetOverlayManifest, strings.Replace(string(original), sha256Hex(patch), sha256Hex(tampered), 1))
			if _, err := validateCronetOverlay(root); err == nil {
				t.Fatal("tampered patch with refreshed digest admitted")
			}
		})
	}
	fixtureFile(t, root, cronetOverlayManifest, string(original))
	t.Run("patch-hash", func(t *testing.T) {
		fixtureFile(t, root, cronetOverlayPatch, string(patch)+"bad")
		if _, err := validateCronetOverlay(root); err == nil || !strings.Contains(err.Error(), "patch SHA256") {
			t.Fatalf("changed patch identity: %v", err)
		}
	})
	t.Run("missing-patch", func(t *testing.T) {
		if err := os.Remove(filepath.Join(root, cronetOverlayPatch)); err != nil {
			t.Fatal(err)
		}
		if _, err := validateCronetOverlay(root); err == nil {
			t.Fatal("missing patch admitted")
		}
	})
	fixtureFile(t, root, cronetOverlayPatch, string(patch))

	for name := range cronetHistory {
		t.Run(path.Base(name), func(t *testing.T) {
			raw := read(root, name)
			defer fixtureFile(t, root, name, string(raw))
			fixtureFile(t, root, name, string(raw)+"tamper")
			if _, err := validateCronetOverlay(root); err == nil || !strings.Contains(err.Error(), "historical") {
				t.Fatalf("changed historical material: %v", err)
			}
		})
	}
	t.Run("vendor-members", func(t *testing.T) {
		victim := cronetVendor + "/loader_observation_types.go"
		filename := filepath.Join(root, victim)
		raw := read(root, victim)
		reject := func() {
			t.Helper()
			if _, err := validateCronetOverlay(root); err == nil {
				t.Fatal("changed vendor directory admitted")
			}
		}
		if err := os.Remove(filename); err != nil {
			t.Fatal(err)
		}
		reject()
		fixtureFile(t, root, victim, string(raw)+"tamper")
		reject()
		fixtureFile(t, root, victim, string(raw))
		if runtime.GOOS != "windows" {
			if err := os.Chmod(filename, 0o755); err != nil {
				t.Fatal(err)
			}
			reject()
			if err := os.Chmod(filename, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		extra := filepath.Join(root, cronetVendor, "extra")
		if err := os.Mkdir(extra, 0o755); err != nil {
			t.Fatal(err)
		}
		reject()
		if err := os.Remove(extra); err != nil {
			t.Fatal(err)
		}
		fixtureFile(t, root, cronetVendor+"/extra", "unexpected")
		reject()
		if err := os.Remove(extra); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{filename, filepath.Dir(filename)} {
			if err := os.Symlink(target, extra); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			reject()
			if err := os.Remove(extra); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("entry-budget", func(t *testing.T) {
		for i := range cronetMaxEntries + 1 {
			fixtureFile(t, root, fmt.Sprintf("%s/extra-%d", cronetVendor, i), "")
		}
		if _, err := validateCronetOverlay(root); err == nil || !strings.Contains(err.Error(), "entry budget") {
			t.Fatalf("vendor entry budget: %v", err)
		}
	})
}
