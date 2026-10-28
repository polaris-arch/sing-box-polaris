//go:build with_naive_outbound && with_purego

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCronetDiagnosticRequiresExactLibraryBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libcronet.so")
	data := []byte("candidate-a")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(data))
	resolved, actual, err := verifyCronetLibraryFile(path, strings.ToUpper(expected))
	if err != nil || !filepath.IsAbs(resolved) || actual != expected {
		t.Fatalf("%s %s %v", resolved, actual, err)
	}
	for _, bad := range []string{"", "0", strings.Repeat("z", 64), strings.Repeat("0", 64)} {
		if _, _, err = verifyCronetLibraryFile(path, bad); err == nil {
			t.Fatalf("bad digest accepted: %q", bad)
		}
	}
	if _, _, err = verifyCronetLibraryFile("", expected); err == nil {
		t.Fatal("empty path selected a fallback")
	}
	if err = os.WriteFile(path, []byte("candidate-b"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = verifyCronetLibraryFile(path, expected); err == nil {
		t.Fatal("same-size replacement accepted")
	}
	if _, _, err = verifyCronetLibraryFile(filepath.Dir(path), expected); err == nil {
		t.Fatal("directory accepted")
	}
	if _, _, err = verifyCronetLibraryFile(path+"missing", expected); err == nil {
		t.Fatal("missing library accepted")
	}
}
