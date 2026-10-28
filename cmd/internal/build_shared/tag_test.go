package build_shared

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadTagPreservesPolarisPatchIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell-backed Git output fixture; no real tag or repository writes")
	}
	directory := t.TempDir()
	// Exercise the real tag entrypoints with inert Git output, not a real tag.
	git := `#!/bin/sh
case "$*" in
  'describe --tags') printf '%s\n' "$TEST_CURRENT_TAG" ;;
  'describe --tags --abbrev=0') printf '%s\n' "$TEST_NEAREST_TAG" ;;
  'rev-parse --short HEAD') printf 'deadbee\n' ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(directory, "git"), []byte(git), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, version := range []string{"1.15.0-polaris-alpha.12.1", "1.15.0-polaris-alpha.12.2", "1.15.0-polaris-alpha.13", "1.15.0-polaris-alpha.99999999999999999999", "1.15.0-alpha.12"} {
		for _, exact := range []bool{true, false} {
			t.Setenv("TEST_NEAREST_TAG", "v"+version)
			current, want := "v"+version, version
			if !exact {
				current += "-2-gdeadbee"
				want += "-deadbee"
			}
			t.Setenv("TEST_CURRENT_TAG", current)
			if actual, err := ReadTag(); err != nil || actual != want {
				t.Fatalf("ReadTag(%s) = %s, %v; want %s", current, actual, err, want)
			}
			// read_tag --nightly uses this exact String() path.
			if actual, err := ReadTagVersion(); err != nil || actual.String() != version {
				t.Fatalf("nightly(%s) = %s, %v", current, actual.String(), err)
			}
			if actual, err := ReadTagVersionRev(); err != nil || actual.String() != version {
				t.Fatalf("nearest(%s) = %s, %v", current, actual.String(), err)
			}
		}
	}
	t.Setenv("TEST_NEAREST_TAG", "v1.15.0")
	t.Setenv("TEST_CURRENT_TAG", "v1.15.0-2-gdeadbee")
	if actual, err := ReadTagVersion(); err != nil || actual.String() != "1.15.1" {
		t.Fatalf("stable nightly increment changed: %s, %v", actual.String(), err)
	}
}
