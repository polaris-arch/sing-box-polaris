package build_shared

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindNDKExplicitToolchainBeforeInstalledDefault(t *testing.T) {
	oldSDK, oldNDK := androidSDKPath, androidNDKPath
	t.Cleanup(func() { androidSDKPath, androidNDKPath = oldSDK, oldNDK })
	androidSDKPath = t.TempDir()
	makeNDK := func(path string) string {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "source.properties"), []byte("Pkg.Revision = 30.0.16248370\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	makeNDK(filepath.Join(androidSDKPath, "ndk", "28.0.13004108"))
	stable := makeNDK(filepath.Join(androidSDKPath, "ndk", "30.0.16248370"))
	explicit := makeNDK(filepath.Join(t.TempDir(), "verified-r30"))
	t.Setenv("ANDROID_NDK_HOME", explicit)
	if !findNDK() || androidNDKPath != explicit {
		t.Fatalf("explicit NDK ignored: %q", androidNDKPath)
	}
	t.Chdir(makeNDK(t.TempDir()))
	t.Setenv("ANDROID_NDK_HOME", "")
	if !findNDK() || androidNDKPath != stable {
		t.Fatalf("empty NDK environment selected the current directory: %q", androidNDKPath)
	}
	t.Setenv("ANDROID_NDK_HOME", filepath.Join(t.TempDir(), "missing"))
	if !findNDK() || androidNDKPath != stable {
		t.Fatalf("stable installed NDK not selected: %q", androidNDKPath)
	}
	if err := os.RemoveAll(stable); err != nil {
		t.Fatal(err)
	}
	if !findNDK() || androidNDKPath != filepath.Join(androidSDKPath, "ndk", "28.0.13004108") {
		t.Fatalf("existing fallback not preserved: %q", androidNDKPath)
	}
	androidSDKPath = t.TempDir()
	if findNDK() {
		t.Fatal("missing NDK accepted")
	}
	t.Setenv("ANDROID_NDK_HOME", explicit)
	if !findNDK() || androidNDKPath != explicit {
		t.Fatalf("explicit NDK requires an installed SDK NDK directory: %q", androidNDKPath)
	}
}
