package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

func patchIOSGo(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("patch-ios-go takes no extra arguments")
	}
	goEnv := exec.Command("go", "env", "-json", "GOROOT", "GOVERSION")
	goEnv.Env = append(goEnv.Environ(), "GOTOOLCHAIN=local")
	goEnv.Stderr = os.Stderr
	raw, err := goEnv.Output()
	if err != nil {
		return err
	}
	var toolchain struct{ GOROOT, GOVERSION string }
	if err := json.Unmarshal(raw, &toolchain); err != nil {
		return err
	}
	if !filepath.IsAbs(toolchain.GOROOT) {
		return fmt.Errorf("Apple CPU patch requires an absolute GOROOT")
	}
	features, err := applyIOSCPUPatch(".", toolchain.GOROOT, toolchain.GOVERSION)
	if err != nil {
		return err
	}

	goList := exec.Command("go", "list", "-json", "internal/cpu")
	goList.Env = append(goList.Environ(), "GOTOOLCHAIN=local", "GOOS=ios", "GOARCH=arm64", "CGO_ENABLED=0")
	goList.Stderr = os.Stderr
	raw, err = goList.Output()
	if err != nil {
		return err
	}
	var cpu struct{ GoFiles []string }
	if err := json.Unmarshal(raw, &cpu); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "internal/cpu files for ios/arm64:", cpu.GoFiles)
	if !slices.Contains(cpu.GoFiles, "cpu_arm64_ios.go") {
		return fmt.Errorf("Apple CPU patch is not effective")
	}
	return writeJSON(os.Stdout, map[string]any{
		"appleCPUSourceVerified": true,
		"goVersion":              toolchain.GOVERSION[2:],
		"features":               features,
	})
}

func applyIOSCPUPatch(sourceRoot, goRoot, goVersion string) ([]string, error) {
	var manifest struct {
		Version string
		IOSCPU  struct {
			Patch, PatchSHA256 string
			Before, After      map[string]*string
			Features           []string
		}
	}
	if err := readNativeSourceJSON(sourceRoot, ".github/go-toolchains.json", &manifest); err != nil {
		return nil, err
	}
	if manifest.Version == "" || goVersion != "go"+manifest.Version {
		return nil, fmt.Errorf("Apple CPU patch requires exact source-owned Go version")
	}
	patch := manifest.IOSCPU
	if len(patch.Before) == 0 || len(patch.After) == 0 || patch.Features == nil {
		return nil, fmt.Errorf("Apple CPU patch manifest is incomplete")
	}
	data, err := readNativeSource(sourceRoot, patch.Patch)
	if err != nil {
		return nil, err
	}
	if sha256Hex(data) != patch.PatchSHA256 {
		return nil, fmt.Errorf("Apple CPU patch input hash mismatch")
	}
	if iosCPUSourcesMatch(goRoot, patch.Before) {
		command := exec.Command("patch", "--batch", "--fuzz=0", "-p1")
		command.Dir = goRoot
		command.Stdin = bytes.NewReader(data)
		command.Stdout, command.Stderr = os.Stderr, os.Stderr
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("apply Apple CPU patch: %w", err)
		}
	}
	if !iosCPUSourcesMatch(goRoot, patch.After) {
		return nil, fmt.Errorf("Apple CPU source is partial, unexpected or corrupt")
	}
	return patch.Features, nil
}

func iosCPUSourcesMatch(root string, expected map[string]*string) bool {
	for name, want := range expected {
		if !checkedRelative(name) {
			return false
		}
		if want == nil {
			if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name))); !errors.Is(err, fs.ErrNotExist) {
				return false
			}
			continue
		}
		data, err := readNativeSource(root, name)
		if err != nil || sha256Hex(data) != *want {
			return false
		}
	}
	return true
}
