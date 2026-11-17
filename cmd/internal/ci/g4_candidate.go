package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	ownedSDK = "github.com/polaris-arch/tailscale"
	localSDK = "./third_party/tailscale"
)

func sdkTestPackages() []string {
	packages := make([]string, 0, len(sdkPackages))
	for _, name := range sdkPackages {
		packages = append(packages, tailscaleModule+"/"+name)
	}
	return packages
}

var forkPackages = []string{
	"./option", "./adapter", "./daemon", "./experimental/libbox", "./experimental/libbox/internal/oomprofile", "./protocol/tailscale",
	"./common/badversion", "./cmd/internal/read_tag",
	"./cmd/internal/update_android_version", "./cmd/internal/update_desktop_version", "./cmd/internal/update_apple_version",
}

type goModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Sum     string    `json:"Sum"`
	Dir     string    `json:"Dir"`
	Replace *goModule `json:"Replace,omitempty"`
}

func requireOwnedSDK(module goModule, root string) error {
	replacement := module.Replace
	if replacement == nil || module.Path != tailscaleModule {
		return fmt.Errorf("G4 requires an immutable owned SDK replacement")
	}
	if replacement.Path == localSDK {
		if root == "" || replacement.Version != "" {
			return fmt.Errorf("local SDK requires exact repository evidence")
		}
		actual, err := filepath.EvalSymlinks(replacement.Dir)
		if err != nil {
			return err
		}
		expected, err := filepath.EvalSymlinks(filepath.Join(root, "third_party/tailscale"))
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("resolved local SDK directory differs")
		}
		return nil
	}
	if replacement.Path != ownedSDK || replacement.Version == "" || !strings.HasPrefix(replacement.Sum, "h1:") {
		return fmt.Errorf("G4 requires the immutable owned SDK version and verified h1; no upstream/local substitute")
	}
	return nil
}

func loggedCommand(root string, env []string, args ...string) error {
	fmt.Println("+", strings.Join(args, " "))
	command := exec.Command(args[0], args[1:]...)
	command.Dir, command.Env = root, env
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}

func checkSDKSelection(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("check-sdk-selection requires one selection directory")
	}
	directory := args[0]
	var plan struct {
		Modules map[string]struct {
			Module         string   `json:"module"`
			Packages       []string `json:"packages"`
			FullValidation *bool    `json:"fullValidation"`
		} `json:"modules"`
	}
	data, err := os.ReadFile(filepath.Join(directory, "selection.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return err
	}
	selected := plan.Modules["third_party/tailscale"]
	expected := sdkTestPackages()
	packages, err := os.ReadFile(filepath.Join(directory, "tailscale-packages.txt"))
	if err != nil {
		return err
	}
	if len(expected) == 0 || selected.Module != tailscaleModule || !slices.Equal(selected.Packages, expected) ||
		selected.FullValidation == nil || *selected.FullValidation ||
		!slices.Equal(strings.Split(strings.TrimSuffix(string(packages), "\n"), "\n"), expected) {
		return fmt.Errorf("Tailscale selection differs from the bounded G4 package contract")
	}
	data, err = os.ReadFile(filepath.Join(directory, "tailscale-module.json"))
	if err != nil {
		return err
	}
	var module goModule
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := requireOwnedSDK(module, root); err != nil {
		return err
	}
	if module.Replace.Path != localSDK {
		return fmt.Errorf("Tailscale patch marker requires the exact selected local carrier")
	}
	return writeJSON(os.Stdout, map[string]any{"selectedSDK": json.RawMessage(data)})
}

func g4Candidate(args []string) error {
	if len(args) != 0 || runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("candidate runtime gates require Linux or macOS and no extra arguments")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	ldflags, err := os.ReadFile(filepath.Join(root, "release/LDFLAGS"))
	if err != nil {
		return err
	}
	env := append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	if _, err := pinnedGoVersion(root, env); err != nil {
		return err
	}
	var rawModule json.RawMessage
	list := func() (goModule, error) {
		var module goModule
		command := exec.Command("go", "list", "-m", "-json", tailscaleModule)
		command.Dir, command.Env = root, env
		data, err := command.Output()
		if err != nil {
			return module, err
		}
		rawModule = data
		err = json.Unmarshal(data, &module)
		return module, err
	}
	module, err := list()
	if err != nil {
		return err
	}
	if module.Replace == nil {
		return fmt.Errorf("G4 SDK replacement is not an owned source")
	}
	if module.Replace.Path != localSDK {
		if module.Replace.Path != ownedSDK {
			return fmt.Errorf("G4 SDK replacement is not an owned source")
		}
		if err := loggedCommand(root, env, "go", "mod", "download", tailscaleModule); err != nil {
			return err
		}
		module, err = list()
		if err != nil {
			return err
		}
	}
	if err := requireOwnedSDK(module, root); err != nil {
		return err
	}
	if err := writeJSON(os.Stdout, map[string]any{"candidateSDK": rawModule}); err != nil {
		return err
	}
	if err := loggedCommand(root, env, "go", "mod", "verify"); err != nil {
		return err
	}
	dependencyTests := []string{"go", "test", "-race", "-count=1", "-timeout=10m"}
	dependencyTests = append(dependencyTests, sdkTestPackages()...)
	productTests := append([]string{"go", "test", "-race", "-count=1", "-timeout=10m", "-ldflags=" + strings.TrimSpace(string(ldflags)), "-tags=with_tailscale"}, forkPackages...)
	for _, command := range [][]string{dependencyTests, productTests} {
		if err := loggedCommand(root, env, command...); err != nil {
			return err
		}
	}
	if runtime.GOOS == "linux" {
		directory, err := os.MkdirTemp("", "g4-cross-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(directory)
		crossEnv := append(env, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
		fmt.Println("cross compile only; not a Windows execution result")
		if err := loggedCommand(root, crossEnv, "go", "test", "-c", "-ldflags="+strings.TrimSpace(string(ldflags)), "-tags=with_tailscale", "-o", filepath.Join(directory, "tailscale.test.exe"), "./protocol/tailscale"); err != nil {
			return err
		}
	}
	return loggedCommand(root, env, "git", "diff", "--exit-code", "--", "go.mod", "go.sum")
}
