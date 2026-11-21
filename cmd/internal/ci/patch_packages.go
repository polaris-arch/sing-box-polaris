package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
)

type moduleRunner struct {
	module string
	marker string
}

const tailscaleModule = "github.com/sagernet/tailscale"

var sdkPackages = []string{
	"util/dirscope", "util/execqueue", "control/controlclient", "ipn/store",
	"ipn/ipnlocal", "ipn/ipnlocal/netmapcache", "feature/acme", "tka", "tsnet",
	"net/netmon", "wgengine/magicsock", "wgengine",
}

// Identity and marker share one registry; unknown module boundaries stay errors.
var moduleRunners = map[string]moduleRunner{
	".":                           {module: "github.com/sagernet/sing-box"},
	"test":                        {"test", "integration-tests-selected"},
	"third_party/sing-tun":        {"github.com/sagernet/sing-tun", "sing-tun-selected"},
	"third_party/metacubex-utls":  {"github.com/metacubex/utls", "metacubex-utls-selected"},
	"third_party/cronet-go":       {"github.com/sagernet/cronet-go", "cronet-go-selected"},
	"third_party/fswatch":         {"github.com/sagernet/fswatch", "fswatch-selected"},
	"third_party/sing":            {"github.com/sagernet/sing", "sing-selected"},
	"third_party/sing-quic":       {"github.com/sagernet/sing-quic", "sing-quic-selected"},
	"third_party/go-nat":          {"github.com/libp2p/go-nat", "go-nat-selected"},
	"third_party/google-nftables": {"github.com/google/nftables", "google-nftables-selected"},
	"third_party/tailscale":       {tailscaleModule, "tailscale-selected"},
	"third_party/wireguard-go":    {"github.com/sagernet/wireguard-go", "wireguard-go-selected"},
	"third_party/tfo-go":          {"github.com/database64128/tfo-go/v2", "tfo-go-selected"},
	"third_party/sing-vmess":      {"github.com/sagernet/sing-vmess", "sing-vmess-selected"},
}

type selectedModule struct {
	Module         string   `json:"module"`
	ChangedPaths   []string `json:"changedPaths"`
	Packages       []string `json:"packages"`
	FullValidation bool     `json:"fullValidation"`
}

type patchPlan struct {
	Schema         string                     `json:"schema"`
	Modules        map[string]*selectedModule `json:"modules"`
	BaseCommit     string                     `json:"baseCommit,omitempty"`
	SourceCommit   string                     `json:"sourceCommit,omitempty"`
	MergeBase      string                     `json:"mergeBaseCommit,omitempty"`
	BaseIsAncestor bool                       `json:"baseIsAncestor,omitempty"`
}

func within(name, directory string) bool {
	return name == directory || strings.HasPrefix(name, directory+"/")
}

func selectPatchPackages(root string, changedPaths []string) (patchPlan, error) {
	plan := patchPlan{Schema: "polaris-patch-module-selection-v1", Modules: map[string]*selectedModule{}}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return plan, err
	}
	paths := slices.Clone(changedPaths)
	slices.Sort(paths)
	for _, name := range slices.Compact(paths) {
		schemaPackage := ""
		if name == "daemon/runtime_config.proto" {
			schemaPackage = "./daemon"
		}
		if path.Ext(name) != ".go" && path.Base(name) != "go.mod" && path.Base(name) != "go.sum" && schemaPackage == "" && !within(name, "test") {
			continue
		}
		if !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\r\n\x00\\") || name == ".." || strings.HasPrefix(name, "../") {
			return plan, fmt.Errorf("invalid changed Go/input path: %q", name)
		}
		owner := ""
		for directory := path.Dir(name); ; directory = path.Dir(directory) {
			for _, relative := range []string{directory, path.Join(directory, "go.mod")} {
				info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
				if statErr != nil && !os.IsNotExist(statErr) {
					return plan, statErr
				}
				if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
					return plan, fmt.Errorf("symlink in module boundary: %s", relative)
				}
			}
			info, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(directory), "go.mod"))
			if statErr != nil && !os.IsNotExist(statErr) {
				return plan, statErr
			}
			if owner == "" && statErr == nil && info.Mode().IsRegular() {
				owner = directory
			}
			// Check ancestors even after finding the nearest owner.
			if directory == "." {
				break
			}
		}
		if owner == "release" {
			data, readErr := os.ReadFile(filepath.Join(root, "release/go.mod"))
			if readErr != nil {
				return plan, readErr
			}
			if string(data) != "module github.com/polaris-arch/sing-box-polaris/release\n\ngo 1.27.0\n" || name != "release/go.mod" && !within(name, "release/licenses") {
				return plan, fmt.Errorf("unaccounted release module path: %s", name)
			}
			continue
		}
		runner, found := moduleRunners[owner]
		if !found {
			return plan, fmt.Errorf("changed module has no approved test runner: %s", owner)
		}
		for nested, candidate := range moduleRunners {
			if candidate.marker != "" && within(name, nested) && owner != nested {
				return plan, fmt.Errorf("missing or changed nested module boundary: %s", nested)
			}
		}
		if (path.Base(name) == "go.mod" || path.Base(name) == "go.sum") && path.Dir(name) != owner {
			return plan, fmt.Errorf("unaccounted module input boundary: %s", name)
		}
		filename := filepath.Join(root, filepath.FromSlash(owner), "go.mod")
		data, readErr := os.ReadFile(filename)
		if readErr != nil {
			return plan, readErr
		}
		module, err := modfile.Parse(filename, data, nil)
		if err != nil || module.Module == nil || module.Module.Mod.Path != runner.module {
			return plan, fmt.Errorf("module identity mismatch: %s", owner)
		}
		if owner == "test" && name != "test/naive_self_test.go" && name != "test/wireguard_test.go" {
			return plan, fmt.Errorf("integration test path has no approved test runner: %s", name)
		}
		entry := plan.Modules[owner]
		if entry == nil {
			entry = &selectedModule{Module: runner.module, Packages: []string{}, FullValidation: owner != "."}
			plan.Modules[owner] = entry
		}
		entry.ChangedPaths = append(entry.ChangedPaths, name)
		if owner == "." && (path.Ext(name) == ".go" || schemaPackage != "") {
			target := name
			if schemaPackage != "" {
				target = path.Dir(name)
			}
			info, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(target)))
			if statErr != nil && !os.IsNotExist(statErr) {
				return plan, statErr
			}
			if statErr != nil || schemaPackage != "" && !info.IsDir() || schemaPackage == "" && !info.Mode().IsRegular() {
				entry.FullValidation = true
			} else if schemaPackage != "" {
				entry.Packages = append(entry.Packages, schemaPackage)
			} else if path.Dir(name) == "." {
				entry.Packages = append(entry.Packages, ".")
			} else {
				entry.Packages = append(entry.Packages, "./"+path.Dir(name))
			}
		}
	}
	for owner, entry := range plan.Modules {
		if owner == "third_party/tailscale" {
			entry.Packages = nil
			entry.Packages = sdkTestPackages()
			entry.FullValidation = false
		} else if owner == "test" {
			entry.Packages = []string{"."}
			entry.FullValidation = false
		} else if entry.FullValidation || len(entry.Packages) == 0 {
			entry.Packages = []string{"./..."}
			entry.FullValidation = true
		} else {
			slices.Sort(entry.Packages)
			entry.Packages = slices.Compact(entry.Packages)
		}
	}
	return plan, nil
}

func writePatchPlan(directory string, plan patchPlan) error {
	if err := os.MkdirAll(filepath.Dir(directory), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		return err
	}
	var output bytes.Buffer
	if err := writeJSON(&output, plan); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "selection.json"), output.Bytes(), 0o644); err != nil {
		return err
	}
	for owner, filename := range map[string]string{".": "root-packages.txt", "third_party/tailscale": "tailscale-packages.txt"} {
		packages := ""
		if entry := plan.Modules[owner]; entry != nil {
			packages = strings.Join(entry.Packages, "\n") + "\n"
		}
		if err := os.WriteFile(filepath.Join(directory, filename), []byte(packages), 0o644); err != nil {
			return err
		}
	}
	for owner, entry := range plan.Modules {
		if marker := moduleRunners[owner].marker; marker != "" {
			if err := os.WriteFile(filepath.Join(directory, marker), []byte(entry.Module+"\n"), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func patchPackages(args []string) error {
	flags := flag.NewFlagSet("patch-packages", flag.ContinueOnError)
	base := flags.String("base", "", "official baseline commit")
	output := flags.String("output-directory", "", "fresh runner-owned plan directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !sourceCommit.MatchString(*base) || *output == "" {
		return fmt.Errorf("full baseline commit and output-directory required")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if _, err = git(root, "merge-base", "--is-ancestor", *base, strings.TrimSpace(string(head))); err != nil {
		return err
	}
	changed, err := git(root, "diff", "--name-only", "--no-renames", "-z", *base+".."+strings.TrimSpace(string(head)))
	if err != nil {
		return err
	}
	paths := strings.Split(strings.TrimSuffix(string(changed), "\x00"), "\x00")
	plan, err := selectPatchPackages(root, paths)
	if err != nil {
		return err
	}
	plan.BaseCommit, plan.SourceCommit = *base, strings.TrimSpace(string(head))
	plan.MergeBase, plan.BaseIsAncestor = *base, true
	if err := writePatchPlan(*output, plan); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(plan)
}
