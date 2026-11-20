package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

var formatExclusions = []string{"vendor/", "third_party/", "release/dependency-sources/", "builtin/", "examples/", "transport/simple-obfs/"}

func excludedFormatPath(name string) bool {
	for _, prefix := range formatExclusions {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return slices.Contains(strings.Split(name, "/"), "testdata")
}

func ownedFormatScope(root string) (map[string]string, error) {
	entries, err := trackedIndex(root)
	if err != nil {
		return nil, err
	}
	var nested []string
	for name, entry := range entries {
		if name != "go.mod" && !strings.HasSuffix(name, "/go.mod") || excludedFormatPath(name) {
			continue
		}
		filename, err := regularSource(root, name)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		if entry.Mode != "100644" && entry.Mode != "100755" || gitObjectHash("blob", data) != entry.Blob {
			return nil, fmt.Errorf("tracked module boundary changed: %s", name)
		}
		module, err := modfile.Parse(filename, data, nil)
		if err != nil || module.Module == nil || module.Module.Mod.Path == "" {
			return nil, fmt.Errorf("invalid tracked module boundary: %s: %v", name, err)
		}
		after, err := os.ReadFile(filename)
		if err != nil || !bytes.Equal(data, after) {
			return nil, fmt.Errorf("module boundary changed while parsing: %s", name)
		}
		if name != "go.mod" {
			nested = append(nested, path.Dir(name)+"/")
		}
	}
	selected := map[string]string{}
	for name, entry := range entries {
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".pb.go") || excludedFormatPath(name) {
			continue
		}
		if slices.ContainsFunc(nested, func(prefix string) bool { return strings.HasPrefix(name, prefix) }) {
			continue
		}
		if entry.Mode != "100644" && entry.Mode != "100755" {
			return nil, fmt.Errorf("unsafe owned Go source: %s", name)
		}
		filename, err := regularSource(root, name)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, data, parser.PackageClauseOnly|parser.ParseComments)
		if err == nil && ast.IsGenerated(parsed) {
			continue
		}
		selected[name] = sha256Hex(data)
	}
	fmt.Fprintf(os.Stderr, "Owned formatting scope: %d files, %d nested modules\n", len(selected), len(nested))
	return selected, nil
}

func checkFormat(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("check-format takes no extra arguments")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	scope, err := ownedFormatScope(root)
	if err != nil {
		return err
	}
	if len(scope) == 0 {
		return fmt.Errorf("empty owned Go formatting scope")
	}
	files := make([]string, 0, len(scope))
	for name := range scope {
		files = append(files, name)
	}
	slices.Sort(files)
	toolName := os.Getenv("GOLANGCI_LINT")
	if toolName == "" {
		toolName = "golangci-lint"
	}
	tool, err := exec.LookPath(toolName)
	if err != nil {
		return err
	}
	version := exec.Command(tool, "version")
	version.Stdout, version.Stderr = os.Stderr, os.Stderr
	if err := version.Run(); err != nil {
		return err
	}
	// The upstream diff mode checks the existing formatter configuration without
	// writing the checkout or copying its vendored dependencies.
	command := exec.Command(tool, append([]string{"fmt", "--diff", "--color=never", "--config", ".golangci.yml", "--"}, files...)...)
	command.Dir = root
	var output, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostics
	err = command.Run()
	os.Stdout.Write(output.Bytes())
	os.Stderr.Write(diagnostics.Bytes())
	if err != nil {
		return err
	}
	if output.Len() != 0 || diagnostics.Len() != 0 {
		return fmt.Errorf("owned source formatting differs or formatter emitted diagnostics")
	}
	for _, name := range files {
		hash, err := fileSHA256(name)
		if err != nil || hash != scope[name] {
			return fmt.Errorf("owned source changed during formatting check: %s", name)
		}
	}
	fmt.Printf("Owned Go formatting clean: %d files; vendor/generated excluded\n", len(files))
	return nil
}
