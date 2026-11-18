package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
)

var nativeSourceModules = [...]struct{ name, field string }{
	{"go.mod", "goModSha256"}, {"go.sum", "goSumSha256"},
}

type nativeLocalReplacement struct {
	Module string `json:"module"`
	Path   string `json:"path"`
	Tree   string `json:"tree"`
}

func nativeSourceModuleBytes(root, source string) ([]byte, map[string]string, error) {
	var goMod []byte
	hashes := make(map[string]string, len(nativeSourceModules))
	for _, module := range nativeSourceModules {
		actual, err := readNativeSource(root, module.name)
		if err != nil {
			return nil, nil, err
		}
		committed, err := git(root, "show", source+":"+module.name)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(actual, committed) {
			return nil, nil, fmt.Errorf("%s working-tree bytes differ from HEAD blob", module.name)
		}
		hashes[module.field] = sha256Hex(committed)
		if module.name == "go.mod" {
			goMod = committed
		}
	}
	return goMod, hashes, nil
}

func nativeLocalReplacements(root, source string, goMod []byte) ([]nativeLocalReplacement, error) {
	module, err := modfile.Parse("go.mod", goMod, nil)
	if err != nil {
		return nil, err
	}
	replacements := []nativeLocalReplacement{}
	for _, entry := range module.Replace {
		if entry.New.Version != "" {
			continue
		}
		name, local := strings.CutPrefix(entry.New.Path, "./")
		if !local || !checkedRelative(name) {
			return nil, fmt.Errorf("non-repository local replacement")
		}
		tree, err := git(root, "rev-parse", source+":"+name)
		if err != nil {
			return nil, err
		}
		replacements = append(replacements, nativeLocalReplacement{entry.Old.Path, entry.New.Path, strings.TrimSpace(string(tree))})
	}
	return replacements, nil
}

func nativeCollectorSource(root string) (map[string]any, error) {
	source := os.Getenv("GITHUB_SHA")
	if err := verifyProducerCheckout(root, source); err != nil {
		return nil, err
	}
	tree, err := git(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, err
	}
	if _, err := validateCronetOverlay(root); err != nil {
		return nil, err
	}
	goMod, hashes, err := nativeSourceModuleBytes(root, source)
	if err != nil {
		return nil, err
	}
	replacements, err := nativeLocalReplacements(root, source, goMod)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sourceCommit": source, "sourceTree": strings.TrimSpace(string(tree)),
		"sourceIdentity": map[string]any{
			"sourceOverlay": 0, "goModSha256": hashes["goModSha256"], "goSumSha256": hashes["goSumSha256"],
			"replacements": replacements,
		},
	}, nil
}
