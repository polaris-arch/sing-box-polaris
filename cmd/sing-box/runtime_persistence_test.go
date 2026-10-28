package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIRuntimePersistenceRequiresOneRegularFileSource(t *testing.T) {
	oldPaths, oldDirectories := configPaths, configDirectories
	defer func() { configPaths, configDirectories = oldPaths, oldDirectories }()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := &OptionsEntry{path: path, content: []byte("{}")}
	configPaths = []string{path}
	configDirectories = nil
	if persist, err := cliRuntimePersistence([]*OptionsEntry{entry}); err != nil || persist == nil {
		t.Fatal("single source not bound", err)
	}
	configDirectories = []string{filepath.Dir(path)}
	if persist, err := cliRuntimePersistence([]*OptionsEntry{entry}); err != nil || persist != nil {
		t.Fatal("directory merge bound", err)
	}
	configDirectories = nil
	configPaths = []string{"stdin"}
	if persist, err := cliRuntimePersistence([]*OptionsEntry{{path: "stdin"}}); err != nil || persist != nil {
		t.Fatal("stdin bound", err)
	}
	configPaths = []string{path, "other.json"}
	if persist, err := cliRuntimePersistence([]*OptionsEntry{entry, entry}); err != nil || persist != nil {
		t.Fatal("merged source bound", err)
	}
}
