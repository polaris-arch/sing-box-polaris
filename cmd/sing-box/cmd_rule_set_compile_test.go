package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
)

func TestCompileRuleSetOversizePreservesOutputAndStdin(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.json")
	input, err := os.Create(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := input.Truncate(srs.DefaultInputBytes + 2); err != nil {
		t.Fatal(err)
	}
	previousStdin, previousOutput := os.Stdin, flagRuleSetCompileOutput
	defer func() { os.Stdin, flagRuleSetCompileOutput = previousStdin, previousOutput }()
	os.Stdin = input
	flagRuleSetCompileOutput = filepath.Join(dir, "existing.srs")
	const existing = "previous compiled rules"
	if err := os.WriteFile(flagRuleSetCompileOutput, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{sourcePath, "stdin"} {
		if err := compileRuleSet(path); !errors.Is(err, srs.ErrResourceLimit) {
			t.Fatalf("%s: expected input limit error, got %v", path, err)
		}
		if content, err := os.ReadFile(flagRuleSetCompileOutput); err != nil || string(content) != existing {
			t.Fatalf("%s: existing output changed: %q, %v", path, content, err)
		}
	}
	if offset, err := input.Seek(0, io.SeekCurrent); err != nil || offset != srs.DefaultInputBytes+1 {
		t.Fatalf("stdin closed or consumed past the sentinel: offset=%d, err=%v", offset, err)
	}
}
