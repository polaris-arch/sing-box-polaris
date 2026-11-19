package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
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
	content := `{"version":1,"rules":[` + strings.Repeat(`{"domain":"example.org"},`, int(srs.DefaultReadLimits().Rules)) + `{"domain":"last.example"}]}`
	if err := os.WriteFile(sourcePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := compileRuleSet(sourcePath); !errors.Is(err, srs.ErrResourceLimit) {
		t.Fatalf("expected rule count limit error, got %v", err)
	}
	if output, err := os.ReadFile(flagRuleSetCompileOutput); err != nil || string(output) != existing {
		t.Fatalf("existing output changed: %q, %v", output, err)
	}
}

func TestRuleSetOversizePreservesInPlaceSource(t *testing.T) {
	source, err := os.Create(filepath.Join(t.TempDir(), "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	const prefix = `{"version":1,"rules":[]}`
	if _, err := source.WriteString(prefix); err != nil {
		t.Fatal(err)
	}
	wantSize := srs.DefaultInputBytes + 1
	if err := source.Truncate(wantSize); err != nil {
		t.Fatal(err)
	}
	previousFormatWrite, previousUpgradeWrite := commandRuleSetFormatFlagWrite, commandRuleSetUpgradeFlagWrite
	previousMatchFormat := flagRuleSetMatchFormat
	defer func() {
		commandRuleSetFormatFlagWrite, commandRuleSetUpgradeFlagWrite = previousFormatWrite, previousUpgradeWrite
		flagRuleSetMatchFormat = previousMatchFormat
	}()
	commandRuleSetFormatFlagWrite, commandRuleSetUpgradeFlagWrite = true, true
	flagRuleSetMatchFormat = C.RuleSetFormatBinary
	for _, command := range []struct {
		name string
		run  func(string) error
	}{
		{"format -w", formatRuleSet},
		{"upgrade -w", upgradeRuleSet},
		{"match -f binary", func(path string) error { return ruleSetMatch(path, "example.org") }},
	} {
		t.Run(command.name, func(t *testing.T) {
			if err := command.run(source.Name()); !errors.Is(err, srs.ErrResourceLimit) {
				t.Fatalf("expected input limit error, got %v", err)
			}
			info, err := os.Stat(source.Name())
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != wantSize {
				t.Fatalf("source size changed: got %d, want %d", info.Size(), wantSize)
			}
			content := make([]byte, len(prefix))
			if _, err := source.ReadAt(content, 0); err != nil || string(content) != prefix {
				t.Fatalf("source prefix changed: %q, %v", content, err)
			}
		})
	}
}

func TestRuleSetMergeAggregateSourceBudget(t *testing.T) {
	dir := t.TempDir()
	const first = `{"version":1,"rules":[{"domain":["first.example"]}]}`
	firstPath := filepath.Join(dir, "first.json")
	if err := os.WriteFile(firstPath, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesDir := filepath.Join(dir, "sources")
	if err := os.Mkdir(sourcesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := os.Create(filepath.Join(sourcesDir, "second.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	const secondContent = `{"version":2,"rules":[{"domain":["second.example"]}]}`
	if _, err := second.WriteString(secondContent); err != nil {
		t.Fatal(err)
	}
	writeRuleSetPadding(t, second, bytes.Repeat([]byte{' '}, 1<<20), srs.DefaultInputBytes-int64(len(first)+len(secondContent)))
	previousPaths, previousDirs := ruleSetPaths, ruleSetDirectories
	defer func() { ruleSetPaths, ruleSetDirectories = previousPaths, previousDirs }()
	ruleSetPaths, ruleSetDirectories = []string{firstPath}, []string{sourcesDir}
	outputPath := filepath.Join(dir, "merged.json")
	if err := mergeRuleSet(outputPath); err != nil {
		t.Fatalf("exact input limit: %v", err)
	}
	merged, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	firstRule := bytes.Index(merged, []byte("first.example"))
	if firstRule < 0 || firstRule >= bytes.Index(merged, []byte("second.example")) {
		t.Fatalf("merged output is missing rules in path order: %s", merged)
	}
	if _, err := second.WriteString(" "); err != nil {
		t.Fatal(err)
	}
	if err := mergeRuleSet(outputPath); !errors.Is(err, srs.ErrResourceLimit) {
		t.Fatalf("expected aggregate input limit error, got %v", err)
	}
	if content, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(content, merged) {
		t.Fatalf("existing output changed: %q, %v", content, err)
	}
}

func TestRuleSetConvertSourceBudgetAndScanFailures(t *testing.T) {
	dir := t.TempDir()
	source, err := os.Create(filepath.Join(dir, "source.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	const prefix = "example.org\n"
	if _, err := source.WriteString(prefix + strings.Repeat("#", bufio.MaxScanTokenSize+1)); err != nil {
		t.Fatal(err)
	}
	previousStdin, previousType, previousOutput := os.Stdin, flagRuleSetConvertType, flagRuleSetConvertOutput
	defer func() {
		os.Stdin, flagRuleSetConvertType, flagRuleSetConvertOutput = previousStdin, previousType, previousOutput
	}()
	flagRuleSetConvertType = "adguard"
	flagRuleSetConvertOutput = filepath.Join(dir, "converted.srs")
	const existing = "previous conversion"
	if err := os.WriteFile(flagRuleSetConvertOutput, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convertRuleSet(source.Name()); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("expected scanner line error, got %v", err)
	}
	if content, err := os.ReadFile(flagRuleSetConvertOutput); err != nil || string(content) != existing {
		t.Fatalf("scan failure changed output: %q, %v", content, err)
	}
	if err := source.Truncate(int64(len(prefix))); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	commentLine := bytes.Repeat([]byte{'#'}, 32<<10)
	commentLine[len(commentLine)-1] = '\n'
	writeRuleSetPadding(t, source, commentLine, srs.DefaultInputBytes-int64(len(prefix)))
	if err := convertRuleSet(source.Name()); err != nil {
		t.Fatalf("exact input limit: %v", err)
	}
	converted, err := os.ReadFile(flagRuleSetConvertOutput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srs.Read(bytes.NewReader(converted), false); err != nil {
		t.Fatalf("invalid converted rule-set: %v", err)
	}
	if _, err := source.WriteString("##"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	os.Stdin = source
	if err := convertRuleSet("stdin"); !errors.Is(err, srs.ErrResourceLimit) {
		t.Fatalf("expected input limit error, got %v", err)
	}
	if content, err := os.ReadFile(flagRuleSetConvertOutput); err != nil || !bytes.Equal(content, converted) {
		t.Fatalf("oversize input changed output: %x, %v", content, err)
	}
	if offset, err := source.Seek(0, io.SeekCurrent); err != nil || offset != srs.DefaultInputBytes+1 {
		t.Fatalf("stdin closed or consumed past the sentinel: offset=%d, err=%v", offset, err)
	}
}

func writeRuleSetPadding(t *testing.T, output io.Writer, chunk []byte, size int64) {
	t.Helper()
	for size > 0 {
		written, err := output.Write(chunk[:min(int64(len(chunk)), size)])
		if err != nil {
			t.Fatal(err)
		}
		size -= int64(written)
	}
}
