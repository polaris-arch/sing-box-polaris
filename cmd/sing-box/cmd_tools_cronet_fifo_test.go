//go:build with_naive_outbound && with_purego && (linux || darwin)

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCronetDiagnosticRejectsFIFOWithoutBlocking(t *testing.T) {
	const helperEnv = "POLARIS_CRONET_FIFO_TEST_PATH"
	if path := os.Getenv(helperEnv); path != "" {
		_, _, err := verifyCronetLibraryFile(path, strings.Repeat("0", 64))
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO result: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "library.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCronetDiagnosticRejectsFIFOWithoutBlocking$")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FIFO verification blocked: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("FIFO child: %v: %s", err, output)
	}
}
