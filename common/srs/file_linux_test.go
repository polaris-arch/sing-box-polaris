package srs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
)

func TestReadFileValidatesOpenedDescriptor(t *testing.T) {
	directory := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), directory, "", os.Getuid(), os.Getgid())
	data := []byte("rules")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "source"), data, 0o600))
	require.NoError(t, os.Symlink("source", filepath.Join(directory, "linked")))
	content, err := ReadFile(ctx, "linked", int64(len(data)))
	require.NoError(t, err)
	require.Equal(t, data, content)

	fifo := filepath.Join(directory, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.NoError(t, os.Symlink("fifo", filepath.Join(directory, "linked-fifo")))
	result := make(chan error, 1)
	go func() {
		_, readErr := ReadFile(ctx, "linked-fifo", int64(len(data)))
		result <- readErr
	}()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "not a regular file")
	case <-time.After(2 * time.Second):
		// Release a mistakenly blocking open before removing the test directory.
		if file, openErr := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); openErr == nil {
			_ = file.Close()
		}
		t.Fatal("opening a rule-set FIFO blocked without a writer")
	}
}
