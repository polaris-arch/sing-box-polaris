//go:build with_tailscale

package tailscale

import (
	"context"
	"testing"
	"time"
)

func TestDirectoryDeadlineDoesNotJoinOrLaterBecomePositive(t *testing.T) {
	endpoint := &Endpoint{directory: newDirectoryOwner(context.Background(), "node", t.TempDir()), taildrop: newTaildropManager(context.Background(), nil, "node", t.TempDir(), nil)}
	release, err := endpoint.directory.scope.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	result := endpoint.RetireTailscaleDirectory(time.Now())
	if result.WriterState != "Unknown" {
		t.Fatal("deadline minted proof")
	}
	select {
	case <-endpoint.directory.retired:
		t.Fatal("observer deadline replaced real join")
	default:
	}
	release()
	select {
	case <-endpoint.directory.retired:
	case <-time.After(time.Second):
		t.Fatal("original worker failed to finish")
	}
	if endpoint.TailscaleDirectoryScope().WriterState != "Unknown" {
		t.Fatal("late completion erased uncertainty")
	}
}

func TestNeverStartedDirectoryHasNoPositiveReceipt(t *testing.T) {
	endpoint := &Endpoint{directory: newDirectoryOwner(context.Background(), "node", t.TempDir()), taildrop: newTaildropManager(context.Background(), nil, "node", t.TempDir(), nil)}
	if err := endpoint.closeDirectory(); err != nil {
		t.Fatal(err)
	}
	result := endpoint.TailscaleDirectoryScope()
	if result.WriterState != "Unknown" || result.DirectoryIdentity != "" {
		t.Fatal("missing lease produced directory proof")
	}
}
