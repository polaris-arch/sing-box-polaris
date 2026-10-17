//go:build with_tailscale && (darwin || linux)

package tailscale

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestGenericDirectoryOwnerDoesNotEnrollOrIssueProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy")
	d := newDirectoryOwner(context.Background(), "node", path)
	if err := d.acquire(); err != nil {
		t.Fatal(err)
	}
	if !d.ready() {
		t.Fatal("generic writer admission blocked")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("generic construction enrolled directory")
	}
	if d.lease != nil {
		t.Fatal("generic owner acquired managed lease")
	}
}

func TestMappedActualDirectoryRetiresUnderOriginalDomain(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	domain, err := adapter.NewTailscaleDirectoryDomain(base, "original-owner")
	if err != nil {
		t.Fatal(err)
	}
	if err = domain.SetFailureHandler(func(error) error { return PoisonDirectoryDomain(domain.PhysicalRoot()) }); err != nil {
		t.Fatal(err)
	}
	if err = domain.Activate(); err != nil {
		t.Fatal(err)
	}
	logical := filepath.Join(domain.LogicalRoot(), "node")
	mapping, err := adapter.NewTailscaleDirectoryMapping(domain, []adapter.TailscaleDirectoryMappingInput{{StateDirectory: logical, TaildropDirectory: filepath.Join(logical, "Taildrop")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), domain)
	ctx = adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping)
	physical, _, ok := mapping.Resolve(logical, filepath.Join(logical, "Taildrop"))
	if !ok {
		t.Fatal("eligible input unmapped")
	}
	actual, lease, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		t.Fatal(err)
	}
	if actual != physical || !lease.Managed {
		t.Fatal("new node did not bind physical lease")
	}
	d := newDirectoryOwner(ctx, "node", actual)
	d.leaseOnce.Do(func() {
		d.lease = lease
		d.admitted = true
		d.node.DirectoryIdentity = lease.Identity
		d.node.Incarnation = lease.Incarnation
		d.node.DirectoryEpoch = lease.Epoch
	})
	endpoint := &Endpoint{directory: d, taildrop: newTaildropManager(ctx, nil, "node", filepath.Join(actual, "Taildrop"), nil)}
	if err := endpoint.closeDirectory(); err != nil {
		t.Fatal(err)
	}
	receipt := endpoint.TailscaleDirectoryScope()
	if receipt.WriterState != "SealedDrained" || receipt.StateDirectory != physical {
		t.Fatalf("incorrect actual-path receipt: %+v", receipt)
	}
	if _, err := os.Stat(logical); !os.IsNotExist(err) {
		t.Fatal("logical path was migrated or created")
	}
	if err := domain.Fail(errors.New("later raw configuration")); err != nil {
		t.Fatal(err)
	}
	if endpoint.TailscaleDirectoryScope().WriterState != "Unknown" {
		t.Fatal("retired accessor ignored domain revocation")
	}
}
