package daemon

import (
	"errors"
	"github.com/sagernet/sing-box/adapter"
	"path/filepath"
	"testing"
)

func TestDirectoryCensusRejectsForeignAndDuplicateOwners(t *testing.T) {
	r := &tailscaleRetirementRun{binding: adapter.TailscaleStoreRunBinding{RunNonce: "run", ConfigDigest: "config"}, expected: []string{"a"}}
	n := adapter.TailscaleDirectoryNode{Tag: "a", StateDirectory: "/state/a", RunNonce: "run", ConfigDigest: "config", CensusVersion: 1}
	if !r.directoryCensus([]adapter.TailscaleDirectoryNode{n}) {
		t.Fatal("original census rejected")
	}
	n.RunNonce = "foreign"
	if r.directoryCensus([]adapter.TailscaleDirectoryNode{n}) {
		t.Fatal("foreign owner accepted")
	}
	n.RunNonce = "run"
	if r.directoryCensus([]adapter.TailscaleDirectoryNode{n, n}) {
		t.Fatal("duplicate owner accepted")
	}
}

func TestDirectoryFreezeUnknownIsWriteOnce(t *testing.T) {
	r := &tailscaleRetirementRun{binding: adapter.TailscaleStoreRunBinding{RunNonce: "run", ConfigDigest: "config"}, expected: []string{"a"}}
	n := adapter.TailscaleDirectoryNode{Tag: "a", StateDirectory: "/state/a", RunNonce: "run", ConfigDigest: "config", CensusVersion: 1, WriterState: "SealedDrained", DirectoryIdentity: "identity", Incarnation: "incarnation"}
	r.freezeDirectories([]adapter.TailscaleDirectoryNode{n}, true)
	if r.directoryFinal.Terminal != "Unknown" {
		t.Fatal("missing epoch certified")
	}
	n.DirectoryEpoch = "epoch"
	r.freezeDirectories([]adapter.TailscaleDirectoryNode{n}, true)
	if r.directoryFinal.Terminal != "Unknown" {
		t.Fatal("late result replaced original terminal")
	}
}

func TestFrozenDirectoryPositiveRequiresCurrentDomainAuthority(t *testing.T) {
	original := tailscaleDirectoryInstance{Terminal: "SealedDrained", CensusComplete: true, Nodes: []adapter.TailscaleDirectoryNode{{WriterState: "SealedDrained"}}}
	checkUnknown := func(d *adapter.TailscaleDirectoryDomain) {
		t.Helper()
		got := applyDirectoryDomainAuthority(original, d)
		if got.Terminal != "Unknown" || got.CensusComplete || got.Nodes[0].WriterState != "Unknown" || got.Nodes[0].Failure == "" {
			t.Fatal("frozen positive escaped missing/revoked domain")
		}
		if original.Nodes[0].WriterState != "SealedDrained" {
			t.Fatal("export mutated original freeze")
		}
	}
	checkUnknown(nil)
	d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
	if err != nil {
		t.Fatal(err)
	}
	checkUnknown(d)
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	if got := applyDirectoryDomainAuthority(original, d); got.Terminal != "SealedDrained" {
		t.Fatal("active domain lost original positive")
	}
	if err := d.Fail(errors.New("later incompatible config")); err != nil {
		t.Fatal(err)
	}
	checkUnknown(d)
}
