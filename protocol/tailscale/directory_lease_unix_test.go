//go:build with_tailscale && (darwin || linux)

package tailscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func leaseTestRoot(t *testing.T) string {
	t.Helper()
	// Temp roots may themselves use /var or /tmp symlinks on macOS.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func directoryLeaseControlPath(t *testing.T, root string) string {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(root, &stat); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(root), fmt.Sprintf("%s%d-%d", directoryControlPrefix, uint64(stat.Dev), uint64(stat.Ino)))
}

func TestDirectoryLeaseCreatesManagedTarget(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if !lease.Managed || !validDirectoryNonce(lease.Incarnation) || !validDirectoryNonce(lease.Epoch) || !strings.HasPrefix(lease.Identity, "unix:") {
		t.Fatalf("invalid managed lease: %+v", lease)
	}
	content, err := os.ReadFile(filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var marker directoryLeaseMarker
	if err = json.Unmarshal(content, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Phase != "Open" || marker.DeleteIntentNonce != "" || marker.Incarnation != lease.Incarnation || marker.DirectoryEpoch != lease.Epoch {
		t.Fatalf("invalid marker: %+v", marker)
	}
	info, err := os.Stat(filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".lock"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode: info=%v err=%v", info, err)
	}
	second, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	if second.Identity != lease.Identity || second.Incarnation != lease.Incarnation || !second.Managed {
		t.Fatal("shared holder changed the incarnation")
	}
	if second.Epoch == lease.Epoch {
		t.Fatal("new shared owner reused an earlier owner's epoch")
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".lock")); err != nil {
		t.Fatal("Close removed the permanent lock:", err)
	}
}

func TestDirectoryLeaseNeverAdoptsLegacyTarget(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "legacy")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.Managed || lease.Incarnation != "" {
		t.Fatal("existing unmarked directory was adopted")
	}
	if _, err := os.Stat(filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("legacy")+".json")); !os.IsNotExist(err) {
		t.Fatalf("legacy marker created: %v", err)
	}
}

func TestDirectoryLeaseRejectsInvalidMarkerWithoutRewrite(t *testing.T) {
	for _, phase := range []string{"Retiring", "Removing", "Deleted", "Unknown"} {
		t.Run(phase, func(t *testing.T) {
			root := leaseTestRoot(t)
			target := filepath.Join(root, "server")
			lease, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			if err = lease.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var marker directoryLeaseMarker
			if err = json.Unmarshal(content, &marker); err != nil {
				t.Fatal(err)
			}
			marker.Phase = phase
			changed, _ := json.Marshal(marker)
			if err = os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := acquireDirectoryLease(target); err == nil {
				got.Close()
				t.Fatal("invalid phase admitted")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(changed) {
				t.Fatal("existing marker was rewritten")
			}
		})
	}
}

func TestDirectoryLeaseRejectsMalformedAndMismatchedMarkers(t *testing.T) {
	for _, mutate := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"version":1`, `"version":1,"version":1`, 1) },
		func(s string) string { return strings.Replace(s, `"rootInode":`, `"unknownField":`, 1) },
		func(s string) string {
			return strings.Replace(s, `"deleteIntentNonce":""`, `"deleteIntentNonce":null`, 1)
		},
		func(s string) string { return strings.Replace(s, `"serverId":"server"`, `"serverId":"other"`, 1) },
		func(s string) string { return s + "{}" },
	} {
		root := leaseTestRoot(t)
		target := filepath.Join(root, "server")
		lease, err := acquireDirectoryLease(target)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".json")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte(mutate(string(content))), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := acquireDirectoryLease(target); err == nil {
			got.Close()
			t.Fatal("malformed marker admitted")
		}
	}
}

func TestDirectoryLeaseRejectsSymlinks(t *testing.T) {
	for _, component := range []string{"root", "control", "lock", "admission", "marker", "target"} {
		t.Run(component, func(t *testing.T) {
			root := leaseTestRoot(t)
			target := filepath.Join(root, "server")
			outside := filepath.Join(root, "outside")
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			control := directoryLeaseControlPath(t, root)
			if component != "control" {
				if err := os.Mkdir(control, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			var link, destination string
			switch component {
			case "root":
				link, destination = filepath.Join(root, "alias"), outside
				target = filepath.Join(link, "server")
			case "control":
				link, destination = control, outside
			case "lock":
				link, destination = filepath.Join(control, directoryControlStem("server")+".lock"), filepath.Join(outside, "missing")
			case "admission":
				link, destination = filepath.Join(control, "root.admission.lock"), filepath.Join(outside, "missing")
			case "marker":
				link, destination = filepath.Join(control, directoryControlStem("server")+".json"), filepath.Join(outside, "missing")
			case "target":
				link, destination = target, outside
			}
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			if lease, err := acquireDirectoryLease(target); err == nil {
				lease.Close()
				t.Fatal("symlink admitted")
			}
		})
	}
}

func TestDirectoryLeaseDetectsLockReplacement(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".lock")
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err == nil {
		t.Fatal("lock replacement was not reported")
	}
	if lease.Close() == nil {
		t.Fatal("idempotent Close lost replacement error")
	}
}

// These subprocess tests are source only until explicitly authorized to run.
// A separate process matters: same-process lock tests are insufficient evidence.
func TestDirectoryLeaseProcessHelper(t *testing.T) {
	if os.Getenv("POLARIS_DIRECTORY_LEASE_HELPER") != "1" {
		return
	}
	path := os.Getenv("POLARIS_DIRECTORY_LEASE_PATH")
	if os.Getenv("POLARIS_DIRECTORY_LEASE_MODE") == "acquire" {
		lease, err := acquireDirectoryLease(path)
		if err != nil {
			os.Exit(73)
		}
		if lease.Close() != nil {
			os.Exit(74)
		}
		os.Exit(0)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		os.Exit(74)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			os.Exit(73)
		}
		os.Exit(74)
	}
	unix.Close(fd)
	os.Exit(0)
}

func directoryLeaseSubprocess(t *testing.T, mode, path string, wantExit int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestDirectoryLeaseProcessHelper$")
	command.Env = append(os.Environ(), "POLARIS_DIRECTORY_LEASE_HELPER=1", "POLARIS_DIRECTORY_LEASE_MODE="+mode, "POLARIS_DIRECTORY_LEASE_PATH="+path)
	output, err := command.CombinedOutput()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	if code != wantExit {
		t.Fatalf("subprocess exit=%d want=%d output=%s", code, wantExit, output)
	}
}

func TestDirectoryLeaseCrossProcessExclusion(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".lock")
	directoryLeaseSubprocess(t, "exclusive", lock, 73)
	directoryLeaseSubprocess(t, "acquire", target, 0)
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	directoryLeaseSubprocess(t, "exclusive", lock, 0)
	fd, err := unix.Open(lock, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	directoryLeaseSubprocess(t, "acquire", target, 73)
}

func TestDirectoryLeaseConflictPrecedesTargetCreation(t *testing.T) {
	root := leaseTestRoot(t)
	control := directoryLeaseControlPath(t, root)
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(control, directoryControlStem("server")+".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "server")
	directoryLeaseSubprocess(t, "acquire", target, 73)
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("conflicting acquisition created target: %v", err)
	}
	if _, err = os.Lstat(filepath.Join(control, directoryControlStem("server")+".json")); !os.IsNotExist(err) {
		t.Fatalf("conflicting acquisition created marker: %v", err)
	}
}

func TestDirectoryLeaseReplacedTargetRemainsLegacy(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".json")
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(target, target+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	if got.Managed || got.hasMarker || got.Incarnation != "" || got.Epoch != "" {
		t.Fatal("replacement inode inherited old incarnation")
	}
	if err = got.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(markerPath)
	if err != nil || string(after) != string(before) {
		t.Fatal("mismatched marker was changed:", err)
	}
}

func TestDirectoryLeaseRotatesEpochAcrossOwners(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	first, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch, incarnation, identity := first.Epoch, first.Incarnation, first.Identity
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Incarnation != incarnation || second.Identity != identity {
		t.Fatal("owner restart changed stable directory identity")
	}
	if !validDirectoryNonce(second.Epoch) || second.Epoch == oldEpoch {
		t.Fatal("owner restart did not invalidate the old epoch")
	}
	marker, missing, err := readDirectoryLeaseMarker(second.controlFD, directoryControlStem("server")+".json")
	if err != nil || missing {
		t.Fatalf("read current marker: missing=%v err=%v", missing, err)
	}
	if marker.DirectoryEpoch != second.Epoch || marker.DirectoryEpoch == oldEpoch {
		t.Fatal("old receipt epoch still matches current marker")
	}
	// Admission EX must be released after startup, while lifetime SH remains.
	directoryLeaseSubprocess(t, "exclusive", filepath.Join(directoryLeaseControlPath(t, root), "root.admission.lock"), 0)
	directoryLeaseSubprocess(t, "exclusive", filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".lock"), 73)
}

func TestDirectoryLeaseRequiresEpochField(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("server")+".json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(content, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "directoryEpoch")
	content, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(target); err == nil {
		got.Close()
		t.Fatal("marker without epoch was downgraded or accepted")
	}
}

func TestDirectoryLeaseDetectsAdmissionLockReplacement(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directoryLeaseControlPath(t, root), "root.admission.lock")
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err == nil {
		t.Fatal("admission lock replacement was not reported")
	}
}

func TestDirectoryLeaseAdmissionConflictPrecedesLifetime(t *testing.T) {
	root := leaseTestRoot(t)
	control := directoryLeaseControlPath(t, root)
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(control, "root.admission.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	directoryLeaseSubprocess(t, "acquire", filepath.Join(root, "server"), 73)
	if _, err = os.Lstat(filepath.Join(control, directoryControlStem("server")+".lock")); !os.IsNotExist(err) {
		t.Fatalf("lifetime touched before admission lock: %v", err)
	}
	if _, err = os.Lstat(filepath.Join(root, "server")); !os.IsNotExist(err) {
		t.Fatalf("target touched before admission lock: %v", err)
	}
}

func TestDirectoryControlStemSeparatesAdmissionNames(t *testing.T) {
	root := leaseTestRoot(t)
	first, err := acquireDirectoryLease(filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireDirectoryLease(filepath.Join(root, "a.admission"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.lockName == second.lockName || first.stem == second.stem || first.admissionName != second.admissionName {
		t.Fatal("control filenames collided")
	}
	if len(first.stem) != len("sha256-")+64 || !strings.HasPrefix(first.stem, "sha256-") {
		t.Fatalf("invalid control stem: %q", first.stem)
	}
	marker, missing, err := readDirectoryLeaseMarker(second.controlFD, second.stem+".json")
	if err != nil || missing || marker.ServerID != "a.admission" {
		t.Fatalf("marker lost original server ID: marker=%v missing=%v err=%v", marker, missing, err)
	}
}

func TestDirectoryLeaseAllowsFormerControlNameAsTarget(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, ".polaris-directory-control"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if !lease.Managed {
		t.Fatal("normal ID was downgraded")
	}
	if filepath.Dir(directoryLeaseControlPath(t, root)) != filepath.Dir(root) {
		t.Fatal("control directory was not placed outside the state root")
	}
}

func TestDirectoryLeaseCreatesMissingParentChain(t *testing.T) {
	base := leaseTestRoot(t)
	root := filepath.Join(base, "first", "second", "state-root")
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if !lease.Managed || !validDirectoryNonce(lease.Epoch) {
		t.Fatal("first launch did not initialize a managed target")
	}
	for _, directory := range []string{
		filepath.Join(base, "first"),
		filepath.Join(base, "first", "second"),
		root,
		target,
	} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("unsafe/missing created directory %q: info=%v err=%v", directory, info, err)
		}
	}
	var rootStat unix.Stat_t
	if err = unix.Stat(root, &rootStat); err != nil {
		t.Fatal(err)
	}
	if !sameDirectoryObject(&rootStat, &lease.rootStat) {
		t.Fatal("retained root identity does not match newly created parent")
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryLeaseMissingParentCreationRejectsSymlink(t *testing.T) {
	base := leaseTestRoot(t)
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(filepath.Join(alias, "new-root", "server")); err == nil {
		got.Close()
		t.Fatal("parent creation followed a symlink")
	}
	if _, err := os.Lstat(filepath.Join(outside, "new-root")); !os.IsNotExist(err) {
		t.Fatalf("parent creation escaped through symlink: %v", err)
	}
}

func TestDirectoryLeasePreservesNormalSpecialIDs(t *testing.T) {
	for _, serverID := range []string{"Foo", "SERVER", "café", "cafe\u0301", "Ｆoo", "space name", "plus+name", ".polaris-directory-control"} {
		t.Run(serverID, func(t *testing.T) {
			root := leaseTestRoot(t)
			lease, err := acquireDirectoryLease(filepath.Join(root, serverID))
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			if !lease.Managed || lease.markerOwner != serverID {
				t.Fatal("normal server ID changed or downgraded")
			}
		})
	}
	for _, serverID := range []string{"", ".", "..", "path/child", "bad\x00name"} {
		if validDirectoryServerID(serverID) {
			t.Fatalf("unsafe server ID accepted: %q", serverID)
		}
	}
}

func directoryLeaseAliasFixture(t *testing.T, original, alias string) (string, *directoryLease) {
	t.Helper()
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, original))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	var stat unix.Stat_t
	if err := unix.Stat(filepath.Join(root, alias), &stat); err != nil || !sameDirectoryObject(&stat, &lease.targetStat) {
		t.Skip("filesystem does not expose this case/Unicode alias")
	}
	return root, lease
}

func TestDirectoryLeaseFilesystemAliasesShareOwnerLock(t *testing.T) {
	for _, pair := range [][2]string{{"Alias", "alias"}, {"café", "café"}} {
		t.Run(pair[0], func(t *testing.T) {
			root, first := directoryLeaseAliasFixture(t, pair[0], pair[1])
			second, err := acquireDirectoryLease(filepath.Join(root, pair[1]))
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if second.Managed || !second.hasMarker || second.markerOwner != pair[0] {
				t.Fatal("alias did not retain canonical ownership without proof")
			}
			if second.lockName != first.lockName || second.Incarnation != first.Incarnation || second.Epoch == first.Epoch {
				t.Fatal("alias split lifetime locks or failed to invalidate the epoch")
			}
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			directoryLeaseSubprocess(t, "exclusive", filepath.Join(directoryLeaseControlPath(t, root), first.lockName), 73)
		})
	}
}

func TestDirectoryLeaseLegacyAliasesShareInodeLock(t *testing.T) {
	root := leaseTestRoot(t)
	if err := os.Mkdir(filepath.Join(root, "Legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := acquireDirectoryLease(filepath.Join(root, "Legacy"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var aliasStat unix.Stat_t
	if err = unix.Stat(filepath.Join(root, "legacy"), &aliasStat); err != nil || !sameDirectoryObject(&aliasStat, &first.targetStat) {
		t.Skip("filesystem is case sensitive")
	}
	second, err := acquireDirectoryLease(filepath.Join(root, "legacy"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Managed || second.Managed || first.hasMarker || second.hasMarker || first.lockName != second.lockName || !strings.HasPrefix(first.lockName, "legacy-") {
		t.Fatal("legacy alias split its inode lifetime lock")
	}
}

func TestDirectoryLeaseRejectsDuplicateLiveAliasMarkers(t *testing.T) {
	root, first := directoryLeaseAliasFixture(t, "Duplicate", "duplicate")
	marker, missing, err := readDirectoryLeaseMarker(first.controlFD, first.stem+".json")
	if err != nil || missing {
		t.Fatalf("read marker: missing=%v err=%v", missing, err)
	}
	marker.ServerID = "duplicate"
	content, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem(marker.ServerID)+".json")
	if err = os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(filepath.Join(root, "Duplicate")); err == nil {
		got.Close()
		t.Fatal("two markers for the same live inode were admitted")
	}
}

func TestDirectoryLeaseRejectsDeletedAlias(t *testing.T) {
	root, first := directoryLeaseAliasFixture(t, "Retired", "retired")
	marker, missing, err := readDirectoryLeaseMarker(first.controlFD, first.stem+".json")
	if err != nil || missing {
		t.Fatalf("read marker: missing=%v err=%v", missing, err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	marker.Phase = "Deleted"
	marker.DeleteIntentNonce = strings.Repeat("a", 32)
	content, _ := json.Marshal(marker)
	if err = os.WriteFile(filepath.Join(directoryLeaseControlPath(t, root), first.stem+".json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(filepath.Join(root, "retired")); err == nil {
		got.Close()
		t.Fatal("alias bypassed a Deleted marker")
	}
}

func TestDirectoryLeaseIgnoresUnrelatedRecycledTombstoneNumbers(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "live")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	marker, missing, err := readDirectoryLeaseMarker(lease.controlFD, lease.stem+".json")
	if err != nil || missing {
		t.Fatalf("read marker: missing=%v err=%v", missing, err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate inode-number recycling: numeric IDs match live, but the original
	// tombstone path is absent and must never be associated by numbers alone.
	marker.ServerID = "gone"
	marker.Phase = "Deleted"
	marker.DeleteIntentNonce = strings.Repeat("b", 32)
	content, _ := json.Marshal(marker)
	if err = os.WriteFile(filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("gone")+".json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, createUnrelatedPath := range []bool{false, true} {
		if createUnrelatedPath {
			if err = os.Mkdir(filepath.Join(root, "gone"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		current, err := acquireDirectoryLease(target)
		if err != nil {
			t.Fatal("unrelated tombstone blocked live target:", err)
		}
		if err = current.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDirectoryLeaseControlCorruptionFailsClosedAcrossRoot(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, "live"))
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directoryLeaseControlPath(t, root), directoryControlStem("corrupt")+".json")
	if err = os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(filepath.Join(root, "live")); err == nil {
		got.Close()
		t.Fatal("control corruption was silently ignored")
	}
}

func TestDirectoryLeaseStampRequiredForManagedEvidence(t *testing.T) {
	for _, stampState := range []string{"missing", "mismatched"} {
		t.Run(stampState, func(t *testing.T) {
			root := leaseTestRoot(t)
			target := filepath.Join(root, "server")
			first, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			incarnation := first.Incarnation
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			stampPath := filepath.Join(target, directoryIncarnationStamp)
			if stampState == "missing" {
				err = os.Remove(stampPath)
			} else {
				other := strings.Repeat("f", 32)
				if other == incarnation {
					other = strings.Repeat("e", 32)
				}
				err = os.WriteFile(stampPath, []byte(other+"\n"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			if legacy.Managed || legacy.hasMarker || legacy.Incarnation != "" || legacy.Epoch != "" || !strings.HasPrefix(legacy.lockName, "legacy-") {
				t.Fatal("missing/mismatched stamp produced managed evidence")
			}
			if err = legacy.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryLeaseStampWrittenBeforeMarkerAndNeverRepaired(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	stamp, valid, err := readDirectoryStamp(lease.targetFD)
	if err != nil || !valid || stamp != lease.Incarnation {
		t.Fatalf("initialized stamp invalid: valid=%v err=%v", valid, err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(directoryLeaseControlPath(t, root), lease.stem+".json")); err != nil {
		t.Fatal(err)
	}
	legacy, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if legacy.Managed || legacy.hasMarker {
		t.Fatal("stamp-only crash state was automatically adopted")
	}
	content, err := os.ReadFile(filepath.Join(target, directoryIncarnationStamp))
	if err != nil || string(content) != stamp+"\n" {
		t.Fatal("legacy stamp was rewritten")
	}
}

func TestDirectoryLeaseRetiredMarkerCannotBypassStamp(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	lease, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	marker, _, err := readDirectoryLeaseMarker(lease.controlFD, lease.stem+".json")
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	marker.Phase = "Retiring"
	marker.DeleteIntentNonce = strings.Repeat("c", 32)
	content, _ := json.Marshal(marker)
	if err = os.WriteFile(filepath.Join(directoryLeaseControlPath(t, root), lease.stem+".json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(target, directoryIncarnationStamp)); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(target); err == nil {
		got.Close()
		t.Fatal("Retiring marker downgraded after losing its stamp")
	}
}

func TestDirectoryLeaseRecreatesAbsentGeneration(t *testing.T) {
	for _, phase := range []string{"Open", "Deleted"} {
		t.Run(phase, func(t *testing.T) {
			root := leaseTestRoot(t)
			target := filepath.Join(root, "server")
			first, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			oldMarker, _, err := readDirectoryLeaseMarker(first.controlFD, first.stem+".json")
			if err != nil {
				t.Fatal(err)
			}
			oldIncarnation, oldEpoch := first.Incarnation, first.Epoch
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			if err = os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			if phase == "Deleted" {
				oldMarker.Phase = "Deleted"
				oldMarker.DeleteIntentNonce = strings.Repeat("d", 32)
				content, _ := json.Marshal(oldMarker)
				if err = os.WriteFile(filepath.Join(directoryLeaseControlPath(t, root), first.stem+".json"), content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			next, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if !next.Managed || next.Incarnation == oldIncarnation || next.Epoch == oldEpoch {
				t.Fatal("new generation reused old receipt identity")
			}
			stamp, valid, err := readDirectoryStamp(next.targetFD)
			if err != nil || !valid || stamp != next.Incarnation || stamp == oldIncarnation {
				t.Fatal("new generation did not receive a fresh target stamp")
			}
			current, missing, err := readDirectoryLeaseMarker(next.controlFD, next.stem+".json")
			if err != nil || missing || current.Phase != "Open" || current.DeleteIntentNonce != "" ||
				current.Incarnation == oldMarker.Incarnation || current.DirectoryEpoch == oldMarker.DirectoryEpoch {
				t.Fatalf("old proof/intent still matches new marker: missing=%v err=%v", missing, err)
			}
		})
	}
}

func TestDirectoryLeaseRecreationRequiresLifetimeExclusive(t *testing.T) {
	root := leaseTestRoot(t)
	target := filepath.Join(root, "server")
	first, err := acquireDirectoryLease(target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Simulate an external removal while an old owner still has lifetime SH.
	if err = os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if got, err := acquireDirectoryLease(target); err == nil {
		got.Close()
		t.Fatal("new generation bypassed an old live owner")
	}
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("target was created before obtaining lifetime EX: %v", err)
	}
}

func TestDirectoryLeaseRecreationRejectsPendingRemoval(t *testing.T) {
	for _, phase := range []string{"Retiring", "Removing", "Deleted"} {
		t.Run(phase, func(t *testing.T) {
			root := leaseTestRoot(t)
			target := filepath.Join(root, "server")
			lease, err := acquireDirectoryLease(target)
			if err != nil {
				t.Fatal(err)
			}
			marker, _, err := readDirectoryLeaseMarker(lease.controlFD, lease.stem+".json")
			if err != nil {
				t.Fatal(err)
			}
			if err = lease.Close(); err != nil {
				t.Fatal(err)
			}
			if err = os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			marker.Phase = phase
			marker.DeleteIntentNonce = strings.Repeat("e", 32)
			content, _ := json.Marshal(marker)
			control := directoryLeaseControlPath(t, root)
			if err = os.WriteFile(filepath.Join(control, lease.stem+".json"), content, 0o600); err != nil {
				t.Fatal(err)
			}
			if phase == "Deleted" {
				if err = os.Mkdir(filepath.Join(control, lease.stem+".retired-"+marker.Incarnation), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := acquireDirectoryLease(target); err == nil {
				got.Close()
				t.Fatal("pending removal/quarantine allowed generation replacement")
			}
			if _, err = os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("rejected recreation created target: %v", err)
			}
		})
	}
}

func TestDirectoryLeaseAliasRecreationWithOldOwnerStaysLegacy(t *testing.T) {
	for _, pair := range [][2]string{{"Owner", "owner"}, {"café", "café"}} {
		t.Run(pair[0], func(t *testing.T) {
			root, old := directoryLeaseAliasFixture(t, pair[0], pair[1])
			// The retained old target FD prevents inode reuse, while its owner
			// still holds SH and may continue opening files by the original path.
			if err := os.RemoveAll(filepath.Join(root, pair[0])); err != nil {
				t.Fatal(err)
			}
			current, err := acquireDirectoryLease(filepath.Join(root, pair[1]))
			if err != nil {
				t.Fatal(err)
			}
			if current.Managed || current.hasMarker || current.Incarnation != "" || current.Epoch != "" {
				t.Fatal("alias recreation bypassed the historical owner's lifetime SH")
			}
			if current.Identity == old.Identity {
				t.Fatal("fixture unexpectedly reused the retained old inode")
			}
			if _, valid, err := readDirectoryStamp(current.targetFD); err != nil || valid {
				t.Fatalf("busy historical owner allowed a new incarnation stamp: %v", err)
			}
			if _, missing, err := readDirectoryLeaseMarker(current.controlFD, directoryControlStem(pair[1])+".json"); err != nil || !missing {
				t.Fatalf("busy historical owner allowed a new alias marker: %v", err)
			}
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
			_ = old.Close() // Its original inode is deliberately no longer at the path.
			reopened, err := acquireDirectoryLease(filepath.Join(root, pair[1]))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if reopened.Managed || reopened.hasMarker {
				t.Fatal("unmarked fallback was later adopted")
			}
		})
	}
}

func TestDirectoryLeaseUnrelatedManagedOwnerDoesNotBlockNewNode(t *testing.T) {
	root := leaseTestRoot(t)
	first, err := acquireDirectoryLease(filepath.Join(root, "first"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireDirectoryLease(filepath.Join(root, "second"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if !second.Managed || second.lockName == first.lockName {
		t.Fatal("unrelated live managed owner prevented independent managed creation")
	}
}

func TestDirectoryLeaseLegacyOwnerPreventsNewPositiveProof(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			root := leaseTestRoot(t)
			legacyPath := filepath.Join(root, "legacy")
			if err := os.Mkdir(legacyPath, 0o700); err != nil {
				t.Fatal(err)
			}
			old, err := acquireDirectoryLease(legacyPath)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			if !active {
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
			}
			created, err := acquireDirectoryLease(filepath.Join(root, "new-node"))
			if err != nil {
				t.Fatal(err)
			}
			defer created.Close()
			if created.Managed == active || created.hasMarker == active {
				t.Fatal("new generation ignored the legacy lifetime barrier")
			}
			_, valid, err := readDirectoryStamp(created.targetFD)
			if err != nil || valid == active {
				t.Fatalf("legacy barrier produced incorrect stamp state: %v", err)
			}
		})
	}
}

func TestDirectoryLeaseDrainedHistoricalAliasAllowsFreshGeneration(t *testing.T) {
	for _, pair := range [][2]string{{"Previous", "previous"}, {"café", "café"}} {
		t.Run(pair[0], func(t *testing.T) {
			root, old := directoryLeaseAliasFixture(t, pair[0], pair[1])
			// Move instead of delete so the old inode stays allocated and the
			// historical marker necessarily differs from the new target inode.
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(root, pair[0]), filepath.Join(root, "displaced-generation")); err != nil {
				t.Fatal(err)
			}
			next, err := acquireDirectoryLease(filepath.Join(root, pair[1]))
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if !next.Managed || next.Incarnation == old.Incarnation || next.Epoch == old.Epoch || next.Identity == old.Identity {
				t.Fatal("drained historical alias prevented a fresh managed generation")
			}
		})
	}
}

func TestDirectoryLeaseMetadataReadReportsCloseFailure(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	closeFailure := errors.New("injected metadata close failure")
	closeFile := func(file *os.File) error {
		return errors.Join(file.Close(), closeFailure)
	}
	if _, _, err := readDirectoryLeaseMarkerWithClose(lease.controlFD, lease.stem+".json", closeFile); !errors.Is(err, closeFailure) {
		t.Fatalf("successful marker read hid close failure: %v", err)
	}
	if _, _, err := readDirectoryStampWithClose(lease.targetFD, closeFile); !errors.Is(err, closeFailure) {
		t.Fatalf("successful stamp read hid close failure: %v", err)
	}
	// Even a nonmatching stamp (normally legacy/no-proof) must preserve the
	// close failure so admission cannot silently downgrade an uncertain read.
	if err := os.WriteFile(filepath.Join(root, "server", directoryIncarnationStamp), []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := readDirectoryStampWithClose(lease.targetFD, closeFile); valid || !errors.Is(err, closeFailure) {
		t.Fatalf("invalid stamp hid close failure: valid=%v err=%v", valid, err)
	}
	if err := lease.Close(); err == nil {
		t.Fatal("changed stamp did not fail the aggregate lease close")
	}
}

func TestMappedDirectoryPreservesExistingLogicalData(t *testing.T) {
	base := leaseTestRoot(t)
	logical := filepath.Join(base, "tailscale", "server")
	physical := filepath.Join(base, "tailscale-g4-v1", "server")
	if err := os.MkdirAll(logical, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logical, "state"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	actual, lease, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if actual != logical || lease.Managed {
		t.Fatal("existing logical state was migrated or adopted")
	}
	if _, err := os.Lstat(physical); !os.IsNotExist(err) {
		t.Fatalf("physical target unexpectedly created: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(logical, "state"))
	if err != nil || string(content) != "existing" {
		t.Fatal("logical state changed")
	}
}

func TestMappedDirectoryCreatesStablePhysicalGeneration(t *testing.T) {
	base := leaseTestRoot(t)
	logical := filepath.Join(base, "tailscale", "server")
	physical := filepath.Join(base, "tailscale-g4-v1", "server")
	actual, first, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		t.Fatal(err)
	}
	if actual != physical || !first.Managed {
		t.Fatal("new endpoint did not select managed physical state")
	}
	incarnation := first.Incarnation
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	actual, second, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if actual != physical || !second.Managed || second.Incarnation != incarnation {
		t.Fatal("physical generation was not stable")
	}
	if _, err := os.Lstat(logical); !os.IsNotExist(err) {
		t.Fatalf("new logical target was created: %v", err)
	}
}

func TestMappedDirectorySelectionRequiresLogicalAdmission(t *testing.T) {
	base := leaseTestRoot(t)
	logical := filepath.Join(base, "tailscale", "server")
	physical := filepath.Join(base, "tailscale-g4-v1", "server")
	admission, err := openDirectoryAdmission(filepath.Dir(logical))
	if err != nil {
		t.Fatal(err)
	}
	defer admission.releaseFDs()
	if _, lease, err := acquireMappedDirectory(logical, physical); err == nil {
		lease.Close()
		t.Fatal("mapping choice bypassed logical admission")
	}
	if _, err := os.Lstat(physical); !os.IsNotExist(err) {
		t.Fatalf("target created before selection lock: %v", err)
	}
}

func TestDirectoryDomainPoisonRevokesExistingAndFutureProof(t *testing.T) {
	root := leaseTestRoot(t)
	old, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PoisonDirectoryDomain(root); err != nil {
		t.Fatal(err)
	}
	if err := PoisonDirectoryDomain(root); err != nil {
		t.Fatal("poison must be idempotent:", err)
	}
	if err := old.Close(); err == nil {
		t.Fatal("old owner closed successfully after durable domain revocation")
	}
	for _, name := range []string{"server", "new-server"} {
		lease, err := acquireDirectoryLease(filepath.Join(root, name))
		if err != nil {
			t.Fatal("poisoned domain must retain connection compatibility:", err)
		}
		if lease.Managed {
			t.Fatal("poisoned domain minted positive evidence")
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(filepath.Join(directoryLeaseControlPath(t, root), ".domain-unsafe"))
	if err != nil || string(content) != "unsafe\n" {
		t.Fatal("durable unsafe marker missing")
	}
}

func TestDirectoryDomainPoisonRequiresAdmission(t *testing.T) {
	root := leaseTestRoot(t)
	admission, err := openDirectoryAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.releaseFDs()
	if err := PoisonDirectoryDomain(root); err == nil {
		t.Fatal("poison bypassed root admission")
	}
	if _, err := os.Lstat(filepath.Join(directoryLeaseControlPath(t, root), ".domain-unsafe")); !os.IsNotExist(err) {
		t.Fatalf("poison wrote before acquiring admission: %v", err)
	}
}

func TestDirectoryDomainPoisonSentinelNeverFollowsSymlink(t *testing.T) {
	root := leaseTestRoot(t)
	lease, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directoryLeaseControlPath(t, root), ".domain-unsafe")); err != nil {
		t.Fatal(err)
	}
	if err := PoisonDirectoryDomain(root); err == nil {
		t.Fatal("poison followed unsafe sentinel symlink")
	}
	current, err := acquireDirectoryLease(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if current.Managed {
		t.Fatal("malformed poison sentinel allowed positive evidence")
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "unchanged" {
		t.Fatal("poison modified symlink destination")
	}
}
