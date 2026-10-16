//go:build with_tailscale && (darwin || linux)

package tailscale

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The control directory and lock are permanent protocol anchors. Neither side
// may unlink/replace them, including after target deletion. This is cooperative
// exclusion, not protection against a malicious process with the same UID.
const directoryControlPrefix = ".polaris-directory-control-"
const directoryIncarnationStamp = ".polaris-directory-incarnation"

type directoryLease struct {
	Identity    string
	Incarnation string
	Epoch       string
	Managed     bool

	rootPath       string
	stem           string
	markerOwner    string
	hasMarker      bool
	lockName       string
	admissionName  string
	admissionFD    int
	admissionStat  unix.Stat_t
	targetName     string
	targetFD       int
	targetStat     unix.Stat_t
	rootFD         int
	controlFD      int
	controlName    string
	rootParentFD   int
	rootParentStat unix.Stat_t
	lockFD         int
	rootStat       unix.Stat_t
	controlStat    unix.Stat_t
	lockStat       unix.Stat_t
	closeOnce      sync.Once
	closeErr       error
}

type directoryLeaseMarker struct {
	Version           int    `json:"version"`
	ServerID          string `json:"serverId"`
	Incarnation       string `json:"incarnation"`
	DirectoryEpoch    string `json:"directoryEpoch"`
	RootDevice        uint64 `json:"rootDevice"`
	RootInode         uint64 `json:"rootInode"`
	DirectoryDevice   uint64 `json:"directoryDevice"`
	DirectoryInode    uint64 `json:"directoryInode"`
	Phase             string `json:"phase"`
	DeleteIntentNonce string `json:"deleteIntentNonce"`
}

// A server ID is a single UTF-8 basename. Case and Unicode are preserved;
// filesystem aliases are resolved to a shared lifetime lock under root admission.
func validDirectoryServerID(serverID string) bool {
	return serverID != "" && serverID != "." && serverID != ".." &&
		utf8.ValidString(serverID) &&
		!strings.ContainsRune(serverID, 0) && !strings.ContainsRune(serverID, '/') &&
		filepath.Base(serverID) == serverID
}

// Hash the exact UTF-8 basename for managed marker and lifetime filenames.
func directoryControlStem(serverID string) string {
	sum := sha256.Sum256([]byte(serverID))
	return "sha256-" + hex.EncodeToString(sum[:])
}

func directoryIdentity(root, directory *unix.Stat_t) string {
	return fmt.Sprintf("unix:%d:%d:%d:%d", uint64(root.Dev), uint64(root.Ino), uint64(directory.Dev), uint64(directory.Ino))
}

func sameDirectoryObject(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT
}

func validDirectoryNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// openDirectoryPath traverses every absolute component relative to an already
// opened directory. No symlink in the root path is followed.
func openDirectoryPath(path string) (int, error) {
	return openDirectoryPathWithCreate(path, false)
}

// createDirectoryPath may create only the preconfigured parent chain. Target
// creation remains behind admission EX and lifetime EX in acquireDirectoryLease.
func createDirectoryPath(path string) (int, error) {
	return openDirectoryPathWithCreate(path, true)
}

func openDirectoryPathWithCreate(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("directory lease: root is not absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if create && errors.Is(openErr, unix.ENOENT) {
			// Both mkdir and the subsequent open are relative to the retained
			// parent FD. A racing symlink is rejected by O_NOFOLLOW, including
			// one that appears after mkdir reports EEXIST.
			mkdirErr := unix.Mkdirat(fd, component, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, mkdirErr
			}
			next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr == nil {
				if syncErr := errors.Join(unix.Fsync(next), unix.Fsync(fd)); syncErr != nil {
					unix.Close(next)
					unix.Close(fd)
					return -1, syncErr
				}
			}
		}
		closeErr := unix.Close(fd)
		if err := errors.Join(openErr, closeErr); err != nil {
			if next >= 0 {
				err = errors.Join(err, unix.Close(next))
			}
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// acquireDirectoryLease must precede ANY target-directory mkdir or IO.
// Missing components of the configured parent chain are created via nofollow
// directory FDs. Only a missing target under an exclusive lock can be initialized
// as managed; existing unmarked directories stay legacy.
func acquireDirectoryLease(directory string) (*directoryLease, error) {
	return acquireDirectoryLeaseSelected(directory, nil)
}

func acquireDirectoryLeaseSelected(directory string, admission *directoryLease) (_ *directoryLease, err error) {
	rawBase := strings.TrimRight(directory, "/")
	rawBase = rawBase[strings.LastIndexByte(rawBase, '/')+1:]
	if !validDirectoryServerID(rawBase) {
		return nil, fmt.Errorf("directory lease: invalid target basename")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	serverID, root := filepath.Base(absolute), filepath.Dir(absolute)
	if absolute == root || !validDirectoryServerID(serverID) {
		return nil, fmt.Errorf("directory lease: invalid server directory")
	}
	lease := admission
	if lease == nil {
		lease, err = openDirectoryAdmission(root)
		if err != nil {
			return nil, err
		}
	} else if lease.rootPath != root {
		return nil, fmt.Errorf("directory lease: admission root mismatch")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lease.releaseFDs())
		}
	}()
	lease.targetName = serverID
	rootFD := lease.rootFD
	lease.targetFD, err = unix.Openat(rootFD, serverID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	missingTarget := errors.Is(err, unix.ENOENT)
	if err != nil && !missingTarget {
		return nil, fmt.Errorf("directory lease: open target: %w", err)
	}
	if missingTarget {
		// Distinguish absence from a dangling symlink before any mkdir.
		var observed unix.Stat_t
		if statErr := unix.Fstatat(rootFD, serverID, &observed, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
			return nil, fmt.Errorf("directory lease: target is not absent")
		}
	} else if err = unix.Fstat(lease.targetFD, &lease.targetStat); err != nil {
		return nil, err
	}
	// Scan under root admission even on first launch. Corrupt candidate markers
	// fail closed across the root; normal unrelated IDs and tombstones do not.
	marker, err := lease.findMarker(!missingTarget)
	if err != nil {
		return nil, err
	}
	var replacedMarker *directoryLeaseMarker
	if missingTarget {
		replacedMarker = marker
		lease.stem = directoryControlStem(serverID)
		lease.lockName = lease.stem + ".lock"
	} else if marker != nil {
		lease.stem = directoryControlStem(marker.ServerID)
		lease.markerOwner = marker.ServerID
		lease.hasMarker = true
		lease.lockName = lease.stem + ".lock"
	} else {
		// Unmarked aliases share one inode lock and remain permanently legacy.
		lease.lockName = fmt.Sprintf("legacy-%d-%d.lock", uint64(lease.targetStat.Dev), uint64(lease.targetStat.Ino))
	}
	lease.lockFD, lease.lockStat, err = openDirectoryLock(lease.controlFD, lease.lockName)
	if err != nil {
		return nil, err
	}
	lockMode := unix.LOCK_SH
	if missingTarget {
		lockMode = unix.LOCK_EX
	}
	if err = unix.Flock(lease.lockFD, lockMode|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("directory lease: lifetime lock busy: %w", err)
	}
	if err = errors.Join(unix.Fsync(lease.lockFD), unix.Fsync(lease.controlFD), unix.Fsync(lease.rootParentFD), unix.Fsync(rootFD)); err != nil {
		return nil, err
	}
	if err = lease.checkAnchors(); err != nil {
		return nil, err
	}
	if missingTarget {
		// Crash before marker publication leaves legacy data; never adopt it.
		if err = unix.Mkdirat(rootFD, serverID, 0o700); err != nil {
			return nil, fmt.Errorf("directory lease: initialize target: %w", err)
		}
		lease.targetFD, err = unix.Openat(rootFD, serverID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		if err = unix.Fstat(lease.targetFD, &lease.targetStat); err != nil {
			return nil, err
		}
		// A tombstone's original spelling may now resolve to the new inode on
		// a case-insensitive filesystem. Reject that ambiguity before publish.
		var previous *directoryLeaseMarker
		// Resolve historical aliases by their current paths, even when the
		// marker describes a different inode. An old owner can still write by
		// that path. Do not publish a stamp or managed generation until every
		// related old lifetime lock is exclusive. Unrelated owners are untouched.
		var historicalFDs []int
		blocked := false
		defer func() {
			for _, fd := range historicalFDs {
				_ = unix.Close(fd)
			}
		}()
		previous, err = lease.findMarkerSkipping(true, replacedMarker, &historicalFDs, &blocked)
		if err != nil {
			return nil, err
		}
		if previous != nil {
			return nil, fmt.Errorf("directory lease: new target aliases an existing marker")
		}
		if err = lease.holdLegacyCreationBarrier(&historicalFDs, &blocked); err != nil {
			return nil, err
		}
		if blocked {
			// An old path-writing owner may have reached this new directory.
			// Keep it unmarked forever instead of manufacturing positive proof.
			// A Deleted tombstone cannot be bypassed by legacy admission.
			if replacedMarker != nil && replacedMarker.Phase == "Deleted" {
				return nil, fmt.Errorf("directory lease: historical owner blocks deleted generation recreation")
			}
			if err = unix.Close(lease.lockFD); err != nil {
				lease.lockFD = -1
				return nil, err
			}
			lease.lockFD = -1
			lease.stem = ""
			lease.lockName = fmt.Sprintf("legacy-%d-%d.lock", uint64(lease.targetStat.Dev), uint64(lease.targetStat.Ino))
			// Release temporary barriers before opening the inode lock again:
			// a recycled inode may use one of those same permanent lock names.
			for _, fd := range historicalFDs {
				if closeErr := unix.Close(fd); closeErr != nil {
					err = errors.Join(err, closeErr)
				}
			}
			historicalFDs = nil
			if err != nil {
				return nil, err
			}
			lease.lockFD, lease.lockStat, err = openDirectoryLock(lease.controlFD, lease.lockName)
			if err != nil {
				return nil, err
			}
			if err = errors.Join(unix.Fsync(lease.lockFD), unix.Fsync(lease.controlFD), unix.Fsync(rootFD)); err != nil {
				return nil, err
			}
			marker = nil
		} else {
			marker, err = lease.initializeMarker(serverID, replacedMarker)
			if err != nil {
				return nil, err
			}
			lease.markerOwner, lease.hasMarker = serverID, true
		}
		// Drop temporary barriers while root admission is still exclusive.
		// No other startup should mistake these short-lived EX holds for a
		// live historical writer and unnecessarily fall back to legacy.
		for _, fd := range historicalFDs {
			err = errors.Join(err, unix.Close(fd))
		}
		historicalFDs = nil
		if err != nil {
			return nil, err
		}
	} else if marker != nil {
		var epoch string
		for epoch == "" || epoch == marker.DirectoryEpoch {
			epoch, err = newDirectoryNonce()
			if err != nil {
				return nil, err
			}
		}
		marker.DirectoryEpoch = epoch
		if err = lease.publishMarker(marker, true); err != nil {
			return nil, err
		}
	}
	lease.Identity = directoryIdentity(&lease.rootStat, &lease.targetStat)
	if marker != nil {
		lease.Incarnation, lease.Epoch = marker.Incarnation, marker.DirectoryEpoch
		// Alias owners invalidate prior receipts but do not issue their own.
		lease.Managed = marker.ServerID == serverID
	}
	poisoned, poisonErr := lease.domainUnsafe()
	if poisonErr != nil {
		return nil, poisonErr
	}
	if poisoned {
		lease.Managed = false
	}
	if err = lease.share(); err != nil {
		return nil, err
	}
	return lease, nil
}

// Legacy locks carry only inode identity, not the paths retained by their
// owners. Hold every old legacy lock EX before publishing a new stamp. A busy
// legacy owner downgrades only the new target to legacy; existing nodes continue.
func (l *directoryLease) holdLegacyCreationBarrier(fds *[]int, blocked *bool) error {
	fd, err := unix.Openat(l.controlFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), l.controlName)
	entries, readErr := directory.ReadDir(-1)
	if err = errors.Join(readErr, directory.Close()); err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "legacy-") || !strings.HasSuffix(name, ".lock") {
			continue
		}
		// Reject malformed protocol lock names rather than omitting a possible
		// owner from the creation barrier.
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "legacy-"), ".lock"), "-")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("directory lease: invalid legacy lock name")
		}
		for _, part := range parts {
			for _, c := range part {
				if c < '0' || c > '9' {
					return fmt.Errorf("directory lease: invalid legacy lock identity")
				}
			}
		}
		lockFD, held, err := openDirectoryLock(l.controlFD, name)
		if err != nil {
			return err
		}
		*fds = append(*fds, lockFD)
		if err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
				return err
			}
			*blocked = true
		}
		var current unix.Stat_t
		if err = unix.Fstatat(l.controlFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameDirectoryObject(&held, &current) || current.Nlink != 1 {
			return fmt.Errorf("directory lease: legacy barrier lock replaced")
		}
	}
	return nil
}

// openDirectoryAdmission returns a retained root-wide EX admission. Its caller
// must either hand it to acquisition or close every FD before returning.
func openDirectoryAdmission(root string) (_ *directoryLease, err error) {
	rootFD, err := createDirectoryPath(root)
	if err != nil {
		return nil, fmt.Errorf("directory lease: open root: %w", err)
	}
	lease := &directoryLease{
		rootPath: root, rootFD: rootFD, rootParentFD: -1, controlFD: -1, lockFD: -1,
		targetFD: -1, admissionFD: -1,
		admissionName: "root.admission.lock",
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lease.releaseFDs())
		}
	}()
	if err = unix.Fstat(rootFD, &lease.rootStat); err != nil {
		return nil, err
	}
	lease.rootParentFD, err = openDirectoryPath(filepath.Dir(root))
	if err != nil {
		return nil, err
	}
	if err = unix.Fstat(lease.rootParentFD, &lease.rootParentStat); err != nil {
		return nil, err
	}
	lease.controlName = fmt.Sprintf("%s%d-%d", directoryControlPrefix, uint64(lease.rootStat.Dev), uint64(lease.rootStat.Ino))
	if err = unix.Mkdirat(lease.rootParentFD, lease.controlName, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("directory lease: create control directory: %w", err)
	}
	lease.controlFD, err = unix.Openat(lease.rootParentFD, lease.controlName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("directory lease: open control directory: %w", err)
	}
	if err = unix.Fstat(lease.controlFD, &lease.controlStat); err != nil {
		return nil, err
	}
	if sameDirectoryObject(&lease.controlStat, &lease.rootStat) {
		return nil, fmt.Errorf("directory lease: control directory aliases state root")
	}
	// All participants take this root-wide admission EX before resolving a
	// lifetime lock. Thus differently spelled filesystem aliases cannot race.
	lease.admissionFD, lease.admissionStat, err = openDirectoryLock(lease.controlFD, lease.admissionName)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(lease.admissionFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("directory lease: owner admission busy: %w", err)
	}
	if err = errors.Join(unix.Fsync(lease.admissionFD), unix.Fsync(lease.controlFD), unix.Fsync(lease.rootParentFD), unix.Fsync(rootFD)); err != nil {
		return nil, err
	}
	if err = lease.checkAnchors(); err != nil {
		return nil, err
	}
	return lease, nil
}

func openDirectoryLock(controlFD int, name string) (int, unix.Stat_t, error) {
	var stat unix.Stat_t
	fd, err := unix.Openat(controlFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return -1, stat, err
	}
	if err = unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		unix.Close(fd)
		return -1, stat, fmt.Errorf("directory lease: lock must be a single-link 0600 regular file")
	}
	return fd, stat, nil
}

func isDirectoryMarkerName(name string) bool {
	const prefix, suffix = "sha256-", ".json"
	if len(name) != len(prefix)+64+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	for _, c := range name[len(prefix) : len(name)-len(suffix)] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// findMarker reads only fd-relative/no-follow metadata while root admission is
// held. Inode numbers alone cannot associate a tombstone with a new directory:
// the marker's original basename must currently resolve to the same live inode.
func (l *directoryLease) findMarker(targetExists bool) (*directoryLeaseMarker, error) {
	return l.findMarkerSkipping(targetExists, nil, nil, nil)
}

// skip is permitted only while reinitializing a genuinely absent target under
// root admission EX plus its original lifetime EX. It must match byte-for-byte
// decoded metadata observed before mkdir; no other marker is ignored.
func (l *directoryLease) findMarkerSkipping(targetExists bool, skip *directoryLeaseMarker, historicalFDs *[]int, blocked *bool) (*directoryLeaseMarker, error) {
	fd, err := unix.Openat(l.controlFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), l.controlName)
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	var selected *directoryLeaseMarker
	liveMarkers := 0
	for _, entry := range entries {
		name := entry.Name()
		if !isDirectoryMarkerName(name) {
			continue
		}
		marker, missing, err := readDirectoryLeaseMarker(l.controlFD, name)
		if err != nil || missing {
			return nil, fmt.Errorf("directory lease: corrupt/disappeared control marker %q: %v", name, err)
		}
		if marker.Version != 1 || !validDirectoryServerID(marker.ServerID) ||
			name != directoryControlStem(marker.ServerID)+".json" ||
			!validDirectoryNonce(marker.Incarnation) || !validDirectoryNonce(marker.DirectoryEpoch) ||
			marker.RootDevice != uint64(l.rootStat.Dev) || marker.RootInode != uint64(l.rootStat.Ino) ||
			(marker.Phase != "Open" && marker.Phase != "Retiring" && marker.Phase != "Removing" && marker.Phase != "Deleted") ||
			(marker.Phase == "Open" && marker.DeleteIntentNonce != "") ||
			(marker.DeleteIntentNonce != "" && !validDirectoryNonce(marker.DeleteIntentNonce)) {
			return nil, fmt.Errorf("directory lease: invalid control marker %q", name)
		}
		exact := name == directoryControlStem(l.targetName)+".json"
		if exact && skip != nil {
			if *marker != *skip {
				return nil, fmt.Errorf("directory lease: generation marker changed during admission")
			}
			if err := l.requireAbsentQuarantine(marker); err != nil {
				return nil, err
			}
			continue
		}
		if exact && !targetExists {
			if marker.Phase != "Open" && marker.Phase != "Deleted" {
				return nil, fmt.Errorf("directory lease: requested generation is still retiring")
			}
			if err := l.requireAbsentQuarantine(marker); err != nil {
				return nil, err
			}
			// Re-creation is not adoption: caller must still obtain lifetime
			// EX, mkdir a new target and generate a new stamp/incarnation.
			selected = marker
			continue
		}
		if exact && marker.Phase != "Open" {
			return nil, fmt.Errorf("directory lease: requested marker is retired")
		}
		originalFD, openErr := unix.Openat(l.rootFD, marker.ServerID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if exact {
				return nil, fmt.Errorf("directory lease: requested marker path is missing")
			}
			continue
		}
		if openErr != nil {
			return nil, fmt.Errorf("directory lease: unsafe original marker path: %w", openErr)
		}
		var original unix.Stat_t
		statErr := unix.Fstat(originalFD, &original)
		closeErr := unix.Close(originalFD)
		if err = errors.Join(statErr, closeErr); err != nil {
			return nil, err
		}
		sameLiveTarget := targetExists && sameDirectoryObject(&original, &l.targetStat)
		if !sameLiveTarget {
			if exact {
				return nil, fmt.Errorf("directory lease: requested marker target changed")
			}
			continue
		}
		if marker.Phase != "Open" {
			return nil, fmt.Errorf("directory lease: target aliases a retired directory")
		}
		if historicalFDs != nil {
			name := directoryControlStem(marker.ServerID) + ".lock"
			if name != l.lockName {
				fd, held, lockErr := openDirectoryLock(l.controlFD, name)
				if lockErr != nil {
					return nil, lockErr
				}
				*historicalFDs = append(*historicalFDs, fd)
				if lockErr = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); lockErr != nil {
					// Keep the newly created directory unmarked. Never remove it:
					// the old owner may already have written through this alias.
					if !errors.Is(lockErr, unix.EWOULDBLOCK) && !errors.Is(lockErr, unix.EAGAIN) {
						return nil, lockErr
					}
					*blocked = true
				}
				var current unix.Stat_t
				if lockErr = unix.Fstatat(l.controlFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); lockErr != nil {
					return nil, lockErr
				}
				if !sameDirectoryObject(&held, &current) || current.Nlink != 1 {
					return nil, fmt.Errorf("directory lease: historical alias lock replaced")
				}
			}
		}
		if marker.DirectoryDevice != uint64(original.Dev) || marker.DirectoryInode != uint64(original.Ino) {
			// An existing unmarked replacement remains usable as legacy.
			// Never transplant the old marker's identity to this inode.
			continue
		}
		liveMarkers++
		if liveMarkers > 1 {
			return nil, fmt.Errorf("directory lease: multiple markers claim one live inode")
		}
		stamp, valid, stampErr := readDirectoryStamp(l.targetFD)
		if stampErr != nil {
			return nil, stampErr
		}
		if !valid || stamp != marker.Incarnation {
			// Inode reuse cannot revive an old receipt: the target-owned
			// incarnation stamp must also match before any managed claim.
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("directory lease: multiple markers own one live directory")
		}
		selected = marker
	}
	return selected, nil
}

func (l *directoryLease) requireAbsentQuarantine(marker *directoryLeaseMarker) error {
	name := directoryControlStem(marker.ServerID) + ".retired-" + marker.Incarnation
	var stat unix.Stat_t
	err := unix.Fstatat(l.controlFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("directory lease: inspect previous quarantine: %w", err)
	}
	return fmt.Errorf("directory lease: previous generation quarantine still exists")
}

func readDirectoryLeaseMarker(controlFD int, name string) (*directoryLeaseMarker, bool, error) {
	return readDirectoryLeaseMarkerWithClose(controlFD, name, (*os.File).Close)
}

func readDirectoryLeaseMarkerWithClose(controlFD int, name string, closeFile func(*os.File) error) (_ *directoryLeaseMarker, _ bool, resultErr error) {
	fd, err := unix.Openat(controlFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("directory lease: open marker: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { resultErr = errors.Join(resultErr, closeFile(file)) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size > 16<<10 {
		return nil, false, fmt.Errorf("directory lease: unsafe marker")
	}
	// Decode into raw fields first to require the complete protocol shape.
	// A streaming token pass also rejects duplicate keys.
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10+1))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false, fmt.Errorf("directory lease: marker must be a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, false, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, false, fmt.Errorf("directory lease: invalid marker key")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, false, fmt.Errorf("directory lease: duplicate marker key")
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return nil, false, err
		}
		fields[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, false, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return nil, false, fmt.Errorf("directory lease: trailing marker data")
	}
	expected := []string{"version", "serverId", "incarnation", "directoryEpoch", "rootDevice", "rootInode", "directoryDevice", "directoryInode", "phase", "deleteIntentNonce"}
	if len(fields) != len(expected) {
		return nil, false, fmt.Errorf("directory lease: unexpected marker fields")
	}
	for _, key := range expected {
		value, exists := fields[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false, fmt.Errorf("directory lease: missing/null marker field %s", key)
		}
	}
	content, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	var marker directoryLeaseMarker
	if err = json.Unmarshal(content, &marker); err != nil {
		return nil, false, err
	}
	return &marker, false, nil
}

func (l *directoryLease) checkAnchors() (resultErr error) {
	var current unix.Stat_t
	if err := unix.Fstatat(l.controlFD, l.admissionName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("directory lease: admission lock disappeared: %w", err)
	}
	if !sameDirectoryObject(&current, &l.admissionStat) || current.Nlink != 1 || current.Mode&0o777 != 0o600 {
		return fmt.Errorf("directory lease: permanent admission lock replaced or changed")
	}
	if l.Managed {
		poisoned, err := l.domainUnsafe()
		if err != nil {
			return err
		}
		if poisoned {
			return fmt.Errorf("directory lease: directory domain is unsafe")
		}
	}
	if l.targetFD >= 0 {
		if l.hasMarker && l.Incarnation != "" {
			stamp, valid, err := readDirectoryStamp(l.targetFD)
			if err != nil {
				return err
			}
			if !valid || stamp != l.Incarnation {
				return fmt.Errorf("directory lease: incarnation stamp changed")
			}
		}
		if err := unix.Fstatat(l.rootFD, l.targetName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameDirectoryObject(&current, &l.targetStat) {
			return fmt.Errorf("directory lease: target directory replaced")
		}
	}
	if l.lockFD >= 0 {
		if err := unix.Fstatat(l.controlFD, l.lockName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("directory lease: lock disappeared: %w", err)
		}
		if !sameDirectoryObject(&current, &l.lockStat) || current.Nlink != 1 || current.Mode&0o777 != 0o600 {
			return fmt.Errorf("directory lease: permanent lock replaced or changed")
		}
	}
	if err := unix.Fstatat(l.rootParentFD, l.controlName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameDirectoryObject(&current, &l.controlStat) {
		return fmt.Errorf("directory lease: control directory replaced")
	}
	parentFD, err := openDirectoryPath(filepath.Dir(l.rootPath))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parentFD)) }()
	if err := unix.Fstat(parentFD, &current); err != nil {
		return err
	}
	if !sameDirectoryObject(&current, &l.rootParentStat) {
		return fmt.Errorf("directory lease: root parent replaced")
	}
	rootFD, err := openDirectoryPath(l.rootPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(rootFD)) }()
	if err := unix.Fstat(rootFD, &current); err != nil {
		return err
	}
	if !sameDirectoryObject(&current, &l.rootStat) {
		return fmt.Errorf("directory lease: root replaced")
	}
	return nil
}

// Close is idempotent and releases only the shared flock/FDs. The caller must
// first establish its aggregate IO drain. Never unlink the permanent lock.
func (l *directoryLease) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closeErr = errors.Join(l.checkAnchors(), l.releaseFDs())
	})
	return l.closeErr
}

func (l *directoryLease) releaseFDs() error {
	var result error
	for _, fd := range []int{l.targetFD, l.lockFD, l.admissionFD, l.controlFD, l.rootParentFD, l.rootFD} {
		if fd >= 0 {
			result = errors.Join(result, unix.Close(fd))
		}
	}
	l.targetFD, l.lockFD, l.admissionFD, l.controlFD, l.rootParentFD, l.rootFD = -1, -1, -1, -1, -1, -1
	return result
}

// share downgrades an initialization lock on the same permanent inode and
// rechecks the anchors. LOCK_NB also avoids waiting on a competing converter.
func (l *directoryLease) share() error {
	if err := unix.Flock(l.lockFD, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return fmt.Errorf("directory lease: retain shared lock: %w", err)
	}
	if err := l.checkAnchors(); err != nil {
		return err
	}
	// Retain admission EX across the entire downgrade and validation, so a
	// deleter cannot pass us even if flock conversion briefly drops lifetime.
	marker, err := l.findMarker(true)
	if err != nil {
		return err
	}
	if !l.hasMarker {
		if marker != nil {
			return fmt.Errorf("directory lease: legacy directory acquired a marker")
		}
		return l.releaseAdmission()
	}
	if marker == nil || marker.ServerID != l.markerOwner ||
		marker.Incarnation != l.Incarnation || marker.DirectoryEpoch != l.Epoch {
		return fmt.Errorf("directory lease: selected marker changed during admission")
	}
	return l.releaseAdmission()
}

func (l *directoryLease) releaseAdmission() error {
	if err := unix.Flock(l.admissionFD, unix.LOCK_UN); err != nil {
		return fmt.Errorf("directory lease: release owner admission: %w", err)
	}
	return nil
}

func newDirectoryNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (l *directoryLease) initializeMarker(serverID string, previous *directoryLeaseMarker) (*directoryLeaseMarker, error) {
	incarnation, err := newDirectoryNonce()
	if err != nil {
		return nil, err
	}
	for previous != nil && incarnation == previous.Incarnation {
		incarnation, err = newDirectoryNonce()
		if err != nil {
			return nil, err
		}
	}
	epoch, err := newDirectoryNonce()
	if err != nil {
		return nil, err
	}
	for previous != nil && epoch == previous.DirectoryEpoch {
		epoch, err = newDirectoryNonce()
		if err != nil {
			return nil, err
		}
	}
	marker := &directoryLeaseMarker{
		Version:           1,
		ServerID:          serverID,
		Incarnation:       incarnation,
		DirectoryEpoch:    epoch,
		RootDevice:        uint64(l.rootStat.Dev),
		RootInode:         uint64(l.rootStat.Ino),
		DirectoryDevice:   uint64(l.targetStat.Dev),
		DirectoryInode:    uint64(l.targetStat.Ino),
		Phase:             "Open",
		DeleteIntentNonce: "",
	}
	if err := l.initializeStamp(incarnation); err != nil {
		return nil, err
	}
	if err := l.publishMarker(marker, previous != nil); err != nil {
		return nil, err
	}
	return marker, nil
}

// publishMarker is called only while admission EX and a lifetime lock are held.
// Initial publication cannot replace a marker; subsequent Open-owner admission
// replaces only the already validated marker to rotate its directory epoch.
func (l *directoryLease) publishMarker(marker *directoryLeaseMarker, replace bool) error {
	content, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary := ".marker-" + marker.DirectoryEpoch + ".tmp"
	fd, err := unix.Openat(l.controlFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	// Only this newly created temporary marker can be removed. Never unlink
	// the permanent lock, a final marker, or a target after initialization error.
	temporaryExists := true
	defer func() {
		if temporaryExists {
			_ = unix.Unlinkat(l.controlFD, temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if replace {
		if err = unix.Renameat(l.controlFD, temporary, l.controlFD, l.stem+".json"); err != nil {
			return fmt.Errorf("directory lease: refresh owner epoch: %w", err)
		}
	} else {
		// linkat publishes atomically without replacing an existing marker.
		if err = unix.Linkat(l.controlFD, temporary, l.controlFD, l.stem+".json", 0); err != nil {
			return fmt.Errorf("directory lease: publish marker without replacement: %w", err)
		}
		if err = unix.Unlinkat(l.controlFD, temporary, 0); err != nil {
			return err
		}
	}
	temporaryExists = false
	if err = errors.Join(unix.Fsync(l.targetFD), unix.Fsync(l.controlFD), unix.Fsync(l.rootParentFD), unix.Fsync(l.rootFD)); err != nil {
		return fmt.Errorf("directory lease: persist initialized directory: %w", err)
	}
	return nil
}

// The stamp is written exactly once, only for a target this admission created.
// It is never repaired/adopted in an existing directory.
func (l *directoryLease) initializeStamp(incarnation string) error {
	fd, err := unix.Openat(l.targetFD, directoryIncarnationStamp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), directoryIncarnationStamp)
	_, writeErr := file.WriteString(incarnation + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr, unix.Fsync(l.targetFD))
}

func readDirectoryStamp(targetFD int) (string, bool, error) {
	return readDirectoryStampWithClose(targetFD, (*os.File).Close)
}

func readDirectoryStampWithClose(targetFD int, closeFile func(*os.File) error) (_ string, _ bool, resultErr error) {
	fd, err := unix.Openat(targetFD, directoryIncarnationStamp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	file := os.NewFile(uintptr(fd), directoryIncarnationStamp)
	defer func() { resultErr = errors.Join(resultErr, closeFile(file)) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size != 33 {
		return "", false, nil
	}
	content, err := io.ReadAll(io.LimitReader(file, 34))
	if err != nil {
		return "", false, err
	}
	if len(content) != 33 || content[32] != '\n' || !validDirectoryNonce(string(content[:32])) {
		return "", false, nil
	}
	return string(content[:32]), true, nil
}

// acquireMappedDirectory makes the logical-versus-physical choice while the
// logical root admission is exclusive. Existing logical data is never migrated
// or adopted. The returned lease is owned by the endpoint even before Start.
func acquireMappedDirectory(logical, physical string) (_ string, _ *directoryLease, resultErr error) {
	if !filepath.IsAbs(logical) || !filepath.IsAbs(physical) || filepath.Clean(logical) != logical || filepath.Clean(physical) != physical ||
		!validDirectoryServerID(filepath.Base(logical)) || filepath.Base(logical) != filepath.Base(physical) {
		return "", nil, fmt.Errorf("directory lease: invalid directory mapping")
	}
	if logical == physical {
		return "", nil, fmt.Errorf("directory lease: mapping must use a separate physical root")
	}
	admission, err := openDirectoryAdmission(filepath.Dir(logical))
	if err != nil {
		return "", nil, err
	}
	owned := true
	defer func() {
		if owned {
			resultErr = errors.Join(resultErr, admission.releaseFDs())
		}
	}()
	var stat unix.Stat_t
	err = unix.Fstatat(admission.rootFD, filepath.Base(logical), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return "", nil, fmt.Errorf("directory lease: unsafe existing logical target")
		}
		owned = false // acquire takes ownership, including on error.
		lease, err := acquireDirectoryLeaseSelected(logical, admission)
		if err != nil {
			return "", nil, err
		}
		lease.Managed = false
		return logical, lease, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return "", nil, err
	}
	lease, err := acquireDirectoryLease(physical)
	if err != nil {
		return "", nil, err
	}
	// Closing the selection admission is part of successful construction.
	// If uncertain, release the actual writer lease and refuse construction.
	owned = false
	if err = admission.releaseFDs(); err != nil {
		return "", nil, errors.Join(err, lease.Close())
	}
	return physical, lease, nil
}

func (l *directoryLease) domainUnsafe() (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(l.controlFD, ".domain-unsafe", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

// PoisonDirectoryDomain permanently revokes retirement evidence for a physical
// root before an unbounded legacy writer may start. No recovery/unlink is allowed.
// The sentinel is presence-based; consumers must reject even malformed entries.
func PoisonDirectoryDomain(root string) (resultErr error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("directory lease: invalid physical domain root")
	}
	admission, err := openDirectoryAdmission(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, admission.releaseFDs()) }()
	fd, err := unix.Openat(admission.controlFD, ".domain-unsafe", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), ".domain-unsafe")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		return fmt.Errorf("directory lease: unsafe domain revocation sentinel")
	}
	// Presence is the durable revocation; writing also detects read-only or
	// otherwise unusable storage rather than permitting an uncertain fallback.
	_, err = file.WriteAt([]byte("unsafe\n"), 0)
	if err = errors.Join(err, file.Sync(), unix.Fsync(admission.controlFD), unix.Fsync(admission.rootParentFD), unix.Fsync(admission.rootFD)); err != nil {
		return err
	}
	return admission.checkAnchors()
}
