//go:build with_tailscale && windows

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

	"golang.org/x/sys/windows"
)

const (
	directoryControlPrefix    = ".polaris-directory-control-win-"
	directoryIncarnationStamp = ".polaris-directory-incarnation"
	windowsDomainStamp        = ".polaris-directory-domain"
	windowsMarkerLimit        = 1 << 20
)

type windowsDirectoryDomainRecord struct {
	Version     int    `json:"version"`
	Platform    string `json:"platform"`
	RootVolume  uint64 `json:"rootVolume"`
	RootFileID  string `json:"rootFileId"`
	DomainNonce string `json:"domainNonce"`
}
type directoryLeaseMarker struct {
	Version           int    `json:"version"`
	Platform          string `json:"platform"`
	ServerID          string `json:"serverId"`
	Incarnation       string `json:"incarnation"`
	DirectoryEpoch    string `json:"directoryEpoch"`
	RootVolume        uint64 `json:"rootVolume"`
	RootFileID        string `json:"rootFileId"`
	DirectoryVolume   uint64 `json:"directoryVolume"`
	DirectoryFileID   string `json:"directoryFileId"`
	Phase             string `json:"phase"`
	DeleteIntentNonce string `json:"deleteIntentNonce"`
}
type directoryLease struct {
	Identity, Incarnation, Epoch                                      string
	Managed                                                           bool
	rootPath, targetName, controlName, markerName, lockName, ownerSID string
	chain                                                             *windowsPathHandles
	children                                                          []windows.Handle
	root, control, admission, target, lifetime                        windows.Handle
	rootID, controlID, admissionID, targetID, lifetimeID              windowsDirectoryID
	domain                                                            windowsDirectoryDomainRecord
	admissionHeld, lifetimeHeld                                       bool
	checkpointExclusive                                            bool
	closeOnce                                                         sync.Once
	closeErr                                                          error
}

func directoryControlStem(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "sha256-" + hex.EncodeToString(sum[:])
}

func windowsValidHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validDirectoryNonce(value string) bool { return windowsValidHex(value, 32) }
func newDirectoryNonce() (string, error) {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(n[:]), nil
}

func windowsNextNonce(previous string) (string, error) {
	for {
		n, err := newDirectoryNonce()
		if err != nil {
			return "", err
		}
		if n != previous {
			return n, nil
		}
	}
}

// Exact object shape, duplicate/null/unknown keys rejected; no partial repair.
func windowsStrictJSON(data []byte, expected []string, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("directory lease: record must be an object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("directory lease: invalid key")
		}
		if _, ok := fields[key]; ok {
			return fmt.Errorf("directory lease: duplicate record key")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return err
		}
		fields[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("directory lease: trailing record data")
	}
	if len(fields) != len(expected) {
		return fmt.Errorf("directory lease: unexpected record fields")
	}
	for _, key := range expected {
		raw, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("directory lease: missing/null record field")
		}
	}
	return json.Unmarshal(data, out)
}

var (
	windowsDomainFields = []string{"version", "platform", "rootVolume", "rootFileId", "domainNonce"}
	windowsMarkerFields = []string{"version", "platform", "serverId", "incarnation", "directoryEpoch", "rootVolume", "rootFileId", "directoryVolume", "directoryFileId", "phase", "deleteIntentNonce"}
)

func windowsValidateMarker(m *directoryLeaseMarker) error {
	if m.Version != 1 || m.Platform != windowsDirectoryPlatform || !validDirectoryServerID(m.ServerID) || !validDirectoryNonce(m.Incarnation) || !validDirectoryNonce(m.DirectoryEpoch) || !windowsValidHex(m.RootFileID, 32) || !windowsValidHex(m.DirectoryFileID, 32) {
		return fmt.Errorf("directory lease: invalid marker identity")
	}
	switch m.Phase {
	case "Open":
		if m.DeleteIntentNonce != "" {
			return fmt.Errorf("directory lease: Open deletion nonce")
		}
	case "Deleting", "Deleted":
		if !validDirectoryNonce(m.DeleteIntentNonce) {
			return fmt.Errorf("directory lease: invalid deletion nonce")
		}
	default:
		return fmt.Errorf("directory lease: unknown phase")
	}
	return nil
}

func windowsMarkerTransition(a, b *directoryLeaseMarker) bool {
	if a == nil {
		return b.Phase == "Open"
	}
	if a.ServerID != b.ServerID || a.RootVolume != b.RootVolume || a.RootFileID != b.RootFileID {
		return false
	}
	if a.Phase == "Deleted" && b.Phase == "Open" {
		return a.Incarnation != b.Incarnation && a.DirectoryEpoch != b.DirectoryEpoch
	}
	if a.Incarnation != b.Incarnation || a.DirectoryVolume != b.DirectoryVolume || a.DirectoryFileID != b.DirectoryFileID {
		return false
	}
	if a.Phase == "Open" && b.Phase == "Open" {
		return a.DirectoryEpoch != b.DirectoryEpoch
	}
	if a.DirectoryEpoch != b.DirectoryEpoch {
		return false
	}
	if a.Phase == "Open" && b.Phase == "Deleting" {
		return true
	}
	return a.Phase == "Deleting" && (b.Phase == "Deleting" || b.Phase == "Deleted") && a.DeleteIntentNonce == b.DeleteIntentNonce
}

func windowsDecodeMarkerLog(data []byte) (*directoryLeaseMarker, error) {
	if len(data) == 0 || len(data) > windowsMarkerLimit || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("directory lease: incomplete marker log")
	}
	var previous *directoryLeaseMarker
	for line := range bytes.SplitSeq(data[:len(data)-1], []byte{'\n'}) {
		if len(line) == 0 || len(line) > 16<<10 {
			return nil, fmt.Errorf("directory lease: invalid marker record size")
		}
		var m directoryLeaseMarker
		if err := windowsStrictJSON(line, windowsMarkerFields, &m); err != nil {
			return nil, err
		}
		if err := windowsValidateMarker(&m); err != nil {
			return nil, err
		}
		if !windowsMarkerTransition(previous, &m) {
			return nil, fmt.Errorf("directory lease: invalid marker transition")
		}
		previous = &m
	}
	return previous, nil
}

func (l *directoryLease) openPrivate(parent windows.Handle, name string, directory bool, disposition uint32, write bool) (windows.Handle, error) {
	var h windows.Handle
	var err error
	if disposition == windows.FILE_OPEN {
		h, err = windowsOpenAt(parent, name, directory, disposition, write, nil)
	} else {
		h, err = windowsCreatePrivateAt(parent, name, directory, disposition, write, l.ownerSID)
	}
	if err != nil {
		return 0, err
	}
	if err := windowsRequirePrivate(h, l.ownerSID); err != nil {
		return 0, errors.Join(err, windows.CloseHandle(h))
	}
	return h, nil
}

func windowsOwnerOfParent(parent windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	if owner == nil || !owner.IsValid() {
		return "", fmt.Errorf("directory lease: missing trusted parent owner")
	}
	current, err := windowsCurrentSID()
	if err != nil {
		return "", err
	}
	value := owner.String()
	if current != value && current != windowsSystemSID {
		return "", fmt.Errorf("directory lease: trusted parent belongs to another account")
	}
	return value, nil
}

func windowsMissing(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// Only an absent root is bootstrapped. Existing or torn roots cannot be adopted.
// Flushes establish the process-crash protocol, not multi-object power-loss fsync.
func openDirectoryAdmission(rootPath string) (_ *directoryLease, resultErr error) {
	if !windowsCanonicalPath(rootPath) || filepath.Dir(rootPath) == rootPath {
		return nil, fmt.Errorf("directory lease: invalid physical root")
	}
	chain, err := windowsOpenPath(filepath.Dir(rootPath))
	if err != nil {
		return nil, err
	}
	l := &directoryLease{rootPath: rootPath, chain: chain}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, l.releaseHandles())
		}
	}()
	l.ownerSID, err = windowsOwnerOfParent(chain.last())
	if err != nil {
		return nil, err
	}
	l.root, err = l.openPrivate(chain.last(), filepath.Base(rootPath), true, windows.FILE_OPEN, false)
	fresh := windowsMissing(err)
	if fresh {
		l.root, err = l.openPrivate(chain.last(), filepath.Base(rootPath), true, windows.FILE_CREATE, false)
	}
	if err != nil {
		return nil, err
	}
	l.rootID, err = windowsInspect(l.root, true)
	if err != nil {
		return nil, err
	}
	l.controlName = directoryControlPrefix + l.rootID.key()
	disposition := uint32(windows.FILE_OPEN)
	if fresh {
		disposition = windows.FILE_CREATE
	}
	l.control, err = l.openPrivate(chain.last(), l.controlName, true, disposition, false)
	if err != nil {
		return nil, fmt.Errorf("directory lease: incomplete or inaccessible control domain: %w", err)
	}
	l.controlID, err = windowsInspect(l.control, true)
	if err != nil {
		return nil, err
	}
	if l.rootID.Volume != l.controlID.Volume || l.rootID == l.controlID {
		return nil, fmt.Errorf("directory lease: invalid control identity")
	}
	l.admission, err = l.openPrivate(l.control, "root.admission.lock", false, disposition, true)
	if err != nil {
		return nil, err
	}
	l.admissionID, err = windowsInspect(l.admission, false)
	if err != nil {
		return nil, err
	}
	if err := windowsLock(l.admission, true); err != nil {
		return nil, fmt.Errorf("directory lease: admission busy: %w", err)
	}
	l.admissionHeld = true
	if fresh {
		nonce, err := newDirectoryNonce()
		if err != nil {
			return nil, err
		}
		l.domain = windowsDirectoryDomainRecord{1, windowsDirectoryPlatform, l.rootID.Volume, l.rootID.hex(), nonce}
		if err := l.writeNew(l.root, windowsDomainStamp, []byte(nonce+"\n")); err != nil {
			return nil, err
		}
		data, err := json.Marshal(l.domain)
		if err != nil {
			return nil, err
		}
		if err := l.writeNew(l.control, "domain.json", data); err != nil {
			return nil, err
		}
		if err := windows.FlushFileBuffers(l.admission); err != nil {
			return nil, err
		}
	}
	if err := l.checkDomain(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *directoryLease) writeNew(parent windows.Handle, name string, data []byte) (resultErr error) {
	h, err := l.openPrivate(parent, name, false, windows.FILE_CREATE, true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	return windowsWriteAll(h, data)
}

func (l *directoryLease) readPrivate(parent windows.Handle, name string, maximum int) (_ []byte, resultErr error) {
	h, err := l.openPrivate(parent, name, false, windows.FILE_OPEN, false)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	return windowsReadBounded(h, maximum)
}

func (l *directoryLease) checkDomain() error {
	data, err := l.readPrivate(l.control, "domain.json", 4096)
	if err != nil {
		return err
	}
	var d windowsDirectoryDomainRecord
	if err := windowsStrictJSON(data, windowsDomainFields, &d); err != nil {
		return err
	}
	if d.Version != 1 || d.Platform != windowsDirectoryPlatform || d.RootVolume != l.rootID.Volume || d.RootFileID != l.rootID.hex() || !validDirectoryNonce(d.DomainNonce) {
		return fmt.Errorf("directory lease: domain identity mismatch")
	}
	if l.domain.DomainNonce != "" && l.domain != d {
		return fmt.Errorf("directory lease: immutable domain changed")
	}
	stamp, err := l.readPrivate(l.root, windowsDomainStamp, 34)
	if err != nil {
		return err
	}
	if string(stamp) != d.DomainNonce+"\n" {
		return fmt.Errorf("directory lease: domain stamp mismatch")
	}
	l.domain = d
	return nil
}

func (l *directoryLease) domainUnsafe() (bool, error) {
	h, err := windowsOpenAt(l.control, ".domain-unsafe", false, windows.FILE_OPEN, false, nil)
	if windowsMissing(err) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, windows.CloseHandle(h)
}

func (l *directoryLease) readMarker(name string) (*directoryLeaseMarker, error) {
	data, err := l.readPrivate(l.control, name, windowsMarkerLimit)
	if err != nil {
		return nil, err
	}
	m, err := windowsDecodeMarkerLog(data)
	if err != nil {
		return nil, err
	}
	if m.RootVolume != l.rootID.Volume || m.RootFileID != l.rootID.hex() || name != directoryControlStem(m.ServerID)+".jsonl" {
		return nil, fmt.Errorf("directory lease: marker domain mismatch")
	}
	return m, nil
}

func (l *directoryLease) appendMarker(m *directoryLeaseMarker, previous *directoryLeaseMarker) (resultErr error) {
	if !l.admissionHeld || !l.lifetimeHeld {
		return fmt.Errorf("directory lease: marker publication without custody")
	}
	if err := windowsValidateMarker(m); err != nil {
		return err
	}
	if !windowsMarkerTransition(previous, m) {
		return fmt.Errorf("directory lease: invalid marker publication")
	}
	name := directoryControlStem(m.ServerID) + ".jsonl"
	disposition := uint32(windows.FILE_OPEN)
	if previous == nil {
		disposition = windows.FILE_CREATE
	}
	h, err := l.openPrivate(l.control, name, false, disposition, true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	size := 0
	if previous != nil {
		data, err := windowsReadBounded(h, windowsMarkerLimit)
		if err != nil {
			return err
		}
		current, err := windowsDecodeMarkerLog(data)
		if err != nil {
			return err
		}
		if *current != *previous {
			return fmt.Errorf("directory lease: marker changed under admission")
		}
		size = len(data)
	}
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	fits, reserveErr := windowsMarkerAdmissionFits(size, *m)
	if reserveErr != nil { return reserveErr }
	if !fits { return fmt.Errorf("directory lease: marker log lacks deletion reserve") }
	if len(line) > 16<<10 || size+len(line)+1 > windowsMarkerLimit {
		return fmt.Errorf("directory lease: marker log full")
	}
	line = append(line, '\n')
	if _, err := windows.Seek(h, int64(size), io.SeekStart); err != nil {
		return err
	}
	return windowsWriteAll(h, line)
}

// Reads every protocol log under admission. An alias is associated only by its
// current original path plus its stored identity and stamp, never a FileId alone.
func (l *directoryLease) findMarker(targetExists bool, skip *directoryLeaseMarker) (*directoryLeaseMarker, error) {
	names, err := windowsReadNames(l.control)
	if err != nil {
		return nil, err
	}
	var selected *directoryLeaseMarker
	for _, name := range names {
		if !strings.HasPrefix(name, "sha256-") {
			continue
		}
		if len(name) != 7+64+6 || !strings.HasSuffix(name, ".jsonl") || !windowsValidHex(name[7:71], 64) {
			return nil, fmt.Errorf("directory lease: malformed marker filename")
		}
		m, err := l.readMarker(name)
		if err != nil {
			return nil, err
		}
		if skip != nil && *m == *skip {
			continue
		}
		if !targetExists {
			if m.ServerID == l.targetName {
				if m.Phase != "Deleted" {
					return nil, fmt.Errorf("directory lease: missing active generation")
				}
				selected = m
			}
			continue
		}
		h, err := l.openPrivate(l.root, m.ServerID, true, windows.FILE_OPEN, false)
		if windowsMissing(err) {
			if m.ServerID == l.targetName {
				return nil, fmt.Errorf("directory lease: marker target absent")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		id, readErr := windowsInspect(h, true)
		err = errors.Join(readErr, windows.CloseHandle(h))
		if err != nil {
			return nil, err
		}
		if id != l.targetID {
			continue
		}
		if m.Phase != "Open" || m.DirectoryVolume != id.Volume || m.DirectoryFileID != id.hex() {
			return nil, fmt.Errorf("directory lease: target aliases retired or replaced generation")
		}
		if selected != nil {
			return nil, fmt.Errorf("directory lease: duplicate markers for one live identity")
		}
		selected = m
	}
	return selected, nil
}

func acquireDirectoryLease(directory string) (_ *directoryLease, resultErr error) {
	if !windowsCanonicalPath(directory) || !validDirectoryServerID(filepath.Base(directory)) {
		return nil, fmt.Errorf("directory lease: invalid target path")
	}
	l, err := openDirectoryAdmission(filepath.Dir(directory))
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, l.releaseHandles())
		}
	}()
	if unsafe, err := l.domainUnsafe(); err != nil || unsafe {
		return nil, fmt.Errorf("directory lease: domain permanently revoked or uncertain: %v", err)
	}
	l.targetName = filepath.Base(directory)
	l.target, err = l.openPrivate(l.root, l.targetName, true, windows.FILE_OPEN, false)
	missing := windowsMissing(err)
	if err != nil && !missing {
		return nil, err
	}
	var previous *directoryLeaseMarker
	if missing {
		previous, err = l.findMarker(false, nil)
		if err != nil {
			return nil, err
		}
		l.target, err = l.openPrivate(l.root, l.targetName, true, windows.FILE_CREATE, false)
		if err != nil {
			return nil, err
		}
	}
	l.targetID, err = windowsInspect(l.target, true)
	if err != nil {
		return nil, err
	}
	if l.targetID.Volume != l.rootID.Volume {
		return nil, fmt.Errorf("directory lease: cross-volume target")
	}
	// Decide cold maintenance under root admission before choosing the lifetime
	// lock. Never upgrade a shared lease or publish a candidate before EX succeeds.
	var existingMarker *directoryLeaseMarker
	checkpoint := false
	if !missing {
		existingMarker, err = l.findMarker(true, nil)
		if err != nil { return nil, err }
		if existingMarker == nil { return nil, fmt.Errorf("directory lease: existing unmarked physical target") }
		checkpoint, err = l.markerNeedsCheckpoint(existingMarker)
		if err != nil { return nil, err }
	}
	l.lockName = "directory-" + l.targetID.key() + ".lock"
	disposition := uint32(windows.FILE_OPEN)
	if missing {
		disposition = windows.FILE_OPEN_IF
	}
	l.lifetime, err = l.openPrivate(l.control, l.lockName, false, disposition, true)
	if err != nil {
		return nil, err
	}
	l.lifetimeID, err = windowsInspect(l.lifetime, false)
	if err != nil {
		return nil, err
	}
	if err := windowsLock(l.lifetime, missing || checkpoint); err != nil {
		return nil, fmt.Errorf("directory lease: lifetime busy: %w", err)
	}
	l.lifetimeHeld = true
	l.checkpointExclusive = checkpoint
	var marker *directoryLeaseMarker
	if missing {
		// A previous generation lock is permanent. EX blocks any stale path writer;
		// FileId reuse naturally uses the initialization EX already retained above.
		if previous != nil {
			oldName := fmt.Sprintf("directory-%d-%s.lock", previous.DirectoryVolume, previous.DirectoryFileID)
			if oldName != l.lockName {
				h, err := l.openPrivate(l.control, oldName, false, windows.FILE_OPEN, true)
				if err != nil {
					return nil, err
				}
				l.children = append(l.children, h)
				if err := windowsLock(h, true); err != nil {
					return nil, fmt.Errorf("directory lease: previous generation still held: %w", err)
				}
			}
		}
		related, err := l.findMarker(true, previous)
		if err != nil {
			return nil, err
		}
		if related != nil {
			return nil, fmt.Errorf("directory lease: new target aliases another marker")
		}
		oldInc, oldEpoch := "", ""
		if previous != nil {
			oldInc, oldEpoch = previous.Incarnation, previous.DirectoryEpoch
		}
		inc, err := windowsNextNonce(oldInc)
		if err != nil {
			return nil, err
		}
		epoch, err := windowsNextNonce(oldEpoch)
		if err != nil {
			return nil, err
		}
		marker = &directoryLeaseMarker{Version: 1, Platform: windowsDirectoryPlatform, ServerID: l.targetName, Incarnation: inc, DirectoryEpoch: epoch, RootVolume: l.rootID.Volume, RootFileID: l.rootID.hex(), DirectoryVolume: l.targetID.Volume, DirectoryFileID: l.targetID.hex(), Phase: "Open"}
		if err := l.writeNew(l.target, directoryIncarnationStamp, []byte(inc+"\n")); err != nil {
			return nil, err
		}
		if err := l.appendMarker(marker, previous); err != nil {
			return nil, err
		}
	} else {
		marker = existingMarker
		stamp, err := l.readPrivate(l.target, directoryIncarnationStamp, 34)
		if err != nil {
			return nil, err
		}
		if string(stamp) != marker.Incarnation+"\n" {
			return nil, fmt.Errorf("directory lease: incarnation mismatch")
		}
		if checkpoint {
			if err := l.checkpointOpenJournal(marker); err != nil { return nil, err }
		}
		next := *marker
		next.DirectoryEpoch, err = windowsNextNonce(marker.DirectoryEpoch)
		if err != nil {
			return nil, err
		}
		if err := l.appendMarker(&next, marker); err != nil {
			return nil, err
		}
		marker = &next
	}
	l.markerName = directoryControlStem(marker.ServerID) + ".jsonl"
	l.Identity = windowsDirectoryIdentity(l.rootID, l.targetID)
	l.Incarnation, l.Epoch = marker.Incarnation, marker.DirectoryEpoch
	l.Managed = marker.ServerID == l.targetName
	if missing || checkpoint {
		if err := windowsUnlock(l.lifetime); err != nil {
			return nil, err
		}
		l.lifetimeHeld = false
		if err := windowsLock(l.lifetime, false); err != nil {
			return nil, err
		}
		l.lifetimeHeld = true
		l.checkpointExclusive = false
	}
	if err := l.checkAnchors(); err != nil {
		return nil, err
	}
	for i, h := range l.children {
		l.children[i] = 0
		if err := windows.CloseHandle(h); err != nil {
			return nil, err
		}
	}
	l.children = nil
	if err := windowsUnlock(l.admission); err != nil {
		return nil, err
	}
	l.admissionHeld = false
	return l, nil
}

func (l *directoryLease) checkObject(parent windows.Handle, name string, directory bool, held windows.Handle, id windowsDirectoryID) (resultErr error) {
	current, err := windowsInspect(held, directory)
	if err != nil {
		return err
	}
	if current != id {
		return fmt.Errorf("directory lease: retained identity changed")
	}
	if err := windowsRequirePrivate(held, l.ownerSID); err != nil {
		return err
	}
	h, err := l.openPrivate(parent, name, directory, windows.FILE_OPEN, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	current, err = windowsInspect(h, directory)
	if err != nil {
		return err
	}
	if current != id {
		return fmt.Errorf("directory lease: anchor replaced")
	}
	return nil
}

func (l *directoryLease) checkAnchors() error {
	if l.root == 0 {
		return nil
	}
	owner, err := windowsOwnerOfParent(l.chain.last())
	if err != nil {
		return err
	}
	if owner != l.ownerSID {
		return fmt.Errorf("directory lease: parent owner changed")
	}
	if err := l.checkObject(l.chain.last(), filepath.Base(l.rootPath), true, l.root, l.rootID); err != nil {
		return err
	}
	if err := l.checkObject(l.chain.last(), l.controlName, true, l.control, l.controlID); err != nil {
		return err
	}
	if err := l.checkObject(l.control, "root.admission.lock", false, l.admission, l.admissionID); err != nil {
		return err
	}
	if err := l.checkDomain(); err != nil {
		return err
	}
	if unsafe, err := l.domainUnsafe(); err != nil || unsafe {
		return fmt.Errorf("directory lease: domain permanently revoked or uncertain: %v", err)
	}
	if l.target != 0 {
		if err := l.checkObject(l.root, l.targetName, true, l.target, l.targetID); err != nil {
			return err
		}
	}
	if l.lifetime != 0 {
		if err := l.checkObject(l.control, l.lockName, false, l.lifetime, l.lifetimeID); err != nil {
			return err
		}
	}
	if l.Incarnation != "" {
		stamp, err := l.readPrivate(l.target, directoryIncarnationStamp, 34)
		if err != nil {
			return err
		}
		if string(stamp) != l.Incarnation+"\n" {
			return fmt.Errorf("directory lease: incarnation stamp changed")
		}
		m, err := l.readMarker(l.markerName)
		if err != nil {
			return err
		}
		if m.Phase != "Open" || m.Incarnation != l.Incarnation || m.DirectoryVolume != l.targetID.Volume || m.DirectoryFileID != l.targetID.hex() {
			return fmt.Errorf("directory lease: live generation changed")
		}
	}
	return nil
}

// Durable presence is permanent revocation. Any failure retains custody until
// process exit; never repair/unlink a sentinel or release on ambiguous poison.
func (l *directoryLease) revoke() (resultErr error) {
	if l.root == 0 {
		return nil
	}
	if !l.admissionHeld {
		if err := windowsLock(l.admission, true); err != nil {
			return fmt.Errorf("directory lease: revoke admission busy: %w", err)
		}
		l.admissionHeld = true
	}
	if err := windowsRequirePrivate(l.control, l.ownerSID); err != nil {
		return err
	}
	if err := windowsRequirePrivate(l.admission, l.ownerSID); err != nil {
		return err
	}
	h, err := l.openPrivate(l.control, ".domain-unsafe", false, windows.FILE_OPEN_IF, true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	if _, err := windows.Seek(h, 0, io.SeekStart); err != nil {
		return err
	}
	return windowsWriteAll(h, []byte("unsafe\n"))
}

func PoisonDirectoryDomain(root string) (resultErr error) {
	l, err := openDirectoryAdmission(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, l.releaseHandles()) }()
	return l.revoke()
}

func (l *directoryLease) Close() error {
	if l == nil || l.root == 0 {
		return nil
	}
	l.closeOnce.Do(func() {
		err := l.checkAnchors()
		if err != nil {
			if revokeErr := l.revoke(); revokeErr != nil {
				l.closeErr = errors.Join(err, revokeErr)
				return
			}
		}
		l.closeErr = errors.Join(err, l.releaseHandles())
	})
	return l.closeErr
}

func (l *directoryLease) releaseHandles() error {
	if l == nil {
		return nil
	}
	var result error
	for _, h := range l.children {
		if h != 0 {
			result = errors.Join(result, windows.CloseHandle(h))
		}
	}
	l.children = nil
	for _, p := range []*windows.Handle{&l.target, &l.lifetime, &l.admission, &l.control, &l.root} {
		if *p != 0 {
			result = errors.Join(result, windows.CloseHandle(*p))
			*p = 0
		}
	}
	result = errors.Join(result, l.chain.close())
	l.chain = nil
	l.admissionHeld, l.lifetimeHeld, l.checkpointExclusive = false, false, false
	return result
}

// Existing logical state remains legacy, with no positive managed receipt.
// Old binaries cannot silently enter the versioned physical namespace because
// the activation envelope is an unknown-field error on old config decoders.
func acquireMappedDirectory(logical, physical string) (string, *directoryLease, error) {
	if !windowsCanonicalPath(logical) || !windowsCanonicalPath(physical) || logical == physical || filepath.Base(logical) != filepath.Base(physical) || !validDirectoryServerID(filepath.Base(logical)) {
		return "", nil, fmt.Errorf("directory lease: invalid directory mapping")
	}
	if info, err := os.Lstat(logical); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", nil, fmt.Errorf("directory lease: unsafe existing logical target")
		}
		return logical, &directoryLease{}, nil
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	lease, err := acquireDirectoryLease(physical)
	return physical, lease, err
}
