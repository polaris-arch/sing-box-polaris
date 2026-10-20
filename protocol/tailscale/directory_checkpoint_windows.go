//go:build with_tailscale && windows

package tailscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func windowsCheckpointName(serverID string) string {
	return ".checkpoint-" + directoryControlStem(serverID) + ".tmp"
}

// A fully validated one-incarnation Open history has the same terminal
// protocol state as its last record. This never reduces deletion/Unknown history
// or modifies the independent original retirement census.
func windowsCheckpointOpenJournal(data []byte) (directoryLeaseMarker, []byte, error) {
	last, err := windowsDecodeMarkerLog(data)
	if err != nil {
		return directoryLeaseMarker{}, nil, err
	}
	if last.Phase != "Open" {
		return directoryLeaseMarker{}, nil, fmt.Errorf("directory lease: checkpoint requires Open-only history")
	}
	for line := range bytes.SplitSeq(data[:len(data)-1], []byte{'\n'}) {
		var record directoryLeaseMarker
		if err := json.Unmarshal(line, &record); err != nil {
			return directoryLeaseMarker{}, nil, err
		}
		record.DirectoryEpoch = last.DirectoryEpoch
		if record != *last {
			return directoryLeaseMarker{}, nil, fmt.Errorf("directory lease: checkpoint history changes identity or phase")
		}
	}
	line, err := windowsMarkerLine(*last)
	return *last, line, err
}

func windowsMarkerLine(marker directoryLeaseMarker) ([]byte, error) {
	if err := windowsValidateMarker(&marker); err != nil {
		return nil, err
	}
	line, err := json.Marshal(marker)
	if err != nil {
		return nil, err
	}
	if len(line) > 16<<10 {
		return nil, fmt.Errorf("directory lease: marker record exceeds size limit")
	}
	return append(line, '\n'), nil
}

// Go's JSON encoding is conservative for the matching Rust fields: it also
// escapes HTML characters and U+2028/U+2029. Both use decimal integers and the
// same fixed-length hexadecimal nonce. Retained bytes are added by the caller.
func windowsMarkerAdmissionBytes(next directoryLeaseMarker) (int, error) {
	if next.Phase != "Open" {
		return 0, fmt.Errorf("directory lease: admission requires Open marker")
	}
	open, err := windowsMarkerLine(next)
	if err != nil {
		return 0, err
	}
	deleting := next
	deleting.Phase = "Deleting"
	deleting.DeleteIntentNonce = strings.Repeat("f", 32)
	deleteLine, err := windowsMarkerLine(deleting)
	if err != nil {
		return 0, err
	}
	deleted := deleting
	deleted.Phase = "Deleted"
	deletedLine, err := windowsMarkerLine(deleted)
	if err != nil {
		return 0, err
	}
	return len(open) + len(deleteLine) + len(deletedLine), nil
}

func windowsMarkerAdmissionFits(retained int, next directoryLeaseMarker) (bool, error) {
	required, err := windowsMarkerAdmissionBytes(next)
	if err != nil {
		return false, err
	}
	// Subtraction keeps arithmetic bounded even for an invalid retained length.
	return retained >= 0 && retained <= windowsMarkerLimit && required <= windowsMarkerLimit-retained, nil
}

func (l *directoryLease) markerNeedsCheckpoint(previous *directoryLeaseMarker) (bool, error) {
	data, err := l.readPrivate(l.control, directoryControlStem(previous.ServerID)+".jsonl", windowsMarkerLimit)
	if err != nil {
		return false, err
	}
	current, err := windowsDecodeMarkerLog(data)
	if err != nil {
		return false, err
	}
	if *current != *previous {
		return false, fmt.Errorf("directory lease: marker changed under admission")
	}
	// Only encoded length is needed before lock selection. Actual acquisition
	// still generates a fresh random epoch after custody/maintenance succeeds.
	fits, err := windowsMarkerAdmissionFits(len(data), *previous)
	return !fits, err
}

// A small publication seam makes irreversible ownership transfer testable.
// Once rename is attempted, even an error may leave the source authoritative.
// No later error can re-enable scratch disposal; close is attempted only once.
func windowsPublishCheckpoint(write, rename, flush, closeSource, verify, dispose func() error) (resultErr error) {
	scratch, closed := true, false
	closeOnce := func() error {
		if closed {
			return nil
		}
		closed = true
		return closeSource()
	}
	defer func() {
		if scratch {
			resultErr = errors.Join(resultErr, dispose())
		}
		resultErr = errors.Join(resultErr, closeOnce())
	}()
	if err := write(); err != nil {
		return err
	}
	scratch = false
	if err := rename(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	if err := closeOnce(); err != nil {
		return err
	}
	return verify()
}

// Called only by an unpublished cold acquisition holding root admission EX and
// lifetime EX. It does not upgrade a shared owner or authorize warm maintenance.
func (l *directoryLease) checkpointOpenJournal(previous *directoryLeaseMarker) error {
	if !l.admissionHeld || !l.lifetimeHeld || !l.checkpointExclusive {
		return fmt.Errorf("directory lease: checkpoint without exclusive custody")
	}
	if err := l.checkAnchors(); err != nil {
		return err
	}
	stamp, err := l.readPrivate(l.target, directoryIncarnationStamp, 34)
	if err != nil {
		return err
	}
	if string(stamp) != previous.Incarnation+"\n" {
		return fmt.Errorf("directory lease: checkpoint incarnation mismatch")
	}
	markerName := directoryControlStem(previous.ServerID) + ".jsonl"
	data, err := l.readPrivate(l.control, markerName, windowsMarkerLimit)
	if err != nil {
		return err
	}
	last, compact, err := windowsCheckpointOpenJournal(data)
	if err != nil {
		return err
	}
	if last != *previous {
		return fmt.Errorf("directory lease: checkpoint marker changed")
	}
	name := windowsCheckpointName(previous.ServerID)
	if err := l.discardCheckpointScratch(name); err != nil {
		return err
	}
	created, err := windowsCreatePrivateAt(l.control, name, false, windows.FILE_CREATE, true, l.ownerSID)
	if err != nil {
		return err
	}
	createdID, inspectErr := windowsInspect(created, false)
	closeErr := windows.CloseHandle(created)
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return err
	}
	h, err := l.openCheckpointScratch(name)
	if err != nil {
		return err
	}
	id, err := windowsInspect(h, false)
	if err != nil || id != createdID {
		return errors.Join(fmt.Errorf("directory lease: checkpoint scratch identity changed: %v", err), windows.CloseHandle(h))
	}
	return windowsPublishCheckpoint(
		func() error {
			if err := windowsWriteAll(h, compact); err != nil {
				return err
			}
			readback, err := windowsReadBounded(h, (16<<10)+1)
			if err != nil {
				return err
			}
			if !bytes.Equal(readback, compact) {
				return fmt.Errorf("directory lease: checkpoint scratch readback differs")
			}
			return l.checkAnchors()
		},
		func() error { return windowsReplacePrivateFile(h, l.control, markerName) },
		func() error { return windows.FlushFileBuffers(h) },
		func() error { return windows.CloseHandle(h) },
		func() (resultErr error) {
			// The DELETE-bearing handle is closed before this normal shared open.
			active, err := l.openPrivate(l.control, markerName, false, windows.FILE_OPEN, false)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(active)) }()
			activeID, err := windowsInspect(active, false)
			if err != nil {
				return err
			}
			if activeID != id {
				return fmt.Errorf("directory lease: checkpoint active identity differs")
			}
			readback, err := windowsReadBounded(active, windowsMarkerLimit)
			if err != nil {
				return err
			}
			decoded, err := windowsDecodeMarkerLog(readback)
			if err != nil {
				return err
			}
			if *decoded != last || !bytes.Equal(readback, compact) {
				return fmt.Errorf("directory lease: checkpoint active record differs")
			}
			return nil
		},
		func() error { return windowsDisposeCheckpointFile(h) },
	)
}

func (l *directoryLease) openCheckpointScratch(name string) (windows.Handle, error) {
	h, err := windowsOpenCheckpointAt(l.control, name)
	if err != nil {
		return 0, err
	}
	id, err := windowsInspect(h, false)
	if err == nil && id.Volume != l.rootID.Volume {
		err = fmt.Errorf("directory lease: cross-volume checkpoint scratch")
	}
	if err == nil {
		err = windowsRequirePrivate(h, l.ownerSID)
	}
	if err != nil {
		return 0, errors.Join(err, windows.CloseHandle(h))
	}
	return h, nil
}

func (l *directoryLease) discardCheckpointScratch(name string) error {
	h, err := l.openCheckpointScratch(name)
	if windowsMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Only this exact reserved, validated unpublished object is disposable.
	return errors.Join(windowsDisposeCheckpointFile(h), windows.CloseHandle(h))
}
