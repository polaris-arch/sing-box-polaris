//go:build with_tailscale && windows

package tailscale

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Local NTFS only. These retained handles are cooperative custody, not a
// boundary against malicious same-SID code, administrators or kernel drivers.
const (
	windowsDirectoryPlatform = "windows-ntfs-v1"
	windowsFileAllAccess     = 0x001f01ff
)

type windowsDirectoryID struct {
	Volume uint64
	FileID [16]byte
}

func (id windowsDirectoryID) hex() string { return hex.EncodeToString(id.FileID[:]) }
func (id windowsDirectoryID) key() string { return fmt.Sprintf("%d-%s", id.Volume, id.hex()) }

func windowsDirectoryIdentity(root, target windowsDirectoryID) string {
	return fmt.Sprintf("%s:%d:%s:%d:%s", windowsDirectoryPlatform, root.Volume, root.hex(), target.Volume, target.hex())
}

func validDirectoryServerID(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "\\/:*?\"<>|\x00") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") || filepath.Base(name) != name || len([]rune(name)) > 255 {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	device := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch device {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '0' && device[3] <= '9' {
		return false
	}
	for _, p := range []string{"COM", "LPT"} {
		if device == p+"¹" || device == p+"²" || device == p+"³" {
			return false
		}
	}
	return true
}

func windowsCanonicalPath(path string) bool {
	v := filepath.VolumeName(path)
	return len(v) == 2 && v[1] == ':' && ((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "/\x00") && !strings.Contains(path[2:], ":")
}

func windowsNormalizeError(err error) error {
	if s, ok := errors.AsType[windows.NTStatus](err); ok {
		return s.Errno()
	}
	return err
}

// Every descendant is relative to an already retained parent, no reparse,
// no inheritance and no FILE_SHARE_DELETE. Security is checked after opening.
func windowsOpenAt(parent windows.Handle, name string, directory bool, disposition uint32, write bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if !validDirectoryServerID(name) {
		return 0, fmt.Errorf("directory lease: invalid Windows component")
	}
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if write {
		access |= windows.GENERIC_WRITE
	}
	flags := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_DIRECTORY_FILE
	} else {
		flags |= windows.FILE_NON_DIRECTORY_FILE
	}
	if write && !directory {
		flags |= windows.FILE_WRITE_THROUGH
	}
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, flags, 0, 0)
	runtime.KeepAlive(u)
	runtime.KeepAlive(sd)
	if err != nil {
		return 0, windowsNormalizeError(err)
	}
	if _, err = windowsInspect(h, directory); err != nil {
		return 0, errors.Join(err, windows.CloseHandle(h))
	}
	return h, nil
}

func windowsInspect(h windows.Handle, directory bool) (windowsDirectoryID, error) {
	var id windowsDirectoryID
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return id, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return id, fmt.Errorf("directory lease: reparse or unexpected object type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return id, fmt.Errorf("directory lease: protocol file has multiple links")
	}
	typ, err := windows.GetFileType(h)
	if err != nil {
		return id, err
	}
	if typ != windows.FILE_TYPE_DISK {
		return id, fmt.Errorf("directory lease: non-disk object")
	}
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return id, err
	}
	if id.FileID == [16]byte{} {
		return id, fmt.Errorf("directory lease: missing 128-bit identity")
	}
	return id, nil
}

var windowsVolumeInformationProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetVolumeInformationByHandleW")

func windowsRequireNTFS(h windows.Handle) error {
	if err := windowsVolumeInformationProc.Find(); err != nil {
		return fmt.Errorf("directory lease: NTFS handle capability unavailable: %w", err)
	}
	var fs [64]uint16
	var serial, maximum, flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, &serial, &maximum, &flags, &fs[0], uint32(len(fs))); err != nil {
		return err
	}
	if windows.UTF16ToString(fs[:]) != "NTFS" {
		return fmt.Errorf("directory lease: only local NTFS supported")
	}
	return nil
}

type windowsPathHandles struct{ handles []windows.Handle }

func (p *windowsPathHandles) last() windows.Handle { return p.handles[len(p.handles)-1] }

func (p *windowsPathHandles) close() error {
	if p == nil {
		return nil
	}
	var err error
	for _, handle := range slices.Backward(p.handles) {
		err = errors.Join(err, windows.CloseHandle(handle))
	}
	p.handles = nil
	return err
}

func windowsOpenPath(path string) (_ *windowsPathHandles, resultErr error) {
	if !windowsCanonicalPath(path) {
		return nil, fmt.Errorf("directory lease: require canonical drive-absolute path")
	}
	root := filepath.VolumeName(path) + `\`
	wide, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	if windows.GetDriveType(wide) != windows.DRIVE_FIXED {
		return nil, fmt.Errorf("directory lease: require fixed local drive")
	}
	volume, _ := windows.UTF16PtrFromString(filepath.VolumeName(path))
	var devices [1024]uint16
	if _, err := windows.QueryDosDevice(volume, &devices[0], uint32(len(devices))); err != nil {
		return nil, err
	}
	device := windows.UTF16ToString(devices[:])
	suffix := strings.TrimPrefix(device, `\Device\HarddiskVolume`)
	if suffix == device || suffix == "" {
		return nil, fmt.Errorf("directory lease: unsupported drive mapping")
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("directory lease: unsupported drive mapping")
		}
	}
	h, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	p := &windowsPathHandles{handles: []windows.Handle{h}}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, p.close())
		}
	}()
	if _, err := windowsInspect(h, true); err != nil {
		return nil, err
	}
	if err := windowsRequireNTFS(h); err != nil {
		return nil, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(path, root), `\`) {
		if component == "" {
			continue
		}
		h, err = windowsOpenAt(p.last(), component, true, windows.FILE_OPEN, false, nil)
		if err != nil {
			return nil, err
		}
		p.handles = append(p.handles, h)
	}
	return p, nil
}

func windowsCurrentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func windowsPrivateDescriptor(owner string, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	// Only containers propagate ACEs. Leaf protocol files need effective
	// grants without inheritance flags that SetSecurityInfo would strip.
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	acl := "O:" + owner + "D:P(A;" + inheritance + ";FA;;;" + owner + ")"
	if owner != "S-1-5-18" {
		acl += "(A;" + inheritance + ";FA;;;SY)"
	}
	return windows.SecurityDescriptorFromString(acl)
}

func windowsRequirePrivate(h windows.Handle, owner string) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actual, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if actual == nil || !actual.IsValid() || actual.String() != owner {
		return fmt.Errorf("directory lease: unexpected control owner")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("directory lease: protocol DACL is not protected")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return fmt.Errorf("directory lease: missing private DACL")
	}
	count := uint16(2)
	if owner == "S-1-5-18" {
		count = 1
	}
	if acl.AceCount != count {
		return fmt.Errorf("directory lease: unexpected access grants")
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask) != windowsFileAllAccess || ace.Header.AceFlags & ^uint8(3) != 0 {
			return fmt.Errorf("directory lease: unsupported access grant")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("directory lease: invalid ACL SID")
		}
		name := sid.String()
		if seen[name] || (name != owner && name != "S-1-5-18") {
			return fmt.Errorf("directory lease: foreign access grant")
		}
		seen[name] = true
	}
	if !seen[owner] || !seen["S-1-5-18"] {
		return fmt.Errorf("directory lease: incomplete access grants")
	}
	return nil
}

func windowsReadBounded(h windows.Handle, maximum int) ([]byte, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileSizeHigh != 0 || info.FileSizeLow > uint32(maximum) {
		return nil, fmt.Errorf("directory lease: record exceeds size limit")
	}
	if _, err := windows.Seek(h, 0, io.SeekStart); err != nil {
		return nil, err
	}
	data := make([]byte, int(info.FileSizeLow))
	for offset := 0; offset < len(data); {
		var n uint32
		if err := windows.ReadFile(h, data[offset:], &n, nil); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		offset += int(n)
	}
	return data, nil
}

func windowsWriteAll(h windows.Handle, data []byte) error {
	for len(data) > 0 {
		var n uint32
		if err := windows.WriteFile(h, data, &n, nil); err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return windows.FlushFileBuffers(h)
}

func windowsLock(h windows.Handle, exclusive bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	return windows.LockFileEx(h, flags, 0, 1, 0, new(windows.Overlapped))
}

func windowsUnlock(h windows.Handle) error {
	return windows.UnlockFileEx(h, 0, 1, 0, new(windows.Overlapped))
}

func windowsReadNames(h windows.Handle) (_ []string, resultErr error) {
	id, err := windowsInspect(h, true)
	if err != nil {
		return nil, err
	}
	// NT relative names do not normalize "." like Win32 paths. An empty
	// name reopens the retained directory itself with an independent cursor;
	// never resolve its pathname again or duplicate its enumeration state.
	name := &windows.NTUnicodeString{}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: h, ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var fd windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&fd, windows.GENERIC_READ|windows.SYNCHRONIZE, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0); err != nil {
		return nil, windowsNormalizeError(err)
	}
	runtime.KeepAlive(name)
	reopenedID, err := windowsInspect(fd, true)
	if err != nil {
		return nil, errors.Join(err, windows.CloseHandle(fd))
	}
	if reopenedID != id {
		return nil, errors.Join(fmt.Errorf("directory lease: enumeration identity changed"), windows.CloseHandle(fd))
	}
	file := os.NewFile(uintptr(fd), "directory protocol control")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return file.Readdirnames(-1)
}

// This opener is deliberately separate from windowsOpenAt: only the reserved
// unpublished checkpoint object receives DELETE. Permanent anchors and ordinary
// marker opens retain their existing access and no-FILE_SHARE_DELETE policy.
func windowsOpenCheckpointAt(parent windows.Handle, name string) (windows.Handle, error) {
	const prefix = ".checkpoint-sha256-"
	if len(name) != len(prefix)+64+4 || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") || !windowsValidHex(name[len(prefix):len(prefix)+64], 64) {
		return 0, fmt.Errorf("directory lease: invalid checkpoint scratch name")
	}
	u, err := windows.NewNTUnicodeString(name)
	if err != nil { return 0, err }
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_WRITE_THROUGH, 0, 0)
	runtime.KeepAlive(u)
	if err != nil { return 0, windowsNormalizeError(err) }
	if _, err := windowsInspect(h, false); err != nil { return 0, errors.Join(err, windows.CloseHandle(h)) }
	return h, nil
}

// Legacy FileRenameInformation uses a BOOLEAN, pointer-aligned root handle and
// UTF-16 byte count. Do not use newer POSIX flags that weaken open-handle checks.
func windowsCheckpointRenameBuffer(directory windows.Handle, name string) ([]byte, error) {
	if !strings.HasPrefix(name, "sha256-") || len(name) != 77 || !strings.HasSuffix(name, ".jsonl") || !windowsValidHex(name[7:71], 64) {
		return nil, fmt.Errorf("directory lease: invalid checkpoint destination")
	}
	wide, err := windows.UTF16FromString(name)
	if err != nil { return nil, err }
	wide = wide[:len(wide)-1]
	type renameInformation struct {
		ReplaceIfExists byte
		RootDirectory windows.Handle
		FileNameLength uint32
		FileName [1]uint16
	}
	var header renameInformation
	buffer := make([]byte, int(unsafe.Sizeof(header))+len(wide)*2)
	info := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	info.ReplaceIfExists = 1
	info.RootDirectory = directory
	info.FileNameLength = uint32(len(wide)*2)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[unsafe.Offsetof(header.FileName)])), len(wide)), wide)
	return buffer, nil
}

func windowsReplacePrivateFile(source windows.Handle, directory windows.Handle, name string) error {
	buffer, err := windowsCheckpointRenameBuffer(directory, name)
	if err != nil { return err }
	var status windows.IO_STATUS_BLOCK
	err = windows.NtSetInformationFile(source, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
	runtime.KeepAlive(buffer)
	return windowsNormalizeError(err)
}

func windowsDisposeCheckpointFile(source windows.Handle) error {
	deleteFile := byte(1)
	var status windows.IO_STATUS_BLOCK
	return windowsNormalizeError(windows.NtSetInformationFile(source, &status, &deleteFile, 1, windows.FileDispositionInformation))
}
