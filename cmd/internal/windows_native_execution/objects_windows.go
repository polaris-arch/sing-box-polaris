//go:build windows && amd64

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const systemSID = "S-1-5-18"

type fileIdentity struct {
	Volume uint64
	ID     [16]byte
}
type cohort struct {
	ctx                      context.Context
	fact                     cohortFact
	parent, directory        windows.Handle
	core, sidecar            *os.File
	coreFact, sidecarFact    objectFact
	children, waited, joined int
	active                   uint32
	forced                   bool
}

func utf16(value string) (*uint16, error) { return windows.UTF16PtrFromString(value) }
func handlePath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 2)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return "", errors.New("native object path bound")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}
func handleIdentity(handle windows.Handle) (fileIdentity, error) {
	var id fileIdentity
	err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)))
	return id, err
}
func hexTime(value windows.Filetime) string {
	return fmt.Sprintf("%08x%08x", value.HighDateTime, value.LowDateTime)
}

func actorFor(process, thread windows.Handle, pid uint32) (_ actorFact, failure error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return actorFact{}, err
	}
	defer func() { failure = errors.Join(failure, token.Close()) }()
	user, err := token.GetTokenUser()
	if err != nil {
		return actorFact{}, err
	}
	var kind uint32
	var needed uint32
	if err = windows.GetTokenInformation(token, windows.TokenType, (*byte)(unsafe.Pointer(&kind)), 4, &needed); err != nil {
		return actorFact{}, err
	}
	if needed != 4 {
		return actorFact{}, errors.New("native primary token type shape differs")
	}
	var impersonation windows.Token
	err = windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &impersonation)
	if err == nil {
		impersonation.Close()
		return actorFact{}, errors.New("thread impersonation token is forbidden")
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return actorFact{}, fmt.Errorf("thread token query: %w", err)
	}
	if kind != windows.TokenPrimary || user.User.Sid.String() != systemSID {
		return actorFact{}, errors.New("native proof requires an actual SYSTEM primary token")
	}
	var created, exited, kernel, userTime windows.Filetime
	if err = windows.GetProcessTimes(process, &created, &exited, &kernel, &userTime); err != nil {
		return actorFact{}, err
	}
	return actorFact{user.User.Sid.String(), "primary", false, pid, hexTime(created)}, nil
}
func currentActor() (actorFact, error) {
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return actorFact{}, err
	}
	return actorFor(windows.CurrentProcess(), thread, uint32(os.Getpid()))
}

func security(handle windows.Handle, exactSystem bool) (string, bool, bool, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", false, false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", false, false, err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return "", false, false, errors.New("NULL/unavailable object DACL")
	}
	control, _, err := sd.Control()
	if err != nil {
		return "", false, false, err
	}
	protected := control&windows.SE_DACL_PROTECTED != 0
	if exactSystem {
		if owner.String() != systemSID || !protected || acl.AceCount != 1 {
			return "", false, false, errors.New("cohort object is not SYSTEM-owned with a protected single-principal DACL")
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, 0, &ace); err != nil {
			return "", false, false, err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask)&0x001f01ff != 0x001f01ff || sid.String() != systemSID {
			return "", false, false, errors.New("cohort DACL grants another principal or lacks SYSTEM full control")
		}
		return owner.String(), protected, true, nil
	}
	// The OS-owned parent may admit administrators/TrustedInstaller; no ordinary
	// principal may replace a just-created child before its deny-delete lease.
	trusted := map[string]bool{systemSID: true, "S-1-5-32-544": true, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	if !trusted[owner.String()] {
		return "", false, false, errors.New("untrusted cohort parent owner")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return "", false, false, err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return "", false, false, errors.New("unsupported parent ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted[sid.String()] && uint32(ace.Mask)&(0x40|0x10000|0x40000|0x80000|0x10000000) != 0 {
			return "", false, false, errors.New("ordinary principal can replace protected cohort through parent")
		}
	}
	return owner.String(), protected, false, nil
}

func openReadOnlyObject(name string) (*os.File, error) {
	pointer, err := utf16(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(handle)
		return nil, errors.New("actual file is not a non-reparse regular object")
	}
	return os.NewFile(uintptr(handle), name), nil
}

func newCohort() (_ *cohort, failure error) {
	windowsDirectory, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Join(windowsDirectory, "SystemTemp")
	pointer, err := utf16(parentPath)
	if err != nil {
		return nil, err
	}
	parent, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("native SYSTEM proof host needs existing OS SystemTemp: %w", err)
	}
	c := &cohort{parent: parent}
	defer func() {
		if failure != nil {
			_, closeErr := c.close()
			failure = errors.Join(failure, closeErr)
		}
	}()
	if _, _, _, err = security(parent, false); err != nil {
		return nil, err
	}
	var parentInfo windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(parent, &parentInfo); err != nil || parentInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("cohort parent is reparse/unavailable")
	}
	fs := make([]uint16, 64)
	if err = windows.GetVolumeInformationByHandle(parent, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return nil, err
	}
	if windows.UTF16ToString(fs) != "NTFS" {
		return nil, errors.New("native cohort requires NTFS")
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(random)
	name := filepath.Join(parentPath, "polaris-native-"+id)
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;OICI;FA;;;SY)")
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	pointer, err = utf16(name)
	if err != nil {
		return nil, err
	}
	if err = windows.CreateDirectory(pointer, &attributes); err != nil {
		return nil, fmt.Errorf("fresh protected cohort creation: %w", err)
	}
	c.fact = cohortFact{ID: id, Path: name, CreatedNew: true, FileSystem: windows.UTF16ToString(fs)}
	c.directory, err = windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	owner, protected, systemOnly, err := security(c.directory, true)
	if err != nil {
		return nil, err
	}
	c.fact.OwnerSID = owner
	c.fact.ProtectedDACL = protected
	c.fact.SystemOnlyDACL = systemOnly
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(c.directory, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("new cohort unexpectedly reparsed")
	}
	identity, err := handleIdentity(c.directory)
	if err != nil {
		return nil, err
	}
	native, err := handlePath(c.directory)
	if err != nil {
		return nil, err
	}
	parentNative, err := handlePath(parent)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Dir(native), parentNative) {
		return nil, errors.New("new cohort left held parent")
	}
	c.fact.VolumeSerial = fmt.Sprintf("%016x", identity.Volume)
	c.fact.FileID = hex.EncodeToString(identity.ID[:])
	c.fact.NativePath = native
	return c, nil
}

func (c *cohort) copyObject(p pin, reader io.Reader) (int64, error) {
	if p.Member != "sing-box.exe" && p.Member != "libcronet.dll" {
		return 0, errors.New("non-cohort member")
	}
	pointer, err := utf16(filepath.Join(c.fact.Path, p.Member))
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)")
	if err != nil {
		return 0, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(handle), p.Member)
	n, copyErr := io.Copy(file, io.LimitReader(reader, p.Bytes+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if n != p.Bytes {
		copyErr = errors.Join(copyErr, errors.New("new cohort member byte count differs"))
	}
	return n, errors.Join(copyErr, syncErr, closeErr)
}
func (c *cohort) holdObjects(core, sidecar pin) error {
	for index, p := range []pin{core, sidecar} {
		name := filepath.Join(c.fact.Path, p.Member)
		file, err := openReadOnlyObject(name)
		if err != nil {
			return err
		}
		if index == 0 {
			c.core = file
		} else {
			c.sidecar = file
		}
		handle := windows.Handle(file.Fd())
		owner, protected, systemOnly, err := security(handle, true)
		if err != nil {
			return err
		}
		identity, err := handleIdentity(handle)
		if err != nil {
			return err
		}
		native, err := handlePath(handle)
		if err != nil {
			return err
		}
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
			return err
		}
		if info.NumberOfLinks != 1 || !strings.EqualFold(filepath.Dir(native), c.fact.NativePath) || fmt.Sprintf("%016x", identity.Volume) != c.fact.VolumeSerial {
			return errors.New("held cohort member alias/volume/parent differs")
		}
		h := sha256.New()
		size, err := io.Copy(h, file)
		if err != nil {
			return err
		}
		actual := hex.EncodeToString(h.Sum(nil))
		if size != p.Bytes || actual != p.SHA256 {
			return errors.New("held cohort member bytes differ")
		}
		fact := objectFact{name, native, fmt.Sprintf("%016x", identity.Volume), hex.EncodeToString(identity.ID[:]), owner, protected, systemOnly, false, size, actual, info.NumberOfLinks, true}
		if index == 0 {
			c.coreFact = fact
		} else {
			c.sidecarFact = fact
		}
	}
	if c.coreFact.FileID == c.sidecarFact.FileID {
		return errors.New("Core and DLL alias one file object")
	}
	return nil
}

func removeOwned(name string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Remove(name)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (c *cohort) close() (cleanupFact, error) {
	var failures []error
	if c.core != nil {
		failures = append(failures, c.core.Close())
		c.core = nil
	}
	if c.sidecar != nil {
		failures = append(failures, c.sidecar.Close())
		c.sidecar = nil
	}
	if c.directory != 0 {
		actual, err := handleIdentity(c.directory)
		if err != nil {
			failures = append(failures, err)
		} else if c.fact.FileID != "" && hex.EncodeToString(actual.ID[:]) != c.fact.FileID {
			failures = append(failures, errors.New("cleanup cohort identity changed"))
		}
		failures = append(failures, windows.CloseHandle(c.directory))
		c.directory = 0
	}
	heldClosed := errors.Join(failures...) == nil
	removed := false
	if c.fact.Path != "" && heldClosed {
		for _, name := range []string{"sing-box.exe", "libcronet.dll"} {
			err := removeOwned(filepath.Join(c.fact.Path, name))
			if err != nil {
				failures = append(failures, err)
			}
		}
		err := removeOwned(c.fact.Path)
		failures = append(failures, err)
		removed = err == nil
	}
	if c.parent != 0 {
		failures = append(failures, windows.CloseHandle(c.parent))
		c.parent = 0
	}
	facts := cleanupFact{c.waited == c.children, c.joined == c.children, c.active, heldClosed, removed, false, c.forced}
	if c.waited != c.children || c.joined != c.children || c.active != 0 || c.forced {
		failures = append(failures, errors.New("native child custody/cleanup incomplete"))
	}
	return facts, errors.Join(failures...)
}
