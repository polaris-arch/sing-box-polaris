package cachefile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A root token is constructed only after native identity and DACL verification.
// It pins that exact root without FILE_SHARE_DELETE; no caller-supplied SID is
// allowed to become a child authority.
type runtimeJournalRootCustody struct {
	access    sync.Mutex
	file      *os.File
	principal string
	closed    bool
	closeErr  error
}

func requireRuntimeJournalRootCustody(path string, info os.FileInfo) (*runtimeJournalRootCustody, error) {
	file, principal, err := openRuntimeWindowsCustody(path, info, true, "")
	if err != nil {
		return nil, err
	}
	return &runtimeJournalRootCustody{file: file, principal: principal}, nil
}
func (r *runtimeJournalRootCustody) Close() error {
	r.access.Lock()
	defer r.access.Unlock()
	if !r.closed {
		r.closed = true
		r.closeErr = r.file.Close()
	}
	return r.closeErr
}
func (r *runtimeJournalRootCustody) RequireFile(path string, info os.FileInfo) (func() error, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return nil, ErrFakeIPRecoveryClosed
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	rootInfo, err := r.file.Stat()
	if err != nil || !os.SameFile(parent, rootInfo) {
		return nil, errors.Join(ErrFakeIPRecoveryCustody, err)
	}
	// Recheck the still-pinned root descriptor. Changing its owner or broadening
	// its ACL cannot turn a formerly accepted principal into current authority.
	sd, err := windows.GetSecurityInfo(windows.Handle(r.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	principal, err := runtimeWindowsDescriptorPrincipal(sd, user.User.Sid.String(), "")
	if err != nil || principal != r.principal {
		return nil, errors.Join(ErrFakeIPRecoveryCustody, err)
	}
	file, _, err := openRuntimeWindowsCustody(path, info, false, r.principal)
	if err != nil {
		return nil, err
	}
	return runtimeWindowsFileRelease(file), nil
}

func runtimeWindowsFileRelease(file *os.File) func() error {
	var once sync.Once
	var closeErr error
	return func() error { once.Do(func() { closeErr = file.Close() }); return closeErr }
}

// Compatibility inspection for readiness and independent same-account objects.
// Journal child inspection goes through the verified root token above.
func requireRuntimeJournalCustody(path string, expected os.FileInfo, directory bool) (func() error, error) {
	file, _, err := openRuntimeWindowsCustody(path, expected, directory, "")
	if err != nil {
		return nil, err
	}
	return runtimeWindowsFileRelease(file), nil
}
func openRuntimeWindowsCustody(path string, expected os.FileInfo, directory bool, rootPrincipal string) (*os.File, string, error) {
	if expected == nil || expected.Mode()&os.ModeSymlink != 0 || expected.IsDir() != directory || (!directory && !expected.Mode().IsRegular()) {
		return nil, "", ErrFakeIPRecoveryCustody
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(handle), path)
	fail := func(cause error) (*os.File, string, error) { return nil, "", errors.Join(cause, file.Close()) }
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &native); err != nil {
		return fail(err)
	}
	if native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (native.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fail(ErrFakeIPRecoveryCustody)
	}
	actual, err := file.Stat()
	if err != nil || !os.SameFile(expected, actual) {
		return fail(errors.Join(ErrFakeIPRecoveryCustody, err))
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fail(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fail(err)
	}
	principal, err := runtimeWindowsDescriptorPrincipal(sd, user.User.Sid.String(), rootPrincipal)
	if err != nil {
		return fail(err)
	}
	return file, principal, nil
}
func requireRuntimeWindowsDescriptor(sd *windows.SECURITY_DESCRIPTOR, current string) error {
	_, err := runtimeWindowsDescriptorPrincipal(sd, current, "")
	return err
}
func runtimeWindowsDescriptorPrincipal(sd *windows.SECURITY_DESCRIPTOR, current, verifiedRootPrincipal string) (string, error) {
	if sd == nil {
		return "", ErrFakeIPRecoveryCustody
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return "", ErrFakeIPRecoveryCustody
	}
	ownerSID := owner.String()
	principal := verifiedRootPrincipal
	if principal == "" {
		if current != ownerSID && current != "S-1-5-18" {
			return "", ErrFakeIPRecoveryCustody
		}
		principal = ownerSID
	} else {
		// SYSTEM can create a child with SY/BA default owner, while retaining only
		// the user principal from the same verified root. A normal user must still
		// own its child; no arbitrary owner or foreign inherited ACE is admitted.
		if current != principal && current != "S-1-5-18" {
			return "", ErrFakeIPRecoveryCustody
		}
		if ownerSID != principal && (current != "S-1-5-18" || (ownerSID != "S-1-5-18" && ownerSID != "S-1-5-32-544")) {
			return "", ErrFakeIPRecoveryCustody
		}
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return "", ErrFakeIPRecoveryCustody
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return "", err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return "", ErrFakeIPRecoveryCustody
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return "", ErrFakeIPRecoveryCustody
		}
		value := sid.String()
		if value != principal && value != "S-1-5-18" && value != "S-1-5-32-544" {
			return "", ErrFakeIPRecoveryCustody
		}
	}
	return principal, nil
}
