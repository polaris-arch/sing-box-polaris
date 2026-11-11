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
		return nil, fakeIPRecoveryError("windows.root-open", err)
	}
	return &runtimeJournalRootCustody{file: file, principal: principal}, nil
}

func (r *runtimeJournalRootCustody) Close() error {
	r.access.Lock()
	defer r.access.Unlock()
	if !r.closed {
		r.closed = true
		r.closeErr = fakeIPRecoveryError("windows.root-close", r.file.Close())
	}
	return r.closeErr
}

func (r *runtimeJournalRootCustody) RequireFile(path string, info os.FileInfo) (func() error, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return nil, fakeIPRecoveryError("windows.child.closed-root", ErrFakeIPRecoveryClosed)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fakeIPRecoveryError("windows.child.parent-stat", err)
	}
	rootInfo, err := r.file.Stat()
	if err != nil || !os.SameFile(parent, rootInfo) {
		return nil, fakeIPRecoveryError("windows.child.parent-identity", errors.Join(ErrFakeIPRecoveryCustody, err))
	}
	// Recheck the still-pinned root descriptor. Changing its owner or broadening
	// its ACL cannot turn a formerly accepted principal into current authority.
	sd, err := windows.GetSecurityInfo(windows.Handle(r.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fakeIPRecoveryError("windows.child.root-security", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fakeIPRecoveryError("windows.child.token-user", err)
	}
	principal, err := runtimeWindowsDescriptorPrincipal(sd, user.User.Sid.String(), "")
	if err != nil || principal != r.principal {
		return nil, fakeIPRecoveryError("windows.child.root-principal", errors.Join(ErrFakeIPRecoveryCustody, err))
	}
	file, _, err := openRuntimeWindowsCustody(path, info, false, r.principal)
	if err != nil {
		return nil, fakeIPRecoveryError("windows.child.open", err)
	}
	return runtimeWindowsFileRelease(file), nil
}

func runtimeWindowsFileRelease(file *os.File) func() error {
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() { closeErr = fakeIPRecoveryError("windows.object-close", file.Close()) })
		return closeErr
	}
}

// Compatibility inspection for readiness and independent same-account objects.
// Journal child inspection goes through the verified root token above.
func requireRuntimeJournalCustody(path string, expected os.FileInfo, directory bool) (func() error, error) {
	file, _, err := openRuntimeWindowsCustody(path, expected, directory, "")
	if err != nil {
		return nil, fakeIPRecoveryError("windows.inspect", err)
	}
	return runtimeWindowsFileRelease(file), nil
}

func openRuntimeWindowsCustody(path string, expected os.FileInfo, directory bool, rootPrincipal string) (*os.File, string, error) {
	if expected == nil || expected.Mode()&os.ModeSymlink != 0 || expected.IsDir() != directory || (!directory && !expected.Mode().IsRegular()) {
		return nil, "", fakeIPRecoveryError("windows.native.input-kind", ErrFakeIPRecoveryCustody)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", fakeIPRecoveryError("windows.native.path-encoding", err)
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	// Attribute-only opens do not participate in Windows sharing checks. Hold
	// data-read (directory-list) access so no-delete sharing pins the object.
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		access |= windows.FILE_LIST_DIRECTORY
	} else {
		access |= windows.FILE_READ_DATA
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, "", fakeIPRecoveryError("windows.native.open", err)
	}
	file := os.NewFile(uintptr(handle), path)
	fail := func(cause error) (*os.File, string, error) {
		return nil, "", errors.Join(cause, fakeIPRecoveryError("windows.native.close-after-failure", file.Close()))
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &native); err != nil {
		return fail(fakeIPRecoveryError("windows.native.handle-info", err))
	}
	if native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (native.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fail(fakeIPRecoveryError("windows.native.handle-kind", ErrFakeIPRecoveryCustody))
	}
	actual, err := file.Stat()
	if err != nil || !os.SameFile(expected, actual) {
		return fail(fakeIPRecoveryError("windows.native.identity", errors.Join(ErrFakeIPRecoveryCustody, err)))
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fail(fakeIPRecoveryError("windows.native.security-info", err))
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fail(fakeIPRecoveryError("windows.native.token-user", err))
	}
	principal, err := runtimeWindowsDescriptorPrincipal(sd, user.User.Sid.String(), rootPrincipal)
	if err != nil {
		return fail(fakeIPRecoveryError("windows.native.descriptor", err))
	}
	return file, principal, nil
}

func requireRuntimeWindowsDescriptor(sd *windows.SECURITY_DESCRIPTOR, current string) error {
	_, err := runtimeWindowsDescriptorPrincipal(sd, current, "")
	return err
}

func runtimeWindowsDescriptorPrincipal(sd *windows.SECURITY_DESCRIPTOR, current, verifiedRootPrincipal string) (string, error) {
	if sd == nil {
		return "", fakeIPRecoveryError("windows.descriptor.missing", ErrFakeIPRecoveryCustody)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return "", fakeIPRecoveryError("windows.descriptor.owner-invalid", ErrFakeIPRecoveryCustody)
	}
	ownerSID := owner.String()
	principal := verifiedRootPrincipal
	if principal == "" {
		if current != ownerSID && current != "S-1-5-18" {
			return "", fakeIPRecoveryError("windows.descriptor.root-owner", ErrFakeIPRecoveryCustody)
		}
		principal = ownerSID
	} else {
		// SYSTEM can create a child with SY/BA default owner, while retaining only
		// the user principal from the same verified root. A normal user must still
		// own its child; no arbitrary owner or foreign inherited ACE is admitted.
		if current != principal && current != "S-1-5-18" {
			return "", fakeIPRecoveryError("windows.descriptor.child-current", ErrFakeIPRecoveryCustody)
		}
		if ownerSID != principal && (current != "S-1-5-18" || (ownerSID != "S-1-5-18" && ownerSID != "S-1-5-32-544")) {
			return "", fakeIPRecoveryError("windows.descriptor.child-owner", ErrFakeIPRecoveryCustody)
		}
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return "", fakeIPRecoveryError("windows.descriptor.dacl-invalid", ErrFakeIPRecoveryCustody)
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return "", fakeIPRecoveryError("windows.descriptor.ace-read", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return "", fakeIPRecoveryError("windows.descriptor.ace-kind", ErrFakeIPRecoveryCustody)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return "", fakeIPRecoveryError("windows.descriptor.ace-sid", ErrFakeIPRecoveryCustody)
		}
		value := sid.String()
		if value != principal && value != "S-1-5-18" && value != "S-1-5-32-544" {
			return "", fakeIPRecoveryError("windows.descriptor.ace-principal", ErrFakeIPRecoveryCustody)
		}
	}
	return principal, nil
}

// Create only a new journal under the still-verified root. Establish the owner
// and private DACL at creation rather than relying on a token's default owner.
// Existing evidence is never opened for mutation, repaired, or removed here.
func createRuntimeJournalFile(rootCustody *runtimeJournalRootCustody, path string) (*os.File, error) {
	if rootCustody == nil {
		return nil, fakeIPRecoveryError("windows.create.missing-root", ErrFakeIPRecoveryCustody)
	}
	r := rootCustody
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return nil, fakeIPRecoveryError("windows.create.closed-root", ErrFakeIPRecoveryClosed)
	}
	if r.file == nil || r.principal == "" || !filepath.IsAbs(path) {
		return nil, fakeIPRecoveryError("windows.create.root-authority", ErrFakeIPRecoveryCustody)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.parent-stat", err)
	}
	rootInfo, err := r.file.Stat()
	if err != nil || !os.SameFile(parent, rootInfo) {
		return nil, fakeIPRecoveryError("windows.create.parent-identity", errors.Join(ErrFakeIPRecoveryCustody, err))
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(r.file.Fd()), &native); err != nil {
		return nil, fakeIPRecoveryError("windows.create.root-handle-info", err)
	}
	if native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || native.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, fakeIPRecoveryError("windows.create.root-handle-kind", ErrFakeIPRecoveryCustody)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(r.file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.root-security", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.token-user", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, fakeIPRecoveryError("windows.create.token-user-invalid", ErrFakeIPRecoveryCustody)
	}
	current := user.User.Sid.String()
	principal, err := runtimeWindowsDescriptorPrincipal(sd, current, "")
	if err != nil || principal != r.principal {
		return nil, fakeIPRecoveryError("windows.create.root-principal", errors.Join(ErrFakeIPRecoveryCustody, err))
	}
	// A normal process must be the verified root owner. SYSTEM's own user SID
	// is an admissible child owner under the unchanged descriptor validator.
	if current != principal && current != "S-1-5-18" {
		return nil, fakeIPRecoveryError("windows.create.current-principal", ErrFakeIPRecoveryCustody)
	}
	creationSD, err := windows.SecurityDescriptorFromString("O:" + current + "D:P(A;;FA;;;" + principal + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.security-descriptor", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.path-encoding", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: creationSD,
		InheritHandle:      0,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fakeIPRecoveryError("windows.create.open", err)
	}
	file := os.NewFile(uintptr(handle), path)
	fail := func(cause error) (*os.File, error) {
		return nil, errors.Join(cause, fakeIPRecoveryError("windows.create.close-after-failure", file.Close()))
	}
	created, err := file.Stat()
	if err != nil {
		return fail(fakeIPRecoveryError("windows.create.file-stat", err))
	}
	// Keep the no-delete creation handle alive while the original native
	// validator checks the exact new identity, owner, and all allowed ACEs.
	verified, _, err := openRuntimeWindowsCustody(path, created, false, principal)
	if err != nil {
		return fail(fakeIPRecoveryError("windows.create.file-custody", err))
	}
	if err := verified.Close(); err != nil {
		return fail(fakeIPRecoveryError("windows.create.validation-close", err))
	}
	return file, nil
}
