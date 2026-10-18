//go:build with_tailscale && windows

package tailscale

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsSystemSID = "S-1-5-18"

// Caller pins its OS thread. Never fall back from an inaccessible thread token.
func windowsOpenEffectiveToken(access uint32) (windows.Token, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), access, true, &token)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		err = windows.OpenProcessToken(windows.CurrentProcess(), access, &token)
	}
	return token, err
}

func windowsTokenSID(token windows.Token) (string, error) {
	u, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	if u.User.Sid == nil || !u.User.Sid.IsValid() {
		return "", fmt.Errorf("directory lease: invalid token user")
	}
	return u.User.Sid.String(), nil
}

func windowsTokenPrivileges(token windows.Token) ([]windows.LUIDAndAttributes, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("directory lease: privilege-size query failed: %v", err)
	}
	if size < 4 || size > 64<<10 {
		return nil, fmt.Errorf("directory lease: invalid privilege size")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	if size < 4 || size > uint32(len(buffer)) {
		return nil, fmt.Errorf("directory lease: invalid privilege response")
	}
	p := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	end := uint64(unsafe.Offsetof(p.Privileges)) + uint64(p.PrivilegeCount)*uint64(unsafe.Sizeof(windows.LUIDAndAttributes{}))
	if end > uint64(size) {
		return nil, fmt.Errorf("directory lease: truncated privileges")
	}
	if p.PrivilegeCount == 0 {
		return nil, nil
	}
	return append([]windows.LUIDAndAttributes(nil), p.AllPrivileges()...), nil
}

func windowsRestoreLUID() (windows.LUID, error) {
	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	var luid windows.LUID
	if err == nil {
		err = windows.LookupPrivilegeValue(nil, name, &luid)
	}
	return luid, err
}

// A private copy only. AdjustTokenPrivileges success can mean not assigned;
// query the resulting token and require exactly SeRestorePrivilege enabled.
func windowsRestoreToken(source windows.Token) (_ windows.Token, resultErr error) {
	user, err := windowsTokenSID(source)
	if err != nil {
		return 0, err
	}
	if user != windowsSystemSID {
		return 0, fmt.Errorf("directory lease: owner assignment requires effective SYSTEM")
	}
	var token windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_ADJUST_PRIVILEGES, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		return 0, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, token.Close())
		}
	}()
	if err := windows.AdjustTokenPrivileges(token, true, nil, 0, nil, nil); err != nil {
		return 0, err
	}
	luid, err := windowsRestoreLUID()
	if err != nil {
		return 0, err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return 0, err
	}
	privileges, err := windowsTokenPrivileges(token)
	if err != nil {
		return 0, err
	}
	enabled := false
	for _, p := range privileges {
		if p.Attributes&windows.SE_PRIVILEGE_ENABLED == 0 {
			continue
		}
		if p.Luid != luid {
			return 0, fmt.Errorf("directory lease: unexpected enabled privilege")
		}
		enabled = true
	}
	if !enabled {
		return 0, fmt.Errorf("directory lease: SeRestorePrivilege was not assigned: %w", windows.ERROR_PRIVILEGE_NOT_HELD)
	}
	return token, nil
}

// The SID must equal the retained parent's actual owner. No config SID grants
// impersonation authority, no repair of existing ACLs and no backup-intent flag.
func windowsCreatePrivateAt(parent windows.Handle, name string, directory bool, disposition uint32, write bool, owner string) (created windows.Handle, resultErr error) {
	if disposition != windows.FILE_CREATE && disposition != windows.FILE_OPEN_IF {
		return 0, fmt.Errorf("directory lease: unsupported private create disposition")
	}
	sid, err := windows.StringToSid(owner)
	if err != nil || sid == nil || !sid.IsValid() || sid.String() != owner {
		return 0, fmt.Errorf("directory lease: invalid private owner SID")
	}
	if _, err := windowsInspect(parent, true); err != nil {
		return 0, err
	}
	if err := windowsRequireNTFS(parent); err != nil {
		return 0, err
	}
	parentSD, err := windows.GetSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	parentOwner, _, err := parentSD.Owner()
	if err != nil || parentOwner == nil || !parentOwner.IsValid() || parentOwner.String() != owner {
		return 0, fmt.Errorf("directory lease: private creation owner differs from retained parent")
	}
	sd, err := windowsPrivateDescriptor(owner, directory)
	if err != nil {
		return 0, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, err := windowsOpenEffectiveToken(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE)
	if err != nil {
		return 0, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, source.Close())
		if resultErr != nil && created != 0 {
			resultErr = errors.Join(resultErr, windows.CloseHandle(created))
			created = 0
		}
	}()
	current, err := windowsTokenSID(source)
	if err != nil {
		return 0, err
	}
	if current == owner {
		return windowsOpenAt(parent, name, directory, disposition, write, sd)
	}
	process, err := windowsCurrentSID()
	if err != nil {
		return 0, err
	}
	if current != windowsSystemSID || process != windowsSystemSID {
		return 0, fmt.Errorf("directory lease: foreign owner creation requires SYSTEM process and effective token")
	}
	token, err := windowsRestoreToken(source)
	if err != nil {
		return 0, err
	}
	return windowsCreateOnRestoreThread(parent, name, directory, disposition, write, sd, token)
}

type windowsOwnerCreateResult struct {
	handle windows.Handle
	err    error
}

// Consumes token. No arbitrary callback runs with enhanced privilege. Restore
// failure closes the created handle and exits the locked goroutine without
// unlocking: Go terminates that OS thread instead of returning it to its pool.
func windowsCreateOnRestoreThread(parent windows.Handle, name string, directory bool, disposition uint32, write bool, sd *windows.SECURITY_DESCRIPTOR, token windows.Token) (windows.Handle, error) {
	result := make(chan windowsOwnerCreateResult, 1)
	go func() {
		runtime.LockOSThread()
		var previous windows.Token
		var created windows.Handle
		var err error
		installed := false
		defer func() {
			restored := true
			if installed {
				if e := windows.SetThreadToken(nil, previous); e != nil {
					restored = false
					err = errors.Join(err, fmt.Errorf("directory lease: restore original thread token: %w", e))
				}
			}
			if previous != 0 {
				err = errors.Join(err, previous.Close())
			}
			err = errors.Join(err, token.Close())
			if err != nil && created != 0 {
				err = errors.Join(err, windows.CloseHandle(created))
				created = 0
			}
			if restored {
				runtime.UnlockOSThread()
			}
			result <- windowsOwnerCreateResult{created, err}
		}()
		err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, true, &previous)
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			previous, err = 0, nil
		}
		if err != nil {
			return
		}
		installed = true
		if err = windows.SetThreadToken(nil, token); err != nil {
			return
		}
		created, err = windowsOpenAt(parent, name, directory, disposition, write, sd)
	}()
	value := <-result
	return value.handle, value.err
}
