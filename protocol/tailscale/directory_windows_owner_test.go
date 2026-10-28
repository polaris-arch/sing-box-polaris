//go:build with_tailscale && windows

package tailscale

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	windowsSystemInteropRoot   = flag.String("polaris-directory-system-root", "", "existing private user-owned config fixture")
	windowsSystemInteropNonce  = flag.String("polaris-directory-system-nonce", "", "random 32 lowercase hex nonce")
	windowsSystemInteropOwner  = flag.String("polaris-directory-system-owner", "", "expected user owner SID, never SYSTEM")
	windowsSystemInteropServer = flag.String("polaris-directory-system-server", "node", "node or system-node")
)

func windowsTestTokenID(token windows.Token) (windows.LUID, error) {
	var data [128]byte
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenStatistics, &data[0], uint32(len(data)), &size); err != nil {
		return windows.LUID{}, err
	}
	if size < uint32(unsafe.Sizeof(windows.LUID{})) {
		return windows.LUID{}, fmt.Errorf("short token statistics")
	}
	return *(*windows.LUID)(unsafe.Pointer(&data[0])), nil
}

func windowsTestPrivilegeState(token windows.Token) (map[windows.LUID]uint32, error) {
	entries, err := windowsTokenPrivileges(token)
	if err != nil {
		return nil, err
	}
	result := make(map[windows.LUID]uint32, len(entries))
	for _, p := range entries {
		result[p.Luid] = p.Attributes & ^uint32(windows.SE_PRIVILEGE_USED_FOR_ACCESS)
	}
	return result, nil
}

// Test-only callback fixture. The production privileged helper accepts no
// arbitrary callback. Failed restoration retires this isolated OS thread.
func windowsTestWithToken(token windows.Token, callback func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		var original windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, true, &original)
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			original, err = 0, nil
		}
		installed := false
		defer func() {
			restored := true
			if installed {
				if e := windows.SetThreadToken(nil, original); e != nil {
					restored = false
					err = errors.Join(err, e)
				}
			}
			if original != 0 {
				err = errors.Join(err, original.Close())
			}
			if restored {
				runtime.UnlockOSThread()
			}
			result <- err
		}()
		if err != nil {
			return
		}
		installed = true
		if err = windows.SetThreadToken(nil, token); err != nil {
			return
		}
		before, idErr := windowsTestTokenID(token)
		if idErr != nil {
			err = idErr
			return
		}
		err = callback()
		var current windows.Token
		if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &current); e != nil {
			err = errors.Join(err, e)
			return
		}
		after, idErr := windowsTestTokenID(current)
		err = errors.Join(err, idErr, current.Close())
		if before != after {
			err = errors.Join(err, fmt.Errorf("caller impersonation token was replaced"))
		}
	}()
	return <-result
}

func TestWindowsDirectoryForeignOwnerRejectsUnverifiedParent(t *testing.T) {
	root := t.TempDir()
	chain, err := windowsOpenPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.close()
	owner, err := windowsOwnerOfParent(chain.last())
	if err != nil {
		t.Fatal(err)
	}
	wrong := windowsSystemSID
	if owner == wrong {
		wrong = "S-1-5-32-545"
	}
	l := &directoryLease{ownerSID: wrong}
	h, err := l.openPrivate(chain.last(), "unverified-owner", true, windows.FILE_CREATE, false)
	if h != 0 {
		_ = windows.CloseHandle(h)
		t.Fatal("unverified owner returned handle")
	}
	if err == nil || !strings.Contains(err.Error(), "differs from retained parent") {
		t.Fatalf("wrong owner not rejected before create: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "unverified-owner")); !os.IsNotExist(err) {
		t.Fatal("owner rejection created an object", err)
	}
}

func TestWindowsDirectoryForeignOwnerRejectsNonSystemToken(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, err := windowsOpenEffectiveToken(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	sid, err := windowsTokenSID(source)
	if err != nil {
		t.Fatal(err)
	}
	if sid == windowsSystemSID {
		t.Skip("ordinary-user negative case; explicit SYSTEM entry runs separately")
	}
	before, err := windowsTestPrivilegeState(source)
	if err != nil {
		t.Fatal(err)
	}
	token, err := windowsRestoreToken(source)
	if token != 0 {
		_ = token.Close()
		t.Fatal("non-SYSTEM obtained restore token")
	}
	if err == nil || !strings.Contains(err.Error(), "requires effective SYSTEM") {
		t.Fatal("non-SYSTEM source not rejected", err)
	}
	after, err := windowsTestPrivilegeState(source)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("negative control altered privileges", err)
	}
}

// Remove SeRestore from a real impersonation token. Production acquisition must
// not bypass this restriction by falling back to the stronger process token.
func windowsTestSystemMissingRestore(root string, source windows.Token) error {
	var restricted windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE|windows.TOKEN_ADJUST_PRIVILEGES, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &restricted); err != nil {
		return err
	}
	defer restricted.Close()
	luid, err := windowsRestoreLUID()
	if err != nil {
		return err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_REMOVED}}}
	if err := windows.AdjustTokenPrivileges(restricted, false, &state, 0, nil, nil); err != nil {
		return err
	}
	privileges, err := windowsTestPrivilegeState(restricted)
	if err != nil {
		return err
	}
	if _, ok := privileges[luid]; ok {
		return fmt.Errorf("fixture did not remove SeRestore")
	}
	physical := filepath.Join(root, "rejected-no-restore")
	if _, err := os.Lstat(physical); !os.IsNotExist(err) {
		return fmt.Errorf("missing-privilege root must be absent")
	}
	err = windowsTestWithToken(restricted, func() error {
		lease, err := acquireDirectoryLease(filepath.Join(physical, "node"))
		if lease != nil {
			_ = lease.releaseHandles()
			return fmt.Errorf("missing SeRestore admitted a lease")
		}
		if err == nil || (!errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) && !strings.Contains(err.Error(), "SeRestorePrivilege")) {
			return fmt.Errorf("missing privilege did not reach explicit rejection: %v", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if _, err := os.Lstat(physical); !os.IsNotExist(err) {
		return fmt.Errorf("missing privilege left root: %v", err)
	}
	return nil
}

// Exact test-only entry. A separately authorized runner launches LocalSystem,
// the ordinary user owns/consumes/cleans the fixture. No task or account is
// created here. Successful ready follows real production source activation.
func TestWindowsDirectorySystemInteropChild(t *testing.T) {
	root, nonce, owner, server := *windowsSystemInteropRoot, *windowsSystemInteropNonce, *windowsSystemInteropOwner, *windowsSystemInteropServer
	if root == "" {
		t.Skip("explicit SYSTEM runner requires root/nonce/owner flags")
	}
	if !validDirectoryNonce(nonce) || !windowsCanonicalPath(root) || owner == "" || owner == windowsSystemSID || (server != "node" && server != "system-node") {
		t.Fatal("invalid SYSTEM request")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, err := windowsOpenEffectiveToken(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	effective, err := windowsTokenSID(source)
	if err != nil || effective != windowsSystemSID {
		t.Fatal("SYSTEM entry needs effective LocalSystem", effective, err)
	}
	process, err := windowsCurrentSID()
	if err != nil || process != windowsSystemSID {
		t.Fatal("SYSTEM entry needs LocalSystem process", process, err)
	}
	processBefore, err := windowsTestPrivilegeState(windows.GetCurrentProcessToken())
	if err != nil {
		t.Fatal(err)
	}
	sourceBefore, err := windowsTestPrivilegeState(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceID, err := windowsTestTokenID(source)
	if err != nil {
		t.Fatal(err)
	}
	luid, err := windowsRestoreLUID()
	if err != nil {
		t.Fatal(err)
	}
	attributes, exists := processBefore[luid]
	if !exists || attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
		t.Fatal("default SYSTEM fixture needs SeRestore present but disabled")
	}
	attributes, exists = sourceBefore[luid]
	if !exists || attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
		t.Fatal("effective SYSTEM SeRestore must initially be disabled")
	}
	assertUnchanged := func() {
		t.Helper()
		after, err := windowsTestPrivilegeState(windows.GetCurrentProcessToken())
		if err != nil || !reflect.DeepEqual(processBefore, after) {
			t.Fatal("process privileges changed", err)
		}
		current, err := windowsOpenEffectiveToken(windows.TOKEN_QUERY)
		if err != nil {
			t.Fatal(err)
		}
		defer current.Close()
		id, err := windowsTestTokenID(current)
		if err != nil || id != sourceID {
			t.Fatal("caller effective token changed", err)
		}
		after, err = windowsTestPrivilegeState(current)
		if err != nil || !reflect.DeepEqual(sourceBefore, after) {
			t.Fatal("caller privileges changed", err)
		}
	}
	chain, err := windowsOpenPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.close()
	actualOwner, err := windowsOwnerOfParent(chain.last())
	if err != nil || actualOwner != owner {
		t.Fatal("root owner differs from expected user", actualOwner, err)
	}
	if err := windowsRequirePrivate(chain.last(), owner); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "tailscale-windows-v1", server)
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("SYSTEM target must be absent")
	}
	if err := windowsTestSystemMissingRestore(root, source); err != nil {
		t.Fatal(err)
	}
	assertUnchanged()
	wrong := &directoryLease{ownerSID: windowsSystemSID}
	h, err := wrong.openPrivate(chain.last(), "rejected-owner", true, windows.FILE_CREATE, false)
	if h != 0 {
		_ = windows.CloseHandle(h)
		t.Fatal("mismatched owner returned handle")
	}
	if err == nil || !strings.Contains(err.Error(), "differs from retained parent") {
		t.Fatal("mismatched parent owner accepted", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "rejected-owner")); !os.IsNotExist(err) {
		t.Fatal("owner mismatch created object")
	}
	assertUnchanged()
	// Force a genuine native create collision after temporary token installation.
	fixture := &directoryLease{ownerSID: owner}
	partial, err := fixture.openPrivate(chain.last(), "partial-owner-create", true, windows.FILE_CREATE, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CloseHandle(partial); err != nil {
		t.Fatal(err)
	}
	h, err = fixture.openPrivate(chain.last(), "partial-owner-create", true, windows.FILE_CREATE, false)
	if h != 0 {
		_ = windows.CloseHandle(h)
		t.Fatal("collision returned handle")
	}
	if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatal("expected native create collision", err)
	}
	assertUnchanged()
	if l, err := acquireDirectoryLease(filepath.Join(root, "partial-owner-create", "node")); err == nil || l != nil {
		if l != nil {
			_ = l.releaseHandles()
		}
		t.Fatal("partial unmarked domain adopted")
	}
	lease, err := windowsTestManagedWriter(root, server)
	if err != nil {
		t.Fatal(err)
	}
	if !lease.Managed || lease.ownerSID != owner {
		_ = lease.releaseHandles()
		t.Fatal("SYSTEM did not preserve user ownership")
	}
	identity, inc, epoch := lease.Identity, lease.Incarnation, lease.Epoch
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertUnchanged()
	lease, err = windowsTestManagedWriter(root, server)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.releaseHandles()
	if lease.Identity != identity || lease.Incarnation != inc || lease.Epoch == epoch {
		t.Fatal("SYSTEM reopen generation/epoch mismatch")
	}
	assertUnchanged()
	if err := windowsTestSignal(filepath.Join(root, "interop-ready"), nonce); err != nil {
		t.Fatal(err)
	}
	t.Log("WINDOWS_DIRECTORY_SYSTEM_INTEROP_READY", nonce, owner, server)
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		closeRequested, err := windowsTestHasSignal(filepath.Join(root, "interop-close"), nonce)
		if err != nil {
			t.Fatal(err)
		}
		if closeRequested {
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if lease.target != 0 || lease.lifetime != 0 {
				t.Fatal("SYSTEM Close retained custody")
			}
			assertUnchanged()
			if err := windowsTestSignal(filepath.Join(root, "interop-closed"), nonce); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("SYSTEM close deadline expired")
		case <-ticker.C:
		}
	}
}
