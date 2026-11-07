//go:build windows

package libbox

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Create only a fresh child of the test-owned short parent. Inherited host ACLs
// are not the positive journal premise; no existing object's ACL is changed.
func commandServerPrivateRecoveryRoot(t *testing.T, parent string) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("private recovery root token owner:", err)
	}
	owner := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal("private recovery root descriptor:", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	root := filepath.Join(parent, "recovery-root")
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal("private recovery root path:", err)
	}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal("create private recovery root:", err)
	}
	return root
}
