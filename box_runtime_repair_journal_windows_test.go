package box

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/json"
	"golang.org/x/sys/windows"
)

// Exercise the actual Box -> journal/cache -> namespace -> delivered-answer
// chain with a newly created private DACL root. The test never edits an ACL on
// an existing host object or starts/impersonates SYSTEM.
func TestRuntimeWindowsPrivateJournalBoxColdRecoveryRetainsIssuedAnswer(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	root := filepath.Join(t.TempDir(), "box-private-root")
	name, _ := windows.UTF16PtrFromString(root)
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cache.db")
	f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
	options.Context = adapter.ContextWithRuntimeRecoveryRoot(options.Context, root)
	runtimeFakeIPCleanupBox(t, f, options)
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "exact_configuration_file", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	next := runtimeClientFakeIPIPv6(t, options.Options)
	content, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	_, request := runtimeClientPlan(t, f, content)
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || !operation.Durable {
		t.Fatal("real namespace transaction not durable", operation, err)
	}
	store, err := f.box.runtime.fakeIP.Borrow(netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:2::/48"))
	if err != nil {
		t.Fatal(err)
	}
	address, err := store.Create("windows-issued.example", false)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	answer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "windows-issued.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600}, A: net.IP(address.AsSlice())}}})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	answer.Delivered(time.Now())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
	cold, restart := runtimeFakeIPCleanupConstruction(t, path, nil)
	restart.Context = adapter.ContextWithRuntimeRecoveryRoot(restart.Context, root)
	restart.Options = runtimeClientFakeIPIPv6(t, restart.Options)
	runtimeFakeIPCleanupBox(t, cold, restart)
	cold.start(t)
	if domain, ok := cold.box.runtime.fakeIP.RecognitionStore().Lookup(address); !ok || domain != "windows-issued.example" {
		t.Fatal("Windows journal reopen lost actually issued answer", domain, ok)
	}
	runtimeFakeIPCleanupAssertSuccess(t, cold.box)
}
