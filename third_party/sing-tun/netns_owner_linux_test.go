package tun

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestNativeNamespaceCleanupUsesPinnedObjectAfterPathReplacement(t *testing.T) {
	// FD 11 represents the acquired namespace. The original path can now map
	// to FD 22; execution must never resolve it again or enter that replacement.
	var enters []int
	namespace := &pinnedNetworkNamespace{fd: 11, enter: func(fd, _ int) error { enters = append(enters, fd); return nil }, release: func(int) error { return nil }}
	tun := &NativeTun{options: Options{Name: "owned", NetNs: "same-path"}, networkNamespace: namespace, namespaceRequired: true}
	if err := tun.runInOwnedNamespace(func() error {
		return tun.ownedRoutes.install([]netlink.Route{ownershipRoute(100)}, func(*netlink.Route) error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
	removed := 0
	if err := tun.runInOwnedNamespace(func() error { return tun.ownedRoutes.clear(func(*netlink.Route) error { removed++; return nil }) }); err != nil {
		t.Fatal(err)
	}
	if len(enters) != 2 || enters[0] != 11 || enters[1] != 11 || removed != 1 {
		t.Fatalf("namespace binding changed: %v", enters)
	}
}

func TestNativeNamespaceEnterFailurePreservesDebt(t *testing.T) {
	failure := errors.New("cannot enter original namespace")
	namespace := &pinnedNetworkNamespace{fd: 11, enter: func(int, int) error { return failure }, release: func(int) error { return nil }}
	tun := &NativeTun{networkNamespace: namespace, namespaceRequired: true}
	_ = tun.ownedRoutes.install([]netlink.Route{ownershipRoute(100)}, func(*netlink.Route) error { return nil })
	called := false
	err := tun.runInOwnedNamespace(func() error { called = true; return tun.ownedRoutes.clear(func(*netlink.Route) error { return nil }) })
	if !errors.Is(err, failure) || called || len(tun.ownedRoutes.routes) != 1 {
		t.Fatal("enter failure discarded cleanup debt")
	}
	missing := &NativeTun{namespaceRequired: true}
	if err := missing.runInOwnedNamespace(func() error { t.Fatal("missing pin bypassed"); return nil }); err == nil {
		t.Fatal("missing identity accepted")
	}
}

func TestNamespacePinCloseJoinsRunningOperation(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	namespace := &pinnedNetworkNamespace{fd: 11, enter: func(int, int) error { return nil }, release: func(int) error { released.Store(true); return nil }}
	workDone := make(chan error, 1)
	go func() { workDone <- namespace.run(func() error { close(entered); <-unblock; return nil }) }()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- namespace.close() }()
	if released.Load() {
		t.Fatal("released pin while operation active")
	}
	close(unblock)
	for _, ch := range []<-chan error{workDone, closeDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("namespace operation did not finish")
		}
	}
	if !released.Load() {
		t.Fatal("pin was not released")
	}
	if err := namespace.run(func() error { t.Fatal("closed pin reused"); return nil }); err == nil {
		t.Fatal("closed pin accepted work")
	}
}

func TestNativeQueueUsesNamespacePinAndRejectsClosedOwner(t *testing.T) {
	enteredFD := -1
	namespace := &pinnedNetworkNamespace{fd: 11, enter: func(fd, _ int) error { enteredFD = fd; return nil }, release: func(int) error { return nil }}
	tun := &NativeTun{options: Options{Name: "owned", NetNs: "rebound-path", GSO: true}, multiQueue: true, networkNamespace: namespace, namespaceRequired: true}
	opened := 0
	openDevice := func(name string, flags int) (int, error) {
		opened++
		if enteredFD != 11 || name != "owned" || flags&unix.IFF_MULTI_QUEUE == 0 || flags&unix.IFF_VNET_HDR == 0 {
			t.Error("queue used wrong owner or flags")
		}
		return 99, nil
	}
	fd, err := tun.openQueueWith(openDevice)
	if err != nil || fd != 99 || opened != 1 {
		t.Fatalf("queue open: fd=%d err=%v", fd, err)
	}
	tun.routeAccess.Lock()
	tun.ownedRoutes.closed = true
	tun.routeAccess.Unlock()
	if _, err := tun.openQueueWith(openDevice); err == nil || opened != 1 {
		t.Fatal("closed owner opened another queue")
	}
}

func TestNativeQueueNamespaceEntryFailureDoesNotOpenDevice(t *testing.T) {
	failure := errors.New("namespace unavailable")
	namespace := &pinnedNetworkNamespace{fd: 11, enter: func(int, int) error { return failure }, release: func(int) error { return nil }}
	tun := &NativeTun{multiQueue: true, networkNamespace: namespace, namespaceRequired: true}
	if fd, err := tun.openQueueWith(func(string, int) (int, error) { t.Fatal("opened queue outside original namespace"); return 99, nil }); fd != -1 || !errors.Is(err, failure) {
		t.Fatalf("failed namespace entry not preserved: fd=%d err=%v", fd, err)
	}
}
