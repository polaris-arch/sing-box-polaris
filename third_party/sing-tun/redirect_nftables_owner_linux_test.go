//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/sys/unix"
)

type ownerTestFinder struct {
	control.InterfaceFinder
	update     func() error
	interfaces []control.Interface
}

func (f ownerTestFinder) Update() error {
	if f.update != nil {
		return f.update()
	}
	return nil
}
func (f ownerTestFinder) Interfaces() []control.Interface { return f.interfaces }

func TestNFTOwnerEarlySetupFailureClosesAndLatches(t *testing.T) {
	for _, failure := range []error{syscall.EOPNOTSUPP, syscall.EPERM} {
		t.Run(failure.Error(), func(t *testing.T) {
			sent := false
			nft, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
				sent = true
				for _, msg := range messages {
					if uint16(msg.Header.Type) == unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE {
						if msg.Header.Flags&netlink.Excl == 0 {
							t.Error("creation not exclusive")
						}
						attrs, decodeErr := netlink.UnmarshalAttributes(msg.Data[4:])
						if decodeErr != nil {
							t.Fatal(decodeErr)
						}
						owner := false
						for _, attr := range attrs {
							if attr.Type == unix.NFTA_TABLE_FLAGS {
								owner = binaryutil.BigEndian.Uint32(attr.Data) == nftTableFlagOwner
							}
						}
						if !owner {
							t.Error("missing non-persistent OWNER flag")
						}
					}
				}
				return nil, failure
			}))
			if err != nil {
				t.Fatal(err)
			}
			r := &autoRedirect{tableName: "test", enableIPv4: true, tunOptions: &Options{}, interfaceFinder: ownerTestFinder{interfaces: []control.Interface{{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}}}
			err = r.setupNFTablesWithOwner(func() (*nftables.Conn, error) { return nft, nil })
			if !errors.Is(err, failure) || !sent || r.nftConn != nil || !r.nftClosed {
				t.Fatalf("failure not retained/closed: sent=%v err=%v closed=%v", sent, err, r.nftClosed)
			}
			// The first set Flush occurs before final commit; it must not leak an owner.
			if r.firewallSetupAttempted.Load() {
				t.Fatal("final commit unexpectedly reached")
			}
			if err = r.setupNFTablesWithOwner(func() (*nftables.Conn, error) { t.Fatal("reopened closed owner"); return nil, nil }); err == nil {
				t.Fatal("closed setup accepted")
			}
		})
	}
}

func TestNFTOwnerPreFlushFailureCloses(t *testing.T) {
	failure := errors.New("finder failed")
	nft, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) { t.Error("unexpected send"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	r := &autoRedirect{interfaceFinder: ownerTestFinder{update: func() error { return failure }}}
	if err = r.setupNFTablesWithOwner(func() (*nftables.Conn, error) { return nft, nil }); !errors.Is(err, failure) || r.nftConn != nil || !r.nftClosed {
		t.Fatalf("err=%v closed=%v", err, r.nftClosed)
	}
}

func TestNFTOwnerCleanupWaitsForUpdateAndRejectsLateCallback(t *testing.T) {
	nft, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
		t.Error("unexpected transient/send")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	r := &autoRedirect{nftConn: nft, tunOptions: &Options{NetNs: "synthetic"}, interfaceFinder: ownerTestFinder{update: func() error { close(entered); <-release; return nil }}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := r.updateNetworkAddresses(); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	go func() {
		defer wg.Done()
		if err := r.cleanupNFTables(); err != nil {
			t.Error(err)
		}
	}()
	close(release)
	wg.Wait()
	if r.nftConn != nil || !r.nftClosed {
		t.Fatal("owner not detached")
	}
	r.interfaceFinder = nil
	if err := r.updateNetworkAddresses(); err != nil {
		t.Fatal(err)
	}
	if err := r.cleanupNFTables(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTOwnerCloseReleasesSocketWhenNamespaceIsGone(t *testing.T) {
	nft, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) { t.Error("unexpected send"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	r := &autoRedirect{useNFTables: true, nftConn: nft, tunOptions: &Options{NetNs: t.TempDir() + "/missing"}}
	r.firewallSetupAttempted.Store(true)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Close(); err == nil {
				t.Error("missing namespace error lost")
			}
		}()
	}
	wg.Wait()
	if r.nftConn != nil || !r.nftClosed {
		t.Fatal("owner socket retained")
	}
	if err := r.updateNetworkAddresses(); err != nil {
		t.Fatal(err)
	}
}

// This fixture uses the pinned dependency's test netlink transport, not a kernel
// ruleset. A live nlconn assertion also detects its silent transient fallback.
func TestNFTOwnerSuccessfulSetupUpdateAndFailedUpdate(t *testing.T) {
	for _, failUpdate := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "update-error"}[failUpdate], func(t *testing.T) {
			batches, queries, sends := 0, 0, 0
			failBatch := false
			nft, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
				sends++
				for _, msg := range messages {
					if uint16(msg.Header.Type) == unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE {
						t.Error("name-based delete emitted")
					}
				}
				if len(messages) == 1 && uint16(messages[0].Header.Type) == unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE {
					attrs, e := netlink.UnmarshalAttributes(messages[0].Data[4:])
					if e != nil {
						return nil, e
					}
					name := ""
					for _, a := range attrs {
						if a.Type == unix.NFTA_TABLE_NAME {
							name = strings.TrimRight(string(a.Data), "\x00")
						}
					}
					if name == "fw4" {
						return nil, syscall.ENOENT
					}
					queries++
					data, e := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(name + "\x00")}, {Type: unix.NFTA_TABLE_FLAGS, Data: binaryutil.BigEndian.PutUint32(nftTableFlagOwner)}})
					if e != nil {
						return nil, e
					}
					return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE), Sequence: messages[0].Header.Sequence, PID: messages[0].Header.PID}, Data: append([]byte{byte(nftables.TableFamilyINet), 0, 0, 0}, data...)}}, nil
				}
				batches++
				if failBatch {
					return nil, syscall.EPERM
				}
				return []netlink.Message{{Header: netlink.Header{Type: netlink.Error}, Data: []byte{0, 0, 0, 0}}}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			socket := func() uintptr { return reflect.ValueOf(nft).Elem().FieldByName("nlconn").Pointer() }
			originalSocket := socket()
			if originalSocket == 0 {
				t.Fatal("no lasting socket")
			}
			finder := &ownerTestFinder{interfaces: []control.Interface{{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}}
			r := &autoRedirect{tableName: "test-owner", customRedirectPort: 1234, enableIPv4: true, tunOptions: &Options{Name: "tun-test", NetNs: "synthetic"}, interfaceFinder: finder, logger: logger.NOP()}
			if err := r.setupNFTablesWithOwner(func() (*nftables.Conn, error) { return nft, nil }); err != nil {
				t.Fatal(err)
			}
			if batches < 2 || r.nftConn != nft || socket() != originalSocket {
				t.Fatalf("setup lost owner: batches=%d", batches)
			}
			before := batches
			finder.interfaces = []control.Interface{{Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}}}
			failBatch = failUpdate
			err = r.updateNetworkAddresses()
			if failUpdate {
				if !errors.Is(err, syscall.EPERM) || r.nftConn != nil || !r.nftClosed || socket() != 0 {
					t.Fatalf("failed update kept owner: %v", err)
				}
			} else {
				if err != nil || batches <= before || queries != 1 || socket() != originalSocket {
					t.Fatalf("update did not reuse owner: batches=%d queries=%d err=%v", batches, queries, err)
				}
				if err = r.cleanupNFTables(); err != nil {
					t.Fatal(err)
				}
				if socket() != 0 {
					t.Fatal("cleanup did not close lasting socket")
				}
			}
			count := sends
			finder.update = func() error { t.Error("late callback reached finder"); return nil }
			if err = r.updateNetworkAddresses(); err != nil {
				t.Fatal(err)
			}
			if sends != count {
				t.Fatal("closed owner sent again")
			}
		})
	}
}
