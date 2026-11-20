//go:build linux

package tun

import (
	"errors"
	"syscall"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"golang.org/x/sys/unix"
)

func TestNFTExclusiveCommit(t *testing.T) {
	for _, failure := range []error{nil, syscall.EEXIST, syscall.EPERM} {
		name := "success"
		if failure != nil {
			name = failure.Error()
		}
		t.Run(name, func(t *testing.T) {
			sent := false
			nft, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
				sent = true
				if len(messages) != 3 {
					t.Fatalf("unexpected transaction: %d messages", len(messages))
				}
				msg := messages[1]
				if uint16(msg.Header.Type) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE || msg.Header.Flags&netlink.Excl == 0 {
					t.Fatalf("table creation is not exclusive: %+v", msg.Header)
				}
				if failure != nil {
					return nil, failure
				}
				return []netlink.Message{{Header: netlink.Header{Type: netlink.Error}, Data: []byte{0, 0, 0, 0}}}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			nft.CreateTable(&nftables.Table{Name: "test", Family: nftables.TableFamilyINet})
			r := &autoRedirect{useNFTables: true}
			err = r.commitNFTables(nft)
			if !sent || !errors.Is(err, failure) {
				t.Fatalf("sent=%v err=%v want=%v", sent, err, failure)
			}
			if r.firewallSetupAttempted.Load() != (failure == nil) {
				t.Fatal("cleanup armed without confirmed commit")
			}
			if failure != nil {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
