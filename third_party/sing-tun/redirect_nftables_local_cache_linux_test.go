//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
)

func TestNFTLocalAddressesCommitAndRetry(t *testing.T) {
	old := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}
	// Removing all addresses queues FlushSet operations without intermediate
	// element batches, so the final flush is the actual failure point.
	changed := []netip.Prefix{}
	r := &autoRedirect{enableIPv4: true, localAddresses: old}
	for _, failure := range []error{syscall.EPERM, nil} {
		sent := false
		nft, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
			sent = true
			if len(messages) <= 2 {
				t.Fatalf("missing address update transaction: %d messages", len(messages))
			}
			if !slices.Equal(r.localAddresses, old) {
				t.Fatal("cache changed before transaction completed")
			}
			if failure != nil {
				return nil, failure
			}
			acks := make([]netlink.Message, len(messages)-2)
			for i := range acks {
				acks[i] = netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: []byte{0, 0, 0, 0}}
			}
			return acks, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		table := &nftables.Table{Name: "test", Family: nftables.TableFamilyINet}
		if err := r.nftablesCreateLocalAddressSets(nft, table, changed, r.localAddresses); err != nil {
			t.Fatal(err)
		}
		err = r.commitNFTablesLocalAddresses(nft, changed)
		if !sent || !errors.Is(err, failure) {
			t.Fatalf("sent=%v error=%v want=%v", sent, err, failure)
		}
		if failure != nil {
			if !slices.Equal(r.localAddresses, old) || slices.Equal(r.localAddresses, changed) {
				t.Fatal("failed flush suppressed retry")
			}
		} else if !slices.Equal(r.localAddresses, changed) {
			t.Fatal("successful flush did not commit cache")
		}
		if err := nft.CloseLasting(); err != nil {
			t.Fatal(err)
		}
	}
}
