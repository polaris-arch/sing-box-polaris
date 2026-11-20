//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestGoogleNFTGenerationBatchErrors(t *testing.T) {
	for _, failure := range []syscall.Errno{syscall.ERESTART, syscall.EOPNOTSUPP, syscall.EINVAL} {
		t.Run(failure.Error(), func(t *testing.T) {
			sends := 0
			c, err := nftables.New(nftables.WithTestDial(func(msgs []netlink.Message) ([]netlink.Message, error) {
				if len(msgs) == 0 {
					return nil, nil
				}
				sends++
				if len(msgs) != 4 {
					t.Fatalf("expected two operations: %d", len(msgs))
				}
				attrs, err := netlink.UnmarshalAttributes(msgs[0].Data[4:])
				if err != nil || len(attrs) != 1 || attrs[0].Type != unix.NFNL_BATCH_GENID || binary.BigEndian.Uint32(attrs[0].Data) != 17 {
					t.Fatal("genid not encoded", err)
				}
				code := make([]byte, 4)
				binary.NativeEndian.PutUint32(code, uint32(-int32(failure)))
				return []netlink.Message{{Header: netlink.Header{Type: netlink.Error, Sequence: msgs[0].Header.Sequence}, Data: code}}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			c.DelTable(&nftables.Table{Name: "one"})
			c.DelTable(&nftables.Table{Name: "two"})
			if err = c.FlushWithGenID(17); !errors.Is(err, failure) || sends != 1 {
				t.Fatalf("err=%v sends=%d", err, sends)
			}
		})
	}
}

func TestGoogleNFTGetGenAndEchoHandle(t *testing.T) {
	c, err := nftables.New(nftables.WithTestDial(func(msgs []netlink.Message) ([]netlink.Message, error) {
		if len(msgs) == 0 {
			return nil, nil
		}
		if len(msgs) == 1 {
			if msgs[0].Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETGEN) {
				t.Fatal("wrong getgen")
			}
			attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0, 17}}})
			return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWGEN), Sequence: msgs[0].Header.Sequence}, Data: append([]byte{0, 0, 0, 0}, attrs...)}}, nil
		}
		if len(msgs) != 3 || msgs[1].Header.Flags&netlink.Echo == 0 {
			t.Fatal("no rule echo request")
		}
		handle := make([]byte, 8)
		binary.BigEndian.PutUint64(handle, 777)
		attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_RULE_HANDLE, Data: handle}})
		return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE), Sequence: msgs[1].Header.Sequence}, Data: append([]byte{0, 0, 0, 0}, attrs...)}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	gen, err := c.GetGen()
	if err != nil || gen.ID != 17 {
		t.Fatal("getgen", gen, err)
	}
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	rule := c.InsertRule(&nftables.Rule{Table: table, Chain: &nftables.Chain{Name: "DOCKER-USER", Table: table}})
	if err = c.FlushWithGenID(gen.ID); err != nil || rule.Handle != 777 {
		t.Fatal("echo handle", rule.Handle, err)
	}
}

func TestGoogleNFTEmptyFlushDoesNotProbe(t *testing.T) {
	c, err := nftables.New(nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
		t.Fatal("unexpected empty batch send")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.FlushWithGenID(17); err != nil {
		t.Fatal(err)
	}
}
