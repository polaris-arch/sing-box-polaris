//go:build linux

package tun

import (
	"encoding/binary"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestDockerTableIdentityRead(t *testing.T) {
	for _, kind := range []string{"valid", "zero", "wrongname", "wrongfamily", "missing", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			c := nltest.Dial(func(messages []netlink.Message) ([]netlink.Message, error) {
				if len(messages) != 1 || messages[0].Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE) {
					t.Fatal("not a read")
				}
				value := make([]byte, 8)
				binary.BigEndian.PutUint64(value, 77)
				name := "filter"
				family := byte(nftables.TableFamilyIPv4)
				switch kind {
				case "zero":
					clear(value)
				case "wrongname":
					name = "other"
				case "wrongfamily":
					family = byte(nftables.TableFamilyIPv6)
				}
				attrs := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(name), 0)}}
				if kind != "missing" {
					attrs = append(attrs, netlink.Attribute{Type: dockerNFTATableHandle, Data: value})
				}
				if kind == "duplicate" {
					attrs = append(attrs, attrs[len(attrs)-1])
				}
				raw, err := netlink.MarshalAttributes(attrs)
				if err != nil {
					t.Fatal(err)
				}
				return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE), Sequence: messages[0].Header.Sequence, PID: messages[0].Header.PID}, Data: append([]byte{family, 0, 0, 0}, raw...)}}, nil
			})
			defer c.Close()
			handle, err := readDockerNFTObjectHandle(c, nftables.TableFamilyIPv4, "filter", "")
			if kind == "valid" && (err != nil || handle != 77) {
				t.Fatal("valid identity", err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("accepted invalid identity")
			}
		})
	}
}

func TestDockerChainIdentityRead(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-table", "missing-table", "zero", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			c := nltest.Dial(func(messages []netlink.Message) ([]netlink.Message, error) {
				if len(messages) != 1 || messages[0].Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETCHAIN) {
					t.Fatal("not a chain read")
				}
				value := make([]byte, 8)
				binary.BigEndian.PutUint64(value, 88)
				table := "filter"
				if kind == "zero" {
					clear(value)
				}
				if kind == "wrong-table" {
					table = "other"
				}
				attrs := []netlink.Attribute{{Type: unix.NFTA_CHAIN_NAME, Data: []byte("DOCKER-USER\x00")}, {Type: unix.NFTA_CHAIN_HANDLE, Data: value}}
				if kind != "missing-table" {
					attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_CHAIN_TABLE, Data: append([]byte(table), 0)})
				}
				if kind == "duplicate" {
					attrs = append(attrs, attrs[1])
				}
				raw, err := netlink.MarshalAttributes(attrs)
				if err != nil {
					t.Fatal(err)
				}
				return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN), Sequence: messages[0].Header.Sequence, PID: messages[0].Header.PID}, Data: append([]byte{byte(nftables.TableFamilyIPv4), 0, 0, 0}, raw...)}}, nil
			})
			defer c.Close()
			handle, err := readDockerNFTObjectHandle(c, nftables.TableFamilyIPv4, "filter", "DOCKER-USER")
			if kind == "valid" && (err != nil || handle != 88) {
				t.Fatal("valid chain identity", err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("invalid chain identity accepted")
			}
		})
	}
}
