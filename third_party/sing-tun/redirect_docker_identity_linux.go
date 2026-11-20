//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// NFTA_TABLE_HANDLE from Linux uapi/linux/netfilter/nf_tables.h.
// Not exported by the pinned x/sys package.
const dockerNFTATableHandle = 4

// Docker compatibility runs only in the caller's default network namespace.
// Table handles and rule handles distinguish replacement objects; neither
// names nor comments are ownership. Keep this read inside the generation window.
func getDockerNFTObjectHandle(family nftables.TableFamily, table, chain string) (uint64, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, err
	}
	return readDockerNFTObjectHandle(conn, family, table, chain)
}

func readDockerNFTObjectHandle(conn *netlink.Conn, family nftables.TableFamily, table, chain string) (uint64, error) {
	name, nameAttr, handleAttr := table, uint16(unix.NFTA_TABLE_NAME), uint16(dockerNFTATableHandle)
	requestType, replyType := unix.NFT_MSG_GETTABLE, unix.NFT_MSG_NEWTABLE
	attributes := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(table), 0)}}
	if chain != "" {
		name, nameAttr, handleAttr = chain, unix.NFTA_CHAIN_NAME, unix.NFTA_CHAIN_HANDLE
		requestType, replyType = unix.NFT_MSG_GETCHAIN, unix.NFT_MSG_NEWCHAIN
		attributes = []netlink.Attribute{{Type: unix.NFTA_CHAIN_TABLE, Data: append([]byte(table), 0)}, {Type: unix.NFTA_CHAIN_NAME, Data: append([]byte(chain), 0)}}
	}
	attrs, err := netlink.MarshalAttributes(attributes)
	if err != nil {
		return 0, err
	}
	replies, err := conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | requestType), Flags: netlink.Request},
		Data:   append([]byte{byte(family), 0, 0, 0}, attrs...),
	})
	if err != nil {
		return 0, err
	}
	if len(replies) != 1 || replies[0].Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|replyType) || len(replies[0].Data) < 4 || replies[0].Data[0] != byte(family) {
		return 0, errors.New("invalid Docker object identity response")
	}
	decoder, err := netlink.NewAttributeDecoder(replies[0].Data[4:])
	if err != nil {
		return 0, err
	}
	decoder.ByteOrder = binary.BigEndian
	var handle uint64
	var gotName string
	var names, handles, tables int
	var gotTable string
	for decoder.Next() {
		if chain != "" && decoder.Type() == unix.NFTA_CHAIN_TABLE {
			gotTable = decoder.String()
			tables++
			continue
		}
		switch decoder.Type() {
		case nameAttr:
			gotName = decoder.String()
			names++
		case handleAttr:
			handle = decoder.Uint64()
			handles++
		}
	}
	if err := decoder.Err(); err != nil {
		return 0, err
	}
	if names != 1 || handles != 1 || gotName != name || handle == 0 || (chain != "" && (tables != 1 || gotTable != table)) {
		return 0, errors.New("Docker object handle missing or mismatched")
	}
	return handle, nil
}
