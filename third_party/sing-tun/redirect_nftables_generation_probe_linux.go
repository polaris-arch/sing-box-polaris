//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const nftGenerationProbeTimeout = 2 * time.Second

// probeNFTablesGeneration checks enforcement, not just attribute acceptance.
// Call in the target network namespace, after GetGen, with a DIFFERENT nonzero
// generation. It sends exactly one empty batch and never any ruleset operation.
// Only ERESTART associated with its begin message is positive evidence. A racing
// generation can match expected and make the probe inconclusive; do not retry
// here or treat a successful ACK as enforcement. No ruleset state is changed.
func probeNFTablesGeneration(expected uint32) error {
	if expected == 0 {
		return errors.New("nftables generation probe requires a nonzero expected generation")
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("dial nftables generation probe: %w", err)
	}
	defer conn.Close()
	return probeNFTablesGenerationWithConn(conn, expected)
}

type nftGenerationProbeConn interface {
	SetDeadline(time.Time) error
	SendMessages([]netlink.Message) ([]netlink.Message, error)
	Receive() ([]netlink.Message, error)
}

func probeNFTablesGenerationWithConn(conn nftGenerationProbeConn, expected uint32) error {
	if expected == 0 {
		return errors.New("nftables generation probe requires a nonzero expected generation")
	}
	if err := conn.SetDeadline(time.Now().Add(nftGenerationProbeTimeout)); err != nil {
		return fmt.Errorf("set nftables generation probe deadline: %w", err)
	}
	generation := make([]byte, 4)
	binary.BigEndian.PutUint32(generation, expected)
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFNL_BATCH_GENID, Data: generation}})
	if err != nil {
		return fmt.Errorf("encode nftables generation probe: %w", err)
	}
	// nfgenmsg: AF_UNSPEC, NFNETLINK_V0, big-endian NFTABLES subsystem id.
	header := []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}
	sent, err := conn.SendMessages([]netlink.Message{
		{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request | netlink.Acknowledge}, Data: append(append([]byte(nil), header...), attrs...)},
		{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}, Data: header},
	})
	if err != nil {
		return fmt.Errorf("send nftables generation probe: %w", err)
	}
	if len(sent) != 2 || sent[0].Header.Sequence == 0 {
		return errors.New("invalid nftables generation probe send receipt")
	}
	_, err = conn.Receive()
	if err != nil {
		var opErr *netlink.OpError
		if errors.As(err, &opErr) && opErr.Op == "receive" && opErr.Sequence == sent[0].Header.Sequence && errors.Is(opErr.Err, unix.ERESTART) {
			return nil
		}
		// Do not expose uncorrelated ERESTART as a support signal via errors.Is.
		return fmt.Errorf("nftables generation enforcement not established: %v", err)
	}
	return errors.New("nftables generation enforcement not established: empty batch accepted or unexpected reply")
}
