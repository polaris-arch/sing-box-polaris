//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// nltest does not expose socket deadlines; this adapter records that the real
// Conn deadline API is called before sending and injects deadline errors.
type generationProbeTestConn struct {
	*netlink.Conn
	deadline    time.Time
	deadlineErr error
}

func (c *generationProbeTestConn) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return c.deadlineErr
}

func TestNFTGenerationProbeEmptyBatch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		errno         int
		wrongSequence bool
		endSequence   bool
		receiveError  error
		supported     bool
	}{
		{name: "matching-restart", errno: int(unix.ERESTART), supported: true},
		{name: "accepted"},
		{name: "wrong-sequence", errno: int(unix.ERESTART), wrongSequence: true},
		{name: "end-sequence", errno: int(unix.ERESTART), endSequence: true},
		{name: "permission", errno: int(unix.EPERM)},
		{name: "unsupported", errno: int(unix.EOPNOTSUPP)},
		{name: "timeout", receiveError: os.ErrDeadlineExceeded},
		{name: "uncorrelated-restart", receiveError: unix.ERESTART},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sends := 0
			c := &generationProbeTestConn{}
			c.Conn = nltest.Dial(func(messages []netlink.Message) ([]netlink.Message, error) {
				sends++
				if c.deadline.IsZero() || time.Until(c.deadline) > nftGenerationProbeTimeout || time.Until(c.deadline) <= 0 {
					t.Error("missing/unbounded deadline")
				}
				if len(messages) != 2 {
					t.Fatalf("probe sent %d messages", len(messages))
				}
				begin, end := messages[0], messages[1]
				if begin.Header.Type != unix.NFNL_MSG_BATCH_BEGIN || begin.Header.Flags != netlink.Request|netlink.Acknowledge || end.Header.Type != unix.NFNL_MSG_BATCH_END || end.Header.Flags != netlink.Request {
					t.Fatal("not an empty ACK begin/end batch")
				}
				header := []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}
				if len(begin.Data) < 4 || !bytes.Equal(begin.Data[:4], header) || !bytes.Equal(end.Data, header) {
					t.Fatal("wrong nfgenmsg")
				}
				attrs, err := netlink.UnmarshalAttributes(begin.Data[4:])
				if err != nil || len(attrs) != 1 || attrs[0].Type != unix.NFNL_BATCH_GENID || len(attrs[0].Data) != 4 || binary.BigEndian.Uint32(attrs[0].Data) != 29 {
					t.Fatalf("wrong generation attribute: %v", err)
				}
				if tc.receiveError != nil {
					return nil, tc.receiveError
				}
				replies, err := nltest.Error(tc.errno, messages[:1])
				if tc.wrongSequence {
					replies[0].Header.Sequence += 100
				}
				if tc.endSequence {
					replies[0].Header.Sequence = end.Header.Sequence
				}
				return replies, err
			})
			defer c.Close()
			err := probeNFTablesGenerationWithConn(c, 29)
			if (err == nil) != tc.supported || sends != 1 {
				t.Fatalf("err=%v supported=%v sends=%d", err, tc.supported, sends)
			}
			if !tc.supported && errors.Is(err, unix.ERESTART) {
				t.Fatal("inconclusive restart exposed as evidence")
			}
		})
	}
}

func TestNFTGenerationProbeRejectsZeroAndDeadlineFailure(t *testing.T) {
	for _, expected := range []uint32{0, 1} {
		c := &generationProbeTestConn{deadlineErr: os.ErrDeadlineExceeded}
		c.Conn = nltest.Dial(func([]netlink.Message) ([]netlink.Message, error) {
			t.Error("sent before preconditions")
			return nil, nil
		})
		if err := probeNFTablesGenerationWithConn(c, expected); err == nil {
			t.Fatal("accepted failed precondition")
		}
		if expected == 0 && !c.deadline.IsZero() {
			t.Error("zero generation touched socket")
		}
		c.Close()
	}
}
