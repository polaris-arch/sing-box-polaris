package tfo

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func tcpTestSocketState(c *net.TCPConn) string {
	raw, err := c.SyscallConn()
	if err != nil {
		return fmt.Sprintf("SyscallConn=%v", err)
	}
	var state string
	err = raw.Control(func(fd uintptr) {
		proto, protoErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
		info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if infoErr != nil {
			state = fmt.Sprintf("SO_PROTOCOL=%d/%v TCP_INFO=%v", proto, protoErr, infoErr)
			return
		}
		state = fmt.Sprintf("SO_PROTOCOL=%d/%v TCP_INFO.State=%d Unacked=%d", proto, protoErr, info.State, info.Unacked)
	})
	if err != nil {
		return fmt.Sprintf("socket control=%v", err)
	}
	return state
}
