//go:build !linux

package tfo

import "net"

func tcpTestSocketState(*net.TCPConn) string { return "" }
