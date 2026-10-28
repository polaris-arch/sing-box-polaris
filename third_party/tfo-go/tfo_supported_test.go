//go:build darwin || freebsd || linux || (windows && tfogo_checklinkname0)

package tfo

import (
	"net"
	"testing"
)

func testClientWriteReadServerReadWriteTCPAddr(listenTCPAddr, dialLocalTCPAddr *net.TCPAddr, t *testing.T) {
	t.Logf("c->s payload: %v", helloworld)
	t.Logf("s->c payload: %v", worldhello)

	lntcp, err := ListenTCP("tcp", listenTCPAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer lntcp.Close()
	t.Log("Started listener on", lntcp.Addr())

	session := newTCPTestSession(t, lntcp)
	session.start(func(conn *net.TCPConn) {
		t.Log("Accepted", conn.RemoteAddr())

		readUntilEOF(conn, helloworld, t)
		write(conn, world, t)
		write(conn, hello, t)
		if !closeTCPTestWrite(t, conn) {
			return
		}
	})

	port := lntcp.Addr().(*net.TCPAddr).Port
	ip := net.IPv6loopback
	if listenTCPAddr != nil && listenTCPAddr.IP != nil {
		ip = listenTCPAddr.IP
	}

	tc, err := DialTCP("tcp", dialLocalTCPAddr, &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, hello)
	if err != nil {
		t.Fatal(err)
	}
	if !session.track(tc, "client DialTCP") {
		t.Fatal("client connected after fixture closed")
	}
	defer tc.Close()

	write(tc, world, t)
	if !closeTCPTestWrite(t, tc) {
		return
	}
	readUntilEOF(tc, worldhello, t)
	session.wait()
}

func TestClientWriteReadServerReadWriteTCPAddr(t *testing.T) {
	for _, c := range []struct {
		name             string
		listenTCPAddr    *net.TCPAddr
		dialLocalTCPAddr *net.TCPAddr
	}{
		{
			name:             "Unspecified",
			listenTCPAddr:    nil,
			dialLocalTCPAddr: nil,
		},
		{
			name: "IPv4Loopback",
			listenTCPAddr: &net.TCPAddr{
				IP: net.IPv4(127, 0, 0, 1),
			},
			dialLocalTCPAddr: nil,
		},
		{
			name: "IPv6Loopback",
			listenTCPAddr: &net.TCPAddr{
				IP: net.IPv6loopback,
			},
			dialLocalTCPAddr: nil,
		},
		{
			name:          "DialBind",
			listenTCPAddr: nil,
			dialLocalTCPAddr: &net.TCPAddr{
				IP: net.IPv6loopback,
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testClientWriteReadServerReadWriteTCPAddr(c.listenTCPAddr, c.dialLocalTCPAddr, t)
		})
	}
}
