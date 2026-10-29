package outbound

import "net"

// Legacy callers have no outer resource carrier to consume a close request.
// Keep their synchronous Close contract using only the exact private barrier
// captured here. This view adds neither a lease nor an unwrap/public waiter.
func runtimeLegacyConn(conn net.Conn) net.Conn {
	wait, known := RuntimeConnectionCloseWaiter(conn)
	if !known {
		return conn
	}
	joined := &runtimeLegacyJoinedConn{Conn: conn, wait: wait, state: runtimeCarrierState(conn)}
	if observed, ok := conn.(*runtimeTLSStateConn); ok {
		return PreserveRuntimeTLSState(joined, observed.tlsState)
	}
	if packet, ok := conn.(net.PacketConn); ok {
		return &runtimeLegacyJoinedConnPacket{runtimeLegacyJoinedConn: joined, packet: packet}
	}
	return joined
}

type runtimeLegacyJoinedConn struct {
	net.Conn
	wait  func() error
	state *runtimeCarrier
}

func (c *runtimeLegacyJoinedConn) Close() error { return c.wait() }

type runtimeLegacyJoinedConnPacket struct {
	*runtimeLegacyJoinedConn
	packet net.PacketConn
}

func (c *runtimeLegacyJoinedConnPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(p)
}

func (c *runtimeLegacyJoinedConnPacket) WriteTo(p []byte, destination net.Addr) (int, error) {
	return c.packet.WriteTo(p, destination)
}

type runtimeLegacyPacketConn struct {
	net.PacketConn
	wait  func() error
	state *runtimeCarrier
}

func (c *runtimeLegacyPacketConn) Close() error { return c.wait() }
