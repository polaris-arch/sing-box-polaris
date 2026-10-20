package vless

import (
 "net"

 "github.com/sagernet/sing-box/common/tls"
 vmess "github.com/sagernet/sing-vmess"
 "github.com/sagernet/sing-vmess/vless"
 "github.com/sagernet/sing/common"
 E "github.com/sagernet/sing/common/exceptions"
 M "github.com/sagernet/sing/common/metadata"
)

// Vision inspects provider buffers during construction, but normal protocol I/O
// must continue through the guarded TLS conn. The returned stream is owned by
// the outbound carrier or mux physical-session fence; direct mode receives the
// TLS provider's already-guarded NetConn, never an unguarded socket.
func (h *vlessDialer) prepareRuntimeVision(original, protocol net.Conn) (result net.Conn, err error) {
 err = tls.WithRuntimeTLSInspection(original,func(native net.Conn)error{
  result,err = vless.NewVisionConn(protocol,native,h.visionUUID,h.logger)
  return err
 })
 if err != nil { return nil,E.Cause(err,"initialize vision") }
 return result,nil
}
func (h *vlessDialer) dialEarlyRuntimeConn(conn net.Conn,destination M.Socksaddr)(net.Conn,error){
 if h.flow != vless.FlowVision { return h.client.DialEarlyConn(conn,destination) }
 protocol:=vless.NewConn(conn,h.visionUUID,vmess.CommandTCP,destination,h.flow)
 return h.prepareRuntimeVision(conn,protocol)
}
func (h *vlessDialer) dialEarlyRuntimeXUDP(conn net.Conn,destination M.Socksaddr)(vmess.PacketConn,error){
 if h.flow != vless.FlowVision { return h.client.DialEarlyXUDPPacketConn(conn,destination) }
 protocol:=vless.NewConn(conn,h.visionUUID,vmess.CommandMux,destination,h.flow)
 vision,err:=h.prepareRuntimeVision(conn,protocol)
 if err != nil { return nil,err }
 // Preserve the pinned client's early-XUDP request write and returned-error
 // semantics; the inspection capability is no longer held during network I/O.
 return vmess.NewXUDPConn(vision,destination),common.Error(protocol.Write(nil))
}
