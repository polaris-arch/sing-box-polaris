package vless

import (
 "context"
 "encoding/binary"
 "io"
 "net"
 "os"
 "sync"

 "github.com/gofrs/uuid/v5"
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/common/tls"
 "github.com/sagernet/sing-vmess"
 "github.com/sagernet/sing-vmess/vless"
 "github.com/sagernet/sing/common/auth"
 "github.com/sagernet/sing/common/buf"
 E "github.com/sagernet/sing/common/exceptions"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

// The pinned vless.Service constructs Vision using a private concrete TLS
// pointer. This runtime-only boundary uses the same public request decoder and
// Vision constructor, while TLS inspection remains a scoped capability. Neither
// this response adapter nor the outer carrier publishes a raw Upstream handle.
func (h *Inbound) newRuntimeConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
 request, err := vless.ReadRequest(conn)
 if err != nil { return err }
 userIndex := -1
 for index, user := range h.users {
  id, parseErr := uuid.FromString(user.UUID)
  if parseErr != nil { id = uuid.NewV5(uuid.Nil, user.UUID) }
  if [16]byte(id) == request.UUID { userIndex = index }
 }
 if userIndex < 0 { return E.New("unknown UUID: ", uuid.FromBytesOrNil(request.UUID[:])) }
 flow := h.users[userIndex].Flow
 if request.Flow != flow { return E.New("flow mismatch: expected ", flow, ", but got ", request.Flow) }
 if request.Flow == vless.FlowVision && request.Command == vmess.CommandUDP { return E.New(vless.FlowVision, " flow does not support UDP") }
 ctx = auth.ContextWithUser(ctx, userIndex)
 handler := adapter.NewUpstreamContextHandler(h.newConnectionEx, h.newPacketConnectionEx)
 response := &runtimeVLESSResponseConn{Conn:conn}
 if request.Command == vmess.CommandUDP {
  handler.NewPacketConnectionEx(ctx, &runtimeVLESSPacketConn{runtimeVLESSResponseConn:response, destination:request.Destination}, source, request.Destination, onClose)
  return nil
 }
 var protocol net.Conn = response
 switch flow {
 case "":
 case vless.FlowVision:
  err = tls.WithRuntimeTLSInspection(conn, func(native net.Conn) error {
   vision, visionErr := vless.NewVisionConn(response, native, request.UUID, h.logger)
   if visionErr == nil { protocol = vision }
   return visionErr
  })
  if err != nil { return E.Cause(err, "initialize vision") }
 default:
  return E.New("unknown flow: ", flow)
 }
 switch request.Command {
 case vmess.CommandTCP:
  handler.NewConnectionEx(ctx, protocol, source, request.Destination, onClose)
  return nil
 case vmess.CommandMux:
  return vmess.HandleMuxConnection(ctx, protocol, source, handler)
 default:
  return E.New("unknown command: ", request.Command)
 }
}

type runtimeVLESSResponseConn struct {
 net.Conn
 writeAccess sync.Mutex
 responseWritten bool
}
func (c *runtimeVLESSResponseConn) writeHeader() error {
 if c.responseWritten { return nil }
 header := []byte{vless.Version, 0}
 for len(header) > 0 {
  n, err := c.Conn.Write(header)
  if err != nil { return err }
  if n == 0 { return io.ErrShortWrite }
  header = header[n:]
 }
 c.responseWritten = true
 return nil
}
func (c *runtimeVLESSResponseConn) Write(p []byte) (int, error) {
 c.writeAccess.Lock(); defer c.writeAccess.Unlock()
 if err := c.writeHeader(); err != nil { return 0, err }
 return c.Conn.Write(p)
}

func (*runtimeVLESSResponseConn) NeedAdditionalReadDeadline() bool { return true }

type runtimeVLESSPacketConn struct {
 *runtimeVLESSResponseConn
 destination M.Socksaddr
}
func (c *runtimeVLESSPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
 var length uint16
 if err := binary.Read(c.Conn, binary.BigEndian, &length); err != nil { return M.Socksaddr{}, err }
 _, err := buffer.ReadFullFrom(c.Conn, int(length))
 return c.destination, err
}
func (c *runtimeVLESSPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
 defer buffer.Release()
 if buffer.Len() > 65535 { return os.ErrInvalid }
 c.writeAccess.Lock(); defer c.writeAccess.Unlock()
 if err := c.writeHeader(); err != nil { return err }
 var header [2]byte
 binary.BigEndian.PutUint16(header[:], uint16(buffer.Len()))
 for _, part := range [][]byte{header[:], buffer.Bytes()} {
  for len(part) > 0 {
   n, err := c.Conn.Write(part)
   if err != nil { return err }
   if n == 0 { return io.ErrShortWrite }
   part = part[n:]
  }
 }
 return nil
}
