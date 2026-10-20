//go:build with_tailscale

package tailscale

import (
	"context"
 "errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
 runtimeTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/types/key"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/mem"
)

var (
	_ adapter.Outbound                   = (*TailcatOutbound)(nil)
	_ adapter.IdleConnectionKeeper       = (*TailcatOutbound)(nil)
	_ adapter.InterfaceUpdateListener    = (*TailcatOutbound)(nil)
	_ dialer.PacketDialerWithDestination = (*TailcatOutbound)(nil)
)

func RegisterTailcatOutbound(registry *outbound.Registry) {
	outbound.Register[option.TailcatOutboundOptions](registry, C.TypeTailcat, NewTailcatOutbound)
}

type TailcatOutbound struct {
	outbound.Adapter
	ctx             context.Context
	logger          logger.ContextLogger
	dnsRouter       adapter.DNSRouter
	dialer          N.Dialer
	queryOptions    adapter.DNSQueryOptions
	privateKey      key.NodePrivate
	serverPublicKey key.NodePublic
	serverDiscoKey  key.DiscoPublic
	presharedKey    device.NoisePresharedKey
	derp            *tailcatDERP
	access          sync.Mutex
	nodeContext     context.Context
	node            *tailcatNode
 nodeCancel context.CancelFunc
 session *runtimeTailcatSession
 operation *runtimeTailcatOperation
 runtimeSource adapter.RuntimeResourceSource
 runtimeStopped bool
 runtimeErr error
	active          int
	idle            bool
}

func NewTailcatOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailcatOutboundOptions) (adapter.Outbound, error) {
	var privateKey [32]byte
	if options.PrivateKey != "" {
		var err error
		privateKey, err = DecodeTailcatKey(options.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "parse private_key")
		}
	} else {
		privateKey = NewTailcatPrivateKey()
	}
	serverPublicKey, err := DecodeTailcatKey(options.ServerPublicKey)
	if err != nil {
		return nil, E.Cause(err, "parse server_public_key")
	}
	serverDiscoKey, err := DecodeTailcatKey(options.ServerDiscoKey)
	if err != nil {
		return nil, E.Cause(err, "parse server_disco_key")
	}
	var presharedKey device.NoisePresharedKey
	if options.PreSharedKey != "" {
		presharedKey, err = DecodeTailcatKey(options.PreSharedKey)
		if err != nil {
			return nil, E.Cause(err, "parse pre_shared_key")
		}
	}
	derp, err := newTailcatDERP(options.TailcatDERPOptions, "client")
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	result:= &TailcatOutbound{
		Adapter:         outbound.NewAdapterWithDialerOptions(C.TypeTailcat, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:             ctx,
		logger:          logger,
		dnsRouter:       service.FromContext[adapter.DNSRouter](ctx),
		dialer:          outboundDialer,
		queryOptions:    outboundDialer.(dialer.ResolveDialer).QueryOptions(),
		privateKey:      tailcatNodePrivate(privateKey),
		serverPublicKey: key.NodePublicFromRaw32(mem.B(serverPublicKey[:])),
		serverDiscoKey:  key.DiscoPublicFromRaw32(mem.B(serverDiscoKey[:])),
		presharedKey:    presharedKey,
		derp:            derp,
	}
 result.runtimeSource,_=adapter.RuntimeResourceSourceFromContext(ctx)
 return result,nil
}

type runtimeTailcatOperation struct{done chan struct{}}

func (o *TailcatOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
 switch stage {
 case adapter.StartStateInitialize:
  o.access.Lock();o.nodeContext,o.nodeCancel=context.WithCancel(scope.Context());o.access.Unlock()
  scope.Add(o.RuntimeCloseAndWait)
 case adapter.StartStatePostStart:
  return o.derp.start(o.ctx,o.logger)
 }
 return nil
}

// One sentinel serializes lazy construction and retirement. Native work and
// every actual join execute outside access; a completion may release a public
// carrier that itself needs access. Publication rechecks this exact sentinel.
func(o *TailcatOutbound)acquire(ctx context.Context)(*tailcatNode,func(),error){
 for {
  o.access.Lock()
  if o.runtimeStopped||o.nodeContext==nil||o.nodeContext.Err()!=nil||o.runtimeErr!=nil{err:=errors.Join(net.ErrClosed,o.runtimeErr);o.access.Unlock();return nil,nil,err}
  if op:=o.operation;op!=nil{o.access.Unlock();select{case <-op.done:continue;case <-ctx.Done():return nil,nil,ctx.Err()}}
  if node:=o.node;node!=nil{o.active++;o.access.Unlock();node.requestMeow();return node,sync.OnceFunc(o.releaseNode),nil}
  op:=&runtimeTailcatOperation{done:make(chan struct{})};o.operation=op;o.access.Unlock()
  node,session,err:=o.buildNode(ctx)
  o.access.Lock()
  publish:=err==nil&&!o.runtimeStopped&&o.nodeContext.Err()==nil&&o.operation==op
  if publish{o.node=node;o.session=session;o.active++}
  o.access.Unlock()
  if !publish&&node!=nil{err=errors.Join(err,closeTailcatNative(node,session));if err==nil{err=net.ErrClosed}}
  o.access.Lock()
  if runtimeTLS.IsRuntimeCleanupIncomplete(err){o.runtimeErr=errors.Join(o.runtimeErr,err)}
  o.operation=nil;close(op.done);o.access.Unlock()
  if !publish{return nil,nil,err}
  return node,sync.OnceFunc(o.releaseNode),nil
 }
}

func(o *TailcatOutbound)buildNode(ctx context.Context)(node *tailcatNode,session *runtimeTailcatSession,resultErr error){
 var constructed *tailcatNode
 defer func(){if recover()!=nil{resultErr=runtimeTLS.NewRuntimeCleanupError(errors.New("Tailcat lazy construction panicked"));resultErr=errors.Join(resultErr,closeTailcatNative(constructed,session));node=nil}}()
 owned,cancel:=context.WithCancel(ctx);finished:=make(chan struct{})
 stop:=context.AfterFunc(o.nodeContext,func(){defer close(finished);cancel()})
 defer func(){cancel();if !stop(){<-finished}}()
 region,err:=o.derp.resolve(owned);if err!=nil{return nil,nil,err}
 binding,err:=newSystemBinding(o.ctx,o.logger);if err!=nil{return nil,nil,err}
 session,err=o.newRuntimeSession();if err!=nil{return nil,nil,err}
 options:=tailcatNodeOptions{
  Context:o.nodeContext,Logger:o.logger,PrivateKey:o.privateKey,PresharedKey:o.presharedKey,Region:region,Hooks:binding.hooks(o.dialer),
  LookupHook:func(ctx context.Context,host string)([]netip.Addr,error){return o.dnsRouter.Lookup(ctx,host,o.queryOptions)},
  MemoryPressure:oomkiller.MemoryPressure(o.ctx),ServerPublicKey:o.serverPublicKey,ServerDiscoKey:o.serverDiscoKey,
 }
 if session!=nil{options=session.wrapOptions(options)}
 previous:=options.OnConstruct;options.OnConstruct=func(n *tailcatNode){constructed=n;if previous!=nil{previous(n)}}
 node,err=newTailcatNode(options)
 if err==nil{err=node.start()}
 if err==nil{err=node.meow(owned)}
 if err!=nil{return nil,session,errors.Join(err,closeTailcatNative(constructed,session))}
 o.logger.Info("connected to server")
 return node,session,nil
}
func closeTailcatNative(node *tailcatNode,session *runtimeTailcatSession)(resultErr error){
 resultErr=runtimeTLS.NewRuntimeCleanupError(errors.New("Tailcat original close did not return"))
 defer func(){if recover()!=nil{resultErr=runtimeTLS.NewRuntimeCleanupError(errors.New("Tailcat original close panicked"))}}()
 if session!=nil{return session.close()}
 if node!=nil{node.close()}
 return nil
}
func(o *TailcatOutbound)releaseNode(){
 o.access.Lock();o.active--;closeIdle:=o.active==0&&o.idle;o.access.Unlock()
 if closeIdle{_ = o.closeIdleNode()}
}
func(o *TailcatOutbound)closeIdleNode()error{
 o.access.Lock()
 if o.operation!=nil||o.active!=0||o.node==nil{o.access.Unlock();return nil}
 node,session:=o.node,o.session;o.node=nil;o.session=nil
 op:=&runtimeTailcatOperation{done:make(chan struct{})};o.operation=op;o.access.Unlock()
 o.logger.Info("disconnected from server")
 err:=closeTailcatNative(node,session)
 o.access.Lock();if err!=nil{o.runtimeErr=errors.Join(o.runtimeErr,err)};o.operation=nil;close(op.done);o.access.Unlock()
 return err
}
func(o *TailcatOutbound)RuntimeCloseAndWait()error{
 for {
  o.access.Lock();o.runtimeStopped=true;if o.nodeCancel!=nil{o.nodeCancel()}
  if op:=o.operation;op!=nil{o.access.Unlock();<-op.done;continue}
  node,session:=o.node,o.session;o.node=nil;o.session=nil
  op:=&runtimeTailcatOperation{done:make(chan struct{})};o.operation=op;o.access.Unlock()
  err:=closeTailcatNative(node,session)
  o.access.Lock();o.runtimeErr=errors.Join(o.runtimeErr,err);result:=o.runtimeErr;o.operation=nil;close(op.done);o.access.Unlock()
  return result
 }
}
func(o *TailcatOutbound)SetKeepIdleConnections(keep bool){
 o.access.Lock();o.idle=!keep;closeIdle:=o.idle&&o.active==0;o.access.Unlock()
 if closeIdle{_ = o.closeIdleNode()}
}
func(o *TailcatOutbound)CloseIdleConnections(){_ = o.closeIdleNode()}
func(o *TailcatOutbound)InterfaceUpdated(ctx context.Context){
 if o.runtimeSource!=nil{_,release,err:=adapter.AcquireRuntimeOperation(ctx,o.runtimeSource);if err!=nil{return};defer release()}
 o.access.Lock();node:=o.node
 if node==nil||o.runtimeStopped||o.operation!=nil{o.access.Unlock();return}
 o.active++;o.access.Unlock()
 defer o.releaseNode();node.interfaceUpdated()
}

func (o *TailcatOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
 return outbound.DialRuntimeConn(ctx,o.runtimeSource,func(ctx context.Context)(net.Conn,error){return o.dialContextOwned(ctx,network,destination)})
}
func (o *TailcatOutbound) dialContextOwned(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if destination.IsDomain() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, (*tailcatDialer)(o), network, destination, destinationAddresses)
	}
	return (*tailcatDialer)(o).DialContext(ctx, network, destination)
}

func (o *TailcatOutbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
 var destinationAddress netip.Addr
 conn,err:=outbound.ListenRuntimePacket(ctx,o.runtimeSource,func(ctx context.Context)(net.PacketConn,error){conn,address,err:=o.listenPacketWithDestinationOwned(ctx,destination);destinationAddress=address;return conn,err})
 return conn,destinationAddress,err
}
func (o *TailcatOutbound) listenPacketWithDestinationOwned(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, (*tailcatDialer)(o), destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(o.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := (*tailcatDialer)(o).ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(o.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(o.logger, packetConn), netip.Addr{}, nil
}

func (o *TailcatOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := o.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

// tailcatDialer is the IP-only dialer behind the outbound: it brings
// the tunnel up, maps IPv4 destinations into the NAT64 prefix that the
// server unmaps, and tracks live connections for the idle teardown.
type tailcatDialer TailcatOutbound

func (d *tailcatDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	node, release, err := (*TailcatOutbound)(d).acquire(ctx)
	if err != nil {
		return nil, err
	}
	mapped := netip.AddrPortFrom(tailcatMapNAT64(destination.Addr), destination.Port)
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		conn, err := node.stack().DialTCP(ctx, node.address, mapped)
		if err != nil {
			release()
			return nil, err
		}
		return (*TailcatOutbound)(d).ownRuntimeConn(&tailcatConn{GoConn: conn, release: func(){}},release), nil
	case N.NetworkUDP:
		conn, err := node.stack().DialUDP(netip.AddrPortFrom(node.address, 0), mapped)
		if err != nil {
			release()
			return nil, err
		}
		return (*TailcatOutbound)(d).ownRuntimeConn(&tailcatPacketConn{conn: conn, remote: destination.UDPAddr(), release: func(){}},release), nil
	default:
		release()
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (d *tailcatDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	node, release, err := (*TailcatOutbound)(d).acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := node.stack().ListenUDP(netip.AddrPortFrom(node.address, 0))
	if err != nil {
		release()
		return nil, err
	}
	return (*TailcatOutbound)(d).ownRuntimePacket(&tailcatPacketConn{conn: conn, release: func(){}},release), nil
}

type tailcatConn struct {
	*tun.GoConn
	release func()
}

func (c *tailcatConn) Close() error {
	err := c.GoConn.Close()
	c.release()
	return err
}

func (c *tailcatConn) Upstream() any {
	return c.GoConn
}

// GoUDPConn also offers buffer-based ReadPacket/WritePacket, which
// bufio prefers over ReadFrom/WriteTo, so every address-carrying
// method is wrapped rather than the conn being embedded.
type tailcatPacketConn struct {
	conn    *tun.GoUDPConn
	remote  net.Addr
	release func()
}

func (c *tailcatPacketConn) Read(buffer []byte) (int, error) {
	return c.conn.Read(buffer)
}

func (c *tailcatPacketConn) Write(buffer []byte) (int, error) {
	return c.conn.Write(buffer)
}

func (c *tailcatPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, source, err := c.conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(netip.AddrPortFrom(tailcatUnmapNAT64(source.Addr()), source.Port())), nil
}

func (c *tailcatPacketConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if !destination.Addr.IsValid() {
		return 0, E.New("invalid destination: ", addr)
	}
	return c.conn.WriteToUDPAddrPort(buffer, netip.AddrPortFrom(tailcatMapNAT64(destination.Addr), destination.Port))
}

func (c *tailcatPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	source, err := c.conn.ReadPacket(buffer)
	if err != nil {
		return M.Socksaddr{}, err
	}
	source.Addr = tailcatUnmapNAT64(source.Addr)
	return source, nil
}

func (c *tailcatPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.Addr.IsValid() {
		buffer.Release()
		return E.New("invalid destination: ", destination)
	}
	destination.Addr = tailcatMapNAT64(destination.Addr)
	return c.conn.WritePacket(buffer, destination)
}

func (c *tailcatPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *tailcatPacketConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.conn.RemoteAddr()
}

func (c *tailcatPacketConn) SetDeadline(deadline time.Time) error {
	return c.conn.SetDeadline(deadline)
}

func (c *tailcatPacketConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *tailcatPacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

func (c *tailcatPacketConn) Close() error {
	err := c.conn.Close()
	c.release()
	return err
}
