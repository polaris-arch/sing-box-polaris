package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

var _ Device = (*stackDevice)(nil)

type stackDevice struct {
	stack        deviceIPStack
	router       *peerRouter
	mtu          uint32
	events       chan wgTun.Event
	closed       chan struct{}
	closeOnce    sync.Once
	closeDone    chan struct{}
	closeErr     error
	inet4Address netip.Addr
	inet6Address netip.Addr
}

func newStackDevice(options DeviceOptions) (*stackDevice, error) {
	router := newPeerRouter(options)
	stack, err := newStack(options, router.memoryTun)
	if err != nil {
		router.close()
		return nil, err
	}
	inet4Address, inet6Address := deviceAddresses(options.Address)
	return &stackDevice{
		closeDone:    make(chan struct{}),
		stack:        stack,
		router:       router,
		mtu:          options.MTU,
		events:       make(chan wgTun.Event, 1),
		closed:       make(chan struct{}),
		inet4Address: inet4Address,
		inet6Address: inet6Address,
	}, nil
}

func (w *stackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var tcpConn *tun.GoConn
		tcpConn, err = w.stack.DialTCP(ctx, bind, destination.AddrPort())
		if err != nil {
			return nil, err
		}
		tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 15 * time.Second})
		return tcpConn, nil
	case N.NetworkUDP:
		var udpConn *tun.GoUDPConn
		udpConn, err = w.stack.DialUDP(netip.AddrPortFrom(bind, 0), destination.AddrPort())
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (w *stackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	udpConn, err := w.stack.ListenUDP(netip.AddrPortFrom(bind, 0))
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (w *stackDevice) bindAddress(destination M.Socksaddr) (netip.Addr, error) {
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return netip.Addr{}, E.New("missing IPv4 local address")
		}
		return w.inet4Address, nil
	}
	if !w.inet6Address.IsValid() {
		return netip.Addr{}, E.New("missing IPv6 local address")
	}
	return w.inet6Address, nil
}

func (w *stackDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *stackDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *stackDevice) UpstreamPort() any {
	return w.stack
}

func (w *stackDevice) SetDevice(device *device.Device, peers []*device.Peer) {
	w.router.setPeers(device.AllowedIPs(), peers)
}

func (w *stackDevice) Start() error {
	err := w.stack.Start()
	if err != nil {
		return err
	}
	w.events <- wgTun.EventUp
	return nil
}

func (w *stackDevice) File() *os.File {
	return nil
}

func (w *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-w.closed
	return 0, os.ErrClosed
}

func (w *stackDevice) Write(bufs [][]byte, offset int) (int, error) {
	packets := make([][]byte, 0, len(bufs))
	for _, packet := range bufs {
		packets = append(packets, packet[offset:])
	}
	return w.router.memoryTun.WritePackets(packets)
}

func (w *stackDevice) Flush() error {
	return nil
}

func (w *stackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *stackDevice) Name() (string, error) {
	return "sing-box", nil
}

func (w *stackDevice) Events() <-chan wgTun.Event {
	return w.events
}

func (w *stackDevice) Close() error {
	w.closeOnce.Do(func() {
		w.closeErr = E.New("device shutdown did not complete")
		defer close(w.closeDone)
		close(w.events)
		close(w.closed)
		w.closeErr = E.Errors(w.stack.Close(), w.router.close())
	})
	return w.closeErr
}

func (w *stackDevice) BatchSize() int {
	return 1
}

// Uses the actual embedded stack, never the UpstreamPort capability chain.
func (w *stackDevice) WaitDetached(ctx context.Context) error {
	return waitStackDetached(ctx, w.closeDone, &w.closeErr, w.stack)
}
