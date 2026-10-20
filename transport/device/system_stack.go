package device

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ Device = (*systemStackDevice)(nil)

type systemStackDevice struct {
	*systemDevice
	stackDevice *stackDevice
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
}

func newSystemStackDevice(options Options) (*systemStackDevice, error) {
	system, err := newSystemDevice(options)
	if err != nil {
		return nil, err
	}
	stackDevice, err := newStackDevice(options)
	if err != nil {
		system.Close()
		return nil, err
	}
	return &systemStackDevice{
		systemDevice: system,
		stackDevice:  stackDevice,
		closeDone:    make(chan struct{}),
	}, nil
}

func (d *systemStackDevice) SetPacketWriter(writer PacketWriter) {
	d.systemDevice.SetPacketWriter(writer)
	d.stackDevice.SetPacketWriter(writer)
}

func (d *systemStackDevice) Start() error {
	err := d.stackDevice.Start()
	if err != nil {
		return err
	}
	err = d.systemDevice.Start()
	return err
}

func (d *systemStackDevice) UpdateConfiguration(configuration Configuration) error {
	err := d.systemDevice.UpdateConfiguration(configuration)
	if err != nil {
		return err
	}
	return d.stackDevice.UpdateConfiguration(configuration)
}

func (d *systemStackDevice) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	return d.systemDevice.processInboundBuffers(packetBuffers, d.writeBuffers)
}

func (d *systemStackDevice) writeBuffers(packetBuffers []*buf.Buffer) error {
	addresses := d.systemDevice.configurationAddresses()
	runStart := 0
	runUsesSystemDevice := false
	var writeErr error
	for i, packetBuffer := range packetBuffers {
		destination := packetDestination(packetBuffer.Bytes())
		useSystemDevice := false
		for _, prefix := range addresses {
			if prefix.Contains(destination) {
				useSystemDevice = true
				break
			}
		}
		if i > runStart && useSystemDevice != runUsesSystemDevice {
			var err error
			if runUsesSystemDevice {
				err = d.systemDevice.writeBuffers(packetBuffers[runStart:i])
			} else {
				err = d.stackDevice.writeBuffers(packetBuffers[runStart:i])
			}
			writeErr = E.Errors(writeErr, err)
			runStart = i
		}
		if i == runStart {
			runUsesSystemDevice = useSystemDevice
		}
	}
	if runStart == len(packetBuffers) {
		return writeErr
	}
	if runUsesSystemDevice {
		return E.Errors(writeErr, d.systemDevice.writeBuffers(packetBuffers[runStart:]))
	}
	return E.Errors(writeErr, d.stackDevice.writeBuffers(packetBuffers[runStart:]))
}

func packetDestination(packet []byte) netip.Addr {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return netip.Addr{}
		}
		return header.IPv4(packet).DestinationAddr()
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return netip.Addr{}
		}
		return header.IPv6(packet).DestinationAddr()
	default:
		return netip.Addr{}
	}
}

func (d *systemStackDevice) NewOutboundQueue(handler func(packetBuffers []*buf.Buffer)) *tun.OutboundQueue {
	return d.stackDevice.NewOutboundQueue(handler)
}

func (d *systemStackDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closeErr = E.New("device shutdown did not complete")
		defer close(d.closeDone)
		d.closeErr = E.Errors(d.stackDevice.Close(), d.systemDevice.Close())
	})
	return d.closeErr
}

// The actual stack is a named child. UpstreamPort exposes system port capabilities.
func (d *systemStackDevice) WaitDetached(ctx context.Context) error {
	return waitStackDetached(ctx, d.closeDone, &d.closeErr, d.stackDevice)
}
