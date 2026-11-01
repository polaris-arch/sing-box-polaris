// Polaris changes: synchronous discovery and acknowledged mapping ownership/cleanup.
// Original source and complete license: UPSTREAM.json and LICENSE.

package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
)

var (
	_ NAT = (*natpmpNAT)(nil)
)

func discoverNATPMP(ctx context.Context, res chan<- NAT) {
	if ctx.Err() != nil {
		return
	}
	ip, err := getDefaultGateway()
	if err != nil || ctx.Err() != nil {
		return
	}
	// The underlying API has no context. Keep it in this owned producer so
	// cancellation cannot advertise discovery completion while it is still live.
	client, err := discoverNATPMPWithAddr(ip)
	if err != nil || ctx.Err() != nil {
		return
	}
	select {
	case res <- &natpmpNAT{c: client, gateway: ip, ports: make(map[int]int)}:
	case <-ctx.Done():
	}
}

func discoverNATPMPWithAddr(ip net.IP) (*natpmp.Client, error) {
	client := natpmp.NewClient(ip)
	_, err := client.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	return client, nil
}

type natpmpClient interface {
	GetExternalAddress() (*natpmp.GetExternalAddressResult, error)
	AddPortMapping(string, int, int, int) (*natpmp.AddPortMappingResult, error)
}

type natpmpNAT struct {
	c                natpmpClient
	gateway          net.IP
	ports            map[int]int
	deleteContextErr error
}

func (n *natpmpNAT) GetDeviceAddress() (addr net.IP, err error) {
	return n.gateway, nil
}

func (n *natpmpNAT) GetInternalAddress() (addr net.IP, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch x := addr.(type) {
			case *net.IPNet:
				if x.Contains(n.gateway) {
					return x.IP, nil
				}
			}
		}
	}

	return nil, ErrNoInternalAddress
}

func (n *natpmpNAT) GetExternalAddress() (addr net.IP, err error) {
	res, err := n.c.GetExternalAddress()
	if err != nil {
		return nil, err
	}

	d := res.ExternalIPAddress
	return net.IPv4(d[0], d[1], d[2], d[3]), nil
}

func (n *natpmpNAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, _ string, timeout time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	seconds := timeout / time.Second
	if (protocol != "udp" && protocol != "tcp") || internalPort <= 0 || internalPort > 65535 || seconds <= 0 || seconds > 0xffffffff {
		return 0, fmt.Errorf("invalid NAT-PMP mapping request")
	}
	if n.ports == nil {
		n.ports = make(map[int]int)
	}
	var lastErr error
	previous := n.ports[internalPort]
	attempts := 3
	if previous > 0 {
		attempts++
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, errors.Join(lastErr, err)
		}
		externalPort := previous
		if attempt != 0 || previous <= 0 {
			externalPort = randomPort()
		}
		// NAT-PMP deletion is keyed by this client's internal port/protocol.
		// Retain an attempted entry even if the reply is lost, so cleanup can
		// issue that exact delete rather than treating the unknown effect as absent.
		n.ports[internalPort] = externalPort
		result, err := n.c.AddPortMapping(protocol, internalPort, externalPort, int(seconds))
		if err == nil {
			if result == nil || result.InternalPort != uint16(internalPort) || result.MappedExternalPort == 0 || result.PortMappingLifetimeInSeconds == 0 {
				err = fmt.Errorf("NAT-PMP creation was not confirmed for internal port %d", internalPort)
			} else {
				n.ports[internalPort] = int(result.MappedExternalPort)
				return int(result.MappedExternalPort), ctx.Err()
			}
		}
		lastErr = err
		if ctx.Err() != nil {
			return 0, errors.Join(err, ctx.Err())
		}
	}
	return 0, lastErr
}

func (n *natpmpNAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	if n.ports[internalPort] == 0 {
		n.deleteContextErr = ctx.Err()
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if (protocol != "udp" && protocol != "tcp") || internalPort <= 0 || internalPort > 65535 {
		// Port zero is a protocol-wide delete-all request, not an owned entry.
		return fmt.Errorf("invalid owned NAT-PMP internal port: %d", internalPort)
	}
	// RFC 6886 section 3.4 requires a zero suggested external port/lifetime.
	// The native client checks protocol version, response opcode and result code.
	// It has no context API: this call must finish before cleanup can complete.
	result, err := n.c.AddPortMapping(protocol, internalPort, 0, 0)
	n.deleteContextErr = ctx.Err()
	if err != nil {
		return errors.Join(err, ctx.Err())
	}
	if result == nil || result.InternalPort != uint16(internalPort) || result.MappedExternalPort != 0 || result.PortMappingLifetimeInSeconds != 0 {
		return errors.Join(fmt.Errorf("NAT-PMP deletion was not confirmed for internal port %d", internalPort), ctx.Err())
	}
	delete(n.ports, internalPort)
	return nil
}

// A joined positive deletion ACK resolves the remote obligation even after a
// deadline. Keep the elapsed context separately from the cleanup outcome.
func (n *natpmpNAT) PortMappingDeleteContextError() error { return n.deleteContextErr }

func (n *natpmpNAT) Type() string {
	return "NAT-PMP"
}
