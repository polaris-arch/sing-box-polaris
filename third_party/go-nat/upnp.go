// Polaris changes: captured discovery and identity-checked mapping cleanup.
// Original source and complete license: UPSTREAM.json and LICENSE.

package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"

	"github.com/koron/go-ssdp"
)

var _ NAT = (*upnp_NAT)(nil)

func discoverUPNP_IG1(ctx context.Context, res chan<- NAT) {
	if ctx.Err() != nil {
		return
	}

	// find devices
	devs, err := discoverUPNPDevices(ctx, internetgateway1.URN_WANConnectionDevice_1)
	if err != nil {
		return
	}

	for _, dev := range devs {
		if dev.Root == nil {
			continue
		}

		dev.Root.Device.VisitServices(func(srv *goupnp.Service) {
			if ctx.Err() != nil {
				return
			}
			switch srv.ServiceType {
			case internetgateway1.URN_WANIPConnection_1:
				client := &internetgateway1.WANIPConnection1{ServiceClient: goupnp.ServiceClient{
					SOAPClient: upnpSOAPClient(ctx, srv),
					RootDevice: dev.Root,
					Service:    srv,
				}}
				_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
				if err == nil && isNat && ctx.Err() == nil {
					gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG1-IP1)", dev.Root)
					if gatewayErr != nil {
						return
					}
					select {
					case res <- gateway:
					case <-ctx.Done():
					}
				}

			case internetgateway1.URN_WANPPPConnection_1:
				client := &internetgateway1.WANPPPConnection1{ServiceClient: goupnp.ServiceClient{
					SOAPClient: upnpSOAPClient(ctx, srv),
					RootDevice: dev.Root,
					Service:    srv,
				}}
				_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
				if err == nil && isNat && ctx.Err() == nil {
					gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG1-PPP1)", dev.Root)
					if gatewayErr != nil {
						return
					}
					select {
					case res <- gateway:
					case <-ctx.Done():
					}
				}

			}
		})
	}

}

func discoverUPNP_IG2(ctx context.Context, res chan<- NAT) {
	if ctx.Err() != nil {
		return
	}

	// find devices
	devs, err := discoverUPNPDevices(ctx, internetgateway2.URN_WANConnectionDevice_2)
	if err != nil {
		return
	}

	for _, dev := range devs {
		if dev.Root == nil {
			continue
		}

		dev.Root.Device.VisitServices(func(srv *goupnp.Service) {
			if ctx.Err() != nil {
				return
			}
			switch srv.ServiceType {
			case internetgateway2.URN_WANIPConnection_1:
				client := &internetgateway2.WANIPConnection1{ServiceClient: goupnp.ServiceClient{
					SOAPClient: upnpSOAPClient(ctx, srv),
					RootDevice: dev.Root,
					Service:    srv,
				}}
				_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
				if err == nil && isNat && ctx.Err() == nil {
					gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG2-IP1)", dev.Root)
					if gatewayErr != nil {
						return
					}
					select {
					case res <- gateway:
					case <-ctx.Done():
					}
				}

			case internetgateway2.URN_WANIPConnection_2:
				client := &internetgateway2.WANIPConnection2{ServiceClient: goupnp.ServiceClient{
					SOAPClient: upnpSOAPClient(ctx, srv),
					RootDevice: dev.Root,
					Service:    srv,
				}}
				_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
				if err == nil && isNat && ctx.Err() == nil {
					gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG2-IP2)", dev.Root)
					if gatewayErr != nil {
						return
					}
					select {
					case res <- gateway:
					case <-ctx.Done():
					}
				}

			case internetgateway2.URN_WANPPPConnection_1:
				client := &internetgateway2.WANPPPConnection1{ServiceClient: goupnp.ServiceClient{
					SOAPClient: upnpSOAPClient(ctx, srv),
					RootDevice: dev.Root,
					Service:    srv,
				}}
				_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
				if err == nil && isNat && ctx.Err() == nil {
					gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG2-PPP1)", dev.Root)
					if gatewayErr != nil {
						return
					}
					select {
					case res <- gateway:
					case <-ctx.Done():
					}
				}

			}
		})
	}

}

func discoverUPNP_GenIGDev(ctx context.Context, res chan<- NAT) {
	if ctx.Err() != nil {
		return
	}

	// Search has no context API. Its synchronous call remains inside this joined producer.
	DeviceList, err := ssdp.Search(ssdp.All, 5, "")
	if err != nil || ctx.Err() != nil {
		return
	}
	var gw ssdp.Service
	for _, Service := range DeviceList {
		if strings.Contains(Service.Type, "InternetGatewayDevice") {
			gw = Service
			break
		}
	}

	DeviceURL, err := url.Parse(gw.Location)
	if err != nil {
		return
	}
	RootDevice, err := upnpDeviceByURL(ctx, DeviceURL)
	if err != nil {
		return
	}

	RootDevice.Device.VisitServices(func(srv *goupnp.Service) {
		if ctx.Err() != nil {
			return
		}
		switch srv.ServiceType {
		case internetgateway1.URN_WANIPConnection_1:
			client := &internetgateway1.WANIPConnection1{ServiceClient: goupnp.ServiceClient{
				SOAPClient: upnpSOAPClient(ctx, srv),
				RootDevice: RootDevice,
				Service:    srv,
			}}
			_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
			if err == nil && isNat && ctx.Err() == nil {
				gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG1-IP1)", RootDevice)
				if gatewayErr != nil {
					return
				}
				select {
				case res <- gateway:
				case <-ctx.Done():
				}
			}

		case internetgateway1.URN_WANPPPConnection_1:
			client := &internetgateway1.WANPPPConnection1{ServiceClient: goupnp.ServiceClient{
				SOAPClient: upnpSOAPClient(ctx, srv),
				RootDevice: RootDevice,
				Service:    srv,
			}}
			_, isNat, err := client.GetNATRSIPStatusCtx(ctx)
			if err == nil && isNat && ctx.Err() == nil {
				gateway, gatewayErr := newUPNPNAT(ctx, client, "UPNP (IG1-PPP1)", RootDevice)
				if gatewayErr != nil {
					return
				}
				select {
				case res <- gateway:
				case <-ctx.Done():
				}
			}

		}
	})
}

type upnp_NAT_Client interface {
	GetExternalIPAddress() (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
	GetSpecificPortMappingEntryCtx(context.Context, string, uint16, string) (uint16, string, bool, string, uint32, error)
}

type upnpMappingOwner struct {
	client   net.IP
	protocol string
}

type upnp_NAT struct {
	c                upnp_NAT_Client
	ports            map[int]int
	typ              string
	rootDevice       *goupnp.RootDevice
	uncertain        map[int]bool
	owners           map[int]upnpMappingOwner
	capturedDevice   bool
	deviceAddress    net.IP
	deleteContextErr error
}

// A typed SOAP rejection is definite only while it has a single error chain.
// Joined transport/cleanup errors must not be erased by a nested fault code.
func upnpFaultCode(err error) int {
	for err != nil {
		if incomplete, ok := err.(interface{ RuntimeCleanupIncomplete() bool }); ok && incomplete.RuntimeCleanupIncomplete() {
			return 0
		}
		if fault, ok := err.(*soap.SOAPFaultError); ok {
			return fault.Detail.UPnPError.Errorcode
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			causes := joined.Unwrap()
			if len(causes) != 1 {
				return 0
			}
			err = causes[0]
			continue
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = wrapped.Unwrap()
	}
	return 0
}

func upnpAddRejected(err error) bool {
	switch upnpFaultCode(err) {
	case 401, 402, 600, 601, 602, 605, 606, 715, 716, 718, 724, 725, 726, 727, 728, 729, 732:
		return true
	default:
		return false
	}
}

func (u *upnp_NAT) rememberMapping(internal, external int, client net.IP, protocol string, uncertain bool) {
	if u.ports == nil {
		u.ports = make(map[int]int)
	}
	if u.owners == nil {
		u.owners = make(map[int]upnpMappingOwner)
	}
	if u.uncertain == nil {
		u.uncertain = make(map[int]bool)
	}
	u.ports[internal] = external
	u.owners[internal] = upnpMappingOwner{client: append(net.IP(nil), client...), protocol: protocol}
	u.uncertain[internal] = uncertain
}

func (u *upnp_NAT) forgetMapping(internal int) {
	delete(u.ports, internal)
	delete(u.owners, internal)
	delete(u.uncertain, internal)
}

func (u *upnp_NAT) GetExternalAddress() (addr net.IP, err error) {
	ipString, err := u.c.GetExternalIPAddress()
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, ErrNoExternalAddress
	}

	return ip, nil
}

// Optional context-aware companion; the original NAT interface remains intact.
// Older/context-free gateway implementations are still honestly joined by the
// caller instead of being detached on cancellation.
func (u *upnp_NAT) GetExternalAddressContext(ctx context.Context) (net.IP, error) {
	if c, ok := u.c.(interface {
		GetExternalIPAddressCtx(context.Context) (string, error)
	}); ok {
		address, err := c.GetExternalIPAddressCtx(ctx)
		if err != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		return net.ParseIP(address), ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	address, err := u.GetExternalAddress()
	return address, errors.Join(err, ctx.Err())
}

func mapProtocol(s string) string {
	switch s {
	case "udp":
		return "UDP"
	case "tcp":
		return "TCP"
	default:
		panic("invalid protocol: " + s)
	}
}

// An unconfirmed UPnP creation cannot safely be deleted by external port:
// a lost conflict response may identify somebody else's existing mapping.
var errMappingUnconfirmed = errors.New("UPnP mapping ownership is unconfirmed; cleanup remains incomplete")

func (u *upnp_NAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, timeout time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	seconds := timeout / time.Second
	if (protocol != "udp" && protocol != "tcp") || internalPort <= 0 || internalPort > 65535 || timeout < 0 || (timeout > 0 && seconds == 0) || seconds > 0xffffffff {
		return 0, fmt.Errorf("invalid UPnP mapping request")
	}
	if u.uncertain[internalPort] {
		return 0, errMappingUnconfirmed
	}
	ip, err := u.GetInternalAddress()
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if u.ports == nil {
		u.ports = make(map[int]int)
	}
	if externalPort := u.ports[internalPort]; externalPort > 0 {
		owner, ok := u.owners[internalPort]
		if !ok || owner.protocol != protocol || !owner.client.Equal(ip) {
			return 0, errMappingUnconfirmed
		}
		// A renewal failure must not silently move the owned mapping to another
		// external port and lose the original lease's cleanup authority.
		err = u.c.AddPortMappingCtx(ctx, "", uint16(externalPort), mapProtocol(protocol), uint16(internalPort), ip.String(), true, description, uint32(seconds))
		if upnpFaultCode(err) == 718 {
			// The old ACK is no longer deletion authority. A later identity query
			// may establish absence/foreign ownership, but never blindly delete.
			if u.uncertain == nil {
				u.uncertain = make(map[int]bool)
			}
			u.uncertain[internalPort] = true
		}
		if err != nil || ctx.Err() != nil {
			return 0, errors.Join(err, ctx.Err())
		}
		return externalPort, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		externalPort := randomPort()
		err = u.c.AddPortMappingCtx(ctx, "", uint16(externalPort), mapProtocol(protocol), uint16(internalPort), ip.String(), true, description, uint32(seconds))
		if err == nil {
			u.rememberMapping(internalPort, externalPort, ip, protocol, false)
			return externalPort, ctx.Err()
		}
		if upnpFaultCode(err) == 718 {
			// A confirmed conflict rejected this request without creating our lease.
			if ctx.Err() != nil {
				return 0, errors.Join(err, ctx.Err())
			}
			continue
		}
		if upnpAddRejected(err) {
			return 0, errors.Join(err, ctx.Err())
		}
		// Do not retry ambiguous errors onto more external ports. Preserve the
		// attempted identity as debt, without claiming it is safe to delete.
		u.rememberMapping(internalPort, externalPort, ip, protocol, true)
		return 0, errors.Join(errMappingUnconfirmed, err, ctx.Err())
	}
	return 0, err
}

func (u *upnp_NAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	if u.ports[internalPort] == 0 {
		u.deleteContextErr = ctx.Err()
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if externalPort := u.ports[internalPort]; externalPort > 0 {
		if (protocol != "udp" && protocol != "tcp") || internalPort <= 0 || internalPort > 65535 || externalPort > 65535 {
			return fmt.Errorf("invalid owned UPnP mapping")
		}
		owner, ok := u.owners[internalPort]
		if !ok || owner.protocol != protocol || owner.client.To4() == nil {
			return errMappingUnconfirmed
		}
		port, client, _, _, _, err := u.c.GetSpecificPortMappingEntryCtx(ctx, "", uint16(externalPort), mapProtocol(protocol))
		u.deleteContextErr = ctx.Err()
		if upnpFaultCode(err) == 714 {
			u.forgetMapping(internalPort)
			return nil
		}
		if err != nil {
			return errors.Join(err, ctx.Err())
		}
		address := net.ParseIP(client)
		if address.To4() == nil || port == 0 {
			return errors.Join(errMappingUnconfirmed, ctx.Err())
		}
		if int(port) != internalPort || !address.Equal(owner.client) {
			// The exact external-port/protocol key now belongs to another target.
			// Our prior obligation is absent; never issue its destructive Delete.
			u.forgetMapping(internalPort)
			return nil
		}
		if u.uncertain[internalPort] {
			return errors.Join(errMappingUnconfirmed, ctx.Err())
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err = u.c.DeletePortMappingCtx(ctx, "", uint16(externalPort), mapProtocol(protocol))
		u.deleteContextErr = ctx.Err()
		if err != nil && upnpFaultCode(err) != 714 {
			return errors.Join(err, ctx.Err())
		}
		// Parsed success or NoSuchEntry confirms the remote obligation ended.
		// Cancellation remains diagnostic, not fabricated uncertainty.
		u.forgetMapping(internalPort)
	}
	return nil
}

func (u *upnp_NAT) GetDeviceAddress() (net.IP, error) {
	if u.capturedDevice {
		if u.deviceAddress.To4() == nil {
			return nil, errors.New("missing captured UPnP device address")
		}
		return append(net.IP(nil), u.deviceAddress...), nil
	}
	addr, err := net.ResolveUDPAddr("udp4", u.rootDevice.URLBase.Host)
	if err != nil {
		return nil, err
	}

	return addr.IP, nil
}

func (u *upnp_NAT) PortMappingDeleteContextError() error { return u.deleteContextErr }

func (u *upnp_NAT) GetInternalAddress() (net.IP, error) {
	devAddr, err := u.GetDeviceAddress()
	if err != nil {
		return nil, err
	}

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
				if x.Contains(devAddr) {
					return x.IP, nil
				}
			}
		}
	}

	return nil, ErrNoInternalAddress
}

func (n *upnp_NAT) Type() string { return n.typ }
