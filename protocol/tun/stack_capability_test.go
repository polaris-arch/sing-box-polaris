//go:build with_gvisor && (linux || darwin || windows)

package tun

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

// This assertion compiles the real native platform adapter. It opens no TUN.
var _ tun.GVisorTun = (*tun.NativeTun)(nil)

type capabilityTun struct{ *tun.MemoryTun }

func (t *capabilityTun) WritePacket(packet *stack.PacketBuffer) (int, error) {
	return packet.Size(), nil
}
func (t *capabilityTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return channel.New(16, 1500, ""), stack.NICOptions{}, nil
}

func TestStackCapabilitiesWithoutSystemTun(t *testing.T) {
	if !tun.WithGVisor {
		t.Fatal("gVisor build did not include the implementation")
	}
	memory := tun.NewMemoryTun(tun.MemoryTunOptions{MTU: 1500})
	defer memory.Close()
	options := tun.StackOptions{Context: context.Background(), Tun: &capabilityTun{memory}, TunOptions: tun.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}}}
	for _, name := range []string{"", "go", "system", "mixed", "gvisor"} {
		value, err := tun.NewStack(name, options)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		switch name {
		case "", "go":
			if _, ok := value.(*tun.Go); !ok {
				t.Fatalf("%q silently changed default to %T", name, value)
			}
		case "system":
			if _, ok := value.(*tun.System); !ok {
				t.Fatalf("system: %T", value)
			}
		case "mixed":
			if _, ok := value.(*tun.Mixed); !ok {
				t.Fatalf("mixed: %T", value)
			}
		case "gvisor":
			if _, ok := value.(*tun.GVisor); !ok {
				t.Fatalf("gvisor: %T", value)
			}
		}
		// Constructors do not start the stack or allocate OS handles. Close on an
		// unstarted legacy stack dereferences its uninitialized dispatcher.
	}
	options.IncludeAllNetworks = true
	for _, name := range []string{"system", "mixed"} {
		if _, err := tun.NewStack(name, options); err != tun.ErrIncludeAllNetworks {
			t.Fatalf("%s must reject includeAllNetworks: %v", name, err)
		}
	}
	for _, name := range []string{"", "go", "gvisor"} {
		if _, err := tun.NewStack(name, options); err != nil {
			t.Fatalf("%q with includeAllNetworks: %v", name, err)
		}
	}
	options.Tun = memory
	if _, err := tun.NewStack("gvisor", options); err == nil {
		t.Fatal("gVisor must reject a device without GVisorTun methods")
	}
	if _, err := tun.NewStack("unknown", options); err == nil {
		t.Fatal("unknown stack accepted")
	}
}
