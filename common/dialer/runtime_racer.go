package dialer

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// startRuntimeRacer reserves the caller and actual receiving closure BEFORE
// publishing a worker. A losing racer owns that reservation through connection
// cleanup. Panic has no trustworthy completion evidence, so its handles remain
// charged instead of allowing retirement to free a possibly live resource.
func startRuntimeRacer(ctx context.Context, source adapter.RuntimeResourceSource, run func(context.Context) error, failed func(error)) error {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		return err
	}
	go func() {
		completed := false
		defer func() {
			if recovered := recover(); recovered != nil {
				failed(fmt.Errorf("runtime dial racer completion unknown after panic: %v", recovered))
			}
			if completed {
				release()
			}
		}()
		if err := run(owned); err != nil {
			failed(fmt.Errorf("runtime dial racer cleanup incomplete: %v", err))
			return
		}
		completed = true
	}()
	return nil
}

// This adapter deliberately does not promote ParallelNetworkDialer. It keeps
// the existing serial address attempts inside each address-family racer.
type runtimeSerialInterfaceDialer struct{ N.Dialer }

func (d runtimeSerialInterfaceDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, _ *C.NetworkStrategy, _, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	return d.DialContext(ctx, network, destination)
}

func (d runtimeSerialInterfaceDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, _ *C.NetworkStrategy, _, _ []C.InterfaceType, _ time.Duration) (net.PacketConn, error) {
	return d.ListenPacket(ctx, destination)
}
