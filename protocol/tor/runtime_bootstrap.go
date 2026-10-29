package tor

import (
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func (t *Outbound) bootstrap() error {
	// Bine EventWait can leave an unjoined relay. Synchronous control calls
	// relay events only to our owned receiver. Context cancellation closes
	// the actual control socket, so even a blocked GetInfo can be joined.
	if err := t.torInstance.EnableNetwork(t.ctx, false); err != nil {
		return err
	}
	for {
		phase, err := t.torInstance.Control.GetInfo("status/bootstrap-phase")
		if err != nil {
			return err
		}
		if len(phase) != 1 || phase[0].Key != "status/bootstrap-phase" {
			return E.New("get tor bootstrap phase")
		}
		fields := strings.Fields(phase[0].Val)
		ready := false
		for _, field := range fields {
			if field == "ERR" {
				return E.New("tor bootstrap reported failure: ", phase[0].Val)
			}
			if field == "PROGRESS=100" {
				ready = true
			}
		}
		if ready {
			break
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-timer.C:
		case <-t.ctx.Done():
			timer.Stop()
			return t.ctx.Err()
		}
	}
	info, err := t.torInstance.Control.GetInfo("net/listeners/socks")
	if err != nil {
		return err
	}
	if len(info) != 1 || info[0].Key != "net/listeners/socks" {
		return E.New("get socks proxy address")
	}
	address := M.ParseSocksaddr(strings.Trim(info[0].Val, "\""))
	if !address.IsValid() || address.Port == 0 {
		return E.New("invalid tor socks proxy address")
	}
	t.logger.Trace("obtained tor socks5 address ", info[0].Val)
	t.socksClient = socks.NewClient(N.SystemDialer, address, socks.Version5, "", "")
	return nil
}
