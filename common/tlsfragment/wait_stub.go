//go:build !(linux || darwin || windows)

package tf

import (
	"context"
	"github.com/sagernet/sing-box/adapter/outbound"
	"time"
)

func writeAndWaitAck(ctx context.Context, conn outbound.RuntimeTCPControlConn, payload []byte, fallbackDelay time.Duration) error {
	_, err := conn.Write(payload)
	if err != nil {
		return err
	}
	time.Sleep(fallbackDelay)
	return nil
}
