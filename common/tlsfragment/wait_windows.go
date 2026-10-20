package tf

import (
	"context"
	"github.com/sagernet/sing-box/adapter/outbound"
	"errors"
	"time"

	"github.com/sagernet/sing/common/winiphlpapi"

	"golang.org/x/sys/windows"
)

func writeAndWaitAck(ctx context.Context, conn outbound.RuntimeTCPControlConn, payload []byte, fallbackDelay time.Duration) error {
	start := time.Now()
	err := winiphlpapi.WriteAndWaitAck(ctx, conn, payload)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			if _, err := conn.Write(payload); err != nil {
				return err
			}
			time.Sleep(fallbackDelay)
			return nil
		}
		return err
	}
	if time.Since(start) <= 20*time.Millisecond {
		time.Sleep(fallbackDelay)
	}
	return nil
}
