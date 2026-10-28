package socks

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestInvalidUOTVersionRejectedBeforeDialerConstruction(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, nil, "invalid-uot", option.SOCKSOutboundOptions{UDPOverTCP: &option.UDPOverTCPOptions{Enabled: true, Version: 255}})
	if err == nil || err.Error() != "unknown UDP over TCP protocol version: 255" {
		t.Fatalf("unexpected constructor result: %v", err)
	}
}
