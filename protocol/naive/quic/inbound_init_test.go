package quic

import (
	"testing"
	"time"
)

func TestQUICConfigKeepsIdleConnectionsAlive(t *testing.T) {
	config := newQUICConfig()
	if config.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("KeepAlivePeriod = %v; want 10s", config.KeepAlivePeriod)
	}
	if config.MaxIncomingStreams != 1<<60 || !config.Allow0RTT || !config.DisablePathManager {
		t.Fatalf("unexpected QUIC config: %+v", config)
	}
}
