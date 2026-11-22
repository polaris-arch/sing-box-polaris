//go:build with_quic

package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestHTTP3DialBackoffPreservesForegroundReserve(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		wantDelay bool
	}{
		{"foreground reserve", errors.Join(adapter.ErrOutboundForegroundSlot, adapter.ErrOutboundForegroundSlot), false},
		{"network failure", io.ErrUnexpectedEOF, true},
		{"mixed failure", errors.Join(io.ErrUnexpectedEOF, adapter.ErrOutboundForegroundSlot), true},
		{"hard capacity", adapter.ErrOutboundCapacity, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const authority = "a.example:443"
			dialer := &http3BackoffTestDialer{backgroundErr: test.err}
			transport, err := newHTTP3FallbackTransport(dialer, nil, new(runtimeTestInner), option.QUICOptions{}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := transport.Close(); err != nil {
					t.Error(err)
				}
			})
			roundTrip := func(ctx context.Context) {
				t.Helper()
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority, strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				response, err := transport.RoundTrip(request)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			roundTrip(urltest.ContextWithBackgroundProbe(t.Context()))
			if count := dialer.dials.Load(); count != 1 {
				t.Fatalf("H3 dials after background request = %d, want 1", count)
			}
			roundTrip(t.Context())
			wantDials := int32(2)
			if test.wantDelay {
				wantDials = 1
			}
			if count := dialer.dials.Load(); count != wantDials {
				t.Fatalf("H3 dials after foreground request = %d, want %d", count, wantDials)
			}
		})
	}
}

type http3BackoffTestDialer struct {
	N.Dialer
	backgroundErr error
	dials         atomic.Int32
}

func (d *http3BackoffTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	if urltest.IsBackgroundProbe(ctx) {
		return nil, d.backgroundErr
	}
	return nil, io.ErrUnexpectedEOF
}

func TestHTTP3BrokenAuthorityIsolation(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	if !transport.h3Broken("a.example:443") {
		t.Fatal("a.example:443 should be broken after mark")
	}
	if transport.h3Broken("b.example:443") {
		t.Fatal("b.example:443 must not be affected by marking a.example")
	}
}

func TestHTTP3BrokenBackoffPerAuthority(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	if transport.broken["a.example:443"].backoff != 5*time.Minute {
		t.Fatalf("first mark should set backoff to 5m, got %v", transport.broken["a.example:443"].backoff)
	}
	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	if transport.broken["a.example:443"].backoff != 10*time.Minute {
		t.Fatalf("second mark should double backoff to 10m, got %v", transport.broken["a.example:443"].backoff)
	}
	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	if transport.broken["a.example:443"].backoff != 20*time.Minute {
		t.Fatalf("third mark should double to 20m, got %v", transport.broken["a.example:443"].backoff)
	}

	if _, found := transport.broken["b.example:443"]; found {
		t.Fatal("marking a.example must not leak into b.example backoff state")
	}

	transport.markH3Broken("b.example:443", io.ErrUnexpectedEOF)
	if transport.broken["b.example:443"].backoff != 5*time.Minute {
		t.Fatalf("b.example first mark should start at 5m independent of a.example, got %v", transport.broken["b.example:443"].backoff)
	}
}

func TestHTTP3BrokenBackoffCap(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.broken["a.example:443"] = http3BrokenEntry{backoff: 48 * time.Hour, until: time.Now().Add(48 * time.Hour)}
	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	if transport.broken["a.example:443"].backoff != 48*time.Hour {
		t.Fatalf("backoff must cap at 48h, got %v", transport.broken["a.example:443"].backoff)
	}
}

func TestHTTP3BrokenClearDeletesEntry(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443", io.ErrUnexpectedEOF)
	transport.markH3Broken("b.example:443", io.ErrUnexpectedEOF)
	transport.clearH3Broken("a.example:443")

	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("clearH3Broken must delete the entry")
	}
	if !transport.h3Broken("b.example:443") {
		t.Fatal("clearing a.example must not affect b.example")
	}
}

func TestHTTP3BrokenExpiredEntryGarbageCollected(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.broken["a.example:443"] = http3BrokenEntry{
		backoff: 5 * time.Minute,
		until:   time.Now().Add(-time.Second),
	}
	if transport.h3Broken("a.example:443") {
		t.Fatal("expired entry must report not broken")
	}
	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("expired entry must be garbage-collected on read")
	}
}

func TestHTTP3BrokenEmptyAuthorityNoOp(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("", io.ErrUnexpectedEOF)
	if len(transport.broken) != 0 {
		t.Fatalf("markH3Broken must ignore empty authority, got %d entries", len(transport.broken))
	}
	if transport.h3Broken("") {
		t.Fatal("h3Broken must return false for empty authority")
	}
	transport.clearH3Broken("")
}
