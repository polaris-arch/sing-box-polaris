package clashapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestConnectionSnapshotIntervalBounds(t *testing.T) {
	const maxMilliseconds = int64((1<<63 - 1) / time.Millisecond)
	for _, test := range []struct {
		raw   string
		want  time.Duration
		valid bool
	}{
		{"", time.Second, true},
		{"1000", time.Second, true},
		{"250", 250 * time.Millisecond, true},
		{"100", 100 * time.Millisecond, true},
		{"99", 100 * time.Millisecond, true},
		{"1", 100 * time.Millisecond, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"-9223372036854775808", 0, false},
		{strconv.FormatInt(maxMilliseconds, 10), time.Duration(maxMilliseconds) * time.Millisecond, true},
		{strconv.FormatInt(maxMilliseconds+1, 10), 0, false},
		{"9223372036854775807", 0, false},
		{"9223372036854775808", 0, false},
		{"garbage", 0, false},
		{"1.5", 0, false},
	} {
		t.Run(test.raw, func(t *testing.T) {
			got, valid := connectionSnapshotInterval(test.raw)
			if valid != test.valid || got != test.want {
				t.Fatalf("interval %q: got (%v, %v), want (%v, %v)", test.raw, got, valid, test.want, test.valid)
			}
		})
	}
}

type connectionUpgradeRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (r *connectionUpgradeRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	return nil, nil, errors.New("test deliberately refuses upgrade after recording it")
}

func connectionWebsocketRequest(interval string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/connections?interval="+interval, nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return request
}

func TestInvalidConnectionIntervalRejectedBeforeWebsocketUpgrade(t *testing.T) {
	for _, raw := range []string{"0", "-1", "9223372036855", "9223372036854775807", "invalid"} {
		t.Run(raw, func(t *testing.T) {
			request := connectionWebsocketRequest(raw)
			response := &connectionUpgradeRecorder{ResponseRecorder: httptest.NewRecorder()}
			// Supply a valid handshake so an old upgrade-first implementation
			// reaches Hijack instead of accidentally returning the same 400.
			getConnections(context.Background(), nil)(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("got status %d, want 400", response.Code)
			}
			if response.hijacked {
				t.Fatal("invalid interval attempted WebSocket hijack")
			}
			var body HTTPError
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("not a business JSON error: %v", err)
			}
			if body.Message != ErrBadRequest.Message {
				t.Fatalf("got business error %q, want %q", body.Message, ErrBadRequest.Message)
			}
			if response.Header().Get("Upgrade") != "" {
				t.Fatal("invalid interval upgraded the connection")
			}
		})
	}
}

func TestValidConnectionIntervalReachesWebsocketUpgrade(t *testing.T) {
	response := &connectionUpgradeRecorder{ResponseRecorder: httptest.NewRecorder()}
	// Hijack deliberately returns an error, so no socket or snapshot is needed.
	getConnections(context.Background(), nil)(response, connectionWebsocketRequest("1000"))
	if !response.hijacked {
		t.Fatal("test handshake did not reach WebSocket upgrade")
	}
}
