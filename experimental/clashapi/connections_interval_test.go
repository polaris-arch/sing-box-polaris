package clashapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/ws"
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
	conn     net.Conn
}

func (r *connectionUpgradeRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	if r.conn != nil {
		rw := bufio.NewReadWriter(bufio.NewReader(r.conn), bufio.NewWriter(r.conn))
		return r.conn, rw, nil
	}
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
			getConnections(nil)(response, request)
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
	getConnections(nil)(response, connectionWebsocketRequest("1000"))
	if !response.hijacked {
		t.Fatal("test handshake did not reach WebSocket upgrade")
	}
}

type connectionSnapshotOutbound struct {
	adapter.Outbound
	kind string
}

func (o connectionSnapshotOutbound) Type() string { return o.kind }
func (o connectionSnapshotOutbound) Tag() string  { return o.kind }

func openConnectionWebSocket(t *testing.T, request *http.Request, manager *trafficcontrol.Manager, server, peer net.Conn) (*bufio.Reader, <-chan struct{}) {
	t.Helper()
	t.Cleanup(func() { _ = server.Close(); _ = peer.Close() })
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	upgraded := &connectionUpgradeRecorder{ResponseRecorder: httptest.NewRecorder(), conn: server}
	done := make(chan struct{})
	go func() {
		defer close(done)
		getConnections(manager)(upgraded, request)
	}()
	reader := bufio.NewReader(peer)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("got status %d, want 101", response.StatusCode)
	}
	return reader, done
}

func TestConnectionSnapshotsAreSingleTextMessages(t *testing.T) {
	manager := trafficcontrol.NewManager()
	for _, kind := range []string{C.TypeDirect, C.TypeDNS} {
		outbound := connectionSnapshotOutbound{kind: kind}
		server, peer := net.Pipe()
		tracked := manager.RoutedConnection(t.Context(), server, adapter.InboundContext{
			Destination:   M.Socksaddr{Fqdn: strings.Repeat("row", 3000), Port: 443},
			OutboundChain: []adapter.Outbound{outbound},
		}, nil, outbound)
		t.Cleanup(func() { _ = tracked.Close(); _ = peer.Close() })
	}
	rest := httptest.NewRecorder()
	getConnections(manager)(rest, httptest.NewRequest(http.MethodGet, "/connections", nil))
	var expected map[string]json.RawMessage
	if err := json.Unmarshal(rest.Body.Bytes(), &expected); err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(expected["connections"], &rows); err != nil || len(rows) != 1 {
		t.Fatalf("REST connection rows = %d, error = %v", len(rows), err)
	}

	server, peer := net.Pipe()
	request := connectionWebsocketRequest("100").WithContext(t.Context())
	reader, _ := openConnectionWebSocket(t, request, manager, server, peer)
	for range 2 {
		var payload bytes.Buffer
		for fragments := 0; ; fragments++ {
			frame, err := ws.ReadFrame(reader)
			if err != nil {
				t.Fatal(err)
			}
			want := ws.OpContinuation
			if fragments == 0 {
				want = ws.OpText
				if frame.Header.Fin {
					t.Fatal("snapshot was sent as one large frame")
				}
			}
			if frame.Header.OpCode != want || frame.Header.Masked {
				t.Fatalf("unexpected server frame header: %+v", frame.Header)
			}
			payload.Write(frame.Payload)
			if frame.Header.Fin {
				break
			}
		}
		var actual map[string]json.RawMessage
		if err := json.Unmarshal(payload.Bytes(), &actual); err != nil {
			t.Fatal(err)
		}
		var memory uint64
		if err := json.Unmarshal(actual["memory"], &memory); err != nil || len(actual) != len(expected) {
			t.Fatalf("unexpected snapshot fields: %v", err)
		}
		for _, key := range []string{"connections", "downloadTotal", "uploadTotal"} {
			if !bytes.Equal(actual[key], expected[key]) {
				t.Fatalf("WebSocket %s differs from REST", key)
			}
		}
	}
}

type connectionSnapshotDeadlineRecorder struct {
	net.Conn
	deadlines      chan time.Time
	nonzeroCount   int
	shortenTimeout bool
}

func (conn *connectionSnapshotDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		conn.nonzeroCount++
		conn.deadlines <- deadline
		if conn.nonzeroCount == 2 && conn.shortenTimeout {
			deadline = time.Now().Add(25 * time.Millisecond)
		}
	}
	return conn.Conn.SetWriteDeadline(deadline)
}

func TestConnectionSnapshotStopsBlockedWriter(t *testing.T) {
	for _, name := range []string{"deadline", "cancellation"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server, peer := net.Pipe()
			socket := &connectionSnapshotDeadlineRecorder{
				Conn:           server,
				deadlines:      make(chan time.Time, 2),
				shortenTimeout: name == "deadline",
			}
			request := connectionWebsocketRequest("1000").WithContext(ctx)
			// Read only the handshake. Subsequent net.Pipe writes block until
			// the handler closes the socket or its deadline expires.
			_, done := openConnectionWebSocket(t, request, trafficcontrol.NewManager(), socket, peer)
			for _, phase := range []string{"handshake", "snapshot"} {
				select {
				case deadline := <-socket.deadlines:
					if remaining := time.Until(deadline); remaining <= 0 || remaining > connectionSnapshotWriteTimeout {
						t.Fatalf("%s write deadline is out of bounds: %v", phase, remaining)
					}
				case <-time.After(time.Second):
					t.Fatalf("%s write is missing a deadline", phase)
				}
			}
			if name == "cancellation" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("snapshot writer stayed blocked")
			}
		})
	}
}
