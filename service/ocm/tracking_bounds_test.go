package ocm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/usagetrack"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

func TestWebSocketMessageBoundIncludesFragments(t *testing.T) {
	var wire bytes.Buffer
	upstream := &webSocketPeer{stream: &wire, state: ws.StateClientSide}
	part := bytes.Repeat([]byte{'x'}, maxWebSocketMessageBytes/2)
	writeFrame := func(frame ws.Frame) {
		t.Helper()
		if err := ws.WriteFrame(&wire, frame); err != nil {
			t.Fatal(err)
		}
	}
	writeFrame(ws.NewFrame(ws.OpBinary, false, part))
	writeFrame(ws.NewFrame(ws.OpContinuation, true, part))
	data, opCode, err := upstream.readData()
	if err != nil || opCode != ws.OpBinary || len(data) != maxWebSocketMessageBytes {
		t.Fatalf("valid message at the limit changed: %d bytes, %v, %v", len(data), opCode, err)
	}

	wire.Reset()
	writeFrame(ws.NewFrame(ws.OpBinary, false, part))
	writeFrame(ws.NewFrame(ws.OpContinuation, false, part))
	if err = ws.WriteHeader(&wire, ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = upstream.readData(); !errors.Is(err, errWebSocketMessageTooLarge) {
		t.Fatalf("expected aggregate message limit, got %v", err)
	}

	wire.Reset()
	if err := ws.WriteHeader(&wire, ws.Header{Fin: true, OpCode: ws.OpBinary, Length: maxWebSocketMessageBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = upstream.readData(); !errors.Is(err, wsutil.ErrFrameTooLarge) {
		t.Fatalf("expected header to be rejected before reading payload, got %v", err)
	}

	wire.Reset()
	writeFrame(ws.MaskFrame(ws.NewTextFrame([]byte("payload"))))
	client := &webSocketPeer{stream: &wire, state: ws.StateServerSide}
	data, opCode, err = client.readData()
	if err != nil || opCode != ws.OpText || string(data) != "payload" {
		t.Fatalf("valid masked WebSocket message changed: %q, %v, %v", data, opCode, err)
	}
	wire.Reset()
	if err := upstream.writeMessage(opCode, data); err != nil {
		t.Fatal(err)
	}
	data, opCode, err = client.readData()
	if err != nil || opCode != ws.OpText || string(data) != "payload" {
		t.Fatalf("upstream forwarding changed the masked message: %q, %v, %v", data, opCode, err)
	}
}

func TestWebSocketLimitReportsMessageTooBig(t *testing.T) {
	for _, state := range []ws.State{ws.StateServerSide, ws.StateClientSide} {
		sender, peer := net.Pipe()
		relay := &webSocketPeer{conn: sender, stream: sender, state: state}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer sender.Close()
			relay.reportSizeLimit(errWebSocketMessageTooLarge)
		}()
		frame, err := ws.ReadFrame(peer)
		_ = peer.Close()
		<-done
		if err != nil || frame.Header.OpCode != ws.OpClose || frame.Header.Masked != (state == ws.StateClientSide) {
			t.Fatalf("incorrect close frame for state %v: %v, %v", state, frame.Header, err)
		}
		if frame.Header.Masked {
			frame = ws.UnmaskFrameInPlace(frame)
		}
		status, _ := ws.ParseCloseFrameData(frame.Payload)
		if status != ws.StatusMessageTooBig {
			t.Fatalf("wrong close code: %v", status)
		}
		if err = relay.writeMessage(ws.OpBinary, []byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("wanted a closed peer after 1009, got %v", err)
		}
	}
}

func TestWebSocketLimitUnblocksAnInFlightWrite(t *testing.T) {
	sender, peer := net.Pipe()
	defer sender.Close()
	defer peer.Close()
	relay := &webSocketPeer{conn: sender, stream: sender, state: ws.StateServerSide}
	writing := make(chan struct{})
	go func() {
		relay.writeMu.Lock()
		defer relay.writeMu.Unlock()
		close(writing)
		_ = wsutil.WriteMessage(sender, ws.StateServerSide, ws.OpBinary, []byte("unread"))
	}()
	<-writing
	done := make(chan struct{})
	go func() {
		relay.reportSizeLimit(errWebSocketMessageTooLarge)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("close notification waited for an unresponsive sender")
	}
}

func TestTrackingOverflowPreservesBodyAndMarksIncomplete(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
		t.Cleanup(func() { _ = tracker.Close() })
		service := &Service{usageTracker: tracker, logger: log.NewNOPFactory().Logger()}
		body := bytes.Repeat([]byte("x"), usagetrack.BodyBudget+1)
		response := &http.Response{Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(bytes.NewReader(body))}
		writer := httptest.NewRecorder()
		service.handleResponseWithTracking(writer, response, "/v1/chat/completions", "model", "user")
		if !bytes.Equal(writer.Body.Bytes(), body) {
			t.Fatal("business body truncated")
		}
		result := tracker.ToJSON()
		if result.IncompleteObservations != 1 || len(result.Combinations) != 0 {
			t.Fatal("partial accounting presented as complete")
		}
	}
}

func TestNormalAndMalformedTracking(t *testing.T) {
	for _, tc := range []struct {
		name, kind, body string
		incomplete       bool
	}{
		{"normal json", "application/json", `{"model":"gpt-5","usage":{"prompt_tokens":12,"completion_tokens":7}}`, false},
		{"bad json", "application/json", `{broken`, true},
		{"normal sse", "text/event-stream", `data: {"model":"gpt-5","usage":{"prompt_tokens":12,"completion_tokens":7}}
`, false},
		{"broken event after usage", "text/event-stream", `data: {"model":"gpt-5","usage":{"prompt_tokens":12,"completion_tokens":7}}
data: {broken
`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
			t.Cleanup(func() { _ = tracker.Close() })
			service := &Service{usageTracker: tracker, logger: log.NewNOPFactory().Logger()}
			response := &http.Response{Header: http.Header{"Content-Type": []string{tc.kind}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			writer := httptest.NewRecorder()
			service.handleResponseWithTracking(writer, response, "/v1/chat/completions", "model", "user")
			if writer.Body.String() != tc.body {
				t.Fatal("response bytes changed")
			}
			result := tracker.ToJSON()
			if tc.incomplete {
				if result.IncompleteObservations != 1 || len(result.Combinations) != 0 {
					t.Fatal("malformed data accepted")
				}
			} else {
				if result.IncompleteObservations != 0 || len(result.Combinations) != 1 {
					t.Fatal("normal usage lost")
				}
				if result.Combinations[0].Total.InputTokens != 12 || result.Combinations[0].Total.OutputTokens != 7 {
					t.Fatal("token semantics changed")
				}
			}
		})
	}
}

type trackingRoundTrip func(*http.Request) (*http.Response, error)

func (f trackingRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

type brokenRequest struct{ calls int }

func (b *brokenRequest) Read(p []byte) (int, error) {
	b.calls++
	if b.calls == 1 {
		return copy(p, `{"model":`), nil
	}
	return copy(p, `"tail"}`), errors.New("synthetic read failure")
}

func TestServeHTTPReadFailureNeverCallsUpstream(t *testing.T) {
	tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = tracker.Close() })
	calls := 0
	service := &Service{
		usageTracker: tracker, logger: log.NewNOPFactory().Logger(), credentials: &oauthCredentials{APIKey: "synthetic-test-only"},
		httpClient: &http.Client{Transport: trackingRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected upstream") })},
	}
	body := &trackingBody{Reader: &brokenRequest{}}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	request.Body = body
	writer := httptest.NewRecorder()
	service.ServeHTTP(writer, request)
	// net/http owns incoming-body Close; invoking the handler directly does not.
	request.Body.Close()
	if calls != 0 || writer.Code != http.StatusBadRequest || !body.closed {
		t.Fatal("failed request forwarded or body ownership lost")
	}
	if tracker.ToJSON().IncompleteObservations != 1 {
		t.Fatal("read failure missing accounting status")
	}
}

func TestServeHTTPReplayHeadersAndBodyClose(t *testing.T) {
	tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = tracker.Close() })
	sent := `{"model":"model","messages":[]}`
	body := &trackingBody{Reader: strings.NewReader(sent)}
	upstreamBody := &trackingBody{Reader: strings.NewReader(`{"model":"gpt-5","usage":{"prompt_tokens":12,"completion_tokens":7}}`)}
	calls := 0
	service := &Service{
		usageTracker: tracker, logger: log.NewNOPFactory().Logger(), credentials: &oauthCredentials{APIKey: "synthetic-test-only"},
		httpClient: &http.Client{Transport: trackingRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			got, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(got) != sent || r.Header.Get("X-Fixture") != "preserved" {
				t.Fatal("request replay/header changed")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}, "X-Fixture": []string{"upstream"}}, Body: upstreamBody}, nil
		})},
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	request.Body = body
	request.Header.Set("X-Fixture", "preserved")
	writer := httptest.NewRecorder()
	service.ServeHTTP(writer, request)
	if calls != 1 || !body.closed || !upstreamBody.closed {
		t.Fatal("body close or upstream count changed")
	}
	if writer.Code != http.StatusOK || writer.Header().Get("X-Fixture") != "upstream" || writer.Body.String() != `{"model":"gpt-5","usage":{"prompt_tokens":12,"completion_tokens":7}}` {
		t.Fatal("response headers/body changed")
	}
}

type failedTrackingResponse struct {
	body []byte
	sent bool
}

func (r *failedTrackingResponse) Read(p []byte) (int, error) {
	if r.sent {
		return 0, errors.New("synthetic upstream read failure")
	}
	r.sent = true
	return copy(p, r.body), nil
}

func TestResponseReadFailureIsIncompleteAndPreservesDeliveredPrefix(t *testing.T) {
	tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = tracker.Close() })
	service := &Service{usageTracker: tracker, logger: log.NewNOPFactory().Logger()}
	prefix := []byte("data: {}\n")
	response := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(&failedTrackingResponse{body: prefix})}
	writer := httptest.NewRecorder()
	service.handleResponseWithTracking(writer, response, "/v1/chat/completions", "model", "user")
	if !bytes.Equal(writer.Body.Bytes(), prefix) {
		t.Fatal("delivered prefix changed")
	}
	if tracker.ToJSON().IncompleteObservations != 1 || len(tracker.Combinations) != 0 {
		t.Fatal("read failure counted as complete")
	}
}

func TestServeHTTPOverBudgetRequestStillForwardsEveryByte(t *testing.T) {
	tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = tracker.Close() })
	sent := append(bytes.Repeat([]byte(" "), usagetrack.BodyBudget), []byte(`{"model":"model"}`)...)
	body := &trackingBody{Reader: bytes.NewReader(sent)}
	calls := 0
	service := &Service{
		usageTracker: tracker, logger: log.NewNOPFactory().Logger(), credentials: &oauthCredentials{APIKey: "synthetic-test-only"},
		httpClient: &http.Client{Transport: trackingRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			got, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || !bytes.Equal(got, sent) {
				t.Fatal("oversized request was truncated")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"model":"model","usage":{"input_tokens":12,"output_tokens":7,"prompt_tokens":12,"completion_tokens":7}}`))}, nil
		})},
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	request.Body = body
	writer := httptest.NewRecorder()
	service.ServeHTTP(writer, request)
	if calls != 1 || !body.closed || writer.Code != http.StatusOK {
		t.Fatal("overflow changed proxy contract")
	}
	if tracker.ToJSON().IncompleteObservations != 1 || len(tracker.Combinations) != 0 {
		t.Fatal("request overflow incorrectly billed as complete")
	}
}

type failingTrackingWriter struct{ *httptest.ResponseRecorder }

func (w failingTrackingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("synthetic downstream failure")
}

func TestDownstreamWriteFailureMarksIncomplete(t *testing.T) {
	for _, kind := range []string{"application/json", "text/event-stream"} {
		tracker := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json"), lastSaveTime: time.Now()}
		t.Cleanup(func() { _ = tracker.Close() })
		service := &Service{usageTracker: tracker, logger: log.NewNOPFactory().Logger()}
		response := &http.Response{Header: http.Header{"Content-Type": []string{kind}}, Body: io.NopCloser(strings.NewReader("data: {}\n"))}
		writer := failingTrackingWriter{httptest.NewRecorder()}
		service.handleResponseWithTracking(writer, response, "/v1/chat/completions", "model", "user")
		if tracker.ToJSON().IncompleteObservations != 1 || len(tracker.Combinations) != 0 {
			t.Fatal("downstream failure accepted as complete")
		}
	}
}
