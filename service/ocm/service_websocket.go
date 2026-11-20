package ocm

import (
	"bufio"
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/openai/openai-go/v3/responses"
)

const maxWebSocketMessageBytes = 16 * 1024 * 1024

var errWebSocketResponseHeadTooLarge = errors.New("websocket response head exceeds HTTP header limit")

var errWebSocketMessageTooLarge = errors.New("websocket message exceeds 16 MiB")

type webSocketSession struct {
	clientConn   net.Conn
	upstreamConn net.Conn
	closeOnce    sync.Once
}

func (s *webSocketSession) Close() {
	s.closeOnce.Do(func() {
		s.clientConn.Close()
		s.upstreamConn.Close()
	})
}

func buildUpstreamWebSocketURL(baseURL string, proxyPath string) string {
	upstreamURL := baseURL
	if strings.HasPrefix(upstreamURL, "https://") {
		upstreamURL = "wss://" + upstreamURL[len("https://"):]
	} else if strings.HasPrefix(upstreamURL, "http://") {
		upstreamURL = "ws://" + upstreamURL[len("http://"):]
	}
	return upstreamURL + proxyPath
}

func isForwardableResponseHeader(key string) bool {
	lowerKey := strings.ToLower(key)
	switch {
	case strings.HasPrefix(lowerKey, "x-codex-"):
		return true
	case strings.HasPrefix(lowerKey, "x-reasoning"):
		return true
	case lowerKey == "openai-model":
		return true
	case strings.Contains(lowerKey, "-secondary-"):
		return true
	default:
		return false
	}
}

func isForwardableWebSocketRequestHeader(key string) bool {
	if isHopByHopHeader(key) {
		return false
	}

	lowerKey := strings.ToLower(key)
	switch {
	case lowerKey == "authorization":
		return false
	case strings.HasPrefix(lowerKey, "sec-websocket-"):
		return false
	default:
		return true
	}
}

type webSocketResponseHeadConn struct {
	net.Conn
	remaining int
}

func (c *webSocketResponseHeadConn) Read(p []byte) (int, error) {
	if c.remaining < 0 {
		return c.Conn.Read(p)
	}
	if c.remaining == 0 {
		return 0, errWebSocketResponseHeadTooLarge
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	return n, err
}

func dialWebSocketWithResponseLimit(ctx context.Context, dialer ws.Dialer, upstreamURL string) (net.Conn, *bufio.Reader, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()

	dial := dialer.NetDial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var routedConn net.Conn
	var stopClose func() bool
	dialer.NetDial = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(dialCtx, network, address)
		if err == nil {
			routedConn = conn
			// Some routed streams do not support deadlines. Close the raw
			// stream on cancellation, even while the TLS layer is stalled.
			stopClose = context.AfterFunc(ctx, func() { _ = conn.Close() })
		}
		return conn, err
	}
	// Wrap the plaintext stream, before the dialer reads the status line or
	// headers. OnHeader only runs after a full line has already been buffered.
	dialer.WrapConn = func(conn net.Conn) net.Conn {
		return &webSocketResponseHeadConn{Conn: conn, remaining: http.DefaultMaxHeaderBytes}
	}
	conn, reader, _, err := dialer.Dial(ctx, upstreamURL)
	// Only the live relay owns an accepted connection. If cancellation
	// already started to close it, keep it out of the relay entirely.
	if stopClose != nil && !stopClose() {
		return nil, nil, ctx.Err()
	}
	if contextErr := ctx.Err(); contextErr != nil {
		if err == nil {
			_ = routedConn.Close()
		}
		return nil, nil, contextErr
	}
	if err != nil {
		return nil, nil, err
	}
	// Keep any frame bytes already buffered during the upgrade. The same
	// reader can continue reading frames after the response-head limit ends.
	conn.(*webSocketResponseHeadConn).remaining = -1
	return conn, reader, nil
}

func (s *Service) handleWebSocket(w http.ResponseWriter, r *http.Request, proxyPath string, username string) {
	accessToken, err := s.getAccessToken(r.Context())
	if err != nil {
		s.logger.Error("get access token for websocket: ", err)
		writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "authentication failed")
		return
	}

	upstreamURL := buildUpstreamWebSocketURL(s.getBaseURL(), proxyPath)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamHeaders := make(http.Header)
	for key, values := range r.Header {
		if isForwardableWebSocketRequestHeader(key) {
			upstreamHeaders[key] = values
		}
	}
	for key, values := range s.httpHeaders {
		upstreamHeaders.Del(key)
		upstreamHeaders[key] = values
	}
	upstreamHeaders.Set("Authorization", "Bearer "+accessToken)
	if accountID := s.getAccountID(); accountID != "" {
		upstreamHeaders.Set("ChatGPT-Account-Id", accountID)
	}

	upstreamResponseHeaders := make(http.Header)
	upstreamDialer := ws.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
		TLSConfig: &stdTLS.Config{
			RootCAs: adapter.RootPoolFromContext(s.ctx),
			Time:    ntp.TimeFuncFromContext(s.ctx),
		},
		Header: ws.HandshakeHeaderHTTP(upstreamHeaders),
		OnHeader: func(key, value []byte) error {
			upstreamResponseHeaders.Add(string(key), string(value))
			return nil
		},
	}

	upstreamConn, upstreamBufferedReader, err := dialWebSocketWithResponseLimit(r.Context(), upstreamDialer, upstreamURL)
	if err != nil {
		s.logger.Error("dial upstream websocket: ", err)
		writeJSONError(w, r, http.StatusBadGateway, "api_error", "upstream websocket connection failed")
		return
	}

	weeklyCycleHint := extractWeeklyCycleHint(upstreamResponseHeaders)

	clientResponseHeaders := make(http.Header)
	for key, values := range upstreamResponseHeaders {
		if isForwardableResponseHeader(key) {
			clientResponseHeaders[key] = values
		}
	}

	clientUpgrader := ws.HTTPUpgrader{
		Header: clientResponseHeaders,
	}
	if s.isShuttingDown() {
		upstreamConn.Close()
		writeJSONError(w, r, http.StatusServiceUnavailable, "api_error", "service is shutting down")
		return
	}
	clientConn, _, _, err := clientUpgrader.Upgrade(r, w)
	if err != nil {
		s.logger.Error("upgrade client websocket: ", err)
		upstreamConn.Close()
		return
	}
	session := &webSocketSession{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
	}
	if !s.registerWebSocketSession(session) {
		session.Close()
		return
	}
	defer s.unregisterWebSocketSession(session)

	var upstreamReadWriter io.ReadWriter
	if upstreamBufferedReader != nil {
		upstreamReadWriter = struct {
			io.Reader
			io.Writer
		}{upstreamBufferedReader, upstreamConn}
	} else {
		upstreamReadWriter = upstreamConn
	}
	clientPeer := &webSocketPeer{conn: clientConn, stream: clientConn, state: ws.StateServerSide}
	upstreamPeer := &webSocketPeer{conn: upstreamConn, stream: upstreamReadWriter, state: ws.StateClientSide}

	modelChannel := make(chan string, 1)
	var waitGroup sync.WaitGroup

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		defer session.Close()
		s.proxyWebSocketClientToUpstream(clientPeer, upstreamPeer, modelChannel)
	}()
	go func() {
		defer waitGroup.Done()
		defer session.Close()
		s.proxyWebSocketUpstreamToClient(upstreamPeer, clientPeer, modelChannel, username, weeklyCycleHint)
	}()
	waitGroup.Wait()
}

type webSocketPeer struct {
	conn    net.Conn
	stream  io.ReadWriter
	state   ws.State
	writeMu sync.Mutex
	closing bool
}

// writeMessage consumes the payload so an upstream write can mask it in place.
func (p *webSocketPeer) writeMessage(opCode ws.OpCode, data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.closing {
		return net.ErrClosed
	}
	frame := ws.NewFrame(opCode, true, data)
	if p.state.ClientSide() {
		frame = ws.MaskFrameInPlace(frame)
	}
	return ws.WriteFrame(p.stream, frame)
}

func (p *webSocketPeer) readData() ([]byte, ws.OpCode, error) {
	writeControl := wsutil.ControlFrameHandler(p.stream, p.state)
	handleControl := func(header ws.Header, frame io.Reader) error {
		var payload [ws.MaxControlFramePayloadSize]byte
		data := payload[:int(header.Length)]
		if _, err := io.ReadFull(frame, data); err != nil {
			return err
		}
		p.writeMu.Lock()
		defer p.writeMu.Unlock()
		if p.closing {
			return net.ErrClosed
		}
		p.closing = header.OpCode == ws.OpClose
		return writeControl(header, bytes.NewReader(data))
	}
	var declaredBytes int64
	reader := wsutil.Reader{
		Source:         p.stream,
		State:          p.state,
		CheckUTF8:      true,
		OnIntermediate: handleControl,
		MaxFrameSize:   maxWebSocketMessageBytes,
		OnContinuation: func(header ws.Header, _ io.Reader) error {
			if header.Length > maxWebSocketMessageBytes-declaredBytes {
				return errWebSocketMessageTooLarge
			}
			declaredBytes += header.Length
			return nil
		},
	}
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return nil, 0, err
		}
		if header.OpCode.IsControl() {
			if err := handleControl(header, &reader); err != nil {
				return nil, 0, err
			}
			continue
		}
		declaredBytes = header.Length
		data, err := readWebSocketPayload(&reader, int(declaredBytes))
		if err != nil {
			return nil, 0, err
		}
		return data, header.OpCode, nil
	}
}

func readWebSocketPayload(reader *wsutil.Reader, firstFrameBytes int) ([]byte, error) {
	// Don't reserve the entire declared length before bytes arrive.
	data := make([]byte, 0, min(firstFrameBytes, 64*1024))
	var next [1]byte
	for {
		tail := data[len(data):cap(data)]
		if len(tail) == 0 {
			// Check the end of the message before growing the allocation.
			tail = next[:]
		}
		n, err := reader.Read(tail)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(data)+n > cap(data) {
			if len(data) == maxWebSocketMessageBytes {
				return nil, errWebSocketMessageTooLarge
			}
			capacity := min(maxWebSocketMessageBytes, max(4096, 2*cap(data)))
			grown := make([]byte, len(data)+n, capacity)
			copy(grown, data)
			grown[len(data)] = next[0]
			data = grown
		} else {
			data = data[:len(data)+n]
		}
		if err == io.EOF {
			return data, nil
		}
	}
}

func (p *webSocketPeer) reportSizeLimit(err error) {
	if !errors.Is(err, wsutil.ErrFrameTooLarge) && !errors.Is(err, errWebSocketMessageTooLarge) {
		return
	}
	// Bound both the current writer and the best-effort close notification.
	if p.conn.SetWriteDeadline(time.Now().Add(time.Second)) == nil {
		p.writeMu.Lock()
		defer p.writeMu.Unlock()
		if !p.closing {
			p.closing = true
			body := ws.NewCloseFrameBody(ws.StatusMessageTooBig, "message exceeds 16 MiB")
			_ = wsutil.WriteMessage(p.stream, p.state, ws.OpClose, body)
		}
	}
}

func (s *Service) proxyWebSocketClientToUpstream(client, upstream *webSocketPeer, modelChannel chan<- string) {
	for {
		data, opCode, err := client.readData()
		if err != nil {
			client.reportSizeLimit(err)
			if !E.IsClosedOrCanceled(err) {
				s.logger.Debug("read client websocket: ", err)
			}
			return
		}

		if opCode == ws.OpText && s.usageTracker != nil {
			var request struct {
				Type  string `json:"type"`
				Model string `json:"model"`
			}
			if json.Unmarshal(data, &request) == nil && request.Type == "response.create" && request.Model != "" {
				select {
				case modelChannel <- request.Model:
				default:
				}
			}
		}

		err = upstream.writeMessage(opCode, data)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				s.logger.Debug("write upstream websocket: ", err)
			}
			return
		}
	}
}

func (s *Service) proxyWebSocketUpstreamToClient(upstream, client *webSocketPeer, modelChannel <-chan string, username string, weeklyCycleHint *WeeklyCycleHint) {
	var requestModel string
	for {
		data, opCode, err := upstream.readData()
		if err != nil {
			upstream.reportSizeLimit(err)
			if !E.IsClosedOrCanceled(err) {
				s.logger.Debug("read upstream websocket: ", err)
			}
			return
		}

		if opCode == ws.OpText && s.usageTracker != nil {
			select {
			case model := <-modelChannel:
				requestModel = model
			default:
			}

			var event struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &event) == nil && event.Type == "response.completed" {
				var streamEvent responses.ResponseStreamEventUnion
				if json.Unmarshal(data, &streamEvent) == nil {
					completedEvent := streamEvent.AsResponseCompleted()
					responseModel := string(completedEvent.Response.Model)
					serviceTier := string(completedEvent.Response.ServiceTier)
					inputTokens := completedEvent.Response.Usage.InputTokens
					outputTokens := completedEvent.Response.Usage.OutputTokens
					cachedTokens := completedEvent.Response.Usage.InputTokensDetails.CachedTokens

					if inputTokens > 0 || outputTokens > 0 {
						if responseModel == "" {
							responseModel = requestModel
						}
						if responseModel != "" {
							contextWindow := detectContextWindow(responseModel, serviceTier, inputTokens)
							s.usageTracker.AddUsageWithCycleHint(
								responseModel,
								contextWindow,
								inputTokens,
								outputTokens,
								cachedTokens,
								serviceTier,
								username,
								time.Now(),
								weeklyCycleHint,
							)
						}
					}
				}
			}
		}

		err = client.writeMessage(opCode, data)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				s.logger.Debug("write client websocket: ", err)
			}
			return
		}
	}
}
