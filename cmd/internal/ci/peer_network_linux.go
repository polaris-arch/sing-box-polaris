package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"golang.org/x/sys/unix"
)

type peerTrace struct {
	mu     sync.Mutex
	events []map[string]any
}

func (trace *peerTrace) event(stage string, facts map[string]any) map[string]any {
	if facts == nil {
		facts = make(map[string]any)
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &now) == nil {
		facts["monotonicSeconds"] = float64(now.Sec) + float64(now.Nsec)/1e9
	}
	facts["stage"] = stage
	trace.mu.Lock()
	trace.events = append(trace.events, facts)
	trace.mu.Unlock()
	return facts
}

func peerErrorName(err error) string {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "EOFError"
	case errors.Is(err, syscall.ECONNRESET):
		return "ConnectionResetError"
	case errors.Is(err, syscall.EPIPE):
		return "BrokenPipeError"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "ConnectionRefusedError"
	case errors.Is(err, context.DeadlineExceeded):
		return "TimeoutError"
	}
	var timed net.Error
	if errors.As(err, &timed) && timed.Timeout() {
		return "TimeoutError"
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		return "OSError"
	}
	return "RuntimeError"
}

func peerDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	return deadline
}

func peerAddress(port int) string { return net.JoinHostPort(peerLoopback, strconv.Itoa(port)) }

func peerReadReady(ctx context.Context, process *peerNativeProcess, port int, trace *peerTrace) error {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	return peerWaitObserved(ctx, process, trace, "tcp", func() (bool, error) {
		conn, err := dialer.DialContext(ctx, "tcp4", peerAddress(port))
		if err != nil {
			return false, nil
		}
		conn.Close()
		return true, nil
	})
}

func peerSend(conn net.Conn, payload []byte, trace *peerTrace, stage string) (err error) {
	fact := trace.event(stage, map[string]any{"requestedBytes": len(payload), "completedBytes": 0, "status": "RUNNING"})
	n, err := io.Copy(conn, bytes.NewReader(payload))
	fact["completedBytes"] = n
	if err != nil {
		fact["status"], fact["errorType"] = "FAIL", peerErrorName(err)
		return err
	}
	fact["status"] = "PASS"
	return nil
}

func peerRead(conn net.Conn, count int, trace *peerTrace, stage string) ([]byte, error) {
	fact := trace.event(stage, map[string]any{"requestedBytes": count, "completedBytes": 0, "status": "RUNNING"})
	payload := make([]byte, count)
	n, err := io.ReadFull(conn, payload)
	fact["completedBytes"] = n
	if err != nil {
		fact["status"], fact["errorType"], fact["partialSHA256"] = "FAIL", peerErrorName(err), sha256Hex(payload[:n])
		return nil, err
	}
	fact["status"] = "PASS"
	return payload, nil
}

func peerSOCKSAuth(conn net.Conn, trace *peerTrace, label string) error {
	var packet bytes.Buffer
	if err := socks5.WriteAuthRequest(&packet, socks5.AuthRequest{Methods: []byte{socks5.AuthTypeNotRequired}}); err != nil {
		return err
	}
	if err := peerSend(conn, packet.Bytes(), trace, label+".greeting.send"); err != nil {
		return err
	}
	greeting, err := peerRead(conn, 2, trace, label+".greeting.receive")
	if err != nil {
		return err
	}
	auth, err := socks5.ReadAuthResponse(bytes.NewReader(greeting))
	if err != nil || auth.Method != socks5.AuthTypeNotRequired {
		return fmt.Errorf("SOCKS auth mode differs")
	}
	return nil
}

func peerSOCKSRequest(conn net.Conn, request socks5.Request, trace *peerTrace, stage string) error {
	var packet bytes.Buffer
	if err := socks5.WriteRequest(&packet, request); err != nil {
		return err
	}
	return peerSend(conn, packet.Bytes(), trace, stage)
}

func peerSOCKSConnect(ctx context.Context, mixed, port int, target string, trace *peerTrace, label string) (net.Conn, error) {
	trace.event(label+".socks.tcp_connect", nil)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", peerAddress(mixed))
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(peerDeadline(ctx, 8*time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	label += ".socks"
	fail := func(err error) (net.Conn, error) { return nil, errors.Join(err, conn.Close()) }

	if err := peerSOCKSAuth(conn, trace, label); err != nil {
		return fail(err)
	}
	request := socks5.Request{Command: socks5.CommandConnect,
		Destination: M.Socksaddr{Addr: netip.MustParseAddr(target), Port: uint16(port)}}
	if err := peerSOCKSRequest(conn, request, trace, label+".connect.send"); err != nil {
		return fail(err)
	}
	reply, err := peerRead(conn, 4, trace, label+".connect.response")
	if err != nil {
		return fail(err)
	}
	trace.event(label+".connect.status", map[string]any{"version": reply[0], "replyCode": reply[1], "addressType": reply[3]})
	if reply[0] != socks5.Version || reply[1] != socks5.ReplyCodeSuccess {
		return fail(errPeerSOCKSRejected)
	}
	length := 0
	switch reply[3] {
	case 1:
		length = 6
	case 4:
		length = 18
	case 3:
		prefix, err := peerRead(conn, 1, trace, label+".connect.address_length")
		if err != nil {
			return fail(err)
		}
		length = int(prefix[0]) + 2
	default:
		return fail(fmt.Errorf("unknown SOCKS address"))
	}
	if _, err := peerRead(conn, length, trace, label+".connect.address"); err != nil {
		return fail(err)
	}
	return conn, nil
}

var errPeerSOCKSRejected = errors.New("SOCKS controlled-peer connection rejected")

func peerTCPExchange(ctx context.Context, mixed, port int, target string, sizes []int, retain bool, trace *peerTrace, label string) (facts []map[string]any, retained net.Conn, err error) {
	facts = []map[string]any{}
	conn, err := peerSOCKSConnect(ctx, mixed, port, target, trace, label)
	if err != nil {
		return facts, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		if retained == nil {
			_ = conn.Close()
		}
	}()
	deadline := peerDeadline(ctx, 20*time.Second)
	for _, size := range sizes {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			return facts, nil, err
		}
		fact := map[string]any{"bytes": size, "sentSHA256": sha256Hex(payload), "status": "RUNNING"}
		facts = append(facts, fact)
		if err := conn.SetWriteDeadline(peerDeadline(ctx, 8*time.Second)); err != nil {
			return facts, nil, err
		}
		if err := peerSend(conn, payload, trace, label+".tcp.payload.send"); err != nil {
			return facts, nil, err
		}
		readDeadline := peerDeadline(ctx, 8*time.Second)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return facts, nil, err
		}
		response, err := peerRead(conn, size, trace, label+".tcp.payload.receive")
		if err != nil {
			return facts, nil, err
		}
		if !bytes.Equal(response, payload) {
			return facts, nil, fmt.Errorf("TCP echoed payload bytes differ")
		}
		fact["receivedSHA256"], fact["status"] = sha256Hex(response), "PASS"
	}
	if retain {
		retained = conn
	}
	return facts, retained, nil
}

func retirePeerStream(ctx context.Context, conn net.Conn, trace *peerTrace) (map[string]any, error) {
	defer conn.Close()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(peerDeadline(ctx, 2*time.Second)); err != nil {
		return nil, err
	}
	err := peerSend(conn, nonce, trace, "healthy.retired_stream.send")
	if err == nil {
		fact := trace.event("healthy.retired_stream.receive", map[string]any{"status": "RUNNING"})
		var buffer [32]byte
		n, readErr := conn.Read(buffer[:])
		if n != 0 {
			fact["status"] = "UNEXPECTED_PAYLOAD"
			return nil, fmt.Errorf("retired stream returned a new payload")
		}
		err = readErr
		if errors.Is(err, io.EOF) {
			fact["status"] = "CLOSED"
		}
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		trace.event("healthy.retired_stream.closed_reset", nil)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("retired stream close is unknown")
	}
	return map[string]any{"nonceSHA256": sha256Hex(nonce), "transportClosed": true}, nil
}

func peerReleased(port int, udp bool) (map[string]any, error) {
	protocol := "tcp"
	var socket io.Closer
	var err error
	if udp {
		protocol = "udp"
		socket, err = net.ListenPacket("udp4", peerAddress(port))
	} else {
		socket, err = net.Listen("tcp4", peerAddress(port))
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"port": port, "protocol": protocol, "released": true}, socket.Close()
}

var peerAssignedAddress = regexp.MustCompile(`assigned 198\.18\.0\.[0-9]+/`)

func peerWaitObserved(ctx context.Context, owner *peerNativeProcess, trace *peerTrace, kind string, observe func() (bool, error)) error {
	fact := trace.event(owner.role+".readiness."+kind, map[string]any{"status": "RUNNING"})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticks := time.NewTicker(50 * time.Millisecond)
	defer ticks.Stop()
	for {
		if owner.exited() != nil {
			return fmt.Errorf("core exited during readiness")
		}
		found, err := observe()
		if err != nil {
			return err
		}
		if found {
			fact["status"] = "PASS"
			return nil
		}
		select {
		case <-ticks.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func peerReadUDPReady(ctx context.Context, owner *peerNativeProcess, port int, trace *peerTrace) error {
	return peerWaitObserved(ctx, owner, trace, "udp", func() (bool, error) {
		inodes, _, err := peerOwnedSocketInodes(owner.identity.PID)
		if err != nil {
			return false, err
		}
		rows, _, err := peerUDPPortRows(owner.identity.PID, port, "udp")
		if err != nil {
			return false, err
		}
		local := fmt.Sprintf("0100007F:%04X", port)
		for _, row := range rows {
			if row.local == local && inodes[row.inode] {
				return true, nil
			}
		}
		return false, nil
	})
}

func peerReadAssignment(ctx context.Context, owner *peerNativeProcess, trace *peerTrace) error {
	return peerWaitObserved(ctx, owner, trace, "assigned", func() (bool, error) {
		raw, err := readPeerLog(owner.log.Name())
		return peerAssignedAddress.Match(raw), err
	})
}

type peerUDPAssociation struct {
	control net.Conn
	socket  *net.UDPConn
	relay   *net.UDPAddr
}

func (session peerUDPAssociation) close() {
	session.socket.Close()
	session.control.Close()
}

func peerSOCKSUDP(ctx context.Context, mixed int, trace *peerTrace, label string) (session peerUDPAssociation, err error) {
	label += ".udp_associate"
	trace.event(label+".tcp_connect", nil)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	control, err := dialer.DialContext(ctx, "tcp4", peerAddress(mixed))
	if err != nil {
		return session, err
	}
	session.control = control
	defer func() {
		if err != nil {
			control.Close()
			if session.socket != nil {
				session.socket.Close()
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	if err := control.SetDeadline(peerDeadline(ctx, 8*time.Second)); err != nil {
		return session, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return session, err
	}
	session.socket = udp
	if err := peerSOCKSAuth(control, trace, label); err != nil {
		return session, err
	}
	request := socks5.Request{Command: socks5.CommandUDPAssociate,
		Destination: M.Socksaddr{Addr: netip.MustParseAddr(peerLoopback), Port: uint16(udp.LocalAddr().(*net.UDPAddr).Port)}}
	if err := peerSOCKSRequest(control, request, trace, label+".request.send"); err != nil {
		return session, err
	}
	reply, err := peerRead(control, 4, trace, label+".response")
	if err != nil {
		return session, err
	}
	trace.event(label+".status", map[string]any{"version": reply[0], "replyCode": reply[1], "addressType": reply[3]})
	if !bytes.Equal(reply, []byte{5, 0, 0, 1}) {
		return session, fmt.Errorf("SOCKS UDP association is not loopback IPv4")
	}
	address, err := peerRead(control, 4, trace, label+".address")
	if err != nil {
		return session, err
	}
	port, err := peerRead(control, 2, trace, label+".port")
	if err != nil {
		return session, err
	}
	relayPort := binary.BigEndian.Uint16(port)
	if relayPort == 0 || !(bytes.Equal(address, peerLoopbackIP[:]) || bytes.Equal(address, []byte{0, 0, 0, 0})) {
		return session, fmt.Errorf("SOCKS UDP relay escaped loopback")
	}
	session.relay = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)}
	return session, nil
}

func peerUDPHeader(target string, port int) []byte {
	address := netip.MustParseAddr(target).As4()
	packet := append([]byte{0, 0, 0, 1}, address[:]...)
	return binary.BigEndian.AppendUint16(packet, uint16(port))
}

func peerUDPExchange(ctx context.Context, mixed, port int, target string, trace *peerTrace, label string) ([]map[string]any, error) {
	facts := []map[string]any{}
	session, err := peerSOCKSUDP(ctx, mixed, trace, label)
	if err != nil {
		return facts, err
	}
	defer session.close()
	stop := context.AfterFunc(ctx, func() { session.socket.Close() })
	defer stop()
	header := peerUDPHeader(target, port)
	response := make([]byte, 65535)
	for _, size := range []int{1, 64, 1200} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			return facts, err
		}
		fact := map[string]any{"bytes": size, "sentSHA256": sha256Hex(payload), "status": "RUNNING"}
		facts = append(facts, fact)
		if err := session.socket.SetDeadline(peerDeadline(ctx, 8*time.Second)); err != nil {
			return facts, err
		}
		packet := append(header, payload...)
		written, err := session.socket.WriteToUDP(packet, session.relay)
		trace.event(label+".udp.payload.send", map[string]any{"requestedBytes": len(packet), "completedBytes": written})
		if err != nil || written != len(packet) {
			return facts, errors.Join(err, io.ErrShortWrite)
		}
		received := trace.event(label+".udp.payload.receive", map[string]any{"status": "RUNNING"})
		n, from, err := session.socket.ReadFromUDP(response)
		if err != nil {
			received["status"], received["errorType"] = "FAIL", peerErrorName(err)
			return facts, err
		}
		received["status"], received["completedBytes"], received["sha256"] = "RECEIVED", n, sha256Hex(response[:n])
		if from.Port != session.relay.Port || !from.IP.Equal(session.relay.IP) || !bytes.Equal(response[:n], packet) {
			return facts, fmt.Errorf("UDP address, boundary or payload differs")
		}
		fact["receivedSHA256"], fact["datagramBoundary"], fact["status"] = sha256Hex(response[len(header):n]), true, "PASS"
		received["status"] = "PASS"
	}
	return facts, nil
}

func peerNegativeUDP(ctx context.Context, mixed, port int, target string, trace *peerTrace) (string, error) {
	session, err := peerSOCKSUDP(ctx, mixed, trace, "negative")
	if err != nil {
		return "", err
	}
	defer session.close()
	stop := context.AfterFunc(ctx, func() { session.socket.Close() })
	defer stop()
	nonce := make([]byte, 48)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	if err := session.socket.SetDeadline(peerDeadline(ctx, 2*time.Second)); err != nil {
		return "", err
	}
	packet := append(peerUDPHeader(target, port), nonce...)
	written, err := session.socket.WriteToUDP(packet, session.relay)
	trace.event("negative.udp.payload.send", map[string]any{"requestedBytes": len(packet), "completedBytes": written})
	if err != nil || written != len(packet) {
		return "", errors.Join(err, io.ErrShortWrite)
	}
	var buf [65535]byte
	_, _, err = session.socket.ReadFromUDP(buf[:])
	var timeout net.Error
	if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
		return "", fmt.Errorf("negative MASQUE UDP no-payload timeout not observed")
	}
	trace.event("negative.udp.no_payload_timeout", nil)
	return sha256Hex(nonce), nil
}
