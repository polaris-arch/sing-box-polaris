//go:build with_utls

package vless

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	coretls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	vmess "github.com/sagernet/sing-vmess"
	vless "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type visionActualRouter struct {
	adapter.ConnectionRouterEx
	destination M.Socksaddr
	packets     [][]byte
	done        chan error
}

func (r *visionActualRouter) RouteConnectionEx(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	var err error
	defer func() { r.done <- err }()
	if metadata.Destination != r.destination {
		err = errors.New("TCP destination changed")
		return
	}
	for _, expected := range r.packets {
		actual := make([]byte, len(expected))
		if _, err = io.ReadFull(conn, actual); err != nil {
			return
		}
		if !bytes.Equal(actual, expected) {
			err = errors.New("TCP payload changed")
			return
		}
		if _, err = conn.Write(actual); err != nil {
			return
		}
	}
}

func (r *visionActualRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	var err error
	defer func() { _ = conn.Close(); r.done <- err }()
	if metadata.Destination != r.destination {
		err = errors.New("XUDP destination changed")
		return
	}
	for _, expected := range r.packets {
		packet := buf.NewPacket()
		packet.Resize(512, 0) // preserve the mux writer's required front headroom
		var destination M.Socksaddr
		destination, err = conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return
		}
		if destination != r.destination || !bytes.Equal(packet.Bytes(), expected) {
			packet.Release()
			err = errors.New("XUDP payload or datagram boundary changed")
			return
		}
		if err = conn.WritePacket(packet, destination); err != nil {
			return
		}
	}
}

func TestRuntimeVisionActualTCPAndXUDP(t *testing.T) {
	for _, profile := range []string{"", "chrome_155"} {
		for _, packet := range []bool{false, true} {
			t.Run(fmt.Sprintf("profile-%s/xudp-%v", profile, packet), func(t *testing.T) { runtimeVisionActualExchange(t, profile, packet, "") })
		}
	}
}

func TestRuntimeVisionActualRejectsUnsupportedUDPAndFlow(t *testing.T) {
	for _, negative := range []string{"direct-udp", "wrong-flow"} {
		t.Run(negative, func(t *testing.T) { runtimeVisionActualExchange(t, "chrome_155", false, negative) })
	}
}

func runtimeVisionActualExchange(t *testing.T, profile string, packet bool, negative string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyPEM, certPEM, err := coretls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := M.ParseSocksaddr("127.0.0.1:5353")
	packets := [][]byte{{0x17}, bytes.Repeat([]byte("datagram"), 16), bytes.Repeat([]byte("different-length"), 257)}
	router := &visionActualRouter{destination: destination, packets: packets, done: make(chan error, 1)}
	logger := log.NewNOPFactory().Logger()
	user := uuid.FromStringOrNil("00000000-0000-0000-0000-000000000123")
	inbound := &Inbound{logger: logger, router: router, users: []option.VLESSUser{{UUID: user.String(), Flow: vless.FlowVision}}}
	serverDone := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		secured := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{certificate}, MinVersion: stdtls.VersionTLS13})
		if err = secured.HandshakeContext(ctx); err == nil {
			err = inbound.newRuntimeConnection(adapter.WithContext(ctx, &adapter.InboundContext{}), secured, M.Socksaddr{}, nil)
		}
		serverDone <- err
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	options := option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{string(certPEM)}}
	if profile != "" {
		options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: profile}
	}
	config, err := coretls.NewClient(ctx, logger, "localhost", options)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := coretls.ClientHandshake(ctx, raw, config)
	if err != nil {
		t.Fatal(err)
	}
	defer secured.Close()
	dialer := &vlessDialer{flow: vless.FlowVision, visionUUID: user, logger: logger}
	if negative != "" {
		request := vless.Request{UUID: user, Command: vmess.CommandTCP, Destination: destination, Flow: vless.FlowVision}
		if negative == "direct-udp" {
			request.Command = vmess.CommandUDP
		} else {
			request.Flow = ""
		}
		if err = vless.WriteRequest(secured, request, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-serverDone:
			expected := "flow mismatch"
			if negative == "direct-udp" {
				expected = "flow does not support UDP"
			}
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("wrong negative outcome: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("negative VLESS server not joined")
		}
		select {
		case <-router.done:
			t.Fatal("negative VLESS request reached data handler")
		default:
		}
		return
	}
	if packet {
		var conn vmess.PacketConn
		conn, err = dialer.dialEarlyRuntimeXUDP(secured, destination)
		if err == nil {
			for _, expected := range packets {
				if _, err = conn.WriteTo(expected, destination); err != nil {
					break
				}
				actual := make([]byte, 65535)
				var n int
				var addr net.Addr
				n, addr, err = conn.ReadFrom(actual)
				if err != nil {
					break
				}
				if M.SocksaddrFromNet(addr) != destination || !bytes.Equal(actual[:n], expected) {
					err = errors.New("XUDP roundtrip changed")
					break
				}
			}
			if err == nil {
				// Consume the peer's actual mux StatusEnd before TLS retirement;
				// otherwise an unread close frame can turn raw close into TCP RST.
				if n, _, terminalErr := conn.ReadFrom(make([]byte, 65535)); n != 0 || !errors.Is(terminalErr, io.EOF) {
					err = fmt.Errorf("XUDP peer did not end its stream cleanly: bytes=%d error=%v", n, terminalErr)
				}
			}
		}
	} else {
		var conn net.Conn
		conn, err = dialer.dialEarlyRuntimeConn(secured, destination)
		if err == nil {
			for _, expected := range packets {
				if _, err = conn.Write(expected); err != nil {
					break
				}
				actual := make([]byte, len(expected))
				if _, err = io.ReadFull(conn, actual); err != nil {
					break
				}
				if !bytes.Equal(actual, expected) {
					err = errors.New("TCP roundtrip changed")
					break
				}
			}
		}
	}
	// Retire the TLS peer cleanly. Closing the raw socket with unread mux close
	// records may produce an OS-dependent TCP reset instead of the intended EOF.
	closeErr := secured.Close()
	if closeErr != nil {
		t.Errorf("actual VLESS client retirement: %v", closeErr)
	}
	if err != nil {
		t.Errorf("actual VLESS client: %v", err)
	}
	select {
	case handlerErr := <-router.done:
		if handlerErr != nil {
			t.Errorf("actual VLESS handler: %v", handlerErr)
		}
	case <-ctx.Done():
		t.Fatal("VLESS handler not joined")
	}
	select {
	case serverErr := <-serverDone:
		if packet && !errors.Is(serverErr, io.EOF) {
			t.Errorf("XUDP server must finish at the peer's deliberate EOF, not a protocol failure: %v", serverErr)
		} else if !packet && serverErr != nil {
			t.Errorf("actual VLESS server: %v", serverErr)
		}
	case <-ctx.Done():
		t.Fatal("VLESS server not joined")
	}
}
