//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// net.Conn allows one reader and one writer concurrently. Exercise detection
// before direct mode, where both directions inspect the first eight packets.
func TestVisionConcurrentPlainTraffic(t *testing.T) {
	certificate, roots := visionTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		provider := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		if err = provider.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		vision, err := NewVisionConn(provider, provider, [16]byte{1}, logger.NOP())
		if err == nil {
			err = visionConcurrentExchange(vision, 7, 9)
		}
		serverDone <- err
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	provider := visionProviderFactories()["refraction-UConn"](conn, roots)
	if err = provider.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	vision, err := NewVisionConn(provider, provider, [16]byte{1}, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	if err = visionConcurrentExchange(vision, 9, 7); err != nil {
		t.Error(err)
	}
	select {
	case err = <-serverDone:
		if err != nil {
			t.Error(err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent Vision server not joined")
	}
}

func visionConcurrentExchange(conn *VisionConn, send, receive byte) error {
	const count = 64
	writeDone := make(chan error, 1)
	var start sync.WaitGroup
	start.Add(1)
	go func() {
		start.Wait()
		for i := 0; i < count; i++ {
			if _, err := conn.Write(bytes.Repeat([]byte{send}, 1024)); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	start.Done()
	actual := make([]byte, count*1024)
	_, readErr := io.ReadFull(conn, actual)
	writeErr := <-writeDone
	if readErr != nil || writeErr != nil {
		return errors.Join(readErr, writeErr)
	}
	if !bytes.Equal(actual, bytes.Repeat([]byte{receive}, len(actual))) {
		return errors.New("concurrent payload changed")
	}
	if conn.directRead || conn.directWrite {
		return errors.New("plain payload incorrectly entered direct mode")
	}
	return nil
}
