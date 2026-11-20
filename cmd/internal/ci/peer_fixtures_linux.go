package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const peerLoopback = "127.0.0.1"

type peerFileFact struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func writePeerPrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Close())
}

type peerCertificate struct{ ca, leaf, key string }

func createPeerCertificate(ctx context.Context, openssl, directory, name string) (peerCertificate, error) {
	base := filepath.Join(directory, name)
	caKey, ca, key, csr, leaf := base+"-ca.key", base+"-ca.pem", base+".key", base+".csr", base+".pem"
	ext := base + ".ext"
	const extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:controlled.invalid,IP:127.0.0.1\n"
	if err := writePeerPrivate(ext, []byte(extensions)); err != nil {
		return peerCertificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return peerCertificate{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	for _, args := range [][]string{
		{
			openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
			"-subj", "/CN=Controlled Peer Temporary CA", "-addext", "basicConstraints=critical,CA:TRUE",
			"-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", caKey, "-out", ca,
		},
		{
			openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
			"-subj", "/CN=controlled.invalid", "-keyout", key, "-out", csr,
		},
		{
			openssl, "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey,
			"-set_serial", serial.String(), "-days", "1", "-sha256", "-extfile", ext, "-out", leaf,
		},
	} {
		step, cancel := context.WithTimeout(ctx, 25*time.Second)
		_, code, err := sourceCombinedOutput(step, directory, peerCoreEnvironment(directory, ""), 1<<20, args...)
		cancel()
		if err != nil || code == nil || *code != 0 {
			return peerCertificate{}, fmt.Errorf("temporary test certificate generation failed")
		}
	}
	for _, path := range []string{caKey, ca, key, csr, leaf} {
		if err := os.Chmod(path, 0o600); err != nil {
			return peerCertificate{}, err
		}
	}
	var result peerCertificate
	for path, target := range map[string]*string{ca: &result.ca, leaf: &result.leaf, key: &result.key} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return peerCertificate{}, err
		}
		*target = string(raw)
	}
	return result, nil
}

type peerEcho struct {
	tcp net.Listener
	udp *net.UDPConn

	accepted, tcpBytes, udpBytes atomic.Uint64
	mu                           sync.Mutex
	connections                  map[net.Conn]struct{}
	closing                      bool
	failure                      error
	workers                      sync.WaitGroup
}

type peerEchoCounters struct {
	TCPAccepted uint64 `json:"tcpAccepted"`
	TCPBytes    uint64 `json:"tcpReceivedBytes"`
	UDPBytes    uint64 `json:"udpReceivedBytes"`
}

func startPeerEcho() (*peerEcho, error) {
	tcp, err := net.Listen("tcp4", peerLoopback+":0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, errors.Join(err, tcp.Close())
	}
	fixture := &peerEcho{tcp: tcp, udp: udp, connections: make(map[net.Conn]struct{})}
	fixture.workers.Add(2)
	go fixture.accept()
	go fixture.receiveUDP()
	return fixture, nil
}

func (echo *peerEcho) ports() (int, int) {
	return echo.tcp.Addr().(*net.TCPAddr).Port, echo.udp.LocalAddr().(*net.UDPAddr).Port
}

func (echo *peerEcho) counters() peerEchoCounters {
	return peerEchoCounters{echo.accepted.Load(), echo.tcpBytes.Load(), echo.udpBytes.Load()}
}

func (echo *peerEcho) error() error {
	echo.mu.Lock()
	defer echo.mu.Unlock()
	return echo.failure
}

func (echo *peerEcho) failed(err error) {
	echo.mu.Lock()
	defer echo.mu.Unlock()
	if !echo.closing && echo.failure == nil {
		echo.failure = err
	}
}

func (echo *peerEcho) accept() {
	defer echo.workers.Done()
	for {
		conn, err := echo.tcp.Accept()
		if err != nil {
			echo.failed(err)
			return
		}
		if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.IPv4(127, 0, 0, 1)) {
			conn.Close()
			echo.failed(fmt.Errorf("non-loopback echo peer"))
			return
		}
		echo.mu.Lock()
		if echo.closing {
			echo.mu.Unlock()
			conn.Close()
			return
		}
		echo.connections[conn] = struct{}{}
		echo.accepted.Add(1)
		echo.workers.Add(1)
		echo.mu.Unlock()
		go echo.receiveTCP(conn)
	}
}

func (echo *peerEcho) receiveTCP(conn net.Conn) {
	defer echo.workers.Done()
	defer func() {
		conn.Close()
		echo.mu.Lock()
		delete(echo.connections, conn)
		echo.mu.Unlock()
	}()
	data := make([]byte, 65536)
	for {
		n, err := conn.Read(data)
		if n != 0 {
			echo.tcpBytes.Add(uint64(n))
			written, writeErr := conn.Write(data[:n])
			if writeErr == nil && written != n {
				writeErr = io.ErrShortWrite
			}
			if writeErr != nil {
				err = writeErr
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
				echo.failed(err)
			}
			return
		}
	}
}

func (echo *peerEcho) receiveUDP() {
	defer echo.workers.Done()
	data := make([]byte, 65535)
	for {
		n, address, err := echo.udp.ReadFromUDP(data)
		if err == nil {
			if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				err = fmt.Errorf("non-loopback echo peer")
			} else {
				echo.udpBytes.Add(uint64(n))
				written, writeErr := echo.udp.WriteToUDP(data[:n], address)
				err = writeErr
				if err == nil && written != n {
					err = io.ErrShortWrite
				}
			}
		}
		if err != nil {
			echo.failed(err)
			return
		}
	}
}

func (echo *peerEcho) close() error {
	echo.mu.Lock()
	echo.closing = true
	err := errors.Join(echo.tcp.Close(), echo.udp.Close())
	for conn := range echo.connections {
		if closeErr := conn.Close(); !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	echo.mu.Unlock()
	done := make(chan struct{})
	go func() {
		echo.workers.Wait()
		close(done)
	}()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return errors.Join(err, echo.error())
	case <-timer.C:
		return errors.Join(err, fmt.Errorf("echo worker did not join"))
	}
}

func peerFreeTCPPort() (int, error) {
	listener, err := net.Listen("tcp4", peerLoopback+":0")
	if err != nil {
		return 0, err
	}
	return listener.Addr().(*net.TCPAddr).Port, listener.Close()
}
