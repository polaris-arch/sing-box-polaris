package ping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

type UnprivilegedConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	controlFunc   control.Func
	destination   netip.Addr
	idleTimeout   time.Duration
	receiveChan   chan *unprivilegedResponse
	readDeadline  pipe.Deadline
	mappingAccess sync.Mutex
	mapping       map[uint16]*unprivilegedSocket
	owned         map[*unprivilegedSocket]struct{}
	closed        bool
	closeOnce     sync.Once
	closeDone     chan struct{}
	closeErr      error
	connectSocket func(bool, control.Func, netip.Addr) (net.Conn, error)
}

type responseConn interface {
	net.Conn
	ReadMsgUDPAddrPort([]byte, []byte) (int, int, int, netip.AddrPort, error)
}

type unprivilegedSocket struct {
	identifier uint16
	ready      chan struct{}
	done       chan struct{}
	conn       net.Conn // published by ready
	reader     responseConn
	creationErr error
	retiring   bool // protected by UnprivilegedConn.mappingAccess
	writers    sync.WaitGroup // admission under mappingAccess, join after retiring
	closeOnce  sync.Once
	closeErr   error
	result     error // published by done
}

func (s *unprivilegedSocket) close() error {
	s.closeOnce.Do(func() {
		if s.conn != nil {
			s.closeErr = runCleanup("unprivileged socket close", s.conn.Close)
		}
	})
	return s.closeErr
}

type unprivilegedResponse struct {
	Buffer *buf.Buffer
	Cmsg   *buf.Buffer
	Addr   netip.Addr
}

func newUnprivilegedConn(ctx context.Context, controlFunc control.Func, destination netip.Addr, idleTimeout time.Duration) (net.Conn, error) {
	conn, err := connect(false, controlFunc, destination)
	if err != nil {
		return nil, err
	}
	if err := runCleanup("probe socket close", conn.Close); err != nil {
		return nil, &cleanupFailure{message: err.Error(), resource: conn}
	}
	ctx, cancel := context.WithCancel(ctx)
	return &UnprivilegedConn{
		ctx:          ctx,
		cancel:       cancel,
		controlFunc:  controlFunc,
		destination:  destination,
		idleTimeout:  idleTimeout,
		receiveChan:  make(chan *unprivilegedResponse),
		readDeadline: pipe.MakeDeadline(),
		mapping:      make(map[uint16]*unprivilegedSocket),
		owned:        make(map[*unprivilegedSocket]struct{}),
		closeDone:    make(chan struct{}),
		connectSocket: connect,
	}, nil
}

func (c *UnprivilegedConn) Read(b []byte) (n int, err error) {
	select {
	case packet := <-c.receiveChan:
		n = copy(b, packet.Buffer.Bytes())
		packet.Buffer.Release()
		packet.Cmsg.Release()
		return
	case <-c.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, os.ErrClosed
	}
}

func (c *UnprivilegedConn) ReadMsg(b []byte, oob []byte) (n, oobn int, addr netip.Addr, err error) {
	select {
	case packet := <-c.receiveChan:
		n = copy(b, packet.Buffer.Bytes())
		oobn = copy(oob, packet.Cmsg.Bytes())
		addr = packet.Addr
		packet.Buffer.Release()
		packet.Cmsg.Release()
		return
	case <-c.readDeadline.Wait():
		return 0, 0, netip.Addr{}, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, 0, netip.Addr{}, os.ErrClosed
	}
}

func (c *UnprivilegedConn) Write(b []byte) (n int, err error) {
	var identifier uint16
	if !c.destination.Is6() {
		identifier = header.ICMPv4(b).Ident()
	} else {
		identifier = header.ICMPv6(b).Ident()
	}

	c.mappingAccess.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mappingAccess.Unlock()
		return 0, os.ErrClosed
	}
	entry, loaded := c.mapping[identifier]
	if !loaded || entry.retiring {
		loaded = false
		entry = &unprivilegedSocket{identifier: identifier, ready: make(chan struct{}), done: make(chan struct{})}
		c.mapping[identifier] = entry
		c.owned[entry] = struct{}{}
	}
	entry.writers.Add(1)
	c.mappingAccess.Unlock()
	defer entry.writers.Done()
	if !loaded {
		// The reservation includes construction, the real fetch loop and writes.
		go c.runSocket(entry)
		c.createSocket(entry)
	}
	<-entry.ready
	if entry.creationErr != nil {
		return 0, entry.creationErr
	}
	c.mappingAccess.Lock()
	admitted := !c.closed && !entry.retiring
	c.mappingAccess.Unlock()
	if !admitted {
		return 0, os.ErrClosed
	}
	n, err = entry.conn.Write(b)
	if err != nil {
		c.removeConn(entry)
	}
	return
}

func (c *UnprivilegedConn) createSocket(entry *unprivilegedSocket) {
	defer close(entry.ready)
	defer func() {
		if value := recover(); value != nil {
			entry.creationErr = &cleanupFailure{message: fmt.Sprintf("ping socket creation panic: %v", value)}
		}
	}()
	entry.conn, entry.creationErr = c.connectSocket(false, c.controlFunc, c.destination)
	if entry.creationErr != nil {
		return
	}
	var loaded bool
	entry.reader, loaded = entry.conn.(responseConn)
	if !loaded {
		entry.creationErr = errors.New("unsupported unprivileged ICMP socket")
	}
}

func (c *UnprivilegedConn) runSocket(entry *unprivilegedSocket) {
	defer func() {
		if value := recover(); value != nil {
			entry.result = &cleanupFailure{message: fmt.Sprintf("ping fetch worker panic: %v", value)}
		}
		c.removeConn(entry)
		// Retiring was set before this join, so no new writers can be added.
		entry.writers.Wait()
		entry.result = E.Errors(entry.result, entry.closeErr)
		var uncertainty *cleanupFailure
		if errors.As(entry.creationErr, &uncertainty) {
			entry.result = E.Errors(entry.result, entry.creationErr)
		}
		entry.result = cleanupError("fetch cleanup", entry.result)
		c.mappingAccess.Lock()
		if c.mapping[entry.identifier] == entry {
			delete(c.mapping, entry.identifier)
		}
		close(entry.done)
		if entry.result == nil {
			delete(c.owned, entry)
		}
		c.mappingAccess.Unlock()
	}()
	<-entry.ready
	if entry.creationErr == nil {
		c.fetchResponse(entry.reader, entry.identifier)
	}
}

func (c *UnprivilegedConn) fetchResponse(conn responseConn, identifier uint16) {
	for {
		if c.idleTimeout > 0 {
			err := conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
			if err != nil {
				return
			}
		}
		buffer := buf.NewSize(maxICMPPacketSize)
		cmsgBuffer := buf.NewSize(1024)
		n, oobN, _, addr, err := conn.ReadMsgUDPAddrPort(buffer.FreeBytes(), cmsgBuffer.FreeBytes())
		if err != nil {
			buffer.Release()
			cmsgBuffer.Release()
			return
		}
		buffer.Truncate(n)
		cmsgBuffer.Truncate(oobN)
		if !c.destination.Is6() {
			icmpHdr := header.ICMPv4(buffer.Bytes())
			icmpHdr.SetIdent(identifier)
			icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
		} else {
			icmpHdr := header.ICMPv6(buffer.Bytes())
			icmpHdr.SetIdent(identifier)
			// offload checksum here since we don't have source address here
		}
		select {
		case c.receiveChan <- &unprivilegedResponse{
			Buffer: buffer,
			Cmsg:   cmsgBuffer,
			Addr:   addr.Addr(),
		}:
		case <-c.ctx.Done():
			buffer.Release()
			cmsgBuffer.Release()
			return
		}
	}
}

func (c *UnprivilegedConn) removeConn(entry *unprivilegedSocket) {
	c.mappingAccess.Lock()
	entry.retiring = true
	c.mappingAccess.Unlock()
	// No mapping lock is held across close callbacks. Keep the ownership
	// record until the fetch loop and every admitted writer actually finish.
	_ = entry.close()
}

// Close signals shutdown. Joining is separate so Destination.loopRead can
// close its own socket without waiting on its own callback stack.
func (c *UnprivilegedConn) Close() error {
	c.closeOnce.Do(func() {
		defer close(c.closeDone)
		c.mappingAccess.Lock()
		c.closed = true
		entries := make([]*unprivilegedSocket, 0, len(c.owned))
		for entry := range c.owned {
			entry.retiring = true
			entries = append(entries, entry)
		}
		c.mappingAccess.Unlock()
		c.cancel()
		var errs []error
		for _, entry := range entries {
			<-entry.ready
			errs = append(errs, entry.close())
		}
		c.closeErr = E.Errors(errs...)
	})
	return c.closeErr
}

func (c *UnprivilegedConn) Wait(ctx context.Context) error {
	if err := waitCompletion(ctx, c.closeDone); err != nil {
		return err
	}
	c.mappingAccess.Lock()
	entries := make([]*unprivilegedSocket, 0, len(c.owned))
	for entry := range c.owned {
		entries = append(entries, entry)
	}
	c.mappingAccess.Unlock()
	errs := []error{c.closeErr}
	for _, entry := range entries {
		if err := waitCompletion(ctx, entry.done); err != nil {
			return err
		}
		errs = append(errs, entry.result)
	}
	return E.Errors(errs...)
}

func (c *UnprivilegedConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *UnprivilegedConn) RemoteAddr() net.Addr {
	return M.SocksaddrFrom(c.destination, 0).UDPAddr()
}

func (c *UnprivilegedConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *UnprivilegedConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *UnprivilegedConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
