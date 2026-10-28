package ping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const defaultFlowTimeout = time.Minute

type Port struct {
	ctx         context.Context
	cancel      context.CancelFunc
	logger      logger.ContextLogger
	controlFunc func(destination netip.Addr) control.Func
	timeout     time.Duration

	returnAccess sync.Mutex
	returnPaths  []tun.Return

	flowAccess sync.Mutex
	flows      map[flowKey]*portFlow
	// owned includes pending constructors and flows detached by earlier resets.
	// Removal requires actual worker completion and successful cleanup.
	owned              map[*portFlow]struct{}
	sealed             bool
	connectDestination func(context.Context, logger.ContextLogger, control.Func, netip.Addr, PacketWriter, time.Duration) (*Destination, error)
}

type portFlow struct {
	key           flowKey
	ready         chan struct{}
	stop          chan struct{}
	stopRequested bool // protected by Port.flowAccess
	closeDone     chan struct{}
	done          chan struct{}
	destination   *Destination // published by ready
	creationErr   error        // published by ready
	closeErr      error        // published by closeDone
	result        error        // published by done
}

type flowKey struct {
	source      netip.Addr
	destination netip.Addr
	identifier  uint16
}

func NewPort(ctx context.Context, logger logger.ContextLogger, controlFunc func(destination netip.Addr) control.Func, timeout time.Duration) *Port {
	if timeout <= 0 {
		timeout = defaultFlowTimeout
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Port{
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
		controlFunc: controlFunc,
		timeout:     timeout,
		flows:       make(map[flowKey]*portFlow),
		owned:       make(map[*portFlow]struct{}),
		connectDestination: ConnectDestination,
	}
}

func (p *Port) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.IPv4Unspecified(), netip.IPv6Unspecified()
}

func (p *Port) PortMTU() uint32 {
	return 0
}

func (p *Port) AttachReturn(returnPath tun.Return) error {
	p.flowAccess.Lock()
	defer p.flowAccess.Unlock()
	if p.sealed {
		return os.ErrClosed
	}
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	if slices.Contains(p.returnPaths, returnPath) {
		return nil
	}
	p.returnPaths = append(slices.Clip(p.returnPaths), returnPath)
	return nil
}

func (p *Port) DetachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	returnPaths := make([]tun.Return, 0, len(p.returnPaths))
	for _, existing := range p.returnPaths {
		if existing != returnPath {
			returnPaths = append(returnPaths, existing)
		}
	}
	p.returnPaths = returnPaths
	return nil
}

func (p *Port) WritePackets(packets [][]byte) error {
	var errs []error
	for _, packet := range packets {
		err := p.writePacket(packet)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (p *Port) writePacket(packet []byte) error {
	var (
		source      netip.Addr
		destination netip.Addr
		identifier  uint16
	)
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber || ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
			return nil
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return nil
		}
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
		identifier = icmpHdr.Ident()
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber || ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
			return nil
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
			return nil
		}
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
		identifier = icmpHdr.Ident()
	default:
		return nil
	}
	flow, err := p.flowFor(source, destination, identifier)
	if err != nil {
		return E.Cause(err, "connect ICMP flow to ", destination)
	}
	return flow.WritePacket(buf.As(packet))
}

func (p *Port) flowFor(source netip.Addr, destination netip.Addr, identifier uint16) (*Destination, error) {
	key := flowKey{source: source, destination: destination, identifier: identifier}
	p.flowAccess.Lock()
	if p.sealed || p.ctx.Err() != nil {
		p.flowAccess.Unlock()
		return nil, os.ErrClosed
	}
	entry, loaded := p.flows[key]
	if loaded {
		select {
		case <-entry.ready:
			if entry.destination == nil || entry.destination.IsClosed() {
				loaded = false
			}
		default:
		}
	}
	if !loaded {
		entry = &portFlow{
			key: key,
			ready: make(chan struct{}),
			stop: make(chan struct{}),
			closeDone: make(chan struct{}),
			done: make(chan struct{}),
		}
		p.flows[key] = entry
		p.owned[entry] = struct{}{}
	}
	p.flowAccess.Unlock()
	if !loaded {
		// Reserve before any caller-supplied control callback or socket creation.
		// The completion worker is independent of the creator/read callback.
		go p.finishFlow(entry)
		p.createFlow(entry)
	}
	<-entry.ready
	if entry.creationErr != nil {
		return nil, entry.creationErr
	}
	p.flowAccess.Lock()
	admitted := !p.sealed && p.flows[key] == entry && !entry.stopRequested && !entry.destination.IsClosed()
	p.flowAccess.Unlock()
	if !admitted {
		return nil, os.ErrClosed
	}
	return entry.destination, nil
}

func (p *Port) createFlow(entry *portFlow) {
	defer close(entry.ready)
	defer func() {
		if value := recover(); value != nil {
			entry.creationErr = &cleanupFailure{message: fmt.Sprintf("ping flow creation panic: %v", value)}
		}
	}()
	var controlFunc control.Func
	if p.controlFunc != nil {
		controlFunc = p.controlFunc(entry.key.destination)
	}
	entry.destination, entry.creationErr = p.connectDestination(p.ctx, p.logger, controlFunc, entry.key.destination, portWriter{p}, p.timeout)
	if entry.destination == nil && entry.creationErr == nil {
		entry.creationErr = &cleanupFailure{message: "ping constructor returned no destination"}
	}
}

func (p *Port) finishFlow(entry *portFlow) {
	closePublished := false
	defer func() {
		if value := recover(); value != nil {
			entry.result = &cleanupFailure{message: fmt.Sprintf("ping flow cleanup panic: %v", value)}
		}
		entry.result = cleanupError("flow cleanup", entry.result)
		if !closePublished {
			entry.closeErr = entry.result
			close(entry.closeDone)
		}
		p.flowAccess.Lock()
		if p.flows[entry.key] == entry {
			delete(p.flows, entry.key)
		}
		// Publish completion before releasing the ownership record. A failed
		// close remains quarantined, even after the worker eventually returns.
		close(entry.done)
		if entry.result == nil {
			delete(p.owned, entry)
		}
		p.flowAccess.Unlock()
	}()
	<-entry.ready
	var uncertainty *cleanupFailure
	if errors.As(entry.creationErr, &uncertainty) {
		entry.result = entry.creationErr
	}
	if entry.destination == nil {
		return
	}
	if entry.creationErr == nil {
		select {
		case <-entry.stop:
		case <-entry.destination.readDone:
		}
	}
	entry.closeErr = entry.destination.Close()
	close(entry.closeDone)
	closePublished = true
	// Neither a close error nor canceling an observer proves these workers
	// ended. This wait is deliberately independent of the port's context.
	entry.result = E.Errors(entry.result, entry.closeErr, cleanupError("destination join", entry.destination.Wait(context.Background())))
}

func (p *Port) stopFlows(terminal bool) []*portFlow {
	p.flowAccess.Lock()
	if terminal {
		p.sealed = true
	}
	entries := make([]*portFlow, 0, len(p.owned))
	for entry := range p.owned {
		entries = append(entries, entry)
		if !entry.stopRequested {
			entry.stopRequested = true
			close(entry.stop)
		}
	}
	// Detach only routing identities. The ownership records are kept until
	// the separate completion worker proves cleanup and actual worker exit.
	p.flows = make(map[flowKey]*portFlow)
	p.flowAccess.Unlock()
	if terminal {
		p.cancel()
	}
	return entries
}

type portWriter struct {
	port *Port
}

func (w portWriter) WritePacket(packet []byte) error {
	w.port.returnAccess.Lock()
	returnPaths := w.port.returnPaths
	w.port.returnAccess.Unlock()
	for _, returnPath := range returnPaths {
		headroom := returnPath.ReturnHeadroom()
		buffer := make([]byte, headroom+len(packet))
		copy(buffer[headroom:], packet)
		unconsumed := returnPath.ReturnPackets([][]byte{buffer})
		if len(unconsumed) == 0 {
			return nil
		}
	}
	return nil
}

// Close resets current ICMP flows after a network change. It intentionally
// leaves admission open and does not join return callbacks on the caller stack.
func (p *Port) Close() error {
	entries := p.stopFlows(false)
	var errs []error
	for _, entry := range entries {
		<-entry.closeDone
		errs = append(errs, entry.closeErr)
	}
	return E.Errors(errs...)
}

// CloseAndWait is terminal ownership cleanup. It must be called by the owning
// resource's close worker, never synchronously from one of its return callbacks.
func (p *Port) CloseAndWait() error {
	p.stopFlows(true)
	return p.Wait(context.Background())
}

// Wait observes terminal cleanup, including pending constructors and workers
// detached by earlier resets. Cancellation never forgets ownership or signals
// completion. Calling Wait before terminal shutdown is an error.
func (p *Port) Wait(ctx context.Context) error {
	p.flowAccess.Lock()
	if !p.sealed {
		p.flowAccess.Unlock()
		return errors.New("ping port has not begun terminal shutdown")
	}
	entries := make([]*portFlow, 0, len(p.owned))
	for entry := range p.owned {
		entries = append(entries, entry)
	}
	p.flowAccess.Unlock()
	var errs []error
	for _, entry := range entries {
		if err := waitCompletion(ctx, entry.done); err != nil {
			return err
		}
		errs = append(errs, entry.result)
	}
	return E.Errors(errs...)
}
