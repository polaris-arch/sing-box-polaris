package box

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

// Each admitted peer owns and joins its writer and cancellation callback.
// Closing the server never closes a client on behalf of the production owner.
type runtimeDNSWireServer struct {
	access    sync.Mutex
	sealed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	peers     []*runtimeDNSWirePeer
	workers   sync.WaitGroup
	errors    []error
	probes    map[string]chan struct{}
	completed map[string]bool
	wrapPeer  func(net.Conn) net.Conn
}

type runtimeDNSWireClient struct {
	net.Conn
	once      sync.Once
	requested chan struct{}
	closed    chan struct{}
	err       error
}

func (c *runtimeDNSWireClient) Close() error {
	c.once.Do(func() {
		close(c.requested)
		c.err = c.Conn.Close()
		close(c.closed)
	})
	return c.err
}

type runtimeDNSWirePeer struct {
	server   *runtimeDNSWireServer
	ctx      context.Context
	conn     net.Conn
	client   *runtimeDNSWireClient
	stopOnce sync.Once
	stopping chan struct{}
	done     chan struct{}
	writing  chan struct{}
	target   string
}

func newRuntimeDNSWireServer(t *testing.T, expectedError error) *runtimeDNSWireServer {
	t.Helper()
	// A successfully returned connection outlives its temporary dial context.
	// Only this fixture owner and the actual client close end a peer session.
	ctx, cancel := context.WithCancel(runtimeTestContext(t))
	s := &runtimeDNSWireServer{ctx: ctx, cancel: cancel, probes: make(map[string]chan struct{}), completed: make(map[string]bool)}
	t.Cleanup(func() {
		s.access.Lock()
		s.sealed = true
		peers := append([]*runtimeDNSWirePeer(nil), s.peers...)
		s.access.Unlock()
		for _, peer := range peers {
			select {
			case <-peer.client.closed:
			default:
				t.Error("production/test client owner did not finish native Close before server cleanup")
			}
		}
		s.requestStop()
		for _, peer := range peers {
			peer.stop()
		}
		joined := make(chan struct{})
		go func() { s.workers.Wait(); close(joined) }()
		runtimeTestWait(t, joined, "DNS server workers and callbacks")
		s.access.Lock()
		defer s.access.Unlock()
		if expectedError != nil {
			if len(s.errors) != 1 || !errors.Is(s.errors[0], expectedError) {
				t.Errorf("DNS fixture lost unexpected I/O error: %v, want %v", s.errors, expectedError)
			}
		} else {
			for _, err := range s.errors {
				t.Error(err)
			}
		}
	})
	return s
}

func (s *runtimeDNSWireServer) dial(ctx context.Context, target string) (net.Conn, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.sealed || s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	client, remote := net.Pipe()
	observed := &runtimeDNSWireClient{Conn: client, requested: make(chan struct{}), closed: make(chan struct{})}
	if s.wrapPeer != nil {
		remote = s.wrapPeer(remote)
	}
	peer := &runtimeDNSWirePeer{server: s, ctx: s.ctx, conn: remote, client: observed, stopping: make(chan struct{}), done: make(chan struct{}), writing: make(chan struct{}), target: target}
	s.peers = append(s.peers, peer)
	if s.probes[target] == nil {
		s.probes[target] = make(chan struct{})
	}
	// Reserve under the same gate that seals admission.
	s.workers.Go(peer.run)
	return observed, nil
}

func (s *runtimeDNSWireServer) requestStop() {
	s.access.Lock()
	s.sealed = true
	s.access.Unlock()
	s.cancel()
}

func (p *runtimeDNSWirePeer) stop() {
	p.stopOnce.Do(func() {
		close(p.stopping)
		if err := p.conn.Close(); err != nil {
			p.server.record(fmt.Errorf("DNS fixture peer Close: %w", err))
		}
	})
}

func (s *runtimeDNSWireServer) record(err error) {
	s.access.Lock()
	s.errors = append(s.errors, err)
	s.access.Unlock()
}

func (p *runtimeDNSWirePeer) reportIO(operation string, err error) {
	if err == nil || operation == "read" && errors.Is(err, io.EOF) {
		return
	}
	ownedStop := p.ctx.Err() != nil
	select {
	case <-p.client.requested:
		ownedStop = true
	default:
	}
	select {
	case <-p.stopping:
		ownedStop = true
	default:
	}
	// Classify at the failing operation, before its own cleanup requests stop.
	// Unknown errors remain failures even when cancellation is already known.
	if ownedStop && (errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)) {
		return
	}
	p.server.record(fmt.Errorf("DNS fixture %s: %w", operation, err))
}

func (p *runtimeDNSWirePeer) run() {
	defer close(p.done)
	callbackDone := make(chan struct{})
	stopCallback := context.AfterFunc(p.ctx, func() { defer close(callbackDone); p.stop() })
	responses := make(chan *mdns.Msg, 2)
	writerDone := make(chan struct{})
	written := 0
	go func() {
		defer close(writerDone)
		defer p.stop()
		wire := &mdns.Conn{Conn: p.conn}
		for response := range responses {
			if written == 0 {
				close(p.writing)
			}
			if err := wire.WriteMsg(response); err != nil {
				p.reportIO("write", err)
				return
			}
			written++
		}
	}()
	reader := &mdns.Conn{Conn: p.conn}
	var questions []uint16
read:
	for {
		query, err := reader.ReadMsg()
		if err != nil {
			p.reportIO("read", err)
			break
		}
		if len(query.Question) != 1 {
			p.server.record(errors.New("DNS fixture requires one question per message"))
			break
		}
		question := query.Question[0]
		questions = append(questions, question.Qtype)
		response := new(mdns.Msg)
		response.SetReply(query)
		header := mdns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: question.Qclass, Ttl: 60}
		switch question.Qtype {
		case mdns.TypeA:
			response.Answer = []mdns.RR{&mdns.A{Hdr: header, A: net.ParseIP(p.target)}}
		case mdns.TypeAAAA:
			response.Answer = []mdns.RR{&mdns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::53")}}
		}
		select {
		case responses <- response:
		case <-writerDone:
			break read
		}
	}
	p.stop()
	close(responses)
	// Stop also interrupts a writer left behind by a malformed/failed read.
	<-writerDone
	if !stopCallback() {
		<-callbackDone
	}
	if len(questions) == 2 && questions[0] == mdns.TypeA && questions[1] == mdns.TypeAAAA && written == 2 {
		p.server.access.Lock()
		if !p.server.completed[p.target] {
			p.server.completed[p.target] = true
			close(p.server.probes[p.target])
		}
		p.server.access.Unlock()
	}
}

func (s *runtimeDNSWireServer) waitProbe(t *testing.T, target string) {
	t.Helper()
	s.access.Lock()
	done := s.probes[target]
	s.access.Unlock()
	if done == nil {
		t.Fatal("no DNS connection for probe target", target)
	}
	runtimeTestWait(t, done, "two-question production DNS probe: "+target)
}

func TestRuntimeDNSWireFixturePipelinesAndReusesConnection(t *testing.T) {
	s := newRuntimeDNSWireServer(t, nil)
	dialCtx, cancelDial := context.WithCancel(runtimeTestContext(t))
	t.Cleanup(cancelDial)
	client, err := s.dial(dialCtx, "192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// ConnPool does exactly this after a successful shared-connection dial.
	// Both pipelined replies and a third request must still use this connection.
	cancelDial()
	queries := make([]*mdns.Msg, 3)
	for i, kind := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeA} {
		query := new(mdns.Msg)
		query.SetQuestion(fmt.Sprintf("query%d.fixture.", i), kind)
		query.Id = uint16(100 + i)
		queries[i] = query
	}
	written := make(chan struct{})
	var writeErr error
	t.Cleanup(func() { _ = client.Close(); runtimeTestWait(t, written, "DNS pipeline client writer") })
	go func() {
		defer close(written)
		writer := &mdns.Conn{Conn: client}
		for _, query := range queries[:2] {
			if writeErr = writer.WriteMsg(query); writeErr != nil {
				return
			}
		}
	}()
	runtimeTestWait(t, written, "two DNS questions before any response read")
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	reader := &mdns.Conn{Conn: client}
	for i := range 3 {
		if i == 2 {
			if err := (&mdns.Conn{Conn: client}).WriteMsg(queries[2]); err != nil {
				t.Fatal(err)
			}
		}
		response, err := reader.ReadMsg()
		if err != nil || response.Id != queries[i].Id || len(response.Question) != 1 || response.Question[0] != queries[i].Question[0] || len(response.Answer) != 1 {
			t.Fatal("pipeline/reused connection lost DNS response", response, err)
		}
	}
}

func TestRuntimeDNSWireFixtureCancellationJoinsReadAndWrite(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(blockedWrite), func(t *testing.T) {
			s := newRuntimeDNSWireServer(t, nil)
			client, err := s.dial(context.Background(), "192.0.2.53")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			peer := s.peers[0]
			if blockedWrite {
				query := new(mdns.Msg)
				query.SetQuestion("cancel.fixture.", mdns.TypeA)
				if err := (&mdns.Conn{Conn: client}).WriteMsg(query); err != nil {
					t.Fatal(err)
				}
				runtimeTestWait(t, peer.writing, "DNS writer admission")
			}
			s.requestStop()
			runtimeTestWait(t, peer.done, "DNS canceled reader/writer and callback")
			select {
			case <-peer.client.requested:
				t.Fatal("server canceled its client's ownership")
			default:
			}
		})
	}
}

func TestRuntimeDNSWireFixtureRejectsCanceledDialAndSealedOwner(t *testing.T) {
	s := newRuntimeDNSWireServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if client, err := s.dial(ctx, "192.0.2.53"); client != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled dial published a client", client, err)
	}
	s.requestStop()
	if client, err := s.dial(context.Background(), "192.0.2.53"); client != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatal("sealed server admitted a peer", client, err)
	}
	if len(s.peers) != 0 {
		t.Fatal("failed admission published a worker or peer")
	}
}

type runtimeDNSWriteErrorConn struct {
	net.Conn
	err error
}

func (c *runtimeDNSWriteErrorConn) Write([]byte) (int, error) { return 0, c.err }

func TestRuntimeDNSWireFixturePreservesUnexpectedWriteError(t *testing.T) {
	for _, failure := range []error{errors.New("unexpected DNS writer failure"), io.ErrClosedPipe, io.EOF} {
		t.Run(failure.Error(), func(t *testing.T) {
			s := newRuntimeDNSWireServer(t, failure)
			s.wrapPeer = func(peer net.Conn) net.Conn { return &runtimeDNSWriteErrorConn{Conn: peer, err: failure} }
			client, err := s.dial(context.Background(), "192.0.2.53")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			query := new(mdns.Msg)
			query.SetQuestion("failure.fixture.", mdns.TypeA)
			if err := (&mdns.Conn{Conn: client}).WriteMsg(query); err != nil {
				t.Fatal(err)
			}
			runtimeTestWait(t, s.peers[0].done, "DNS failed writer and reader")
		})
	}
}
