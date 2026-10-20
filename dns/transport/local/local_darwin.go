//go:build darwin

package local

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

func (t *Transport) systemExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	question := message.Question[0]
	t.system.exchangeAsync(ctx, question.Name, question.Qtype, question.Qclass, func(response *mDNS.Msg, err error) {
		if err != nil {
			if rcodeError, ok := errors.AsType[dns.RcodeError](err); ok {
				callback(dns.FixedResponseStatus(message, int(rcodeError)), nil)
				return
			}
			callback(nil, err)
			return
		}
		response.Id = message.Id
		response.Response = true
		response.RecursionAvailable = true
		callback(response, nil)
	})
}

// The mDNSResponder daemon speaks an undocumented binary protocol over a
// AF_UNIX SOCK_STREAM socket. The framing below is taken from the client
// stub of Apple's open-source mDNSResponder (mDNSShared/dnssd_ipc.h,
// dnssd_clientstub.c and uds_daemon.c). All multi-byte fields are
// big-endian. A connection opened with connection_request acts as a shared
// connection (DNSServiceCreateConnection): subsequent requests on the same
// stream carry a unique client_context in header bytes 16-24, which the
// daemon echoes back in every reply, allowing concurrent queries to be
// demultiplexed. With IPC_FLAGS_NOERRSD set the daemon does not expect the
// SCM_RIGHTS error-return socket used by Apple's stub; request errors are
// instead delivered as async_error_op replies, and success produces no
// acknowledgment at all. A query is cancelled by sending cancel_request
// with the same client_context and no payload.
const (
	mdnsResponderSocketPath        = "/var/run/mDNSResponder"
	mdnsResponderSocketEnv         = "DNSSD_UDS_PATH"
	mdnsResponderVersion           = 1
	mdnsResponderHeaderLength      = 28
	mdnsResponderConnectionRequest = 1  // connection_request
	mdnsResponderQueryRequest      = 8  // query_request
	mdnsResponderCancelRequest     = 63 // cancel_request
	mdnsResponderQueryReply        = 68 // query_reply_op
	mdnsResponderAsyncErrorReply   = 73 // async_error_op

	mdnsResponderFlagMoreComing          = 0x1
	mdnsResponderFlagAdd                 = 0x2
	mdnsResponderFlagReturnIntermediates = 0x1000
	mdnsResponderFlagShareConnection     = 0x4000
	mdnsResponderFlagTimeout             = 0x10000

	mdnsResponderIPCFlagNoErrorSocket = 0x4 // IPC_FLAGS_NOERRSD

	mdnsResponderErrNoError      = 0
	mdnsResponderErrNoSuchName   = -65538
	mdnsResponderErrNoSuchRecord = -65554
	mdnsResponderErrTimeout      = -65568

	mdnsResponderMaxReplyLength = 1 << 20
)

type systemResolver struct {
 socketErrors resolverSocketErrors
	work lifecycle.Work
	stopCtx context.Context
	stopCancel context.CancelFunc
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr error

	initOnce    sync.Once
	connection  *dnsTransport.ConnPool[net.Conn]
	queryAccess sync.Mutex
	queryId     uint64
	queries     map[uint64]*systemPendingQuery
}

type systemPendingQuery struct {
	conn           net.Conn
	name           string
	qtype          uint16
	qclass         uint16
	answers        []mDNS.RR
	hasFinalAnswer bool
	ready          bool
	callback       func(response *mDNS.Msg, err error)
	stopContext    func() bool
	stopConn       func() bool
}

type systemCompletion struct {
	pending *systemPendingQuery
	err     error
}

func (r *systemResolver) init() {
	r.stopCtx, r.stopCancel = context.WithCancel(context.Background())
	r.closeDone = make(chan struct{})
	r.queries = make(map[uint64]*systemPendingQuery)
	r.connection = dnsTransport.NewConnPool(dnsTransport.ConnPoolOptions[net.Conn]{
		Mode: dnsTransport.ConnPoolSingle,
		IsAlive: func(conn net.Conn) bool {
			return conn != nil
		},
		Close: func(conn net.Conn, cause error) {
			conn.Close()
		},
	})
}

func (r *systemResolver) stop() {
	r.initOnce.Do(r.init)
	r.closeOnce.Do(func() {
		r.work.Seal()
		r.stopCancel()
		go func() {
			defer close(r.closeDone)
			r.closeErr = lifecycle.CleanupResult("mDNSResponder", func() error {
				err := lifecycle.Uncertain("mDNSResponder connection", r.connection.Close())
				r.work.Wait()
				return errors.Join(err, r.socketErrors.result())
			})
		}()
	})
}

func (r *systemResolver) close() error {
	r.stop()
	<-r.closeDone
	return r.closeErr
}

func (r *systemResolver) reset() {
	r.initOnce.Do(r.init)
	done, ok := r.work.Reserve(); if !ok { return }; defer done()
	r.connection.Reset()
}

func (r *systemResolver) setKeepIdleConnections(keep bool) {
	r.initOnce.Do(r.init)
	done, ok := r.work.Reserve(); if !ok { return }; defer done()
	r.connection.SetKeepIdleConnections(keep)
}

func (r *systemResolver) closeIdleConnections() {
	r.initOnce.Do(r.init)
	done, ok := r.work.Reserve(); if !ok { return }; defer done()
	r.connection.CloseIdle()
}

func (r *systemResolver) exchangeAsync(ctx context.Context, name string, qtype uint16, qclass uint16, callback func(response *mDNS.Msg, err error)) {
	r.initOnce.Do(r.init)
	callDone, ok := r.work.Reserve()
	if !ok { callback(nil, lifecycle.ErrStopped); return }; defer callDone()
	callbackDone, ok := r.work.Reserve()
	if !ok { callback(nil, lifecycle.ErrStopped); return }
	ctx, unlink := lifecycle.LinkCancellation(ctx, r.stopCtx)
	originalCallback := callback
	var called atomic.Bool
	callback = func(response *mDNS.Msg, err error) {
		if !called.CompareAndSwap(false, true) { return }
		defer callbackDone(); defer unlink()
		originalCallback(response, err)
	}
	for firstAttempt := true; ; firstAttempt = false {
		conn, connCtx, created, err := r.connection.AcquireShared(ctx, r.dial)
		if err != nil {
			callback(nil, err)
			return
		}
		if created {
			if !r.work.Go(func() { r.recvLoop(conn) }) {
				r.connection.Invalidate(conn, lifecycle.ErrStopped)
				callback(nil, lifecycle.ErrStopped); return
			}
		}
		queryId, registerErr := r.register(ctx, connCtx, conn, name, qtype, qclass, callback)
		if registerErr != nil { r.connection.Release(conn, false); callback(nil, registerErr); return }
		_, writeErr := conn.Write(buildQueryRequest(queryId, name, qtype, qclass))
		if writeErr == nil {
			return
		}
		pending := r.take(queryId)
		r.connection.Invalidate(conn, writeErr)
		if pending == nil {
			return
		}
		if !created && firstAttempt {
			continue
		}
		callback(nil, E.Cause(writeErr, "write mDNSResponder query"))
		return
	}
}

func (r *systemResolver) dial(ctx context.Context) (net.Conn, error) {
	socketPath := cmp.Or(os.Getenv(mdnsResponderSocketEnv), mdnsResponderSocketPath)
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, E.Cause(err, "connect mDNSResponder")
	}
 return r.initializeConnection(ctx, conn)
}

func (r *systemResolver) initializeConnection(ctx context.Context, conn net.Conn) (net.Conn, error) {
	conn = &resolverOwnedConn{Conn: conn, errors: &r.socketErrors}
	closeDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { defer close(closeDone); conn.Close() })
	err := writeConnectionRequest(conn)
	if !stopCancel() { <-closeDone }
	if err == nil && ctx.Err() != nil { err = ctx.Err() }
	if err != nil {
		conn.Close()
		return nil, contextError(ctx, err)
	}
	return conn, nil
}

func writeConnectionRequest(conn net.Conn) error {
	_, err := conn.Write(appendResponderHeader(make([]byte, 0, mdnsResponderHeaderLength), mdnsResponderConnectionRequest, 0, 0, 0))
	if err != nil {
		return E.Cause(err, "write mDNSResponder connection request")
	}
	var status [4]byte
	_, err = io.ReadFull(conn, status[:])
	if err != nil {
		return E.Cause(err, "read mDNSResponder connection status")
	}
	statusCode := int32(binary.BigEndian.Uint32(status[:]))
	if statusCode != mdnsResponderErrNoError {
		return E.New("mDNSResponder connection request failed: error ", statusCode)
	}
	return nil
}

func (r *systemResolver) register(ctx context.Context, connCtx context.Context, conn net.Conn, name string, qtype uint16, qclass uint16, callback func(response *mDNS.Msg, err error)) (uint64, error) {
	r.queryAccess.Lock()
	defer r.queryAccess.Unlock()
	if r.queryId == ^uint64(0) { return 0, E.New("mDNSResponder query identity exhausted") }
	r.queryId++
	queryId := r.queryId
	pending := &systemPendingQuery{
		conn:     conn,
		name:     name,
		qtype:    qtype,
		qclass:   qclass,
		callback: callback,
	}
	r.queries[queryId] = pending
	stopContext, ok := r.work.AfterFunc(ctx, func() { r.cancelQuery(queryId, ctx) })
	if !ok { delete(r.queries, queryId); return 0, lifecycle.ErrStopped }
	pending.stopContext = stopContext
	stopConn, ok := r.work.AfterFunc(connCtx, func() { r.completeConnClosed(queryId, connCtx) })
	if !ok { delete(r.queries, queryId); stopContext(); return 0, lifecycle.ErrStopped }
	pending.stopConn = stopConn
	return queryId, nil
}

func (r *systemResolver) take(queryId uint64) *systemPendingQuery {
	r.queryAccess.Lock()
	pending, loaded := r.queries[queryId]
	if !loaded {
		r.queryAccess.Unlock()
		return nil
	}
	delete(r.queries, queryId)
	r.queryAccess.Unlock()
	pending.stopContext()
	pending.stopConn()
	return pending
}

func (r *systemResolver) cancelQuery(queryId uint64, ctx context.Context) {
	pending := r.take(queryId)
	if pending == nil {
		return
	}
	_, err := pending.conn.Write(appendResponderHeader(make([]byte, 0, mdnsResponderHeaderLength), mdnsResponderCancelRequest, 0, queryId, 0))
	if err != nil {
		r.connection.Invalidate(pending.conn, err)
	} else {
		r.connection.Release(pending.conn, true)
	}
	pending.callback(nil, ctx.Err())
}

func (r *systemResolver) completeConnClosed(queryId uint64, connCtx context.Context) {
	pending := r.take(queryId)
	if pending == nil {
		return
	}
	pending.callback(nil, context.Cause(connCtx))
}

func (r *systemResolver) finish(pending *systemPendingQuery, err error) {
	pending.stopContext()
	pending.stopConn()
	r.connection.Release(pending.conn, true)
	if err != nil {
		pending.callback(nil, err)
		return
	}
	pending.callback(&mDNS.Msg{
		Question: []mDNS.Question{{Name: mDNS.Fqdn(pending.name), Qtype: pending.qtype, Qclass: pending.qclass}},
		Answer:   pending.answers,
	}, nil)
}

func (r *systemResolver) recvLoop(conn net.Conn) {
	for {
		operation, clientContext, data, err := readResponderReply(conn)
		if err != nil {
			r.connection.Invalidate(conn, err)
			return
		}
		switch operation {
		case mdnsResponderQueryReply:
			reply, parseErr := parseResponderReply(data)
			if parseErr != nil {
				r.connection.Invalidate(conn, parseErr)
				return
			}
			r.handleQueryReply(clientContext, reply)
		case mdnsResponderAsyncErrorReply:
			if len(data) >= 12 {
				r.completeQueryError(clientContext, binary.BigEndian.Uint32(data[0:4]), int32(binary.BigEndian.Uint32(data[8:12])))
			}
		}
	}
}

// On a shared connection MoreComing applies collectively to all operations
// (dns_sd.h "Collective kDNSServiceFlagsMoreComing flag"): the daemon sets it
// whenever another reply, for any query, is queued behind this one. A reply
// without it is therefore a connection-wide flush point, at which every query
// that already collected its final answer is completed.
func (r *systemResolver) handleQueryReply(queryId uint64, reply mdnsResponderReply) {
	var completions []systemCompletion
	r.queryAccess.Lock()
	pending, loaded := r.queries[queryId]
	if loaded {
		if reply.errorCode != mdnsResponderErrNoError {
			delete(r.queries, queryId)
			if len(pending.answers) > 0 {
				completions = append(completions, systemCompletion{pending: pending})
			} else {
				completions = append(completions, systemCompletion{pending: pending, err: darwinResolverError(pending.name, reply.errorCode)})
			}
		} else {
			if reply.flags&mdnsResponderFlagAdd != 0 && len(reply.rdata) > 0 {
				record, buildErr := buildResourceRecord(reply)
				if buildErr == nil {
					pending.answers = append(pending.answers, record)
					if record.Header().Rrtype == pending.qtype {
						pending.hasFinalAnswer = true
					}
				}
			}
			if pending.hasFinalAnswer && reply.rrtype == pending.qtype {
				pending.ready = true
			}
		}
	}
	if reply.flags&mdnsResponderFlagMoreComing == 0 {
		completions = r.collectReadyLocked(completions)
	}
	r.queryAccess.Unlock()
	for _, completion := range completions {
		r.finish(completion.pending, completion.err)
	}
}

func (r *systemResolver) completeQueryError(queryId uint64, flags uint32, errorCode int32) {
	var completions []systemCompletion
	r.queryAccess.Lock()
	pending, loaded := r.queries[queryId]
	if loaded {
		delete(r.queries, queryId)
		completions = append(completions, systemCompletion{pending: pending, err: darwinResolverError(pending.name, errorCode)})
	}
	if flags&mdnsResponderFlagMoreComing == 0 {
		completions = r.collectReadyLocked(completions)
	}
	r.queryAccess.Unlock()
	for _, completion := range completions {
		r.finish(completion.pending, completion.err)
	}
}

func (r *systemResolver) collectReadyLocked(completions []systemCompletion) []systemCompletion {
	for queryId, pending := range r.queries {
		if pending.ready {
			delete(r.queries, queryId)
			completions = append(completions, systemCompletion{pending: pending})
		}
	}
	return completions
}

func appendResponderHeader(buffer []byte, operation uint32, dataLength int, clientContext uint64, ipcFlags uint32) []byte {
	buffer = binary.BigEndian.AppendUint32(buffer, mdnsResponderVersion)
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(dataLength))
	buffer = binary.BigEndian.AppendUint32(buffer, ipcFlags)
	buffer = binary.BigEndian.AppendUint32(buffer, operation)
	buffer = binary.BigEndian.AppendUint64(buffer, clientContext)
	buffer = binary.BigEndian.AppendUint32(buffer, 0) // reg_index
	return buffer
}

func buildQueryRequest(queryId uint64, name string, qtype uint16, qclass uint16) []byte {
	payloadLength := 4 + 4 + len(name) + 1 + 2 + 2
	message := make([]byte, 0, mdnsResponderHeaderLength+payloadLength)
	message = appendResponderHeader(message, mdnsResponderQueryRequest, payloadLength, queryId, mdnsResponderIPCFlagNoErrorSocket)
	message = binary.BigEndian.AppendUint32(message, mdnsResponderFlagShareConnection|mdnsResponderFlagReturnIntermediates|mdnsResponderFlagTimeout)
	message = binary.BigEndian.AppendUint32(message, 0) // interfaceIndex
	message = append(message, name...)
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, qtype)
	message = binary.BigEndian.AppendUint16(message, qclass)
	return message
}

func readResponderReply(conn net.Conn) (operation uint32, clientContext uint64, data []byte, err error) {
	var header [mdnsResponderHeaderLength]byte
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		return
	}
	dataLength := binary.BigEndian.Uint32(header[4:8])
	if dataLength > mdnsResponderMaxReplyLength {
		err = E.New("oversized mDNSResponder reply: ", dataLength)
		return
	}
	operation = binary.BigEndian.Uint32(header[12:16])
	clientContext = binary.BigEndian.Uint64(header[16:24])
	data = make([]byte, dataLength)
	_, err = io.ReadFull(conn, data)
	return
}

type mdnsResponderReply struct {
	flags     uint32
	errorCode int32
	name      string
	rrtype    uint16
	rrclass   uint16
	ttl       uint32
	rdata     []byte
}

func parseResponderReply(data []byte) (mdnsResponderReply, error) {
	var reply mdnsResponderReply
	reader := replyReader{data: data}
	reply.flags = reader.uint32()
	reader.uint32() // interfaceIndex
	reply.errorCode = int32(reader.uint32())
	reply.name = reader.cString()
	reply.rrtype = reader.uint16()
	reply.rrclass = reader.uint16()
	rdlen := reader.uint16()
	reply.rdata = reader.bytes(int(rdlen))
	reply.ttl = reader.uint32()
	if reader.err != nil {
		return reply, reader.err
	}
	return reply, nil
}

func buildResourceRecord(reply mdnsResponderReply) (mDNS.RR, error) {
	name := mDNS.Fqdn(reply.name)
	nameBuffer := make([]byte, 256)
	offset, err := mDNS.PackDomainName(name, nameBuffer, 0, nil, false)
	if err != nil {
		return nil, err
	}
	record := make([]byte, 0, offset+10+len(reply.rdata))
	record = append(record, nameBuffer[:offset]...)
	record = binary.BigEndian.AppendUint16(record, reply.rrtype)
	record = binary.BigEndian.AppendUint16(record, reply.rrclass)
	record = binary.BigEndian.AppendUint32(record, reply.ttl)
	record = binary.BigEndian.AppendUint16(record, uint16(len(reply.rdata)))
	record = append(record, reply.rdata...)
	resourceRecord, _, err := mDNS.UnpackRR(record, 0)
	if err != nil {
		return nil, err
	}
	return resourceRecord, nil
}

// The daemon's NoSuchRecord conflates NXDOMAIN and NODATA, so it is reported as
// an empty NOERROR to avoid a false NXDOMAIN.
func darwinResolverError(name string, code int32) error {
	switch code {
	case mdnsResponderErrNoSuchRecord:
		return dns.RcodeSuccess
	case mdnsResponderErrNoSuchName:
		return dns.RcodeNameError
	case mdnsResponderErrTimeout:
		return E.New("mDNSResponder query timeout for ", name)
	default:
		return E.New("mDNSResponder query failed for ", name, ": error ", code)
	}
}

func contextError(ctx context.Context, err error) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return ctxErr
	}
	return err
}

type replyReader struct {
	data   []byte
	offset int
	err    error
}

func (r *replyReader) uint32() uint32 {
	if r.err != nil || r.offset+4 > len(r.data) {
		r.fail()
		return 0
	}
	value := binary.BigEndian.Uint32(r.data[r.offset:])
	r.offset += 4
	return value
}

func (r *replyReader) uint16() uint16 {
	if r.err != nil || r.offset+2 > len(r.data) {
		r.fail()
		return 0
	}
	value := binary.BigEndian.Uint16(r.data[r.offset:])
	r.offset += 2
	return value
}

func (r *replyReader) cString() string {
	if r.err != nil {
		return ""
	}
	end := r.offset
	for end < len(r.data) && r.data[end] != 0 {
		end++
	}
	if end >= len(r.data) {
		r.fail()
		return ""
	}
	value := string(r.data[r.offset:end])
	r.offset = end + 1
	return value
}

func (r *replyReader) bytes(length int) []byte {
	if r.err != nil || length < 0 || r.offset+length > len(r.data) {
		r.fail()
		return nil
	}
	value := r.data[r.offset : r.offset+length]
	r.offset += length
	return value
}

func (r *replyReader) fail() {
	if r.err == nil {
		r.err = E.New("truncated mDNSResponder reply")
	}
}
