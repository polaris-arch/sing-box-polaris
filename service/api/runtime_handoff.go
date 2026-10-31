package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	handoffPrefix   = "x-polaris-api-"
	handoffVersion  = "listener-handoff-hmac-v1"
	handoffLifetime = 5 * time.Minute
	// Independent from unused Plan custody; never refreshed by recovery or ACK.
	handoffAuthLifetime = 5 * time.Minute
)

type apiIssuedPlan struct {
	ingress         *apiGeneration
	carrier         *apiOwnedConn
	connectionBound bool
	expires         time.Time
}

// runtimeAPI is the stable, local control-plane owner. A graph publication
// changes admission, not ownership of the old recovery socket. Neither a
// credential nor a client-declared transaction/generation supplies this owner.
// At most one prepared/unacknowledged successor is retained per API service.
type runtimeAPI struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	service     *Service
	provider    adapter.RuntimeAPIProvider
	actor       string
	attached    *daemon.StartedService
	generations []*apiGeneration
	endpoints   []*apiEndpoint
	plans       map[string]apiIssuedPlan
	pending     *apiHandoff
	preparing   bool
	closing     bool
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
	tlsOwned    bool // protected by mu; includes a partially started TLS provider
	now         func() time.Time
}

type apiGeneration struct {
	hub              *runtimeAPI
	options          option.APIServiceOptions
	digest, id       string
	endpoint         *apiEndpoint
	ctx              context.Context
	cancel           context.CancelFunc
	attached         *daemon.StartedService
	grpc             *grpc.Server
	handler          http.Handler
	mu               sync.Mutex
	closing          bool
	quiescing        bool
	admissionChanged chan struct{}
	ordinary         int
	ordinaryIdle     chan struct{}
	requests         sync.WaitGroup
	once             sync.Once
	done             chan struct{}
	closeErr         error
	confirmed        *apiHandoff
}

type apiEndpoint struct {
	hub         *runtimeAPI
	listener    net.Listener
	server      *http.Server
	mu          sync.Mutex
	closing     bool
	conns       map[*apiOwnedConn]struct{}
	requests    sync.WaitGroup
	connWorkers sync.WaitGroup
	serveDone   chan struct{}
	serveErr    error
	once        sync.Once
	closeErr    error
}

type apiConnContextKey struct{}

type apiOwnedConn struct {
	generation *apiGeneration // protected by endpoint.mu
	net.Conn
	endpoint  *apiEndpoint
	once      sync.Once
	err       error
	serveOnce sync.Once
}

func (c *apiOwnedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.endpoint.mu.Lock()
		delete(c.endpoint.conns, c)
		c.endpoint.mu.Unlock()
	})
	return c.err
}

type apiAccept struct {
	net.Listener
	endpoint *apiEndpoint
}

func (a apiAccept) Accept() (net.Conn, error) {
	c, err := a.Listener.Accept()
	if err != nil {
		return nil, err
	}
	owned := &apiOwnedConn{Conn: c, endpoint: a.endpoint}
	a.endpoint.mu.Lock()
	if a.endpoint.closing {
		a.endpoint.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	a.endpoint.conns[owned] = struct{}{}
	a.endpoint.connWorkers.Add(1)
	a.endpoint.mu.Unlock()
	return owned, nil
}

type apiHandoff struct {
	hub          *runtimeAPI
	origin, next *apiGeneration
	key          [32]byte
	transaction  string
	active       *daemon.RuntimeIdentity
	acknowledged bool
	retiring     bool
	aborted      bool
	authDeadline time.Time
	authExpired  bool
	authTimer    *time.Timer
	done         chan struct{}
	closeErr     error
}

// Caller holds hub.mu. Expiry revokes authentication, never asserts that the
// published graph or retained socket cleanup has completed.
func (h *apiHandoff) expireAuthentication() {
	h.authExpired = true
	h.key = [32]byte{}
	if h.authTimer != nil {
		h.authTimer.Stop()
	}
}

func (h *apiHandoff) authenticationLive() bool {
	if h.authExpired || h.aborted || h.hub.closing || !h.hub.now().Before(h.authDeadline) {
		h.expireAuthentication()
		return false
	}
	return true
}

func randomAPIID() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}

func newRuntimeAPI(ctx context.Context, s *Service, provider adapter.RuntimeAPIProvider) (*runtimeAPI, error) {
	id, err := randomAPIID()
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	h := &runtimeAPI{ctx: owned, cancel: cancel, service: s, provider: provider, actor: "api:local-owner:" + id, plans: make(map[string]apiIssuedPlan), closeDone: make(chan struct{}), now: time.Now}
	if err := adapter.DeferConstructionCleanup(ctx, h.close); err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}

func (h *runtimeAPI) identity() (adapter.RuntimeAPIIdentity, error) {
	return h.provider.RuntimeAPIIngressIdentity(h.service.Tag())
}
func (g *apiGeneration) Actor() string { return g.hub.actor }
func apiCommitted(op *daemon.RuntimeConfigOperation) bool {
	return op != nil && (op.State == daemon.RuntimeOperationState_COMMITTED || op.State == daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING)
}

func sameAPIIdentity(a *daemon.RuntimeIdentity, b adapter.RuntimeAPIIdentity) bool {
	return a != nil && a.Incarnation == b.Incarnation && a.AppliedRevision == b.Revision && a.EffectiveDigest == b.EffectiveDigest
}

func apiTransaction(request any) string {
	switch r := request.(type) {
	case *daemon.RuntimeConfigStatusRequest:
		return r.TransactionId
	case *daemon.RuntimePersistenceRetryRequest:
		return r.TransactionId
	case *daemon.RuntimePersistenceAcknowledgementRequest:
		return r.TransactionId
	}
	return ""
}

func recoveryAPIMethod(method string) bool {
	return method == daemon.RuntimeConfigService_GetRuntimeConfigStatus_FullMethodName || method == daemon.RuntimeConfigService_RetryRuntimePersistence_FullMethodName || method == daemon.RuntimeConfigService_AcknowledgeRuntimePersistence_FullMethodName
}

func (g *apiGeneration) BeforeUnary(ctx context.Context, method string, request any) (func(), error) {
	if err := g.beforeUnary(ctx, method, request); err != nil {
		return nil, err
	}
	g.mu.Lock()
	if g.closing || (g.quiescing && !recoveryAPIMethod(method)) {
		g.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "API ordinary admission sealed")
	}
	// The original Apply cannot wait for itself. Recovery is fenced by the
	// actual Core transaction/actor and never borrows a new graph action.
	if method == daemon.RuntimeConfigService_ApplyRuntimeConfig_FullMethodName || recoveryAPIMethod(method) {
		g.mu.Unlock()
		return func() {}, nil
	}
	g.beginWorkLocked()
	g.mu.Unlock()
	return g.endWork, nil
}

func (g *apiGeneration) beginWorkLocked() {
	if g.ordinary == 0 {
		g.ordinaryIdle = make(chan struct{})
	}
	g.ordinary++
}

func (g *apiGeneration) endWork() {
	g.mu.Lock()
	g.ordinary--
	if g.ordinary == 0 {
		close(g.ordinaryIdle)
	}
	g.mu.Unlock()
}

func (g *apiGeneration) quiesce(ctx context.Context) error {
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		return errors.New("API origin closing")
	}
	if !g.quiescing {
		g.quiescing = true
		close(g.admissionChanged)
	}
	idle := g.ordinaryIdle
	empty := g.ordinary == 0
	g.mu.Unlock()
	if empty {
		return ctx.Err()
	}
	select {
	case <-idle:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *apiGeneration) resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.quiescing && !g.closing && g.hub.ctx.Err() == nil {
		g.quiescing = false
		g.admissionChanged = make(chan struct{})
	}
}

func (g *apiGeneration) beforeUnary(ctx context.Context, method string, request any) error {
	// An attached Box is not the daemon's replaceable lifecycle owner. These
	// methods must not close/reload the instance from inside its own RPC task.
	if strings.HasSuffix(method, "/StartOrReloadService") || strings.HasSuffix(method, "/CloseService") {
		return status.Error(codes.FailedPrecondition, "attached API cannot own service lifecycle")
	}

	carrier, _ := ctx.Value(apiConnContextKey{}).(*apiOwnedConn)
	if apply, ok := request.(*daemon.ApplyRuntimeConfigRequest); ok {
		g.hub.mu.Lock()
		issued, known := g.hub.plans[apply.TransactionId]
		g.hub.mu.Unlock()
		if known && issued.connectionBound && (issued.ingress != g || issued.carrier != carrier) {
			return status.Error(codes.FailedPrecondition, "API apply requires its original captured channel")
		}
	}
	identity, err := g.hub.identity()
	if err != nil {
		return status.Error(codes.Unavailable, "API publication unavailable")
	}
	h := g.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing {
		return status.Error(codes.Unavailable, "API owner closing")
	}
	if identity.ConfigurationDigest == g.digest {
		return nil
	}
	// This is only a preliminary filter. Core still authenticates this actor's
	// actual receipt/state/identity; a supplied transaction alone grants nothing.
	plan, known := h.plans[apiTransaction(request)]
	if recoveryAPIMethod(method) && known && plan.ingress == g && plan.carrier == carrier && h.pending != nil && h.pending.origin == g && !h.pending.aborted && !h.pending.acknowledged && h.pending.authenticationLive() {
		return nil
	}
	return status.Error(codes.FailedPrecondition, "retired API ingress permits only its original transaction recovery")
}

func (g *apiGeneration) StreamContext(ctx context.Context) (context.Context, func(), error) {
	identity, err := g.hub.identity()
	if err != nil || identity.ConfigurationDigest != g.digest {
		return nil, nil, status.Error(codes.FailedPrecondition, "API stream ingress retired")
	}
	g.mu.Lock()
	if g.closing || g.quiescing {
		g.mu.Unlock()
		return nil, nil, status.Error(codes.FailedPrecondition, "API stream admission sealed")
	}
	changed := g.admissionChanged
	g.beginWorkLocked()
	g.mu.Unlock()
	child, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-child.Done():
				return
			case <-changed:
				cancel()
				return
			case <-identity.Changed:
			}
			next, e := g.hub.identity()
			if e != nil || next.ConfigurationDigest != g.digest {
				cancel()
				return
			}
			identity = next
		}
	}()
	return child, func() { cancel(); <-done; g.endWork() }, nil
}

func (h *runtimeAPI) start(scope *adapter.Scope) error {
	h.mu.Lock()
	if h.closing || h.preparing || len(h.generations) != 0 {
		h.mu.Unlock()
		return errors.New("API owner already started or closing")
	}
	h.preparing = true
	h.workers.Add(1)
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.preparing = false; h.mu.Unlock(); h.workers.Done() }()
	if err := scope.Context().Err(); err != nil {
		return err
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	scope.Add(h.close)
	if h.service.dashboard != nil {
		if err := h.service.dashboard.start(h.ctx); err != nil {
			return err
		}
	}
	if h.service.tlsConfig != nil {
		h.mu.Lock()
		if h.closing {
			h.mu.Unlock()
			return net.ErrClosed
		}
		h.tlsOwned = true
		h.mu.Unlock()
		if err := h.service.startTLS(); err != nil {
			return err
		}
	}
	h.attached = daemon.NewAttachedService(h.ctx)
	tcp, err := h.service.listener.ListenTCP()
	if err != nil {
		return err
	}
	if h.service.tlsConfig != nil {
		// Keep the established lazy TLS wrapper inside the tracked carrier.
		// Authentication/retirement still bind to apiOwnedConn, never to a tuple.
		tcp = apiTLSListener{Listener: tcp, config: h.service.tlsConfig}
	}
	endpoint := &apiEndpoint{hub: h, listener: tcp, conns: make(map[*apiOwnedConn]struct{}), serveDone: make(chan struct{})}
	g, err := h.newGeneration(h.service.options, endpoint)
	if err != nil {
		return errors.Join(err, endpoint.close())
	}
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return errors.Join(net.ErrClosed, endpoint.close(), g.close())
	}
	h.generations = append(h.generations, g)
	h.endpoints = append(h.endpoints, g.endpoint)
	g.endpoint.start()
	h.mu.Unlock()
	return nil
}

func (h *runtimeAPI) newGeneration(options option.APIServiceOptions, endpoint *apiEndpoint) (*apiGeneration, error) {
	digest, err := adapter.RuntimeAPIConfigDigest(options)
	if err != nil {
		return nil, err
	}
	id, err := randomAPIID()
	if err != nil {
		return nil, err
	}
	// There is no network, TLS, HTTP-manager lookup or graph admission until this
	// explicit prepare call. Ordinary constructors and Plan remain inert.
	if endpoint == nil {
		l := listener.New(listener.Options{Exclusive: true, Context: h.ctx, Logger: h.service.logger, Network: []string{N.NetworkTCP}, Listen: options.ListenOptions})
		tcp, e := l.ListenTCP()
		if e != nil {
			return nil, e
		}
		endpoint = &apiEndpoint{hub: h, listener: tcp, conns: make(map[*apiOwnedConn]struct{}), serveDone: make(chan struct{})}
	}
	ctx, cancel := context.WithCancel(h.ctx)
	g := &apiGeneration{admissionChanged: make(chan struct{}), hub: h, options: options, digest: digest, id: id, endpoint: endpoint, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	g.attached = h.attached
	g.grpc = daemon.NewServerWithRuntimeIngress(g.attached, options.Secret, g, grpc.ForceServerCodec(apiWireCodec{}))
	g.handler = newHTTPHandler(h.service.logger, g.grpc, options, h.service.dashboard)
	return g, nil
}

func (e *apiEndpoint) start() {
	e.startHandler(e.hub.ctx, http.HandlerFunc(e.dispatch))
}

// The legacy TLS ingress owns the same actual HTTP/TLS loops, while retaining
// its existing daemon service and lack of runtime-configuration admission.
func (e *apiEndpoint) startHandler(ctx context.Context, next http.Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return
	}
	handler := h2c.NewHandler(next, new(http2.Server))
	e.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			if e.closing {
				e.mu.Unlock()
				http.Error(w, "API closing", http.StatusServiceUnavailable)
				return
			}
			e.requests.Add(1)
			e.mu.Unlock()
			defer e.requests.Done()
			handler.ServeHTTP(w, r)
		}), BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, apiConnContextKey{}, conn)
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				// Closed joins the HTTP/TLS read/handshake tail. Hijacked work
				// stays owned by requests (h2c/WebSocket), not net/http's loop.
				conn.(*apiOwnedConn).serveOnce.Do(e.connWorkers.Done)
			}
		},
	}
	go func() {
		defer close(e.serveDone)
		err := e.server.Serve(apiAccept{Listener: e.listener, endpoint: e})
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			e.serveErr = err
		}
	}()
}

func (e *apiEndpoint) dispatch(w http.ResponseWriter, r *http.Request) {
	h := e.hub
	identity, err := h.identity()
	if err != nil {
		http.Error(w, "API publication unavailable", http.StatusServiceUnavailable)
		return
	}
	h.mu.Lock()
	var selected, empty *apiGeneration
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for _, g := range h.generations {
		if g.endpoint != e {
			continue
		}
		if g.options.Secret != "" && token == g.options.Secret {
			selected = g
			break
		}
		if g.options.Secret == "" {
			if identity.ConfigurationDigest == g.digest {
				empty = g
			} else if empty == nil {
				empty = g
			}
		}
	}
	if selected == nil {
		selected = empty
	}
	// Static dashboard assets and CORS were never bearer-authenticated. A
	// WebSocket carries its gRPC metadata only in the first frame: choose the
	// current generation here and let its existing interceptor authenticate
	// that frame. Native/header gRPC never gets this fallback.
	if selected == nil && (isWebSocketGRPCRequest(r) || r.Method == http.MethodOptions || !strings.HasPrefix(r.Header.Get("Content-Type"), contentTypeGRPC)) {
		for _, g := range h.generations {
			if g.endpoint == e && g.digest == identity.ConfigurationDigest {
				selected = g
				break
			}
		}
	}
	h.mu.Unlock()
	if selected == nil {
		http.Error(w, "API authentication required", http.StatusUnauthorized)
		return
	}
	// The HTTP bridge, dashboard and WebSocket paths obey the same retirement
	// boundary as native gRPC; old credentials cannot bypass it through a bridge.
	if identity.ConfigurationDigest != selected.digest && !recoveryAPIMethod(r.URL.Path) {
		http.Error(w, "API ingress retired", http.StatusForbidden)
		return
	}
	selected.mu.Lock()
	if selected.closing {
		selected.mu.Unlock()
		http.Error(w, "API ingress closed", http.StatusServiceUnavailable)
		return
	}
	// First admission pins the actual accepted carrier. Even with the same
	// tuple, a new credential must establish its own channel; changing headers
	// on an old h2 connection cannot transfer listener generation custody.
	carrier, ok := r.Context().Value(apiConnContextKey{}).(*apiOwnedConn)
	if !ok {
		selected.mu.Unlock()
		http.Error(w, "API carrier custody unavailable", http.StatusServiceUnavailable)
		return
	}
	e.mu.Lock()
	if e.closing || (carrier.generation != nil && carrier.generation != selected) {
		e.mu.Unlock()
		selected.mu.Unlock()
		http.Error(w, "API carrier belongs to another generation", http.StatusForbidden)
		return
	}
	carrier.generation = selected
	e.mu.Unlock()
	selected.requests.Add(1)
	selected.mu.Unlock()
	defer selected.requests.Done()
	selected.handler.ServeHTTP(w, r)
}

func (e *apiEndpoint) close() error {
	e.once.Do(func() {
		e.mu.Lock()
		e.closing = true
		conns := make([]*apiOwnedConn, 0, len(e.conns))
		for c := range e.conns {
			conns = append(conns, c)
		}
		e.mu.Unlock()
		if e.server != nil {
			e.closeErr = errors.Join(e.closeErr, e.server.Close())
		}
		if err := e.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			e.closeErr = errors.Join(e.closeErr, err)
		}
		for _, c := range conns {
			if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				e.closeErr = errors.Join(e.closeErr, err)
			}
		}
		if e.server != nil {
			<-e.serveDone
			e.closeErr = errors.Join(e.closeErr, e.serveErr)
		}
		e.requests.Wait()
		e.connWorkers.Wait()
	})
	return e.closeErr
}

func (g *apiGeneration) close() error {
	g.once.Do(func() {
		g.mu.Lock()
		g.closing = true
		g.mu.Unlock()
		g.cancel()
		g.endpoint.mu.Lock()
		var carriers []*apiOwnedConn
		for conn := range g.endpoint.conns {
			if conn.generation == g {
				carriers = append(carriers, conn)
			}
		}
		g.endpoint.mu.Unlock()
		for _, conn := range carriers {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				g.closeErr = errors.Join(g.closeErr, err)
			}
		}
		g.grpc.Stop()
		g.requests.Wait()
		close(g.done)
	})
	<-g.done
	return g.closeErr
}

func sameAPIEndpoint(a, b option.APIServiceOptions) bool {
	return a.Listen != nil && b.Listen != nil && netip.Addr(*a.Listen).Unmap() == netip.Addr(*b.Listen).Unmap() && a.ListenPort == b.ListenPort
}

func (s *Service) PrepareRuntimeAPI(ctx context.Context, options option.APIServiceOptions) (adapter.RuntimeAPIHandoff, error) {
	h := s.runtime
	if h == nil {
		return nil, errors.New("API runtime owner unavailable")
	}
	options = adapter.NormalizeRuntimeAPIOptions(options)
	if !adapter.RuntimeAPISecretValid(options.Secret) {
		return nil, errors.New("API handoff credential is not bounded header-safe ASCII")
	}
	if options.Listen == nil || netip.Addr(*options.Listen).Zone() != "" || !netip.Addr(*options.Listen).IsLoopback() || options.TLS != nil || options.ReuseAddr || options.Detour != "" || options.NetNs != "" || options.BindInterface != "" || options.RoutingMark != 0 || options.TCPFastOpen || options.TCPMultiPath {
		return nil, errors.New("unsupported API handoff socket or TLS options")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active, err := h.identity()
	if err != nil {
		return nil, err
	}
	digest, err := adapter.RuntimeAPIConfigDigest(options)
	if err != nil {
		return nil, err
	}
	if digest == active.ConfigurationDigest {
		return nil, errors.New("unchanged API ingress needs no handoff")
	}
	h.mu.Lock()
	if h.closing || h.preparing || h.pending != nil {
		h.mu.Unlock()
		return nil, errors.New("API handoff or cleanup is already pending")
	}
	var old *apiGeneration
	for _, g := range h.generations {
		if g.digest == active.ConfigurationDigest {
			old = g
			break
		}
	}
	if old == nil {
		h.mu.Unlock()
		return nil, errors.New("published API owner missing")
	}
	original, successor := old.options, options
	original.Listen = nil
	successor.Listen = nil
	original.ListenPort = 0
	successor.ListenPort = 0
	original.Secret = ""
	successor.Secret = ""
	if !reflect.DeepEqual(original, successor) {
		h.mu.Unlock()
		return nil, errors.New("API handoff changes unsupported options")
	}
	address := *options.Listen
	options.Listen = &address
	h.preparing = true
	h.workers.Add(1)
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.preparing = false; h.mu.Unlock(); h.workers.Done() }()
	var endpoint *apiEndpoint
	if sameAPIEndpoint(old.options, options) {
		endpoint = old.endpoint
	} else if options.ListenPort == 0 {
		return nil, errors.New("API successor requires an explicit reachable port")
	}
	next, err := h.newGeneration(options, endpoint)
	if err != nil {
		return nil, err
	}
	handoff := &apiHandoff{hub: h, origin: old, next: next, done: make(chan struct{})}
	if _, err = rand.Read(handoff.key[:]); err != nil {
		handoff.key = [32]byte{}
		_ = next.close()
		if endpoint == nil {
			_ = next.endpoint.close()
		}
		return nil, err
	}
	h.mu.Lock()
	h.generations = append(h.generations, next)
	if endpoint == nil {
		h.endpoints = append(h.endpoints, next.endpoint)
	}
	handoff.authDeadline = h.now().Add(handoffAuthLifetime)
	handoff.authTimer = time.AfterFunc(handoffAuthLifetime, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		handoff.expireAuthentication()
	})
	h.pending = handoff
	h.mu.Unlock()
	if endpoint == nil {
		next.endpoint.start()
	}
	if err = old.quiesce(ctx); err != nil {
		return handoff, errors.Join(err, handoff.Abort())
	}
	if err = ctx.Err(); err != nil {
		return handoff, errors.Join(err, handoff.Abort())
	}
	return handoff, nil
}

func (s *Service) RuntimeAPIHandoffPending() bool {
	if s.runtime == nil {
		return false
	}
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	return s.runtime.pending != nil
}

func (h *apiHandoff) Status() (bool, error) {
	h.hub.mu.Lock()
	defer h.hub.mu.Unlock()
	select {
	case <-h.done:
		return h.closeErr == nil, h.closeErr
	default:
		return false, nil
	}
}

func (h *apiHandoff) Abort() error {
	owner := h.hub
	if identity, err := owner.identity(); err == nil && identity.ConfigurationDigest == h.next.digest {
		return errors.New("published API handoff cannot be aborted")
	}
	owner.mu.Lock()
	if h.retiring || h.acknowledged {
		owner.mu.Unlock()
		return errors.New("published API handoff cannot be aborted")
	}
	if h.aborted {
		owner.mu.Unlock()
		<-h.done
		return h.closeErr
	}
	h.aborted = true
	h.expireAuthentication()
	owner.mu.Unlock()
	h.origin.resume()
	err := h.next.close()
	if h.next.endpoint != h.origin.endpoint {
		err = errors.Join(err, h.next.endpoint.close())
	}
	owner.mu.Lock()
	h.closeErr = err
	if err == nil {
		owner.removeGeneration(h.next)
		if h.next.endpoint != h.origin.endpoint {
			owner.removeEndpoint(h.next.endpoint)
		}
		if owner.pending == h {
			owner.pending = nil
		}
	}
	close(h.done)
	owner.mu.Unlock()
	return err
}

func (h *runtimeAPI) removeEndpoint(endpoint *apiEndpoint) {
	for i, e := range h.endpoints {
		if e == endpoint {
			h.endpoints = append(h.endpoints[:i], h.endpoints[i+1:]...)
			return
		}
	}
}

func (h *runtimeAPI) removeGeneration(g *apiGeneration) {
	for i, x := range h.generations {
		if x == g {
			h.generations = append(h.generations[:i], h.generations[i+1:]...)
			return
		}
	}
}

func (h *runtimeAPI) close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closing = true
		if h.pending != nil {
			h.pending.expireAuthentication()
		}
		for _, generation := range h.generations {
			if generation.confirmed != nil {
				generation.confirmed.expireAuthentication()
			}
		}
		h.cancel()
		earlyEndpoints := append([]*apiEndpoint(nil), h.endpoints...)
		tlsOwned := h.tlsOwned
		h.mu.Unlock()
		if tlsOwned {
			// Cold TLS cannot prepare a hot successor. Interrupt its physical I/O
			// before closing the provider, including a partially blocked Start.
			// Initial start cannot publish after closing is set. Plain handoff
			// prepare keeps its original worker-before-endpoint close ordering.
			for _, endpoint := range earlyEndpoints {
				h.closeErr = errors.Join(h.closeErr, endpoint.close())
			}
			h.closeErr = errors.Join(h.closeErr, h.service.tlsConfig.Close())
		}
		h.workers.Wait()
		h.mu.Lock()
		gens := append([]*apiGeneration(nil), h.generations...)
		eps := append([]*apiEndpoint(nil), h.endpoints...)
		h.mu.Unlock()
		// Close physical carriers before waiting for handlers, including hijacked h2c
		// and WebSocket carriers not joined by http.Server.Close itself.
		for _, e := range eps {
			h.closeErr = errors.Join(h.closeErr, e.close())
		}
		for _, g := range gens {
			h.closeErr = errors.Join(h.closeErr, g.close())
		}
		if h.attached != nil {
			h.attached.Close()
		}
		if h.service.dashboard != nil {
			h.closeErr = errors.Join(h.closeErr, h.service.dashboard.close())
		}
		close(h.closeDone)
	})
	<-h.closeDone
	return h.closeErr
}

// Transcript fields are server-owned except the random challenge. Newline is
// unambiguous here: IDs/digests/challenges are fixed hex and endpoint is net.Addr.
// The verifier key is disclosed only on the original authenticated channel.
// It is never sent to the candidate peer, used as an actor, logged or persisted.
func (h *apiHandoff) transcript(kind, challenge, bodyDigest string) string {
	a := h.active
	return strings.Join([]string{handoffVersion, kind, h.next.id, h.transaction, a.Incarnation, strconv.FormatUint(a.AppliedRevision, 10), a.EffectiveDigest, h.next.endpoint.listener.Addr().String(), challenge, bodyDigest}, "\n")
}

func (h *apiHandoff) mac(kind, challenge, bodyDigest string) string {
	m := hmac.New(sha256.New, h.key[:])
	_, _ = m.Write([]byte(h.transcript(kind, challenge, bodyDigest)))
	return hex.EncodeToString(m.Sum(nil))
}

func apiHeader(ctx context.Context, key string) string {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(handoffPrefix + key)
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

func validAPIHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func (g *apiGeneration) AfterUnary(ctx context.Context, method string, request, response any) error {
	h := g.hub
	if plan, ok := response.(*daemon.RuntimeConfigPlan); ok && plan.Applicable && plan.TransactionId != "" {
		h.mu.Lock()
		now := h.now()
		for id, p := range h.plans {
			retained := h.pending != nil && p.connectionBound && p.ingress == h.pending.origin
			for _, generation := range h.generations {
				if generation.confirmed != nil && generation.confirmed.transaction == id {
					retained = true
				}
			}
			if !retained && !now.Before(p.expires) {
				delete(h.plans, id)
			}
		}
		if len(h.plans) >= 256 {
			h.mu.Unlock()
			return status.Error(codes.ResourceExhausted, "API plan custody budget exceeded")
		}
		carrier, _ := ctx.Value(apiConnContextKey{}).(*apiOwnedConn)
		if carrier == nil {
			h.mu.Unlock()
			return status.Error(codes.FailedPrecondition, "API plan has no captured carrier")
		}
		bound := false
		for _, impact := range plan.Impacts {
			if impact.EffectivePath == "services" {
				bound = true
			}
		}
		h.plans[plan.TransactionId] = apiIssuedPlan{ingress: g, carrier: carrier, connectionBound: bound, expires: now.Add(handoffLifetime)}
		h.mu.Unlock()
	}
	result, ok := response.(*daemon.RuntimeConfigStatus)
	if !ok || method != daemon.RuntimeConfigService_GetRuntimeConfigStatus_FullMethodName {
		return nil
	}
	req, ok := request.(*daemon.RuntimeConfigStatusRequest)
	if !ok || result.LookupState != daemon.RuntimeLookupState_FOUND || !apiCommitted(result.Operation) {
		return nil
	}
	identity, err := h.identity()
	if err != nil {
		return status.Error(codes.Unavailable, "API graph unavailable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := h.pending
	if pending == nil {
		pending = g.confirmed
	}
	if pending == nil || pending.aborted {
		return nil
	}
	if pending.acknowledged && g != pending.next {
		return nil
	}
	issued, known := h.plans[req.TransactionId]
	if !known || issued.ingress != pending.origin || !sameAPIIdentity(result.Operation.Active, identity) || !sameAPIIdentity(result.Active, identity) || identity.ConfigurationDigest != pending.next.digest || result.Operation.CandidateDigest != identity.EffectiveDigest {
		return nil
	}
	// This deadline belongs only to this handshake. A previous confirmed
	// handoff must not poison later ordinary Status transactions on its API.
	live := pending.authenticationLive()
	// Ordinary receipt/persistence observation on the current API needs no
	// temporary proof. In particular it must remain usable after ACK and TTL.
	if g == pending.next && apiHeader(ctx, "challenge") == "" && apiHeader(ctx, "ack") == "" {
		return nil
	}
	if !live {
		return status.Error(codes.FailedPrecondition, "API handoff authentication expired")
	}
	if pending.transaction != "" && pending.transaction != req.TransactionId {
		return status.Error(codes.FailedPrecondition, "API handoff transaction mismatch")
	}
	pending.transaction = req.TransactionId
	pending.active = result.Operation.Active
	headers := metadata.Pairs(handoffPrefix+"protocol", handoffVersion, handoffPrefix+"generation", pending.next.id, handoffPrefix+"endpoint", pending.next.endpoint.listener.Addr().String())
	if g == pending.origin {
		carrier, _ := ctx.Value(apiConnContextKey{}).(*apiOwnedConn)
		if carrier != issued.carrier {
			return status.Error(codes.PermissionDenied, "handoff key requires the original captured channel")
		}
		headers.Set(handoffPrefix+"key", hex.EncodeToString(pending.key[:]))
	} else if g == pending.next {
		challenge := apiHeader(ctx, "challenge")
		if !validAPIHex(challenge, 64) {
			return status.Error(codes.InvalidArgument, "API handoff requires a fresh32-byte challenge")
		}
		body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(result)
		if err != nil {
			return status.Error(codes.Internal, "cannot encode API handoff status")
		}
		bodyHash := sha256.Sum256(body)
		ack := apiHeader(ctx, "ack")
		if pending.acknowledged {
			headers.Set(handoffPrefix+"acknowledged", "true")
		}
		if ack != "" && !pending.acknowledged {
			if !validAPIHex(ack, 64) || !hmac.Equal([]byte(ack), []byte(pending.mac("ack", challenge, ""))) {
				return status.Error(codes.PermissionDenied, "API handoff acknowledgement proof mismatch")
			}
			if h.closing {
				return status.Error(codes.Unavailable, "API owner closing")
			}
			pending.acknowledged = true
			pending.retiring = true
			pending.next.confirmed = pending
			headers.Set(handoffPrefix+"acknowledged", "true")
			h.workers.Add(1)
			go func() {
				defer h.workers.Done()
				err := pending.origin.close()
				if pending.origin.endpoint != pending.next.endpoint {
					err = errors.Join(err, pending.origin.endpoint.close())
				}
				h.mu.Lock()
				pending.closeErr = err
				if err == nil {
					h.removeGeneration(pending.origin)
					if pending.origin.endpoint != pending.next.endpoint {
						h.removeEndpoint(pending.origin.endpoint)
					}
					if pending.origin.confirmed != nil {
						pending.origin.confirmed.expireAuthentication()
						pending.origin.confirmed = nil
					}
					if h.pending == pending {
						h.pending = nil
					}
				}
				close(pending.done)
				h.mu.Unlock()
			}()
		}
		proofKind := "proof"
		if pending.acknowledged {
			proofKind = "accepted"
		}
		headers.Set(handoffPrefix+"proof", pending.mac(proofKind, challenge, hex.EncodeToString(bodyHash[:])))
	} else {
		return status.Error(codes.PermissionDenied, "API handoff ingress is not a participant")
	}
	return grpc.SetHeader(ctx, headers)
}

var (
	_ adapter.RuntimeAPIService = (*Service)(nil)
	_ daemon.RuntimeIngress     = (*apiGeneration)(nil)
)

// The proof hashes the exact protobuf body emitted by this API transport. The
// client retains the received bytes before decoding rather than re-encoding.
// This is the ordinary proto wire format, with deterministic map ordering.
type apiWireCodec struct{}

func (apiWireCodec) Name() string { return "proto" }
func (apiWireCodec) Marshal(value any) ([]byte, error) {
	message, ok := value.(proto.Message)
	if !ok {
		return nil, errors.New("non-protobuf API response")
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

func (apiWireCodec) Unmarshal(data []byte, value any) error {
	message, ok := value.(proto.Message)
	if !ok {
		return errors.New("non-protobuf API request")
	}
	return proto.Unmarshal(data, message)
}
