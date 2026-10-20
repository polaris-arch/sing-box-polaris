package v2raygrpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	boundary      *httpclient.RuntimeTransportBoundary
	source        adapter.RuntimeResourceSource
	closed        bool
	connecting    chan struct{}
	admitOwned    func(context.Context) (context.Context, func(), error)
	connectCancel context.CancelFunc
	ctx           context.Context
	dialer        N.Dialer
	serverAddr    string
	serviceName   string
	dialOptions   []grpc.DialOption
	conn          atomic.Pointer[grpc.ClientConn]
	connAccess    sync.Mutex
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayGRPCOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	client := &Client{ctx: ctx, dialer: dialer, serverAddr: serverAddr.String(), serviceName: options.ServiceName}
	client.source, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	client.boundary = httpclient.NewRuntimeTransportBoundary(client.closeConnection)
	var err error
	client.admitOwned, err = client.boundary.RegisterRuntimeOwner(ctx)
	if err != nil {
		return nil, err
	}
	var dialOptions []grpc.DialOption
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(&TLSTransportCredentials{config: tlsConfig.Clone(), boundary: client.boundary}))
		if tlsConfig.ServerName() != "" {
			dialOptions = append(dialOptions, grpc.WithAuthority(tlsConfig.ServerName()))
		}
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if options.IdleTimeout > 0 {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Duration(options.IdleTimeout),
			Timeout:             time.Duration(options.PingTimeout),
			PermitWithoutStream: options.PermitWithoutStream,
		}))
	}
	dialOptions = append(dialOptions, grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  500 * time.Millisecond,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   19 * time.Second,
		},
		MinConnectTimeout: 5 * time.Second,
	}))
	dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, server string) (net.Conn, error) {
		return client.dialPhysical(ctx, server)
	}))
	//nolint:staticcheck
	dialOptions = append(dialOptions, grpc.WithReturnConnectionError())
	client.dialOptions = dialOptions
	return client, nil
}

// Automatic reconnect is concrete transport-owned work. Its registration
// binds this boundary to the exact constructor owner and captured dependency
// closure, without choosing another stream's graph or holding an idle lease.
func (c *Client) dialPhysical(ctx context.Context, server string) (net.Conn, error) {
	return c.boundary.Dial(ctx, func(ctx context.Context) (net.Conn, error) {
		owned, release, err := c.admitOwned(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		if c.source != nil {
			owned, err = outbound.ContextForRuntimeOwnedSession(owned, c.source)
			if err != nil {
				return nil, err
			}
		}
		return c.dialer.DialContext(owned, N.NetworkTCP, M.ParseSocksaddr(server))
	})
}

func (c *Client) connect(ctx context.Context) (*grpc.ClientConn, error) {
	for {
		c.connAccess.Lock()
		if c.closed {
			c.connAccess.Unlock()
			return nil, net.ErrClosed
		}
		if conn := c.conn.Load(); conn != nil && conn.GetState() != connectivity.Shutdown {
			c.connAccess.Unlock()
			return conn, nil
		}
		if pending := c.connecting; pending != nil {
			c.connAccess.Unlock()
			select {
			case <-pending:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		pending := make(chan struct{})
		c.connecting = pending
		dialCtx, cancel := context.WithCancel(ctx)
		c.connectCancel = cancel
		c.connAccess.Unlock()
		//nolint:staticcheck
		conn, err := grpc.DialContext(dialCtx, c.serverAddr, c.dialOptions...)
		c.connAccess.Lock()
		closed := c.closed
		if err == nil && !closed {
			c.conn.Store(conn)
		}
		c.connecting = nil
		c.connectCancel = nil
		close(pending)
		c.connAccess.Unlock()
		cancel()
		if err != nil {
			return nil, err
		}
		if closed {
			c.boundary.RecordClose(conn.Close())
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, c.source)
	if err != nil {
		return nil, err
	}
	leave, err := c.boundary.Acquire()
	if err != nil {
		release()
		return nil, err
	}
	defer leave()
	conn, err := c.dialStream(ctx)
	if err != nil {
		release()
		return nil, err
	}
	return outbound.WrapRuntimeConn(ctx, release, conn), nil
}

func (c *Client) dialStream(ctx context.Context) (net.Conn, error) {
	clientConn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	client := NewGunServiceClient(clientConn).(GunServiceCustomNameClient)
	streamCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	propagationDone := make(chan struct{})
	stopPropagation := context.AfterFunc(ctx, func() {
		defer close(propagationDone)
		cancel(context.Cause(ctx))
	})
	stream, err := client.TunCustomName(streamCtx, c.serviceName)
	if err != nil {
		if !stopPropagation() {
			<-propagationDone
		}
		cancel(err)
		return nil, err
	}
	if !stopPropagation() {
		<-propagationDone
		cancel(context.Cause(ctx))
		return nil, context.Cause(ctx)
	}
	return NewGRPCConn(stream, cancel), nil
}

func (c *Client) closeConnection() error {
	c.connAccess.Lock()
	c.closed = true
	conn := c.conn.Swap(nil)
	cancel := c.connectCancel
	c.connAccess.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}
func (c *Client) Close() error               { return c.boundary.RuntimeCloseAndWait() }
func (c *Client) RuntimeCloseAndWait() error { return c.Close() }

func (c *Client) StopRuntimeOperations() { c.boundary.StopRuntimeOperations() }
