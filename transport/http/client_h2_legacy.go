//go:build !go1.27 || http2legacy || !badlinkname

package http

import (
	"net"
	"net/http"
	"errors"
	"github.com/sagernet/sing-box/common/httpclient"

	"golang.org/x/net/http2"
)

type http2ClientConn struct {
	*http2.ClientConn
	boundary *httpclient.RuntimeTransportBoundary
}

func newHTTP2ClientConn(transport *http2.Transport, conn net.Conn) (*http2ClientConn, error) {
	boundary:=httpclient.NewRuntimeTransportBoundary(nil)
	guarded,err:=boundary.GuardConnection(conn)
	if err!=nil{return nil,err}
	clientConn, err := transport.NewClientConn(guarded)
	if err != nil {
		return nil, errors.Join(err,boundary.Close())
	}
	return &http2ClientConn{ClientConn: clientConn,boundary:boundary}, nil
}

func (c *http2ClientConn) isClosed() bool {
	return c.State().Closed
}

func (c *http2ClientConn) reserveNewRequest() bool {
	return c.ReserveNewRequest()
}

func (c *http2ClientConn) roundTrip(request *http.Request) (*http.Response, error) {
	return c.boundary.RoundTrip(request,c.ClientConn.RoundTrip)
}

func(c *http2ClientConn)Close()error{return errors.Join(c.ClientConn.Close(),c.boundary.Close())}
