package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func newTestListener(t *testing.T) (*listener.Listener, net.Listener) {
	t.Helper()
	wrapped := listener.New(listener.Options{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
		Network: []string{"tcp"},
		Listen:  option.ListenOptions{},
	})
	tcpListener, err := wrapped.ListenTCP()
	if err != nil {
		t.Fatal(err)
	}
	return wrapped, tcpListener
}

func requireNotAccepting(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("API listener still accepts after close")
	}
}

func TestScopeCloseAfterHTTPServerServesClosesListenerOnce(t *testing.T) {
	wrapped, tcpListener := newTestListener(t)
	served := make(chan struct{})
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(served)
		w.WriteHeader(http.StatusNoContent)
	})}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	scope.Add(func() error {
		return closeHTTPListener(httpServer, wrapped)
	})
	go httpServer.Serve(tcpListener)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	response, err := client.Get("http://" + tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	<-served
	err = scope.Close()
	if err != nil {
		t.Fatalf("scope.Close() = %v; want nil", err)
	}
	requireNotAccepting(t, tcpListener.Addr().String())
}

func TestScopeCloseBeforeHTTPServeStillClosesListener(t *testing.T) {
	wrapped, tcpListener := newTestListener(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	// Start can reach ListenTCP before the Serve goroutine registers the socket.
	scope.Add(func() error {
		return closeHTTPListener(&http.Server{}, wrapped)
	})
	err := scope.Close()
	if err != nil {
		t.Fatalf("scope.Close() before Serve = %v; want nil", err)
	}
	requireNotAccepting(t, tcpListener.Addr().String())
}

type failingHTTPListener struct {
	entered   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	failure   error
}

func (l *failingHTTPListener) Accept() (net.Conn, error) {
	close(l.entered)
	<-l.closed
	return nil, net.ErrClosed
}

func (l *failingHTTPListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.failure
}

func (l *failingHTTPListener) Addr() net.Addr { return &net.TCPAddr{} }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestCloseHTTPListenerPreservesHTTPListenerFailure(t *testing.T) {
	failure := errors.New("HTTP listener close failed")
	httpListener := &failingHTTPListener{entered: make(chan struct{}), closed: make(chan struct{}), failure: failure}
	httpServer := &http.Server{}
	go httpServer.Serve(httpListener)
	<-httpListener.entered
	listenerClosed := false
	err := closeHTTPListener(httpServer, closerFunc(func() error {
		listenerClosed = true
		return net.ErrClosed
	}))
	if !errors.Is(err, failure) {
		t.Fatalf("closeHTTPListener() = %v; want original HTTP close failure", err)
	}
	if !listenerClosed {
		t.Fatal("listener was not closed after the HTTP server failed to close")
	}
}

func TestCloseHTTPListenerPreservesListenerFailure(t *testing.T) {
	failure := errors.New("API listener close failed")
	err := closeHTTPListener(&http.Server{}, closerFunc(func() error { return failure }))
	if !errors.Is(err, failure) {
		t.Fatalf("closeHTTPListener() = %v; want original listener close failure", err)
	}
}
