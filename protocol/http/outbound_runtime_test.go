package http

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestHTTPOutboundConstructorOwnsClientBeforeStart(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	component, err := NewOutbound(ctx, nil, logger, "proxy", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080},
		Version:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound := component.(*Outbound)
	if !outbound.constructionOwned {
		t.Fatal("constructor did not bind its client owner")
	}
	// Simulate a later constructor failing; Start has never been invoked.
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("unstarted client survived constructor rollback: %v", err)
	}
}

func TestHTTPOutboundCanceledConstructionScope(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	parent, cancel := context.WithCancel(context.Background())
	scope := adapter.NewScope(parent, logger)
	cancel()
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	component, err := NewOutbound(ctx, nil, logger, "proxy", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080},
		Version:       1,
	})
	if component != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scope produced outbound: %v, %v", component, err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPOutboundStandaloneKeepsLifecycleOwnership(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	component, err := NewOutbound(context.Background(), nil, logger, "proxy", option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080},
		Version:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound := component.(*Outbound)
	if outbound.constructionOwned {
		t.Fatal("standalone constructor claimed a nonexistent scope")
	}
	scope := adapter.NewScope(context.Background(), logger)
	if err := outbound.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("standalone lifecycle did not close client: %v", err)
	}
}
