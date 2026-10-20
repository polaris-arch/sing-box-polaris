// NewSource needs a network manager on Darwin and Windows.
//go:build !darwin && !windows

package mdns

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestUnstartedTransportReleasesConfigSourceOnce(t *testing.T) {
	closed := 0
	original := closeConfigSource
	closeConfigSource = func(source *systemconfig.Source) error {
		closed++
		return original(source)
	}
	t.Cleanup(func() { closeConfigSource = original })
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	_, err := NewTransport(ctx, log.NewNOPFactory().Logger(), "mdns", option.MDNSDNSServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if closed != 0 {
		t.Fatal("config source closed while the construction scope is open")
	}
	err = scope.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("config source of an unstarted transport closed %d times, want 1", closed)
	}
}

func TestClosedConstructionScopeCannotReturnSuccessfulTransport(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	if err := scope.Close(); err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	transport, err := NewTransport(ctx, logger, "already-closed", option.MDNSDNSServerOptions{})
	if err == nil || transport != nil { t.Fatal("constructor returned an already-cleaned source") }
}

func TestStandaloneConstructionDoesNotPrematurelyCloseSource(t *testing.T) {
	closed := 0
	original := closeConfigSource
	closeConfigSource = func(source *systemconfig.Source) error { closed++; return original(source) }
	t.Cleanup(func() { closeConfigSource = original })
	transport, err := NewTransport(context.Background(), log.NewNOPFactory().Logger(), "standalone", option.MDNSDNSServerOptions{})
	if err != nil { t.Fatal(err) }
	if closed != 0 { t.Fatal("standalone constructor closed its live source") }
	if err := transport.(*Transport).close(); err != nil { t.Fatal(err) }
	if closed != 1 { t.Fatal("standalone source did not close exactly once") }
}
