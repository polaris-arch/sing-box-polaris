// NewSource needs a network manager on Darwin and Windows.
//go:build !darwin && !windows

package local

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
	_, err := NewTransport(ctx, log.NewNOPFactory().Logger(), "local", option.LocalDNSServerOptions{})
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
