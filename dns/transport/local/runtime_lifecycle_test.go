package local

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
)

type barrierResolved struct{ callback chan func(*mDNS.Msg, error) }

func (*barrierResolved) Start() error                  { return nil }
func (*barrierResolved) Close() error                  { return nil }
func (*barrierResolved) Reset()                        {}
func (*barrierResolved) SetKeepIdleConnections(bool)   {}
func (*barrierResolved) CloseIdleConnections()         {}
func (*barrierResolved) Environment() []string         { return nil }
func (*barrierResolved) ServerAddresses() []netip.Addr { return nil }
func (r *barrierResolved) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	r.callback <- callback
}

func TestLocalCancellationDoesNotReleaseUncompletedCallback(t *testing.T) {
	var transport *Transport
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "local-callback", Sequence: 1}, nil, func() error { return transport.close() })
	if err != nil {
		t.Fatal(err)
	}
	root, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	resolver := &barrierResolved{callback: make(chan func(*mDNS.Msg, error), 1)}
	transport = &Transport{ctx: adapter.ContextWithRuntimeResourceSource(context.Background(), owner), logger: log.NewNOPFactory().Logger(), preferredResolver: &PreferredDomainResolver{}, resolved: resolver}
	ctx, cancel := context.WithCancel(adapter.ContextWithRuntimeResourceLease(context.Background(), root))
	request := new(mDNS.Msg)
	request.SetQuestion("retained.example.", mDNS.TypeA)
	callbackEntered, callbackMayReturn := make(chan struct{}), make(chan struct{})
	transport.ExchangeAsync(ctx, request, func(*mDNS.Msg, error) { close(callbackEntered); <-callbackMayReturn })
	callback := <-resolver.callback
	owner.Seal()
	root.Release()
	cancel()
	transport.StopRuntimeOperations()
	select {
	case <-owner.Closed():
		t.Fatal("cancellation released a pending foreign callback")
	default:
	}
	go callback(nil, context.Canceled)
	select {
	case <-callbackEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not start")
	}
	select {
	case <-owner.Closed():
		t.Fatal("callback stack was not retained")
	default:
	}
	close(callbackMayReturn)
	select {
	case <-owner.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("resource did not close after actual callback completion")
	}
}
