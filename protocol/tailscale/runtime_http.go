//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter/outbound"
)

// acquireHTTPClient is installed at the native whole-operation boundary. Each
// returned client keeps the standard redirect policy and one immutable binding
// through the complete redirect chain. Native releases only after its original
// operation has returned; response bodies and transport carriers retain their
// own reservations beyond that return when necessary.
func (p *runtimeEndpointPhysical) acquireHTTPClient(ctx context.Context) (*http.Client, func(), error) {
	b, owned, release, err := p.bindingContext(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{Transport: &runtimeBoundHTTPTransport{binding: b, owned: owned}}, release, nil
}

type runtimeBoundHTTPTransport struct {
	binding *runtimeEndpointBinding
	owned   context.Context
}

func (t *runtimeBoundHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Preserve caller cancellation, deadlines and ordinary values. The inherited
	// capability is borrowed from this exact operation, never from publication.
	ctx := request.Context()
	ctx = context.WithValue(ctx, runtimeBindingContextKey{}, t.owned.Value(runtimeBindingContextKey{}))
	owned, release, err := t.binding.acquire(ctx)
	if err != nil {
		return nil, err
	}
	response, err := t.binding.transport.RoundTrip(request.Clone(owned))
	if response == nil || response.Body == nil {
		release()
		return response, err
	}
	fence := outbound.NewRuntimeIOFence(response.Body.Close)
	response.Body = &runtimeHTTPBody{body: response.Body, fence: fence}
	t.binding.holdCarrier(fence, release)
	if err != nil {
		return nil, errors.Join(err, fence.RuntimeCloseAndWait())
	}
	return response, nil
}
func (t *runtimeBoundHTTPTransport) CloseIdleConnections() {
	t.binding.transport.CloseIdleConnections()
}

type runtimeHTTPBody struct {
	body  io.ReadCloser
	fence *outbound.RuntimeIOFence
}

func (b *runtimeHTTPBody) Read(buffer []byte) (int, error) {
	release, err := b.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer release()
	return b.body.Read(buffer)
}
func (b *runtimeHTTPBody) Close() error { return b.fence.Close() }

// Only native whole-operation acquisition may issue requests. This original
// client remains the native idle-pool control surface and fails closed if an
// unconverted native path attempts a bare request.
type runtimeHTTPDispatcher struct{ physical *runtimeEndpointPhysical }

func (t *runtimeHTTPDispatcher) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("Tailscale HTTP request lacks whole-operation binding")
}

func (t *runtimeHTTPDispatcher) CloseIdleConnections() {
	p := t.physical
	p.mu.Lock()
	bindings := make([]*runtimeEndpointBinding, 0, len(p.attachments))
	for b := range p.attachments {
		bindings = append(bindings, b)
	}
	p.mu.Unlock()
	for _, b := range bindings {
		release, err := b.reserve(false)
		if err != nil {
			continue
		}
		b.transport.CloseIdleConnections()
		release()
	}
}
