//go:build with_acme

package tls

import (
	"context"
	"io"
	"net/http"
	"sync"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

// Certmagic DNS cleanup intentionally starts a new Background context. Admission
// here attaches a new owned callback capability, never an old request/graph lease.
// It is valid only until the enclosing synchronous worker and callback fence join.
type runtimeACMETransport struct {
	inner http.RoundTripper
	owner *RuntimeACME
}

func (t *runtimeACMETransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, release, err := t.owner.beginCallback(request.Context())
	if err != nil {
		return nil, err
	}
	response, err := t.inner.RoundTrip(request.Clone(ctx))
	if err != nil || response == nil || response.Body == nil {
		release()
		return response, err
	}
	response.Body = &runtimeACMEBody{ReadCloser: response.Body, release: release, record: t.owner.recordCleanup}
	return response, nil
}

func (t *runtimeACMETransport) CloseIdleConnections() {
	_, release, err := t.owner.beginCallback(context.Background())
	if err != nil {
		return
	}
	defer release()
	if closer, ok := t.inner.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type runtimeACMEBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
	record  func(error)
	err     error
}

func (b *runtimeACMEBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.record(b.err); b.release() })
	return b.err
}

type runtimeACMEDNSSolver struct {
	inner acmez.Solver
	owner *RuntimeACME
}

func (s *runtimeACMEDNSSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	ctx, release, err := s.owner.beginCallback(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.inner.Present(ctx, challenge)
}

func (s *runtimeACMEDNSSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	ctx, release, err := s.owner.beginCallback(ctx)
	if err != nil {
		return err
	}
	defer release()
	if waiter, ok := s.inner.(acmez.Waiter); ok {
		return waiter.Wait(ctx, challenge)
	}
	return nil
}

func (s *runtimeACMEDNSSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	ctx, release, err := s.owner.beginCallback(ctx)
	if err != nil {
		return err
	}
	defer release()
	err = s.inner.CleanUp(ctx, challenge)
	s.owner.recordCleanup(err)
	return err
}
