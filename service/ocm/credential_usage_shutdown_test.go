package ocm

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type usageRefreshTransport struct {
	entered chan struct{}
}

func (t *usageRefreshTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	close(t.entered)
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestUsageShutdownCanCancelCredentialRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &usageRefreshTransport{entered: make(chan struct{})}
	client := &http.Client{Transport: transport}
	done := make(chan error, 1)
	go func() {
		_, err := refreshToken(ctx, client, &oauthCredentials{Tokens: &tokenData{RefreshToken: "synthetic-test-only"}})
		done <- err
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("refresh never reached transport")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("refresh lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh ignored request cancellation")
	}
}
