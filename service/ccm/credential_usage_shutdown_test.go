package ccm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	C "github.com/sagernet/sing-box/constant"
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
		_, err := refreshToken(ctx, client, &oauthCredentials{RefreshToken: "synthetic-test-only"})
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

func TestCredentialRefreshResponseBudget(t *testing.T) {
	const tokenJSON = `{"access_token":"updated","expires_in":3600}`
	for _, test := range []struct {
		name      string
		status    int
		body      string
		size      int
		readError bool
	}{
		{name: "exact budget", status: http.StatusOK, body: tokenJSON, size: maxOAuthResponseBytes},
		{name: "invalid JSON suffix", status: http.StatusOK, body: tokenJSON + ` {}`},
		{name: "oversized after valid JSON", status: http.StatusOK, body: tokenJSON, size: maxOAuthResponseBytes + 1},
		{name: "interrupted after valid JSON", status: http.StatusOK, body: tokenJSON, readError: true},
		{name: "provider diagnostic", status: http.StatusTooManyRequests, body: "provider diagnostic"},
		{name: "oversized error body", status: http.StatusTooManyRequests, body: "provider diagnostic", size: maxOAuthResponseBytes + 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := test.body
			if test.size != 0 {
				payload += strings.Repeat(" ", test.size-len(payload))
			}
			wire := strings.NewReader(payload)
			body := &trackingBody{Reader: wire}
			readError := errors.New("synthetic response read failure")
			if test.readError {
				body.Reader = io.MultiReader(wire, iotest.ErrReader(readError))
			}
			client := &http.Client{Transport: trackingRoundTrip(func(r *http.Request) (*http.Response, error) {
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > C.TCPTimeout || r.Method != http.MethodPost || r.URL.String() != oauth2TokenURL ||
					r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
					t.Fatal("OAuth request deadline, transport or format changed")
				}
				return &http.Response{StatusCode: test.status, Status: http.StatusText(test.status), Body: body, ContentLength: -1}, nil
			})}
			credentials := &oauthCredentials{AccessToken: "original", RefreshToken: "refresh"}
			next, err := refreshToken(t.Context(), client, credentials)
			if !body.closed {
				t.Fatal("OAuth response body was not closed")
			}
			if test.status == http.StatusOK && test.size == maxOAuthResponseBytes {
				if err != nil || next == nil || next.AccessToken != "updated" || next.RefreshToken != "refresh" || next.ExpiresAt <= time.Now().UnixMilli() {
					t.Fatalf("ordinary token response at the limit failed: %v", err)
				}
				return
			}
			if err == nil || next != nil || credentials.AccessToken != "original" {
				t.Fatal("failed or partial refresh changed credentials")
			}
			if test.size > maxOAuthResponseBytes {
				var oversize *http.MaxBytesError
				if !errors.As(err, &oversize) || oversize.Limit != maxOAuthResponseBytes || wire.Len() != test.size-maxOAuthResponseBytes-1 {
					t.Fatalf("OAuth response byte limit was not applied: %v, unread %d", err, wire.Len())
				}
			}
			if test.readError && !errors.Is(err, readError) {
				t.Fatalf("response read cause lost: %v", err)
			}
			if test.status != http.StatusOK && (!strings.Contains(err.Error(), http.StatusText(test.status)) ||
				strings.Contains(err.Error(), test.body) != (test.size == 0)) {
				t.Fatalf("provider status or bounded diagnostic changed: %v", err)
			}
		})
	}
}
