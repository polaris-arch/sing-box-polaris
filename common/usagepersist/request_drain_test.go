package usagepersist

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestDrainKeepsFinalizerPendingUntilProducerExit(t *testing.T) {
	var drain RequestDrain
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var tail, flushed atomic.Bool
	handler := drain.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
		tail.Store(true)
	}))
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-entered
	select {
	case <-canceled:
		t.Fatal("live request was canceled before shutdown")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverClosed := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- drain.Close(ctx, func() error { close(serverClosed); return nil }, func() error {
			if !tail.Load() {
				t.Error("flushed before last producer update")
			}
			flushed.Store(true)
			return nil
		})
	}()
	<-serverClosed
	<-canceled
	cancel()
	if err := <-closeDone; err == nil {
		t.Fatal("missing pending close status")
	} else {
		var pending *PendingError
		if !errors.As(err, &pending) || !errors.Is(pending.Cause, context.Canceled) {
			t.Fatalf("unexpected pending status: %v", err)
		}
	}
	if flushed.Load() {
		t.Fatal("timeout pretended final flush completed")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("request admitted after close boundary")
	}
	close(release)
	<-requestDone
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := drain.Close(joined, func() error { t.Fatal("server closed twice"); return nil }, func() error { t.Fatal("flushed twice"); return nil }); err != nil {
		t.Fatal(err)
	}
	if !flushed.Load() {
		t.Fatal("retained finalizer did not finish")
	}
}

func TestRequestDrainReturnsFinalFlushError(t *testing.T) {
	var drain RequestDrain
	failure := errors.New("disk full")
	if err := drain.Close(context.Background(), func() error { return nil }, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("final persistence failure lost: %v", err)
	}
}

func TestRequestDrainContainsCallbackPanics(t *testing.T) {
	var drain RequestDrain
	finalized := false
	err := drain.Close(context.Background(), func() error {
		panic("server test panic")
	}, func() error {
		finalized = true
		panic("flush test panic")
	})
	if !finalized || err == nil || !strings.Contains(err.Error(), "server close") || !strings.Contains(err.Error(), "final usage flush") {
		t.Fatalf("panic containment lost cleanup/error: finalized=%v err=%v", finalized, err)
	}
	select {
	case <-drain.done:
	default:
		t.Fatal("panic left completion channel open")
	}
}
