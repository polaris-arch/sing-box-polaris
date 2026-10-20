package runtimegraph

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDNSRefreshOwnerStopCancelsBeforeDrain(t *testing.T) {
	owner := NewDNSRefreshOwner(context.Background())
	operation, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	owner.Stop()
	select {
	case <-owner.Context().Done():
	default:
		t.Fatal("Stop did not cancel active work")
	}
	if _, err := owner.Acquire(); err == nil {
		t.Fatal("admitted after seal")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Wait(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("false completion: %v", err)
	}
	operation.Release()
	operation.Release()
	owner.Stop()
	ctx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err := owner.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRefreshOwnerAdmissionSealRace(t *testing.T) {
	for range 100 {
		owner := NewDNSRefreshOwner(context.Background())
		gate := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-gate
			if operation, err := owner.Acquire(); err == nil {
				operation.Release()
			}
		}()
		go func() { defer group.Done(); <-gate; owner.Stop() }()
		close(gate)
		group.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := owner.Wait(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		owner.resource.mu.Lock()
		refs := owner.resource.refs
		owner.resource.mu.Unlock()
		if refs != 0 {
			t.Fatalf("leaked operations: %d", refs)
		}
	}
}

func TestDNSRefreshOwnerWaitDoesNotCancelOperations(t *testing.T) {
	host, cancelHost := context.WithCancel(context.Background())
	defer cancelHost()
	owner := NewDNSRefreshOwner(host)
	operation, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	wait, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if err := owner.Wait(wait); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if owner.Context().Err() != nil {
		t.Fatal("wait canceled operational context")
	}
	cancelHost()
	if owner.Context().Err() == nil {
		t.Fatal("host shutdown not inherited")
	}
	operation.Release()
	owner.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
