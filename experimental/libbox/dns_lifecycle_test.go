package libbox

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitDNSFinished(t *testing.T, finished <-chan struct{}) {
	t.Helper()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation registration did not finish")
	}
}

func TestDNSBackgroundRegistrationStopsWithoutPermanentWaiter(t *testing.T) {
	before := runtime.NumGoroutine()
	var invoked atomic.Int32
	for range 2000 {
		registration := newDNSCancelRegistration(context.Background(), func() error { invoked.Add(1); return nil })
		awaitDNSFinished(t, registration.stopAndDetach())
		registration.access.Lock()
		if registration.callback != nil || registration.stop != nil {
			t.Fatal("stopped registration retained its callback or context association")
		}
		registration.access.Unlock()
	}
	runtime.GC()
	if invoked.Load() != 0 || runtime.NumGoroutine() > before+4 {
		t.Fatal("successful Background queries retained cancellation waiters")
	}
}

func TestDNSPreCancelledRegistrationAndRepeatedStopShareCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	registration := newDNSCancelRegistration(ctx, func() error { close(entered); <-release; return nil })
	awaitDNSFinished(t, entered)
	first, second := registration.stopAndDetach(), registration.stopAndDetach()
	if first != second {
		t.Fatal("repeated stop manufactured another completion state")
	}
	select {
	case <-second:
		t.Fatal("already-stopped association was mistaken for callback exit")
	default:
	}
	close(release)
	awaitDNSFinished(t, first)
	awaitDNSFinished(t, registration.stopAndDetach())
	registration.access.Lock()
	defer registration.access.Unlock()
	if registration.callback != nil || registration.stop != nil {
		t.Fatal("initial registration publication resurrected completed references")
	}
}

func TestDNSRunningCancellationStopWaitsForActualExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("injected cancellation failure")
	registration := newDNSCancelRegistration(ctx, func() error { close(entered); <-release; return failure })
	cancel()
	awaitDNSFinished(t, entered)
	finished := registration.stopAndDetach()
	select {
	case <-finished:
		t.Fatal("stop mistook a running callback for completion")
	default:
	}
	close(release)
	awaitDNSFinished(t, finished)
	if !errors.Is(registration.result(), failure) {
		t.Fatal("running cancellation error was lost")
	}
}

func TestDNSCancellationRegistrationRaceAndPanicCompletion(t *testing.T) {
	for range 300 {
		ctx, cancel := context.WithCancel(context.Background())
		var invoked atomic.Int32
		registration := newDNSCancelRegistration(ctx, func() error { invoked.Add(1); return nil })
		var running sync.WaitGroup
		running.Add(2)
		go func() { defer running.Done(); cancel() }()
		go func() { defer running.Done(); registration.stopAndDetach() }()
		running.Wait()
		awaitDNSFinished(t, registration.stopAndDetach())
		if invoked.Load() > 1 {
			t.Fatal("cancellation callback ran more than once")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	registration := newDNSCancelRegistration(ctx, func() error { close(entered); panic("injected cancellation panic") })
	cancel()
	awaitDNSFinished(t, entered)
	awaitDNSFinished(t, registration.finished)
	if registration.result() == nil {
		t.Fatal("callback panic disappeared from local bookkeeping")
	}
}

func TestDNSUpperCancellationDoesNotReleasePlatformLease(t *testing.T) {
	var gate dnsCallGate
	ctx, cancel := context.WithCancel(context.Background())
	lease, err := gate.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entered, actualReturn := make(chan struct{}), make(chan struct{})
	returned := make(chan struct{})
	go func() {
		close(entered)
		<-actualReturn
		lease.returned()
		close(returned)
	}()
	awaitDNSFinished(t, entered)
	cancel()
	awaitDNSFinished(t, lease.ctx.Done())
	cancels, snapshot := gate.sealAndSnapshot()
	for _, requestCancel := range cancels {
		requestCancel()
	}
	if !snapshot.sealed || snapshot.inFlight != 1 || gate.snapshot().inFlight != 1 {
		t.Fatal("upper cancellation or seal erased an in-flight platform call")
	}
	if _, err = gate.begin(context.Background()); !errors.Is(err, errDNSCallAdmissionClosed) {
		t.Fatal("sealed transport admitted another platform call")
	}
	close(actualReturn)
	awaitDNSFinished(t, returned)
	if gate.snapshot().inFlight != 0 || lease.ctx != nil || lease.cancel != nil {
		t.Fatal("actual return did not release local lease references")
	}
}

func TestDNSCallbackCannotSelfJoinAndRetainsLeaseUntilExit(t *testing.T) {
	var gate dnsCallGate
	lease, err := gate.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	returned, release := make(chan struct{}), make(chan struct{})
	var registration *dnsCancelRegistration
	registration = newDNSCancelRegistration(ctx, func() error {
		lease.returned(registration)
		close(returned)
		<-release
		return nil
	})
	cancel()
	awaitDNSFinished(t, returned)
	if gate.snapshot().inFlight != 1 {
		t.Fatal("callback self-unregistration prematurely released the lease")
	}
	close(release)
	awaitDNSFinished(t, registration.finished)
	deadline := time.Now().Add(time.Second)
	for gate.snapshot().inFlight != 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if gate.snapshot().inFlight != 0 {
		t.Fatal("drain task did not release the lease after callback exit")
	}
	lease.returned(registration)
}

func TestDNSAdmissionAndSealRace(t *testing.T) {
	for range 300 {
		var gate dnsCallGate
		start := make(chan struct{})
		admitted := make(chan *dnsCallLease, 1)
		sealed := make(chan struct{})
		go func() {
			<-start
			lease, _ := gate.begin(context.Background())
			admitted <- lease
		}()
		go func() {
			<-start
			cancels, _ := gate.sealAndSnapshot()
			for _, cancel := range cancels {
				cancel()
			}
			close(sealed)
		}()
		close(start)
		lease := <-admitted
		awaitDNSFinished(t, sealed)
		if lease != nil {
			if gate.snapshot().inFlight != 1 {
				t.Fatal("seal lost a previously admitted call")
			}
			lease.returned()
		}
		if _, err := gate.begin(context.Background()); !errors.Is(err, errDNSCallAdmissionClosed) || gate.snapshot().inFlight != 0 {
			t.Fatal("admission was not linearized with seal")
		}
	}
}

func TestDNSReturnedLeaseRetainsCancellationFailureSeparately(t *testing.T) {
	var gate dnsCallGate
	lease, err := gate.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	failure := errors.New("cancellation returned an error")
	registration := newDNSCancelRegistration(ctx, func() error { return failure })
	cancel()
	awaitDNSFinished(t, registration.finished)
	lease.returned(registration)
	_, snapshot := gate.sealAndSnapshot()
	if snapshot.inFlight != 0 || !errors.Is(snapshot.failure, failure) {
		t.Fatal("local callback failure was erased when its lease ended")
	}
	// No operational Close result or Exact proof is produced by this snapshot.
}

func TestDNSCompletionBeforeArmCannotPublishCancellation(t *testing.T) {
	var invoked atomic.Int32
	registration := makeDNSCancelRegistration(func() error { invoked.Add(1); return nil })
	awaitDNSFinished(t, registration.stopAndDetach())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	registration.arm(ctx)
	awaitDNSFinished(t, registration.finished)
	if invoked.Load() != 0 || registration.callback != nil || registration.stop != nil {
		t.Fatal("completion-before-arm resurrected cancellation capability")
	}
}

func TestDNSReturnedDrainOwnsRegistrationSlice(t *testing.T) {
	var gate dnsCallGate
	lease, err := gate.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("original registration failure")
	registration := newDNSCancelRegistration(ctx, func() error { close(entered); <-release; return failure })
	cancel()
	awaitDNSFinished(t, entered)
	input := []*dnsCancelRegistration{registration}
	lease.returned(input...)
	other := newDNSCancelRegistration(context.Background(), func() error { t.Error("reused slice callback ran"); return nil })
	input[0] = other
	other.stopAndDetach()
	if gate.snapshot().inFlight != 1 {
		t.Fatal("caller slice reuse ended a running original registration")
	}
	close(release)
	awaitDNSFinished(t, registration.finished)
	deadline := time.Now().Add(time.Second)
	for gate.snapshot().inFlight != 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !errors.Is(gate.snapshot().failure, failure) || gate.snapshot().inFlight != 0 {
		t.Fatal("drain task followed reused caller slice instead of its own snapshot")
	}
}
