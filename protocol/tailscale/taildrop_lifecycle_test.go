//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func lifecycleManager(t *testing.T) *taildropManager {
	t.Helper()
	return newTaildropManager(context.Background(), nil, "test", t.TempDir(), nil)
}

func awaitTaildropDrain(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Taildrop drain did not finish")
	}
}

func TestTaildropSealJoinsAdmittedIO(t *testing.T) {
	m := lifecycleManager(t)
	if !m.beginIO() {
		t.Fatal("initial admission rejected")
	}
	m.seal()
	if m.beginIO() {
		t.Fatal("admitted after seal")
	}
	done := make(chan struct{})
	go func() { m.wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("drain returned before admitted IO")
	default:
	}
	m.endIO()
	awaitTaildropDrain(t, done)
	m.close() // Idempotent.
}

func TestTaildropAdmissionSealRace(t *testing.T) {
	for range 100 {
		m := lifecycleManager(t)
		var workers sync.WaitGroup
		for range 16 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if m.beginIO() {
					m.endIO()
				}
			}()
		}
		m.close()
		workers.Wait()
		if m.beginIO() {
			t.Fatal("admission reopened")
		}
	}
}

func TestTaildropSealClosesReturnedFiles(t *testing.T) {
	m := lifecycleManager(t)
	if err := os.WriteFile(filepath.Join(m.directory, "received"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, size, err := m.openFile("received")
	if err != nil || size != 7 {
		t.Fatalf("open: size=%d err=%v", size, err)
	}
	m.close()
	if _, err = reader.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after drain: %v", err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.openFile("received"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("open after drain: %v", err)
	}
	if err = m.deleteFile("received"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("delete after drain: %v", err)
	}
	if _, err = os.Stat(filepath.Join(m.directory, "received")); err != nil {
		t.Fatalf("closed operation changed file: %v", err)
	}
}

func TestTaildropSealStopsTimersAndStartupIO(t *testing.T) {
	m := lifecycleManager(t)
	name := "sample.peer.partial"
	if err := os.WriteFile(filepath.Join(m.directory, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m.scheduleDelete(name, time.Hour)
	m.cancelDelete(name) // Successful Stop must release its callback lease.
	m.scheduleDelete(name, time.Hour)
	m.close() // Must not wait an hour for a stopped callback.
	m.start()
	m.deleteExpired(name)
	if _, err := os.Stat(filepath.Join(m.directory, name)); err != nil {
		t.Fatalf("post-close callback touched file: %v", err)
	}
}

func TestTaildropSealJoinsInterrupts(t *testing.T) {
	m := lifecycleManager(t)
	entered, release := make(chan struct{}), make(chan struct{})
	m.incoming[taildropIncomingKey{senderID: "peer", name: "file"}] = &taildropIncomingFile{
		interrupt: func() { close(entered); <-release },
	}
	m.seal()
	awaitTaildropDrain(t, entered)
	done := make(chan struct{})
	go func() { m.wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("drain returned while interrupt callback was running")
	default:
	}
	close(release)
	awaitTaildropDrain(t, done)
}

type lifecycleBlockingReader struct {
	entered chan struct{}
	release chan struct{}
}

func (r *lifecycleBlockingReader) Read([]byte) (int, error) {
	close(r.entered)
	<-r.release
	return 0, io.EOF
}

func TestTaildropSendReaderJoinsLateTransportRead(t *testing.T) {
	source := &lifecycleBlockingReader{entered: make(chan struct{}), release: make(chan struct{})}
	reader := &taildropSendReader{reader: source}
	readDone, closeDone := make(chan struct{}), make(chan struct{})
	go func() { _, _ = reader.Read(make([]byte, 1)); close(readDone) }()
	awaitTaildropDrain(t, source.entered)
	go func() { reader.close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Fatal("source lease released with Read in flight")
	default:
	}
	close(source.release)
	awaitTaildropDrain(t, readDone)
	awaitTaildropDrain(t, closeDone)
	if _, err := reader.Read(nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late transport read was admitted: %v", err)
	}
}

func TestTaildropPublicSendRejectsSealedManager(t *testing.T) {
	m := lifecycleManager(t)
	m.close()
	endpoint := &Endpoint{taildrop: m}
	err := endpoint.SendTaildropFile(context.Background(), "peer", "file", 0, nil, nil)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("send after seal: %v", err)
	}
}

func TestTaildropReceiveRejectsSealedManager(t *testing.T) {
	m := lifecycleManager(t)
	m.close()
	// A nil reader would panic if the rejected request reached io.Copy.
	err := m.putFile("peer", "Peer", "file", nil, 0, 0, nil)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("receive after seal: %v", err)
	}
	entries, err := os.ReadDir(m.directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected receive touched directory: entries=%d err=%v", len(entries), err)
	}
}

func TestTaildropTimerSealRace(t *testing.T) {
	for range 100 {
		m := lifecycleManager(t)
		name := "sample.peer.partial"
		m.scheduleDelete(name, 0)
		m.cancelDelete(name)
		m.scheduleDelete(name, time.Hour)
		done := make(chan struct{})
		go func() { m.close(); close(done) }()
		awaitTaildropDrain(t, done)
		// A stale callback must not remove the replacement timer from the
		// registry and leave its lease waiting for the one-hour expiry.
	}
}

func TestTaildropDeadlineDoesNotPretendToDrain(t *testing.T) {
	m := lifecycleManager(t)
	if !m.beginIO() {
		t.Fatal("initial admission rejected")
	}
	m.seal()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.waitContext(ctx); !errors.Is(err, errTaildropDrainIncomplete) {
		t.Fatalf("blocked owner must report failed retirement: %v", err)
	}
	select {
	case <-m.drainDone:
		t.Fatal("caller timeout forged actual IO completion")
	default:
	}
	if m.beginIO() {
		t.Fatal("deadline reopened admission")
	}
	m.endIO()
	awaitTaildropDrain(t, m.drainDone)
	if err := m.waitContext(context.Background()); !errors.Is(err, errTaildropDrainIncomplete) {
		t.Fatalf("repeat close erased original incomplete terminal: %v", err)
	}
}

func TestTaildropSynchronousCallbackCloseCanUnwind(t *testing.T) {
	m := lifecycleManager(t)
	if !m.beginIO() {
		t.Fatal("initial admission rejected")
	}
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		defer m.endIO()
		// Simulates a callback within admitted IO synchronously closing its
		// owner. The production caller uses five seconds; this test shortens
		// only the caller deadline, not the required real-IO completion.
		m.seal()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if err := m.waitContext(ctx); !errors.Is(err, errTaildropDrainIncomplete) {
			t.Errorf("self-dependent close must fail at deadline: %v", err)
		}
		select {
		case <-m.drainDone:
			t.Error("callback still owns a lease but drain was reported complete")
		default:
		}
	}()
	awaitTaildropDrain(t, callbackDone)
	awaitTaildropDrain(t, m.drainDone)
}

func TestTaildropIncompleteDrainSurvivesScopeCancellationFilter(t *testing.T) {
	m := lifecycleManager(t)
	if !m.beginIO() {
		t.Fatal("initial admission rejected")
	}
	defer m.endIO()
	m.seal()
	scope := adapter.NewScope(context.Background(), nil)
	scope.Add(func() error {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return m.waitContext(ctx)
	})
	if err := scope.Close(); !errors.Is(err, errTaildropDrainIncomplete) {
		t.Fatalf("Scope swallowed incomplete drain as ordinary cancellation: %v", err)
	}
}
