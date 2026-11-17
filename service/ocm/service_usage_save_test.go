package ocm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/usagepersist"
	"github.com/sagernet/sing/service/filemanager"
)

func TestUsageSaveSchedulingCoalescesRequests(t *testing.T) {
	u := &AggregatedUsage{lastSaveTime: time.Now()}
	u.scheduleSave()
	u.saveMutex.Lock()
	first := u.saveTimer
	u.saveMutex.Unlock()
	for i := 0; i < 1000; i++ {
		u.scheduleSave()
	}
	u.saveMutex.Lock()
	if u.saveTimer != first || !u.pendingSave || !u.saveDirty {
		t.Error("updates did not coalesce into one pending timer")
	}
	u.saveMutex.Unlock()
	u.cancelPendingSave()
	u.saveMutex.Lock()
	defer u.saveMutex.Unlock()
	if u.pendingSave || u.saveTimer != nil {
		t.Fatal("stopped timer retained ownership")
	}
}

func TestUsageConcurrentExplicitSavesSerializeRename(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := u.Save(); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	data, err := os.ReadFile(u.filePath)
	if err != nil || !json.Valid(data) {
		t.Fatalf("final snapshot invalid: %v", err)
	}
	if _, err := os.Stat(u.filePath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains: %v", err)
	}
}

func waitUsageSaveState(t *testing.T, u *AggregatedUsage, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		u.saveMutex.Lock()
		ok := ready()
		u.saveMutex.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for save state")
}

func TestUsageUpdateDuringRunningSaveSurvivesCancel(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	u.saveWriteMutex.Lock()
	locked := true
	defer func() {
		if locked {
			u.saveWriteMutex.Unlock()
		}
		u.cancelPendingSave()
	}()
	u.scheduleSave()
	waitUsageSaveState(t, u, func() bool { return !u.lastSaveAttempt.IsZero() })
	// The callback has fired and is blocked on the transaction lock. Stop must
	// fail without releasing its ownership, and a real update must stay dirty.
	if err := u.AddUsage("gpt-test", 200000, 1, 1, 0, "default", "test"); err != nil {
		t.Fatal(err)
	}
	u.cancelPendingSave()
	u.saveMutex.Lock()
	runningTimer := u.saveTimer
	if !u.pendingSave || !u.saveDirty {
		t.Error("active callback or dirty update lost after Stop(false)")
	}
	u.saveMutex.Unlock()
	u.saveWriteMutex.Unlock()
	locked = false
	waitUsageSaveState(t, u, func() bool {
		return !u.lastSaveTime.IsZero() && u.pendingSave && u.saveDirty && u.saveTimer != runningTimer
	})
	u.saveMutex.Lock()
	firstSave := u.lastSaveTime
	// Advance only the owned timer rather than waiting a production minute.
	u.saveTimer.Reset(0)
	u.saveMutex.Unlock()
	waitUsageSaveState(t, u, func() bool { return u.lastSaveTime.After(firstSave) && !u.pendingSave })
	data, err := os.ReadFile(u.filePath)
	if err != nil || !json.Valid(data) {
		t.Fatalf("follow-up snapshot invalid: %v", err)
	}
}

func TestUsageFailedAttemptThrottlesNewUpdates(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "missing", "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	u.scheduleSave()
	waitUsageSaveState(t, u, func() bool { return !u.lastSaveAttempt.IsZero() && !u.pendingSave })
	u.scheduleSave()
	u.saveMutex.Lock()
	attempt := u.lastSaveAttempt
	timer := u.saveTimer
	u.saveMutex.Unlock()
	for i := 0; i < 1000; i++ {
		u.scheduleSave()
	}
	u.saveMutex.Lock()
	if !u.lastSaveAttempt.Equal(attempt) || u.saveTimer != timer || !u.pendingSave {
		t.Error("failed save caused immediate retry storm")
	}
	u.saveMutex.Unlock()
	u.cancelPendingSave()
}

func TestUsageCloseJoinsActiveSaveAndFinalFlush(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	u.saveWriteMutex.Lock()
	locked := true
	defer func() {
		if locked {
			u.saveWriteMutex.Unlock()
		}
	}()
	u.scheduleSave()
	waitUsageSaveState(t, u, func() bool { return !u.lastSaveAttempt.IsZero() })
	done := make(chan error, 1)
	go func() { done <- u.Close() }()
	waitUsageSaveState(t, u, func() bool { return u.saveStopping })
	select {
	case <-done:
		t.Fatal("Close returned before active writer joined")
	default:
	}
	u.saveWriteMutex.Unlock()
	locked = false
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(u.filePath)
	if err != nil || !json.Valid(data) {
		t.Fatalf("final snapshot missing: %v", err)
	}
	if err := u.Save(); err == nil {
		t.Fatal("closed writer accepted a new save")
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUsageCloseReturnsFinalFlushFailure(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "missing", "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	if err := u.Close(); err == nil {
		t.Fatal("failed final flush reported success")
	}
}

func TestRequestDrainFlushesLastUsageEvent(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	var drain usagepersist.RequestDrain
	entered := make(chan struct{})
	handler := drain.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		if err := u.AddUsage("gpt-test", 200000, 1, 1, 0, "default", "test"); err != nil {
			t.Error(err)
		}
	}))
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := drain.Close(ctx, func() error { return nil }, u.Close); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(u.filePath)
	if err != nil {
		t.Fatal(err)
	}
	var saved AggregatedUsageJSON
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Combinations) != 1 || saved.Combinations[0].Total.RequestCount != 1 {
		t.Fatalf("last usage event not flushed: %+v", saved.Combinations)
	}
}

func TestIncompleteObservationsRoundTripWithoutInventedUsage(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "incomplete.json"), lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = u.Close() })
	defer u.cancelPendingSave()
	u.MarkIncomplete()
	if err := u.Save(); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	v := &AggregatedUsage{ctx: context.Background(), filePath: u.filePath}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.Load(); err != nil {
		t.Fatal(err)
	}
	if v.ToJSON().IncompleteObservations != 1 || len(v.Combinations) != 0 {
		t.Fatal("missing accounting became zero usage")
	}
}

func TestLegacyUsageWithoutIncompleteFieldLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte(`{"combinations":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &AggregatedUsage{ctx: context.Background(), filePath: path}
	t.Cleanup(func() { _ = u.Close() })
	if err := u.Load(); err != nil {
		t.Fatal(err)
	}
	if u.ToJSON().IncompleteObservations != 0 {
		t.Fatal("legacy migration invented incomplete observations")
	}
}

func TestRequestDrainFlushesLastIncompleteObservation(t *testing.T) {
	u := &AggregatedUsage{ctx: context.Background(), filePath: filepath.Join(t.TempDir(), "usage.json")}
	t.Cleanup(func() { _ = u.Close() })
	var drain usagepersist.RequestDrain
	entered := make(chan struct{})
	handler := drain.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		u.MarkIncomplete()
	}))
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := drain.Close(ctx, func() error { return nil }, u.Close); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(u.filePath)
	if err != nil {
		t.Fatal(err)
	}
	var saved AggregatedUsageJSON
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.IncompleteObservations != 1 || len(saved.Combinations) != 0 {
		t.Fatalf("last incomplete observation not flushed separately: %+v", saved)
	}
	u.MarkIncomplete()
	if u.ToJSON().IncompleteObservations != 1 {
		t.Fatal("closed tracker accepted an incomplete observation")
	}
	u.saveMutex.Lock()
	pending := u.pendingSave
	u.saveMutex.Unlock()
	if pending {
		t.Fatal("closed tracker scheduled another save")
	}
}

func TestUsageFileOwnershipSpansLoadAndFinalFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	first := &AggregatedUsage{ctx: context.Background(), filePath: path, lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = first.Close() })
	if err := first.Load(); err != nil {
		t.Fatal(err)
	}
	second := &AggregatedUsage{ctx: context.Background(), filePath: path, lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = second.Close() })
	if err := second.Load(); !errors.Is(err, usagepersist.ErrFileInUse) {
		t.Fatalf("second load admitted: %v", err)
	}
	if err := second.Save(); !errors.Is(err, usagepersist.ErrFileInUse) {
		t.Fatalf("second save admitted: %v", err)
	}
	first.MarkIncomplete()
	// The finalizer still owns the file while waiting for an earlier transaction.
	first.saveWriteMutex.Lock()
	done := make(chan error, 1)
	go func() { done <- first.Close() }()
	waitUsageSaveState(t, first, func() bool { return first.saveStopping })
	if err := second.Load(); !errors.Is(err, usagepersist.ErrFileInUse) {
		t.Errorf("pending close released ownership: %v", err)
	}
	first.saveWriteMutex.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := second.Load(); err != nil {
		t.Fatal(err)
	}
	if second.IncompleteObservations != 1 {
		t.Fatal("successor loaded stale snapshot")
	}
	if err := first.Load(); err == nil {
		t.Fatal("closed tracker reacquired file")
	}
}

func TestUsageFailedLoadReleasesFileOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := &AggregatedUsage{ctx: context.Background(), filePath: path}
	if err := first.Load(); err == nil {
		t.Fatal("invalid snapshot loaded")
	}
	// Do not Close the rejected tracker: production disables it after Load fails.
	lease, err := usagepersist.AcquireFile(context.Background(), path)
	if err != nil {
		t.Fatal("load failure leaked owner", err)
	}
	lease.Close()
}

func TestUsageTrackerWithNonemptyFileManagerBase(t *testing.T) {
	root := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), root, "", os.Getuid(), os.Getgid())
	first := &AggregatedUsage{ctx: ctx, filePath: "usage.json", lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = first.Close() })
	if err := first.Load(); err != nil {
		t.Fatal(err)
	}
	first.MarkIncomplete()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := &AggregatedUsage{ctx: ctx, filePath: "usage.json", lastSaveTime: time.Now()}
	t.Cleanup(func() { _ = second.Close() })
	if err := second.Load(); err != nil {
		t.Fatal(err)
	}
	if second.IncompleteObservations != 1 {
		t.Fatal("manager-backed snapshot was not preserved")
	}
	if _, err := os.Stat(filepath.Join(root, "usage.json")); err != nil {
		t.Fatal(err)
	}
}
