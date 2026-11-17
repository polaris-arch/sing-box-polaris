package ocm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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
	waitUsageSaveState(t, u, func() bool { return !u.lastSaveTime.IsZero() && u.pendingSave && u.saveDirty && u.saveTimer != runningTimer })
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
