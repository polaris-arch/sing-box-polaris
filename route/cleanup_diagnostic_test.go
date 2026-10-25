package route

import "testing"

func TestCleanupSnapshotConnectionTaskAndContention(t *testing.T) {
	m := &ConnectionManager{}
	done, err := m.reserveTask()
	if err != nil {
		t.Fatal(err)
	}
	s := m.CleanupSnapshot()
	if !s.Available || s.Tasks != 1 || s.Closed || s.Physical != 0 {
		t.Fatal(s)
	}
	m.access.Lock()
	s = m.CleanupSnapshot()
	m.access.Unlock()
	if s.Available {
		t.Fatal("diagnostic waited for manager lock")
	}
	done()
	done()
	s = m.CleanupSnapshot()
	if s.Tasks != 0 {
		t.Fatal("observation changed exact once task count")
	}
	if err := m.closeRuntimeTasks(); err != nil {
		t.Fatal(err)
	}
	s = m.CleanupSnapshot()
	if !s.Available || !s.Closed || s.Tasks != 0 {
		t.Fatal(s)
	}
}

func TestCleanupSnapshotReferenceSignalsAndContention(t *testing.T) {
	m := &RuntimeReferenceManager{setupDone: make(chan struct{}), workerDone: make(chan struct{}), stoppedDone: make(chan struct{})}
	s := m.CleanupSnapshot()
	if !s.Available || s.SetupDone || s.WorkerDone || s.StoppedDone {
		t.Fatal(s)
	}
	m.mu.Lock()
	s = m.CleanupSnapshot()
	m.mu.Unlock()
	if s.Available {
		t.Fatal("diagnostic waited for reference lock")
	}
	close(m.setupDone)
	close(m.workerDone)
	close(m.stoppedDone)
	s = m.CleanupSnapshot()
	if !s.SetupDone || !s.WorkerDone || !s.StoppedDone {
		t.Fatal(s)
	}
}
