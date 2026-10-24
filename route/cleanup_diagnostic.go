package route

// These scalar observations are not global atomic snapshots or completion
// certificates. TryLock keeps diagnostics from delaying the actual shutdown.
type ConnectionCleanupSnapshot struct {
	Available bool   `json:"available"`
	Closed    bool   `json:"closed"`
	Tasks     uint64 `json:"tasks"`
	Physical  uint64 `json:"physical"`
}

func (m *ConnectionManager) CleanupSnapshot() ConnectionCleanupSnapshot {
	if !m.access.TryLock() {
		return ConnectionCleanupSnapshot{}
	}
	result := ConnectionCleanupSnapshot{true, m.closed, m.diagnosticTasks.Load(), uint64(m.connections.Len())}
	m.access.Unlock()
	return result
}

type ReferenceCleanupSnapshot struct {
	Available   bool   `json:"available"`
	Started     bool   `json:"started"`
	Stopping    bool   `json:"stopping"`
	Busy        bool   `json:"busy"`
	Pauses      uint64 `json:"pauses"`
	Quarantined uint64 `json:"quarantined"`
	Failed      bool   `json:"failed"`
	SetupDone   bool   `json:"setupDone"`
	WorkerDone  bool   `json:"workerDone"`
	StoppedDone bool   `json:"stoppedDone"`
}

func (m *RuntimeReferenceManager) CleanupSnapshot() ReferenceCleanupSnapshot {
	if !m.mu.TryLock() {
		return ReferenceCleanupSnapshot{}
	}
	result := ReferenceCleanupSnapshot{Available: true, Started: m.started, Stopping: m.stopping, Busy: m.busy, Pauses: m.pauses, Quarantined: uint64(len(m.quarantined)), Failed: m.failure != nil}
	m.mu.Unlock()
	select {
	case <-m.setupDone:
		result.SetupDone = true
	default:
	}
	select {
	case <-m.workerDone:
		result.WorkerDone = true
	default:
	}
	select {
	case <-m.stoppedDone:
		result.StoppedDone = true
	default:
	}
	return result
}
