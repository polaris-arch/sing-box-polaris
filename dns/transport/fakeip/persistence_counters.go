package fakeip

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

func (m *Manager) counterCapacityLocked(count uint64) bool {
	return m.counterRoot == nil || (m.nextAnswerToken < m.counterCeiling.Token && m.nextAnswerRevision <= m.counterCeiling.Revision && count <= m.counterCeiling.Revision-m.nextAnswerRevision)
}

// This is ID reservation, not a fake-IP capacity budget. The existing allocator
// reservation quantum amortizes anchor transactions; the pool stays unchanged.
// Only a depleted block incurs I/O. One owned worker retains a started write if
// the caller stops waiting, and never treats its cancellation as completion.
func (m *Manager) ensureCounterCapacity(ctx context.Context, count uint64) error {
	m.mappingAccess.Lock(); enough := m.counterCapacityLocked(count); m.mappingAccess.Unlock()
	if enough { return nil }
	done, ok := m.work.Reserve(); if !ok { return lifecycle.ErrStopped }
	job, cancel := m.persistenceWriter.submit(func() error {
		defer done()
		m.counterAccess.Lock(); defer m.counterAccess.Unlock()
		if err := ctx.Err(); err != nil { return err }
		m.mappingAccess.Lock()
		if m.counterCapacityLocked(count) { m.mappingAccess.Unlock(); return nil }
		root := m.counterRoot; minimum := adapter.FakeIPRuntimeCounters{Revision: m.nextAnswerRevision, Token: m.nextAnswerToken}
		m.mappingAccess.Unlock()
		floor, ceiling, err := root.ReserveFakeIPRuntimeCounters(ctx, minimum, max(uint64(reservedAddressCount), count)); if err != nil { return err }
		m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
		if m.counterRoot != root { return ErrPersistenceIdentity }
		m.nextAnswerRevision = max(m.nextAnswerRevision, floor.Revision); m.nextAnswerToken = max(m.nextAnswerToken, floor.Token)
		m.counterCeiling.Revision = max(m.counterCeiling.Revision, ceiling.Revision); m.counterCeiling.Token = max(m.counterCeiling.Token, ceiling.Token)
		return nil
	})
	select { case err := <-job.result: return err; case <-ctx.Done(): if cancel() { done() }; return ctx.Err() }
}
