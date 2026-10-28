package route

import (
	"context"
	"fmt"
	"io"
)

// The stable manager joins its own bookkeeping/logger tails. Internal physical
// carriers do not acquire a graph lease merely to retain this Box-owned manager.
func (m *ConnectionManager) reserveTask() (func(), error) {
	return m.reserveFlowTask(context.Background())
}

func (m *ConnectionManager) runtimeTask(ctx context.Context, task func(context.Context)) error {
	done, err := m.reserveFlowTask(ctx)
	if err != nil {
		return err
	}
	if err := runtimeTask(ctx, func(owned context.Context) { defer done(); task(owned) }); err != nil {
		done()
		return err
	}
	return nil
}

func (m *ConnectionManager) closeRuntimeTasks() error {
	m.closeOnce.Do(func() {
		m.StopFinal()
		// A blocked callback or nonreturning external dial remains an incomplete
		// stable shutdown. Higher-level observers may stop waiting, not free it.
		m.tasks.Wait()
	})
	m.access.Lock()
	defer m.access.Unlock()
	return m.closeErr
}

func closeManagedSocket(closer io.Closer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("connection manager close panicked: %v", recovered)
		}
	}()
	if closeErr := closer.Close(); closeErr != nil {
		return fmt.Errorf("connection manager close incomplete: %v", closeErr)
	}
	return nil
}
