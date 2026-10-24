package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// The stable manager joins its own bookkeeping/logger tails. Internal physical
// carriers do not acquire a graph lease merely to retain this Box-owned manager.
func (m *ConnectionManager) reserveTask() (func(), error) {
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return nil, net.ErrClosed
	}
	m.tasks.Add(1)
	m.diagnosticTasks.Add(1)
	m.access.Unlock()
	var once sync.Once
	return func() { once.Do(func() { m.diagnosticTasks.Add(^uint64(0)); m.tasks.Done() }) }, nil
}

func (m *ConnectionManager) runtimeTask(ctx context.Context, task func(context.Context)) error {
	done, err := m.reserveTask()
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
		m.access.Lock()
		m.closed = true
		var closers []io.Closer
		for element := m.connections.Front(); element != nil; {
			next := element.Next()
			closers = append(closers, element.Value)
			m.connections.Remove(element)
			element = next
		}
		m.access.Unlock()
		for _, closer := range closers {
			m.closeErr = errors.Join(m.closeErr, closeManagedSocket(closer))
		}
		// A blocked callback or nonreturning external dial remains an incomplete
		// stable shutdown. Higher-level observers may stop waiting, not free it.
		m.tasks.Wait()
	})
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
