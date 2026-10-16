//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// This sentinel must not unwrap context.Canceled/DeadlineExceeded: Scope.Close
// filters ordinary canceled errors, but incomplete IO retirement is a failure.
var errTaildropDrainIncomplete = errors.New("Taildrop IO retirement unknown")

// beginIO is the only admission point. Once seal returns, no further positive
// Add is possible, so wait cannot race a zero-to-one WaitGroup transition.
func (m *taildropManager) beginIO() bool {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed || (m.directoryReady != nil && !m.directoryReady()) {
		return false
	}
	m.ioWG.Add(1)
	return true
}

func (m *taildropManager) endIO() {
	m.ioWG.Done()
}

// seal rejects new work and requests cancellation without waiting for arbitrary
// readers or callbacks. Call wait after shutting down the peer HTTP server.
// Sealing is permanent; this manager cannot be restarted.
func (m *taildropManager) seal() {
	m.closeOnce.Do(func() {
		m.access.Lock()
		m.closed = true
		for _, timer := range m.deleteTimers {
			if timer.Stop() {
				m.endIO()
			}
		}
		clear(m.deleteTimers)
		watchers := make([]chan struct{}, 0, len(m.inboxWatchers)+len(m.fileWatchers))
		for signal := range m.inboxWatchers {
			watchers = append(watchers, signal)
		}
		for signal := range m.fileWatchers {
			watchers = append(watchers, signal)
		}
		incoming := make([]*taildropIncomingFile, 0, len(m.incoming))
		for _, file := range m.incoming {
			file.canceled.Store(true)
			incoming = append(incoming, file)
		}
		files := make([]*taildropReadCloser, 0, len(m.openFiles))
		for file := range m.openFiles {
			files = append(files, file)
		}
		// Count cleanup before unlocking. No positive Add occurs after seal.
		m.ioWG.Add(1)
		m.access.Unlock()
		m.cancelIO()
		for _, signal := range watchers {
			select {
			case signal <- struct{}{}:
			default:
			}
		}
		go func() {
			defer m.endIO()
			for _, file := range incoming {
				if file.interrupt != nil {
					file.interrupt()
				}
			}
			for _, file := range files {
				_ = file.Close()
			}
		}()
		// Keep the original owner alive until the actual IO join completes.
		// A caller deadline never closes this channel or reopens admission.
		go func() {
			m.ioWG.Wait()
			close(m.drainDone)
		}()
	})
}

// wait must follow seal. An uncooperative reader, response writer, platform
// notification, or progress callback can block it; a timeout must never be
// treated as a successful drain.
func (m *taildropManager) wait() {
	<-m.drainDone
}

// waitContext bounds only the caller's wait, never the lifetime of admitted IO.
// It also breaks a synchronous user callback -> Close -> own lease cycle: Close
// returns an explicit failure at its deadline, allowing the callback to unwind.
// The first incomplete result is retained: a second Close cannot erase it.
// drainDone independently records later real completion. No caller may
// translate an incomplete result into successful directory retirement.
func (m *taildropManager) waitContext(ctx context.Context) error {
	m.access.Lock()
	prior := m.drainErr
	m.access.Unlock()
	if prior != nil {
		return prior
	}
	select {
	case <-m.drainDone:
		m.access.Lock()
		defer m.access.Unlock()
		return m.drainErr
	case <-ctx.Done():
		m.access.Lock()
		defer m.access.Unlock()
		if m.drainErr == nil {
			m.drainErr = fmt.Errorf("%w: %v", errTaildropDrainIncomplete, ctx.Err())
		}
		return m.drainErr
	}
}

// A returned file owns its admission lease until Close finishes. Serializing
// Read and Close means even an in-flight read has finished before lease release.
// seal also closes these files, so callers need not close them to unblock drain.
type taildropReadCloser struct {
	access  sync.Mutex
	file    *os.File
	manager *taildropManager
	closed  bool
	err     error
}

func (r *taildropReadCloser) Read(p []byte) (int, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	return r.file.Read(p)
}

func (r *taildropReadCloser) Close() error {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return r.err
	}
	r.closed = true
	r.err = r.file.Close()
	r.manager.access.Lock()
	if r.err != nil && r.manager.drainErr == nil {
		r.manager.drainErr = fmt.Errorf("%w: retained file close: %v", errTaildropDrainIncomplete, r.err)
	}
	delete(r.manager.openFiles, r)
	r.manager.access.Unlock()
	r.manager.endIO()
	return r.err
}

// taildropSendReader joins reads initiated by net/http independently of
// RoundTrip's return. It does not close caller-owned content. A caller-supplied
// Read or progress callback must return for close to finish.
type taildropSendReader struct {
	access sync.Mutex
	reader io.Reader
	closed bool
}

func (r *taildropSendReader) Read(p []byte) (int, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	return r.reader.Read(p)
}

func (r *taildropSendReader) close() {
	r.access.Lock()
	r.closed = true
	r.access.Unlock()
}

// failIO records uncertainty before releasing the original operation token.
// Close failures cannot be erased by a later successful owner drain.
func (m *taildropManager) failIO(err error) {
	if err == nil {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.drainErr == nil {
		m.drainErr = fmt.Errorf("%w: %v", errTaildropDrainIncomplete, err)
	}
}

func (m *taildropManager) closeFile(file io.Closer) error {
	err := file.Close()
	m.failIO(err)
	return err
}

// os.ReadDir hides its descriptor Close result; retain explicit ownership.
func (m *taildropManager) readDir(path string) ([]os.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := m.closeFile(file)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, errors.Join(readErr, closeErr)
}
