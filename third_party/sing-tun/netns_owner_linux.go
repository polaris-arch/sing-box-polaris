package tun

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// A path is only a discovery mechanism. Keep the actual namespace object alive
// for the full native owner's lifetime so unlink/rebind cannot redirect cleanup.
type pinnedNetworkNamespace struct {
	access  sync.Mutex
	fd      int
	closed  bool
	enter   func(int, int) error
	release func(int) error
}

func pinCurrentNetworkNamespace() (*pinnedNetworkNamespace, error) {
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &pinnedNetworkNamespace{fd: fd, enter: unix.Setns, release: unix.Close}, nil
}

func (n *pinnedNetworkNamespace) run(block func() error) error {
	n.access.Lock()
	defer n.access.Unlock()
	if n.closed {
		return errors.New("native network namespace owner is closed")
	}
	result := make(chan error, 1)
	go func() {
		// Do not unlock: the runtime discards this thread on goroutine exit,
		// rather than returning a changed namespace thread to the shared pool.
		runtime.LockOSThread()
		var err error
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("native namespace operation panicked: %v", recovered)
			}
			result <- err
		}()
		if err = n.enter(n.fd, unix.CLONE_NEWNET); err != nil {
			return
		}
		err = block()
	}()
	return <-result
}

func (n *pinnedNetworkNamespace) close() error {
	n.access.Lock()
	defer n.access.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	return n.release(n.fd)
}

func (t *NativeTun) runInOwnedNamespace(block func() error) error {
	if t.networkNamespace != nil {
		return t.networkNamespace.run(block)
	}
	if t.namespaceRequired {
		return errors.New("native network namespace identity is unavailable")
	}
	return block()
}
