//go:build with_acme

package tls

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"

	"github.com/caddyserver/certmagic"
)

// Challenge HTTP/TLS handlers can outlive certmagic solver accept-loop cleanup.
// Their private configs may only enter storage while this exact owner callback
// fence is open. Admitted methods are joined before graph dependencies leave.
type runtimeACMEStorage struct {
	inner  certmagic.Storage
	fence  *outbound.RuntimeIOFence
	record func(error)
}

func (s *runtimeACMEStorage) Store(ctx context.Context, key string, value []byte) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	err = s.inner.Store(ctx, key, value)
	s.record(err)
	return err
}

func (s *runtimeACMEStorage) Load(ctx context.Context, key string) ([]byte, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.inner.Load(ctx, key)
}

func (s *runtimeACMEStorage) Delete(ctx context.Context, key string) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	err = s.inner.Delete(ctx, key)
	s.record(err)
	return err
}

func (s *runtimeACMEStorage) Exists(ctx context.Context, key string) bool {
	leave, err := s.fence.Acquire()
	if err != nil {
		return false
	}
	defer leave()
	return s.inner.Exists(ctx, key)
}

func (s *runtimeACMEStorage) List(ctx context.Context, key string, recursive bool) ([]string, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.inner.List(ctx, key, recursive)
}

func (s *runtimeACMEStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	defer leave()
	return s.inner.Stat(ctx, key)
}

func (s *runtimeACMEStorage) Lock(ctx context.Context, key string) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return s.inner.Lock(ctx, key)
}

func (s *runtimeACMEStorage) Unlock(ctx context.Context, key string) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	err = s.inner.Unlock(ctx, key)
	s.record(err)
	return err
}

type runtimeACMETryStorage struct {
	*runtimeACMEStorage
	try certmagic.TryLocker
}

func (s *runtimeACMETryStorage) TryLock(ctx context.Context, key string) (bool, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return false, err
	}
	defer leave()
	return s.try.TryLock(ctx, key)
}

type runtimeACMELeaseStorage struct {
	*runtimeACMEStorage
	renew certmagic.LockLeaseRenewer
}

func (s *runtimeACMELeaseStorage) RenewLockLease(ctx context.Context, key string, duration time.Duration) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return s.renew.RenewLockLease(ctx, key, duration)
}

type runtimeACMETryLeaseStorage struct {
	*runtimeACMETryStorage
	renew certmagic.LockLeaseRenewer
}

func (s *runtimeACMETryLeaseStorage) RenewLockLease(ctx context.Context, key string, duration time.Duration) error {
	leave, err := s.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return s.renew.RenewLockLease(ctx, key, duration)
}

func guardACMEStorage(storage certmagic.Storage, fence *outbound.RuntimeIOFence, record func(error)) certmagic.Storage {
	if record == nil {
		record = func(error) {}
	}
	base := &runtimeACMEStorage{inner: storage, fence: fence, record: record}
	try, hasTry := storage.(certmagic.TryLocker)
	renew, hasRenew := storage.(certmagic.LockLeaseRenewer)
	if hasTry && hasRenew {
		return &runtimeACMETryLeaseStorage{runtimeACMETryStorage: &runtimeACMETryStorage{runtimeACMEStorage: base, try: try}, renew: renew}
	}
	if hasTry {
		return &runtimeACMETryStorage{runtimeACMEStorage: base, try: try}
	}
	if hasRenew {
		return &runtimeACMELeaseStorage{runtimeACMEStorage: base, renew: renew}
	}
	return base
}
