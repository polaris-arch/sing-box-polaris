package originca

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/service/filemanager"
)

var (
	_ certificate.RuntimePreparedProvider = (*Service)(nil)
	_ certificate.RuntimeProvider         = (*Service)(nil)
)

type runtimeOriginCA struct {
	ctx           context.Context
	cancel        context.CancelFunc
	source        adapter.RuntimeResourceSource
	fence         *outbound.RuntimeIOFence
	beginOwned    func(context.Context) (context.Context, func(), error)
	mu            sync.Mutex
	prepared      bool
	stopped       bool
	stageDone     chan struct{}
	stageErr      error
	stageReturned bool
	ready         bool
	done          chan struct{}
	closeErr      error
}

func (s *Service) initializeRuntime(ctx context.Context) error {
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok || !adapter.HasConstructionScope(ctx) {
		return errors.New("origin CA requires its constructor resource and scope")
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &runtimeOriginCA{ctx: ctx, cancel: cancel, source: source}
	s.runtime = r
	r.fence = outbound.NewRuntimeIOFence(func() error {
		s.RuntimeStop()
		r.mu.Lock()
		stage, done := r.stageDone, r.done
		r.mu.Unlock()
		if stage != nil {
			<-stage
		}
		if done != nil {
			<-done
		}
		r.mu.Lock()
		err := r.closeErr
		if r.stageDone != nil && !r.stageReturned {
			err = errors.Join(err, errors.New("origin CA stage completion unknown"))
		}
		r.mu.Unlock()
		// Do not close a borrowed HTTP-manager transport. Its exact resource is an
		// immutable dependency and owns its own pooled-connection retirement.
		if err != nil {
			return fmt.Errorf("origin CA cleanup incomplete: %v", err)
		}
		return nil
	})
	begin, err := outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
	if err != nil {
		cancel()
		return err
	}
	r.beginOwned = begin
	return nil
}

func (s *Service) RuntimeResourceID() adapter.RuntimeResourceID {
	if s.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return s.runtime.source.ID()
}

func (s *Service) RuntimeValidate() error {
	if s.runtime == nil {
		return errors.New("origin CA provider was not privately constructed")
	}
	return nil
}

func (s *Service) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := s.RuntimeValidate(); err != nil {
		return err
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return net.ErrClosed
	}
	if stage == adapter.StartStateStarted {
		r.prepared = true
	}
	return r.ctx.Err()
}

// This preserves the existing synchronous first-certificate requirement.
// External issuance and durable cache writes are explicit transaction effects;
// abort stops the worker but does not revoke a new cert or delete reusable keys.
func (s *Service) StageRuntime(ctx context.Context) error {
	r := s.runtime
	leave, err := r.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	r.mu.Lock()
	if !r.prepared || r.stopped {
		r.mu.Unlock()
		return errors.New("origin CA is not prepared for staging")
	}
	if r.stageDone != nil {
		done := r.stageDone
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		err := r.stageErr
		r.mu.Unlock()
		return err
	}
	r.stageDone = make(chan struct{})
	done := r.stageDone
	r.stageErr = errors.New("origin CA stage did not complete")
	r.mu.Unlock()
	defer close(done)
	stageContext, cancel := context.WithCancel(r.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	err = s.stageCertificate(stageContext)
	r.mu.Lock()
	r.stageErr, r.stageReturned, r.ready = err, true, err == nil
	r.mu.Unlock()
	return err
}

func (s *Service) stageCertificate(ctx context.Context) error {
	ctx, leave, err := s.runtime.beginOwned(ctx)
	if err != nil {
		return err
	}
	defer leave()
	if s.dataDirectory != "" {
		if err := filemanager.MkdirAll(ctx, s.dataDirectory, 0o700); err != nil {
			return err
		}
	}
	err = s.initializeCertificate(ctx)
	s.runtime.mu.Lock()
	cleanupErr := s.runtime.closeErr
	s.runtime.mu.Unlock()
	if cleanupErr != nil {
		return errors.Join(err, fmt.Errorf("origin CA stage cleanup incomplete: %v", cleanupErr))
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

func (s *Service) RuntimeActivate() {
	r := s.runtime
	r.mu.Lock()
	if r.done != nil || r.stopped || !r.ready {
		r.mu.Unlock()
		return
	}
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()
	go func() {
		defer close(done)
		defer func() {
			if value := recover(); value != nil {
				r.mu.Lock()
				r.closeErr = fmt.Errorf("origin CA refresh panicked: %v", value)
				r.mu.Unlock()
			}
		}()
		ctx, leave, err := r.beginOwned(r.ctx)
		if err != nil {
			return
		}
		defer leave()
		s.refreshLoop(ctx, make(chan struct{}))
	}()
}

func (s *Service) RuntimeStop() {
	r := s.runtime
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.cancel()
}

func (s *Service) RuntimeCloseAndWait() error {
	if s.runtime == nil {
		return nil
	}
	return s.runtime.fence.RuntimeCloseAndWait()
}
func (s *Service) CompensateRuntime() error { return s.RuntimeCloseAndWait() }
func (s *Service) GetCertificateWithContext(ctx context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.runtime == nil {
		return s.certificateValue()
	}
	_, release, err := certificate.BeginRuntimeCallback(ctx, s.runtime.source, s.runtime.fence)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.certificateValue()
}

func (s *Service) RuntimeExternalEffects() bool { return true }
