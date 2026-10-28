//go:build with_acme

package acme

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
)

var (
	_ certificate.RuntimePreparedProvider = (*Service)(nil)
	_ certificate.RuntimeProvider         = (*Service)(nil)
)

func (s *Service) RuntimeValidate() error {
	if s.runtime == nil {
		return errors.New("ACME provider was not privately constructed")
	}
	return s.runtime.RuntimeValidate()
}

func (s *Service) RuntimeResourceID() adapter.RuntimeResourceID {
	if s.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return s.runtime.RuntimeResourceID()
}

func (s *Service) PrepareRuntime(stage adapter.StartStage, scope *adapter.Scope) error {
	if err := s.RuntimeValidate(); err != nil {
		return err
	}
	return s.runtime.PrepareRuntime(stage, scope)
}
func (s *Service) StageRuntime(ctx context.Context) error { return s.runtime.StageRuntime(ctx) }
func (s *Service) CompensateRuntime() error               { return s.runtime.CompensateRuntime() }
func (s *Service) RuntimeActivate()                       { s.runtime.RuntimeActivate() }
func (s *Service) RuntimeStop()                           { s.runtime.RuntimeStop() }
func (s *Service) RuntimeCloseAndWait() error {
	if s.runtime == nil {
		return nil
	}
	return s.runtime.RuntimeCloseAndWait()
}

func (s *Service) GetCertificateWithContext(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.runtime != nil {
		return s.runtime.GetCertificateWithContext(ctx, hello)
	}
	return s.config.GetCertificateWithContext(ctx, hello)
}

func (s *Service) RuntimeExternalEffects() bool { return false }
