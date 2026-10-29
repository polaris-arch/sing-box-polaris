package box

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

// Certificate issuance is an explicit pre-publication external effect. It must
// never run inside the graph publication guard or be described as reversible
// merely because the candidate graph itself was never published.
func (g *preparedRuntimeGraph) stageRuntimeCertificates(ctx context.Context) (resultErr error) {
	if err := g.validateRuntimeCertificateClaims(); err != nil {
		return err
	}
	// Retain newly created directory identities on partial issuance as well as
	// success; an uncertain cleanup must continue to exclude renamed aliases.
	defer func() { resultErr = errors.Join(resultErr, g.validateRuntimeCertificateClaims()) }()
	var providers []adapter.RuntimeStagedEffect
	if g.certificateManager != nil {
		named, err := g.certificateManager.PreparedProviders()
		if err != nil {
			return err
		}
		for _, provider := range named {
			providers = append(providers, provider)
		}
	}
	g.effectAccess.Lock()
	providers = append(providers, g.inlineEffects...)
	g.effectAccess.Unlock()
	// Issuance is the explicit effect boundary. A fresh offset-only clock may
	// take one owned synchronous sample here so TLS can validate the issuer;
	// background polling and all system writes still require publication.
	needsClock := false
	for _, provider := range providers {
		if consumer, ok := provider.(interface{ RuntimeClockBootstrapRequired() bool }); ok && consumer.RuntimeClockBootstrapRequired() {
			needsClock = true
		}
	}
	if needsClock {
		for _, resource := range g.created {
			for _, component := range resource.components {
				if component.clock != nil {
					if err := component.clock.BootstrapOffset(ctx); err != nil {
						return err
					}
				}
			}
		}
	}
	for _, provider := range providers {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.stagedProviders = append(g.stagedProviders, provider)
		if provider.RuntimeExternalEffects() {
			g.externalEffectsAttempted = true
		}
		if err := provider.StageRuntime(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (g *preparedRuntimeGraph) compensateRuntimeCertificates() {
	for _, provider := range slices.Backward(g.stagedProviders) {
		err := func() (err error) {
			defer func() {
				if recover() != nil {
					err = errors.New("certificate compensation panicked; completion unknown")
				}
			}()
			return provider.CompensateRuntime()
		}()
		if err != nil {
			g.compensationError = errors.Join(g.compensationError, fmt.Errorf("certificate effect compensation: %w", err))
		}
	}
}

func (s *Box) recordRuntimeCertificateEffects(record *runtimePlanRecord, g *preparedRuntimeGraph) {
	if g == nil {
		return
	}
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if g.externalEffectsAttempted {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "EXTERNAL_EFFECTS_MAY_REMAIN", Path: "certificate_providers", Message: "candidate was not published; certificate issuance, account or challenge/cache effects may remain"})
	}
	if g.compensationError != nil {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "CERTIFICATE_COMPENSATION_INCOMPLETE", Path: "certificate_providers", Message: "certificate compensation completion is unconfirmed"})
	}
}
