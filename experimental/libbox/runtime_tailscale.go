package libbox

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
)

// RuntimeTailscalePlatform belongs to one original Android CommandServer.
// Callbacks must be bounded, must not call back into Core, and must not join a
// service that can be closing concurrently. Validate is advisory and read-only.
type RuntimeTailscalePlatform interface {
	RuntimeTailscaleVersion() int32
	ValidateRuntimeTailscale(tag string, stateDirectory string, taildropDirectory string) bool
	// False certifies that no native claim was taken. An error leaves that scope
	// in quarantine. Neither result permits physical writer preparation.
	ClaimRuntimeTailscale(scope *RuntimeTailscaleScope) (bool, error)
	// Release follows either certified no physical acquisition or actual
	// original Close with a checked writer census (acquired == true).
	ReleaseRuntimeTailscale(scope *RuntimeTailscaleScope, acquired bool) error
}

// RuntimeTailscaleScope is immutable and issued only by the original Go child
// registrar. Its digest identifies the accepted Plan configuration.
type RuntimeTailscaleScope struct {
	scope adapter.RuntimeTailscaleWriterScope
}

func (s *RuntimeTailscaleScope) Incarnation() string     { return s.scope.ResourceID.Incarnation }
func (s *RuntimeTailscaleScope) ResourceSequence() int64 { return int64(s.scope.ResourceID.Sequence) }

// Generation is the physical holder's counter.
func (s *RuntimeTailscaleScope) Generation() int64      { return int64(s.scope.Generation) }
func (s *RuntimeTailscaleScope) RunNonce() string       { return s.scope.Binding.RunNonce }
func (s *RuntimeTailscaleScope) ConfigDigest() string   { return s.scope.Binding.ConfigDigest }
func (s *RuntimeTailscaleScope) Tag() string            { return s.scope.Tag }
func (s *RuntimeTailscaleScope) StateDirectory() string { return s.scope.Directories.State }
func (s *RuntimeTailscaleScope) TaildropDirectory() string {
	return s.scope.Directories.Taildrop
}

// SetRuntimeTailscalePlatform installs a typed opt-in on the strict Android
// main server, before the original Box initializes.
func (s *CommandServer) SetRuntimeTailscalePlatform(platform RuntimeTailscalePlatform) error {
	w := s.platformWrapper
	if w == nil || !w.androidTailscaleHost || !s.strictCleanup || s.transient || platform == nil {
		return errors.New("native Tailscale registration requires the strict original Android main command owner")
	}
	if platform.RuntimeTailscaleVersion() != 1 {
		return errors.New("unsupported native Tailscale bridge version")
	}
	s.commandAccess.Lock()
	defer s.commandAccess.Unlock()
	w.runtimeTailscaleAccess.Lock()
	defer w.runtimeTailscaleAccess.Unlock()
	if s.commandIsClosing || w.runtimeTailscaleFrozen || w.runtimeTailscalePlatform != nil {
		return errors.New("native Tailscale registration is already frozen")
	}
	w.runtimeTailscalePlatform = platform
	return nil
}

func (w *platformInterfaceWrapper) RequiresRuntimeTailscaleWriter() bool {
	return w.androidTailscaleHost
}

func (w *platformInterfaceWrapper) runtimeTailscaleAdmission() RuntimeTailscalePlatform {
	w.runtimeTailscaleAccess.Lock()
	defer w.runtimeTailscaleAccess.Unlock()
	if w.runtimeTailscaleQuarantined {
		return nil
	}
	return w.runtimeTailscalePlatform
}

func (w *platformInterfaceWrapper) ValidateRuntimeTailscaleWriter(tag string, directories adapter.RuntimeTailscaleDirectories) (allowed bool) {
	native := w.runtimeTailscaleAdmission()
	if native == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			allowed = false
		}
	}()
	return native.ValidateRuntimeTailscale(tag, directories.State, directories.Taildrop)
}

func (w *platformInterfaceWrapper) ClaimRuntimeTailscaleWriter(scope adapter.RuntimeTailscaleWriterScope) (claimed bool, err error) {
	native := w.runtimeTailscaleAdmission()
	if native == nil {
		return false, nil
	}
	defer func() {
		if recover() != nil || err != nil {
			w.quarantineRuntimeTailscaleAdmission()
			claimed, err = false, errors.New("native Tailscale claim did not acknowledge its original scope")
		}
	}()
	return native.ClaimRuntimeTailscale(&RuntimeTailscaleScope{scope: scope})
}

func (w *platformInterfaceWrapper) ReleaseRuntimeTailscaleWriter(scope adapter.RuntimeTailscaleWriterScope, acquired bool) (err error) {
	w.runtimeTailscaleAccess.Lock()
	native := w.runtimeTailscalePlatform
	w.runtimeTailscaleAccess.Unlock()
	if native == nil {
		return errors.New("original native Tailscale claim owner is unavailable")
	}
	defer func() {
		if recover() != nil || err != nil {
			w.quarantineRuntimeTailscaleAdmission()
			err = errors.New("native Tailscale release did not acknowledge its original scope")
		}
	}()
	return native.ReleaseRuntimeTailscale(&RuntimeTailscaleScope{scope: scope}, acquired)
}

func (w *platformInterfaceWrapper) quarantineRuntimeTailscaleAdmission() {
	w.runtimeTailscaleAccess.Lock()
	defer w.runtimeTailscaleAccess.Unlock()
	w.runtimeTailscaleQuarantined = true
}

var _ adapter.RuntimeTailscaleWriterPlatform = (*platformInterfaceWrapper)(nil)
