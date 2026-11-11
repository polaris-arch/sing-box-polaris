package libbox

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

// RuntimeTunPlatform is a separately registered optional binding. Existing
// PlatformInterface implementations and old generated bindings stay unchanged.
type RuntimeTunPlatform interface {
	RuntimeTunVersion() int32
	NewTunSession(options TunOptions, previous RuntimeTunSession, receipt *RuntimeTunReceipt) (RuntimeTunSession, error)
}

// NewTunSession must only allocate/snapshot. The returned session is retained
// before Prepare may touch the VPN, provider settings or original descriptor.
type RuntimeTunSession interface {
	OwnerID() string
	Prepare() error
	FileDescriptor() int32
	Validate() error
	Abort() error
	Retire() error
}

type RuntimeTunReceipt struct{ receipt *adapter.RuntimeTunReceipt }

func (r *RuntimeTunReceipt) OwnerID() string { return r.receipt.OwnerID() }
func (r *RuntimeTunReceipt) Published() bool { return r.receipt.Published() }

// SetRuntimeTunPlatform is installed once through the actual new binding's
// typed parameter, before any Box Initialize. Missing old-binding symbols keep
// legacy startup and cannot grant native replacement through PlatformInterface.
func (s *CommandServer) SetRuntimeTunPlatform(platform RuntimeTunPlatform) error {
	s.commandAccess.Lock()
	defer s.commandAccess.Unlock()
	if s.commandIsClosing || platform == nil {
		return errors.New("native TUN registration requires a live original command owner")
	}
	w := s.platformWrapper
	w.tunAccess.Lock()
	defer w.tunAccess.Unlock()
	if w.tunFrozen || w.runtimeTunPlatform != nil {
		return errors.New("native TUN registration is already frozen")
	}
	if platform.RuntimeTunVersion() != 1 {
		return errors.New("unsupported native TUN bridge version")
	}
	w.runtimeTunPlatform = platform
	return nil
}

func (w *platformInterfaceWrapper) RuntimeTunVersion() int {
	w.tunAccess.Lock()
	defer w.tunAccess.Unlock()
	if w.runtimeTunPlatform == nil || w.runtimeTunFailure != nil {
		return 0
	}
	return 1
}

func (w *platformInterfaceWrapper) NewRuntimeTunSession(options *tun.Options, platform option.TunPlatformOptions, previous adapter.RuntimeTunSession, receipt *adapter.RuntimeTunReceipt) (adapter.RuntimeTunSession, error) {
	w.tunAccess.Lock()
	native, failed := w.runtimeTunPlatform, w.runtimeTunFailure
	w.tunAccess.Unlock()
	if native == nil || failed != nil {
		return nil, errors.Join(errors.New("native TUN original owner unavailable or quarantined"), failed)
	}
	if err := validatePlatformTunOptions(options); err != nil {
		return nil, err
	}
	ranges, err := options.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	var old RuntimeTunSession
	if previous != nil {
		value, ok := previous.(*runtimeTunSessionWrapper)
		if !ok || value.platform != w {
			return nil, errors.New("native TUN previous owner belongs to another provider")
		}
		old = value.session
	}
	session, err := native.NewTunSession(&tunOptions{options, ranges, platform}, old, &RuntimeTunReceipt{receipt: receipt})
	if err != nil {
		return nil, err
	} // allocation contract guarantees no native effect
	if session == nil || session.OwnerID() != receipt.OwnerID() {
		return nil, errors.New("native TUN session receipt identity mismatch")
	}
	return &runtimeTunSessionWrapper{platform: w, session: session}, nil
}

type runtimeTunSessionWrapper struct {
	mu          sync.Mutex
	platform    *platformInterfaceWrapper
	session     RuntimeTunSession
	terminal    bool
	terminalErr error
}

func (s *runtimeTunSessionWrapper) OwnerID() string { return s.session.OwnerID() }
func (s *runtimeTunSessionWrapper) available() error {
	s.platform.tunAccess.Lock()
	defer s.platform.tunAccess.Unlock()
	return s.platform.runtimeTunFailure
}

func (s *runtimeTunSessionWrapper) Prepare() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return errors.New("native TUN session finalized")
	}
	if err := s.available(); err != nil {
		return err
	}
	returned := false
	defer func() {
		if !returned {
			s.platform.tunAccess.Lock()
			s.platform.runtimeTunFailure = errors.Join(s.platform.runtimeTunFailure, errors.New("native TUN Prepare panicked; original session retained"))
			s.platform.tunAccess.Unlock()
		}
	}()
	err = s.session.Prepare()
	returned = true
	return err
}

func (s *runtimeTunSessionWrapper) Validate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return errors.New("native TUN session finalized")
	}
	if err := s.available(); err != nil {
		return err
	}
	return s.session.Validate()
}

func (s *runtimeTunSessionWrapper) OpenInterface(options *tun.Options) (tun.Tun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return nil, errors.New("native TUN session finalized")
	}
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.session.Validate(); err != nil {
		return nil, err
	}
	fd := s.session.FileDescriptor()
	if fd < 0 {
		return nil, errors.New("native TUN session has no confirmed descriptor")
	}
	return s.platform.openTunFD(options, fd)
}

func (s *runtimeTunSessionWrapper) finish(abort bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return s.terminalErr
	}
	// A failed phase stays attached to this exact session, including after panic.
	s.terminal = true
	s.terminalErr = errors.New("native TUN cleanup has not acknowledged completion")
	defer func() {
		if s.terminalErr != nil {
			s.platform.tunAccess.Lock()
			s.platform.runtimeTunFailure = errors.Join(s.platform.runtimeTunFailure, s.terminalErr)
			s.platform.tunAccess.Unlock()
		}
	}()
	if err := s.available(); err != nil {
		s.terminalErr = err
		return err
	}
	if abort {
		s.terminalErr = s.session.Abort()
	} else {
		s.terminalErr = s.session.Retire()
	}
	return s.terminalErr
}
func (s *runtimeTunSessionWrapper) Abort() error  { return s.finish(true) }
func (s *runtimeTunSessionWrapper) Retire() error { return s.finish(false) }

var (
	_ adapter.RuntimeTunPlatform = (*platformInterfaceWrapper)(nil)
	_ adapter.RuntimeTunSession  = (*runtimeTunSessionWrapper)(nil)
)
