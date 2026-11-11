package adapter

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

// RuntimeTunPlatform is an optional original-FD/settings owner, registered
// before any Box exists. Version is pure inventory, never a native operation.
type RuntimeTunPlatform interface {
	RuntimeTunVersion() int
	NewRuntimeTunSession(options *tun.Options, platform option.TunPlatformOptions, previous RuntimeTunSession, receipt *RuntimeTunReceipt) (RuntimeTunSession, error)
}

// RuntimeTunSession remains owned independently of Core's physical duplicate.
// Prepare/Abort/Retire synchronously acknowledge actual completion, or return
// uncertainty while retaining native custody. Abort restores previous settings
// and updates the previous session's descriptor before Core rebuilds readers.
type RuntimeTunSession interface {
	OwnerID() string
	Prepare() error
	OpenInterface(options *tun.Options) (tun.Tun, error)
	Validate() error
	Abort() error
	Retire() error
}

// RuntimeTunReceipt is a concrete memory-only graph publication participant.
// It is not a permission, device readiness proof or transferable FD identity.
type RuntimeTunReceipt struct {
	ownerID       string
	published     atomic.Bool
	everPublished atomic.Bool
}

func NewRuntimeTunReceipt() (*RuntimeTunReceipt, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	return &RuntimeTunReceipt{ownerID: hex.EncodeToString(identity[:])}, nil
}
func (r *RuntimeTunReceipt) OwnerID() string { return r.ownerID }
func (r *RuntimeTunReceipt) Published() bool { return r.published.Load() }

// Published follows the current Core physical admission, including suspension
// and compensation. Historical publication is separate cleanup custody.
func (r *RuntimeTunReceipt) WasPublished() bool { return r.everPublished.Load() }
func (r *RuntimeTunReceipt) Suspend()           { r.published.Store(false) }
func (r *RuntimeTunReceipt) Publish()           { r.everPublished.Store(true); r.published.Store(true) }
