//go:build with_tailscale && !darwin && !linux && !windows

package tailscale

import "github.com/sagernet/sing/service/filemanager"

func (t *Endpoint) prepareTaildropDirectory() error {
	if _, err := ownedTaildropRelative(t.server.Dir, t.taildrop.directory); err != nil {
		return err
	}
	// These platforms cannot produce directory retirement evidence.
	return filemanager.MkdirAll(t.ctx, t.taildrop.directory, 0o700)
}
