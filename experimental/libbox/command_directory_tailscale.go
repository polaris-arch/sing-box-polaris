//go:build with_tailscale

package libbox

import "github.com/sagernet/sing-box/protocol/tailscale"

const tailscaleDirectoryDomainSupported = true

func poisonTailscaleDirectoryDomain(root string) error { return tailscale.PoisonDirectoryDomain(root) }
