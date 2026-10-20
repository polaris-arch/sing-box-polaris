package group

import "github.com/sagernet/sing-box/adapter"

// URLTestTarget freezes the concrete dialer and history key together before a
// probe starts. Changing a selector while it runs cannot relabel its result.
func URLTestTarget(detour adapter.Outbound, network string) (adapter.Outbound, string) {
	seen := make(map[string]bool)
	for detour != nil {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return detour, detour.Tag()
		}
		tag := group.Tag()
		if seen[tag] {
			return nil, ""
		}
		seen[tag] = true
		detour = group.Selected(network)
	}
	return nil, ""
}
