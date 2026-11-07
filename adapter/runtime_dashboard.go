package adapter

import (
	"net/netip"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Only the actual client's dashboard toggle is a new policy-v1 variant.
// This does not admit edits to URL/interval/path/client while both sides serve,
// additional services, public binds, CORS, TLS, or other socket configuration.
func RuntimeDashboardToggleEligible(before, after option.APIServiceOptions) bool {
	shape := func(value option.APIServiceOptions) (bool, bool) {
		if value.Listen == nil || netip.Addr(*value.Listen).Zone() != "" || !netip.Addr(*value.Listen).Unmap().IsLoopback() || !RuntimeAPISecretValid(value.Secret) {
			return false, false
		}
		dashboard := value.Dashboard
		value.Listen, value.ListenPort, value.Secret, value.Dashboard = nil, 0, "", nil
		if !reflect.ValueOf(value).IsZero() {
			return false, false
		}
		if dashboard == nil {
			return false, true
		}
		if !dashboard.Enabled {
			return false, reflect.ValueOf(*dashboard).IsZero()
		}
		if dashboard.DownloadURL != "" || dashboard.UpdateInterval != 0 || strings.ContainsRune(dashboard.Path, 0) || dashboard.HTTPClient == nil || dashboard.HTTPClient.Detour == "" {
			return false, false
		}
		client := *dashboard.HTTPClient
		client.Detour = ""
		return true, reflect.ValueOf(client).IsZero()
	}
	a, validA := shape(before)
	b, validB := shape(after)
	return validA && validB && a != b
}
