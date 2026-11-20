package adapter

import (
	"net/netip"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// RuntimeDashboardHTTPDetour returns the detour of the explicit inline client
// whose transport is owned by the runtime graph.
func RuntimeDashboardHTTPDetour(dashboard *option.APIDashboardOptions) string {
	if dashboard == nil || !dashboard.Enabled || dashboard.HTTPClient == nil || dashboard.HTTPClient.Detour == "" {
		return ""
	}
	client := *dashboard.HTTPClient
	client.Detour = ""
	if !reflect.ValueOf(client).IsZero() {
		return ""
	}
	return dashboard.HTTPClient.Detour
}

// The dashboard toggle requires the client's bounded configuration on both sides.
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
		return true, dashboard.DownloadURL == "" && dashboard.UpdateInterval == 0 &&
			!strings.ContainsRune(dashboard.Path, 0) && RuntimeDashboardHTTPDetour(dashboard) != ""
	}
	a, validA := shape(before)
	b, validB := shape(after)
	return validA && validB && a != b
}
