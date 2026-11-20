package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// RuntimeAPIIdentity is an observation of the admitted graph, not credentials.
// The stable control-plane owner survives ordinary graph retirement.
type RuntimeAPIIdentity struct {
	Incarnation         string
	Revision            uint64
	EffectiveDigest     string
	ConfigurationDigest string
	Changed             <-chan struct{}
}

type RuntimeAPIProvider interface {
	RuntimeAPIIngressIdentity(tag string) (RuntimeAPIIdentity, error)
}

// A prepared handoff retains both physical ingress claims until abort, or until
// the original owner has authenticated the new channel and acknowledged it.
// Graph durability acknowledgement does not complete this lifecycle.
type RuntimeAPIHandoff interface {
	Abort() error
	Status() (complete bool, err error)
}

type RuntimeAPIService interface {
	PrepareRuntimeAPI(context.Context, option.APIServiceOptions) (RuntimeAPIHandoff, error)
}

// RuntimeStableAPIService reports whether a local API can use the stable
// ingress. Daemon operations and supported dashboard downloads borrow current
// graph snapshots. Other dashboard clients and TLS retain the legacy path.
func RuntimeStableAPIService(item option.Service) bool {
	options, ok := item.Options.(*option.APIServiceOptions)
	if item.Type != C.TypeAPI || !ok || options.Listen == nil || (!netip.Addr(*options.Listen).Unmap().IsLoopback() || netip.Addr(*options.Listen).Zone() != "") {
		return false
	}
	return options.TLS == nil && runtimeStableDashboard(options.Dashboard) &&
		options.Detour == "" && options.NetNs == "" && options.BindInterface == "" &&
		options.RoutingMark == 0 && !options.ReuseAddr && !options.TCPFastOpen && !options.TCPMultiPath
}

func NormalizeRuntimeAPIOptions(options option.APIServiceOptions) option.APIServiceOptions {
	if options.Listen != nil && netip.Addr(*options.Listen).Zone() == "" {
		address := badoption.Addr(netip.Addr(*options.Listen).Unmap())
		options.Listen = &address
	}
	return options
}

func RuntimeAPIConfigDigest(options option.APIServiceOptions) (string, error) {
	options = NormalizeRuntimeAPIOptions(options)
	// The published graph fingerprints and leases this transport. Keep the
	// ingress identity stable when only that graph-owned detour changes.
	if RuntimeDashboardHTTPDetour(options.Dashboard) != "" {
		dashboard := *options.Dashboard
		dashboard.HTTPClient = &option.HTTPClientOptions{}
		options.Dashboard = &dashboard
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// RuntimeAPISecretValid bounds the metadata-only handoff subset. Ordinary cold
// API constructors keep their existing credential semantics.
func RuntimeAPISecretValid(secret string) bool {
	if len(secret) > 4096 {
		return false
	}
	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
