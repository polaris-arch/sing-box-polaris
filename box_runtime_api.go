package box

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The local API is a stable control-plane ingress. It captures no graph leaf:
// daemon operations explicitly borrow current graph snapshots. Dashboard/TLS
// variants retain their established legacy constructor and remain unsupported
// for connected updates until their separate dependency adapters are ready.
func runtimeStableAPIService(item option.Service) bool {
	options, ok := item.Options.(*option.APIServiceOptions)
	if item.Type != C.TypeAPI || !ok || options.Listen == nil || !netip.Addr(*options.Listen).IsLoopback() {
		return false
	}
	return options.TLS == nil && (options.Dashboard == nil || !options.Dashboard.Enabled) &&
		options.Detour == "" && options.NetNs == "" && options.BindInterface == "" &&
		options.RoutingMark == 0 && !options.TCPFastOpen && !options.TCPMultiPath
}

// AcquireRuntimeAPI transfers a current graph reservation plus its publication
// change signal in the same admission epoch. Callers must join all work using
// the view before Release. A legacy Box returns connected=false.
func (s *Box) AcquireRuntimeAPI() (lease adapter.RuntimeLease, changed <-chan struct{}, connected bool, err error) {
	if s == nil || s.runtime == nil {
		return nil, nil, false, nil
	}
	lease, changed, err = s.runtime.store.AcquireWithChanges()
	return lease, changed, true, err
}
