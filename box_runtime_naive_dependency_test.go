package box

import (
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRuntimeNaiveIPPeerRetainsNativeDNSCallbackDependency(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: "naive", Tag: "native", Options: &option.NaiveOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 443}}}}}
	node := runtimeHTTPNode(t, options, "outbound:native")
	if !slices.Contains(node.dependencies, "dns-router") {
		t.Fatal("native DNS callback lost its constructor graph")
	}
}
