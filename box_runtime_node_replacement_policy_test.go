package box

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestRuntimePersistentTorPresenceDoesNotRequireReplacement(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: C.TypeTor, Tag: "tor", Options: &option.TorOutboundOptions{DataDirectory: "private-state"}}}}
	if problems := runtimeNodeReplacementProblems(options, map[string]bool{}, nil); len(problems) != 0 {
		t.Fatal("unchanged Tor owner rejected", problems)
	}
	problems := runtimeNodeReplacementProblems(options, map[string]bool{"outbound:tor": true}, nil)
	if len(problems) != 1 || problems[0].Code != "RESTART_REQUIRED" || problems[0].Path != "outbounds[0].data_directory" {
		t.Fatal(problems)
	}
	options.Outbounds[0].Options = &option.TorOutboundOptions{}
	if problems := runtimeNodeReplacementProblems(options, map[string]bool{"outbound:tor": true}, nil); len(problems) != 0 {
		t.Fatal("private temporary Tor rejected", problems)
	}
}
