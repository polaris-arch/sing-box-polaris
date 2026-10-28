package libbox

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
)

type classificationOwnership struct{ releases int }

func (*classificationOwnership) Retain() (tun.FlowOwnership, error) {
	panic("classification cannot retain a flow")
}

func (*classificationOwnership) BindContext(context.Context) context.Context {
	panic("classification cannot hand off a context")
}

func (*classificationOwnership) RetainPort(tun.Port) (tun.PortOwnership, error) {
	panic("classification cannot retain a port")
}
func (o *classificationOwnership) Release() { o.releases++ }

type classificationHandler struct {
	tun.AutoRedirectHandler
	action tun.FlowAction
	owner  *classificationOwnership
	calls  int
}

func (h *classificationHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	h.calls++
	return tun.FlowVerdict{Action: h.action, Ownership: h.owner, NewTracker: func() tun.FlowTracker { panic("classification cannot create a tracker") }}
}

func TestAutoRedirectClassificationReleasesEveryVerdict(t *testing.T) {
	for _, action := range []tun.FlowAction{tun.ActionAccept, tun.ActionFlow, tun.ActionReject, tun.ActionDrop, tun.ActionBypass, tun.ActionHijackDNS} {
		owner := &classificationOwnership{}
		handler := &classificationHandler{action: action, owner: owner}
		wrapper := &autoRedirectHandlerWrapper{handler: handler}
		got, err := wrapper.JudgeFlow(17, "192.0.2.1", 10000, "192.0.2.2", 53, nil)
		if err != nil || got != int32(action) || handler.calls != 1 || owner.releases != 1 {
			t.Fatalf("action %d: scalar=%d calls=%d releases=%d err=%v", action, got, handler.calls, owner.releases, err)
		}
	}
}

func TestAutoRedirectInvalidAddressDoesNotAcquireVerdict(t *testing.T) {
	handler := &classificationHandler{owner: &classificationOwnership{}}
	wrapper := &autoRedirectHandlerWrapper{handler: handler}
	for _, addresses := range [][2]string{{"invalid", "192.0.2.2"}, {"192.0.2.1", "invalid"}} {
		if _, err := wrapper.JudgeFlow(17, addresses[0], 1, addresses[1], 2, nil); err == nil {
			t.Fatal("invalid address accepted")
		}
	}
	if handler.calls != 0 || handler.owner.releases != 0 {
		t.Fatal("parse failure admitted a graph")
	}
}
