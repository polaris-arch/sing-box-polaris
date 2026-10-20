package box

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSelectorIntentCandidateMembershipAndType(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: C.TypeSelector, Tag: "default", Options: &option.SelectorOutboundOptions{Outbounds: []string{"a", "b"}}}}}
	intent := RuntimeSelectorIntent{Group: "default", Selected: "a", ExpectedSelectionPath: []string{"default", "auto", "a"}}
	if err := runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}); err != nil {
		t.Fatal(err)
	}
	intent.Selected = "removed"
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("removed member admitted")
	}
	intent.Selected = "a"
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent, intent}) == nil {
		t.Fatal("duplicate group admitted")
	}
	options.Outbounds[0].Type = C.TypeURLTest
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("non-selector target admitted")
	}
}

func TestSelectorIntentSnapshotOwnsCallerPath(t *testing.T) {
	input := []RuntimeSelectorIntent{{Group: "rule", Selected: "winner", ExpectedSelectionPath: []string{"rule", "winner"}}}
	frozen := cloneRuntimeSelectorIntents(input)
	input[0].ExpectedSelectionPath[1] = "other"
	if frozen[0].ExpectedSelectionPath[1] != "winner" {
		t.Fatal("plan aliases mutable caller state")
	}
}

func TestSelectorIntentFingerprintOnlyChangesTarget(t *testing.T) {
	nodes := []runtimeDependencyNode{{name: "outbound:default", fingerprint: "same"}, {name: "outbound:rule", fingerprint: "same"}}
	runtimeBindSelectorIntentFingerprints(nodes, []RuntimeSelectorIntent{{Group: "default", Selected: "a"}})
	if nodes[0].fingerprint == "same" || nodes[1].fingerprint != "same" {
		t.Fatal("selection scope crossed independent rule group")
	}
}

func TestSelectorPinMustMatchConfirmedPhysicalWinner(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{
		{Type: C.TypeSelector, Tag: "rule", Options: &option.SelectorOutboundOptions{Outbounds: []string{"a", "auto"}}},
		{Type: C.TypeDirect, Tag: "a", Options: &option.DirectOutboundOptions{}},
		{Type: C.TypeURLTest, Tag: "auto", Options: &option.URLTestOutboundOptions{Outbounds: []string{"a"}}},
	}}
	intent := RuntimeSelectorIntent{Group: "rule", Selected: "auto", ExpectedSelectionPath: []string{"rule", "auto", "a"}, PinCurrentTCP: true}
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("automatic group accepted as frozen physical winner")
	}
	intent.Selected = "a"
	if err := runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}); err != nil {
		t.Fatal(err)
	}
	intent.ExpectedSelectionPath = nil
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("new group claimed an observed winner")
	}
}
