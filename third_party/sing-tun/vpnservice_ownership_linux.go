//go:build linux

package tun

import (
	"errors"
	"fmt"

	"github.com/sagernet/netlink"
)

type vpnRuleOps struct {
	list func() ([]netlink.Rule, error)
	add  func(*netlink.Rule) error
	del  func(*netlink.Rule) error
}

// This key is for VPNService-generated table lookup rules only. RuleList in
// our netlink fork omits MarkSet and Type. Deletion still uses the original
// successful-add receipt, including its mark presence and table action.
// A readback is not a CAS; identical external replacement is indistinguishable.
type vpnRuleKey struct {
	rule                       netlink.Rule
	dport, sport               netlink.RulePortRange
	uid                        netlink.RuleUIDRange
	hasDport, hasSport, hasUID bool
}

func vpnKey(r *netlink.Rule) vpnRuleKey {
	k := vpnRuleKey{rule: *r}
	k.rule.MarkSet = false
	k.rule.Type = 0
	if r.Dport != nil {
		k.hasDport = true
		k.dport = *r.Dport
	}
	if r.Sport != nil {
		k.hasSport = true
		k.sport = *r.Sport
	}
	if r.UIDRange != nil {
		k.hasUID = true
		k.uid = *r.UIDRange
	}
	k.rule.Dport, k.rule.Sport, k.rule.UIDRange = nil, nil, nil
	return k
}

type vpnRuleSlot struct {
	family, priority, table int
	mark                    uint32
	mask                    int
	iif, oif                string
}

func vpnSlot(r *netlink.Rule) vpnRuleSlot {
	return vpnRuleSlot{r.Family, r.Priority, r.Table, r.Mark, r.Mask, r.IifName, r.OifName}
}
func validVPNReceipt(r *netlink.Rule) bool {
	return r != nil && r.Table > 0 && r.MarkSet && r.Mark != 0 && r.Type == 0
}

// Callers serialize access. Preflight completes before mutations, and only
// successful adds become owned. Failed deletions retain receipts for retry.
func reconcileVPNServiceRules(receipts *[]*netlink.Rule, desired []*netlink.Rule, ops vpnRuleOps) error {
	live, err := ops.list()
	if err != nil {
		return fmt.Errorf("list VPNService rules: %w", err)
	}
	current := make(map[vpnRuleKey]int, len(live))
	slots := make(map[vpnRuleSlot]int, len(live))
	for i := range live {
		current[vpnKey(&live[i])]++
		slots[vpnSlot(&live[i])]++
	}
	owned := make(map[vpnRuleKey]bool, len(*receipts))
	present := make(map[vpnRuleKey]bool, len(*receipts))
	for _, r := range *receipts {
		if !validVPNReceipt(r) {
			return errors.New("unsupported VPNService receipt")
		}
		key := vpnKey(r)
		if owned[key] {
			return errors.New("duplicate VPNService receipt")
		}
		owned[key] = true
		if slots[vpnSlot(r)] != 0 {
			if slots[vpnSlot(r)] != 1 || current[key] != 1 {
				return errors.New("owned VPNService rule changed or ambiguous")
			}
			present[key] = true
		}
	}
	wanted := make(map[vpnRuleKey]bool, len(desired))
	wantedSlots := make(map[vpnRuleSlot]bool, len(desired))
	for _, r := range desired {
		if !validVPNReceipt(r) {
			return errors.New("unsupported desired VPNService rule")
		}
		key, slot := vpnKey(r), vpnSlot(r)
		if wanted[key] {
			continue
		}
		if wantedSlots[slot] {
			return errors.New("duplicate desired VPNService slot")
		}
		wantedSlots[slot] = true
		wanted[key] = true
		if slots[slot] != 0 && !present[key] {
			return errors.New("foreign VPNService rule conflicts")
		}
	}
	var errs []error
	old := *receipts
	kept := old[:0]
	retained := make(map[vpnRuleKey]bool, len(old))
	for _, r := range old {
		key := vpnKey(r)
		if !present[key] {
			continue
		}
		if wanted[key] {
			kept = append(kept, r)
			retained[key] = true
			continue
		}
		if e := ops.del(cloneBypassRule(r)); !bypassAbsent(e) {
			kept = append(kept, r)
			errs = append(errs, fmt.Errorf("delete VPNService rule: %w", e))
		}
	}
	clear(old[len(kept):])
	*receipts = kept
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	for _, r := range desired {
		if retained[vpnKey(r)] {
			continue
		}
		receipt := cloneBypassRule(r)
		if err := ops.add(cloneBypassRule(receipt)); err != nil {
			return fmt.Errorf("add VPNService rule: %w", err)
		}
		*receipts = append(*receipts, receipt)
		retained[vpnKey(receipt)] = true
	}
	return nil
}
