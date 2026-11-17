//go:build linux

package tun

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type dockerRuleReceipt struct {
	family                           nftables.TableFamily
	tableHandle, chainHandle, handle uint64
	direction                        expr.MetaKey
	ifName, comment                  string
}
type dockerFirewallState struct {
	receipts                     []dockerRuleReceipt
	probed, uncertain, untracked bool
}
type dockerNFTSnapshot struct {
	table                    *nftables.Table
	chain                    *nftables.Chain
	tableHandle, chainHandle uint64
	rules                    []*nftables.Rule
}
type dockerNFTIO struct {
	generation func() (uint32, error)
	probe      func(uint32) error
	snapshot   func(nftables.TableFamily) (dockerNFTSnapshot, error)
	insert     func(*nftables.Rule) *nftables.Rule
	remove     func(*nftables.Rule) error
	flush      func(uint32) error
}
type dockerPendingRule struct {
	rule    *nftables.Rule
	receipt dockerRuleReceipt
}

// Called under dockerFirewallAccess. A generation mismatch is the only flush
// failure retried: all other outcomes may have committed and block new writes.
func (r *autoRedirect) transactDockerFirewall(io dockerNFTIO, cleanup bool) (result error) {
	state := &r.dockerFirewallState
	defer func() {
		if cleanup && state.untracked {
			result = errors.Join(result, errors.New("Docker firewall may contain untracked committed rules; cleanup incomplete"))
		}
	}()
	if state.uncertain && !cleanup {
		return errors.New("Docker firewall transaction outcome unknown; automatic writes stopped")
	}
	if cleanup && len(state.receipts) == 0 {
		return nil
	}
	families := []nftables.TableFamily{}
	if r.enableIPv4 {
		families = append(families, nftables.TableFamilyIPv4)
	}
	if r.enableIPv6 {
		families = append(families, nftables.TableFamilyIPv6)
	}
	for attempt := 0; attempt < 3; attempt++ {
		gen, err := io.generation()
		if err != nil {
			return err
		}
		if gen == 0 {
			return errors.New("zero Docker firewall generation")
		}
		if !state.probed {
			wrong := gen + 1
			if wrong == 0 {
				wrong = 1
			}
			if err := io.probe(wrong); err != nil {
				return fmt.Errorf("Docker generation enforcement not verified: %w", err)
			}
			state.probed = true
		}
		snapshots := make(map[nftables.TableFamily]dockerNFTSnapshot, len(families))
		for _, family := range families {
			snapshot, err := io.snapshot(family)
			if err != nil {
				return err
			}
			snapshots[family] = snapshot
		}
		after, err := io.generation()
		if err != nil {
			return err
		}
		if after == 0 {
			return errors.New("zero Docker firewall generation")
		}
		if after != gen {
			continue
		}
		var next []dockerRuleReceipt
		var deletes []*nftables.Rule
		var pending []dockerPendingRule
		for _, family := range families {
			snap := snapshots[family]
			var owned []dockerRuleReceipt
			for _, receipt := range state.receipts {
				if receipt.family == family {
					owned = append(owned, receipt)
				}
			}
			// Tables cannot be renamed by the nft table update API. Under this
			// stable generation snapshot, a missing/replaced same-name table
			// means its old rules are gone. Release receipts, never delete new
			// objects by reused names/handles. Chains can be renamed, so a
			// missing chain in the same table remains unresolved debt.
			if snap.table == nil {
				continue
			}
			if snap.tableHandle == 0 {
				return errors.New("Docker table identity unavailable")
			}
			currentOwned := owned[:0]
			for _, receipt := range owned {
				if receipt.tableHandle == snap.tableHandle {
					currentOwned = append(currentOwned, receipt)
				}
			}
			owned = currentOwned
			if snap.chain == nil {
				if len(owned) != 0 {
					return errors.New("owned Docker chain missing in same table; receipts retained")
				}
				continue
			}
			if snap.chainHandle == 0 {
				return errors.New("Docker chain identity unavailable")
			}
			live := make(map[uint64]*nftables.Rule, len(snap.rules))
			for _, rule := range snap.rules {
				if rule == nil || rule.Handle == 0 {
					return errors.New("Docker rule identity unavailable")
				}
				if _, exists := live[rule.Handle]; exists {
					return errors.New("duplicate Docker rule handle")
				}
				live[rule.Handle] = rule
			}
			recognized := make(map[uint64]bool, len(owned))
			keptDirection := make(map[expr.MetaKey]bool, 2)
			for _, receipt := range owned {
				if receipt.chainHandle != snap.chainHandle {
					return errors.New("Docker chain identity changed; receipts retained")
				}
				rule := live[receipt.handle]
				if rule == nil {
					continue
				}
				if !nftablesDockerCompatibilityRuleMatches(rule, receipt.ifName, receipt.direction, receipt.comment) {
					return errors.New("owned Docker rule changed; receipts retained")
				}
				recognized[receipt.handle] = true
				if cleanup {
					deletes = append(deletes, rule)
				} else {
					next = append(next, receipt)
					keptDirection[receipt.direction] = true
				}
			}
			for _, rule := range snap.rules {
				if !cleanup && !recognized[rule.Handle] && r.nftablesIsDockerCompatibilityRule(rule) {
					return errors.New("unowned historical Docker compatibility rule preserved")
				}
			}
			if !cleanup {
				for _, direction := range []expr.MetaKey{expr.MetaKeyOIFNAME, expr.MetaKeyIIFNAME} {
					if keptDirection[direction] {
						continue
					}
					label := "output to tun"
					if direction == expr.MetaKeyIIFNAME {
						label = "input from tun"
					}
					receipt := dockerRuleReceipt{family: family, tableHandle: snap.tableHandle, chainHandle: snap.chainHandle, direction: direction, ifName: r.tunOptions.Name, comment: r.nftablesDockerCompatibilityComment(label)}
					pending = append(pending, dockerPendingRule{nftablesDockerCompatibilityRule(snap.table, snap.chain, receipt.ifName, direction, receipt.comment), receipt})
				}
			}
		}
		if len(deletes) == 0 && len(pending) == 0 {
			state.receipts = next
			if cleanup && !state.untracked {
				state.uncertain = false
			}
			return nil
		}
		for _, rule := range deletes {
			if err := io.remove(rule); err != nil {
				return err
			}
		}
		for i := range pending {
			pending[i].rule = io.insert(pending[i].rule)
		}
		if err := io.flush(gen); err != nil {
			if errors.Is(err, syscall.ERESTART) {
				continue
			}
			state.uncertain = true
			state.untracked = state.untracked || len(pending) > 0
			return fmt.Errorf("Docker firewall commit uncertain; no replay: %w", err)
		}
		handles := make(map[[2]uint64]bool, len(pending)+len(next))
		for _, receipt := range next {
			handles[[2]uint64{receipt.tableHandle, receipt.handle}] = true
		}
		missingEcho := false
		for _, p := range pending {
			if p.rule == nil || p.rule.Handle == 0 {
				missingEcho = true
				continue
			}
			key := [2]uint64{p.receipt.tableHandle, p.rule.Handle}
			if handles[key] {
				missingEcho = true
				continue
			}
			handles[key] = true
			receipt := p.receipt
			receipt.handle = p.rule.Handle
			next = append(next, receipt)
		}
		state.receipts = next
		if missingEcho {
			state.uncertain = true
			state.untracked = true
			return errors.New("Docker rule echo handle missing or ambiguous; confirmed receipts retained, no replay")
		}
		if cleanup && !state.untracked {
			state.uncertain = false
		}
		return nil
	}
	return errors.New("Docker firewall generation changed repeatedly; no stale replay")
}
