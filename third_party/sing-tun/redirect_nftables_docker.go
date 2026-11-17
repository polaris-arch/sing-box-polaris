//go:build linux

package tun

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
)

const (
	nftablesDockerFilterTable = "filter"
	nftablesDockerUserChain   = "DOCKER-USER"
)

func (r *autoRedirect) startDockerFirewallMonitor() {
	r.dockerFirewallAccess.Lock()
	defer r.dockerFirewallAccess.Unlock()
	if r.dockerFirewallClosed {
		return
	}
	if r.dockerFirewallMonitor != nil {
		return
	}
	doneCh := make(chan struct{})
	r.dockerFirewallDone = doneCh
	monitor := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionAny),
		nftables.WithMonitorObject(nftables.MonitorObjectRuleset),
		nftables.WithMonitorEventBuffer(16),
	)
	nft, err := nftables.New()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("create nftables monitor connection: ", err)
		}
		close(doneCh)
		r.dockerFirewallDone = nil
		return
	}
	events, err := nft.AddGenerationalMonitor(monitor)
	_ = nft.CloseLasting()
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("start nftables monitor: ", err)
		}
		close(doneCh)
		r.dockerFirewallDone = nil
		return
	}
	r.dockerFirewallMonitor = monitor
	go r.loopDockerFirewallMonitor(events, doneCh)
}

func (r *autoRedirect) stopDockerFirewallMonitor() {
	r.dockerFirewallAccess.Lock()
	r.dockerFirewallClosed = true
	monitor, done := r.dockerFirewallMonitor, r.dockerFirewallDone
	r.dockerFirewallMonitor, r.dockerFirewallDone = nil, nil
	r.dockerFirewallAccess.Unlock()
	if monitor != nil {
		_ = monitor.Close()
		<-done
	}
}

func (r *autoRedirect) loopDockerFirewallMonitor(events <-chan *nftables.MonitorEvents, doneCh chan<- struct{}) {
	defer close(doneCh)
	for monitorEvents := range events {
		if monitorEvents != nil && monitorEvents.GeneratedBy != nil && monitorEvents.GeneratedBy.Error != nil {
			if r.logger != nil {
				r.logger.Warn("nftables monitor closed: ", monitorEvents.GeneratedBy.Error)
			}
			return
		}
		if !nftablesDockerFirewallEventsRelevant(monitorEvents) {
			continue
		}
		err := r.configureDockerFirewall(false)
		if err != nil && r.logger != nil {
			r.logger.Warn("update docker firewall: ", err)
		}
	}
}

func (r *autoRedirect) configureDockerFirewall(cleanup bool) error {
	r.dockerFirewallAccess.Lock()
	defer r.dockerFirewallAccess.Unlock()
	if r.dockerFirewallClosed && !cleanup {
		return nil
	}
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	return r.transactDockerFirewall(dockerNFTIO{
		generation: func() (uint32, error) {
			gen, err := nft.GetGen()
			if err != nil {
				return 0, err
			}
			if gen == nil {
				return 0, E.New("missing Docker generation")
			}
			return gen.ID, nil
		},
		probe: probeNFTablesGeneration,
		snapshot: func(family nftables.TableFamily) (dockerNFTSnapshot, error) {
			table, err := nft.ListTableOfFamily(nftablesDockerFilterTable, family)
			if errors.Is(err, syscall.ENOENT) {
				return dockerNFTSnapshot{}, nil
			}
			if err != nil {
				return dockerNFTSnapshot{}, err
			}
			handle, err := getDockerNFTObjectHandle(family, table.Name, "")
			if err != nil {
				return dockerNFTSnapshot{}, err
			}
			chain, err := nft.ListChain(table, nftablesDockerUserChain)
			if errors.Is(err, syscall.ENOENT) {
				return dockerNFTSnapshot{table: table, tableHandle: handle}, nil
			}
			if err != nil {
				return dockerNFTSnapshot{}, err
			}
			chainHandle, err := getDockerNFTObjectHandle(family, table.Name, chain.Name)
			if err != nil {
				return dockerNFTSnapshot{}, err
			}
			rules, err := nft.GetRules(table, chain)
			return dockerNFTSnapshot{table: table, chain: chain, tableHandle: handle, chainHandle: chainHandle, rules: rules}, err
		},
		insert: nft.InsertRule, remove: nft.DelRule, flush: nft.FlushWithGenID,
	}, cleanup)
}

func nftablesDockerFirewallEventsRelevant(events *nftables.MonitorEvents) bool {
	if events == nil {
		return false
	}
	return slices.ContainsFunc(events.Changes, nftablesDockerFirewallEventRelevant)
}

func nftablesDockerFirewallEventRelevant(event *nftables.MonitorEvent) bool {
	if event == nil || event.Error != nil {
		return false
	}
	switch data := event.Data.(type) {
	case *nftables.Table:
		return nftablesIsDockerFirewallTable(data)
	case *nftables.Chain:
		return data.Name == nftablesDockerUserChain && nftablesIsDockerFirewallTable(data.Table)
	case *nftables.Rule:
		return data.Chain != nil && data.Chain.Name == nftablesDockerUserChain && nftablesIsDockerFirewallTable(data.Table)
	default:
		return false
	}
}

func nftablesIsDockerFirewallTable(table *nftables.Table) bool {
	return table != nil &&
		table.Name == nftablesDockerFilterTable &&
		(table.Family == nftables.TableFamilyIPv4 || table.Family == nftables.TableFamilyIPv6)
}

func nftablesDockerCompatibilityRule(table *nftables.Table, chain *nftables.Chain, ifName string, ifNameKey expr.MetaKey, comment string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      ifNameKey,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     nftablesIfname(ifName),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
		UserData: userdata.AppendString(nil, userdata.TypeComment, comment),
	}
}

func nftablesDockerCompatibilityRuleMatches(rule *nftables.Rule, ifName string, ifNameKey expr.MetaKey, comment string) bool {
	expected := nftablesDockerCompatibilityRule(rule.Table, rule.Chain, ifName, ifNameKey, comment)
	if rule.Flags != 0 || !bytes.Equal(rule.UserData, expected.UserData) || len(rule.Exprs) != len(expected.Exprs) {
		return false
	}
	for i, expression := range rule.Exprs {
		if i == 2 {
			if _, ok := expression.(*expr.Counter); !ok {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(expression, expected.Exprs[i]) {
			return false
		}
	}
	return true
}

func (r *autoRedirect) nftablesIsDockerCompatibilityRule(rule *nftables.Rule) bool {
	comment, loaded := userdata.GetString(rule.UserData, userdata.TypeComment)
	return loaded && strings.HasPrefix(comment, r.nftablesDockerCompatibilityCommentPrefix())
}

func (r *autoRedirect) nftablesDockerCompatibilityComment(direction string) string {
	return r.nftablesDockerCompatibilityCommentPrefix() + direction
}

func (r *autoRedirect) nftablesDockerCompatibilityCommentPrefix() string {
	return "!" + r.tableName + ": Docker compatibility "
}
