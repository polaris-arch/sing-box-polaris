package box

import (
	"context"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

func (v *runtimeView) RuntimeURLTestHistory(tag string) (*urltest.HistoryStorage, adapter.RuntimeResourceID, bool) {
	history := v.histories[tag]
	id, ok := v.componentIDs["outbound:"+tag]
	return history, id, ok && history != nil
}

func (v *runtimeView) RuntimeURLTestConsumers(tag string) []*urltest.HistoryStorage {
	return append([]*urltest.HistoryStorage(nil), v.historyConsumers[tag]...)
}

// Called once before graph sealing. Consumer membership follows the actual
// immutable group dependency closure, never a live selected-tag lookup. Any
// changed captured target replaces its owning cohort and therefore its history.
func (v *runtimeView) bindRuntimeHistoryConsumers() {
	v.historyConsumers = make(map[string][]*urltest.HistoryStorage)
	var tags []string
	for tag := range v.histories {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		history := v.histories[tag]
		if history == nil {
			continue
		}
		seen := make(map[string]bool)
		var visit func(string)
		visit = func(target string) {
			if seen[target] {
				return
			}
			seen[target] = true
			if _, exists := v.componentIDs["outbound:"+target]; !exists {
				return
			}
			v.historyConsumers[target] = append(v.historyConsumers[target], history)
			outbound, exists := v.outbounds.Outbound(target)
			if !exists {
				return
			}
			if group, ok := outbound.(adapter.OutboundGroup); ok {
				for _, member := range group.All() {
					visit(member)
				}
			}
		}
		visit(tag)
	}
}

func (v *runtimeView) runtimeActiveHistories() []*urltest.HistoryStorage {
	var tags []string
	for tag := range v.histories {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	result := make([]*urltest.HistoryStorage, 0, len(tags))
	for _, tag := range tags {
		result = append(result, v.histories[tag])
	}
	return result
}

func (s *Box) AcquireRuntimeURLTest(ctx context.Context, tag string) (*urltest.RuntimeProbe, bool, error) {
	if s.runtime == nil {
		return nil, false, nil
	}
	return urltest.AcquireRuntimeProbeFromContext(s.runtime.ctx, ctx, tag)
}

var _ urltest.RuntimeHistoryView = (*runtimeView)(nil)
