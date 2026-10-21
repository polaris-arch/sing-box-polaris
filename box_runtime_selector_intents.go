package box

import (
	"context"
	"errors"
	"slices"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// An explicit intent pins one confirmed TCP winner for both network types.
// The entire current path is a CAS condition, not a request to rerank a group.
type RuntimeSelectorIntent struct {
	Group                 string   `json:"group"`
	Selected              string   `json:"selected"`
	ExpectedSelectionPath []string `json:"expected_selection_path"`
	PinCurrentTCP         bool     `json:"pin_current_tcp"`
}

func cloneRuntimeSelectorIntents(values []RuntimeSelectorIntent) []RuntimeSelectorIntent {
	result := append([]RuntimeSelectorIntent(nil), values...)
	for index := range result {
		result[index].ExpectedSelectionPath = append([]string(nil), result[index].ExpectedSelectionPath...)
	}
	return result
}

func runtimeValidateSelectorIntents(options option.Options, intents []RuntimeSelectorIntent) error {
	if len(intents) > 256 {
		return errors.New("selector intent budget exceeded")
	}
	encoded, err := json.Marshal(intents)
	if err != nil || len(encoded) > 256<<10 {
		return errors.New("selector intent byte budget exceeded")
	}
	seen := make(map[string]bool)
	for _, intent := range intents {
		if intent.Group == "" || intent.Selected == "" || seen[intent.Group] || len(intent.ExpectedSelectionPath) > 64 {
			return errors.New("invalid or duplicate selector intent")
		}
		seen[intent.Group] = true
		if intent.PinCurrentTCP {
			if len(intent.ExpectedSelectionPath) < 2 || intent.Selected != intent.ExpectedSelectionPath[len(intent.ExpectedSelectionPath)-1] {
				return errors.New("pin target differs from confirmed TCP winner")
			}
			physical := false
			for _, outbound := range options.Outbounds {
				if outbound.Tag == intent.Selected {
					physical = outbound.Type != C.TypeSelector && outbound.Type != C.TypeURLTest
				}
			}
			for _, endpoint := range options.Endpoints {
				if endpoint.Tag == intent.Selected {
					physical = true
				}
			}
			if !physical {
				return errors.New("pin target is not a physical candidate node")
			}
		}
		found := false
		for _, outbound := range options.Outbounds {
			if outbound.Tag != intent.Group {
				continue
			}
			if outbound.Type != C.TypeSelector {
				return errors.New("selector intent target is not a selector")
			}
			selector, ok := outbound.Options.(*option.SelectorOutboundOptions)
			if !ok {
				return errors.New("invalid selector options")
			}
			found = found || slices.Contains(selector.Outbounds, intent.Selected)
		}
		if !found {
			return errors.New("selector intent target or member missing")
		}
	}
	return nil
}

func runtimeBindSelectorIntentFingerprints(nodes []runtimeDependencyNode, intents []RuntimeSelectorIntent) {
	for _, intent := range intents {
		encoded, _ := json.Marshal(intent)
		for index := range nodes {
			if nodes[index].name == "outbound:"+intent.Group {
				nodes[index].fingerprint = runtimeDigest(append(append([]byte(nodes[index].fingerprint), 0), encoded...))
			}
		}
	}
}

// Caller holds controlEffects. Automatic URLTest publications are frozen as
// well, in stable tag order. The returned release retains all exact old owners
// until CAS and publication finish. No network or persistence work runs here.
func (c *runtimeCoordinator) lockRuntimeSelectorIntents(ctx context.Context, expected RuntimeIdentity, intents []RuntimeSelectorIntent) (func(), error) {
	if len(intents) == 0 {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.access.Lock()
	current := !c.stopped && c.active == expected
	c.access.Unlock()
	if !current {
		return nil, errors.New("selector identity changed")
	}
	lease, err := c.store.Acquire()
	if err != nil {
		return nil, err
	}
	view, ok := lease.View().(*runtimeView)
	if !ok || view.identity != expected.graphRevision() {
		lease.Release()
		return nil, errors.New("selector graph changed")
	}
	outbounds := append([]adapter.Outbound(nil), view.outbounds.Outbounds()...)
	sort.Slice(outbounds, func(i, j int) bool { return outbounds[i].Tag() < outbounds[j].Tag() })
	var unlocks []func()
	release := func() {
		for _, value := range slices.Backward(unlocks) {
			value()
		}
		lease.Release()
	}
	for _, outbound := range outbounds {
		if locker, ok := outbound.(interface{ RuntimeLockSelection() func() }); ok {
			unlocks = append(unlocks, locker.RuntimeLockSelection())
		}
	}
	for _, intent := range intents {
		path := intent.ExpectedSelectionPath
		current, exists := view.outbounds.Outbound(intent.Group)
		if len(path) == 0 {
			if exists {
				release()
				return nil, errors.New("expected absent selector already exists")
			}
			continue
		}
		if !exists || path[0] != intent.Group {
			release()
			return nil, errors.New("selector CAS path changed")
		}
		visited := make(map[string]bool)
		for index, tag := range path {
			if current == nil || current.Tag() != tag || visited[tag] {
				release()
				return nil, errors.New("selector CAS path changed")
			}
			visited[tag] = true
			group, isGroup := current.(adapter.OutboundGroup)
			if index == len(path)-1 {
				if isGroup {
					release()
					return nil, errors.New("selector CAS path does not end at a physical node")
				}
				break
			}
			if !isGroup {
				release()
				return nil, errors.New("selector CAS path exceeds physical node")
			}
			if snapshot, ok := current.(interface{ RuntimeSelectionSnapshot() adapter.Outbound }); ok {
				current = snapshot.RuntimeSelectionSnapshot()
			} else {
				current = group.Selected(N.NetworkTCP)
			}
		}
	}
	return release, nil
}

func (s *Box) applyRuntimeSelectorIntents(g *preparedRuntimeGraph, intents []RuntimeSelectorIntent) error {
	for _, intent := range intents {
		applied := false
		for _, resource := range g.created {
			for _, component := range resource.components {
				if component.outbound == nil || component.outbound.Tag() != intent.Group {
					continue
				}
				selector, ok := component.outbound.(interface{ RuntimeSelectInitial(string) bool })
				if !ok || !selector.RuntimeSelectInitial(intent.Selected) {
					return errors.New("candidate selector intent rejected")
				}
				applied = true
			}
		}
		if !applied {
			return errors.New("selector intent has no private candidate owner")
		}
	}
	return nil
}

// This fallible durable tail is deliberately outside atomic publication. Failure
// retains COMMITTED_DURABILITY_PENDING; it never rolls back the published graph.
func runtimePersistSelectorIntents(ctx context.Context, intents []RuntimeSelectorIntent) error {
	if len(intents) == 0 {
		return nil
	}
	cache := service.FromContext[adapter.CacheFile](ctx)
	if cache == nil {
		return errors.New("selector durability backend unavailable")
	}
	for _, intent := range intents {
		if err := cache.StoreSelected(intent.Group, intent.Selected); err != nil {
			return err
		}
	}
	return nil
}

func (c *runtimeCoordinator) persistRuntimeTransaction(ctx context.Context, identity RuntimeIdentity, canonical []byte, intents []RuntimeSelectorIntent, persist func(RuntimeIdentity, []byte) error, migration runtimePersistenceParticipant) error {
	if err := c.controlEffects.LockContext(ctx); err != nil {
		return err
	}
	defer c.controlEffects.Unlock()
	return c.persistRuntimeTransactionLocked(ctx, identity, canonical, intents, persist, migration)
}

// The caller owns controlEffects for the entire synchronous durability tail.
func (c *runtimeCoordinator) persistRuntimeTransactionLocked(ctx context.Context, identity RuntimeIdentity, canonical []byte, intents []RuntimeSelectorIntent, persist func(RuntimeIdentity, []byte) error, migration runtimePersistenceParticipant) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime persistence tail panicked; durability remains pending")
		}
	}()
	c.access.Lock()
	current := !c.stopped && c.active == identity
	c.access.Unlock()
	if !current {
		return errors.New("newer runtime control superseded durable transaction")
	}
	if err := runtimePersistSelectorIntents(ctx, intents); err != nil {
		return err
	}
	checkedPersist := func(id RuntimeIdentity, content []byte) error {
		err := persist(id, content)
		if err == nil && c.persistenceMode == "app_authoritative_regeneration" {
			return errors.New("owner reload receipt is required before desired-state acknowledgement")
		}
		return err
	}
	return runtimePersistCommitted(ctx, identity, canonical, checkedPersist, migration)
}
