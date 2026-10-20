package box

import (
	"bytes"
	stdjson "encoding/json"
	"sort"
)

// Classification is pure. A restart-required result is an unapplied plan, not
// permission to restart Box. The application owns explanation and user choice.
// Values are never copied into diagnostics: configurations can contain secrets.
func runtimeDailyStructuralChanges(before, after map[string]stdjson.RawMessage) ([]RuntimeImpact, []RuntimePlanError) {
	paths := make(map[string]bool)
	keys := make(map[string]bool)
	for key := range before { keys[key] = true }
	for key := range after { keys[key] = true }
	for key := range keys {
		if bytes.Equal(before[key], after[key]) { continue }
		switch key {
		case "outbounds", "endpoints", "dns":
			// Concrete protocol/range support is checked separately. Endpoints
			// include ordinary userspace nodes, not only host interfaces.
		case "log":
   var oldLog,newLog map[string]stdjson.RawMessage
   _ = stdjson.Unmarshal(before[key],&oldLog);_ = stdjson.Unmarshal(after[key],&newLog)
   fields:=make(map[string]bool);for field:=range oldLog{fields[field]=true};for field:=range newLog{fields[field]=true}
   for field:=range fields{if field!="level"{runtimeChangedLeaves("log."+field,oldLog[field],newLog[field],paths)}}
  case "route":
			var oldRoute, newRoute map[string]stdjson.RawMessage
			_ = stdjson.Unmarshal(before[key], &oldRoute)
			_ = stdjson.Unmarshal(after[key], &newRoute)
			routeKeys := make(map[string]bool)
			for field := range oldRoute { routeKeys[field] = true }
			for field := range newRoute { routeKeys[field] = true }
			for field := range routeKeys {
				if bytes.Equal(oldRoute[field], newRoute[field]) { continue }
				switch field {
				case "rules", "rule_set", "final", "default_domain_resolver", "default_interface", "default_mark", "default_network_strategy", "default_network_type", "default_fallback_network_type", "default_fallback_delay":
				default: runtimeChangedLeaves("route."+field, oldRoute[field], newRoute[field], paths)
				}
			}
		default:
			runtimeChangedLeaves(key, before[key], after[key], paths)
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths { ordered = append(ordered, path) }
	sort.Strings(ordered)
	var impacts []RuntimeImpact
	var problems []RuntimePlanError
	for _, path := range ordered {
		impacts = append(impacts, RuntimeImpact{Path:path, UpdateClass:"RESTART_REQUIRED", Reason:"structural configuration is outside daily runtime updates", ReconnectRequired:true, AffectedSessionClasses:[]string{"none; candidate not applied"}})
		problems = append(problems, RuntimePlanError{Code:"RESTART_REQUIRED", Path:path, Message:"this changed setting requires an explicit application-managed restart"})
	}
	return impacts, problems
}

func runtimeChangedLeaves(path string, before, after stdjson.RawMessage, paths map[string]bool) {
	if bytes.Equal(before, after) { return }
	var left, right map[string]stdjson.RawMessage
	leftObject := stdjson.Unmarshal(before, &left) == nil && left != nil
	rightObject := stdjson.Unmarshal(after, &right) == nil && right != nil
	if leftObject && rightObject {
		keys := make(map[string]bool)
		for key := range left { keys[key] = true }
		for key := range right { keys[key] = true }
		for key := range keys { runtimeChangedLeaves(path+"."+key, left[key], right[key], paths) }
		return
	}
	// Arrays are reported as one field. Index churn must not pretend to
	// identify a stable resource, and diagnostics never include tag secrets.
	paths[path] = true
}
