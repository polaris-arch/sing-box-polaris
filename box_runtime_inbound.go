package box

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/adapter/inbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func runtimeResourceListeners(resources []*runtimeResource) []*listener.Listener {
	var result []*listener.Listener
	for _, resource := range resources {
		for _, component := range resource.components {
			if value, ok := component.inbound.(inbound.RuntimePreparedInbound); ok {
				result = append(result, value.RuntimeListeners()...)
			}
			if value, ok := component.service.(boxService.RuntimePreparedService); ok {
				result = append(result, value.RuntimeListeners()...)
			}
		}
	}
	return result
}

// Stage pauses only replaced/removed ingress. Retained listeners continue to
// admit against the stable current-graph gateway. All physical bind effects
// precede publication and remain owned by the compensation record on failure.
func (s *Box) stageRuntimeListeners(ctx context.Context, g *preparedRuntimeGraph, allowReconnect bool) error {
	current := make(map[*runtimeResource]bool, len(g.resources))
	for _, r := range g.resources {
		current[r] = true
	}
	s.runtime.access.Lock()
	old := append([]*runtimeResource(nil), s.runtime.resources...)
	s.runtime.access.Unlock()
	var replaced, retained []*runtimeResource
	for _, r := range old {
		if current[r] {
			retained = append(retained, r)
		} else {
			replaced = append(replaced, r)
		}
	}
	previous := runtimeResourceListeners(replaced)
	next := runtimeResourceListeners(g.created)
	if len(previous) == 0 && len(next) == 0 {
		return nil
	}
	// Include unchanged occupancy in validation, without pausing its ingress.
	all := append(runtimeResourceListeners(retained), next...)
	if _, err := listener.PlanListenerSet(nil, all); err != nil {
		return err
	}
	transaction, err := listener.ReserveListenerSet(previous, next, allowReconnect)
	if err != nil {
		return err
	}
	g.listenerTransaction = transaction
	if err := transaction.Stage(ctx); err != nil {
		var bind *net.OpError
		if errors.As(err, &bind) && bind.Op == "listen" {
			return &runtimeListenerBindError{cause: err}
		}
		return err
	}
	return nil
}

func (g *preparedRuntimeGraph) restoreRuntimeListenersWithEffects(candidateAbsent bool) error {
	if g == nil || g.listenerRestoration != nil {
		return nil
	}
	restoreEffects := func() error {
		if !candidateAbsent {
			return errors.New("candidate registration absence remains unknown")
		}
		g.restoreRuntimePreviousEffects()
		return g.postBindError
	}
	if g.listenerTransaction == nil {
		return restoreEffects()
	}
	restoration := g.listenerTransaction.CompensateBeforeActivate(restoreEffects)
	g.listenerRestoration = &restoration
	if !restoration.Restored {
		if restoration.Error != nil {
			return restoration.Error
		}
		return errors.New("previous listener restoration remains unconfirmed")
	}
	return nil
}

func runtimeAcceptedListenerReconnect(impacts []RuntimeImpact) bool {
	for _, impact := range impacts {
		if (impact.Path == "inbounds" || impact.Path == "services" || impact.Path == "endpoints") && impact.ReconnectRequired {
			return true
		}
	}
	return false
}

func (s *Box) recordRuntimeListenerRestoration(record *runtimePlanRecord, g *preparedRuntimeGraph) {
	if g.listenerRestoration == nil {
		return
	}
	restoration := g.listenerRestoration
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if !restoration.Restored {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "LISTENER_RESTORATION_FAILED", Path: "inbounds", Message: "candidate unpublished; previous physical ingress could not be fully restored"})
	}
	if restoration.LocalReconnect {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "LISTENER_RECONNECT_REQUIRED", Path: "inbounds", Message: "candidate unpublished; local socket handoff interrupted affected sessions"})
	}
}

// Classification grants no OS authority. Typed decode, eligibility, Plan/CAS,
// policy consent, full occupancy reservation and actual bind still run.
func runtimeClientInboundChanges(before, after stdjson.RawMessage, policy uint32) bool {
	if policy != 1 {
		return false
	}
	left, lok := runtimeClientInboundInventory(before)
	right, rok := runtimeClientInboundInventory(after)
	if !lok || !rok {
		return false
	}
	withoutCanary := func(items []map[string]stdjson.RawMessage) []map[string]stdjson.RawMessage {
		result := make([]map[string]stdjson.RawMessage, 0, len(items))
		for _, item := range items {
			if runtimeResourceString(item["tag"]) != "np-probe-in" {
				result = append(result, item)
			}
		}
		return result
	}
	for _, items := range [][]map[string]stdjson.RawMessage{left, right} {
		for _, item := range items {
			if runtimeResourceString(item["tag"]) == "np-probe-in" && !runtimeClientCanaryShape(item) {
				return false
			}
		}
	}
	left, right = withoutCanary(left), withoutCanary(right)
	if len(left) != len(right) {
		return false // changing the main carrier has another App owner
	}
	for index, old := range left {
		next := right[index]
		a, _ := stdjson.Marshal(old)
		b, _ := stdjson.Marshal(next)
		if bytes.Equal(a, b) {
			continue
		}
		if runtimeResourceString(old["tag"]) != runtimeResourceString(next["tag"]) {
			return false
		}
		var fields []string
		switch runtimeResourceString(old["tag"]) {
		case "mixed-in":
			if !runtimeClientMixedShape(old) || !runtimeClientMixedShape(next) {
				return false
			}
			fields = []string{"listen", "listen_port"}
		case "tun-in":
			if !runtimeClientTunShape(old, runtime.GOOS) || !runtimeClientTunShape(next, runtime.GOOS) {
				return false
			}
			fields = runtimeClientTunFields
			if runtime.GOOS == "darwin" {
				// The macOS control is unavailable. Preserve its startup value;
				// a same-shape MTU update does not implement a strict-route toggle.
				fields = append([]string(nil), fields...)
				for i, field := range fields {
					if field == "strict_route" {
						fields = append(fields[:i], fields[i+1:]...)
						break
					}
				}
			}
		default:
			return false
		}
		for _, key := range fields {
			delete(old, key)
			delete(next, key)
		}
		a, _ = stdjson.Marshal(old)
		b, _ = stdjson.Marshal(next)
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

func runtimeClientInboundInventory(content []byte) ([]map[string]stdjson.RawMessage, bool) {
	if len(content) == 0 {
		return nil, true
	}
	var items []map[string]stdjson.RawMessage
	if stdjson.Unmarshal(content, &items) != nil {
		return nil, false
	}
	seen := make(map[string]bool)
	for _, item := range items {
		tag := runtimeResourceString(item["tag"])
		if item == nil || tag == "" || seen[tag] {
			return nil, false
		}
		seen[tag] = true
	}
	return items, true
}

func runtimeResourceString(value stdjson.RawMessage) string {
	var text string
	_ = stdjson.Unmarshal(value, &text)
	return text
}

func runtimeResourceList(value stdjson.RawMessage) ([]string, bool) {
	var list badoption.Listable[string]
	err := json.Unmarshal(value, &list)
	return list, err == nil
}

func runtimeClientPort(value stdjson.RawMessage) bool {
	var port uint16
	return stdjson.Unmarshal(value, &port) == nil && port != 0
}

func runtimeClientMixedShape(item map[string]stdjson.RawMessage) bool {
	listen := runtimeResourceString(item["listen"])
	return len(item) == 4 && runtimeResourceString(item["type"]) == "mixed" &&
		runtimeResourceString(item["tag"]) == "mixed-in" &&
		(listen == "127.0.0.1" || listen == "::" || listen == "0.0.0.0") && runtimeClientPort(item["listen_port"])
}

func runtimeClientCanaryShape(item map[string]stdjson.RawMessage) bool {
	return len(item) == 5 && runtimeResourceString(item["type"]) == "direct" &&
		runtimeResourceString(item["tag"]) == "np-probe-in" &&
		runtimeResourceString(item["network"]) == "udp" &&
		runtimeResourceString(item["listen"]) == "127.0.0.1" && runtimeClientPort(item["listen_port"])
}

func runtimeClientCanaryInbound(item option.Inbound) bool {
	encoded, err := json.MarshalContext(context.Background(), &item)
	var fields map[string]stdjson.RawMessage
	return err == nil && stdjson.Unmarshal(encoded, &fields) == nil && runtimeClientCanaryShape(fields)
}

var runtimeClientTunFields = []string{"mtu", "address", "auto_route", "dns_mode", "auto_redirect", "strict_route", "udp_mapping", "udp_filtering", "route_exclude_address", "include_mac_address", "exclude_mac_address", "exclude_package"}

func runtimeClientTunShape(item map[string]stdjson.RawMessage, platform string) bool {
	if runtimeResourceString(item["type"]) != "tun" || runtimeResourceString(item["tag"]) != "tun-in" ||
		(platform != "linux" && platform != "windows" && platform != "darwin" && platform != "android" && platform != "ios") {
		return false
	}
	mobile := platform == "android" || platform == "ios"
	// This function classifies geometry only. Actual native authority remains
	// registered V1 + policy1 + captured-dependency/physical-owner preflight.
	// Complete closed inventory from the real client generator. Presence of
	// another TUN feature cannot acquire migration support merely by this tag.
	for key := range item {
		switch key {
		case "type", "tag", "interface_name", "address", "mtu", "auto_route", "dns_mode", "auto_redirect", "strict_route", "udp_mapping", "udp_filtering", "route_exclude_address", "include_mac_address", "exclude_mac_address", "exclude_package", "platform":
			if mobile && (key == "interface_name" || key == "dns_mode" || key == "auto_redirect" || key == "strict_route" || key == "include_mac_address" || key == "exclude_mac_address" || key == "platform") {
				return false
			}
			if key == "exclude_package" && platform != "android" {
				return false
			}
		default:
			return false
		}
	}
	if name := runtimeResourceString(item["interface_name"]); name != "" {
		switch platform {
		case "linux":
			if name != "polaris-tun0" {
				return false
			}
		case "windows":
			if len(name) > 32 {
				return false
			}
			for _, char := range name {
				if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
					return false
				}
			}
		default:
			return false
		}
	}
	autoRoute := string(item["auto_route"]) == "true"
	if mode := runtimeResourceString(item["dns_mode"]); mode != "" && (mode != "hijack" || autoRoute) {
		return false
	}
	if raw := item["platform"]; len(raw) != 0 {
		var outer, proxy map[string]stdjson.RawMessage
		if platform != "darwin" || stdjson.Unmarshal(raw, &outer) != nil || len(outer) != 1 || stdjson.Unmarshal(outer["http_proxy"], &proxy) != nil || len(proxy) != 3 || string(proxy["enabled"]) != "true" || runtimeResourceString(proxy["server"]) != "127.0.0.1" || !runtimeClientPort(proxy["server_port"]) {
			return false
		}
	}
	// Only the real client's fixed IPv6 toggle, not arbitrary subnet editing.
	addresses, addressesOK := runtimeResourceList(item["address"])
	if !addressesOK || len(addresses) < 1 || len(addresses) > 2 {
		return false
	}
	v4 := "172.19.0.1/16"
	if platform == "darwin" {
		v4 = "172.19.0.1/30"
	}
	// iOS currently defaults to /16 too. The existing explicit inet4_address
	// override can project the already-supported fixed /30; no generic subnet
	// editor is enabled by accepting those two exact client values.
	if (addresses[0] != v4 && !(platform == "ios" && addresses[0] == "172.19.0.1/30")) || (len(addresses) == 2 && addresses[1] != "fdfe:dcba:9876::1/126") {
		return false
	}
	if value := item["mtu"]; len(value) != 0 {
		var mtu uint32
		if stdjson.Unmarshal(value, &mtu) != nil || (mtu != 0 && (mtu < 576 || mtu > 65535)) {
			return false
		}
	}
	for _, key := range []string{"auto_route", "strict_route"} {
		if value := item[key]; len(value) != 0 {
			var enabled bool
			if stdjson.Unmarshal(value, &enabled) != nil {
				return false
			}
		}
	}
	mapping, filtering := runtimeResourceString(item["udp_mapping"]), runtimeResourceString(item["udp_filtering"])
	if (mapping != "" || filtering != "") && (mapping != "endpoint_independent" ||
		(filtering != "endpoint_independent" && filtering != "address_dependent" && filtering != "address_and_port_dependent")) {
		return false
	}
	if value := item["route_exclude_address"]; len(value) != 0 {
		exclusions, ok := runtimeResourceList(value)
		if !ok {
			return false
		}
		for _, value := range exclusions {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Bits() == 0 || mobile && prefix.Addr().IsLoopback() {
				return false
			}
		}
	}
	if raw := item["exclude_package"]; len(raw) != 0 {
		packages, ok := runtimeResourceList(raw)
		if !ok || len(packages) > 256 {
			return false
		}
		for _, name := range packages {
			if len(name) == 0 || len(name) > 255 || !strings.Contains(name, ".") {
				return false
			}
			for _, part := range strings.Split(name, ".") {
				if part == "" {
					return false
				}
				for index, char := range part {
					if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9')) {
						return false
					}
				}
			}
		}
	}
	macCount := 0
	for _, key := range []string{"include_mac_address", "exclude_mac_address"} {
		if value := item[key]; len(value) != 0 {
			addresses, ok := runtimeResourceList(value)
			if !ok || (len(addresses) != 0 && (platform != "linux" || !autoRoute || string(item["auto_redirect"]) != "true")) {
				return false
			}
			if len(addresses) != 0 {
				macCount++
			}
			for _, value := range addresses {
				if _, err := net.ParseMAC(value); err != nil {
					return false
				}
			}
		}
	}
	if macCount > 1 {
		return false
	}
	if raw := item["auto_redirect"]; len(raw) != 0 && (platform != "linux" || string(raw) != "true" || !autoRoute || macCount != 1) {
		return false
	}
	return true
}

// A direct tag/socket alone does not grant a new general loopback proxy.
func runtimeClientCanaryProblems(ctx context.Context, options option.Options) []RuntimePlanError {
	present := false
	for _, item := range options.Inbounds {
		if item.Tag == "np-probe-in" {
			if !runtimeClientCanaryInbound(item) {
				return []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "inbounds", Message: "network canary requires its exact UDP loopback shape"}}
			}
			present = true
		}
	}
	if !present {
		return nil
	}
	problem := []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "inbounds", DependencyPath: []string{"canary.dns_custody"}, Message: "network canary requires the original hijack and terminal REFUSED rule prefix"}}
	encoded, err := json.MarshalContext(ctx, options)
	var root map[string]stdjson.RawMessage
	if err != nil || stdjson.Unmarshal(encoded, &root) != nil {
		return problem
	}
	rules := func(raw stdjson.RawMessage) []map[string]stdjson.RawMessage {
		var parent struct {
			Rules []map[string]stdjson.RawMessage
		}
		_ = stdjson.Unmarshal(raw, &parent)
		return parent.Rules
	}
	tags := func(raw stdjson.RawMessage) bool {
		list, ok := runtimeResourceList(raw)
		return ok && len(list) == 1 && list[0] == "np-probe-in"
	}
	route := rules(root["route"])
	if len(route) == 0 || len(route[0]) != 2 || !tags(route[0]["inbound"]) || runtimeResourceString(route[0]["action"]) != "hijack-dns" {
		return problem
	}
	for _, rule := range rules(root["dns"]) {
		if !tags(rule["inbound"]) || runtimeResourceString(rule["action"]) != "predefined" {
			return problem
		}
		if runtimeResourceString(rule["rcode"]) == "REFUSED" && len(rule) == 3 {
			return nil
		}
		domains, ok := runtimeResourceList(rule["domain"])
		if !ok || len(domains) != 1 || !strings.HasSuffix(domains[0], ".np-canary.polaris.invalid") {
			return problem
		}
		switch runtimeResourceString(rule["rcode"]) {
		case "NOERROR", "NXDOMAIN":
		default:
			return problem
		}
	}
	return problem
}

// Preserve the actual cause for ownership/compensation while exposing only a
// fixed path/code to the authenticated transaction result, never bind addresses.
type runtimeListenerBindError struct{ cause error }

func (e *runtimeListenerBindError) Error() string { return "candidate listener bind failed" }
func (e *runtimeListenerBindError) Unwrap() error { return e.cause }
func (*runtimeListenerBindError) RuntimePlanError() RuntimePlanError {
	return RuntimePlanError{Code: "LISTENER_BIND_FAILED", Path: "inbounds", Message: "candidate exclusive listener could not bind; candidate not published"}
}
