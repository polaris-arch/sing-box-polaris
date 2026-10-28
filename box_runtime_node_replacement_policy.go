package box

import (
	"context"
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	protocolOC "github.com/sagernet/sing-box/protocol/openconnect"
	protocolTor "github.com/sagernet/sing-box/protocol/tor"
)

func runtimeNodeReplacementProblems(options option.Options, replaced map[string]bool, current []*runtimeResource) []RuntimePlanError {
	existingEndpoints := make(map[string]bool)
	for _, resource := range current {
		for name, component := range resource.components {
			if component.endpoint != nil {
				existingEndpoints[name] = true
			}
		}
	}
	var problems []RuntimePlanError
	add := func(path, field, reason string) {
		if field != "" {
			problems = append(problems, RuntimePlanError{Code: "RESTART_REQUIRED", Path: path + "." + field, Message: reason})
		}
	}
	for index, node := range options.Outbounds {
		tag := node.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		if node.Type != C.TypeTor || !replaced["outbound:"+tag] {
			continue
		}
		if value, ok := node.Options.(*option.TorOutboundOptions); ok {
			field, reason := protocolTor.RuntimeOverlapProblem(*value)
			add(fmt.Sprintf("outbounds[%d]", index), field, reason)
		}
	}
	for index, node := range options.Endpoints {
		tag := node.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		name := "endpoint:" + tag
		if !replaced[name] {
			continue
		}
		switch value := node.Options.(type) {
		case *option.OpenVPNClientEndpointOptions:
			if value.System {
				add(fmt.Sprintf("endpoints[%d]", index), "system", "system device handoff requires restart")
			}
		case *option.MASQUEClientEndpointOptions:
			if value.System {
				add(fmt.Sprintf("endpoints[%d]", index), "system", "system device handoff requires restart")
			}
		}
		if node.Type != C.TypeOpenConnect {
			continue
		}
		if value, ok := node.Options.(*option.OpenConnectEndpointOptions); ok {
			field, reason := protocolOC.RuntimeReplacementProblem(*value)
			// A newly added HOTP owner starts from its configured counter. Only reuse
			// of an existing identity needs transfer of the already consumed counter.
			if field == "token.counter" && !existingEndpoints[name] {
				continue
			}
			add(fmt.Sprintf("endpoints[%d]", index), field, reason)
		}
	}
	return problems
}

func (s *Box) preflightRuntimeNodeReplacements(ctx context.Context, options option.Options, intents []RuntimeSelectorIntent, rootDigest [32]byte) ([]RuntimePlanError, error) {
	s.runtime.access.Lock()
	current := append([]*runtimeResource(nil), s.runtime.resources...)
	s.runtime.access.Unlock()
	replaced, err := runtimeReplacementNames(ctx, options, intents, rootDigest, current)
	if err != nil {
		return nil, err
	}
	return runtimeNodeReplacementProblems(options, replaced, current), nil
}

func (s *Box) checkPreparedRuntimeNodeReplacements(g *preparedRuntimeGraph) error {
	if g.initial {
		return nil
	}
	replaced := make(map[string]bool)
	for _, resource := range g.created {
		for name := range resource.components {
			replaced[name] = true
		}
	}
	s.runtime.access.Lock()
	current := append([]*runtimeResource(nil), s.runtime.resources...)
	s.runtime.access.Unlock()
	if problems := runtimeNodeReplacementProblems(g.options, replaced, current); len(problems) > 0 {
		return &runtimeEndpointRestartRequiredError{detail: problems[0]}
	}
	return nil
}
