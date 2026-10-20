package libbox

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func runtimeRequestJSON(content string, message proto.Message) error {
	if len(content) == 0 || len(content) > 5<<20 {
		return errors.New("runtime request exceeds input budget")
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(content), message); err != nil {
		return errors.New("invalid runtime request JSON")
	}
	return nil
}

func runtimeResponseJSON(message proto.Message, err error) (string, error) {
	if err != nil {
		return "", err
	}
	content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(message)
	return string(content), err
}

func (s *CommandServer) runtimeContext() context.Context {
	return daemon.ContextWithRuntimeActor(s.ctx, "libbox:command-owner")
}

func (s *CommandServer) RuntimeCapabilities() (string, error) {
	result, err := s.StartedService.GetRuntimeCapabilities(s.runtimeContext(), &emptypb.Empty{})
	return runtimeResponseJSON(result, err)
}

func (s *CommandServer) PlanRuntimeConfig(requestJSON string) (string, error) {
	var request daemon.PlanRuntimeConfigRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	result, err := s.StartedService.PlanRuntimeConfig(s.runtimeContext(), &request)
	return runtimeResponseJSON(result, err)
}

func (s *CommandServer) ApplyRuntimeConfig(requestJSON string) (string, error) {
	var request daemon.ApplyRuntimeConfigRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	result, err := s.StartedService.ApplyRuntimeConfig(s.runtimeContext(), &request)
	return runtimeResponseJSON(result, err)
}

func (s *CommandServer) RuntimeConfigStatus(requestJSON string) (string, error) {
	var request daemon.RuntimeConfigStatusRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	result, err := s.StartedService.GetRuntimeConfigStatus(s.runtimeContext(), &request)
	return runtimeResponseJSON(result, err)
}

func (c *CommandClient) runtimeClientForCall() (daemon.RuntimeConfigServiceClient, context.Context, error) {
	if _, _, err := c.getClientForCall(); err != nil {
		return nil, nil, err
	}
	c.clientAccess.RLock()
	defer c.clientAccess.RUnlock()
	if c.grpcRuntimeClient == nil || c.ctx.Err() != nil {
		return nil, nil, errors.New("runtime command connection is closed")
	}
	return c.grpcRuntimeClient, c.ctx, nil
}

func (c *CommandClient) RuntimeCapabilities() (string, error) {
	client, ctx, err := c.runtimeClientForCall()
	if err != nil {
		return "", err
	}
	result, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	return runtimeResponseJSON(result, err)
}

func (c *CommandClient) PlanRuntimeConfig(requestJSON string) (string, error) {
	var request daemon.PlanRuntimeConfigRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	client, ctx, err := c.runtimeClientForCall()
	if err != nil {
		return "", err
	}
	result, err := client.PlanRuntimeConfig(ctx, &request)
	return runtimeResponseJSON(result, err)
}

func (c *CommandClient) ApplyRuntimeConfig(requestJSON string) (string, error) {
	var request daemon.ApplyRuntimeConfigRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	client, ctx, err := c.runtimeClientForCall()
	if err != nil {
		return "", err
	}
	result, err := client.ApplyRuntimeConfig(ctx, &request)
	return runtimeResponseJSON(result, err)
}

func (c *CommandClient) RuntimeConfigStatus(requestJSON string) (string, error) {
	var request daemon.RuntimeConfigStatusRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	client, ctx, err := c.runtimeClientForCall()
	if err != nil {
		return "", err
	}
	result, err := client.GetRuntimeConfigStatus(ctx, &request)
	return runtimeResponseJSON(result, err)
}

func (s *CommandServer) AcknowledgeRuntimePersistence(requestJSON string) (string, error) {
	var request daemon.RuntimePersistenceAcknowledgementRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	result, err := s.StartedService.AcknowledgeRuntimePersistence(s.runtimeContext(), &request)
	return runtimeResponseJSON(result, err)
}

func (c *CommandClient) AcknowledgeRuntimePersistence(requestJSON string) (string, error) {
	var request daemon.RuntimePersistenceAcknowledgementRequest
	if err := runtimeRequestJSON(requestJSON, &request); err != nil {
		return "", err
	}
	client, ctx, err := c.runtimeClientForCall()
	if err != nil {
		return "", err
	}
	result, err := client.AcknowledgeRuntimePersistence(ctx, &request)
	return runtimeResponseJSON(result, err)
}
