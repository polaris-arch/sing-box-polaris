package libbox

import (
	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *CommandServer) RuntimeCapabilities() (string, error) {
	result, err := s.StartedService.GetRuntimeCapabilities(daemon.ContextWithRuntimeActor(s.ctx, "libbox:command-owner"), &emptypb.Empty{})
	if err != nil {
		return "", err
	}
	content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(result)
	return string(content), err
}
