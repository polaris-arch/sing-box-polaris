//go:build !with_naive_outbound

package naive

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

const RuntimeClientSharing = false

func NewRuntimeClientGroup(context.Context, log.ContextLogger, option.NaiveOutboundOptions) (func(context.Context) context.Context, error) {
	return nil, errors.New("Naive outbound is not included in this build")
}
