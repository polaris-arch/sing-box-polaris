package qtls

import (
 "context"
 "github.com/sagernet/quic-go"
 aTLS "github.com/sagernet/sing/common/tls"
)

// ServerRuntime is optional. Context comes from the accepted physical QUIC
// connection, never a new lookup of the current routing graph. Task must reserve
// synchronously before launching, return false without invoking task on denial,
// and join admitted work before its owner reports cleanup complete.
// The constructor context is valid only for the private accept-loop worker.
type ServerRuntime interface {
 RuntimeServerContext(context.Context, *quic.Conn) (context.Context, error)
 RuntimeServerTask(context.Context, func(context.Context)) bool
}

func RuntimeServerSupported() bool { return true }

func ServerConnectionContext(config aTLS.ServerConfig, fallback context.Context, connection *quic.Conn) (context.Context, error) {
 if runtime, ok := config.(ServerRuntime); ok { return runtime.RuntimeServerContext(fallback, connection) }
 return fallback, nil
}

func RunServerTask(config aTLS.ServerConfig, ctx context.Context, task func(context.Context)) bool {
 if runtime, ok := config.(ServerRuntime); ok { return runtime.RuntimeServerTask(ctx, task) }
 go task(ctx)
 return true
}
