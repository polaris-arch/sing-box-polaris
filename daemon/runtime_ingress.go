package daemon

import (
	"context"

	"google.golang.org/grpc"
)

// RuntimeIngress is supplied by the actual local listener owner. It is never
// populated from metadata, a credential hash, or a request's actor declaration.
// AfterUnary sees only a successfully authenticated, completed Core operation.
type RuntimeIngress interface {
	Actor() string
	BeforeUnary(context.Context, string, any) (func(), error)
	AfterUnary(context.Context, string, any, any) error
	StreamContext(context.Context) (context.Context, func(), error)
}

func ingressUnary(owner RuntimeIngress) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		release, err := owner.BeforeUnary(ctx, info.FullMethod, request)
		if err != nil {
			return nil, err
		}
		defer release()
		ctx = ContextWithRuntimeActor(ctx, owner.Actor())
		response, err := handler(ctx, request)
		if err == nil {
			err = owner.AfterUnary(ctx, info.FullMethod, request, response)
		}
		return response, err
	}
}

type ingressStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s ingressStream) Context() context.Context { return s.ctx }

func ingressStreams(owner RuntimeIngress) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, release, err := owner.StreamContext(stream.Context())
		if err != nil {
			return err
		}
		defer release()
		return handler(server, ingressStream{ServerStream: stream, ctx: ContextWithRuntimeActor(ctx, owner.Actor())})
	}
}
