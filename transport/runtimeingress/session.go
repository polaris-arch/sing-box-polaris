package runtimeingress

import "context"

// BindSession transfers one existing admission reservation to the concrete
// protocol connection's terminal context. It does not choose a graph itself.
func BindSession(connection context.Context, acquire func(context.Context) (context.Context, func(), error)) (context.Context, error) {
	owned, release, err := acquire(connection)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(connection, release)
	return owned, nil
}
