package ping

import (
	"context"
	"fmt"
)

// cleanupFailure deliberately has no Unwrap. A canceled/deadline close is
// uncertainty about resource release, not benign observer cancellation. Owners
// such as adapter.Scope must retain this failure rather than filter it out.
type cleanupFailure struct {
	message string
	// Retain a partially acquired handle if construction cannot prove cleanup.
	resource any
}

func (e *cleanupFailure) Error() string { return e.message }

func cleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &cleanupFailure{message: fmt.Sprintf("ping %s: %v", operation, err), resource: err}
}

func runCleanup(operation string, cleanup func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = &cleanupFailure{message: fmt.Sprintf("ping %s panic: %v", operation, value)}
		}
	}()
	return cleanupError(operation, cleanup())
}

// A completed result wins over an already canceled observer, including the
// race between the first readiness probe and selection of ctx.Done().
func waitCompletion(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		select {
		case <-done:
			return nil
		default:
			return ctx.Err()
		}
	}
}
