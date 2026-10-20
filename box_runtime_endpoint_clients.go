package box

import (
	"context"
	"errors"
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

// Prepared client endpoints own private userspace engines. Physical system
// devices and servers are rejected by their validators before Stage. Publication
// callbacks must contain prevalidated RAM stores only, never external I/O.
type runtimePreparedClientEndpoint interface {
	adapter.Endpoint
	RuntimeValidate() error
	RuntimeReservePhysical(context.Context) error
	RuntimeStagePhysical(context.Context) error
	RuntimeReleasePhysicalReservation(context.Context) error
	RuntimeCloseAndWait() error
	RuntimePreparePublication() (func(), error)
}

type runtimeClientEndpointTransaction struct {
	next     []runtimePreparedClientEndpoint
	reserved []runtimePreparedClientEndpoint
	publish  []func()
}

func runtimeClientEndpointParticipants(resources []*runtimeResource) []runtimePreparedClientEndpoint {
	var result []runtimePreparedClientEndpoint
	seen := make(map[adapter.Endpoint]bool)
	for _, resource := range resources {
		for _, component := range resource.components {
			if value, ok := component.endpoint.(runtimePreparedClientEndpoint); ok && !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	return result
}

func (t *runtimeClientEndpointTransaction) stage(ctx context.Context) error {
	// Validate every participant before any candidate is allowed to bind.
	for _, value := range t.next {
		if err := value.RuntimeValidate(); err != nil {
			return err
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return err
		}
		t.reserved = append(t.reserved, value)
		if err := value.RuntimeReservePhysical(ctx); err != nil {
			return err
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := value.RuntimeStagePhysical(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (t *runtimeClientEndpointTransaction) preparePublication() error {
	t.publish = nil
	for _, value := range t.next {
		publish, err := value.RuntimePreparePublication()
		if err != nil {
			return err
		}
		if publish == nil {
			return errors.New("endpoint returned no prepared publication")
		}
		t.publish = append(t.publish, publish)
	}
	return nil
}

func (t *runtimeClientEndpointTransaction) compensate(ctx context.Context) error {
	var result error
	for _, value := range slices.Backward(t.next) {
		result = errors.Join(result, value.RuntimeCloseAndWait())
	}
	for _, value := range slices.Backward(t.reserved) {
		result = errors.Join(result, value.RuntimeReleasePhysicalReservation(ctx))
	}
	return result
}
