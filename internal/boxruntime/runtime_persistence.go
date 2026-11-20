package boxruntime

import (
	"context"
	"errors"
)

// Persistence never rolls back a published graph.
func runtimePersistCommitted(identity RuntimeIdentity, canonical []byte, persist func(RuntimeIdentity, []byte) error) (err error) {
	defer func() {
		if recover() != nil {
			err = &runtimePersistenceUncertainError{}
		}
	}()
	return persist(identity, append([]byte(nil), canonical...))
}

type runtimePersistenceUncertainError struct{}

func (*runtimePersistenceUncertainError) Error() string {
	return "runtime persistence tail panicked; durability remains pending"
}

func runtimePersistenceUncertain(err error) bool {
	var panicError *runtimePersistenceUncertainError
	var cleanup interface{ RuntimeCleanupIncomplete() bool }
	return errors.As(err, &panicError) || errors.Is(err, errRuntimeCleanupIncomplete) || (errors.As(err, &cleanup) && cleanup.RuntimeCleanupIncomplete())
}

func (c *runtimeCoordinator) persistRuntimeTransaction(ctx context.Context, identity RuntimeIdentity, canonical []byte, intents []RuntimeSelectorIntent, persist func(RuntimeIdentity, []byte) error) error {
	if err := c.controlEffects.LockContext(ctx); err != nil {
		return err
	}
	defer c.controlEffects.Unlock()
	return c.persistRuntimeTransactionLocked(ctx, identity, canonical, intents, persist)
}

// The caller owns controlEffects for the entire synchronous durability tail.
func (c *runtimeCoordinator) persistRuntimeTransactionLocked(ctx context.Context, identity RuntimeIdentity, canonical []byte, intents []RuntimeSelectorIntent, persist func(RuntimeIdentity, []byte) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime persistence tail panicked; durability remains pending")
		}
	}()
	c.access.Lock()
	current := !c.stopped && c.active == identity
	c.access.Unlock()
	if !current {
		return errors.New("newer runtime control superseded durable transaction")
	}
	if err := runtimePersistSelectorIntents(ctx, intents); err != nil {
		return err
	}
	checkedPersist := func(id RuntimeIdentity, content []byte) error {
		err := persist(id, content)
		if err == nil && c.persistenceMode == "app_authoritative_regeneration" {
			return errors.New("owner reload receipt is required before desired-state acknowledgement")
		}
		return err
	}
	return runtimePersistCommitted(identity, canonical, checkedPersist)
}
