package box

import "errors"

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
