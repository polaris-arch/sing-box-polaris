package box

import (
	"context"
	"errors"
)

// These operations observe/acknowledge already-owned persistence work. They
// never roll back a published graph or detach a failed backend's ownership.
type runtimePersistenceParticipant interface {
	WaitPersistence(context.Context) error
	AcknowledgePersistence(context.Context, string) error
}

func runtimePersistCommitted(ctx context.Context, identity RuntimeIdentity, canonical []byte, persist func(RuntimeIdentity, []byte) error, migration runtimePersistenceParticipant) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime persistence tail panicked; durability remains pending")
		}
	}()
	if migration != nil {
		if err := migration.WaitPersistence(ctx); err != nil {
			return err
		}
	}
	if err := persist(identity, append([]byte(nil), canonical...)); err != nil {
		return err
	}
	if migration != nil {
		return migration.AcknowledgePersistence(ctx, identity.EffectiveDigest)
	}
	return nil
}
