package libbox

import (
 "errors"
 box "github.com/sagernet/sing-box"
)

// RuntimePersistenceHandler belongs to one exact native start/reload owner.
// The callback is synchronous after runtime publication, outside publication
// and daemon lifecycle locks. Close joins this callback: do not dispatch-sync
// to a queue that may be waiting for Close, or call back into the kernel.
//
// Return nil only after the established authoritative App persistence contract
// and the owner's actual reload source have both accepted this generation.
// Diagnostic snapshots or an asynchronous "accepted" signal do not qualify.
// The App decides how its existing persisted desired-profile/bootstrap state
// satisfies restart semantics; this interface introduces no new storage path.
// A revoked/replaced host owner or any write/ack error must return an error.
// In app_authoritative_regeneration mode a successful callback is only the
// provider reload receipt. An authenticated App acknowledgement must separately
// confirm its durable desired generation before the operation becomes durable.
// Publication is never rolled back; failures leave durability pending.
type RuntimePersistenceHandler interface {
 RuntimePersistenceMode() string
 PersistRuntimeConfiguration(incarnation string, revision int64, effectiveDigest string, configContent string) error
}

func runtimeHostPersistence(handler RuntimePersistenceHandler, mode string) func(box.RuntimeIdentity, []byte) error {
 return func(identity box.RuntimeIdentity, content []byte) error {
  if identity.Incarnation == "" || identity.Revision > 1<<63-1 { return errors.New("runtime host persistence identity is invalid") }
  if err := handler.PersistRuntimeConfiguration(identity.Incarnation, int64(identity.Revision), identity.EffectiveDigest, string(content)); err != nil { return err }
  if mode == "app_authoritative_regeneration" { return &box.RuntimeOwnerAcknowledgementRequiredError{Mode: mode} }
  return nil
 }
}
