package runtimegraph

import "github.com/sagernet/sing-box/adapter"

// RetainResource continues work through this resource's captured dependency DAG.
// A temporary source Fork pins the immutable ownership edges throughout traversal;
// no owner mutex is held while taking a different owner's mutex. An exact-ID
// dependency can continue after seal, but an unknown resource cannot be admitted.
func (l *resourceLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	reservation, err := l.fork()
	if err != nil { return nil, err }
	defer reservation.release()
	if id.Incarnation != reservation.ID().Incarnation || id.Sequence == 0 { return nil, ErrResourceNotMember }
	seen := make(map[adapter.RuntimeResourceID]*resourceOwner)
	pending := []*resourceLease{reservation}
	var found *resourceLease
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		currentID := current.ID()
		if previous := seen[currentID]; previous != nil {
			if previous != current.owner { return nil, ErrResourceNotMember }
			continue
		}
		if currentID.Incarnation != id.Incarnation { return nil, ErrResourceNotMember }
		seen[currentID] = current.owner
		if currentID == id { found = current }
		pending = append(pending, current.owner.dependencies...)
	}
	if found == nil { return nil, ErrResourceNotMember }
	retained, err := found.fork()
	if err != nil { return nil, err }
	return retained, nil
}

var _ adapter.RuntimeResourceContinuation = (*resourceLease)(nil)
var _ adapter.RuntimeResourceSource = (*ResourceOwner)(nil)
