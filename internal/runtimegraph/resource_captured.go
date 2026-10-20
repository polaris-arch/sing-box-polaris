package runtimegraph

import "github.com/sagernet/sing-box/adapter"

// RetainCapturedResource never creates an owner/root reservation. A concrete
// registered callback fence supplies the owner's lifetime; only already-owned
// dependency handles authorize this traversal. Racing terminal cleanup fails
// closed if any captured root has already been released.
func (o *ResourceOwner) RetainCapturedResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	if o == nil || o.owner == nil {
		return nil, ErrResourceNotMember
	}
	r := o.owner
	if id == r.id || id.Sequence == 0 || id.Incarnation != r.id.Incarnation {
		return nil, ErrResourceNotMember
	}
	r.mu.Lock()
	closed := r.state == resourceClosed
	r.mu.Unlock()
	if closed {
		return nil, errResourceSealed
	}
	roots := make([]*resourceLease, 0, len(r.dependencies))
	defer func() {
		for _, root := range roots {
			root.release()
		}
	}()
	for _, dependency := range r.dependencies {
		root, err := dependency.fork()
		if err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	// Each root pins its entire immutable dependency closure. No owner mutex is
	// held while acquiring another owner, and duplicate IDs must identify the
	// very same owner even when multiple paths converge.
	seen := make(map[adapter.RuntimeResourceID]*resourceOwner)
	pending := append([]*resourceLease(nil), roots...)
	var found *resourceLease
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		currentID := current.ID()
		if previous := seen[currentID]; previous != nil {
			if previous != current.owner {
				return nil, ErrResourceNotMember
			}
			continue
		}
		if currentID.Incarnation != id.Incarnation || currentID == r.id {
			return nil, ErrResourceNotMember
		}
		seen[currentID] = current.owner
		if currentID == id {
			found = current
		}
		pending = append(pending, current.owner.dependencies...)
	}
	if found == nil {
		return nil, ErrResourceNotMember
	}
	return found.Fork()
}

var _ adapter.RuntimeCapturedResourceSource = (*ResourceOwner)(nil)
