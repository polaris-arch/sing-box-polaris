package clashmode

import "github.com/sagernet/sing/common/observable"

// RemoveUpdateHook removes future registrations. A previously captured detached
// mode effect may still emit its payload-free notification; the receiver must
// seal its own admission before unregistering and join its actual work.
func (m *Manager) RemoveUpdateHook(hook *observable.Subscriber[struct{}]) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	kept := m.updateHooks[:0]
	for _, current := range m.updateHooks { if current != hook { kept = append(kept, current) } }
	for i := len(kept); i < len(m.updateHooks); i++ { m.updateHooks[i] = nil }
	m.updateHooks = kept
}
