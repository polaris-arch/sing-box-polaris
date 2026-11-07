package api

import "sync"

// Dashboard work may survive an address/secret-only API handoff. References
// held by retired ingress generations therefore cannot close its live worker.
type runtimeDashboardResource struct {
	dashboard *dashboard
	access    sync.Mutex
	refs      int
}

func (r *runtimeDashboardResource) retain() {
	if r == nil {
		return
	}
	r.access.Lock()
	r.refs++
	r.access.Unlock()
}

func (r *runtimeDashboardResource) release() error {
	if r == nil {
		return nil
	}
	r.access.Lock()
	r.refs--
	last := r.refs == 0
	r.access.Unlock()
	if last {
		return r.dashboard.close()
	}
	return nil
}
