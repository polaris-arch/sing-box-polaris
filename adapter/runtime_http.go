package adapter

import "context"

// RuntimeDashboardHTTPProvider admits only clients prepared for stable dashboard
// services. It is not an HTTPClientManager and cannot create clients after graph
// publication. A successful lease must outlive redirects, body close and idle
// connection cleanup for the entire fetch.
type RuntimeDashboardHTTPProvider interface {
	AcquireDashboardHTTP(context.Context, string) (RuntimeDashboardHTTPLease, error)
}

type RuntimeDashboardHTTPLease interface {
	Context() context.Context
	Transport() HTTPTransport
	Release()
}
