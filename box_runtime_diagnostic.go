package box

import (
	"github.com/sagernet/sing-box/route"
)

const (
	cleanupDiagnosticCap    uint64 = 1000000
	cleanupDiagnosticOwners        = 256
)

// Category order: unknown, stable, endpoint, inbound, outbound, DNS, router,
// certificate, HTTP, source producer. State order: open,sealed,closing,closed.
// No tag, incarnation, sequence, address, path, config, or error text is exposed.
type cleanupResourceDiagnostic struct {
	Owners           uint64    `json:"owners"`
	Unavailable      uint64    `json:"unavailable"`
	States           [4]uint64 `json:"states"`
	References       uint64    `json:"references"`
	Dependencies     uint64    `json:"dependencies"`
	EndpointPhases   [8]uint64 `json:"endpointPhases"`
	EndpointFailures uint64    `json:"endpointFailures"`
	OwnerFailures    uint64    `json:"ownerFailures"`
}
type RuntimeCleanupDiagnostic struct {
	Schema        string                          `json:"schema"`
	Atomic        bool                            `json:"atomic"`
	Available     bool                            `json:"available"`
	Preparing     bool                            `json:"preparing"`
	Phase         uint32                          `json:"phase"`
	Done          bool                            `json:"done"`
	Failed        bool                            `json:"failed"`
	Truncated     bool                            `json:"truncated"`
	ResourceCount uint64                          `json:"resourceCount"`
	Resources     [10]cleanupResourceDiagnostic   `json:"resources"`
	Connections   route.ConnectionCleanupSnapshot `json:"connections"`
	Reference     route.ReferenceCleanupSnapshot  `json:"reference"`
}

func cleanupDiagnosticAdd(dst *uint64, n uint64, truncated *bool) {
	if n > cleanupDiagnosticCap || *dst > cleanupDiagnosticCap-n {
		*dst = cleanupDiagnosticCap
		*truncated = true
		return
	}
	*dst += n
}

func cleanupDiagnosticKind(r *runtimeResource, budget *int, truncated *bool) int {
	switch r.kind {
	case "stable":
		return 1
	case "certificate-store":
		return 7
	case "source-producer":
		return 9
	}
	kind := 0
	for _, c := range r.components {
		if *budget == 0 {
			*truncated = true
			return 0
		}
		*budget--
		next := 0
		switch {
		case c.endpoint != nil:
			next = 2
		case c.inbound != nil:
			next = 3
		case c.outbound != nil:
			next = 4
		case c.transport != nil || c.dns != nil:
			next = 5
		case c.router != nil:
			next = 6
		case c.provider != nil:
			next = 7
		case c.httpClients != nil || c.dashboardHTTP != nil:
			next = 8
		}
		if next != 0 && (kind == 0 || next < kind) {
			kind = next
		}
	}
	return kind
}

// RuntimeCleanupSnapshot is deliberately nonblocking and non-atomic across
// subsystems. Missing/contended observations never certify successful cleanup.
func (s *Box) RuntimeCleanupSnapshot() RuntimeCleanupDiagnostic {
	d := RuntimeCleanupDiagnostic{Schema: "runtime-cleanup-v1"}
	c := s.runtime
	if c == nil || !c.access.TryLock() {
		return d
	}
	d.Available = true
	d.Preparing = c.preparing
	cleanupDiagnosticAdd(&d.ResourceCount, uint64(len(c.catalog)), &d.Truncated)
	resources := make([]*runtimeResource, 0, min(len(c.catalog), cleanupDiagnosticOwners))
	for _, r := range c.catalog {
		if len(resources) == cleanupDiagnosticOwners {
			d.Truncated = true
			break
		}
		resources = append(resources, r)
	}
	c.access.Unlock()
	d.Phase = c.shutdownDiagnosticPhase.Load()
	select {
	case <-c.shutdownDone:
		d.Done = true
		d.Failed = c.shutdownError != nil
	default:
	}
	if s.connection != nil {
		d.Connections = s.connection.CleanupSnapshot()
	}
	if c.reference != nil {
		d.Reference = c.reference.CleanupSnapshot()
	}
	for _, n := range []*uint64{&d.Connections.Tasks, &d.Connections.Physical, &d.Reference.Pauses, &d.Reference.Quarantined} {
		if *n > cleanupDiagnosticCap {
			*n = cleanupDiagnosticCap
			d.Truncated = true
		}
	}
	componentBudget := 2048
	for _, r := range resources {
		kind := 0
		if !d.Preparing {
			kind = cleanupDiagnosticKind(r, &componentBudget, &d.Truncated)
		}
		group := &d.Resources[kind]
		group.Owners++
		observed := r.owner.CleanupSnapshot()
		if !observed.Available {
			group.Unavailable++
			continue
		}
		if observed.State > 3 {
			group.Unavailable++
			continue
		}
		group.States[observed.State]++
		if observed.Failed {
			group.OwnerFailures++
		}
		cleanupDiagnosticAdd(&group.References, observed.References, &d.Truncated)
		cleanupDiagnosticAdd(&group.Dependencies, observed.Dependencies, &d.Truncated)
		if !d.Preparing {
			for _, component := range r.components {
				if componentBudget == 0 {
					d.Truncated = true
					break
				}
				componentBudget--
				if endpoint, ok := component.endpoint.(interface{ RuntimeCleanupObservation() (uint32, bool) }); ok {
					phase, failed := endpoint.RuntimeCleanupObservation()
					if phase > 7 {
						group.Unavailable++
						continue
					}
					cleanupDiagnosticAdd(&group.EndpointPhases[phase], 1, &d.Truncated)
					if failed {
						cleanupDiagnosticAdd(&group.EndpointFailures, 1, &d.Truncated)
					}
				}
			}
		}
	}
	return d
}
