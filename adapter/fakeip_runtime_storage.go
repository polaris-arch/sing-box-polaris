package adapter

import (
	"context"
	"net/netip"
	"time"

	mDNS "github.com/miekg/dns"
)

// These interfaces describe persistence, not runtime configuration selection.
// A prepared bucket or link is never evidence that its graph was published.
// Startup uses its explicit effective configuration and imports issued-answer
// recognition separately. All returned snapshots are detached copies.
type FakeIPAnswerContextProtection interface {
	ProtectAnswerContext(context.Context, *mDNS.Msg) (FakeIPAnswerLease, error)
}

type FakeIPStorageSnapshot struct {
	// Issued means a post-publication allocator/answer write was admitted.
	// It does not assert that a network peer received an answer.
	Issued         bool
	Metadata       *FakeIPMetadata
	Mappings       map[netip.Addr]string
	Answers        []FakeIPRuntimeAnswer
	PendingAnswers []FakeIPRuntimeAnswer
}

type FakeIPRuntimeBackendDescriptor struct {
	Path       string
	CacheID    string
	DatabaseID string
}

type FakeIPRuntimeNamespaceDescriptor struct {
	Version uint8
	// Immutable fixed-journal owner; a shared cache can contain other owners.
	AnchorDatabaseID         string
	Backend                  FakeIPRuntimeBackendDescriptor
	ID                       string
	EffectiveConfigurationID string
	LogicalID                string
	Allocator                bool
	Generation               uint64
}

type FakeIPRuntimeAnswer struct {
	Token    uint64
	Obsolete bool
	// Superseded is an exact identity invalidation, unlike an expired copy.
	// It wins over an equally revised stale pending copy during recovery.
	Superseded bool
	Address    netip.Addr
	Domain     string
	// Global address-authority order, assigned only after actual mapping
	// arbitration. Newer different-domain certificates supersede stale copies.
	Revision   uint64
	Pending    uint64
	PendingTTL uint32
	ExpiresAt  time.Time
}

type FakeIPRuntimeLink struct {
	ID                       string
	EffectiveConfigurationID string
	Namespaces               []FakeIPRuntimeNamespaceDescriptor
	Acknowledged             bool
	// DiscoveryReady certifies all participant descriptors/links were durable;
	// it does not certify graph publication or choose the active configuration.
	DiscoveryReady bool
}

type FakeIPRuntimeCatalog struct {
	Namespaces []FakeIPRuntimeNamespaceDescriptor
	Links      []FakeIPRuntimeLink
}

// A namespace handle permanently names one database identity and bucket. It
// must never follow an active-bucket pointer when an old graph writes through it.
type FakeIPRuntimeNamespace interface {
	FakeIPStorage
	Descriptor() FakeIPRuntimeNamespaceDescriptor
	Snapshot(context.Context) (FakeIPStorageSnapshot, error)
	// SnapshotAllocation is a detached RAM-only allocator image, without
	// durability claims; migration combines it with exact manager tokens.
	SnapshotAllocation() FakeIPStorageSnapshot
	Flush(context.Context) error
	// QueueAuthority is RAM-only and uses the existing bounded write batch.
	// A newer reassignment tombstone prevents old certificates resurrecting.
	QueueAuthority(FakeIPRuntimeAnswer)
	// Observe certifies pending egress durably, with deduplication when an
	// existing durable pending certificate already covers this identity/TTL.
	Observe(context.Context, []FakeIPRuntimeAnswer) error
	// Complete may batch the absolute expiry. A failed write leaves the old
	// pending certificate recoverable, rather than pretending it completed.
	Complete(context.Context, []FakeIPRuntimeAnswer, time.Time, bool) error
	// Recover commits pending -> one absolute expiry before returning. A
	// restart after that transaction reuses the same expiry, never now+TTL.
	Recover(context.Context, time.Time) ([]FakeIPRuntimeAnswer, error)
	RecoverWithDeadlines(context.Context, time.Time, map[uint64]time.Time) ([]FakeIPRuntimeAnswer, error)
	// Invalidate removes only the specified baseline-reused identity revision.
	Invalidate(context.Context, []FakeIPRuntimeAnswer) error
	// Abort succeeds only if there is no durable or queued admitted write.
	Abort(context.Context) error
	// Reclaim requires the owner to have sealed every writer and released all
	// actual answer/flow protections. It removes even conservative disk pending
	// markers left by failed completion writes; that proof comes from the owner.
	Reclaim(context.Context) error
}

type FakeIPRuntimeCounters struct {
	Revision uint64
	Token    uint64
}

type FakeIPRuntimeBackend interface {
	// Reserve is called only on the fixed recovery anchor. Returned floors
	// cover all earlier reserved IDs, including aborted gaps. New IDs must
	// be strictly greater than the floor and at most the returned ceiling.
	ReserveFakeIPRuntimeCounters(context.Context, FakeIPRuntimeCounters, uint64) (FakeIPRuntimeCounters, FakeIPRuntimeCounters, error)
	// Fixed-anchor maintenance only. Retain the maximal per-address identity
	// before deleting a newer namespace that suppresses older certificates.
	RetainFakeIPRuntimeAuthority(context.Context, []FakeIPRuntimeAnswer) error
	FakeIPRuntimeAuthority(context.Context) ([]FakeIPRuntimeAnswer, error)
	// Complete fixed-anchor discovery and serialized link removal are required.
	// Ranges include namespaces with any actual in-flight writer ownership.
	PruneFakeIPRuntimeAuthority(context.Context, []netip.Prefix) error
	AllocateFakeIPGeneration(context.Context) (uint64, error)
	SnapshotFakeIP(context.Context) (FakeIPStorageSnapshot, error)
	RuntimeDescriptor(context.Context) (FakeIPRuntimeBackendDescriptor, error)
	PrepareFakeIPNamespace(context.Context, FakeIPRuntimeNamespaceDescriptor, FakeIPStorageSnapshot) (FakeIPRuntimeNamespace, error)
	OpenFakeIPNamespace(context.Context, string) (FakeIPRuntimeNamespace, error)
	FakeIPRuntimeCatalog(context.Context) (FakeIPRuntimeCatalog, error)
	// Cold-start only, after complete anchor discovery and before admission.
	// It visits only this already-open physical file, including old cache IDs.
	ReclaimFakeIPRuntimeOrphans(context.Context, string, []FakeIPRuntimeNamespaceDescriptor) error
	SaveFakeIPRuntimeLink(context.Context, FakeIPRuntimeLink) error
	RemoveFakeIPRuntimeLink(context.Context, string) error
	ResolveFakeIPPendingExpiries(context.Context, []FakeIPRuntimeAnswer, time.Time) (map[uint64]time.Time, uint64, error)
	ReleaseFakeIPPendingExpiries(context.Context, []uint64) error
}

// Resolve must enforce the coordinator's configured/custody allowlist BEFORE
// opening Path, then compare immutable DatabaseID from the actual file. An
// arbitrary pathname read from a journal never authorizes filesystem access.
// Release is held until all namespace operations and recovery I/O complete.
type FakeIPRuntimeResolver interface {
	ResolveFakeIPRuntime(context.Context, FakeIPRuntimeBackendDescriptor) (FakeIPRuntimeBackend, func() error, error)
}
