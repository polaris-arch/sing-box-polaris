package fakeip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

type recoveredPersistence struct {
	handles []adapter.FakeIPRuntimeNamespace
	backends map[adapter.FakeIPRuntimeBackendDescriptor]adapter.FakeIPRuntimeBackend
	releases []func() error
	links map[string]adapter.FakeIPRuntimeLink
	namespaces []*memoryNamespace
	selection string
	selectionAcknowledged bool
}
type recoveredImage struct {
	handle adapter.FakeIPRuntimeNamespace
	snapshot adapter.FakeIPStorageSnapshot
	records []adapter.FakeIPRuntimeAnswer
}
type recoveredIdentity struct { answer adapter.FakeIPRuntimeAnswer; image *recoveredImage }

// RecoverPersistent imports recognition only. It never selects the running
// configuration from a source tag, a prepared bucket, or a local checkpoint.
// The caller supplies the explicit startup effective identity, runs this before
// graph answer admission, then prepares its configured allocator as usual.
func (m *Manager) RecoverPersistent(ctx context.Context, anchor adapter.FakeIPRuntimeBackend, resolver adapter.FakeIPRuntimeResolver, effectiveID string, configured ...adapter.FakeIPRuntimeBackend) error {
	if anchor == nil || resolver == nil { return ErrRecoveryAnchorRequired }
	if effectiveID == "" { return ErrPersistenceIdentity }
	done, ok := m.work.Reserve(); if !ok { return lifecycle.ErrStopped }; defer done()
	m.mappingAccess.Lock()
	if !m.started.Load() || m.preparing != nil || len(m.pendingAnswers) != 0 || m.active.handles != 0 || m.recovered != nil { m.mappingAccess.Unlock(); return ErrPersistencePreparing }
	active := m.active; storage := active.store.storage
	m.mappingAccess.Unlock()
	activeSnapshot, err := storageSnapshot(ctx, storage); if err != nil { return err }
	recovered := &recoveredPersistence{backends: make(map[adapter.FakeIPRuntimeBackendDescriptor]adapter.FakeIPRuntimeBackend), links: make(map[string]adapter.FakeIPRuntimeLink), selection: effectiveID}
	keep := false
	defer func() { if !keep { for _, release := range recovered.releases { _ = release() } } }()
	root, err := anchor.RuntimeDescriptor(ctx); if err != nil { return err }
	queue := []adapter.FakeIPRuntimeBackendDescriptor{root}
	for _, backend := range configured { descriptor, err := backend.RuntimeDescriptor(ctx); if err != nil { return err }; queue = append(queue, descriptor) }
	allowed := make(map[adapter.FakeIPRuntimeNamespaceDescriptor]bool)
	type catalogNamespace struct { backend adapter.FakeIPRuntimeBackend; descriptor adapter.FakeIPRuntimeNamespaceDescriptor }
	var namespaceCatalog []catalogNamespace
	var incompleteLinks []struct { backend adapter.FakeIPRuntimeBackend; id string }
	var images []*recoveredImage
	var tokens []adapter.FakeIPRuntimeAnswer
	for len(queue) != 0 {
		descriptor := queue[0]; queue = queue[1:]
		if _, seen := recovered.backends[descriptor]; seen { continue }
		backend, release, err := resolver.ResolveFakeIPRuntime(ctx, descriptor); if err != nil { return fmt.Errorf("recover fake-IP backend %q: %w", descriptor.DatabaseID, err) }
		actual, err := backend.RuntimeDescriptor(ctx)
		if err != nil || actual != descriptor { _ = release(); if err != nil { return err }; return ErrPersistenceIdentity }
		recovered.backends[descriptor] = backend; recovered.releases = append(recovered.releases, release)
		catalog, err := backend.FakeIPRuntimeCatalog(ctx); if err != nil { return err }
		for _, link := range catalog.Links {
			owned, err := recoveryLinkOwned(link, root.DatabaseID); if err != nil { return err }; if !owned { continue }
			if descriptor == root {
				if !link.DiscoveryReady { incompleteLinks = append(incompleteLinks, struct { backend adapter.FakeIPRuntimeBackend; id string }{backend, link.ID}); continue }
				recovered.links[link.ID] = link
				for _, namespace := range link.Namespaces { if namespace.Backend.DatabaseID == "" { return ErrPersistenceIdentity }; allowed[namespace] = true; queue = append(queue, namespace.Backend) }
			} else if previous, found := recovered.links[link.ID]; found {
				if !sameRuntimeLink(previous, link) { return ErrPersistenceIdentity }
				previous.Acknowledged = previous.Acknowledged && link.Acknowledged; recovered.links[link.ID] = previous
			} else { incompleteLinks = append(incompleteLinks, struct { backend adapter.FakeIPRuntimeBackend; id string }{backend, link.ID}) }
		}
		for _, namespace := range catalog.Namespaces {
			if err := validateRecoveryNamespace(namespace); err != nil { return err }
			if namespace.Backend != descriptor { return ErrPersistenceIdentity }
			if namespace.AnchorDatabaseID != root.DatabaseID { continue }
			namespaceCatalog = append(namespaceCatalog, catalogNamespace{backend, namespace})
		}
	}
	seenNamespaces := make(map[adapter.FakeIPRuntimeNamespaceDescriptor]bool)
	for _, entry := range namespaceCatalog {
		seenNamespaces[entry.descriptor] = true
		if !allowed[entry.descriptor] { continue }
		handle, err := entry.backend.OpenFakeIPNamespace(ctx, entry.descriptor.ID); if err != nil { return err }
		if handle.Descriptor() != entry.descriptor { return ErrPersistenceIdentity }
		snapshot, err := handle.Snapshot(ctx); if err != nil { return err }
		images = append(images, &recoveredImage{handle: handle, snapshot: snapshot})
		recovered.handles = append(recovered.handles, handle)
		tokens = append(tokens, snapshot.PendingAnswers...)
	}
	for descriptor := range allowed { if !seenNamespaces[descriptor] { return fmt.Errorf("%w: ready namespace %q is missing", ErrPersistenceIdentity, descriptor.ID) } }
	// No cleanup/deadline writes precede complete, validated discovery. A
	// foreign anchor, missing participant or unknown format cannot authorize
	// reclaiming an apparently orphaned bucket in an already configured file.
	if err = validateRecoveryImages(images); err != nil { return err }
	authorityRecords, err := anchor.FakeIPRuntimeAuthority(ctx); if err != nil { return err }
	if err = validateRetainedAuthority(authorityRecords, images); err != nil { return err }
	for _, incomplete := range incompleteLinks { if err = incomplete.backend.RemoveFakeIPRuntimeLink(ctx, incomplete.id); err != nil { return err } }
	allowedDescriptors := make([]adapter.FakeIPRuntimeNamespaceDescriptor, 0, len(allowed)); for descriptor := range allowed { allowedDescriptors = append(allowedDescriptors, descriptor) }
	for _, backend := range recovered.backends { if err = backend.ReclaimFakeIPRuntimeOrphans(ctx, root.DatabaseID, allowedDescriptors); err != nil { return err } }

	// One anchor transaction fixes each token's deadline before touching any
	// copied namespace. If later I/O fails, these entries remain for the retry.
	now := m.now()
	deadlines, highToken, err := anchor.ResolveFakeIPPendingExpiries(ctx, tokens, now); if err != nil { return err }
 byAddress := make(map[netip.Addr]recoveredIdentity)
 var highRevision uint64
 for _, answer := range authorityRecords { highRevision=max(highRevision,answer.Revision); byAddress[answer.Address]=recoveredIdentity{answer:answer} }
 for _, image := range images {
  image.records, err = image.handle.RecoverWithDeadlines(ctx, now, deadlines); if err != nil { return err }
  for _, answer := range image.records {
   if !answer.Address.IsValid() || answer.Domain == "" || answer.Revision == 0 { return ErrPersistenceIdentity }
   highRevision = max(highRevision, answer.Revision)
   previous, exists := byAddress[answer.Address]
   if !exists || answer.Revision > previous.answer.Revision { byAddress[answer.Address] = recoveredIdentity{answer, image}; continue }
   if answer.Revision < previous.answer.Revision { continue }
   merged, err := mergeRecoveredIdentity(previous.answer, answer); if err != nil { return err }
   previous.answer = merged; if !merged.Obsolete { previous.image = image }; byAddress[answer.Address] = previous
  }
 }
	// Every discovered token copy was durably consumed. Forget only temporary
	// deadline rows; the constant-size high-water mark prevents token collision.
	ids := make([]uint64, 0, len(deadlines)); for token := range deadlines { ids = append(ids, token) }
	if err = anchor.ReleaseFakeIPPendingExpiries(ctx, ids); err != nil { return err }
	floor, ceiling, err := recovered.backends[root].ReserveFakeIPRuntimeCounters(ctx, adapter.FakeIPRuntimeCounters{Revision: highRevision, Token: highToken}, reservedAddressCount); if err != nil { return err }
	m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
	if m.active != active || active.handles != 0 || len(m.pendingAnswers) != 0 || m.preparing != nil { return ErrPersistencePreparing }
	m.nextAnswerToken = max(m.nextAnswerToken, floor.Token)
	m.nextAnswerRevision = max(m.nextAnswerRevision, floor.Revision)
	m.counterRoot, m.counterCeiling = recovered.backends[root], ceiling
	m.persistenceResolver = resolver
	if m.authority == nil { m.authority = make(map[netip.Addr]authorityEntry); m.domains = make(map[domainKey]netip.Addr) }
	if active.owned == nil { active.owned = make(map[netip.Addr]struct{}) }
	for address, domain := range activeSnapshot.Mappings { m.authority[address] = authorityEntry{domain: domain, namespace: active}; m.domains[domainKey{domain, address.Is6()}] = address; active.owned[address] = struct{}{} }
	logicalNamespaces := make(map[string]*memoryNamespace)
	for _, identity := range byAddress {
		answer := identity.answer
		if answer.Obsolete || !answer.ExpiresAt.After(now) { continue }
		if identity.image == nil { return ErrPersistenceIdentity }
		logical := identity.image.handle.Descriptor().LogicalID
		namespace := logicalNamespaces[logical]
		if namespace == nil {
			if m.nextNamespace == ^uint64(0) { return ErrMigrationStale }
			m.nextNamespace++
			metadata := identity.image.snapshot.Metadata
			store := NewStore(m.store.ctx, m.store.logger, metadata.Inet4Range, metadata.Inet6Range)
			namespace = &memoryNamespace{id: m.nextNamespace, store: store, published: true, retired: true, compacted: true, owned: make(map[netip.Addr]struct{}), durable: &namespacePersistence{handle: identity.image.handle, backend: recovered.backends[identity.image.handle.Descriptor().Backend]}}
			m.namespaces[namespace.id] = namespace; logicalNamespaces[logical] = namespace; recovered.namespaces = append(recovered.namespaces, namespace)
		}
		record := m.protection.get(namespace.id, answer.Address, answer.Domain); record.revision = answer.Revision; m.protection.extend(record, answer.ExpiresAt)
		if old, exists := m.authority[answer.Address]; exists { delete(old.namespace.owned, answer.Address) }
		m.authority[answer.Address] = authorityEntry{domain: answer.Domain, namespace: namespace, revision: answer.Revision}; namespace.owned[answer.Address] = struct{}{}
		m.domains[domainKey{answer.Domain, answer.Address.Is6()}] = answer.Address
	}
	m.recovered = recovered; keep = true
	return nil
}
func validateRecoveryNamespace(descriptor adapter.FakeIPRuntimeNamespaceDescriptor) error {
 if descriptor.Version != 1 || descriptor.AnchorDatabaseID == "" || descriptor.Backend.DatabaseID == "" || descriptor.ID == "" || descriptor.LogicalID == "" || descriptor.EffectiveConfigurationID == "" { return ErrPersistenceIdentity }; return nil
}
func recoveryLinkOwned(link adapter.FakeIPRuntimeLink, anchorID string) (bool,error) {
 if link.ID == "" || link.EffectiveConfigurationID == "" || len(link.Namespaces)==0 { return false,ErrPersistenceIdentity }
 owner:=link.Namespaces[0].AnchorDatabaseID
 for _, descriptor:=range link.Namespaces { if err:=validateRecoveryNamespace(descriptor); err!=nil { return false,err }; if descriptor.AnchorDatabaseID!=owner { return false,ErrPersistenceIdentity } }
 return owner==anchorID,nil
}
func validateRecoveryImages(images []*recoveredImage) error {
 type addressRevision struct { address netip.Addr; revision uint64 }
 identities:=make(map[addressRevision]string)
 for _, image:=range images {
  snapshot:=image.snapshot; if snapshot.Metadata==nil { return ErrPersistenceIdentity }
  contains:=func(address netip.Addr) bool { return snapshot.Metadata.Inet4Range.Contains(address)||snapshot.Metadata.Inet6Range.Contains(address) }
  for address,domain:=range snapshot.Mappings { if !address.IsValid()||domain==""||!contains(address) { return ErrPersistenceIdentity } }
  answers:=make(map[netip.Addr]adapter.FakeIPRuntimeAnswer)
  for _, answer:=range snapshot.Answers {
   if !answer.Address.IsValid()||answer.Domain==""||answer.Revision==0||!contains(answer.Address) { return ErrPersistenceIdentity }
   if _,found:=answers[answer.Address]; found { return ErrPersistenceIdentity }; answers[answer.Address]=answer
   key:=addressRevision{answer.Address,answer.Revision}; if domain,found:=identities[key]; found&&domain!=answer.Domain { return ErrRecoveryConflict }; identities[key]=answer.Domain
  }
  type tokenAddress struct { token uint64; address netip.Addr }
  seen:=make(map[tokenAddress]bool); counts:=make(map[netip.Addr]uint64); ttl:=make(map[netip.Addr]uint32)
  for _, token:=range snapshot.PendingAnswers {
   answer,found:=answers[token.Address]; key:=tokenAddress{token.Token,token.Address}
   if token.Token==0||token.Revision==0||token.Domain==""||!found||token.Revision>answer.Revision||seen[key] { return ErrPersistenceIdentity }; seen[key]=true
   if token.Revision==answer.Revision { if token.Domain!=answer.Domain { return ErrRecoveryConflict }; if !answer.Superseded { counts[token.Address]++; ttl[token.Address]=max(ttl[token.Address],token.PendingTTL) } }
  }
  for address,answer:=range answers { if answer.Pending!=counts[address] || (answer.Pending!=0&&answer.PendingTTL<ttl[address]) { return ErrPersistenceIdentity } }
 }
 return nil
}

// A higher revision ends all older identities, even if an old crash-pending
// marker was conservatively extended. Equal identity copies may extend TTL,
// except an exact Superseded marker; an expired copy alone cannot erase a later
// delivery of that same identity in another namespace.
func mergeRecoveredIdentity(a, b adapter.FakeIPRuntimeAnswer) (adapter.FakeIPRuntimeAnswer, error) {
 if a.Revision != b.Revision || a.Domain != b.Domain || a.Address != b.Address { return a, ErrRecoveryConflict }
 if b.ExpiresAt.After(a.ExpiresAt) { a.ExpiresAt = b.ExpiresAt }
 a.Superseded = a.Superseded || b.Superseded
 a.Obsolete = a.Superseded || (a.Obsolete && b.Obsolete)
 return a, nil
}
func sameRuntimeLink(a, b adapter.FakeIPRuntimeLink) bool {
	if a.ID != b.ID || a.EffectiveConfigurationID != b.EffectiveConfigurationID || len(a.Namespaces) != len(b.Namespaces) { return false }
	for index := range a.Namespaces { if a.Namespaces[index] != b.Namespaces[index] { return false } }
	return true
}

// ReclaimPersistence is explicit post-publication maintenance. It never runs
// under a publication guard, and does not infer quiescence from cancellation.
func (m *Manager) ReclaimPersistence(ctx context.Context) error {
	m.persistenceMaintenance.Lock(); defer m.persistenceMaintenance.Unlock()
	done, ok := m.work.Reserve(); if !ok { return lifecycle.ErrStopped }; defer done()
	m.mappingAccess.Lock()
	m.protection.prune(m.now()); m.collectNamespacesLocked()
	var retired []*persistentPreparation
	for _, transition := range m.transitions {
		if !transition.acknowledged { continue }
		complete := true
		select { case <-transition.finished: default: complete = false }
		for _, lease := range transition.leases { if !lease.finished { complete = false; break } }
		if !complete { continue }
		// Superseded copies can go once exact token callbacks finished. Current
		// namespace bindings are retained independently below.
		retired = append(retired, transition)
	}
	live := make(map[adapter.FakeIPRuntimeNamespace]bool)
	for _, namespace := range m.namespaces { if namespace.durable != nil { live[namespace.durable.handle] = true } }
	for _, lease := range m.pendingAnswers { for handle := range lease.journals { live[handle] = true } }
	for completion := range m.failedCompletions { live[completion.handle] = true }
	busyBackends := make(map[adapter.FakeIPRuntimeBackend]bool)
	for storage := range m.storageOperations {
		if handle, ok := storage.(adapter.FakeIPRuntimeNamespace); ok { live[handle] = true }
		if backend, ok := storage.(adapter.FakeIPRuntimeBackend); ok { busyBackends[backend] = true }
	}
	recovered := m.recovered
	m.mappingAccess.Unlock()
	for _, transition := range retired {
		if err := m.compactTransition(ctx, transition, live, busyBackends); err != nil { return err }
	}
	// A successfully acknowledged replacement has durably copied every live
	// recovered identity. Only then can startup's old discovery union go away.
	if recovered != nil && (len(retired) != 0 || recovered.selectionAcknowledged) {
		allRetired := true
		for _, handle := range recovered.handles { if live[handle] { allRetired = false; break } }
		if allRetired {
			if err := m.retainNamespaceAuthority(ctx, recovered.handles); err != nil { return err }
			for _, backend := range recovered.backends { for id := range recovered.links { if err := backend.RemoveFakeIPRuntimeLink(ctx, id); err != nil { return err } } }
			for _, handle := range recovered.handles { if err := handle.Reclaim(ctx); err != nil { return err } }
			for _, release := range recovered.releases { if err := release(); err != nil { return err } }
			m.mappingAccess.Lock(); if m.recovered == recovered { m.recovered = nil }; m.mappingAccess.Unlock()
		}
	}
	return m.pruneRetainedAuthority(ctx)
}

// compactTransition durably replaces its discovery link before removing the
// old one. The compact link keeps the fixed root anchor and only live private
// handles. A crash at any step discovers a superset of valid recognition; no
// retired backend is forgotten until every old link was removed successfully.
func (m *Manager) compactTransition(ctx context.Context, p *persistentPreparation, live map[adapter.FakeIPRuntimeNamespace]bool, busyBackends map[adapter.FakeIPRuntimeBackend]bool) error {
	var keep []adapter.FakeIPRuntimeNamespace
	var anchor adapter.FakeIPRuntimeNamespace
	for _, handle := range p.created { if handle.Descriptor().ID == p.options.TransactionID+"/anchor" { anchor = handle }; if live[handle] { keep = append(keep, handle) } }
	if len(keep) != 0 && anchor != nil && !live[anchor] { keep = append(keep, anchor) }
	// The transition that created each superseded handle owns its link and
	// reclaims that handle only after removing that link. A newer transition
	// must never delete a bucket still named by an older ready anchor link.
	unchanged := len(keep) == len(p.created)
	if unchanged {
		retained := make(map[adapter.FakeIPRuntimeBackendDescriptor]bool); for _, handle := range keep { retained[handle.Descriptor().Backend] = true }
		for descriptor, release := range p.releases { if !retained[descriptor] && !busyBackends[p.backends[descriptor]] { if err := release(); err != nil { return err }; delete(p.releases, descriptor); delete(p.backends, descriptor) } }
		p.images = nil; p.transfers = nil; p.post = nil; p.deltas = nil; p.publicationTransitions = nil
		if len(keep) == 0 && len(p.releases) == 0 { m.mappingAccess.Lock(); for index, candidate := range m.transitions { if candidate == p { m.transitions = append(m.transitions[:index], m.transitions[index+1:]...); break } }; m.mappingAccess.Unlock() }
		return nil
	}
	var discarded []adapter.FakeIPRuntimeNamespace
	for _, handle := range p.created { retained := false; for _, current := range keep { if current == handle { retained = true; break } }; if !retained { discarded = append(discarded,handle) } }
	if err := m.retainNamespaceAuthority(ctx, discarded); err != nil { return err }
	var next adapter.FakeIPRuntimeLink
	needed := make(map[adapter.FakeIPRuntimeBackendDescriptor]bool)
	if len(keep) != 0 {
		// Each successful reduction shortens the retained set. IDs are derived
		// from its finite cardinality, so a failed retry reuses exactly one ID.
		next = adapter.FakeIPRuntimeLink{ID: p.options.TransactionID+"/retained/"+strconv.Itoa(len(keep)), EffectiveConfigurationID: p.options.EffectiveConfigurationID, Acknowledged: true}
		for _, handle := range keep { descriptor := handle.Descriptor(); next.Namespaces = append(next.Namespaces, descriptor); needed[descriptor.Backend] = true }
		for descriptor := range needed { if err := p.backends[descriptor].SaveFakeIPRuntimeLink(ctx, next); err != nil { return err } }
		next.DiscoveryReady = true
		if err := p.anchor.SaveFakeIPRuntimeLink(ctx, next); err != nil { return err }
	}
	for _, backend := range p.backends { if err := backend.RemoveFakeIPRuntimeLink(ctx, p.link.ID); err != nil { return err } }
	for _, handle := range p.created { retained := false; for _, current := range keep { if current == handle { retained = true; break } }; if !retained { if err := handle.Reclaim(ctx); err != nil { return err } } }
	for descriptor, release := range p.releases { if !needed[descriptor] && !busyBackends[p.backends[descriptor]] { if err := release(); err != nil { return err }; delete(p.releases, descriptor); delete(p.backends, descriptor) } }
	m.mappingAccess.Lock()
	p.link, p.created = next, keep
	p.images, p.transfers, p.post, p.deltas, p.publicationTransitions, p.superseded, p.leases = nil, nil, nil, nil, nil, nil, nil
	if len(keep) == 0 && len(p.releases) == 0 { for index, candidate := range m.transitions { if candidate == p { m.transitions = append(m.transitions[:index], m.transitions[index+1:]...); break } } }
	m.mappingAccess.Unlock()
	return nil
}

func (m *Manager) closePersistence() error {
	var failures []error
	seen := make(map[adapter.FakeIPRuntimeNamespace]bool)
	for _, transition := range m.transitions { for _, handle := range transition.created { if !seen[handle] { seen[handle] = true; if flush, ok := handle.(interface{ Flush(context.Context) error }); ok { if err := flush.Flush(context.Background()); err != nil { failures = append(failures, err) } } } } }
	if m.persistenceErr != nil { failures = append(failures, m.persistenceErr) }
	if len(failures) != 0 { return fmt.Errorf("fake-IP persistence retained after incomplete close: %v", errors.Join(failures...)) }
	for _, transition := range m.transitions { for descriptor, release := range transition.releases { if err := release(); err != nil { failures = append(failures, err) } else { delete(transition.releases, descriptor) } } }
	if m.recovered != nil { var retained []func() error; for _, release := range m.recovered.releases { if err := release(); err != nil { failures = append(failures, err); retained = append(retained, release) } }; m.recovered.releases = retained }
	return errors.Join(failures...)
}


func (m *Manager) retainFailedCompletion(completion persistentCompletion, err error) {
	m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
	if m.failedCompletions == nil { m.failedCompletions = make(map[*persistentCompletion]struct{}) }
	m.failedCompletions[&completion] = struct{}{}
	m.persistenceErr = fmt.Errorf("fake-IP completion durability pending: %v", err)
}

// RetryPersistence is explicit retryable backpressure recovery. A durable I/O
// failure closes further protected-answer admission, rather than accumulating
// one retained failed cleanup per subsequent DNS query without bound.
func (m *Manager) RetryPersistence(ctx context.Context) error {
	done, ok := m.work.Reserve(); if !ok { return lifecycle.ErrStopped }
	job, cancel := m.persistenceWriter.submit(func() error {
		defer done()
		m.persistenceMaintenance.Lock(); defer m.persistenceMaintenance.Unlock()
		m.mappingAccess.Lock()
		preparing := m.preparing
		m.mappingAccess.Unlock()
		if preparing != nil && preparing.canceled.Load() {
			select { case <-preparing.finished: preparing.cleanupAborted(); if preparing.cleanupErr != nil { return preparing.cleanupErr }; default: return ErrPersistencePreparing }
		}
		m.mappingAccess.Lock()
		pending := make([]*persistentCompletion, 0, len(m.failedCompletions)); for completion := range m.failedCompletions { pending = append(pending, completion) }
		handles := make(map[adapter.FakeIPRuntimeNamespace]bool)
		for _, namespace := range m.namespaces { if namespace.durable != nil { handles[namespace.durable.handle] = true } }
		for _, transition := range m.transitions { for _, handle := range transition.created { handles[handle] = true } }
		m.mappingAccess.Unlock()
		for handle := range handles { if err := handle.Flush(ctx); err != nil { return err } }
		for _, completion := range pending {
			if err := completion.handle.Complete(ctx, completion.answers, completion.at, completion.delivered); err != nil { return err }
			m.mappingAccess.Lock(); delete(m.failedCompletions, completion); m.mappingAccess.Unlock()
		}
		m.mappingAccess.Lock(); if len(m.failedCompletions) == 0 && (m.preparing == nil || m.preparing.cleanupErr == nil) { m.persistenceErr = nil }; m.mappingAccess.Unlock()
		return nil
	})
	select { case err := <-job.result: return err; case <-ctx.Done(): if cancel() { done() }; return ctx.Err() }
}

// The coordinator owns one maintenance waiter. Snapshot this notification
// before ReclaimPersistence to avoid missing a release racing the sweep.
func (m *Manager) PersistenceChanged() <-chan struct{} {
	m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
	if m.persistenceChanged == nil { m.persistenceChanged = make(chan struct{}) }
	return m.persistenceChanged
}
func (m *Manager) persistenceChangedLocked() {
	if m.persistenceChanged != nil { close(m.persistenceChanged); m.persistenceChanged = make(chan struct{}) }
}
// WaitPersistenceChange observes the supplied pre-sweep generation and the
// current earliest answer expiry. It neither releases backend ownership nor
// declares any pending operation complete when its context is canceled.
func (m *Manager) WaitPersistenceChange(ctx context.Context, changed <-chan struct{}) error {
	m.mappingAccess.Lock()
	var wait time.Duration; hasExpiry := len(m.protection.expiries) != 0
	if hasExpiry { wait = m.protection.expiries[0].expires.Sub(m.now()) }
	m.mappingAccess.Unlock()
	if !hasExpiry { select { case <-changed: return nil; case <-ctx.Done(): return ctx.Err() } }
	if wait <= 0 { return nil }
	timer := time.NewTimer(wait); defer timer.Stop()
	select { case <-changed: return nil; case <-timer.C: return nil; case <-ctx.Done(): return ctx.Err() }
}

// Persist the newest evidence before removing its owning namespace. A delayed
// old Observe can subsequently finish, but cannot outrank this anchor record.
func (m *Manager) retainNamespaceAuthority(ctx context.Context, handles []adapter.FakeIPRuntimeNamespace) error {
 m.mappingAccess.Lock(); root:=m.counterRoot; m.mappingAccess.Unlock()
 if root==nil { if len(handles)==0 { return nil }; return ErrRecoveryAnchorRequired }
 var records []adapter.FakeIPRuntimeAnswer
 for _,handle:=range handles { snapshot,err:=handle.Snapshot(ctx); if err!=nil { return err }; records=append(records,snapshot.Answers...) }
 return root.RetainFakeIPRuntimeAuthority(ctx,records)
}
func validateRetainedAuthority(records []adapter.FakeIPRuntimeAnswer, images []*recoveredImage) error {
 latest:=make(map[netip.Addr]adapter.FakeIPRuntimeAnswer)
 for _,record:=range records { if !record.Obsolete||!record.Address.IsValid()||record.Domain==""||record.Revision==0||record.Pending!=0 { return ErrPersistenceIdentity }; if _,exists:=latest[record.Address]; exists { return ErrPersistenceIdentity }; latest[record.Address]=record }
 for _,image:=range images { for _,answer:=range image.snapshot.Answers { if previous,exists:=latest[answer.Address]; exists&&previous.Revision==answer.Revision&&previous.Domain!=answer.Domain { return ErrRecoveryConflict } } }
 return nil
}
// Called only under persistenceMaintenance after link compaction/removal. The
// union includes whole still-linked ranges, even when one delayed Observe has
// not yet stored its address. Incomplete discovery leaves authority untouched.
func (m *Manager) pruneRetainedAuthority(ctx context.Context) error {
 m.mappingAccess.Lock(); root,resolver:=m.counterRoot,m.persistenceResolver
 known:=make(map[adapter.FakeIPRuntimeNamespaceDescriptor]adapter.FakeIPRuntimeNamespace)
 for _,transition:=range m.transitions { for _,handle:=range transition.created { known[handle.Descriptor()]=handle } }; if m.recovered!=nil { for _,handle:=range m.recovered.handles { known[handle.Descriptor()]=handle } }
 m.mappingAccess.Unlock()
 if root==nil { return nil }; if resolver==nil { return ErrRecoveryAnchorRequired }
 descriptor,err:=root.RuntimeDescriptor(ctx); if err!=nil { return err }
 catalog,err:=root.FakeIPRuntimeCatalog(ctx); if err!=nil { return err }
 wanted:=make(map[adapter.FakeIPRuntimeNamespaceDescriptor]bool)
 for _,link:=range catalog.Links { owned,err:=recoveryLinkOwned(link,descriptor.DatabaseID); if err!=nil { return err }; if !owned { continue }; if !link.DiscoveryReady { return ErrPersistencePreparing }; for _,namespace:=range link.Namespaces { wanted[namespace]=true } }
 var ranges []netip.Prefix
 for namespace:=range wanted {
  handle:=known[namespace]; var release func() error
  if handle==nil { backend,done,err:=resolver.ResolveFakeIPRuntime(ctx,namespace.Backend); if err!=nil { return err }; release=done; handle,err=backend.OpenFakeIPNamespace(ctx,namespace.ID); if err!=nil { return errors.Join(err,release()) } }
  imageErr:=func() error { if handle.Descriptor()!=namespace { return ErrPersistenceIdentity }; snapshot,err:=handle.Snapshot(ctx); if err!=nil { return err }; if snapshot.Metadata==nil { return ErrPersistenceIdentity }; if snapshot.Metadata.Inet4Range.IsValid() { ranges=append(ranges,snapshot.Metadata.Inet4Range) }; if snapshot.Metadata.Inet6Range.IsValid() { ranges=append(ranges,snapshot.Metadata.Inet6Range) }; return nil }()
  var releaseErr error; if release!=nil { releaseErr=release() }; if imageErr!=nil||releaseErr!=nil { return errors.Join(imageErr,releaseErr) }
 }
 return root.PruneFakeIPRuntimeAuthority(ctx,ranges)
}
