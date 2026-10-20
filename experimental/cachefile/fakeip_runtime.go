package cachefile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

var (
	ErrFakeIPRuntimeVersion = errors.New("unsupported fake-IP runtime journal version")
	ErrFakeIPRuntimeIdentity = errors.New("fake-IP runtime database identity mismatch")
	ErrFakeIPRuntimeMissing = errors.New("fake-IP runtime namespace is missing")
	ErrFakeIPRuntimeIssued = errors.New("fake-IP runtime namespace has issued answers")
	ErrFakeIPRuntimeConflict = errors.New("fake-IP runtime namespace preparation conflicts with existing state")
	ErrFakeIPRuntimeDurability = errors.New("fake-IP runtime database does not provide synchronous transactions")
	bucketFakeIPRuntime = []byte("fakeip_runtime_v1")
	keyRuntimeVersion = []byte("version")
	keyRuntimeIdentity = []byte("database_id")
	bucketRuntimeNamespaces = []byte("namespaces")
	bucketRuntimeLinks = []byte("links")
	keyRuntimeDescriptor = []byte("descriptor")
	keyRuntimeMetadata = []byte("metadata")
	keyRuntimeIssued = []byte("issued")
	bucketRuntimeAddresses = []byte("addresses")
	bucketRuntimeDomains4 = []byte("domains4")
	bucketRuntimeDomains6 = []byte("domains6")
	bucketRuntimeAnswers = []byte("answers")
	bucketRuntimeTokens = []byte("tokens")
)

type runtimePending struct {
	metadata *adapter.FakeIPMetadata
	mappings map[netip.Addr]string
	answers map[netip.Addr]adapter.FakeIPRuntimeAnswer
	authorities map[netip.Addr]adapter.FakeIPRuntimeAnswer
	domains4 map[string]netip.Addr
	domains6 map[string]netip.Addr
	issued bool
	tokens map[string]*adapter.FakeIPRuntimeAnswer
}
func newRuntimePending() *runtimePending {
	return &runtimePending{mappings: make(map[netip.Addr]string), answers: make(map[netip.Addr]adapter.FakeIPRuntimeAnswer), authorities: make(map[netip.Addr]adapter.FakeIPRuntimeAnswer), domains4: make(map[string]netip.Addr), domains6: make(map[string]netip.Addr), tokens: make(map[string]*adapter.FakeIPRuntimeAnswer)}
}

// runtimeUpdate/runtimeView never reset or replace a damaged database. In
// particular, a different file at an old Path must not inherit its identity.
func (c *CacheFile) runtimeUpdate(fn func(*bbolt.Tx) error) (err error) {
	c.dbAccess.RLock(); defer c.dbAccess.RUnlock()
	if c.DB == nil { return ErrFakeIPRuntimeMissing }
	if c.DB.NoSync { return ErrFakeIPRuntimeDurability }
	defer func() { if value := recover(); value != nil { err = fmt.Errorf("fake-IP durable transaction panic: %v", value) } }()
	return c.DB.Update(fn)
}
func (c *CacheFile) runtimeView(fn func(*bbolt.Tx) error) (err error) {
	c.dbAccess.RLock(); defer c.dbAccess.RUnlock()
	if c.DB == nil { return ErrFakeIPRuntimeMissing }
	defer func() { if value := recover(); value != nil { err = fmt.Errorf("fake-IP journal read panic: %v", value) } }()
	return c.DB.View(fn)
}
func runtimeRoot(tx *bbolt.Tx) (*bbolt.Bucket, error) {
	// Never initialize beside or reclaim an unknown future HOT root schema.
	if err := tx.ForEach(func(name []byte, _ *bbolt.Bucket) error { if bytes.HasPrefix(name, []byte("fakeip_runtime_")) && !bytes.Equal(name, bucketFakeIPRuntime) { return ErrFakeIPRuntimeVersion }; return nil }); err != nil { return nil, err }
	root := tx.Bucket(bucketFakeIPRuntime)
	if root == nil { return nil, ErrFakeIPRuntimeMissing }
	if err := validateRuntimeHeader(root.Get(keyRuntimeVersion), root.Get(keyRuntimeIdentity)); err != nil { return nil, err }
	return root, nil
}
func validateRuntimeHeader(version, identity []byte) error {
	if !bytes.Equal(version, []byte{1}) { return ErrFakeIPRuntimeVersion }
	decoded, err := hex.DecodeString(string(identity)); if err != nil || len(decoded) != 16 { return ErrFakeIPRuntimeIdentity }
	return nil
}
func runtimeNamespaceBucket(tx *bbolt.Tx, id string) (*bbolt.Bucket, error) {
	root, err := runtimeRoot(tx); if err != nil { return nil, err }
	all := root.Bucket(bucketRuntimeNamespaces)
	if all == nil { return nil, ErrFakeIPRuntimeMissing }
	namespace := all.Bucket([]byte(id))
	if namespace == nil { return nil, ErrFakeIPRuntimeMissing }
	return namespace, nil
}
func putRuntimeJSON(bucket *bbolt.Bucket, key []byte, value any) error {
	encoded, err := json.Marshal(value); if err != nil { return err }; return bucket.Put(key, encoded)
}
func readRuntimeJSON(bucket *bbolt.Bucket, key []byte, value any) error {
	encoded := bucket.Get(key); if len(encoded) == 0 { return ErrFakeIPRuntimeMissing }; return json.Unmarshal(encoded, value)
}

func (c *CacheFile) RuntimeDescriptor(ctx context.Context) (adapter.FakeIPRuntimeBackendDescriptor, error) {
	// Promotion precedes any identity access and is intentionally irreversible
	// for this open handle. Existing legacy callbacks may not auto-reset it.
	c.runtimeStrict.Store(true)
	if err := ctx.Err(); err != nil { return adapter.FakeIPRuntimeBackendDescriptor{}, err }
	if err := c.validateRuntimeFileIdentity(); err != nil { return adapter.FakeIPRuntimeBackendDescriptor{}, err }
	path, err := filepath.Abs(c.path); if err != nil { return adapter.FakeIPRuntimeBackendDescriptor{}, err }
	descriptor := adapter.FakeIPRuntimeBackendDescriptor{Path: filepath.Clean(path), CacheID: c.cacheIDText}
	// Reading an initialized identity does not force a write/fsync.
	err = c.runtimeView(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }; descriptor.DatabaseID = string(root.Get(keyRuntimeIdentity)); return nil
	})
	if err == nil { return descriptor, nil }
	if !errors.Is(err, ErrFakeIPRuntimeMissing) { return descriptor, err }
	var identity [16]byte
	if _, err = rand.Read(identity[:]); err != nil { return descriptor, err }
	err = c.runtimeUpdate(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketFakeIPRuntime) != nil {
			root, err := runtimeRoot(tx); if err != nil { return err }; descriptor.DatabaseID = string(root.Get(keyRuntimeIdentity)); return nil
		}
		root, err := tx.CreateBucket(bucketFakeIPRuntime); if err != nil { return err }
		if err = root.Put(keyRuntimeVersion, []byte{1}); err != nil { return err }
		descriptor.DatabaseID = hex.EncodeToString(identity[:])
		if err = root.Put(keyRuntimeIdentity, []byte(descriptor.DatabaseID)); err != nil { return err }
		if _, err = root.CreateBucket(bucketRuntimeNamespaces); err != nil { return err }
		_, err = root.CreateBucket(bucketRuntimeLinks); return err
	})
	return descriptor, err
}

// SnapshotFakeIP sees one durable image plus all admitted writes not yet flushed.
// Holding flushAccess excludes the writing swap; pendingAccess is held only for
// copies, never during bbolt I/O. The caller validates its manager mutation stamp.
func (c *CacheFile) SnapshotFakeIP(ctx context.Context) (adapter.FakeIPStorageSnapshot, error) {
	c.flushAccess.Lock(); defer c.flushAccess.Unlock()
	if err := ctx.Err(); err != nil { return adapter.FakeIPStorageSnapshot{}, err }
	snapshot := adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
	err := c.runtimeView(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP); if bucket == nil { return nil }
		if raw := bucket.Get(keyMetadata); len(raw) != 0 {
			snapshot.Metadata = new(adapter.FakeIPMetadata)
			if err := snapshot.Metadata.UnmarshalBinary(raw); err != nil { return err }
		}
		return bucket.ForEach(func(key, value []byte) error {
			if bytes.Equal(key, keyMetadata) { return nil }
			address, valid := netip.AddrFromSlice(key)
			if !valid || value == nil { return fmt.Errorf("invalid fake-IP legacy mapping key") }
			snapshot.Mappings[address.Unmap()] = string(value); return nil
		})
	})
	if err != nil { return snapshot, err }
	c.pendingAccess.RLock()
	for address, domain := range c.pending.fakeIPDomain { snapshot.Mappings[address] = domain }
	if c.pending.fakeIPMetadata != nil { metadata := *c.pending.fakeIPMetadata; snapshot.Metadata = &metadata }
	c.pendingAccess.RUnlock()
	return snapshot, nil
}

func (c *CacheFile) PrepareFakeIPNamespace(ctx context.Context, descriptor adapter.FakeIPRuntimeNamespaceDescriptor, snapshot adapter.FakeIPStorageSnapshot) (adapter.FakeIPRuntimeNamespace, error) {
	actual, err := c.RuntimeDescriptor(ctx); if err != nil { return nil, err }
	return c.prepareFakeIPNamespace(ctx, actual, descriptor, snapshot)
}
func (c *CacheFile) prepareFakeIPNamespace(ctx context.Context, actual adapter.FakeIPRuntimeBackendDescriptor, descriptor adapter.FakeIPRuntimeNamespaceDescriptor, snapshot adapter.FakeIPStorageSnapshot) (adapter.FakeIPRuntimeNamespace, error) {
	var err error
	if err = validateRuntimeNamespaceDescriptor(descriptor); err != nil { return nil, err }
	if descriptor.Backend != actual { return nil, ErrFakeIPRuntimeIdentity }
	if snapshot.Metadata == nil { return nil, errors.New("fake-IP namespace snapshot has no metadata") }
	if err = validateRuntimeSnapshot(snapshot); err != nil { return nil, err }
	c.flushAccess.Lock(); defer c.flushAccess.Unlock()
	if err = ctx.Err(); err != nil { return nil, err }
	err = c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		if string(root.Get(keyRuntimeIdentity)) != descriptor.Backend.DatabaseID { return ErrFakeIPRuntimeIdentity }
		all := root.Bucket(bucketRuntimeNamespaces)
		if all.Bucket([]byte(descriptor.ID)) != nil { return ErrFakeIPRuntimeConflict }
		namespace, err := all.CreateBucket([]byte(descriptor.ID)); if err != nil { return err }
		if err = putRuntimeJSON(namespace, keyRuntimeDescriptor, descriptor); err != nil { return err }
		if err = putRuntimeJSON(namespace, keyRuntimeMetadata, snapshot.Metadata); err != nil { return err }
		for _, key := range [][]byte{bucketRuntimeAddresses, bucketRuntimeDomains4, bucketRuntimeDomains6, bucketRuntimeAnswers, bucketRuntimeTokens} { if _, err = namespace.CreateBucket(key); err != nil { return err } }
		for address, domain := range snapshot.Mappings { if err = putRuntimeMapping(namespace, address, domain); err != nil { return err } }
		answers := namespace.Bucket(bucketRuntimeAnswers)
		for _, answer := range snapshot.Answers { if err = putRuntimeJSON(answers, answer.Address.AsSlice(), answer); err != nil { return err } }
		for _, pending := range snapshot.PendingAnswers { if pending.Token == 0 { return ErrFakeIPRuntimeConflict }; if err = putRuntimeJSON(namespace.Bucket(bucketRuntimeTokens), runtimeTokenKey(pending), pending); err != nil { return err } }
		return nil
	})
	if err != nil { return nil, err }
	return newRuntimeNamespace(c, descriptor, snapshot), nil
}
func validateRuntimeSnapshot(snapshot adapter.FakeIPStorageSnapshot) error {
	if snapshot.Metadata == nil { return ErrFakeIPRuntimeConflict }
	contains := func(address netip.Addr) bool { return snapshot.Metadata.Inet4Range.Contains(address) || snapshot.Metadata.Inet6Range.Contains(address) }
	for address, domain := range snapshot.Mappings { if !address.IsValid() || domain == "" || !contains(address) { return ErrFakeIPRuntimeConflict } }
	answers := make(map[netip.Addr]adapter.FakeIPRuntimeAnswer)
	for _, answer := range snapshot.Answers {
		if !answer.Address.IsValid() || answer.Domain == "" || answer.Revision == 0 || !contains(answer.Address) { return ErrFakeIPRuntimeConflict }
		if _, duplicate := answers[answer.Address]; duplicate { return ErrFakeIPRuntimeConflict }; answers[answer.Address] = answer
	}
	seen := make(map[string]bool)
	counts := make(map[netip.Addr]uint64); ttl := make(map[netip.Addr]uint32)
	for _, token := range snapshot.PendingAnswers {
		answer, found := answers[token.Address]
		if token.Token == 0 || !found || answer.Revision != token.Revision || answer.Domain != token.Domain { return ErrFakeIPRuntimeConflict }
		key := string(runtimeTokenKey(token)); if seen[key] { return ErrFakeIPRuntimeConflict }; seen[key] = true
		counts[token.Address]++; ttl[token.Address] = max(ttl[token.Address], token.PendingTTL)
	}
	for address, answer := range answers { if answer.Pending != counts[address] || (answer.Pending != 0 && answer.PendingTTL != ttl[address]) { return ErrFakeIPRuntimeConflict } }
	return nil
}
func (c *CacheFile) OpenFakeIPNamespace(ctx context.Context, id string) (adapter.FakeIPRuntimeNamespace, error) {
	actual, err := c.RuntimeDescriptor(ctx); if err != nil { return nil, err }
	return c.openFakeIPNamespace(ctx, actual, id)
}
func (c *CacheFile) openFakeIPNamespace(ctx context.Context, actual adapter.FakeIPRuntimeBackendDescriptor, id string) (adapter.FakeIPRuntimeNamespace, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	var descriptor adapter.FakeIPRuntimeNamespaceDescriptor
	err := c.runtimeView(func(tx *bbolt.Tx) error {
		namespace, err := runtimeNamespaceBucket(tx, id); if err != nil { return err }
		if err = readRuntimeJSON(namespace, keyRuntimeDescriptor, &descriptor); err != nil { return err }
		root, err := runtimeRoot(tx); if err != nil { return err }
		if err = validateRuntimeNamespaceDescriptor(descriptor); err != nil { return err }
		if descriptor.ID != id || descriptor.Backend.DatabaseID != string(root.Get(keyRuntimeIdentity)) { return ErrFakeIPRuntimeIdentity }; return nil
	})
	if err != nil { return nil, err }
	if descriptor.Backend != actual { return nil, ErrFakeIPRuntimeIdentity }
	reader := &runtimeNamespace{cache: c, descriptor: descriptor}
	snapshot, err := reader.Snapshot(ctx); if err != nil { return nil, err }
	return newRuntimeNamespace(c, descriptor, snapshot), nil
}
func (c *CacheFile) FakeIPRuntimeCatalog(ctx context.Context) (adapter.FakeIPRuntimeCatalog, error) {
	actual, err := c.RuntimeDescriptor(ctx); if err != nil { return adapter.FakeIPRuntimeCatalog{}, err }
	return c.fakeIPRuntimeCatalog(ctx, actual)
}
func (c *CacheFile) fakeIPRuntimeCatalog(ctx context.Context, actual adapter.FakeIPRuntimeBackendDescriptor) (adapter.FakeIPRuntimeCatalog, error) {
	var catalog adapter.FakeIPRuntimeCatalog
	if err := ctx.Err(); err != nil { return catalog, err }
	err := c.runtimeView(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if errors.Is(err, ErrFakeIPRuntimeMissing) { return nil }; if err != nil { return err }
		if err = root.Bucket(bucketRuntimeNamespaces).ForEachBucket(func(id []byte) error {
			var descriptor adapter.FakeIPRuntimeNamespaceDescriptor
			if err := readRuntimeJSON(root.Bucket(bucketRuntimeNamespaces).Bucket(id), keyRuntimeDescriptor, &descriptor); err != nil { return err }
			if err := validateRuntimeNamespaceDescriptor(descriptor); err != nil { return err }
			if descriptor.ID != string(id) || descriptor.Backend.DatabaseID != string(root.Get(keyRuntimeIdentity)) { return ErrFakeIPRuntimeIdentity }
			catalog.Namespaces = append(catalog.Namespaces, descriptor); return nil
		}); err != nil { return err }
		return root.Bucket(bucketRuntimeLinks).ForEach(func(_, raw []byte) error { var link adapter.FakeIPRuntimeLink; if err := json.Unmarshal(raw, &link); err != nil { return err }; catalog.Links = append(catalog.Links, link); return nil })
	})
	if err != nil { return catalog, err }; return filterRuntimeCatalog(actual, catalog), nil
}
func filterRuntimeCatalog(actual adapter.FakeIPRuntimeBackendDescriptor, raw adapter.FakeIPRuntimeCatalog) adapter.FakeIPRuntimeCatalog {
	var filtered adapter.FakeIPRuntimeCatalog
	for _, namespace := range raw.Namespaces { if namespace.Backend == actual { filtered.Namespaces = append(filtered.Namespaces, namespace) } }
	for _, link := range raw.Links { for _, namespace := range link.Namespaces { if namespace.Backend == actual { filtered.Links = append(filtered.Links, link); break } } }
	return filtered
}
func (c *CacheFile) SaveFakeIPRuntimeLink(ctx context.Context, link adapter.FakeIPRuntimeLink) error {
	actual, err := c.RuntimeDescriptor(ctx); if err != nil { return err }
	return c.saveFakeIPRuntimeLink(ctx, actual, link)
}
func (c *CacheFile) saveFakeIPRuntimeLink(ctx context.Context, actual adapter.FakeIPRuntimeBackendDescriptor, link adapter.FakeIPRuntimeLink) error {
	if link.ID == "" || link.EffectiveConfigurationID == "" || len(link.Namespaces) == 0 { return ErrFakeIPRuntimeIdentity }
	participant := false
	owner := link.Namespaces[0].AnchorDatabaseID
	for _, namespace := range link.Namespaces { if err := validateRuntimeNamespaceDescriptor(namespace); err != nil { return err }; if namespace.AnchorDatabaseID != owner { return ErrFakeIPRuntimeIdentity }; if namespace.Backend == actual { participant = true } }
	if !participant { return ErrFakeIPRuntimeIdentity }
	return c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		links := root.Bucket(bucketRuntimeLinks)
		if raw := links.Get([]byte(link.ID)); len(raw) != 0 {
			var old adapter.FakeIPRuntimeLink; if err = json.Unmarshal(raw, &old); err != nil { return err }
			newAcknowledged := link.Acknowledged; oldAcknowledged := old.Acknowledged
			newReady := link.DiscoveryReady; oldReady := old.DiscoveryReady
			link.DiscoveryReady, old.DiscoveryReady = false, false
			link.Acknowledged, old.Acknowledged = false, false
			a, _ := json.Marshal(link); b, _ := json.Marshal(old)
			if !bytes.Equal(a, b) { return ErrFakeIPRuntimeConflict }
			link.Acknowledged = newAcknowledged || oldAcknowledged
			link.DiscoveryReady = newReady || oldReady
		}
		return putRuntimeJSON(links, []byte(link.ID), link)
	})
}

func putRuntimeMapping(namespace *bbolt.Bucket, address netip.Addr, domain string) error {
	addresses := namespace.Bucket(bucketRuntimeAddresses)
	domains := namespace.Bucket(bucketRuntimeDomains4); if address.Is6() { domains = namespace.Bucket(bucketRuntimeDomains6) }
	old := addresses.Get(address.AsSlice())
	if old != nil && bytes.Equal(domains.Get(old), address.AsSlice()) { if err := domains.Delete(old); err != nil { return err } }
	if err := addresses.Put(address.AsSlice(), []byte(domain)); err != nil { return err }
	return domains.Put([]byte(domain), address.AsSlice())
}

var _ adapter.FakeIPRuntimeBackend = (*CacheFile)(nil)
var _ adapter.FakeIPRuntimeNamespace = (*runtimeNamespace)(nil)


func (c *CacheFile) RemoveFakeIPRuntimeLink(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil { return err }
	return c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		return root.Bucket(bucketRuntimeLinks).Delete([]byte(id))
	})
}

// The caller supplies a completely discovered fixed-anchor union. A single
// transaction validates the whole private catalog before deleting any bucket.
// Other anchor owners, other schemas and every legacy cache bucket are excluded.
func (c *CacheFile) ReclaimFakeIPRuntimeOrphans(ctx context.Context, anchorID string, allowed []adapter.FakeIPRuntimeNamespaceDescriptor) error {
 if err := ctx.Err(); err != nil { return err }
 if anchorID == "" { return ErrFakeIPRuntimeIdentity }
 c.flushAccess.Lock(); defer c.flushAccess.Unlock()
 var removed []string
 err := c.runtimeUpdate(func(tx *bbolt.Tx) error {
  root, err := runtimeRoot(tx); if err != nil { return err }; namespaces := root.Bucket(bucketRuntimeNamespaces)
  var catalog []adapter.FakeIPRuntimeNamespaceDescriptor
  if err = namespaces.ForEachBucket(func(id []byte) error {
   var descriptor adapter.FakeIPRuntimeNamespaceDescriptor
   if err := readRuntimeJSON(namespaces.Bucket(id),keyRuntimeDescriptor,&descriptor); err != nil { return err }
   if descriptor.ID != string(id) || descriptor.Backend.DatabaseID != string(root.Get(keyRuntimeIdentity)) { return ErrFakeIPRuntimeIdentity }
   catalog = append(catalog,descriptor); return nil
  }); err != nil { return err }
  removed, err = runtimeOrphanIDs(anchorID, catalog, allowed); if err != nil { return err }
  for _, id := range removed { if err = namespaces.DeleteBucket([]byte(id)); err != nil { return err } }; return nil
 })
 if err == nil { c.pendingAccess.Lock(); for _, id := range removed { c.dropRuntimePendingLocked(id) }; c.pendingAccess.Unlock() }; return err
}
func validateRuntimeNamespaceDescriptor(descriptor adapter.FakeIPRuntimeNamespaceDescriptor) error {
 if descriptor.Version != 1 { return ErrFakeIPRuntimeVersion }
 if descriptor.AnchorDatabaseID == "" || descriptor.Backend.DatabaseID == "" || descriptor.ID == "" || descriptor.LogicalID == "" || descriptor.EffectiveConfigurationID == "" { return ErrFakeIPRuntimeIdentity }
 return nil
}
func runtimeOrphanIDs(anchorID string, catalog, allowed []adapter.FakeIPRuntimeNamespaceDescriptor) ([]string,error) {
 if anchorID == "" { return nil,ErrFakeIPRuntimeIdentity }
 keep := make(map[adapter.FakeIPRuntimeNamespaceDescriptor]bool)
 for _, descriptor := range allowed { if err := validateRuntimeNamespaceDescriptor(descriptor); err != nil { return nil,err }; if descriptor.AnchorDatabaseID != anchorID { return nil,ErrFakeIPRuntimeIdentity }; keep[descriptor]=true }
 var removed []string
 for _, descriptor := range catalog { if err := validateRuntimeNamespaceDescriptor(descriptor); err != nil { return nil,err }; if descriptor.AnchorDatabaseID==anchorID && !keep[descriptor] { removed=append(removed,descriptor.ID) } }
 return removed,nil
}
