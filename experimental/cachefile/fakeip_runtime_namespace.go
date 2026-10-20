package cachefile

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

type runtimeNamespace struct {
	cache         *CacheFile
	descriptor    adapter.FakeIPRuntimeNamespaceDescriptor
	mappingAccess sync.RWMutex
	metadata      adapter.FakeIPMetadata
	mappings      map[netip.Addr]string
	domains4      map[string]netip.Addr
	domains6      map[string]netip.Addr
}

// The private allocator's detached mirror makes normal lookup/queue operations
// RAM-only. Slow bbolt reads and flushes stay outside manager data fences.
func newRuntimeNamespace(cache *CacheFile, descriptor adapter.FakeIPRuntimeNamespaceDescriptor, snapshot adapter.FakeIPStorageSnapshot) *runtimeNamespace {
	s := &runtimeNamespace{cache: cache, descriptor: descriptor, mappings: make(map[netip.Addr]string), domains4: make(map[string]netip.Addr), domains6: make(map[string]netip.Addr)}
	if snapshot.Metadata != nil {
		s.metadata = *snapshot.Metadata
	}
	for address, domain := range snapshot.Mappings {
		s.mappings[address] = domain
		if address.Is4() {
			s.domains4[domain] = address
		} else {
			s.domains6[domain] = address
		}
	}
	return s
}

func (s *runtimeNamespace) bucket(tx *bbolt.Tx) (*bbolt.Bucket, error) {
	root, err := runtimeRoot(tx)
	if err != nil {
		return nil, err
	}
	if string(root.Get(keyRuntimeIdentity)) != s.descriptor.Backend.DatabaseID {
		return nil, ErrFakeIPRuntimeIdentity
	}
	namespace, err := runtimeNamespaceBucket(tx, s.descriptor.ID)
	if err != nil {
		return nil, err
	}
	var actual adapter.FakeIPRuntimeNamespaceDescriptor
	if err = readRuntimeJSON(namespace, keyRuntimeDescriptor, &actual); err != nil {
		return nil, err
	}
	if err = validateRuntimeNamespaceDescriptor(actual); err != nil {
		return nil, err
	}
	if actual != s.descriptor {
		return nil, ErrFakeIPRuntimeIdentity
	}
	return namespace, nil
}

func (s *runtimeNamespace) Descriptor() adapter.FakeIPRuntimeNamespaceDescriptor { return s.descriptor }

func (s *runtimeNamespace) SnapshotAllocation() adapter.FakeIPStorageSnapshot {
	s.mappingAccess.RLock()
	defer s.mappingAccess.RUnlock()
	metadata := s.metadata
	snapshot := adapter.FakeIPStorageSnapshot{Metadata: &metadata, Mappings: make(map[netip.Addr]string, len(s.mappings))}
	for address, domain := range s.mappings {
		snapshot.Mappings[address] = domain
	}
	return snapshot
}

func (s *runtimeNamespace) Snapshot(ctx context.Context) (adapter.FakeIPStorageSnapshot, error) {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return adapter.FakeIPStorageSnapshot{}, err
	}
	return s.snapshotLocked()
}

func (s *runtimeNamespace) snapshotLocked() (adapter.FakeIPStorageSnapshot, error) {
	snapshot := adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
	answers := make(map[netip.Addr]adapter.FakeIPRuntimeAnswer)
	tokens := make(map[string]adapter.FakeIPRuntimeAnswer)
	err := s.cache.runtimeView(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		snapshot.Issued = len(namespace.Get(keyRuntimeIssued)) != 0
		snapshot.Metadata = new(adapter.FakeIPMetadata)
		if err = readRuntimeJSON(namespace, keyRuntimeMetadata, snapshot.Metadata); err != nil {
			return err
		}
		if err = namespace.Bucket(bucketRuntimeAddresses).ForEach(func(key, value []byte) error {
			address, ok := netip.AddrFromSlice(key)
			if !ok || len(value) == 0 {
				return ErrFakeIPRuntimeConflict
			}
			snapshot.Mappings[address.Unmap()] = string(value)
			return nil
		}); err != nil {
			return err
		}
		if err = namespace.Bucket(bucketRuntimeAnswers).ForEach(func(key, raw []byte) error {
			var answer adapter.FakeIPRuntimeAnswer
			if err := json.Unmarshal(raw, &answer); err != nil {
				return err
			}
			address, valid := netip.AddrFromSlice(key)
			if !valid || address.Unmap() != answer.Address || answer.Revision == 0 || answer.Domain == "" {
				return ErrFakeIPRuntimeConflict
			}
			answers[answer.Address] = answer
			return nil
		}); err != nil {
			return err
		}
		return namespace.Bucket(bucketRuntimeTokens).ForEach(func(key, raw []byte) error {
			var answer adapter.FakeIPRuntimeAnswer
			if err := json.Unmarshal(raw, &answer); err != nil {
				return err
			}
			if string(key) != string(runtimeTokenKey(answer)) || answer.Token == 0 {
				return ErrFakeIPRuntimeConflict
			}
			tokens[string(key)] = answer
			return nil
		})
	})
	if err != nil {
		return snapshot, err
	}
	s.cache.pendingAccess.RLock()
	if pending := s.cache.pending.fakeIPRuntime[s.descriptor.ID]; pending != nil {
		snapshot.Issued = snapshot.Issued || pending.issued
		if pending.metadata != nil {
			metadata := *pending.metadata
			snapshot.Metadata = &metadata
		}
		for address, domain := range pending.mappings {
			snapshot.Mappings[address] = domain
		}
		for address, authority := range pending.authorities {
			current, exists := answers[address]
			write, err := mergeRuntimeAnswer(current, exists, authority)
			if err != nil {
				s.cache.pendingAccess.RUnlock()
				return snapshot, err
			}
			if write {
				answers[address] = authority
			}
		}
		for address, answer := range pending.answers {
			current, exists := answers[address]
			write, err := mergeRuntimeAnswer(current, exists, answer)
			if err != nil {
				s.cache.pendingAccess.RUnlock()
				return snapshot, err
			}
			if write {
				answers[address] = answer
			}
		}
		for key, token := range pending.tokens {
			if token == nil {
				delete(tokens, key)
			} else {
				tokens[key] = *token
			}
		}
	}
	s.cache.pendingAccess.RUnlock()
	for _, answer := range answers {
		snapshot.Answers = append(snapshot.Answers, answer)
	}
	for _, token := range tokens {
		snapshot.PendingAnswers = append(snapshot.PendingAnswers, token)
	}
	return snapshot, nil
}

func (s *runtimeNamespace) FakeIPMetadata() *adapter.FakeIPMetadata {
	s.mappingAccess.RLock()
	metadata := s.metadata
	s.mappingAccess.RUnlock()
	return &metadata
}

func (s *runtimeNamespace) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	if metadata == nil {
		return errors.New("missing fake-IP metadata")
	}
	s.mappingAccess.Lock()
	s.metadata = *metadata
	s.mappingAccess.Unlock()
	s.cache.pendingAccess.Lock()
	pending := s.cache.runtimePendingLocked(s.descriptor.ID)
	added := pending.metadata == nil
	copyMetadata := *metadata
	pending.metadata = &copyMetadata
	s.cache.enqueueLocked(added, 0)
	s.cache.pendingAccess.Unlock()
	return s.cache.FlushFakeIP(context.Background())
}

func (s *runtimeNamespace) FakeIPStore(address netip.Addr, domain string) error {
	s.queueMapping(address, domain)
	return s.cache.FlushFakeIP(context.Background())
}

func (s *runtimeNamespace) FakeIPStoreAsync(address netip.Addr, domain string, _ logger.Logger) {
	s.queueMapping(address, domain)
}

func (s *runtimeNamespace) queueMapping(address netip.Addr, domain string) {
	s.mappingAccess.Lock()
	oldDomain, found := s.mappings[address]
	index := s.domains4
	if address.Is6() {
		index = s.domains6
	}
	if found && index[oldDomain] == address {
		delete(index, oldDomain)
	}
	s.mappings[address] = domain
	index[domain] = address
	s.mappingAccess.Unlock()
	s.cache.pendingAccess.Lock()
	defer s.cache.pendingAccess.Unlock()
	pending := s.cache.runtimePendingLocked(s.descriptor.ID)
	old, exists := pending.mappings[address]
	pending.mappings[address] = domain
	// Only a published allocator can call this method; preparation writes its
	// snapshot directly without this admitted-operation marker.
	pending.issued = true
	if address.Is4() {
		if found {
			pending.domains4[oldDomain] = netip.Addr{}
		}
		pending.domains4[domain] = address
	} else {
		if found {
			pending.domains6[oldDomain] = netip.Addr{}
		}
		pending.domains6[domain] = address
	}
	s.cache.enqueueLocked(!exists, len(domain)-len(old))
}

func (s *runtimeNamespace) FakeIPLoad(address netip.Addr) (string, bool) {
	s.mappingAccess.RLock()
	domain, found := s.mappings[address]
	s.mappingAccess.RUnlock()
	return domain, found
}

func (s *runtimeNamespace) FakeIPLoadDomain(domain string, ipv6 bool) (netip.Addr, bool) {
	s.mappingAccess.RLock()
	index := s.domains4
	if ipv6 {
		index = s.domains6
	}
	address, found := index[domain]
	s.mappingAccess.RUnlock()
	return address, found
}

func (s *runtimeNamespace) FakeIPReset() error {
	return errors.New("runtime fake-IP namespaces cannot be reset; prepare a replacement")
}

func (s *runtimeNamespace) answerLocked(address netip.Addr) (adapter.FakeIPRuntimeAnswer, bool, error) {
	s.cache.pendingAccess.RLock()
	if pending := s.cache.pending.fakeIPRuntime[s.descriptor.ID]; pending != nil {
		if answer, found := pending.answers[address]; found {
			s.cache.pendingAccess.RUnlock()
			return answer, true, nil
		}
	}
	s.cache.pendingAccess.RUnlock()
	var answer adapter.FakeIPRuntimeAnswer
	found := false
	err := s.cache.runtimeView(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		raw := namespace.Bucket(bucketRuntimeAnswers).Get(address.AsSlice())
		if len(raw) == 0 {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &answer)
	})
	return answer, found, err
}

func (s *runtimeNamespace) queueAnswerLocked(answer adapter.FakeIPRuntimeAnswer, issued bool) {
	s.cache.pendingAccess.Lock()
	defer s.cache.pendingAccess.Unlock()
	pending := s.cache.runtimePendingLocked(s.descriptor.ID)
	old, found := pending.answers[answer.Address]
	pending.answers[answer.Address] = answer
	pending.issued = pending.issued || issued
	size := len(answer.Domain) - len(old.Domain)
	if !found {
		size += 64
	}
	s.cache.enqueueLocked(!found, size)
}

func runtimeTokenKey(answer adapter.FakeIPRuntimeAnswer) []byte {
	key := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(key, answer.Token)
	return append(key, answer.Address.AsSlice()...)
}

func (s *runtimeNamespace) tokenLocked(answer adapter.FakeIPRuntimeAnswer) (adapter.FakeIPRuntimeAnswer, bool, error) {
	key := runtimeTokenKey(answer)
	s.cache.pendingAccess.RLock()
	if pending := s.cache.pending.fakeIPRuntime[s.descriptor.ID]; pending != nil {
		if token, found := pending.tokens[string(key)]; found {
			s.cache.pendingAccess.RUnlock()
			if token == nil {
				return adapter.FakeIPRuntimeAnswer{}, false, nil
			}
			return *token, true, nil
		}
	}
	s.cache.pendingAccess.RUnlock()
	var token adapter.FakeIPRuntimeAnswer
	found := false
	err := s.cache.runtimeView(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		raw := namespace.Bucket(bucketRuntimeTokens).Get(key)
		if len(raw) == 0 {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &token)
	})
	return token, found, err
}

func (s *runtimeNamespace) queueTokenLocked(answer adapter.FakeIPRuntimeAnswer, remove bool) {
	s.cache.pendingAccess.Lock()
	defer s.cache.pendingAccess.Unlock()
	pending := s.cache.runtimePendingLocked(s.descriptor.ID)
	key := string(runtimeTokenKey(answer))
	_, found := pending.tokens[key]
	if remove {
		pending.tokens[key] = nil
	} else {
		copyAnswer := answer
		pending.tokens[key] = &copyAnswer
	}
	size := 0
	if !found {
		size = len(key) + 64
	}
	s.cache.enqueueLocked(!found, size)
}

func (s *runtimeNamespace) Observe(ctx context.Context, requested []adapter.FakeIPRuntimeAnswer) error {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.cache.pendingAccess.RLock()
	priorFailure := s.cache.pending.fakeIPFailure
	s.cache.pendingAccess.RUnlock()
	if priorFailure != nil {
		return fmt.Errorf("fake-IP batch durability pending: %v", priorFailure)
	}
	needSync := false
	err := s.cache.runtimeView(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		if len(namespace.Get(keyRuntimeIssued)) == 0 {
			needSync = true
		}
		for _, request := range requested {
			var durable adapter.FakeIPRuntimeAnswer
			raw := namespace.Bucket(bucketRuntimeAnswers).Get(request.Address.AsSlice())
			if len(raw) == 0 {
				needSync = true
				continue
			}
			if err := json.Unmarshal(raw, &durable); err != nil {
				return err
			}
			if durable.Obsolete || durable.Domain != request.Domain || durable.Revision != request.Revision || durable.Pending == 0 || durable.PendingTTL < request.PendingTTL {
				needSync = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, request := range requested {
		if request.Token == 0 || request.Revision == 0 || request.Domain == "" {
			return ErrFakeIPRuntimeConflict
		}
		oldToken, exists, err := s.tokenLocked(request)
		if err != nil {
			return err
		}
		if exists {
			if oldToken.Domain != request.Domain || oldToken.Revision != request.Revision || oldToken.PendingTTL != request.PendingTTL {
				return ErrFakeIPRuntimeConflict
			}
			continue
		}
		current, found, err := s.answerLocked(request.Address)
		if err != nil {
			return err
		}
		if !found || current.Domain != request.Domain || current.Revision != request.Revision {
			current = request
			current.Token = 0
			current.Pending = 0
		}
		if current.Pending == ^uint64(0) {
			return ErrFakeIPRuntimeConflict
		}
		current.Obsolete, current.Superseded = false, false
		current.Pending++
		current.PendingTTL = max(current.PendingTTL, request.PendingTTL)
		s.queueAnswerLocked(current, true)
		s.queueTokenLocked(request, false)
	}
	if needSync {
		return s.cache.flushPendingLocked()
	}
	return nil
}

func (s *runtimeNamespace) Complete(ctx context.Context, completed []adapter.FakeIPRuntimeAnswer, at time.Time, delivered bool) error {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, completion := range completed {
		token, found, err := s.tokenLocked(completion)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if token.Revision != completion.Revision || token.Domain != completion.Domain {
			return ErrFakeIPRuntimeConflict
		}
		current, found, err := s.answerLocked(completion.Address)
		if err != nil {
			return err
		}
		if found && current.Revision == completion.Revision && current.Domain == completion.Domain {
			if current.Pending != 0 {
				current.Pending--
			}
			if delivered {
				expiry := at.Add(time.Duration(completion.PendingTTL) * time.Second)
				if expiry.After(current.ExpiresAt) {
					current.ExpiresAt = expiry
				}
			}
			if current.Pending == 0 {
				current.PendingTTL = 0
			}
			s.queueAnswerLocked(current, true)
		}
		s.queueTokenLocked(completion, true)
	}
	return nil
}

func (s *runtimeNamespace) Recover(ctx context.Context, now time.Time) ([]adapter.FakeIPRuntimeAnswer, error) {
	return s.RecoverWithDeadlines(ctx, now, nil)
}

func (s *runtimeNamespace) RecoverWithDeadlines(ctx context.Context, now time.Time, deadlines map[uint64]time.Time) ([]adapter.FakeIPRuntimeAnswer, error) {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.cache.flushPendingLocked(); err != nil {
		return nil, err
	}
	var records []adapter.FakeIPRuntimeAnswer
	err := s.cache.runtimeUpdate(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		answers := namespace.Bucket(bucketRuntimeAnswers)
		tokenExpiries := make(map[netip.Addr]map[uint64]time.Time)
		if deadlines != nil {
			if err = namespace.Bucket(bucketRuntimeTokens).ForEach(func(_, raw []byte) error {
				var token adapter.FakeIPRuntimeAnswer
				if err := json.Unmarshal(raw, &token); err != nil {
					return err
				}
				expires, found := deadlines[token.Token]
				if !found {
					return ErrFakeIPRuntimeConflict
				}
				if tokenExpiries[token.Address] == nil {
					tokenExpiries[token.Address] = make(map[uint64]time.Time)
				}
				if expires.After(tokenExpiries[token.Address][token.Revision]) {
					tokenExpiries[token.Address][token.Revision] = expires
				}
				return nil
			}); err != nil {
				return err
			}
		}
		var changed []adapter.FakeIPRuntimeAnswer
		if err = answers.ForEach(func(_, raw []byte) error {
			var answer adapter.FakeIPRuntimeAnswer
			if err := json.Unmarshal(raw, &answer); err != nil {
				return err
			}
			if answer.Pending != 0 {
				expiry := now.Add(time.Duration(answer.PendingTTL) * time.Second)
				if deadlines != nil {
					expiry = tokenExpiries[answer.Address][answer.Revision]
					if expiry.IsZero() && !answer.Obsolete {
						return ErrFakeIPRuntimeConflict
					}
				}
				if expiry.After(answer.ExpiresAt) {
					answer.ExpiresAt = expiry
				}
				answer.Pending, answer.PendingTTL = 0, 0
				changed = append(changed, answer)
			}
			if !answer.Obsolete && !answer.ExpiresAt.After(now) {
				answer.Obsolete = true
				answer.ExpiresAt = time.Time{}
				changed = append(changed, answer)
			}
			// One tombstone per allocated address suppresses older copied
			// certificates; whole-namespace reclamation removes it later.
			records = append(records, answer)
			return nil
		}); err != nil {
			return err
		}
		for _, answer := range changed {
			if err = putRuntimeJSON(answers, answer.Address.AsSlice(), answer); err != nil {
				return err
			}
		}
		if err = namespace.DeleteBucket(bucketRuntimeTokens); err != nil {
			return err
		}
		_, err = namespace.CreateBucket(bucketRuntimeTokens)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *runtimeNamespace) Abort(ctx context.Context) error {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.cache.pendingAccess.RLock()
	pending := s.cache.pending.fakeIPRuntime[s.descriptor.ID]
	issued := pending != nil && pending.issued
	s.cache.pendingAccess.RUnlock()
	if issued {
		return ErrFakeIPRuntimeIssued
	}
	err := s.cache.runtimeUpdate(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if errors.Is(err, ErrFakeIPRuntimeMissing) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(namespace.Get(keyRuntimeIssued)) != 0 {
			return ErrFakeIPRuntimeIssued
		}
		root, err := runtimeRoot(tx)
		if err != nil {
			return err
		}
		return root.Bucket(bucketRuntimeNamespaces).DeleteBucket([]byte(s.descriptor.ID))
	})
	if err == nil {
		s.cache.pendingAccess.Lock()
		s.cache.dropRuntimePendingLocked(s.descriptor.ID)
		s.cache.pendingAccess.Unlock()
	}
	return err
}

func (s *runtimeNamespace) Reclaim(ctx context.Context) error {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.cache.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx)
		if err != nil {
			return err
		}
		if string(root.Get(keyRuntimeIdentity)) != s.descriptor.Backend.DatabaseID {
			return ErrFakeIPRuntimeIdentity
		}
		all := root.Bucket(bucketRuntimeNamespaces)
		if all.Bucket([]byte(s.descriptor.ID)) == nil {
			return nil
		}
		if _, err = s.bucket(tx); err != nil {
			return err
		}
		return all.DeleteBucket([]byte(s.descriptor.ID))
	})
	if err == nil {
		s.cache.pendingAccess.Lock()
		s.cache.dropRuntimePendingLocked(s.descriptor.ID)
		s.cache.pendingAccess.Unlock()
	}
	return err
}

func (s *runtimeNamespace) Invalidate(ctx context.Context, identities []adapter.FakeIPRuntimeAnswer) error {
	s.cache.flushAccess.Lock()
	defer s.cache.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.cache.flushPendingLocked(); err != nil {
		return err
	}
	return s.cache.runtimeUpdate(func(tx *bbolt.Tx) error {
		namespace, err := s.bucket(tx)
		if err != nil {
			return err
		}
		answers := namespace.Bucket(bucketRuntimeAnswers)
		for _, identity := range identities {
			var current adapter.FakeIPRuntimeAnswer
			raw := answers.Get(identity.Address.AsSlice())
			if len(raw) == 0 {
				continue
			}
			if err := json.Unmarshal(raw, &current); err != nil {
				return err
			}
			if current.Revision == identity.Revision && current.Domain == identity.Domain {
				current.Obsolete, current.Superseded = true, true
				current.Pending = 0
				current.PendingTTL = 0
				current.ExpiresAt = time.Time{}
				if err := putRuntimeJSON(answers, identity.Address.AsSlice(), current); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *runtimeNamespace) Flush(ctx context.Context) error { return s.cache.FlushFakeIP(ctx) }

// QueueAuthority cannot perform I/O: manager calls it under its short data
// fence. One latest tombstone per pool address shares ordinary batch limits.
func (s *runtimeNamespace) QueueAuthority(authority adapter.FakeIPRuntimeAnswer) {
	s.cache.pendingAccess.Lock()
	defer s.cache.pendingAccess.Unlock()
	pending := s.cache.runtimePendingLocked(s.descriptor.ID)
	old, found := pending.authorities[authority.Address]
	if found && old.Revision >= authority.Revision {
		return
	}
	authority.Token, authority.Pending, authority.PendingTTL = 0, 0, 0
	authority.Obsolete, authority.Superseded, authority.ExpiresAt = true, false, time.Time{}
	pending.issued = true
	pending.authorities[authority.Address] = authority
	size := len(authority.Domain) - len(old.Domain)
	if !found {
		size += 64
	}
	s.cache.enqueueLocked(!found, size)
}
