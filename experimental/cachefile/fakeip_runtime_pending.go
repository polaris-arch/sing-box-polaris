package cachefile

import (
	"encoding/json"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

func (c *CacheFile) runtimePendingLocked(id string) *runtimePending {
	pending := c.pending.fakeIPRuntime[id]
	if pending == nil {
		pending = newRuntimePending()
		c.pending.fakeIPRuntime[id] = pending
	}
	return pending
}

func writeRuntimePending(tx *bbolt.Tx, namespaces map[string]*runtimePending) error {
	for id, pending := range namespaces {
		namespace, err := runtimeNamespaceBucket(tx, id)
		if err != nil {
			return err
		}
		if pending.metadata != nil {
			if err = putRuntimeJSON(namespace, keyRuntimeMetadata, pending.metadata); err != nil {
				return err
			}
		}
		for address, domain := range pending.mappings {
			if err = putRuntimeMapping(namespace, address, domain); err != nil {
				return err
			}
		}
		for _, authority := range pending.authorities {
			if err = putRuntimeAnswer(namespace.Bucket(bucketRuntimeAnswers), authority); err != nil {
				return err
			}
		}
		for _, answer := range pending.answers {
			if err = putRuntimeAnswer(namespace.Bucket(bucketRuntimeAnswers), answer); err != nil {
				return err
			}
		}
		for key, token := range pending.tokens {
			if token == nil {
				if err = namespace.Bucket(bucketRuntimeTokens).Delete([]byte(key)); err != nil {
					return err
				}
			} else {
				if err = putRuntimeJSON(namespace.Bucket(bucketRuntimeTokens), []byte(key), token); err != nil {
					return err
				}
			}
		}
		if pending.issued {
			if err = namespace.Put(keyRuntimeIssued, []byte{1}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CacheFile) restoreFakeIPLocked(failed *pendingWrites) {
	// Newer pending entries win. A transaction failure never discards an
	// issued identity or silently turns an uncertain write into completion.
	for address, domain := range failed.fakeIPDomain {
		if _, newer := c.pending.fakeIPDomain[address]; !newer {
			c.pending.fakeIPDomain[address] = domain
			c.pending.count++
			c.pending.size += len(domain)
		}
	}
	for domain, address := range failed.fakeIPAddress4 {
		if _, newer := c.pending.fakeIPAddress4[domain]; !newer {
			c.pending.fakeIPAddress4[domain] = address
		}
	}
	for domain, address := range failed.fakeIPAddress6 {
		if _, newer := c.pending.fakeIPAddress6[domain]; !newer {
			c.pending.fakeIPAddress6[domain] = address
		}
	}
	if c.pending.fakeIPMetadata == nil && failed.fakeIPMetadata != nil {
		c.pending.fakeIPMetadata = failed.fakeIPMetadata
		c.pending.count++
	}
	for id, older := range failed.fakeIPRuntime {
		pending := c.runtimePendingLocked(id)
		if pending.metadata == nil && older.metadata != nil {
			pending.metadata = older.metadata
			c.pending.count++
		}
		for address, domain := range older.mappings {
			if _, newer := pending.mappings[address]; !newer {
				pending.mappings[address] = domain
				c.pending.count++
				c.pending.size += len(domain)
			}
		}
		for domain, address := range older.domains4 {
			if _, newer := pending.domains4[domain]; !newer {
				pending.domains4[domain] = address
			}
		}
		for domain, address := range older.domains6 {
			if _, newer := pending.domains6[domain]; !newer {
				pending.domains6[domain] = address
			}
		}
		for address, answer := range older.answers {
			if _, newer := pending.answers[address]; !newer {
				pending.answers[address] = answer
				c.pending.count++
				c.pending.size += len(answer.Domain) + 64
			}
		}
		for address, authority := range older.authorities {
			if current, newer := pending.authorities[address]; !newer {
				pending.authorities[address] = authority
				c.pending.count++
				c.pending.size += len(authority.Domain) + 64
			} else if authority.Revision > current.Revision {
				pending.authorities[address] = authority
				c.pending.size += len(authority.Domain) - len(current.Domain)
			}
		}
		for key, token := range older.tokens {
			if _, newer := pending.tokens[key]; !newer {
				pending.tokens[key] = token
				c.pending.count++
				c.pending.size += len(key) + 64
			}
		}
		pending.issued = pending.issued || older.issued
	}
}

func (c *CacheFile) dropRuntimePendingLocked(id string) {
	pending := c.pending.fakeIPRuntime[id]
	if pending == nil {
		return
	}
	if pending.metadata != nil {
		c.pending.count--
	}
	for _, domain := range pending.mappings {
		c.pending.count--
		c.pending.size -= len(domain)
	}
	for _, answer := range pending.answers {
		c.pending.count--
		c.pending.size -= len(answer.Domain) + 64
	}
	for _, authority := range pending.authorities {
		c.pending.count--
		c.pending.size -= len(authority.Domain) + 64
	}
	c.pending.count -= len(pending.tokens)
	for key := range pending.tokens {
		c.pending.size -= len(key) + 64
	}
	delete(c.pending.fakeIPRuntime, id)
}

func mergeRuntimeAnswer(current adapter.FakeIPRuntimeAnswer, exists bool, next adapter.FakeIPRuntimeAnswer) (bool, error) {
	if !exists || next.Revision > current.Revision {
		return true, nil
	}
	if next.Revision < current.Revision {
		return false, nil
	}
	if next.Domain != current.Domain {
		return false, ErrFakeIPRuntimeConflict
	}
	// A queued assignment with this same identity cannot erase an already
	// certified answer. Explicit Invalidate has its own exact transaction.
	if current.Superseded && !next.Superseded {
		return false, nil
	}
	if next.Obsolete && !next.Superseded && !current.Obsolete {
		return false, nil
	}
	return true, nil
}

func putRuntimeAnswer(bucket *bbolt.Bucket, next adapter.FakeIPRuntimeAnswer) error {
	raw := bucket.Get(next.Address.AsSlice())
	var current adapter.FakeIPRuntimeAnswer
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &current); err != nil {
			return err
		}
	}
	write, err := mergeRuntimeAnswer(current, len(raw) != 0, next)
	if err != nil || !write {
		return err
	}
	return putRuntimeJSON(bucket, next.Address.AsSlice(), next)
}
