package cachefile

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
)

const defaultBufferSize = 1024 * 1024

type pendingWrites struct {
	dnsCache       map[saveCacheKey]saveDNSCacheEntry
	rdrc           map[saveCacheKey]struct{}
	fakeIPDomain   map[netip.Addr]string
	fakeIPAddress4 map[string]netip.Addr
	fakeIPAddress6 map[string]netip.Addr
	fakeIPMetadata *adapter.FakeIPMetadata
	count          int
	size           int
}

func newPendingWrites() *pendingWrites {
	return &pendingWrites{
		dnsCache:       make(map[saveCacheKey]saveDNSCacheEntry),
		rdrc:           make(map[saveCacheKey]struct{}),
		fakeIPDomain:   make(map[netip.Addr]string),
		fakeIPAddress4: make(map[string]netip.Addr),
		fakeIPAddress6: make(map[string]netip.Addr),
	}
}

func (c *CacheFile) enqueueLocked(added bool, sizeDelta int) {
	if added {
		c.pending.count++
		if c.pending.count == 1 && c.flushInterval > 0 {
			c.flushTimer.Reset(c.flushInterval)
		}
	}
	c.pending.size += sizeDelta
	if c.pending.size >= c.bufferSize {
		select {
		case c.flushSignal <- struct{}{}:
		default:
		}
	}
}

func (c *CacheFile) loopFlush(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.flushTimer.C:
		case <-c.flushSignal:
		}
		c.Flush()
	}
}

func (c *CacheFile) Flush() {
	if err := c.FlushFakeIP(context.Background()); err != nil {
		c.logger.Warn("save cache: ", err)
	}
}

// FlushFakeIP preserves failed fake-IP writes and exposes the real transaction
// result. Cancellation is observed before I/O; a started transaction is joined.
func (c *CacheFile) FlushFakeIP(ctx context.Context) error {
	c.flushAccess.Lock()
	defer c.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.pendingAccess.Lock()
	if c.pending.count == 0 {
		c.pendingAccess.Unlock()
		return nil
	}
	writing := c.pending
	c.writing = writing
	c.pending = newPendingWrites()
	c.pendingAccess.Unlock()
	// A database retained by runtime views must not take the legacy reset path.
	var err error
	if c.runtimeStrict.Load() {
		err = c.runtimeUpdate(func(tx *bbolt.Tx) error { return c.writePending(tx, writing) })
	} else {
		err = c.update(func(tx *bbolt.Tx) error { return c.writePending(tx, writing) })
	}
	c.pendingAccess.Lock()
	if err != nil {
		c.restoreFakeIPLocked(writing)
	}
	c.writing = nil
	c.pendingAccess.Unlock()
	return err
}

func (c *CacheFile) writePending(tx *bbolt.Tx, pending *pendingWrites) error {
	if len(pending.dnsCache) > 0 {
		bucket, err := c.createBucket(tx, bucketDNSCache)
		if err != nil {
			return err
		}
		for key, entry := range pending.dnsCache {
			err = putCacheEntry(bucket, key, entry.value)
			if err != nil {
				return err
			}
		}
	}
	if len(pending.rdrc) > 0 {
		bucket, err := c.createBucket(tx, bucketRDRC)
		if err != nil {
			return err
		}
		expiresAt := make([]byte, 8)
		binary.BigEndian.PutUint64(expiresAt, uint64(time.Now().Add(c.rdrcTimeout).Unix()))
		for key := range pending.rdrc {
			err = putCacheEntry(bucket, key, expiresAt)
			if err != nil {
				return err
			}
		}
	}
	for address, domain := range pending.fakeIPDomain {
		err := putFakeIP(tx, address, domain)
		if err != nil {
			return err
		}
	}
	if pending.fakeIPMetadata != nil {
		err := putFakeIPMetadata(tx, pending.fakeIPMetadata)
		if err != nil {
			return err
		}
	}
	return nil
}

func putCacheEntry(bucket *bbolt.Bucket, key saveCacheKey, value []byte) error {
	transportBucket, err := bucket.CreateBucketIfNotExists([]byte(key.TransportName))
	if err != nil {
		return err
	}
	keyBytes := buf.Get(2 + len(key.QuestionName))
	defer buf.Put(keyBytes)
	binary.BigEndian.PutUint16(keyBytes, key.QType)
	copy(keyBytes[2:], key.QuestionName)
	return transportBucket.Put(keyBytes, value)
}

func getCacheEntry(bucket *bbolt.Bucket, key saveCacheKey) []byte {
	transportBucket := bucket.Bucket([]byte(key.TransportName))
	if transportBucket == nil {
		return nil
	}
	keyBytes := buf.Get(2 + len(key.QuestionName))
	defer buf.Put(keyBytes)
	binary.BigEndian.PutUint16(keyBytes, key.QType)
	copy(keyBytes[2:], key.QuestionName)
	return transportBucket.Get(keyBytes)
}

func (c *CacheFile) restoreFakeIPLocked(failed *pendingWrites) {
	// Newer pending entries win. A transaction failure never discards an
	// issued mapping or silently turns an uncertain write into completion.
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
}
