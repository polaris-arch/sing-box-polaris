package cachefile

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net/netip"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

// SnapshotFakeIP sees one durable image plus all admitted writes not yet flushed.
// Holding flushAccess excludes the writing swap; pendingAccess is held only for
// copies, never during bbolt I/O. The caller revalidates its candidate afterwards.
func (c *CacheFile) SnapshotFakeIP(ctx context.Context) (adapter.FakeIPStorageSnapshot, error) {
	c.flushAccess.Lock()
	defer c.flushAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return adapter.FakeIPStorageSnapshot{}, err
	}
	snapshot := adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
	err := c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		if raw := bucket.Get(keyMetadata); len(raw) != 0 {
			snapshot.Metadata = new(adapter.FakeIPMetadata)
			if err := snapshot.Metadata.UnmarshalBinary(raw); err != nil {
				return err
			}
		}
		return bucket.ForEach(func(key, value []byte) error {
			if bytes.Equal(key, keyMetadata) {
				return nil
			}
			address, valid := netip.AddrFromSlice(key)
			if !valid || value == nil {
				return fmt.Errorf("invalid fake-IP legacy mapping key")
			}
			snapshot.Mappings[address.Unmap()] = string(value)
			return nil
		})
	})
	if err != nil {
		return snapshot, err
	}
	c.pendingAccess.RLock()
	maps.Copy(snapshot.Mappings, c.pending.fakeIPDomain)
	if c.pending.fakeIPMetadata != nil {
		metadata := *c.pending.fakeIPMetadata
		snapshot.Metadata = &metadata
	}
	c.pendingAccess.RUnlock()
	return snapshot, nil
}
