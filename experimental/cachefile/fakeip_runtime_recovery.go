package cachefile

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

var bucketRuntimeDeadlines = []byte("recovery_deadlines")
var keyRuntimeHighToken = []byte("high_token")

// The custody anchor fixes deadlines BEFORE any copied namespace consumes a
// pending token. A crash halfway through recovery reuses this same transaction's
// deadline. Entries are removed only after every discovered copy was consumed;
// the monotonic token high-water mark remains a constant-size scalar.
func (c *CacheFile) ResolveFakeIPPendingExpiries(ctx context.Context, tokens []adapter.FakeIPRuntimeAnswer, now time.Time) (map[uint64]time.Time, uint64, error) {
	if err := ctx.Err(); err != nil { return nil, 0, err }
	maximumTTL := make(map[uint64]uint32)
	for _, token := range tokens { if token.Token == 0 { return nil, 0, ErrFakeIPRuntimeConflict }; maximumTTL[token.Token] = max(maximumTTL[token.Token], token.PendingTTL) }
	deadlines := make(map[uint64]time.Time); var high uint64
	err := c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		bucket, err := root.CreateBucketIfNotExists(bucketRuntimeDeadlines); if err != nil { return err }
		if raw := root.Get(keyRuntimeHighToken); len(raw) == 8 { high = binary.BigEndian.Uint64(raw) } else if len(raw) != 0 { return ErrFakeIPRuntimeVersion }
		// Discovery is complete before this recovery-only method is called.
		// A crash after all copies were consumed but before release must not
		// leave an ever-growing set of already-finished deadline certificates.
		var stale [][]byte
		if err = bucket.ForEach(func(key, _ []byte) error { if len(key) != 8 { return ErrFakeIPRuntimeVersion }; if _, live := maximumTTL[binary.BigEndian.Uint64(key)]; !live { stale = append(stale, append([]byte(nil), key...)) }; return nil }); err != nil { return err }
		for _, key := range stale { if err = bucket.Delete(key); err != nil { return err } }
		for token, ttl := range maximumTTL {
			var key [8]byte; binary.BigEndian.PutUint64(key[:], token)
			var deadline time.Time
			if raw := bucket.Get(key[:]); len(raw) != 0 { if err = json.Unmarshal(raw, &deadline); err != nil { return err } } else {
				deadline = now.Add(time.Duration(ttl)*time.Second)
				if err = putRuntimeJSON(bucket, key[:], deadline); err != nil { return err }
			}
			deadlines[token] = deadline; high = max(high, token)
		}
		var encoded [8]byte; binary.BigEndian.PutUint64(encoded[:], high)
		return root.Put(keyRuntimeHighToken, encoded[:])
	})
	return deadlines, high, err
}
func (c *CacheFile) ReleaseFakeIPPendingExpiries(ctx context.Context, tokens []uint64) error {
	if err := ctx.Err(); err != nil { return err }
	return c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		bucket := root.Bucket(bucketRuntimeDeadlines); if bucket == nil { return nil }
		for _, token := range tokens { var key [8]byte; binary.BigEndian.PutUint64(key[:], token); if err = bucket.Delete(key[:]); err != nil { return err } }
		return nil
	})
}

// AllocateFakeIPGeneration reserves an ordering label, not a config decision.
// Failed/aborted candidates may leave gaps; overflow is an explicit Plan error.
func (c *CacheFile) AllocateFakeIPGeneration(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil { return 0, err }
	var generation uint64
	err := c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		key := []byte("namespace_generation")
		if raw := root.Get(key); len(raw) == 8 { generation = binary.BigEndian.Uint64(raw) } else if len(raw) != 0 { return ErrFakeIPRuntimeVersion }
		if generation == ^uint64(0) { return ErrFakeIPRuntimeConflict }; generation++
		var encoded [8]byte; binary.BigEndian.PutUint64(encoded[:], generation)
		return root.Put(key, encoded[:])
	})
	return generation, err
}

func (c *CacheFile) ReserveFakeIPRuntimeCounters(ctx context.Context, minimum adapter.FakeIPRuntimeCounters, count uint64) (floor, ceiling adapter.FakeIPRuntimeCounters, err error) {
	if err = ctx.Err(); err != nil { return }
	if count == 0 { err = ErrFakeIPRuntimeConflict; return }
	err = c.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		key := []byte("authority_counter_ceiling")
		if raw := root.Get(key); len(raw) != 0 { if err = json.Unmarshal(raw, &floor); err != nil { return err } }
		floor.Revision = max(floor.Revision, minimum.Revision); floor.Token = max(floor.Token, minimum.Token)
		if floor.Revision > ^uint64(0)-count || floor.Token > ^uint64(0)-count { return ErrFakeIPRuntimeConflict }
		ceiling = adapter.FakeIPRuntimeCounters{Revision: floor.Revision+count, Token: floor.Token+count}
		return putRuntimeJSON(root, key, ceiling)
	})
	return
}
