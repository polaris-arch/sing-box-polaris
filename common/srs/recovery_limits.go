package srs

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"

	"github.com/sagernet/sing-box/common/ipset"
	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"

	"go4.org/netipx"
)

// checkMatcherRecovery bounds the succinct trie's expanded output before Dump
// materializes keys. LOUDS encodes nodes in breadth-first order as zero bits for
// their children followed by one bit, so depths can be counted with level
// boundaries and constant auxiliary memory. The decoded-size limit alone is
// insufficient: a chain with a leaf at every node expands quadratically.
func checkMatcherRecovery(reader varbin.Reader, data domain.Mmap) error {
	b := resourceBudget(reader)
	if b == nil {
		return nil
	}
	malformed := func() error { return errors.New("malformed domain matcher recovery topology") }
	checkContext := func() error {
		if b.ctx != nil {
			return b.ctx.Err()
		}
		return nil
	}
	if err := checkContext(); err != nil {
		return err
	}
	lastOne := -1
	for i, word := range data.LabelBitmap {
		if i&1023 == 0 {
			if err := checkContext(); err != nil {
				return err
			}
		}
		if word != 0 {
			lastOne = i*64 + bits.Len64(word) - 1
		}
	}
	if lastOne < 0 {
		return malformed()
	}
	var node, created, levelEnd, depth uint64 = 0, 1, 1, 0
	var labels, leaves, expanded uint64
	// Reserve a small per-key margin for AdGuard's reconstructed | / || / ^
	// decorations. This also makes the shared budget conservative for Matcher.
	const decorationBytes uint64 = 4
	maxExpanded := uint64(b.limits.DecodedBytes)
	if b.recoveredBytes > maxExpanded {
		return limitError("recovered bytes")
	}
	for bit := 0; bit <= lastOne; bit++ {
		if bit&4095 == 0 {
			if err := checkContext(); err != nil {
				return err
			}
		}
		if node >= created {
			return malformed()
		}
		if data.LabelBitmap[bit/64]&(uint64(1)<<uint(bit%64)) == 0 {
			labels++
			if labels > uint64(len(data.Labels)) {
				return malformed()
			}
			created++
			continue
		}
		if node/64 >= uint64(len(data.Leaves)) {
			return malformed()
		}
		// Limit traversal stack depth too, including unmarked internal nodes.
		if depth > b.limits.StringBytes {
			return limitError("recovered string bytes")
		}
		if data.Leaves[node/64]&(uint64(1)<<uint(node%64)) != 0 {
			// Both domain Dump methods index key[0]; an empty root key is unsafe.
			if depth == 0 {
				return malformed()
			}
			leaves++
			remaining := maxExpanded - b.recoveredBytes - expanded
			if remaining < decorationBytes || depth > remaining-decorationBytes {
				return limitError("recovered bytes")
			}
			expanded += depth + decorationBytes
		}
		node++
		if node == levelEnd {
			depth++
			levelEnd = created
		}
	}
	if node != created || labels != uint64(len(data.Labels)) {
		return malformed()
	}
	if err := checkContext(); err != nil {
		return err
	}
	if err := claimEntries(reader, leaves); err != nil {
		return err
	}
	b.recoveredBytes += expanded
	return nil
}

// checkIPSetRecovery bounds Prefixes/Common.Map before either allocates the
// whole expansion. One range yields at most 2*address-bits prefixes, so this
// preflight has constant bounded scratch space. Adjacent stored ranges may
// merge in IPSet.Prefixes; summing them separately is a conservative bound.
func checkIPSetRecovery(reader varbin.Reader, set *ipset.Set) error {
	b := resourceBudget(reader)
	if b == nil {
		return nil
	}
	// Account conservatively for the transient Prefix slice, pointer slice and
	// Prefixable objects, not as a claim about allocator RSS or JSON encoding.
	const prefixUnits uint64 = 128
	maxBytes := uint64(b.limits.DecodedBytes)
	if b.recoveredBytes > maxBytes {
		return limitError("recovered bytes")
	}
	var count uint64
	checkRange := func(from, to netip.Addr) error {
		if b.ctx != nil {
			if err := b.ctx.Err(); err != nil {
				return err
			}
		}
		n := uint64(len(netipx.IPRangeFrom(from, to).Prefixes()))
		if n > b.limits.Entries-b.entries-count {
			return limitError("recovered prefixes")
		}
		count += n
		if count > (maxBytes-b.recoveredBytes)/prefixUnits {
			return limitError("recovered bytes")
		}
		return nil
	}
	for _, r := range set.Ranges4() {
		var from, to [4]byte
		binary.BigEndian.PutUint32(from[:], r.From)
		binary.BigEndian.PutUint32(to[:], r.To)
		if err := checkRange(netip.AddrFrom4(from), netip.AddrFrom4(to)); err != nil {
			return err
		}
	}
	for _, r := range set.Ranges6() {
		if err := checkRange(netip.AddrFrom16(r.From), netip.AddrFrom16(r.To)); err != nil {
			return err
		}
	}
	if err := claimEntries(reader, count); err != nil {
		return err
	}
	b.recoveredBytes += count * prefixUnits
	return nil
}
