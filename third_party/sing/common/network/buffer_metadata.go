package network

import "github.com/sagernet/sing/common"

// ReaderBufferMetadata and WriterBufferMetadata describe a complete hidden
// suffix of a connection's buffer contract. They contain only scalar values:
// no carrier, callback or raw descriptor can escape an ownership boundary.
// Lazy is directional and resets any already accumulated outer metadata, just
// as LazyHeadroom does when traversed without a boundary.
type ReaderBufferMetadata struct {
	Overhead int
	MTU      int
	Lazy     bool
}

type WriterBufferMetadata struct {
	FrontHeadroom int
	RearHeadroom  int
	MTU           int
	Lazy          bool
}

type ReaderBufferMetadataProvider interface{ ReaderBufferMetadata() ReaderBufferMetadata }
type WriterBufferMetadataProvider interface{ WriterBufferMetadata() WriterBufferMetadata }

// Each direction is traversed once. In particular, nested opaque boundaries
// must not recursively resample every field (which would be exponential).
func CalculateReaderBufferMetadata(reader any) ReaderBufferMetadata {
	var result ReaderBufferMetadata
	for reader != nil {
		if boundary, ok := reader.(ReaderBufferMetadataProvider); ok {
			value := boundary.ReaderBufferMetadata()
			if value.Lazy {
				return ReaderBufferMetadata{Overhead: DefaultHeadroom, Lazy: true}
			}
			result.Overhead += value.Overhead
			if value.MTU > result.MTU {
				result.MTU = value.MTU
			}
			return result
		}
		if lazy, ok := reader.(LazyHeadroom); ok && lazy.LazyHeadroom() {
			return ReaderBufferMetadata{Overhead: DefaultHeadroom, Lazy: true}
		}
		if overhead, ok := reader.(ReaderOverhead); ok {
			result.Overhead += overhead.ReaderOverhead()
		}
		if withMTU, ok := reader.(ReaderWithMTU); ok {
			if mtu := withMTU.ReaderMTU(); mtu > result.MTU {
				result.MTU = mtu
			}
		}
		if upstream, ok := reader.(WithUpstreamReader); ok {
			reader = upstream.UpstreamReader()
		} else if upstream, ok := reader.(common.WithUpstream); ok {
			reader = upstream.Upstream()
		} else {
			break
		}
	}
	return result
}

func CalculateWriterBufferMetadata(writer any) WriterBufferMetadata {
	var result WriterBufferMetadata
	for writer != nil {
		if boundary, ok := writer.(WriterBufferMetadataProvider); ok {
			value := boundary.WriterBufferMetadata()
			if value.Lazy {
				return WriterBufferMetadata{FrontHeadroom: DefaultHeadroom, RearHeadroom: DefaultHeadroom, Lazy: true}
			}
			result.FrontHeadroom += value.FrontHeadroom
			result.RearHeadroom += value.RearHeadroom
			if result.MTU == 0 || value.MTU > 0 && value.MTU < result.MTU {
				result.MTU = value.MTU
			}
			return result
		}
		if lazy, ok := writer.(LazyHeadroom); ok && lazy.LazyHeadroom() {
			return WriterBufferMetadata{FrontHeadroom: DefaultHeadroom, RearHeadroom: DefaultHeadroom, Lazy: true}
		}
		if front, ok := writer.(FrontHeadroom); ok {
			result.FrontHeadroom += front.FrontHeadroom()
		}
		if rear, ok := writer.(RearHeadroom); ok {
			result.RearHeadroom += rear.RearHeadroom()
		}
		if withMTU, ok := writer.(WriterWithMTU); ok {
			if mtu := withMTU.WriterMTU(); result.MTU == 0 || mtu > 0 && mtu < result.MTU {
				result.MTU = mtu
			}
		}
		if upstream, ok := writer.(WithUpstreamWriter); ok {
			writer = upstream.UpstreamWriter()
		} else if upstream, ok := writer.(common.WithUpstream); ok {
			writer = upstream.Upstream()
		} else {
			break
		}
	}
	return result
}
