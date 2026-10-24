package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type runtimeSinglePacketReader struct {
	payload []byte
	address M.Socksaddr
	read    bool
	last    *buf.Buffer
}

type runtimePacketMetadataFixture struct {
	N.PacketConn
	front, rear, overhead, readMTU, writeMTU int
	lazy                                     bool
	upstream                                 any
}

func (c *runtimePacketMetadataFixture) FrontHeadroom() int  { return c.front }
func (c *runtimePacketMetadataFixture) RearHeadroom() int   { return c.rear }
func (c *runtimePacketMetadataFixture) ReaderOverhead() int { return c.overhead }
func (c *runtimePacketMetadataFixture) ReaderMTU() int      { return c.readMTU }
func (c *runtimePacketMetadataFixture) WriterMTU() int      { return c.writeMTU }
func (c *runtimePacketMetadataFixture) LazyHeadroom() bool  { return c.lazy }
func (c *runtimePacketMetadataFixture) Upstream() any       { return c.upstream }

type runtimePacketMetadataFork struct {
	*runtimePacketMetadataFixture
	reader, writer any
}

func (c *runtimePacketMetadataFork) UpstreamReader() any { return c.reader }
func (c *runtimePacketMetadataFork) UpstreamWriter() any { return c.writer }

func TestRuntimePacketMetadataOuterAndDirectionalLazy(t *testing.T) {
	for _, readerLazy := range []bool{false, true} {
		for _, writerLazy := range []bool{false, true} {
			reader := &runtimePacketMetadataFixture{front: 1, rear: 2, overhead: 19, readMTU: 1700, writeMTU: 1800, lazy: readerLazy}
			writer := &runtimePacketMetadataFixture{front: 23, rear: 29, overhead: 3, readMTU: 1200, writeMTU: 1300, lazy: writerLazy}
			fork := &runtimePacketMetadataFork{runtimePacketMetadataFixture: &runtimePacketMetadataFixture{front: 3, rear: 5, overhead: 7, readMTU: 1400, writeMTU: 1500}, reader: reader, writer: writer}
			original := &runtimePacketMetadataFixture{front: 31, rear: 37, overhead: 41, readMTU: 1600, writeMTU: 1900, upstream: fork}
			wrapped := &runtimePacketConn{PacketConn: fork}
			nested := &runtimePacketConn{PacketConn: wrapped}
			for _, hidden := range []N.PacketConn{wrapped, nested} {
				outside := &runtimePacketMetadataFixture{front: 31, rear: 37, overhead: 41, readMTU: 1600, writeMTU: 1900, upstream: hidden}
				want := N.NewReadWaitOptions(original, original)
				got := N.NewReadWaitOptions(outside, outside)
				if got != want {
					t.Fatalf("readerLazy=%v writerLazy=%v: got=%+v want=%+v", readerLazy, writerLazy, got, want)
				}
				if N.CalculateReaderBufferMetadata(outside).Lazy != readerLazy || N.CalculateWriterBufferMetadata(outside).Lazy != writerLazy {
					t.Fatal("directional lazy reset changed")
				}
			}
		}
	}
}

type runtimeBlockingMetadataPacket struct {
	*runtimePacketMetadataFixture
	entered, release chan struct{}
	once             sync.Once
}

func (c *runtimeBlockingMetadataPacket) FrontHeadroom() int {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.front
}
func (c *runtimeBlockingMetadataPacket) Close() error { return nil }

func TestRuntimePacketMetadataWorkerRetainsLeaseDuringConcurrentClose(t *testing.T) {
	graph := newReferenceTestGraph(1, nil, nil)
	lease := graph.acquire()
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce, finishOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	raw := &runtimeBlockingMetadataPacket{runtimePacketMetadataFixture: &runtimePacketMetadataFixture{front: 11}, entered: entered, release: release}
	wrapped := &runtimePacketConn{PacketConn: raw, lease: lease, finish: func(error) { finishOnce.Do(lease.Release) }}
	if err := runtimeTask(adapter.ContextWithRuntimeLease(context.Background(), lease), func(context.Context) {
		defer close(returned)
		if N.CalculateFrontHeadroom(wrapped) != 11 {
			t.Error("metadata changed")
		}
	}); err != nil {
		t.Fatal(err)
	}
	managerAwait(t, entered)
	wrapped.Close()
	if count, _ := graph.counts(); count != 1 {
		t.Fatalf("concurrent close released active metadata worker: %d", count)
	}
	unblock()
	managerAwait(t, returned)
	deadline := time.Now().Add(time.Second)
	for {
		if count, _ := graph.counts(); count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("metadata worker leaked graph")
		}
		time.Sleep(time.Millisecond)
	}
}

type runtimeCountedMetadataBoundary struct {
	*runtimePacketConn
	reads, writes int
}

func (c *runtimeCountedMetadataBoundary) ReaderBufferMetadata() N.ReaderBufferMetadata {
	c.reads++
	return c.runtimePacketConn.ReaderBufferMetadata()
}
func (c *runtimeCountedMetadataBoundary) WriterBufferMetadata() N.WriterBufferMetadata {
	c.writes++
	return c.runtimePacketConn.WriterBufferMetadata()
}

func TestRuntimePacketMetadataNestedTraversalIsLinear(t *testing.T) {
	base := &runtimePacketMetadataFixture{front: 11, rear: 13, overhead: 17, readMTU: 1200, writeMTU: 1300}
	var hidden N.PacketConn = base
	var boundaries []*runtimeCountedMetadataBoundary
	for i := 0; i < 32; i++ {
		next := &runtimeCountedMetadataBoundary{runtimePacketConn: &runtimePacketConn{PacketConn: hidden}}
		boundaries = append(boundaries, next)
		hidden = next
	}
	if N.CalculateReaderBufferMetadata(hidden) != N.CalculateReaderBufferMetadata(base) || N.CalculateWriterBufferMetadata(hidden) != N.CalculateWriterBufferMetadata(base) {
		t.Fatal("nested metadata aggregate changed")
	}
	for i, boundary := range boundaries {
		if boundary.reads != 1 || boundary.writes != 1 {
			t.Fatalf("boundary%d redundantly sampled: reads=%d writes=%d", i, boundary.reads, boundary.writes)
		}
	}
}

func TestRuntimePacketMetadataExactAggregationAndNoEscape(t *testing.T) {
	inner := &runtimePacketMetadataFixture{front: 11, rear: 13, overhead: 17, readMTU: 1200, writeMTU: 1300}
	outer := &runtimePacketMetadataFixture{front: 3, rear: 5, overhead: 7, readMTU: 1400, writeMTU: 1500, upstream: inner}
	graph := newReferenceTestGraph(1, nil, nil)
	lease := graph.acquire()
	defer lease.Release()
	wrapped := &runtimePacketConn{PacketConn: outer, lease: lease}
	nested := &runtimePacketConn{PacketConn: wrapped, lease: lease}
	check := func(label string) {
		t.Helper()
		for _, candidate := range []N.PacketConn{wrapped, nested} {
			want := N.NewReadWaitOptions(outer, outer)
			got := N.NewReadWaitOptions(candidate, candidate)
			if got != want {
				t.Fatalf("%s: metadata differs got=%+v want=%+v", label, got, want)
			}
			if _, ok := any(candidate).(common.WithUpstream); ok {
				t.Fatal("raw Upstream exposed")
			}
			if _, ok := any(candidate).(N.WithUpstreamReader); ok {
				t.Fatal("raw reader exposed")
			}
			if _, ok := any(candidate).(N.WithUpstreamWriter); ok {
				t.Fatal("raw writer exposed")
			}
			if _, ok := N.CastPacketWriter[*runtimePacketMetadataFixture](candidate); ok {
				t.Fatal("packet writer escaped lease wrapper")
			}
		}
		if count, _ := graph.counts(); count != 1 {
			t.Fatalf("scalar metadata changed flow lease ownership: %d", count)
		}
	}
	check("initial exact sum/min/max")
	inner.front = 29
	inner.rear = 31
	inner.readMTU = 1900
	inner.writeMTU = 1100
	check("dynamic metadata not frozen or double counted")
	inner.lazy = true
	check("inner lazy contract")
	inner.lazy = false
	outer.lazy = true
	check("outer lazy contract")
	outer.lazy = false
	outer.upstream = nil
	check("absent inner chain")
}

func (r *runtimeSinglePacketReader) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if r.read {
		return M.Socksaddr{}, io.EOF
	}
	r.read = true
	r.last = buffer
	_, err := buffer.Write(r.payload)
	return r.address, err
}

func TestRuntimePacketSocksCopyPreservesHeadroom(t *testing.T) {
	for _, address := range []string{"127.0.0.1:23456", "[::1]:23456", "controlled.invalid:23456"} {
		for _, owned := range []bool{false, true} {
			t.Run(address+map[bool]string{false: "/baseline", true: "/owned"}[owned], func(t *testing.T) {
				wire := &handshakeWireConn{}
				protocol := socks.NewAssociatePacketConn(wire, M.ParseSocksaddr(address), nil)
				var destination N.PacketConn = protocol
				graph := newReferenceTestGraph(1, nil, nil)
				lease := graph.acquire()
				var once sync.Once
				finish := func(error) { once.Do(lease.Release) }
				if owned {
					destination = &runtimePacketConn{PacketConn: protocol, lease: lease, finish: finish}
				}
				_, timed := canceler.NewTimeoutPacketConn(context.Background(), destination, time.Second)
				defer timed.Close()
				defer finish(nil)
				reader := &runtimeSinglePacketReader{payload: []byte("controlled-response"), address: M.ParseSocksaddr(address)}
				defer func() {
					if failure := recover(); failure != nil {
						if reader.last != nil {
							reader.last.Release()
						}
						t.Errorf("real CopyPacket/SOCKS header panic (headroom=%d): %v", N.CalculateFrontHeadroom(timed), failure)
					}
				}()
				n, err := bufio.CopyPacket(timed, reader)
				if n != int64(len(reader.payload)) || !errors.Is(err, io.EOF) {
					t.Fatalf("copy result: bytes=%d err=%v", n, err)
				}
				expected := buf.New()
				defer expected.Release()
				expected.WriteZeroN(3)
				M.SocksaddrSerializer.WriteAddrPort(expected, reader.address)
				expected.Write(reader.payload)
				if !bytes.Equal(wire.output.Bytes(), expected.Bytes()) {
					t.Fatalf("SOCKS response framing mismatch: actual=%x expected=%x", wire.output.Bytes(), expected.Bytes())
				}
			})
		}
	}
}
