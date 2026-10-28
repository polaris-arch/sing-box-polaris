package tun

import (
	"encoding/binary"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
)

// segmentRetainCount bounds how many segment buffers survive a Flush; the pool
// grows to the burst high-water mark within a batch and is trimmed afterwards.
const segmentRetainCount = 128

// Linux delivers TSO aggregates to the TUN even with IFF_VNET_HDR off
// (observed on 6.x: the pre-segmentation skb is handed to the fd as-is).
func (s *ForwardStage) resegmentTCP(flow *forwardFlow, packet *forwardPacket, raw []byte, effectiveMTU uint32) {
	if len(packet.transport) < header.TCPMinimumSize {
		return
	}
	headerLength := len(raw) - len(packet.transport)
	if packet.ipVersion == 6 && headerLength != header.IPv6MinimumSize {
		reply := buildICMPError(packet, ICMPErrorPacketTooBig, effectiveMTU, s.writeback.ReturnHeadroom())
		s.access.Lock()
		s.writebackBatch = append(s.writebackBatch, reply)
		s.access.Unlock()
		return
	}
	tcpHeaderLength := int(header.TCP(packet.transport).DataOffset())
	if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(packet.transport) {
		return
	}
	totalHeaderLength := headerLength + tcpHeaderLength
	segmentSize := int(effectiveMTU) - totalHeaderLength
	if segmentSize <= 0 {
		return
	}
	gsoType := GSOTCPv4
	if packet.ipVersion == 6 {
		gsoType = GSOTCPv6
	}
	neededSegments := max((len(raw)-totalHeaderLength+segmentSize-1)/segmentSize, 1)
	bufs, sizes := s.reserveSegments(neededSegments, int(effectiveMTU))
	n, err := GSOSplit(raw, GSOOptions{
		GSOType:    gsoType,
		HdrLen:     uint16(totalHeaderLength),
		CsumStart:  uint16(headerLength),
		CsumOffset: header.TCPChecksumOffset,
		GSOSize:    uint16(segmentSize),
	}, bufs, sizes, 0)
	if err != nil {
		s.dispatcher.logger.Trace(E.Cause(err, "resegment packet"))
		return
	}
	for i := range n {
		s.stagePort(flow, bufs[i][:sizes[i]])
	}
}

// Each queued batch owns its packet storage. Reusing a stage-wide slice while
// Flush runs outside the stage lock would race a concurrent dispatch/Close.
func (s *ForwardStage) reserveSegments(count, size int) ([][]byte, []int) {
	buffers := make([][]byte, count)
	for index := range buffers { buffers[index] = make([]byte, size) }
	return buffers, make([]int, count)
}

const synthesizedTTL = 64

func fragmentIPv4Packet(packet header.IPv4, effectiveMTU uint32) ([][]byte, bool) {
	headerLength := int(packet.HeaderLength())
	if headerLength < header.IPv4MinimumSize || headerLength >= len(packet) {
		return nil, false
	}
	payload := packet[headerLength:]
	maxFragmentPayload := (int(effectiveMTU) - headerLength) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	baseOffset := packet.FragmentOffset()
	originalMore := packet.Flags()&header.IPv4FlagMoreFragments != 0
	baseFlags := packet.Flags() &^ header.IPv4FlagMoreFragments
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := min(start+maxFragmentPayload, len(payload))
		fragment := header.IPv4(make([]byte, headerLength+end-start))
		copy(fragment, packet[:headerLength])
		copy(fragment[headerLength:], payload[start:end])
		flags := baseFlags
		if originalMore || end < len(payload) {
			flags |= header.IPv4FlagMoreFragments
		}
		fragment.SetFlagsFragmentOffset(flags, baseOffset+uint16(start))
		fragment.SetTotalLength(uint16(len(fragment)))
		fragment.SetChecksum(0)
		fragment.SetChecksum(^fragment.CalculateChecksum())
		fragments = append(fragments, fragment)
	}
	return fragments, true
}

func fragmentIPv6Packet(packet header.IPv6, effectiveMTU uint32, ident uint32) ([][]byte, bool) {
	if len(packet) < header.IPv6MinimumSize {
		return nil, false
	}
	payload := packet.Payload()
	maxFragmentPayload := (int(effectiveMTU) - header.IPv6MinimumSize - header.IPv6FragmentHeaderSize) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	transportProtocol := packet.NextHeader()
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := min(start+maxFragmentPayload, len(payload))
		fragment := header.IPv6(make([]byte, header.IPv6MinimumSize+header.IPv6FragmentHeaderSize+end-start))
		copy(fragment, packet[:header.IPv6MinimumSize])
		fragment.SetNextHeader(header.IPv6FragmentHeader)
		fragment.SetPayloadLength(uint16(header.IPv6FragmentHeaderSize + end - start))
		encodeIPv6FragmentHeader(fragment[header.IPv6MinimumSize:], transportProtocol, start, end < len(payload), ident)
		copy(fragment[header.IPv6MinimumSize+header.IPv6FragmentHeaderSize:], payload[start:end])
		fragments = append(fragments, fragment)
	}
	return fragments, true
}

func encodeIPv6FragmentHeader(target []byte, nextHeader uint8, offset int, more bool, ident uint32) {
	target[0] = nextHeader
	target[1] = 0
	value := uint16(offset)
	if more {
		value |= 1
	}
	binary.BigEndian.PutUint16(target[2:], value)
	binary.BigEndian.PutUint32(target[4:], ident)
}
