package listener

import (
	"os"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (l *Listener) runtimeBatchSupported() bool {
	if l.runtime == nil { return true }
 if l.runtime.control!=nil{return false}
	_, ok := l.packetHandler.(RuntimePacketBatchHandler)
	return ok
}

// The mutex covers only admission to the queue, never buffer release or socket
// writes. Closing seals enqueue before joining/draining the sole output worker.
// A paused UDP receiver may still write replies to existing admitted sessions.
func (l *Listener) writeRuntimePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packet := N.NewPacketBuffer()
	packet.Buffer, packet.Destination = buffer, destination
	r := l.runtime
	r.mu.Lock()
	closed := l.shutdown.Load() || !r.outputStarted || l.disablePacketOutput
	queued := false
	if !closed { select { case l.packetOutbound <- packet: queued = true; default: } }
	r.mu.Unlock()
	if queued { return nil }
	buffer.Release(); N.PutPacketBuffer(packet)
	if closed { return os.ErrClosed }
	l.logger.Trace("dropped packet to ", destination)
	return nil
}
func (l *Listener) writeRuntimePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) { buf.ReleaseMulti(buffers); return os.ErrInvalid }
	for index, buffer := range buffers {
		if err := l.writeRuntimePacket(buffer, destinations[index]); err != nil { buf.ReleaseMulti(buffers[index+1:]); return err }
	}
	return nil
}
