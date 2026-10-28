package vless

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// Each adapter returns its own concrete TLS Conn. Never reinterpret one TLS
// fork as another or carry a Go pointer across a call as uintptr.
var tlsRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, owner any)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, owner any) {
		tlsConn, loaded := N.CastReader[*tls.Conn](conn)
		if !loaded {
			return
		}
		if tlsConn == nil {
			return true, nil, nil
		}
		return true, tlsConn.NetConn(), tlsConn
	})
}

// Vision drains these provider-owned buffers when TLS record framing switches
// to direct mode. Validate the exact pinned layout before creating interior
// pointers. Value.UnsafePointer and unsafe.Add keep the allocation visible to
// the GC; the owner is also retained by VisionConn for its full lifetime.
func visionTLSBuffers(owner any) (*bytes.Reader, *bytes.Buffer, error) {
	value := reflect.ValueOf(owner)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() || value.Type().Elem().Kind() != reflect.Struct {
		return nil, nil, E.New("vision: invalid TLS buffer owner")
	}
	typ := value.Type().Elem()
	field := func(name string, expected reflect.Type) (uintptr, error) {
		member, ok := typ.FieldByName(name)
		if !ok || len(member.Index) != 1 || member.Type != expected || member.Type.Size() > typ.Size() ||
			member.Offset > typ.Size()-member.Type.Size() || member.Offset%uintptr(member.Type.Align()) != 0 {
			return 0, E.New("vision: unsupported TLS buffer layout: ", typ, ".", name)
		}
		return member.Offset, nil
	}
	inputOffset, err := field("input", reflect.TypeOf(bytes.Reader{}))
	if err != nil {
		return nil, nil, err
	}
	rawInputOffset, err := field("rawInput", reflect.TypeOf(bytes.Buffer{}))
	if err != nil {
		return nil, nil, err
	}
	base := value.UnsafePointer()
	return (*bytes.Reader)(unsafe.Add(base, inputOffset)), (*bytes.Buffer)(unsafe.Add(base, rawInputOffset)), nil
}

const xrayChunkSize = 8192

type VisionConn struct {
	net.Conn
	reader      *bufio.ChunkReader
	writer      N.VectorisedWriter
	writeAccess sync.Mutex
	tlsAccess   sync.Mutex
	input       *bytes.Reader
	rawInput    *bytes.Buffer
	tlsOwner    any
	netConn     net.Conn
	logger      logger.Logger

	userUUID               [16]byte
	isTLS                  bool
	numberOfPacketToFilter int
	isTLS12orAbove         bool
	remainingServerHello   int32
	cipher                 uint16
	enableXTLS             bool
	isPadding              bool
	directWrite            bool
	writeUUID              bool
	withinPaddingBuffers   bool
	remainingContent       int
	remainingPadding       int
	currentCommand         byte
	paddingHeader          [5]byte
	paddingHeaderLen       int
	directRead             bool
	remainingBuffers       []*buf.Buffer
}

func NewVisionConn(conn net.Conn, tlsConn net.Conn, userUUID [16]byte, logger logger.Logger) (*VisionConn, error) {
	var (
		loaded  bool
		owner   any
		netConn net.Conn
	)
	for _, tlsCreator := range tlsRegistry {
		loaded, netConn, owner = tlsCreator(tlsConn)
		if loaded {
			break
		}
	}
	if !loaded {
		return nil, E.New("vision: not a valid supported TLS connection: ", reflect.TypeOf(tlsConn))
	}
	input, rawInput, err := visionTLSBuffers(owner)
	if err != nil {
		return nil, err
	}
	if netConn == nil {
		return nil, E.New("vision: missing TLS transport")
	}
	return &VisionConn{
		Conn:     conn,
		reader:   bufio.NewChunkReader(conn, xrayChunkSize),
		writer:   bufio.NewVectorisedWriter(conn),
		input:    input,
		rawInput: rawInput,
		tlsOwner: owner,
		netConn:  netConn,
		logger:   logger,

		userUUID:               userUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		isPadding:              true,
		writeUUID:              true,
		withinPaddingBuffers:   true,
		remainingContent:       -1,
		remainingPadding:       -1,
	}, nil
}

func (c *VisionConn) Read(p []byte) (n int, err error) {
	for {
		n = 0
		for len(c.remainingBuffers) > 0 {
			newN, _ := c.remainingBuffers[0].Read(p[n:])
			if c.remainingBuffers[0].IsEmpty() {
				c.remainingBuffers[0].Release()
				c.remainingBuffers = c.remainingBuffers[1:]
			}
			n += newN
			if n == len(p) {
				break
			}
		}
		if n > 0 {
			return
		}
		if c.directRead {
			return c.netConn.Read(p)
		}
		var bufferBytes []byte
		var chunkBuffer *buf.Buffer
		if len(p) > xrayChunkSize {
			n, err = c.Conn.Read(p)
			if err != nil {
				return
			}
			bufferBytes = p[:n]
		} else {
			chunkBuffer, err = c.reader.ReadChunk()
			if err != nil {
				return 0, err
			}
			bufferBytes = chunkBuffer.Bytes()
		}
		if c.withinPaddingBuffers || c.needsTLSFilter() {
			buffers := c.unPadding(bufferBytes)
			if chunkBuffer != nil {
				chunkBuffer.Reset()
			}
			if c.remainingContent == 0 && c.remainingPadding == 0 {
				if c.currentCommand == commandPaddingEnd {
					c.withinPaddingBuffers = false
					c.remainingContent = -1
					c.remainingPadding = -1
				} else if c.currentCommand == commandPaddingDirect {
					c.withinPaddingBuffers = false
					c.directRead = true

					inputBuffer, err := io.ReadAll(c.input)
					if err != nil {
						return 0, err
					}
					buffers = append(buffers, buf.As(inputBuffer))

					rawInputBuffer, err := io.ReadAll(c.rawInput)
					if err != nil {
						return 0, err
					}

					buffers = append(buffers, buf.As(rawInputBuffer))

					c.logger.Trace("XtlsRead readV")
				} else if c.currentCommand == commandPaddingContinue {
					c.withinPaddingBuffers = true
				} else {
					return 0, E.New("unknown command ", c.currentCommand)
				}
			} else if c.remainingContent > 0 || c.remainingPadding > 0 {
				c.withinPaddingBuffers = true
			} else {
				c.withinPaddingBuffers = false
			}
			c.filterTLS(buf.ToSliceMulti(buffers))
			c.remainingBuffers = buffers
			continue
		} else {
			c.filterTLS([][]byte{bufferBytes})
			if chunkBuffer != nil {
				c.remainingBuffers = append(c.remainingBuffers, buf.As(chunkBuffer.Bytes()))
				chunkBuffer.Reset() // chunkBuffer should not be release and only reused after c.remainingBuffers be emptied, so must reset at here
				continue
			}
			return
		}
	}
}

func (c *VisionConn) Write(p []byte) (n int, err error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	state := c.filterTLS([][]byte{p})
	if c.isPadding {
		inputLen := len(p)
		buffers := reshapeBuffer(p)
		var specIndex int
		for i, buffer := range buffers {
			if state.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
				var command byte = commandPaddingEnd
				if state.enableXTLS {
					c.directWrite = true
					specIndex = i
					command = commandPaddingDirect
				}
				c.isPadding = false
				buffers[i] = c.padding(buffer, command, state.isTLS)
				break
			} else if !state.isTLS12orAbove && state.numberOfPacketToFilter <= 1 {
				c.isPadding = false
				buffers[i] = c.padding(buffer, commandPaddingEnd, state.isTLS)
				break
			}
			buffers[i] = c.padding(buffer, commandPaddingContinue, state.isTLS)
		}
		if c.directWrite {
			encryptedBuffer := buffers[:specIndex+1]
			err = c.writer.WriteVectorised(encryptedBuffer)
			if err != nil {
				return
			}
			buffers = buffers[specIndex+1:]
			c.writer = bufio.NewVectorisedWriter(c.netConn)
			if len(buffers) > 0 {
				c.logger.Trace("XtlsWrite writeV ", specIndex, " ", buf.LenMulti(encryptedBuffer), " ", len(buffers))
				time.Sleep(5 * time.Millisecond) // wtf
			}
		}
		if len(buffers) > 0 {
			err = c.writer.WriteVectorised(buffers)
		}
		if err == nil {
			n = inputLen
		}
		return
	}
	if c.directWrite {
		return c.netConn.Write(p)
	} else {
		return c.Conn.Write(p)
	}
}

type visionTLSDetection struct {
	isTLS, isTLS12orAbove, enableXTLS bool
	numberOfPacketToFilter            int
}

func (c *VisionConn) needsTLSFilter() bool {
	c.tlsAccess.Lock()
	defer c.tlsAccess.Unlock()
	return c.numberOfPacketToFilter > 0
}

// Read and Write may inspect packets concurrently. Serialize only detection
// state and give the writer an immutable decision snapshot; never hold this
// lock across provider, protocol or direct network I/O.
func (c *VisionConn) filterTLS(buffers [][]byte) (state visionTLSDetection) {
	c.tlsAccess.Lock()
	defer func() {
		state = visionTLSDetection{c.isTLS, c.isTLS12orAbove, c.enableXTLS, c.numberOfPacketToFilter}
		c.tlsAccess.Unlock()
	}()
	if c.numberOfPacketToFilter <= 0 {
		return
	}
	for _, buffer := range buffers {
		c.numberOfPacketToFilter--
		if len(buffer) > 6 {
			if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
				c.isTLS = true
				if buffer[5] == 2 {
					c.isTLS12orAbove = true
					c.remainingServerHello = (int32(buffer[3])<<8 | int32(buffer[4])) + 5
					if len(buffer) >= 79 && c.remainingServerHello >= 79 {
						sessionIdLen := int(buffer[43])
						if len(buffer) >= 43+sessionIdLen+3 {
							cipherSuite := buffer[43+sessionIdLen+1 : 43+sessionIdLen+3]
							c.cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
						}
					} else {
						c.logger.Trace("XtlsFilterTls short server hello, tls 1.2 or older? ", len(buffer), " ", c.remainingServerHello)
					}
				}
			} else if bytes.Equal(tlsClientHandShakeStart, buffer[:2]) && buffer[5] == 1 {
				c.isTLS = true
				c.logger.Trace("XtlsFilterTls found tls client hello! ", len(buffer))
			}
		}
		if c.remainingServerHello > 0 {
			end := int(c.remainingServerHello)
			if end > len(buffer) {
				end = len(buffer)
			}
			c.remainingServerHello -= int32(end)
			if bytes.Contains(buffer[:end], tls13SupportedVersions) {
				cipher, ok := tls13CipherSuiteDic[c.cipher]
				if ok && cipher != "TLS_AES_128_CCM_8_SHA256" {
					c.enableXTLS = true
				}
				c.logger.Trace("XtlsFilterTls found tls 1.3! ", len(buffer), " ", c.cipher, " ", c.enableXTLS)
				c.numberOfPacketToFilter = 0
				return
			} else if c.remainingServerHello == 0 {
				c.logger.Trace("XtlsFilterTls found tls 1.2! ", len(buffer))
				c.numberOfPacketToFilter = 0
				return
			}
		}
		if c.numberOfPacketToFilter == 0 {
			c.logger.Trace("XtlsFilterTls stop filtering ", len(buffer))
		}
	}
	return
}

func (c *VisionConn) padding(buffer *buf.Buffer, command byte, isTLS bool) *buf.Buffer {
	contentLen := 0
	paddingLen := 0
	if buffer != nil {
		contentLen = buffer.Len()
	}
	if contentLen < 900 && isTLS {
		l, _ := rand.Int(rand.Reader, big.NewInt(500))
		paddingLen = int(l.Int64()) + 900 - contentLen
	} else {
		l, _ := rand.Int(rand.Reader, big.NewInt(256))
		paddingLen = int(l.Int64())
	}
	var bufferLen int
	if c.writeUUID {
		bufferLen += 16
	}
	bufferLen += 5
	if buffer != nil {
		bufferLen += buffer.Len()
	}
	bufferLen += paddingLen
	newBuffer := buf.NewSize(bufferLen)
	if c.writeUUID {
		common.Must1(newBuffer.Write(c.userUUID[:]))
		c.writeUUID = false
	}
	common.Must1(newBuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)}))
	if buffer != nil {
		common.Must1(newBuffer.Write(buffer.Bytes()))
		buffer.Release()
	}
	newBuffer.Extend(paddingLen)
	c.logger.Trace("XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newBuffer
}

func (c *VisionConn) unPadding(buffer []byte) []*buf.Buffer {
	var bufferIndex int
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		if len(buffer) >= 21 && bytes.Equal(c.userUUID[:], buffer[:16]) {
			bufferIndex = 16
			c.remainingContent = 0
			c.remainingPadding = 0
			c.currentCommand = 0
		}
	}
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		return []*buf.Buffer{buf.As(buffer).ToOwned()}
	}
	var buffers []*buf.Buffer
	for bufferIndex < len(buffer) {
		if c.remainingContent <= 0 && c.remainingPadding <= 0 {
			if c.currentCommand == 1 {
				buffers = append(buffers, buf.As(buffer[bufferIndex:]).ToOwned())
				break
			} else {
				headerLen := copy(c.paddingHeader[c.paddingHeaderLen:], buffer[bufferIndex:])
				c.paddingHeaderLen += headerLen
				bufferIndex += headerLen
				if c.paddingHeaderLen < len(c.paddingHeader) {
					break
				}
				c.paddingHeaderLen = 0
				c.currentCommand = c.paddingHeader[0]
				c.remainingContent = int(c.paddingHeader[1])<<8 | int(c.paddingHeader[2])
				c.remainingPadding = int(c.paddingHeader[3])<<8 | int(c.paddingHeader[4])
				c.logger.Trace("Xtls Unpadding new block ", bufferIndex, " ", c.remainingContent, " padding ", c.remainingPadding, " ", c.currentCommand)
			}
		} else if c.remainingContent > 0 {
			end := c.remainingContent
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			buffers = append(buffers, buf.As(buffer[bufferIndex:bufferIndex+end]).ToOwned())
			c.remainingContent -= end
			bufferIndex += end
		} else {
			end := c.remainingPadding
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			c.remainingPadding -= end
			bufferIndex += end
		}
		if bufferIndex == len(buffer) {
			break
		}
	}
	return buffers
}

func (c *VisionConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *VisionConn) Upstream() any {
	return c.Conn
}
