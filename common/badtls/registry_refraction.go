//go:build go1.27 && badlinkname && with_utls

package badtls

import (
	"net"
	"unsafe"

	N "github.com/sagernet/sing/common/network"

	"github.com/refraction-networking/utls"
)

func init() {
	methodRegistry = append(methodRegistry, func(conn net.Conn) (unsafe.Pointer, *Methods, bool) {
		var pointer unsafe.Pointer
		if uConn, loaded := N.CastReader[*tls.Conn](conn); loaded {
			pointer = unsafe.Pointer(uConn)
		} else if uConn, loaded := N.CastReader[*tls.UConn](conn); loaded {
			pointer = unsafe.Pointer(uConn.Conn)
		} else {
			return nil, nil, false
		}
		return pointer, &Methods{
			readRecord:                 upstreamReadRecord,
			handlePostHandshakeMessage: upstreamHandlePostHandshakeMessage,
			writeRecordLocked: func(c unsafe.Pointer, typ uint16, data []byte) (int, error) {
				return upstreamWriteRecordLocked(c, uint8(typ), data)
			},

			setErrorLocked:       upstreamSetErrorLocked,
			decrypt:              upstreamDecrypt,
			setTrafficSecret:     upstreamSetTrafficSecret,
			explicitNonceLen:     upstreamExplicitNonceLen,
			cipherSuiteTLS13ByID: upstreamCipherSuiteTLS13ByID, nextTrafficSecret: upstreamNextTrafficSecret, trafficKey: upstreamTrafficKey,
		}, true
	})
}

//go:linkname upstreamReadRecord github.com/refraction-networking/utls.(*Conn).readRecord
func upstreamReadRecord(c unsafe.Pointer) error

//go:linkname upstreamHandlePostHandshakeMessage github.com/refraction-networking/utls.(*Conn).handlePostHandshakeMessage
func upstreamHandlePostHandshakeMessage(c unsafe.Pointer) error

//go:linkname upstreamWriteRecordLocked github.com/refraction-networking/utls.(*Conn).writeRecordLocked
func upstreamWriteRecordLocked(hc unsafe.Pointer, typ uint8, data []byte) (int, error)

//go:linkname upstreamSetErrorLocked github.com/refraction-networking/utls.(*halfConn).setErrorLocked
func upstreamSetErrorLocked(hc unsafe.Pointer, err error) error

//go:linkname upstreamDecrypt github.com/refraction-networking/utls.(*halfConn).decrypt
func upstreamDecrypt(hc unsafe.Pointer, record []byte) ([]byte, uint8, error)

//go:linkname upstreamSetTrafficSecret github.com/refraction-networking/utls.(*halfConn).setTrafficSecret
func upstreamSetTrafficSecret(hc unsafe.Pointer, suite unsafe.Pointer, level int, secret []byte)

//go:linkname upstreamExplicitNonceLen github.com/refraction-networking/utls.(*halfConn).explicitNonceLen
func upstreamExplicitNonceLen(hc unsafe.Pointer) int

//go:linkname upstreamCipherSuiteTLS13ByID github.com/refraction-networking/utls.cipherSuiteTLS13ByID
func upstreamCipherSuiteTLS13ByID(id uint16) unsafe.Pointer

//go:linkname upstreamNextTrafficSecret github.com/refraction-networking/utls.(*cipherSuiteTLS13).nextTrafficSecret
func upstreamNextTrafficSecret(suite unsafe.Pointer, secret []byte) []byte

//go:linkname upstreamTrafficKey github.com/refraction-networking/utls.(*cipherSuiteTLS13).trafficKey
func upstreamTrafficKey(suite unsafe.Pointer, secret []byte) (key, iv []byte)
