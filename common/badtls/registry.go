//go:build go1.25 && badlinkname

package badtls

import (
	"crypto/tls"
	"net"
	"unsafe"
)

// cmd/compile creates the method symbols of *tls.Conn and of its field types with their
// package recorded when the type is first used by a declaration; a linkname pull processed
// afterwards reuses that symbol as a package-indexed reference, which the linker's
// -checklinkname does not inspect. This declaration must precede the linkname declarations.
var _ *tls.Conn

type Methods struct {
	readRecord                 func(c unsafe.Pointer) error
	handlePostHandshakeMessage func(c unsafe.Pointer) error
	writeRecordLocked          func(c unsafe.Pointer, typ uint16, data []byte) (int, error)

	setErrorLocked       func(hc unsafe.Pointer, err error) error
	decrypt              func(hc unsafe.Pointer, record []byte) ([]byte, uint8, error)
	setTrafficSecret     func(hc unsafe.Pointer, suite unsafe.Pointer, level int, secret []byte)
	explicitNonceLen     func(hc unsafe.Pointer) int
	cipherSuiteTLS13ByID func(id uint16) unsafe.Pointer
	nextTrafficSecret    func(suite unsafe.Pointer, secret []byte) []byte
	trafficKey           func(suite unsafe.Pointer, secret []byte) (key, iv []byte)
}

var methodRegistry []func(conn net.Conn) (unsafe.Pointer, *Methods, bool)

func init() {
	methodRegistry = append(methodRegistry, func(conn net.Conn) (unsafe.Pointer, *Methods, bool) {
		tlsConn, loaded := conn.(*tls.Conn)
		if !loaded {
			return nil, nil, false
		}
		return unsafe.Pointer(tlsConn), &Methods{
			readRecord:                 stdTLSReadRecord,
			handlePostHandshakeMessage: stdTLSHandlePostHandshakeMessage,
			writeRecordLocked: func(c unsafe.Pointer, typ uint16, data []byte) (int, error) {
				return stdWriteRecordLocked(c, uint8(typ), data)
			},

			setErrorLocked:       stdSetErrorLocked,
			decrypt:              stdDecrypt,
			setTrafficSecret:     stdSetTrafficSecret,
			explicitNonceLen:     stdExplicitNonceLen,
			cipherSuiteTLS13ByID: stdCipherSuiteTLS13ByID, nextTrafficSecret: stdNextTrafficSecret, trafficKey: stdTrafficKey,
		}, true
	})
}

//go:linkname stdTLSReadRecord crypto/tls.(*Conn).readRecord
func stdTLSReadRecord(c unsafe.Pointer) error

//go:linkname stdTLSHandlePostHandshakeMessage crypto/tls.(*Conn).handlePostHandshakeMessage
func stdTLSHandlePostHandshakeMessage(c unsafe.Pointer) error

//go:linkname stdWriteRecordLocked crypto/tls.(*Conn).writeRecordLocked
func stdWriteRecordLocked(c unsafe.Pointer, typ uint8, data []byte) (int, error)

//go:linkname stdSetErrorLocked crypto/tls.(*halfConn).setErrorLocked
func stdSetErrorLocked(hc unsafe.Pointer, err error) error

//go:linkname stdDecrypt crypto/tls.(*halfConn).decrypt
func stdDecrypt(hc unsafe.Pointer, record []byte) ([]byte, uint8, error)

//go:linkname stdSetTrafficSecret crypto/tls.(*halfConn).setTrafficSecret
func stdSetTrafficSecret(hc unsafe.Pointer, suite unsafe.Pointer, level int, secret []byte)

//go:linkname stdExplicitNonceLen crypto/tls.(*halfConn).explicitNonceLen
func stdExplicitNonceLen(hc unsafe.Pointer) int

//go:linkname stdCipherSuiteTLS13ByID crypto/tls.cipherSuiteTLS13ByID
func stdCipherSuiteTLS13ByID(id uint16) unsafe.Pointer

//go:linkname stdNextTrafficSecret crypto/tls.(*cipherSuiteTLS13).nextTrafficSecret
func stdNextTrafficSecret(suite unsafe.Pointer, secret []byte) []byte

//go:linkname stdTrafficKey crypto/tls.(*cipherSuiteTLS13).trafficKey
func stdTrafficKey(suite unsafe.Pointer, secret []byte) (key, iv []byte)
