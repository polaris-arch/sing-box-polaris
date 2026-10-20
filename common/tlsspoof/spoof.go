package tlsspoof

import (
	"net"

	"github.com/sagernet/sing-box/common/tlsspoof/method"

	E "github.com/sagernet/sing/common/exceptions"
)

type Method = method.Method

const (
	MethodWrongSequence = method.MethodWrongSequence
	MethodWrongChecksum = method.MethodWrongChecksum
	MethodWrongAcknowledgment = method.MethodWrongAcknowledgment
	MethodWrongMD5Sig = method.MethodWrongMD5Sig
	MethodWrongTimestamp = method.MethodWrongTimestamp
	MethodNameWrongSequence = method.MethodNameWrongSequence
	MethodNameWrongChecksum = method.MethodNameWrongChecksum
	MethodNameWrongAcknowledgment = method.MethodNameWrongAcknowledgment
	MethodNameWrongMD5Sig = method.MethodNameWrongMD5Sig
	MethodNameWrongTimestamp = method.MethodNameWrongTimestamp
)

func ParseOptions(spoof, method string) (string, Method, error) {
	if spoof == "" {
		if method != "" {
			return "", 0, E.New("spoof_method requires spoof")
		}
		return "", 0, nil
	}
	if !PlatformSupported {
		return "", 0, E.New("tls_spoof is not supported on this platform")
	}
	parsedMethod, err := ParseMethod(method)
	if err != nil {
		return "", 0, err
	}
	return spoof, parsedMethod, nil
}

func ParseMethod(s string) (Method, error) {
	switch s {
	case "", MethodNameWrongSequence:
		return MethodWrongSequence, nil
	case MethodNameWrongChecksum:
		return MethodWrongChecksum, nil
	case MethodNameWrongAcknowledgment:
		return MethodWrongAcknowledgment, nil
	case MethodNameWrongMD5Sig:
		return MethodWrongMD5Sig, nil
	case MethodNameWrongTimestamp:
		return MethodWrongTimestamp, nil
	default:
		return 0, E.New("tls_spoof: unknown method: ", s)
	}
}

type rawSpoofer interface {
	Inject(payload []byte) error
	Close() error
}

type Conn struct {
	net.Conn
	spoofer   rawSpoofer
	fakeHello []byte
	injected  bool
}

func NewConn(conn net.Conn, method Method, fakeSNI string) (*Conn, error) {
	spoofer, err := newRawSpoofer(conn, method)
	if err != nil {
		return nil, err
	}
	result, err := newConn(conn, spoofer, fakeSNI)
	if err != nil {
		spoofer.Close()
		return nil, err
	}
	return result, nil
}

func newConn(conn net.Conn, spoofer rawSpoofer, fakeSNI string) (*Conn, error) {
	fakeHello, err := buildFakeClientHello(fakeSNI)
	if err != nil {
		return nil, E.Cause(err, "tls_spoof: build fake ClientHello")
	}
	return &Conn{
		Conn:      conn,
		spoofer:   spoofer,
		fakeHello: fakeHello,
	}, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.injected {
		return c.Conn.Write(b)
	}
	defer func() {
		closeErr := c.spoofer.Close()
		if err == nil && closeErr != nil {
			err = E.Cause(closeErr, "tls_spoof: close spoofer")
		}
	}()
	err = c.spoofer.Inject(c.fakeHello)
	if err != nil {
		return 0, E.Cause(err, "tls_spoof: inject")
	}
	c.injected = true
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	return E.Append(c.Conn.Close(), c.spoofer.Close(), func(e error) error {
		return E.Cause(e, "tls_spoof: close spoofer")
	})
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.injected
}

func (c *Conn) Upstream() any {
	return c.Conn
}
