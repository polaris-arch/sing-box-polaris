//go:build with_quic

package httpclient

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
)

// QUIC's early setup error path cancels its public context without running the
// normal crypto/send teardown. Guard the actual graph-facing provider methods
// independently: context cancellation is never used as their completion proof.
// Nil fields stay nil, preserving ChromeParrot's explicit capability checks.
//
// This is exclusively a client-side guard for DialRuntimeQUIC. Both the pinned
// standard QUIC client and ChromeParrot ignore the server-only named-certificate
// map. Do not reuse this guard for server handshakes: those require a separate
// fence for legacy named-certificate selection and its private-key providers.
func guardRuntimeQUICTLS(original *tls.Config, fence *outbound.RuntimeIOFence) *tls.Config {
	config := original.Clone()
	if value := config.Rand; value != nil {
		config.Rand = runtimeQUICReader{value, fence}
	}
	if value := config.Time; value != nil {
		config.Time = func() time.Time {
			leave, err := fence.Acquire()
			if err != nil {
				return time.Time{}
			}
			defer leave()
			return value()
		}
	}
	if value := config.KeyLogWriter; value != nil {
		config.KeyLogWriter = runtimeQUICWriter{value, fence}
	}
	if value := config.VerifyPeerCertificate; value != nil {
		config.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			leave, err := fence.Acquire()
			if err != nil {
				return err
			}
			defer leave()
			return value(raw, chains)
		}
	}
	if value := config.VerifyConnection; value != nil {
		config.VerifyConnection = func(state tls.ConnectionState) error {
			leave, err := fence.Acquire()
			if err != nil {
				return err
			}
			defer leave()
			return value(state)
		}
	}
	if value := config.EncryptedClientHelloRejectionVerify; value != nil {
		config.EncryptedClientHelloRejectionVerify = func(state tls.ConnectionState) error {
			leave, err := fence.Acquire()
			if err != nil {
				return err
			}
			defer leave()
			return value(state)
		}
	}
	if value := config.GetClientCertificate; value != nil {
		config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			cert, err := value(info)
			return guardRuntimeQUICCertificate(cert, fence), err
		}
	}
	if value := config.GetCertificate; value != nil {
		config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			cert, err := value(info)
			return guardRuntimeQUICCertificate(cert, fence), err
		}
	}
	if value := config.GetConfigForClient; value != nil {
		config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			next, err := value(info)
			if next != nil {
				next = guardRuntimeQUICTLS(next, fence)
			}
			return next, err
		}
	}
	if value := config.GetEncryptedClientHelloKeys; value != nil {
		config.GetEncryptedClientHelloKeys = func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			return value(info)
		}
	}
	if value := config.WrapSession; value != nil {
		config.WrapSession = func(state tls.ConnectionState, session *tls.SessionState) ([]byte, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			return value(state, session)
		}
	}
	if value := config.UnwrapSession; value != nil {
		config.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
			leave, err := fence.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			return value(identity, state)
		}
	}
	if value := config.ClientSessionCache; value != nil {
		config.ClientSessionCache = runtimeQUICSessionCache{value, fence}
	}
	if config.Certificates != nil {
		certificates := make([]tls.Certificate, len(config.Certificates))
		for i := range certificates {
			certificates[i] = *guardRuntimeQUICCertificate(&config.Certificates[i], fence)
		}
		config.Certificates = certificates
	}
	return config
}

type runtimeQUICReader struct {
	reader io.Reader
	fence  *outbound.RuntimeIOFence
}

func (r runtimeQUICReader) Read(p []byte) (int, error) {
	leave, err := r.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	return r.reader.Read(p)
}

type runtimeQUICWriter struct {
	writer io.Writer
	fence  *outbound.RuntimeIOFence
}

func (w runtimeQUICWriter) Write(p []byte) (int, error) {
	leave, err := w.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	return w.writer.Write(p)
}

type runtimeQUICSessionCache struct {
	cache tls.ClientSessionCache
	fence *outbound.RuntimeIOFence
}

func (c runtimeQUICSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return nil, false
	}
	defer leave()
	return c.cache.Get(key)
}

func (c runtimeQUICSessionCache) Put(key string, state *tls.ClientSessionState) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	c.cache.Put(key, state)
}

// PrivateKey may be a hardware/provider signer rather than Go-owned key data.
// Cache its immutable public key while admitted, and fence every signing call.
func guardRuntimeQUICCertificate(original *tls.Certificate, fence *outbound.RuntimeIOFence) *tls.Certificate {
	if original == nil {
		return nil
	}
	copy := *original
	if key, ok := copy.PrivateKey.(crypto.Signer); ok {
		signer := runtimeQUICSigner{key: key, public: key.Public(), fence: fence}
		if decrypter, ok := copy.PrivateKey.(crypto.Decrypter); ok {
			copy.PrivateKey = runtimeQUICSignerDecrypter{runtimeQUICSigner: signer, decrypter: decrypter}
		} else {
			copy.PrivateKey = signer
		}
	}
	return &copy
}

type runtimeQUICSigner struct {
	key    crypto.Signer
	public crypto.PublicKey
	fence  *outbound.RuntimeIOFence
}

func (s runtimeQUICSigner) Public() crypto.PublicKey { return s.public }
func (s runtimeQUICSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.key.Sign(random, digest, options)
}

type runtimeQUICSignerDecrypter struct {
	runtimeQUICSigner
	decrypter crypto.Decrypter
}

func (s runtimeQUICSignerDecrypter) Decrypt(random io.Reader, message []byte, options crypto.DecrypterOpts) ([]byte, error) {
	leave, err := s.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.decrypter.Decrypt(random, message, options)
}
