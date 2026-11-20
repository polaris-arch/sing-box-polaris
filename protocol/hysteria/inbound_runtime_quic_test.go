//go:build with_quic

package hysteria

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func ingressTLSOptions(t *testing.T) *option.InboundTLSOptions {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 1024)), template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &option.InboundTLSOptions{Enabled: true, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}}
}

func TestRuntimeQUICConstructorAndPrepareRemainPrivate(t *testing.T) {
	f := newIngressFixture()
	ctx, scope := ingressConstruction(f)
	defer scope.Close()
	options := option.HysteriaInboundOptions{UpMbps: 10, DownMbps: 10, TLS: ingressTLSOptions(t)}
	member, err := NewInbound(ctx, nil, log.NewNOPFactory().Logger(), "in", options)
	if err != nil {
		t.Fatal(err)
	}
	prepared := member.(inbound.RuntimePreparedInbound)
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStateStart} {
		if err := prepared.PrepareRuntime(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range prepared.RuntimeListeners() {
		if l.RuntimeStatus().Phase != "inert" {
			t.Fatal("private preparation activated physical listener")
		}
	}
	if f.graphAcquires.Load() != 0 || f.sourceAcquires.Load() != 0 {
		t.Fatal("private preparation admitted a request")
	}
}
