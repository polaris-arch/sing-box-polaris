package vless

import (
	"bytes"
	"crypto/tls"
	"net"
	"runtime"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

type visionBufferFixture struct {
	before   uint64
	input    bytes.Reader
	rawInput bytes.Buffer
	after    uint64
}

func TestVisionTLSBufferLayoutAndGCLifetime(t *testing.T) {
	owner := &visionBufferFixture{before: 17, after: 29}
	input, raw, err := visionTLSBuffers(owner)
	if err != nil {
		t.Fatal(err)
	}
	if input != &owner.input || raw != &owner.rawInput {
		t.Fatal("wrong provider buffer address")
	}
	for i := 0; i < 8; i++ {
		runtime.GC()
		input.Reset([]byte("input"))
		raw.Reset()
		_, _ = raw.WriteString("raw")
		if owner.input.Len() != 5 || owner.rawInput.String() != "raw" || owner.before != 17 || owner.after != 29 {
			t.Fatal("provider allocation changed")
		}
	}
}

func TestVisionTLSBufferLayoutRejectsUnknownShapes(t *testing.T) {
	type promoted struct{ visionBufferFixture }
	for name, owner := range map[string]any{
		"nil": nil, "typed-nil": (*visionBufferFixture)(nil), "value": visionBufferFixture{},
		"scalar": new(int), "missing": &struct{}{}, "promoted": &promoted{},
		"input-type": &struct {
			input    bytes.Buffer
			rawInput bytes.Buffer
		}{},
		"raw-type": &struct {
			input    bytes.Reader
			rawInput bytes.Reader
		}{},
		"pointer-field": &struct {
			input    *bytes.Reader
			rawInput bytes.Buffer
		}{},
	} {
		t.Run(name, func(t *testing.T) {
			if input, raw, err := visionTLSBuffers(owner); err == nil || input != nil || raw != nil {
				t.Fatal("invalid layout admitted")
			}
		})
	}
}

func TestVisionTLSProviderUnknownAndNilRejected(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for _, conn := range []net.Conn{a, nil, (*tls.Conn)(nil)} {
		if result, err := NewVisionConn(a, conn, [16]byte{}, logger.NOP()); err == nil || result != nil {
			t.Fatal("unsupported provider admitted")
		}
	}
}
