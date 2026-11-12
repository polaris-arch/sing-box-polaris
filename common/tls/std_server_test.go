package tls

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestSTDServerReloadsCertificateFiles(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		certificatePath  string
		keyPath          string
		writeCertificate func(t *testing.T, certificate, key []byte)
	}{
		{
			name:            "relative",
			certificatePath: "./certs/cert.pem",
			keyPath:         "./certs/key.pem",
			writeCertificate: func(t *testing.T, certificate, key []byte) {
				writeTestFile(t, "certs/cert.pem", certificate)
				writeTestFile(t, "certs/key.pem", key)
			},
		},
		{
			name:            "nested",
			certificatePath: "cert.pem",
			keyPath:         "private/key.pem",
			writeCertificate: func(t *testing.T, certificate, key []byte) {
				writeTestFile(t, "cert.pem", certificate)
				writeTestFile(t, "private/key.pem", key)
			},
		},
		{
			name:            "combined",
			certificatePath: "combined.pem",
			keyPath:         "combined.pem",
			writeCertificate: func(t *testing.T, certificate, key []byte) {
				writeTestFile(t, "combined.pem", append(certificate, key...))
			},
		},
		{
			// Kubernetes secret volumes swap a ..data symlink, never touching the file names.
			name:            "kubernetes",
			certificatePath: "cert.pem",
			keyPath:         "key.pem",
			writeCertificate: func(t *testing.T, certificate, key []byte) {
				if runtime.GOOS != "linux" {
					t.Skip("symlink swap detection is supported on Linux only")
				}
				directory, err := os.MkdirTemp(".", "..data_")
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(directory, "cert.pem"), certificate)
				writeTestFile(t, filepath.Join(directory, "key.pem"), key)
				if err = os.Symlink(directory, "..data_tmp"); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename("..data_tmp", "..data"); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"cert.pem", "key.pem"} {
					if err = os.Symlink(filepath.Join("..data", name), name); err != nil && !os.IsExist(err) {
						t.Fatal(err)
					}
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			key, certificate, err := GenerateCertificate(nil, nil, time.Now, "old.example", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			testCase.writeCertificate(t, certificate, key)
			config, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: testCase.certificatePath,
				KeyPath:         testCase.keyPath,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = config.Start(); err != nil {
				t.Fatal(err)
			}
			defer config.Close()
			// QUIC listeners keep the config taken at start; handshakes resolve the current one through it.
			snapshot, err := config.STDConfig()
			if err != nil {
				t.Fatal(err)
			}
			key, certificate, err = GenerateCertificate(nil, nil, time.Now, "new.example", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			testCase.writeCertificate(t, certificate, key)
			block, _ := pem.Decode(certificate)
			deadline := time.Now().Add(5 * time.Second)
			for {
				current, err := snapshot.GetConfigForClient(nil)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(current.Certificates[0].Certificate[0], block.Bytes) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("certificate not reloaded")
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func writeTestFile(t *testing.T, name string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
