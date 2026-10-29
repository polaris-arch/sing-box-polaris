//go:build with_tailscale

package tailscale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

type taildropResumeTransport func(*http.Request) (*http.Response, error)

func (f taildropResumeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func resumeResponse(data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}
}

// Use the actual retained-partial producer, then the actual sender's checksum
// reader. No live Tailscale peer, socket or duplicate checksum algorithm.
func TestTaildropResumeRetainedPartialBoundariesPreserveExactRemainingBytes(t *testing.T) {
	payload := make([]byte, 5*taildropBlockSize+19)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	for _, prefix := range []int{0, 1, 65535, 65536, 65537, 3*65536 + 17} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			manager := lifecycleManager(t)
			manager.logger = log.NewNOPFactory().Logger()
			defer manager.close()
			partial := filepath.Join(manager.directory, "same.bin.peer"+taildropPartialSuffix)
			if err := os.WriteFile(partial, payload[:prefix], 0o600); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			manager.writePartialChecksums(response, "peer", "same.bin")
			client := &http.Client{Transport: taildropResumeTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/v0/put/same.bin" {
					t.Fatal("resume probe changed", r.Method, r.URL)
				}
				return resumeResponse(response.Body.Bytes()), nil
			})}
			offset, reader := taildropResume(context.Background(), client, "http://owned.invalid/v0/put/same.bin", bytes.NewReader(payload))
			if offset != int64(prefix) {
				t.Fatal("wrong verified offset", offset, prefix)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if len(remaining) != len(payload)-prefix || !bytes.Equal(remaining, payload[prefix:]) {
				t.Fatal("remaining body changed")
			}
			restored := append(append([]byte{}, payload[:offset]...), remaining...)
			if sha256.Sum256(restored) != sha256.Sum256(payload) {
				t.Fatal("resumed full SHA differs")
			}
			retained, err := os.ReadFile(partial)
			if err != nil || !bytes.Equal(retained, payload[:prefix]) {
				t.Fatal("outgoing probe modified receiver partial", err)
			}
			// Feed the actual verified offset and remaining body into the real
			// receiver, including its length check and partial-to-final rename.
			if err = manager.putFile("peer", "fixture-peer", "same.bin", bytes.NewReader(remaining), offset, int64(len(remaining)), nil); err != nil {
				t.Fatal(err)
			}
			final, err := os.ReadFile(filepath.Join(manager.directory, "same.bin"))
			if err != nil || !bytes.Equal(final, payload) || sha256.Sum256(final) != sha256.Sum256(payload) {
				t.Fatal("receiver final bytes/SHA differ", err)
			}
		})
	}
}

func TestTaildropResumeBadChecksumsAndProbeErrorsPreserveUnverifiedBytes(t *testing.T) {
	payload := bytes.Repeat([]byte("source-data"), 20000)
	first := sha256.Sum256(payload[:taildropBlockSize])
	valid := taildropBlockChecksum{Algorithm: "sha256", Size: taildropBlockSize, Checksum: hex.EncodeToString(first[:])}
	encode := func(rows ...taildropBlockChecksum) []byte {
		var b bytes.Buffer
		for _, r := range rows {
			if e := json.NewEncoder(&b).Encode(r); e != nil {
				t.Fatal(e)
			}
		}
		return b.Bytes()
	}
	for _, test := range []struct {
		name    string
		body    []byte
		status  int
		failure error
		offset  int64
	}{
		{name: "empty", status: 200},
		{name: "get-error", failure: errors.New("owned GET failure")},
		{name: "bad-status", status: 500},
		{name: "malformed", status: 200, body: []byte("{")},
		{name: "algorithm", status: 200, body: encode(taildropBlockChecksum{Algorithm: "sha1", Size: 1})},
		{name: "zero-size", status: 200, body: encode(taildropBlockChecksum{Algorithm: "sha256", Size: 0})},
		{name: "negative-size", status: 200, body: encode(taildropBlockChecksum{Algorithm: "sha256", Size: -1})},
		{name: "oversize", status: 200, body: encode(taildropBlockChecksum{Algorithm: "sha256", Size: taildropBlockSize + 1})},
		{name: "first-mismatch", status: 200, body: encode(taildropBlockChecksum{Algorithm: "sha256", Size: 7, Checksum: "wrong"})},
		{name: "later-mismatch", status: 200, body: encode(valid, taildropBlockChecksum{Algorithm: "sha256", Size: 37, Checksum: "wrong"}), offset: taildropBlockSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: taildropResumeTransport(func(*http.Request) (*http.Response, error) {
				if test.failure != nil {
					return nil, test.failure
				}
				r := resumeResponse(test.body)
				r.StatusCode = test.status
				return r, nil
			})}
			offset, reader := taildropResume(context.Background(), client, "http://owned.invalid/v0/put/file", bytes.NewReader(payload))
			if offset != test.offset {
				t.Fatal("unverified offset admitted", offset)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(remaining, payload[offset:]) {
				t.Fatal("fallback lost consumed bytes", err)
			}
		})
	}
}

type cancelResumeSource struct {
	ctx     context.Context
	entered chan struct{}
}

func (s *cancelResumeSource) Read([]byte) (int, error) {
	close(s.entered)
	<-s.ctx.Done()
	return 0, s.ctx.Err()
}
func TestTaildropResumeCancellationJoinsTheActualLocalPrefixRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancelResumeSource{ctx: ctx, entered: make(chan struct{})}
	var wire bytes.Buffer
	if err := json.NewEncoder(&wire).Encode(taildropBlockChecksum{Algorithm: "sha256", Size: 1, Checksum: "unused"}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: taildropResumeTransport(func(*http.Request) (*http.Response, error) { return resumeResponse(wire.Bytes()), nil })}
	done := make(chan int64, 1)
	terminal := make(chan struct{})
	go func() {
		defer close(terminal)
		offset, _ := taildropResume(ctx, client, "http://owned.invalid/v0/put/file", source)
		done <- offset
	}()
	defer func() { cancel(); awaitTaildropDrain(t, terminal) }()
	awaitTaildropDrain(t, source.entered)
	cancel()
	select {
	case offset := <-done:
		if offset != 0 {
			t.Fatal("cancel forged resume", offset)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled prefix read did not join")
	}
}

func TestTaildropResumeProbeCancellationDoesNotReadOrDeleteSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	payload := []byte("retained-source")
	client := &http.Client{Transport: taildropResumeTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}
	offset, reader := taildropResume(ctx, client, "http://owned.invalid/v0/put/file", bytes.NewReader(payload))
	remaining, err := io.ReadAll(reader)
	if offset != 0 || err != nil || !bytes.Equal(remaining, payload) {
		t.Fatal("probe cancellation changed source", offset, err)
	}
}

type taildropInterruptedBody struct {
	prefix  []byte
	ctx     context.Context
	blocked chan struct{}
}

func (r *taildropInterruptedBody) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	close(r.blocked)
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}
func TestTaildropOutgoingInterruptionRetainsPartialButReceiverCancelRemovesIt(t *testing.T) {
	for _, receiverCancel := range []bool{false, true} {
		t.Run(fmt.Sprint(receiverCancel), func(t *testing.T) {
			manager := lifecycleManager(t)
			manager.logger = log.NewNOPFactory().Logger()
			ctx, cancel := context.WithCancel(context.Background())
			defer manager.close()
			defer cancel()
			prefix := bytes.Repeat([]byte("retained-prefix"), 100)
			body := &taildropInterruptedBody{prefix: prefix, ctx: ctx, blocked: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				done <- manager.putFile("peer", "fixture-peer", "same.bin", body, 0, int64(len(prefix)+65537), cancel)
			}()
			awaitTaildropDrain(t, body.blocked)
			if receiverCancel {
				manager.cancelReceiving("peer", "same.bin")
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if receiverCancel {
					if !errors.Is(err, errTaildropCanceled) {
						t.Fatal(err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("receiver IO did not join canceled source")
			}
			partial, err := os.ReadFile(filepath.Join(manager.directory, "same.bin.peer"+taildropPartialSuffix))
			if receiverCancel {
				if !os.IsNotExist(err) {
					t.Fatal("explicit receiver cancel retained partial", err)
				}
			} else if err != nil || !bytes.Equal(partial, prefix) {
				t.Fatal("outgoing interruption lost retained bytes", err)
			}
			if _, err = os.Stat(filepath.Join(manager.directory, "same.bin")); !os.IsNotExist(err) {
				t.Fatal("interruption fabricated final file", err)
			}
		})
	}
}
