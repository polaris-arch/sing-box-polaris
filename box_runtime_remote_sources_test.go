package box

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
)

type runtimeSourceTestTransport func(*http.Request) (*http.Response, error)

func (f runtimeSourceTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type runtimeSourceTestBody struct {
	io.Reader
	closed   *atomic.Bool
	closeErr error
}

func (b *runtimeSourceTestBody) Close() error { b.closed.Store(true); return b.closeErr }
func runtimeRemoteTestOptions() option.Options {
	return option.Options{Route: &option.RouteOptions{RuleSet: []option.RuleSet{{Type: C.RuleSetTypeRemote, Tag: []string{"sites"}, Format: C.RuleSetFormatSource, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.example/sites.json"}}}}}
}

func runtimeRemoteTestDigest(t *testing.T, options option.Options) string {
	t.Helper()
	encoded, err := json.MarshalContext(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeDigest(encoded)
}

func runtimeRemoteTestSession(digest string, transport http.RoundTripper, close func() error) *runtimeSourceDownloadSession {
	return &runtimeSourceDownloadSession{ctx: context.Background(), candidateDigest: digest, dependencyDigest: "http-owner:original", resolve: func(context.Context, option.RuleSet) (http.RoundTripper, error) { return transport, nil }, closeAndWait: close}
}

func TestRuntimeRemoteSourceClosesBodyBeforeReleasingOriginalOwner(t *testing.T) {
	for _, test := range []struct {
		name     string
		original []byte
		empty    bool
	}{
		{"nonempty", runtimeTestSourceBytes("first.example"), false},
		{"empty", []byte(`{"version":3,"rules":[]}`), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := runtimeRemoteTestOptions()
			digest := runtimeRemoteTestDigest(t, options)
			var closed atomic.Bool
			original := test.original
			transport := runtimeSourceTestTransport(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: bytes.NewReader(original), closed: &closed}}, nil
			})
			joined := false
			session := runtimeRemoteTestSession(digest, transport, func() error {
				if !closed.Load() {
					t.Error("owner released before original response body close")
				}
				joined = true
				return nil
			})
			batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, session)
			if err != nil {
				t.Fatal(err)
			}
			if !joined {
				t.Fatal("original owner not joined")
			}
			frozen, snapshots, _, failures := runtimeSnapshotSources(context.Background(), context.Background(), options, batch)
			if len(failures) != 0 {
				t.Fatal(failures)
			}
			if frozen.Route.RuleSet[0].Type != C.RuleSetTypeInline || len(snapshots) != 1 {
				t.Fatal("remote source not frozen")
			}
			if snapshots[0].digest != runtimeDigest(original) || !bytes.Equal(snapshots[0].content, original) {
				t.Fatal("frozen digest/bytes changed after original owner close")
			}
			set, err := R.NewRuleSet(context.Background(), logger.NOP(), "sites", frozen.Route.RuleSet[0])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := set.Close(); err != nil {
					t.Error(err)
				}
			})
			if set.Match(&adapter.InboundContext{Domain: "first.example"}) == test.empty {
				t.Fatal("empty/nonempty frozen source has wrong matching semantics")
			}
			if test.empty && set.Metadata() != (adapter.RuleSetMetadata{}) {
				t.Fatal("empty frozen source retained nonempty metadata")
			}
			for key, value := range batch {
				value.content[0] = '!'
				batch[key] = value
			}
			if snapshots[0].content[0] != '{' {
				t.Fatal("immutable plan bytes alias download batch")
			}
		})
	}
}

func TestRuntimeRemoteSourceBodyCloseFailureRejectsBatch(t *testing.T) {
	options := runtimeRemoteTestOptions()
	digest := runtimeRemoteTestDigest(t, options)
	var closed atomic.Bool
	transport := runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: bytes.NewReader(runtimeTestSourceBytes("first.example")), closed: &closed, closeErr: errors.New("uncertain close")}}, nil
	})
	batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, runtimeRemoteTestSession(digest, transport, func() error { return nil }))
	if err == nil || batch != nil || !closed.Load() {
		t.Fatal("uncertain body completion accepted")
	}
}

func TestRuntimeRemoteSourceDownloadFailureDoesNotMutatePrevious(t *testing.T) {
	options := runtimeRemoteTestOptions()
	digest := runtimeRemoteTestDigest(t, options)
	previous := map[string]runtimeSourceSnapshot{"old": {content: []byte("unchanged"), digest: "original"}}
	session := runtimeRemoteTestSession(digest, runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("network failed") }), func() error { return nil })
	session.previous = previous
	batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, session)
	if err == nil || batch != nil || string(previous["old"].content) != "unchanged" {
		t.Fatal("failed fetch changed previous graph source")
	}
}

func TestRuntimeRemoteSourceProvenanceRejectsDifferentCandidate(t *testing.T) {
	options := runtimeRemoteTestOptions()
	digest := runtimeRemoteTestDigest(t, options)
	var closed atomic.Bool
	transport := runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: bytes.NewReader(runtimeTestSourceBytes("first.example")), closed: &closed}}, nil
	})
	batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, runtimeRemoteTestSession(digest, transport, func() error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	options.Route.RuleSet[0].RemoteOptions.URL = "https://rules.example/replacement.json"
	_, _, _, failures := runtimeSnapshotSources(context.Background(), context.Background(), options, batch)
	if len(failures) == 0 {
		t.Fatal("different source options accepted old bytes")
	}
}

func TestRuntimeRemoteSourceScheduledReuseDoesNotRedownloadNonDueSource(t *testing.T) {
	options := runtimeRemoteTestOptions()
	digest := runtimeRemoteTestDigest(t, options)
	var closed atomic.Bool
	var requests atomic.Int32
	transport := runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: bytes.NewReader(runtimeTestSourceBytes("first.example")), closed: &closed}}, nil
	})
	batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, runtimeRemoteTestSession(digest, transport, func() error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	session := runtimeRemoteTestSession(digest, transport, func() error { return nil })
	session.previous = batch
	ctx := context.WithValue(context.Background(), runtimeSourceRefreshKey{}, map[string]bool{})
	reused, err := runtimePrepareRemoteSources(ctx, options, digest, session)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || len(reused) != 1 {
		t.Fatal("non-due source redownloaded")
	}
}

func TestRuntimeRemoteSourceLimitClosesOriginalBody(t *testing.T) {
	var closed atomic.Bool
	transport := runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: strings.NewReader("unused"), closed: &closed}, ContentLength: runtimeSourceByteLimit + 1}, nil
	})
	if _, err := runtimeDownloadSource(context.Background(), "https://rules.example/sites.json", transport); err == nil {
		t.Fatal("oversize accepted")
	}
	if !closed.Load() {
		t.Fatal("oversize original body leaked")
	}
}

func TestRuntimeRemoteSourceSnapshotEqualityTracksContentAndSourceIdentity(t *testing.T) {
	first := []runtimeSourceSnapshot{{identity: "source", digest: "bytes-a", remoteURL: "https://rules.example/a", downloadDependencyDigest: "egress-a", updateInterval: time.Hour}}
	same := append([]runtimeSourceSnapshot(nil), first...)
	if !runtimeEqualSourceSnapshots(first, same) {
		t.Fatal("unchanged source is not a no-op")
	}
	same[0].digest = "bytes-b"
	if runtimeEqualSourceSnapshots(first, same) {
		t.Fatal("changed bytes ignored")
	}
	same[0] = first[0]
	same[0].downloadDependencyDigest = "egress-b"
	if !runtimeEqualSourceSnapshots(first, same) {
		t.Fatal("unchanged bytes caused provenance-only publication")
	}
	same[0].identity = "different-source-options"
	if runtimeEqualSourceSnapshots(first, same) {
		t.Fatal("source selection change ignored")
	}
}

type runtimeSourceReadFailure struct{}

func (runtimeSourceReadFailure) Read([]byte) (int, error) { return 0, errors.New("body failure") }
func TestRuntimeRemoteSourceReadFailureStillClosesBody(t *testing.T) {
	var closed atomic.Bool
	transport := runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &runtimeSourceTestBody{Reader: runtimeSourceReadFailure{}, closed: &closed}}, nil
	})
	content, err := runtimeDownloadSource(context.Background(), "https://rules.example/sites.json", transport)
	if err == nil || content != nil || !closed.Load() {
		t.Fatal("failed read lost original body ownership")
	}
}

func TestRuntimeRemoteSourceCancellationWaitsActualRoundTrip(t *testing.T) {
	options := runtimeRemoteTestOptions()
	digest := runtimeRemoteTestDigest(t, options)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var joined atomic.Bool
	transport := runtimeSourceTestTransport(func(request *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := runtimeRemoteTestSession(digest, transport, func() error { joined.Store(true); return nil })
	go func() { defer close(done); _, _ = runtimePrepareRemoteSources(ctx, options, digest, session) }()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("observer cancellation fabricated original completion")
	default:
	}
	if joined.Load() {
		t.Fatal("lease released while RoundTrip still executing")
	}
	close(release)
	<-done
	if !joined.Load() {
		t.Fatal("actual completion not joined")
	}
}

func TestRuntimeRemoteSourceUsesEachSelectedTransport(t *testing.T) {
	options := runtimeRemoteTestOptions()
	first := options.Route.RuleSet[0]
	first.RemoteOptions.HTTPClient = &option.HTTPClientOptions{Tag: "a"}
	second := first
	second.Tag = []string{"other"}
	second.RemoteOptions.URL = "https://rules.example/other.json"
	second.RemoteOptions.HTTPClient = &option.HTTPClientOptions{Tag: "b"}
	options.Route.RuleSet = []option.RuleSet{first, second}
	digest := runtimeRemoteTestDigest(t, options)
	selected := make(map[string]int)
	session := &runtimeSourceDownloadSession{ctx: context.Background(), candidateDigest: digest, dependencyDigest: "original-manager", closeAndWait: func() error { return nil }}
	session.resolve = func(_ context.Context, source option.RuleSet) (http.RoundTripper, error) {
		tag := source.RemoteOptions.HTTPClient.Tag
		return runtimeSourceTestTransport(func(*http.Request) (*http.Response, error) {
			selected[tag]++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(runtimeTestSourceBytes(tag + ".example")))}, nil
		}), nil
	}
	batch, err := runtimePrepareRemoteSources(context.Background(), options, digest, session)
	if err != nil {
		t.Fatal(err)
	}
	if selected["a"] != 1 || selected["b"] != 1 || len(batch) != 2 {
		t.Fatal("per-rule selected egress was conflated")
	}
}
