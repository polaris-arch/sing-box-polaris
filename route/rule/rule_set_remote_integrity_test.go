package rule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type srsTestTransport func(*http.Request) (*http.Response, error)

func (f srsTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (f srsTestTransport) CloseIdleConnections()                             {}
func (f srsTestTransport) Reset()                                            {}

type ruleSetTestHTTPClientManager struct {
	adapter.HTTPClientManager
	transport srsTestTransport
}

func (m ruleSetTestHTTPClientManager) DefaultTransport() adapter.HTTPTransport { return m.transport }

func TestRemoteRuleSetDownloadDeadline(t *testing.T) {
	for _, shorter := range []bool{false, true} {
		name := "default"
		if shorter {
			name = "earlier caller deadline"
		}
		t.Run(name, func(t *testing.T) {
			var deadline time.Time
			transport := srsTestTransport(func(request *http.Request) (*http.Response, error) {
				var ok bool
				deadline, ok = request.Context().Deadline()
				require.True(t, ok, "default transport received no request deadline")
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"version":4,"rules":[]}`))}, nil
			})
			owner := service.ContextWith[adapter.HTTPClientManager](t.Context(), ruleSetTestHTTPClientManager{transport: transport})
			ctx := owner
			if shorter {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(owner, 10*time.Second)
				defer cancel()
			}
			set, err := NewRemoteRuleSet(owner, logger.NOP(), "deadline", option.RuleSet{
				Format: C.RuleSetFormatSource, RemoteOptions: option.RemoteRuleSet{URL: "http://127.0.0.1/rules"},
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, set.Close()) })
			start := time.Now()
			require.NoError(t, set.StartContext(ctx, adapter.NewHTTPStartContext()))
			if shorter {
				want, _ := ctx.Deadline()
				require.Equal(t, want, deadline)
			} else {
				require.WithinRange(t, deadline, start.Add(C.RuleSetDownloadTimeout), time.Now().Add(C.RuleSetDownloadTimeout))
			}
		})
	}
}

func TestRemoteRuleSetCacheUsesActiveContentLimit(t *testing.T) {
	const url = "http://127.0.0.1/rules"
	const tag = "cache-budget"
	content := []byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)
	limit := int64(len(content))
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := cachefile.New(t.Context(), logger.NOP(), option.CacheFileOptions{Path: path})
	db, err := bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	cache.DB = db
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	urlHash := sha256.Sum256([]byte(url))
	previous := &adapter.SavedBinary{
		Content: append(bytes.Clone(content), ' '), LastUpdated: time.Unix(20, 0), LastEtag: "cached", URLHash: urlHash[:],
	}
	require.NoError(t, cache.SaveRuleSet(tag, previous))
	require.Equal(t, previous, cache.LoadRuleSet(tag, limit+1))
	require.Nil(t, cache.LoadRuleSet(tag, limit))
	requests := 0
	transport := srsTestTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 2, 3, 4:
			require.Equal(t, "fresh", request.Header.Get("If-None-Match"))
			return &http.Response{StatusCode: http.StatusNotModified, Body: http.NoBody}, nil
		case 5:
			require.Equal(t, "fresh", request.Header.Get("If-None-Match"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Etag": []string{strings.Repeat("x", http.DefaultMaxHeaderBytes+1)}},
				Body:       io.NopCloser(bytes.NewReader(content)),
			}, nil
		case 6:
			require.Empty(t, request.Header.Get("If-None-Match"))
			return &http.Response{StatusCode: http.StatusNotModified, Body: http.NoBody}, nil
		}
		require.Empty(t, request.Header.Get("If-None-Match"))
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": []string{"fresh"}}, Body: io.NopCloser(bytes.NewReader(content))}, nil
	})
	ctx := service.ContextWith[adapter.HTTPClientManager](t.Context(), ruleSetTestHTTPClientManager{transport: transport})
	ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	set, err := NewRemoteRuleSet(ctx, logger.NOP(), tag, option.RuleSet{
		Format: C.RuleSetFormatSource, RemoteOptions: option.RemoteRuleSet{URL: url},
		ResourceLimits: &option.RuleSetResourceLimits{InputBytes: limit},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, set.Close()) })
	require.NoError(t, set.StartContext(ctx, adapter.NewHTTPStartContext()))
	require.Equal(t, 1, requests)
	require.True(t, set.Match(&adapter.InboundContext{Domain: "example.com"}))
	fresh := cache.LoadRuleSet(tag, limit)
	require.NotNil(t, fresh)
	require.Equal(t, content, fresh.Content)
	require.Equal(t, "fresh", fresh.LastEtag)
	require.Equal(t, urlHash[:], fresh.URLHash)

	current := set.loadSnapshot()
	fresh.LastUpdated = time.Unix(20, 0)
	require.NoError(t, cache.SaveRuleSet(tag, fresh))
	require.NoError(t, set.fetch(ctx, false))
	require.Equal(t, 2, requests)
	require.Same(t, current, set.loadSnapshot())
	fresh.LastUpdated = set.lastUpdated.Truncate(time.Second)
	require.Equal(t, fresh, cache.LoadRuleSet(tag, limit))

	// A same-tag record from a different configured limit must not be read
	// and written back under this rule-set's limit on a 304 response.
	require.NoError(t, cache.SaveRuleSet(tag, previous))
	require.NoError(t, set.fetch(ctx, false))
	require.Equal(t, 3, requests)
	require.Same(t, current, set.loadSnapshot())
	require.Equal(t, previous, cache.LoadRuleSet(tag, limit+1))

	// A 304 for the active URL must not rebind an older row with the same
	// tag and validator. This can happen if the last cache write failed.
	otherHash := sha256.Sum256([]byte("http://127.0.0.1/previous"))
	foreign := *fresh
	foreign.URLHash = otherHash[:]
	foreign.LastUpdated = time.Unix(20, 0)
	require.NoError(t, cache.SaveRuleSet(tag, &foreign))
	require.NoError(t, set.fetch(ctx, false))
	require.Equal(t, 4, requests)
	require.Same(t, current, set.loadSnapshot())
	require.Equal(t, &foreign, cache.LoadRuleSet(tag, limit))

	// A successful download stays usable when its optional ETag is oversized.
	require.NoError(t, set.fetch(ctx, false))
	require.Equal(t, 5, requests)
	require.Zero(t, len(set.lastEtag))
	fresh = cache.LoadRuleSet(tag, limit)
	require.NotNil(t, fresh)
	require.Equal(t, content, fresh.Content)
	require.Zero(t, len(fresh.LastEtag))
	require.Equal(t, urlHash[:], fresh.URLHash)

	current = set.loadSnapshot()
	updated := set.lastUpdated
	require.ErrorContains(t, set.fetch(ctx, false), "without a rule-set validator")
	require.Equal(t, 6, requests)
	require.Same(t, current, set.loadSnapshot())
	require.Equal(t, updated, set.lastUpdated)
	require.Equal(t, fresh, cache.LoadRuleSet(tag, limit))
}

func TestRemoteRuleSetLegacyCacheContentLimit(t *testing.T) {
	// Version 1: length-prefixed content, big-endian update seconds, and ETag.
	legacy := []byte{1, 2, 'r', 's', 0, 0, 0, 0, 0, 0, 0, 20, 3, 'o', 'l', 'd'}
	var decoded adapter.SavedBinary
	require.Error(t, decoded.UnmarshalBinaryWithContentLimit(legacy, 1))
	require.Nil(t, decoded.Content)
	require.NoError(t, decoded.UnmarshalBinaryWithContentLimit(legacy, 2))
	require.Equal(t, []byte("rs"), decoded.Content)
	require.Equal(t, "old", decoded.LastEtag)
	require.Equal(t, time.Unix(20, 0), decoded.LastUpdated)
	require.Empty(t, decoded.URLHash)

	// A legacy v2 record may carry a large optional validator, but its URL
	// identity still needs to be the real digest size when it is present.
	digest := sha256.Sum256([]byte("https://fixture.invalid/rules"))
	saved := adapter.SavedBinary{
		Content:     []byte("rs"),
		LastUpdated: time.Unix(20, 0),
		LastEtag:    strings.Repeat("x", http.DefaultMaxHeaderBytes+1),
		URLHash:     digest[:],
	}
	encoded, err := saved.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, decoded.UnmarshalBinaryWithContentLimit(encoded, 2))
	require.Equal(t, saved.Content, decoded.Content)
	require.Equal(t, digest[:], decoded.URLHash)
	require.Zero(t, len(decoded.LastEtag))
	saved.LastEtag = "in-range"
	saved.URLHash = append(digest[:], 0)
	encoded, err = saved.MarshalBinary()
	require.NoError(t, err)
	require.ErrorContains(t, decoded.UnmarshalBinaryWithContentLimit(encoded, 2), "invalid url hash length")
}

func TestRemoteRuleSetIntegrityFailurePreservesPublicationAndETag(t *testing.T) {
	ctx := context.Background()
	set := &RemoteRuleSet{ctx: ctx, logger: logger.NOP(), tag: "integrity", options: option.RuleSet{Format: C.RuleSetFormatSource}}
	require.NoError(t, set.loadBytesContext(ctx, []byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)))
	set.options.Format = C.RuleSetFormatBinary
	set.lastEtag = "old-etag"
	set.lastUpdated = time.Unix(100, 0)
	set.url = "http://fixture.invalid/rules"
	var compressed bytes.Buffer
	require.NoError(t, srs.Write(&compressed, option.PlainRuleSet{}, C.RuleSetVersionCurrent))
	malformed := append([]byte(nil), compressed.Bytes()...)
	malformed[len(malformed)-1] ^= 1
	set.httpClient = &http.Client{Transport: srsTestTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "old-etag", r.Header.Get("If-None-Match"))
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": []string{"new-etag"}}, Body: io.NopCloser(bytes.NewReader(malformed))}, nil
	})}
	require.Error(t, set.fetch(ctx, false))
	require.Equal(t, "old-etag", set.lastEtag)
	require.Equal(t, time.Unix(100, 0), set.lastUpdated)
	require.True(t, set.Match(&adapter.InboundContext{Domain: "example.com"}))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, set.loadBytesContext(cancelled, compressed.Bytes()), context.Canceled)
	require.True(t, set.Match(&adapter.InboundContext{Domain: "example.com"}))
	require.Equal(t, "old-etag", set.lastEtag)
}

// Cancel precisely at the lock-protected check so the result does not depend
// on when a second goroutine reaches the publication lock.
type publicationLockCheckingContext struct {
	context.Context
	publication *ruleSetPublication
	cancel      context.CancelFunc
}

func (c *publicationLockCheckingContext) Err() error {
	if c.publication.access.TryLock() {
		c.publication.access.Unlock()
	} else {
		c.cancel()
	}
	return c.Context.Err()
}

func TestPublicationCancellationCheckIsInsideCommitLock(t *testing.T) {
	var publication ruleSetPublication
	_, err := publication.publish(nil, adapter.RuleSetMetadata{}, "old")
	require.NoError(t, err)
	old := publication.loadSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = publication.publishContext(&publicationLockCheckingContext{
		Context: ctx, publication: &publication, cancel: cancel,
	}, nil, adapter.RuleSetMetadata{}, "new")
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, old, publication.loadSnapshot())
}

func TestRemoteRuleSetOversizedDownloadKeepsPublicationAndETag(t *testing.T) {
	ctx := context.Background()
	set := &RemoteRuleSet{ctx: ctx, logger: logger.NOP(), tag: "budget", options: option.RuleSet{Format: C.RuleSetFormatSource}}
	require.NoError(t, set.loadBytesContext(ctx, []byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)))
	old := set.loadSnapshot()
	set.lastEtag = "old"
	set.lastUpdated = time.Unix(100, 0)
	set.url = "http://fixture.invalid/rules"
	body := &forbiddenOversizedBody{t: t}
	set.httpClient = &http.Client{Transport: srsTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: srs.DefaultInputBytes + 1, Header: http.Header{"Etag": []string{"new"}}, Body: body}, nil
	})}
	require.ErrorIs(t, set.fetch(ctx, false), srs.ErrResourceLimit)
	require.True(t, body.closed)
	require.Same(t, old, set.loadSnapshot())
	require.Equal(t, "old", set.lastEtag)
	require.Equal(t, time.Unix(100, 0), set.lastUpdated)

	set.options.ResourceLimits = &option.RuleSetResourceLimits{Rules: 1}
	set.httpClient.Transport = srsTestTransport(func(*http.Request) (*http.Response, error) {
		content := `{"version":4,"rules":[{"type":"logical","mode":"or","rules":[{"domain":"changed.example"}]}]}`
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(content)), Header: http.Header{"Etag": []string{"new"}}, Body: io.NopCloser(strings.NewReader(content))}, nil
	})
	require.ErrorIs(t, set.fetch(ctx, false), srs.ErrResourceLimit)
	require.Same(t, old, set.loadSnapshot())
	require.Equal(t, "old", set.lastEtag)
	require.Equal(t, time.Unix(100, 0), set.lastUpdated)
}

type forbiddenOversizedBody struct {
	t      *testing.T
	closed bool
}

func (b *forbiddenOversizedBody) Read([]byte) (int, error) {
	b.t.Error("oversized declared body should not be read")
	return 0, io.EOF
}
func (b *forbiddenOversizedBody) Close() error { b.closed = true; return nil }

func TestRuleSetFileBudgetRejectsBeforeReadingAndPreservesLocalPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.srs")
	var encoded bytes.Buffer
	require.NoError(t, srs.Write(&encoded, option.PlainRuleSet{}, C.RuleSetVersionCurrent))
	require.NoError(t, os.WriteFile(path, encoded.Bytes(), 0o600))
	set := &LocalRuleSet{ctx: context.Background(), logger: logger.NOP(), tag: "budget", fileFormat: C.RuleSetFormatBinary}
	require.NoError(t, set.reloadFile(path))
	old := set.loadSnapshot()
	require.NoError(t, os.Truncate(path, srs.DefaultInputBytes+1))
	content, err := readRuleSetFile(context.Background(), path, nil)
	require.ErrorIs(t, err, srs.ErrResourceLimit)
	require.Nil(t, content)
	require.ErrorIs(t, set.reloadFile(path), srs.ErrResourceLimit)
	require.Same(t, old, set.loadSnapshot())
}

func TestRuleSetResourceLimitsDefaultAndConfiguredCompatibility(t *testing.T) {
	ctx := context.Background()
	content := []byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)
	set := &RemoteRuleSet{ctx: ctx, logger: logger.NOP(), tag: "override", options: option.RuleSet{Format: C.RuleSetFormatSource}}
	require.NoError(t, set.loadBytesContext(ctx, content)) // unchanged configuration
	old := set.loadSnapshot()
	set.options.ResourceLimits = &option.RuleSetResourceLimits{InputBytes: int64(len(content) - 1)}
	require.ErrorIs(t, set.loadBytesContext(ctx, content), srs.ErrResourceLimit)
	require.Same(t, old, set.loadSnapshot())
	set.options.ResourceLimits.InputBytes = int64(len(content))
	require.NoError(t, set.loadBytesContext(ctx, content)) // explicit larger override takes effect
	path := filepath.Join(t.TempDir(), "rules.json")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	local := &LocalRuleSet{ctx: ctx, logger: logger.NOP(), tag: "override-local", fileFormat: C.RuleSetFormatSource, resourceLimits: &option.RuleSetResourceLimits{InputBytes: int64(len(content) - 1)}}
	require.ErrorIs(t, local.reloadFile(path), srs.ErrResourceLimit)
	local.resourceLimits.InputBytes = int64(len(content))
	require.NoError(t, local.reloadFile(path))
	limits, err := ruleSetLimits(&option.RuleSetResourceLimits{InputBytes: 128 << 20})
	require.NoError(t, err)
	require.Equal(t, int64(128<<20), limits.InputBytes)
	require.Equal(t, srs.DefaultReadLimits().DecodedBytes, limits.DecodedBytes)
	_, err = ruleSetLimits(&option.RuleSetResourceLimits{InputBytes: -1})
	require.Error(t, err)
}

func TestRemoteUnknownLengthBudgetKeepsOldState(t *testing.T) {
	ctx := context.Background()
	set := &RemoteRuleSet{ctx: ctx, logger: logger.NOP(), tag: "unknown-length", options: option.RuleSet{Format: C.RuleSetFormatSource}}
	require.NoError(t, set.loadBytesContext(ctx, []byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)))
	old := set.loadSnapshot()
	set.options.ResourceLimits = &option.RuleSetResourceLimits{InputBytes: 3}
	set.lastEtag = "old"
	set.lastUpdated = time.Unix(100, 0)
	set.url = "http://fixture.invalid/rules"
	body := &countedBudgetBody{reader: bytes.NewReader([]byte("untrusted response longer than limit"))}
	set.httpClient = &http.Client{Transport: srsTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: http.Header{"Etag": []string{"new"}}, Body: body}, nil
	})}
	require.ErrorIs(t, set.fetch(ctx, false), srs.ErrResourceLimit)
	require.Equal(t, 4, body.read)
	require.True(t, body.closed)
	require.Same(t, old, set.loadSnapshot())
	require.Equal(t, "old", set.lastEtag)
	require.Equal(t, time.Unix(100, 0), set.lastUpdated)
}

type countedBudgetBody struct {
	reader io.Reader
	read   int
	closed bool
}

func (b *countedBudgetBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}
func (b *countedBudgetBody) Close() error { b.closed = true; return nil }
