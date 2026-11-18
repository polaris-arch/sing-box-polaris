package rule

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type srsTestTransport func(*http.Request) (*http.Response, error)

func (f srsTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
