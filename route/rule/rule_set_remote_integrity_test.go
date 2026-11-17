package rule

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
	require.NoError(t, set.loadBytes([]byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`)))
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

func TestPublicationCancelledWhileAccessLockedKeepsOldSnapshot(t *testing.T) {
	var publication ruleSetPublication
	_, err := publication.publish(nil, adapter.RuleSetMetadata{}, "old")
	require.NoError(t, err)
	old := publication.loadSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	publication.access.Lock()
	entered := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		close(entered)
		_, err := publication.publishContext(ctx, nil, adapter.RuleSetMetadata{}, "new")
		finished <- err
	}()
	<-entered
	select {
	case err := <-finished:
		t.Fatalf("published despite held lock: %v", err)
	default:
	}
	cancel()
	publication.access.Unlock()
	require.ErrorIs(t, <-finished, context.Canceled)
	require.Same(t, old, publication.loadSnapshot())
}

// This test context detects lock ownership synchronously, without depending on
// goroutine scheduling. Moving the cancellation check before access.Lock makes
// TryLock succeed and fails the test even if the concurrent test happens to pass.
type publicationLockCheckingContext struct {
	context.Context
	publication      *ruleSetPublication
	checkedUnderLock bool
	calls            int
}

func (c *publicationLockCheckingContext) Err() error {
	c.calls++
	if c.publication.access.TryLock() {
		c.publication.access.Unlock()
	} else {
		c.checkedUnderLock = true
	}
	return context.Canceled
}

func TestPublicationCancellationCheckIsInsideCommitLock(t *testing.T) {
	var publication ruleSetPublication
	_, err := publication.publish(nil, adapter.RuleSetMetadata{}, "old")
	require.NoError(t, err)
	old := publication.loadSnapshot()
	ctx := &publicationLockCheckingContext{Context: context.Background(), publication: &publication}
	_, err = publication.publishContext(ctx, nil, adapter.RuleSetMetadata{}, "new")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, ctx.calls)
	require.True(t, ctx.checkedUnderLock, "cancellation must be checked inside publication critical section")
	require.Same(t, old, publication.loadSnapshot())
}
