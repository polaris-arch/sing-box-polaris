package box

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service/filemanager"
)

const runtimeSourceByteLimit = 16 << 20

type runtimeSourceSnapshot struct {
	identity                 string
	path                     string
	digest                   string
	content                  []byte
	remoteURL                string
	candidateDigest          string
	downloadDependencyDigest string
	updateInterval           time.Duration
}

func runtimeReadSource(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := filemanager.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	statFile, ok := any(file).(interface{ Stat() (fs.FileInfo, error) })
	if !ok {
		return nil, fmt.Errorf("source lacks regular-file identity")
	}
	info, err := statFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("source is not a regular file")
	}
	if info.Size() > runtimeSourceByteLimit {
		return nil, fmt.Errorf("source exceeds bounded size")
	}
	content, err := io.ReadAll(io.LimitReader(file, runtimeSourceByteLimit+1))
	if err != nil {
		return nil, err
	}
	if len(content) > runtimeSourceByteLimit {
		return nil, fmt.Errorf("source exceeds %d bytes", runtimeSourceByteLimit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func runtimeSnapshotSources(request context.Context, registry context.Context, options option.Options, trusted map[string]runtimeSourceSnapshot) (option.Options, []runtimeSourceSnapshot, string, []RuntimePlanError) {
	if options.Route == nil {
		return options, nil, runtimeDigest(nil), nil
	}
	encodedCandidate, candidateErr := json.MarshalContext(registry, options)
	if candidateErr != nil {
		return options, nil, "", []RuntimePlanError{{Code: "INVALID_SOURCE_PROVENANCE", Path: "route.rule_set"}}
	}
	candidateDigest := runtimeDigest(encodedCandidate)
	routeOptions := *options.Route
	options.Route = &routeOptions
	var frozen []option.RuleSet
	var snapshots []runtimeSourceSnapshot
	totalBytes := 0
	hash := sha256.New()
	for i, source := range routeOptions.RuleSet {
		if err := request.Err(); err != nil {
			return options, nil, "", []RuntimePlanError{{Code: "CANCELED", Path: "route.rule_set"}}
		}
		for _, tag := range source.Tag {
			identityBytes, err := json.Marshal(source)
			if err != nil {
				return options, nil, "", []RuntimePlanError{{Code: "INVALID_SOURCE", Path: "route.rule_set"}}
			}
			identity := runtimeDigest(identityBytes) + ":" + tag
			path := ""
			var content []byte
			switch source.Type {
			case "", C.RuleSetTypeInline:
				inline := source
				inline.Tag = []string{tag}
				frozen = append(frozen, inline)
				runtimeHashField(hash, identity)
				continue
			case C.RuleSetTypeLocal:
				path = filemanager.BasePath(registry, strings.ReplaceAll(source.LocalOptions.Path, C.RuleSetTagPlaceholder, tag))
				path, err = filepath.Abs(path)
				if err != nil {
					break
				}
				// The read retains registry filesystem bindings and request cancellation
				// is checked before/after; no successful resource lifetime uses request.
				content, err = runtimeReadSource(registry, path)
			case C.RuleSetTypeRemote:
				if snapshot, ok := trusted[identity]; ok {
					if snapshot.identity != identity || snapshot.digest != runtimeDigest(snapshot.content) || snapshot.remoteURL != strings.ReplaceAll(source.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag) || snapshot.candidateDigest != candidateDigest || snapshot.downloadDependencyDigest == "" {
						return options, nil, "", []RuntimePlanError{{Code: "INVALID_SOURCE_PROVENANCE", Path: fmt.Sprintf("route.rule_set[%d]", i)}}
					}
					content = append([]byte(nil), snapshot.content...)
				} else {
					return options, nil, "", []RuntimePlanError{{Code: "SOURCE_PREPARATION_REQUIRED", Path: fmt.Sprintf("route.rule_set[%d]", i), Message: "verified immutable remote bytes are not available"}}
				}
			default:
				err = fmt.Errorf("unsupported source format")
			}
			if err != nil {
				return options, nil, "", []RuntimePlanError{{Code: "SOURCE_READ_FAILED", Path: fmt.Sprintf("route.rule_set[%d]", i)}}
			}
			if request.Err() != nil {
				return options, nil, "", []RuntimePlanError{{Code: "CANCELED", Path: "route.rule_set"}}
			}
			totalBytes += len(content)
			if len(content) > runtimeSourceByteLimit || totalBytes > 64<<20 || len(snapshots) >= 256 {
				return options, nil, "", []RuntimePlanError{{Code: "SOURCE_BUDGET_EXHAUSTED", Path: "route.rule_set"}}
			}
			var compatible option.PlainRuleSetCompat
			switch source.Format {
			case C.RuleSetFormatSource, "":
				compatible, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
			case C.RuleSetFormatBinary:
				compatible, err = srs.Read(bytes.NewReader(content), false)
			default:
				err = fmt.Errorf("unsupported source format")
			}
			if err != nil {
				return options, nil, "", []RuntimePlanError{{Code: "INVALID_SOURCE", Path: fmt.Sprintf("route.rule_set[%d]", i)}}
			}
			plain, err := compatible.Upgrade()
			if err != nil {
				return options, nil, "", []RuntimePlanError{{Code: "INVALID_SOURCE_VERSION", Path: fmt.Sprintf("route.rule_set[%d]", i)}}
			}
			inline := source
			inline.Type = C.RuleSetTypeInline
			inline.Tag = []string{tag}
			inline.Format = ""
			inline.InlineOptions = plain
			inline.LocalOptions = option.LocalRuleSet{}
			inline.RemoteOptions = option.RemoteRuleSet{}
			frozen = append(frozen, inline)
			digest := runtimeDigest(content)
			snapshot := runtimeSourceSnapshot{identity: identity, path: path, digest: digest, content: append([]byte(nil), content...)}
			if source.Type == C.RuleSetTypeRemote {
				prepared := trusted[identity]
				snapshot.path = prepared.path
				snapshot.remoteURL = prepared.remoteURL
				snapshot.candidateDigest = prepared.candidateDigest
				snapshot.downloadDependencyDigest = prepared.downloadDependencyDigest
				snapshot.updateInterval = prepared.updateInterval
				runtimeHashField(hash, snapshot.remoteURL)
				runtimeHashField(hash, snapshot.downloadDependencyDigest)
			}
			snapshots = append(snapshots, snapshot)
			runtimeHashField(hash, identity)
			runtimeHashField(hash, digest)
		}
	}
	options.Route.RuleSet = frozen
	return options, snapshots, hex.EncodeToString(hash.Sum(nil)), nil
}

func runtimeCheckSources(ctx context.Context, snapshots []runtimeSourceSnapshot) error {
	for _, snapshot := range snapshots {
		if snapshot.path == "" {
			continue
		}
		content, err := runtimeReadSource(ctx, snapshot.path)
		if err != nil {
			return fmt.Errorf("source unavailable before commit")
		}
		if runtimeDigest(content) != snapshot.digest {
			return fmt.Errorf("source revision changed before commit")
		}
	}
	return nil
}

// runtimeSourceDownloadSession is supplied by Box after proving the candidate
// download closure is unchanged from the exact retained current graph. resolve
// uses that captured HTTP/detour/DNS closure. closeAndWait releases per-fetch
// reservations and the retained graph lease after actual fetch/body completion;
// it must not stop the borrowed manager or its shared native workers.
// A live mutable manager or process-default client is not a valid session.
// The session owns ctx's resource capabilities until closeAndWait returns.
type runtimeSourceRefreshKey struct{}

type runtimeSourceDownloadSession struct {
	ctx              context.Context
	candidateDigest  string
	dependencyDigest string
	resolve          func(context.Context, option.RuleSet) (http.RoundTripper, error)
	closeAndWait     func() error
	previous         map[string]runtimeSourceSnapshot
}

// runtimePrepareRemoteSources keeps source authority transaction-owned. The
// returned private batch is consumed once by the same Plan, whose dependency
// digest binds exact bytes and current-revision downloader provenance.
func runtimePrepareRemoteSources(request context.Context, options option.Options, candidateDigest string, session *runtimeSourceDownloadSession) (result map[string]runtimeSourceSnapshot, resultErr error) {
	if session == nil {
		return nil, errors.New("candidate source download session missing")
	}
	if session.closeAndWait == nil {
		return nil, errors.New("candidate source download join missing")
	}
	defer func() {
		cleanup := session.closeAndWait()
		if cleanup != nil {
			result = nil
			resultErr = errors.Join(resultErr, runtimeCleanupResult(cleanup))
		}
	}()
	if session.ctx == nil || session.resolve == nil || session.dependencyDigest == "" || candidateDigest == "" || session.candidateDigest != candidateDigest {
		return nil, errors.New("candidate source download provenance mismatch")
	}
	ctx, cancel := context.WithCancel(session.ctx)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(request, func() { defer close(stopped); cancel() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	if err := request.Err(); err != nil {
		return nil, err
	}
	result = make(map[string]runtimeSourceSnapshot)
	if options.Route == nil {
		return result, nil
	}
	total := 0
	for _, source := range options.Route.RuleSet {
		if source.Type != C.RuleSetTypeRemote {
			continue
		}
		encoded, err := json.Marshal(source)
		if err != nil {
			return nil, errors.New("remote source identity is invalid")
		}
		for _, tag := range source.Tag {
			if len(result) >= 256 {
				return nil, errors.New("remote source count exceeds budget")
			}
			identity := runtimeDigest(encoded) + ":" + tag
			if _, duplicate := result[identity]; duplicate {
				return nil, errors.New("duplicate remote source identity")
			}
			if due, scheduled := request.Value(runtimeSourceRefreshKey{}).(map[string]bool); scheduled && !due[identity] {
				if old, ok := session.previous[identity]; ok && old.identity == identity && old.candidateDigest == candidateDigest && old.digest == runtimeDigest(old.content) && old.downloadDependencyDigest == session.dependencyDigest {
					old.content = append([]byte(nil), old.content...)
					result[identity] = old
					total += len(old.content)
					if total > 64<<20 {
						return nil, errors.New("remote source bytes exceed budget")
					}
					continue
				}
			}
			address := strings.ReplaceAll(source.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
			parsed, err := url.Parse(address)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
				return nil, errors.New("remote source URL must use HTTP or HTTPS")
			}
			transport, err := session.resolve(ctx, source)
			if err != nil {
				return nil, errors.New("candidate source transport preparation failed")
			}
			if transport == nil {
				return nil, errors.New("candidate source transport missing")
			}
			// Timeout requests cancellation; synchronous return/body close and the
			// session join, not the timeout, establish actual worker completion.
			fetchContext, fetchCancel := context.WithTimeout(ctx, time.Minute)
			content, err := runtimeDownloadSource(fetchContext, address, transport)
			fetchCancel()
			if err != nil {
				return nil, err
			}
			total += len(content)
			if total > 64<<20 {
				return nil, errors.New("remote source bytes exceed budget")
			}
			interval := time.Duration(source.RemoteOptions.UpdateInterval)
			if interval <= 0 {
				interval = 24 * time.Hour
			}
			result[identity] = runtimeSourceSnapshot{identity: identity, digest: runtimeDigest(content), content: append([]byte(nil), content...), remoteURL: address, candidateDigest: candidateDigest, downloadDependencyDigest: session.dependencyDigest, updateInterval: interval}
		}
	}
	if err := request.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func runtimeDownloadSource(ctx context.Context, address string, transport http.RoundTripper) (content []byte, resultErr error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("remote source request is invalid")
	}
	client := &http.Client{Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		var cleanup error
		if response != nil && response.Body != nil {
			cleanup = runtimeCleanupResult(response.Body.Close())
		}
		return nil, errors.Join(errors.New("remote source request failed"), cleanup)
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("remote source response missing")
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			content = nil
			resultErr = errors.Join(resultErr, runtimeCleanupResult(err))
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote source returned HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > runtimeSourceByteLimit {
		return nil, errors.New("remote source exceeds bounded size")
	}
	content, err = io.ReadAll(io.LimitReader(response.Body, runtimeSourceByteLimit+1))
	if err != nil {
		return nil, errors.New("remote source body read failed")
	}
	if len(content) > runtimeSourceByteLimit {
		return nil, errors.New("remote source exceeds bounded size")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func runtimeEqualSourceSnapshots(first, second []runtimeSourceSnapshot) bool {
	if len(first) != len(second) {
		return false
	}
	for index, a := range first {
		b := second[index]
		if a.identity != b.identity || a.path != b.path || a.digest != b.digest || a.remoteURL != b.remoteURL || !bytes.Equal(a.content, b.content) {
			return false
		}
	}
	return true
}

// Startup has no current graph to borrow. A configured InitialPath can seed
// immutable bytes; absent one, report the network bootstrap gap explicitly.
// The path is retained so Apply's ordinary source recheck detects replacement.
func runtimeInitialRemoteSources(ctx context.Context, options option.Options, candidateDigest string) (map[string]runtimeSourceSnapshot, error) {
	result := make(map[string]runtimeSourceSnapshot)
	if options.Route == nil {
		return result, nil
	}
	total := 0
	for _, source := range options.Route.RuleSet {
		if source.Type != C.RuleSetTypeRemote {
			continue
		}
		if source.RemoteOptions.InitialPath == "" {
			return nil, errors.New("remote source needs an initial_path before current-graph downloads are available")
		}
		encoded, err := json.Marshal(source)
		if err != nil {
			return nil, errors.New("remote source identity is invalid")
		}
		for _, tag := range source.Tag {
			if len(result) >= 256 {
				return nil, errors.New("remote source count exceeds budget")
			}
			identity := runtimeDigest(encoded) + ":" + tag
			if _, duplicate := result[identity]; duplicate {
				return nil, errors.New("duplicate remote source identity")
			}
			path := filemanager.BasePath(ctx, strings.ReplaceAll(source.RemoteOptions.InitialPath, C.RuleSetTagPlaceholder, tag))
			path, err = filepath.Abs(path)
			if err != nil {
				return nil, errors.New("remote initial path is invalid")
			}
			content, err := runtimeReadSource(ctx, path)
			if err != nil {
				return nil, errors.New("remote initial source is unavailable")
			}
			total += len(content)
			if total > 64<<20 {
				return nil, errors.New("remote source bytes exceed budget")
			}
			interval := time.Duration(source.RemoteOptions.UpdateInterval)
			if interval <= 0 {
				interval = 24 * time.Hour
			}
			result[identity] = runtimeSourceSnapshot{identity: identity, path: path, digest: runtimeDigest(content), content: content, remoteURL: strings.ReplaceAll(source.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag), candidateDigest: candidateDigest, downloadDependencyDigest: "initial-file:" + runtimeDigest([]byte(path)), updateInterval: interval}
		}
	}
	return result, nil
}
