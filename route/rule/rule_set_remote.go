package rule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	tag            string
	url            string
	urlHash        [32]byte
	initialPath    string
	options        option.RuleSet
	updateInterval time.Duration
	httpClient     *http.Client
	ruleSetPublication
	lastUpdated  time.Time
	lastEtag     string
	cacheFile    adapter.CacheFile
	pauseManager pause.Manager
	refs         atomic.Int32
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, tag string, options option.RuleSet) (*RemoteRuleSet, error) {
	if _, err := ruleSetLimits(options.ResourceLimits); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	var initialPath string
	if options.RemoteOptions.InitialPath != "" {
		initialPath = filemanager.BasePath(ctx, strings.ReplaceAll(options.RemoteOptions.InitialPath, C.RuleSetTagPlaceholder, tag))
		initialPath, _ = filepath.Abs(initialPath)
	}
	url := strings.ReplaceAll(options.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
	return &RemoteRuleSet{
		watcherState:   "remote",
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		tag:            tag,
		url:            url,
		urlHash:        sha256.Sum256([]byte(url)),
		initialPath:    initialPath,
		options:        options,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *RemoteRuleSet) Name() string {
	return s.tag
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.loadSnapshot().rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create rule-set http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.cacheFile != nil {
		savedSet := s.cacheFile.LoadRuleSet(s.tag)
		if savedSet != nil {
			if len(savedSet.URLHash) > 0 && !bytes.Equal(savedSet.URLHash, s.urlHash[:]) {
				s.logger.Info("cached rule-set was downloaded from another URL, will refetch")
			} else {
				err = s.loadBytesContext(ctx, savedSet.Content)
				if err != nil {
					s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
				} else {
					s.lastUpdated = savedSet.LastUpdated
					s.lastEtag = savedSet.LastEtag
				}
			}
		}
	}
	var loadedFromInitialPath bool
	if s.lastUpdated.IsZero() && s.initialPath != "" {
		var content []byte
		content, err = readRuleSetFile(s.ctx, s.initialPath, s.options.ResourceLimits)
		if err == nil {
			err = s.loadBytesContext(ctx, content)
		}
		if err != nil {
			s.logger.Warn(E.Cause(err, "load initial rule-set from ", s.initialPath))
		} else {
			loadedFromInitialPath = true
		}
	}
	if s.lastUpdated.IsZero() && !loadedFromInitialPath {
		err = s.fetch(ctx, true)
		if err != nil {
			return E.Cause(err, "initial rule-set: ", s.tag)
		}
	}
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.loadSnapshot().metadata
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	return common.FlatMap(s.loadSnapshot().rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.cleanupPublication()
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte) error {
	return s.loadBytesContext(s.ctx, content)
}

func (s *RemoteRuleSet) loadBytesContext(ctx context.Context, content []byte) (result error) {
	s.reloadAccess.Lock()
	var callbacks []adapter.RuleSetUpdateCallback
	defer func() {
		s.recordError(result)
		s.reloadAccess.Unlock()
		if result == nil {
			for _, callback := range callbacks {
				callback(s)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	limits, limitsErr := ruleSetLimits(s.options.ResourceLimits)
	if limitsErr != nil {
		return limitsErr
	}
	if int64(len(content)) > limits.InputBytes {
		return fmt.Errorf("%w: input bytes", srs.ErrResourceLimit)
	}
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.options.Format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.ReadContextWithLimits(ctx, bytes.NewReader(content), false, limits)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.options.Format)
	}
	plainRuleSet, err := mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet).Upgrade()
	if err != nil {
		return err
	}
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(plainRuleSet.Rules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	callbacks, result = s.publishContext(ctx, rules, metadata, hex.EncodeToString(sum[:]))
	return result
}

func (s *RemoteRuleSet) updateOnce() {
	err := s.fetch(s.ctx, false)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.cleanupPublication()
	}
}

func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) error {
	limits, limitsErr := ruleSetLimits(s.options.ResourceLimits)
	if limitsErr != nil {
		return limitsErr
	}
	s.logger.Debug("updating rule-set ", s.tag, " from URL: ", s.url)
	request, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	response, err := s.httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		if response.ContentLength > limits.InputBytes {
			return fmt.Errorf("%w: input bytes", srs.ErrResourceLimit)
		}
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		if s.cacheFile != nil {
			savedRuleSet := s.cacheFile.LoadRuleSet(s.tag)
			if savedRuleSet != nil {
				savedRuleSet.LastUpdated = s.lastUpdated
				savedRuleSet.URLHash = s.urlHash[:]
				err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return nil
				}
			}
		}
		s.logger.Info("update rule-set ", s.tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := srs.ReadContent(response.Body, limits.InputBytes)
	if err != nil {
		return err
	}
	err = s.loadBytesContext(ctx, content)
	if err != nil {
		return err
	}
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     content,
			LastEtag:    s.lastEtag,
			URLHash:     s.urlHash[:],
		})
		if err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.Info("updated rule-set ", s.tag)
	return nil
}

func (s *RemoteRuleSet) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.options.RemoteOptions.HTTPClient != nil && !s.options.RemoteOptions.HTTPClient.IsEmpty() {
		if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.options.RemoteOptions.HTTPClient)
	}
	if s.options.RemoteOptions.DownloadDetour != "" { //nolint:staticcheck
		deprecated.Report(s.ctx, deprecated.OptionLegacyRuleSetDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.options.RemoteOptions.DownloadDetour, //nolint:staticcheck
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *RemoteRuleSet) Close() error {
	s.closePublication()
	s.cancel()
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.loadSnapshot().rules, metadata)
}

func (s *RemoteRuleSet) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.loadSnapshot().rules)
}

// Bound file acquisition too: validating len(content) after ReadFile is too late.
func readRuleSetFile(ctx context.Context, path string, configured *option.RuleSetResourceLimits) ([]byte, error) {
	limits, err := ruleSetLimits(configured)
	if err != nil {
		return nil, err
	}
	file, err := filemanager.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() > limits.InputBytes {
		return nil, fmt.Errorf("%w: input bytes", srs.ErrResourceLimit)
	}
	// Still bound actual reads in case the file grows after Stat.
	return srs.ReadContent(file, limits.InputBytes)
}

func ruleSetLimits(configured *option.RuleSetResourceLimits) (srs.ReadLimits, error) {
	if configured == nil {
		return srs.DefaultReadLimits(), nil
	}
	return srs.ResolveReadLimits(*configured)
}
