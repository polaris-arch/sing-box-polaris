package rule

import (
	"context"
 "crypto/sha256"
 "encoding/hex"
 "io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/filemanager"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	ctx        context.Context
	logger     logger.Logger
	tag        string
	ruleSetPublication
	fileFormat string
	watcher    *fswatch.Watcher
 lifecycleAccess sync.Mutex
	refs       atomic.Int32
}

func NewLocalRuleSet(ctx context.Context, logger logger.Logger, tag string, options option.RuleSet) (*LocalRuleSet, error) {
	ruleSet := &LocalRuleSet{
		ctx:        ctx,
		logger:     logger,
		tag:        tag,
		fileFormat: options.Format,
	}
	ruleSet.watcherState = "not-started"
 if options.Type == C.RuleSetTypeInline {
 ruleSet.watcherState = "inline"
		if len(options.InlineOptions.Rules) == 0 {
			return nil, E.New("empty inline rule-set")
		}
		err := ruleSet.reloadRules(options.InlineOptions.Rules)
		if err != nil {
			return nil, err
		}
	} else {
		filePath := filemanager.BasePath(ctx, strings.ReplaceAll(options.LocalOptions.Path, C.RuleSetTagPlaceholder, tag))
		filePath, _ = filepath.Abs(filePath)
		err := ruleSet.reloadFile(filePath)
		if err != nil {
			return nil, err
		}
		watcher, err := fswatch.NewWatcher(fswatch.Options{
			Path: []string{filePath},
			Callback: func(path string) {
				uErr := ruleSet.reloadFile(path)
				if uErr != nil {
					logger.Error(E.Cause(uErr, "reload rule-set ", tag))
				}
			},
		})
		if err != nil {
			return nil, err
		}
		ruleSet.watcher = watcher
	}
	return ruleSet, nil
}

func (s *LocalRuleSet) Name() string {
	return s.tag
}

func (s *LocalRuleSet) String() string {
	return strings.Join(F.MapToString(s.loadSnapshot().rules), " ")
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
 s.lifecycleAccess.Lock()
 defer s.lifecycleAccess.Unlock()
 s.access.RLock()
 closed := s.closed
 s.access.RUnlock()
 if closed { return E.New("rule-set is closed") }
 if s.watcher != nil {
  err := s.watcher.Start()
  s.access.Lock()
  if err != nil { s.watcherState = "failed"; s.lastError = err.Error() } else { s.watcherState = "watching" }
  s.access.Unlock()
  if err != nil { s.logger.Error(E.Cause(err, "watch rule-set file")) }
 }
	return nil
}

func (s *LocalRuleSet) reloadFile(path string) (result error) {
 s.reloadAccess.Lock()
 var callbacks []adapter.RuleSetUpdateCallback
 defer func() {
  s.recordError(result)
  s.reloadAccess.Unlock()
  if result == nil { for _, callback := range callbacks { callback(s) } }
 }()
 var digest string
	var ruleSet option.PlainRuleSetCompat
	switch s.fileFormat {
	case C.RuleSetFormatSource, "":
		content, err := filemanager.ReadFile(s.ctx, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
 digest = hex.EncodeToString(sum[:])
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		setFile, err := filemanager.Open(s.ctx, path)
		if err != nil {
			return err
		}
		defer setFile.Close()
		h := sha256.New()
 reader := io.TeeReader(setFile, h)
 ruleSet, err = srs.Read(reader, false)
 if err == nil { _, err = io.Copy(io.Discard, reader) }
 digest = hex.EncodeToString(h.Sum(nil))
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.fileFormat)
	}
	plainRuleSet, err := mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet).Upgrade()
	if err != nil {
		return err
	}
	callbacks, result = s.prepareRules(plainRuleSet.Rules, digest)
 return result
}

func (s *LocalRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
 s.reloadAccess.Lock()
 callbacks, err := s.prepareRules(headlessRules, "")
 s.recordError(err)
 s.reloadAccess.Unlock()
 if err == nil { for _, callback := range callbacks { callback(s) } }
 return err
}

func (s *LocalRuleSet) prepareRules(headlessRules []option.HeadlessRule, digest string) ([]adapter.RuleSetUpdateCallback, error) {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return nil, err
	}
	return s.publish(rules, metadata, digest)
}

func (s *LocalRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.loadSnapshot().metadata
}

func (s *LocalRuleSet) ExtractIPSet() []*netipx.IPSet {
	return common.FlatMap(s.loadSnapshot().rules, extractIPSetFromRule)
}

func (s *LocalRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *LocalRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *LocalRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.cleanupPublication()
	}
}

func (s *LocalRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *LocalRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *LocalRuleSet) Close() error {
	s.lifecycleAccess.Lock()
 defer s.lifecycleAccess.Unlock()
 s.closePublication()
	return common.Close(common.PtrOrNil(s.watcher))
}

func (s *LocalRuleSet) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.loadSnapshot().rules, metadata)
}

func (s *LocalRuleSet) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.loadSnapshot().rules)
}
