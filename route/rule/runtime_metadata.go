package rule

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// RuntimeRuleSetMetadata computes requirements from frozen source options,
// without constructing rules, watchers, clients or native resources.
func RuntimeRuleSetMetadata(rules []option.HeadlessRule) adapter.RuleSetMetadata {
	return buildRuleSetMetadata(rules)
}
