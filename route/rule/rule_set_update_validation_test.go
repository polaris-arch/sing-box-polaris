package rule

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
)

type fakeDNSRuleSetUpdateValidator struct {
	validate func(tag string, metadata adapter.RuleSetMetadata) error
}

func (v *fakeDNSRuleSetUpdateValidator) ValidateRuleSetMetadataUpdate(tag string, metadata adapter.RuleSetMetadata) error {
	if v.validate == nil {
		return nil
	}
	return v.validate(tag, metadata)
}

func TestLocalRuleSetReloadRulesRejectsInvalidUpdateBeforeCommit(t *testing.T) {
	t.Parallel()

	var callbackCount atomic.Int32
	rejectEmpty := false
	ctx := service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), &fakeDNSRuleSetUpdateValidator{
		validate: func(tag string, metadata adapter.RuleSetMetadata) error {
			require.Equal(t, "dynamic-set", tag)
			if metadata.ContainsDNSQueryTypeRule {
				return E.New("dns conflict")
			}
			if rejectEmpty && metadata == (adapter.RuleSetMetadata{}) {
				return E.New("empty metadata conflict")
			}
			return nil
		},
	})
	ruleSet := &LocalRuleSet{
		ctx:        ctx,
		tag:        "dynamic-set",
		fileFormat: C.RuleSetFormatSource,
	}
	_ = ruleSet.callbacks.PushBack(func(adapter.RuleSet) {
		callbackCount.Add(1)
	})

	err := ruleSet.reloadRules([]option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			Domain: badoption.Listable[string]{"example.com"},
		},
	}})
	require.NoError(t, err)
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))

	err = ruleSet.reloadRules([]option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			QueryType: badoption.Listable[option.DNSQueryType]{option.DNSQueryType(1)},
		},
	}})
	require.ErrorContains(t, err, "dns conflict")
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))

	accepted := ruleSet.loadSnapshot()
	rejectEmpty = true
	err = ruleSet.reloadRules(nil)
	require.ErrorContains(t, err, "empty metadata conflict")
	require.Same(t, accepted, ruleSet.loadSnapshot())
	require.Equal(t, int32(1), callbackCount.Load())
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
	rejectEmpty = false
	err = ruleSet.reloadRules(nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), callbackCount.Load())
	require.Equal(t, adapter.RuleSetMetadata{}, ruleSet.Metadata())
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
}

func TestHeadlessRuleEmptyConditionsAreNotEmptyContainers(t *testing.T) {
	reject := func(t *testing.T, content string) {
		t.Helper()
		var options option.HeadlessRule
		require.NoError(t, json.Unmarshal([]byte(content), &options))
		_, err := NewHeadlessRule(context.Background(), options)
		require.ErrorContains(t, err, "missing conditions")
	}
	fields := reflect.TypeFor[option.DefaultHeadlessRule]()
	for i := range fields.NumField() {
		field := fields.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.Type.Kind() != reflect.Slice || name == "" || name == "-" {
			continue
		}
		for _, value := range []string{"null", "[]"} {
			t.Run(name+"="+value, func(t *testing.T) {
				reject(t, `{"`+name+`":`+value+`}`)
			})
		}
		t.Run(name+"=typed empty slice", func(t *testing.T) {
			options := option.HeadlessRule{Type: C.RuleTypeDefault}
			reflect.ValueOf(&options.DefaultOptions).Elem().Field(i).Set(reflect.MakeSlice(field.Type, 0, 0))
			// This is the nonnil [] path that passes the original IsValid check.
			require.True(t, options.DefaultOptions.IsValid())
			_, err := NewHeadlessRule(context.Background(), options)
			require.ErrorContains(t, err, "missing conditions")
			for _, mode := range []string{C.LogicalTypeAnd, C.LogicalTypeOr} {
				logical := option.HeadlessRule{
					Type: C.RuleTypeLogical,
					LogicalOptions: option.LogicalHeadlessRule{
						Mode:  mode,
						Rules: []option.HeadlessRule{options},
					},
				}
				require.True(t, logical.LogicalOptions.IsValid())
				_, err := NewHeadlessRule(context.Background(), logical)
				require.ErrorContains(t, err, "missing conditions")
			}
		})
	}
	for _, content := range []string{
		`{}`,
		`{"invert":true}`,
		`{"ip_cidr":[],"invert":true}`,
		`{"type":"logical","mode":"and","rules":[]}`,
		`{"type":"logical","mode":"or","rules":[]}`,
		`{"type":"logical","mode":"and","rules":[{"ip_cidr":[]}]}`,
		`{"type":"logical","mode":"or","rules":[{"domain":[]}]}`,
		`{"type":"logical","mode":"and","rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":[]}]}]}`,
	} {
		t.Run(content, func(t *testing.T) { reject(t, content) })
	}
}

func TestRuleSetTypedDecodingRetainsEmptyRuleElements(t *testing.T) {
	for _, test := range []struct {
		rules string
		count int
	}{
		{`[{}]`, 1},
		{`[{"ip_cidr":[]}]`, 1},
		{`[{}, {"domain":[]}]`, 2},
		{`[{"invert":true}]`, 1},
		{`[{"type":"logical","mode":"and","rules":[{"ip_cidr":[]}]}]`, 1},
		{`[{"type":"logical","mode":"or","rules":[{"domain":[]}]}]`, 1},
	} {
		t.Run(test.rules, func(t *testing.T) {
			content := []byte(`{/* source comment */"version":3,"rules":` + test.rules + `}`)
			compatible, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
			require.NoError(t, err)
			require.Equal(t, test.count, len(compatible.Options.Rules))
			require.NotEmpty(t, compatible.RawMessage)
			plain, err := compatible.Upgrade()
			require.NoError(t, err)
			_, err = NewLocalRuleSet(context.Background(), logger.NOP(), "source", option.RuleSet{
				Type:          C.RuleSetTypeInline,
				InlineOptions: plain,
			})
			require.ErrorContains(t, err, "missing conditions")
			inline, err := json.UnmarshalExtended[option.RuleSet]([]byte(`{/* inline comment */"type":"inline","tag":"inline","rules":` + test.rules + `}`))
			require.NoError(t, err)
			require.Equal(t, test.count, len(inline.InlineOptions.Rules))
			encoded, err := json.Marshal(inline)
			require.NoError(t, err)
			roundtrip, err := json.UnmarshalExtended[option.RuleSet](encoded)
			require.NoError(t, err)
			require.Equal(t, test.count, len(roundtrip.InlineOptions.Rules))
			_, err = NewLocalRuleSet(context.Background(), logger.NOP(), "inline", inline)
			require.ErrorContains(t, err, "missing conditions")
		})
	}
	for _, version := range []uint8{1, 2, 3, 4, 5} {
		for _, rules := range []string{"null", "[]"} {
			content := []byte(fmt.Sprintf(`{/* empty */"version":%d,"rules":%s}`, version, rules))
			compatible, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
			require.NoError(t, err)
			require.Equal(t, version, compatible.Version)
			require.Empty(t, compatible.Options.Rules)
			require.NotEmpty(t, compatible.RawMessage)
			set, err := NewLocalRuleSet(context.Background(), logger.NOP(), "empty", option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: compatible.Options})
			require.NoError(t, err)
			require.False(t, set.Match(&adapter.InboundContext{Domain: "example.org"}))
			require.NoError(t, set.Close())
		}
	}
	raw := []byte(`{/* direct decoder input */"version":3,"rules":[]}`)
	original := append([]byte(nil), raw...)
	var direct option.PlainRuleSetCompat
	require.NoError(t, direct.UnmarshalJSON(raw))
	require.True(t, bytes.Equal(original, direct.RawMessage))
	for _, content := range []string{
		`{"version":3,"rules":[],"unknown":[]}`,
		`{"version":3,"rules":[{"unknown":true}]}`,
		`{"version":255,"rules":[]}`,
		`{"rules":[]}`,
		`{"version":3,"rules":{}}`,
	} {
		_, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(content))
		require.Error(t, err, content)
	}
	for _, content := range []string{
		`{"type":"inline","tag":"bad","rules":[],"unknown":[]}`,
		`{"type":"inline","rules":[]}`,
		`{"type":"unknown","tag":"bad","rules":[]}`,
		`{"type":"inline","tag":["a","b"],"rules":[]}`,
	} {
		_, err := json.UnmarshalExtended[option.RuleSet]([]byte(content))
		require.Error(t, err, content)
	}
	inline, err := json.UnmarshalExtended[option.RuleSet]([]byte(`{"tag":"empty","format":"ignored-for-inline","rules":[]}`))
	require.NoError(t, err)
	require.Equal(t, C.RuleSetTypeInline, inline.Type)
	require.Empty(t, inline.Format)
}

func TestValidInlineRuleSetCanonicalEncodingIsUnchanged(t *testing.T) {
	for _, content := range []string{
		`{"tag":"sites","rules":[]}`,
		`{"type":"inline","tag":["sites"],"rules":null}`,
		`{"type":"inline","tag":"sites","rules":[{"domain":["example.org"]}]}`,
		`{"tag":"sites","rules":[{"ip_cidr":["192.0.2.7/32"]}]}`,
		`{"tag":"sites","rules":[{"type":"logical","mode":"or","rules":[{"network":"tcp"},{"domain":"example.org"}]}]}`,
	} {
		t.Run(content, func(t *testing.T) {
			inline, err := json.UnmarshalExtended[option.RuleSet]([]byte(content))
			require.NoError(t, err)
			for _, format := range []string{"", C.RuleSetFormatSource} {
				inline.Format = format
				// This is the old inline marshaler, including Type normalization,
				// Listable tag encoding, Format and omission of empty rules.
				legacy, err := badjson.MarshallObjects(struct {
					Type   string                     `json:"type,omitempty"`
					Tag    badoption.Listable[string] `json:"tag"`
					Format string                     `json:"format,omitempty"`
				}{Tag: inline.Tag, Format: inline.Format}, inline.InlineOptions)
				require.NoError(t, err)
				legacy, err = json.Marshal(json.RawMessage(legacy))
				require.NoError(t, err)
				actual, err := json.Marshal(inline)
				require.NoError(t, err)
				require.True(t, bytes.Equal(legacy, actual), "legacy=%s actual=%s", legacy, actual)
			}
		})
	}
}

func TestHeadlessRuleConditionGroupsRemainValid(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		match   adapter.InboundContext
		miss    adapter.InboundContext
	}{
		{"domain", `{"domain":["valid.example"]}`, adapter.InboundContext{Domain: "valid.example"}, adapter.InboundContext{Domain: "other.example"}},
		{"destination IPv4", `{"ip_cidr":["192.0.2.7/32"]}`, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.8:443")}},
		{"destination IPv6", `{"ip_cidr":["2001:db8::7/128"]}`, adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::7]:443")}, adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::8]:443")}},
		{"source", `{"source_ip_cidr":["198.51.100.7/32"]}`, adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.7:1234")}, adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.8:1234")}},
		{"source port", `{"source_port":[1234]}`, adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.7:1234")}, adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.7:1235")}},
		{"destination port", `{"port":[443]}`, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:80")}},
		{"network", `{"network":["tcp"]}`, adapter.InboundContext{Network: N.NetworkTCP}, adapter.InboundContext{Network: N.NetworkUDP}},
		{"invert", `{"domain":["blocked.example"],"invert":true}`, adapter.InboundContext{Domain: "valid.example"}, adapter.InboundContext{Domain: "blocked.example"}},
		{"logical", `{"type":"logical","mode":"and","rules":[{"domain":["valid.example"]},{"network":["tcp"]}]}`, adapter.InboundContext{Domain: "valid.example", Network: N.NetworkTCP}, adapter.InboundContext{Domain: "other.example", Network: N.NetworkTCP}},
		{"logical or", `{"type":"logical","mode":"or","rules":[{"domain":["valid.example"]},{"network":["udp"]}]}`, adapter.InboundContext{Domain: "valid.example", Network: N.NetworkTCP}, adapter.InboundContext{Domain: "other.example", Network: N.NetworkTCP}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options option.HeadlessRule
			require.NoError(t, json.Unmarshal([]byte(test.content), &options))
			rule, err := NewHeadlessRule(context.Background(), options)
			require.NoError(t, err)
			require.True(t, rule.Match(&test.match))
			require.False(t, rule.Match(&test.miss))
		})
	}
}

func TestRemoteRuleSetLoadBytesRejectsInvalidUpdateBeforeCommit(t *testing.T) {
	t.Parallel()

	var callbackCount atomic.Int32
	ctx := service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), &fakeDNSRuleSetUpdateValidator{
		validate: func(tag string, metadata adapter.RuleSetMetadata) error {
			require.Equal(t, "dynamic-set", tag)
			if metadata.ContainsDNSQueryTypeRule {
				return E.New("dns conflict")
			}
			return nil
		},
	})
	ctx = filemanager.WithDefault(ctx, "", t.TempDir(), os.Getuid(), os.Getgid())
	ruleSet := &RemoteRuleSet{
		ctx:    ctx,
		logger: logger.NOP(),
		tag:    "dynamic-set",
		options: option.RuleSet{
			Format: C.RuleSetFormatSource,
		},
		callbacks: list.List[adapter.RuleSetUpdateCallback]{},
	}
	_ = ruleSet.callbacks.PushBack(func(adapter.RuleSet) {
		callbackCount.Add(1)
	})

	err := ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`))
	require.NoError(t, err)
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))

	err = ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"query_type":["A"]}]}`))
	require.ErrorContains(t, err, "dns conflict")
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
}
