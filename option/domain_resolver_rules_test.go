package option

import (
	"context"
	"reflect"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestDomainResolverRulesJSON(t *testing.T) {
	for _, raw := range []string{
		`"bootstrap"`,
		`{"server":"bootstrap","strategy":"prefer_ipv4","timeout":"2s"}`,
		`{"mode":"rules"}`,
		`{"mode":"rules","strategy":"prefer_ipv4","timeout":"2s","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":15,"client_subnet":"192.0.2.0/24"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var value DomainResolveOptions
			require.NoError(t, json.Unmarshal([]byte(raw), &value))
			content, err := json.Marshal(value)
			require.NoError(t, err)
			require.JSONEq(t, raw, string(content))
			var roundTrip DomainResolveOptions
			require.NoError(t, json.Unmarshal(content, &roundTrip))
			require.Equal(t, value, roundTrip)
		})
	}
	for _, raw := range []string{
		`{}`, `{"strategy":"prefer_ipv4"}`, `{"mode":"invalid","server":"bootstrap"}`,
		`{"mode":"rules","server":"bootstrap"}`, `{"mode":"rules","timeout":"-1s"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var value DomainResolveOptions
			require.Error(t, json.Unmarshal([]byte(raw), &value))
		})
	}
	// Reusing a value must not retain an earlier mode, server or strategy.
	value := DomainResolveOptions{Mode: DomainResolverModeRules, Strategy: DomainStrategy(C.DomainStrategyPreferIPv4)}
	require.NoError(t, json.Unmarshal([]byte(`"bootstrap"`), &value))
	require.Equal(t, DomainResolveOptions{Server: "bootstrap"}, value)
	require.NoError(t, json.Unmarshal([]byte(`{"mode":"rules"}`), &value))
	require.Equal(t, DomainResolveOptions{Mode: DomainResolverModeRules}, value)
	_, err := json.Marshal(DomainResolveOptions{Mode: DomainResolverModeRules, Server: "bootstrap"})
	require.Error(t, err)
}

func TestDomainResolverRulesSchema(t *testing.T) {
	content, err := schema.Generate(context.Background(), reflect.TypeFor[DomainResolveOptions]())
	require.NoError(t, err)
	var document struct {
		Defs map[string]struct {
			AnyOf []struct {
				Required   []string `json:"required"`
				Properties map[string]struct {
					Const string `json:"const"`
				} `json:"properties"`
			} `json:"anyOf"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(content, &document))
	variants := document.Defs["DomainResolver"].AnyOf
	require.Len(t, variants, 3)
	require.Equal(t, []string{"server"}, variants[1].Required)
	require.Equal(t, []string{"mode"}, variants[2].Required)
	require.Equal(t, DomainResolverModeRules, variants[2].Properties["mode"].Const)
	require.Equal(t, "", variants[2].Properties["server"].Const)
}
