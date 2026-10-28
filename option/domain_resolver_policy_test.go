package option

import (
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestDomainResolverPolicyIsExplicitRulesOnly(t *testing.T) {
	for _, input := range []string{`{"mode":"rules","policy":""}`, `{"server":"bootstrap","policy":"node"}`, `{"mode":"rules","server":"bootstrap","policy":"node"}`} {
		var option DomainResolveOptions
		require.Error(t, json.Unmarshal([]byte(input), &option), input)
	}
	var scoped DomainResolveOptions
	require.NoError(t, json.Unmarshal([]byte(`{"mode":"rules","policy":"node-bootstrap","timeout":"2s","strategy":"prefer_ipv4"}`), &scoped))
	require.NotNil(t, scoped.Policy)
	require.Equal(t, "node-bootstrap", *scoped.Policy)
	encoded, err := json.Marshal(scoped)
	require.NoError(t, err)
	var again DomainResolveOptions
	require.NoError(t, json.Unmarshal(encoded, &again))
	require.Equal(t, scoped, again)
	var legacy DomainResolveOptions
	require.NoError(t, json.Unmarshal([]byte(`{"mode":"rules"}`), &legacy))
	require.Nil(t, legacy.Policy)
	require.NoError(t, json.Unmarshal([]byte(`"bootstrap"`), &legacy))
	require.Nil(t, legacy.Policy)
}

func TestPolicySchemaPreservesLogicalRespondMode(t *testing.T) {
	var logical DNSRule
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"type":"logical","mode":"and","rules":[{"domain":"example.com"}],"action":"respond"}`), &logical))
	require.Equal(t, "and", logical.LogicalOptions.Mode)
	require.Empty(t, logical.LogicalOptions.RespondOptions.Mode)
	encoded, err := schema.Generate(context.Background(), reflect.TypeFor[DNSRule]())
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(encoded, &document))
	defs := document["$defs"].(map[string]any)
	for _, raw := range defs["DNSLogicalRuleAction"].(map[string]any)["oneOf"].([]any) {
		properties := raw.(map[string]any)["properties"].(map[string]any)
		if properties["action"].(map[string]any)["const"] == "respond" {
			require.NotContains(t, properties, "mode")
			require.NotContains(t, properties, "fallback_rcode")
		}
	}
	nested := defs["NestedDNSRule"].(map[string]any)["oneOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	require.NotContains(t, nested, "resolver_policy")
	require.NotContains(t, nested, "response_class")
}
