package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestDERPSTUNListenOptionsMarshalJSONScalar(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input string
		want  string
	}{
		{"zero", `{}`, `false`},
		{"enabled", `{"enabled":true}`, `true`},
		{"enabled_with_port", `{"enabled":true,"listen_port":3478}`, `true`},
		{"disabled_with_port", `{"listen_port":3478}`, `false`},
		{"numeric_zero", `0`, `true`},
		{"numeric_port", `3478`, `true`},
		{"numeric_maximum", `65535`, `true`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var options DERPSTUNListenOptions
			require.NoError(t, json.Unmarshal([]byte(testCase.input), &options))
			content, err := json.Marshal(options)
			require.NoError(t, err)
			require.JSONEq(t, testCase.want, string(content))
		})
	}
}

func TestDERPSTUNListenOptionsMarshalJSONPreservesListenOptions(t *testing.T) {
	for _, raw := range []string{
		`{"enabled":true,"listen":"127.0.0.1","listen_port":3478}`,
		`{"enabled":true,"listen_port":3478,"bind_interface":"lo"}`,
		`{"enabled":true,"listen_port":3478,"reuse_addr":true}`,
		`{"enabled":true,"listen_port":3478,"udp_fragment":false}`,
		`{"enabled":true,"listen_port":3478,"udp_timeout":"30s"}`,
		`{"listen_port":3478,"bind_interface":"lo"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var options DERPSTUNListenOptions
			require.NoError(t, json.Unmarshal([]byte(raw), &options))
			content, err := json.Marshal(options)
			require.NoError(t, err)
			require.JSONEq(t, raw, string(content))
			var roundTrip DERPSTUNListenOptions
			require.NoError(t, json.Unmarshal(content, &roundTrip))
			require.Equal(t, options, roundTrip)
		})
	}
}

func TestDERPSTUNListenOptionsMarshalJSONInternalListenOptionsUseObjectForm(t *testing.T) {
	var options DERPSTUNListenOptions
	options.Enabled = true
	options.ListenPort = 3478
	options.UDPFragmentDefault = true
	content, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, `{"enabled":true,"listen_port":3478}`, string(content))
}
