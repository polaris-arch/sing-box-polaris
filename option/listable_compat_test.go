package option

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Listable retains assignment compatibility with the existing slice consumers.
var (
	_ []TailcatDERPServer = TailcatDERPOptions{}.DERPServers
	_ []netip.Prefix      = MASQUEClientEndpointOptions{}.AdvertiseRoutes
	_ []netip.Prefix      = MASQUEServerEndpointOptions{}.AdvertiseRoutes
)

func TestTailcatDERPServersListableJSON(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input string
		want  []TailcatDERPServer
	}{
		{"single_string", `"derp.example"`, []TailcatDERPServer{{Host: "derp.example"}}},
		{"single_object", `{"host":"derp.example","derp_port":8443,"stun_port":3478}`, []TailcatDERPServer{{Host: "derp.example", DERPPort: 8443, STUNPort: 3478}}},
		{"one_element_array", `["derp.example"]`, []TailcatDERPServer{{Host: "derp.example"}}},
		{"mixed_array", `["first.example",{"host":"second.example","ipv4":"192.0.2.1"}]`, []TailcatDERPServer{{Host: "first.example"}, {Host: "second.example", IPv4: "192.0.2.1"}}},
		{"empty_array", `[]`, nil},
		{"null", `null`, nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var options TailcatDERPOptions
			require.NoError(t, json.Unmarshal([]byte(`{"derp_servers":`+testCase.input+`}`), &options))
			require.Len(t, options.DERPServers, len(testCase.want))
			for index, server := range testCase.want {
				require.Equal(t, server, options.DERPServers[index])
			}
			encoded, err := json.Marshal(options)
			require.NoError(t, err)
			var roundTrip TailcatDERPOptions
			require.NoError(t, json.Unmarshal(encoded, &roundTrip))
			require.Len(t, roundTrip.DERPServers, len(options.DERPServers))
			for index, server := range options.DERPServers {
				require.Equal(t, server, roundTrip.DERPServers[index])
			}
		})
	}
	for _, input := range []string{
		`true`, `42`, `{"host":42}`, `{"host":"derp.example","unknown":true}`,
		`{"host":"derp.example","derp_port":65536}`, `["derp.example",false]`, `[["derp.example"]]`,
	} {
		t.Run("reject_"+input, func(t *testing.T) {
			var options TailcatDERPOptions
			require.Error(t, json.Unmarshal([]byte(`{"derp_servers":`+input+`}`), &options))
		})
	}
	var omitted TailcatDERPOptions
	require.NoError(t, json.Unmarshal([]byte(`{}`), &omitted))
	require.Empty(t, omitted.DERPServers)
}

func TestMASQUEAdvertiseRoutesListableJSON(t *testing.T) {
	for _, server := range []bool{false, true} {
		name := "client"
		if server {
			name = "server"
		}
		decode := func(content []byte) ([]netip.Prefix, []byte, error) {
			if server {
				var options MASQUEServerEndpointOptions
				if err := json.UnmarshalContext(context.Background(), content, &options); err != nil {
					return nil, nil, err
				}
				encoded, err := json.Marshal(options)
				return options.AdvertiseRoutes, encoded, err
			}
			var options MASQUEClientEndpointOptions
			if err := json.UnmarshalContext(context.Background(), content, &options); err != nil {
				return nil, nil, err
			}
			encoded, err := json.Marshal(options)
			return options.AdvertiseRoutes, encoded, err
		}
		for _, testCase := range []struct {
			name  string
			input string
			want  []string
		}{
			{"single_ipv4", `"192.0.2.0/24"`, []string{"192.0.2.0/24"}},
			{"single_ipv6", `"2001:db8::/32"`, []string{"2001:db8::/32"}},
			{"one_element_array", `["192.0.2.0/24"]`, []string{"192.0.2.0/24"}},
			{"mixed_array", `["192.0.2.0/24","2001:db8::/32"]`, []string{"192.0.2.0/24", "2001:db8::/32"}},
			{"empty_array", `[]`, nil},
			{"null", `null`, nil},
		} {
			t.Run(name+"/"+testCase.name, func(t *testing.T) {
				routes, encoded, err := decode([]byte(`{"version":1,"advertise_routes":` + testCase.input + `}`))
				require.NoError(t, err)
				require.Len(t, routes, len(testCase.want))
				for index, prefix := range testCase.want {
					require.Equal(t, netip.MustParsePrefix(prefix), routes[index])
				}
				roundTrip, _, err := decode(encoded)
				require.NoError(t, err)
				require.Len(t, roundTrip, len(routes))
				for index, prefix := range routes {
					require.Equal(t, prefix, roundTrip[index])
				}
			})
		}
		for _, input := range []string{`true`, `42`, `{}`, `"not-a-prefix"`, `"192.0.2.0/33"`, `"2001:db8::/129"`, `["192.0.2.0/24",false]`, `[["192.0.2.0/24"]]`} {
			t.Run(name+"/reject_"+input, func(t *testing.T) {
				_, _, err := decode([]byte(`{"version":1,"advertise_routes":` + input + `}`))
				require.Error(t, err)
			})
		}
		routes, _, err := decode([]byte(`{"version":1}`))
		require.NoError(t, err)
		require.Empty(t, routes)
	}
}

// HTTP/1 has no additional version-options object; HTTP/2 and HTTP/3 do.
// All supported variants must retain the routes through the public JSON methods.
func TestMASQUEVersionRoutesRoundTrip(t *testing.T) {
	for _, version := range []string{"0", "1", "2", "3"} {
		t.Run("client/"+version, func(t *testing.T) {
			var options MASQUEClientEndpointOptions
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"version":`+version+`,"advertise_routes":"192.0.2.0/24"}`), &options))
			encoded, err := json.Marshal(options)
			require.NoError(t, err)
			var roundTrip MASQUEClientEndpointOptions
			require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &roundTrip))
			require.Equal(t, options.Version, roundTrip.Version)
			require.Equal(t, options.AdvertiseRoutes, roundTrip.AdvertiseRoutes)
		})
	}
	for _, version := range []string{"[]", "[1]", "[2]", "[3]", "[1,2]", "[1,3]", "[1,2,3]"} {
		t.Run("server/"+version, func(t *testing.T) {
			var options MASQUEServerEndpointOptions
			require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"version":`+version+`,"advertise_routes":"2001:db8::/32"}`), &options))
			encoded, err := json.Marshal(options)
			require.NoError(t, err)
			var roundTrip MASQUEServerEndpointOptions
			require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &roundTrip))
			require.Equal(t, options.Versions(), roundTrip.Versions())
			require.Equal(t, options.AdvertiseRoutes, roundTrip.AdvertiseRoutes)
		})
	}
}
