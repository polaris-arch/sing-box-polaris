package option

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

// These are option/canonicalization tests only. Transport availability, platform
// constraints and HTTP/3's TLS requirement remain constructor responsibilities.
func TestHTTPVersionObjectVariantsRoundTrip(t *testing.T) {
	for _, kind := range []string{"outbound", "named-client", "inline-client"} {
		for _, version := range []int{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("%s/%d", kind, version), func(t *testing.T) {
				extra := ""
				if version == 0 || version == 2 {
					extra = `,"idle_timeout":"17s","max_concurrent_streams":7`
				}
				if version == 3 {
					extra = `,"idle_timeout":"19s","max_concurrent_streams":9,"initial_packet_size":1300,"disable_path_mtu_discovery":true`
				}
				input := fmt.Sprintf(`{"version":%d,"headers":{"X-Variant":"kept"}%s}`, version, extra)
				var first, second any
				switch kind {
				case "outbound":
					input = fmt.Sprintf(`{"server":"192.0.2.1","server_port":443,"username":"fixture","password":"fixture","tls":{"enabled":true,"server_name":"proxy.invalid"},"version":%d,"headers":{"X-Variant":"kept"}%s}`, version, extra)
					first, second = new(HTTPOutboundOptions), new(HTTPOutboundOptions)
				case "named-client":
					input = fmt.Sprintf(`{"tag":"named","version":%d,"headers":{"X-Variant":"kept"}%s}`, version, extra)
					first, second = new(HTTPClient), new(HTTPClient)
				case "inline-client":
					first, second = new(HTTPClientOptions), new(HTTPClientOptions)
				}
				if err := json.UnmarshalContext(context.Background(), []byte(input), first); err != nil {
					t.Fatal(err)
				}
				encoded, err := json.MarshalContext(context.Background(), first)
				if err != nil {
					t.Fatal("valid HTTP variant failed canonicalization", err)
				}
				if err = json.UnmarshalContext(context.Background(), encoded, second); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(first, second) {
					t.Fatalf("typed HTTP variant changed on roundtrip: %#v -> %#v", first, second)
				}
				var fields map[string]stdjson.RawMessage
				if err = stdjson.Unmarshal(encoded, &fields); err != nil {
					t.Fatal(err)
				}
				var actual int
				if field := fields["version"]; len(field) != 0 {
					if err = stdjson.Unmarshal(field, &actual); err != nil {
						t.Fatal(err)
					}
				}
				if actual != version {
					t.Fatalf("explicit HTTP version changed: %d -> %d (%s)", version, actual, encoded)
				}
				if version == 1 {
					if _, leaked := fields["idle_timeout"]; leaked {
						t.Fatal("HTTP/1 acquired HTTP/2 options")
					}
				}
			})
		}
	}
}

func TestHTTPInboundVersionVariantsRoundTrip(t *testing.T) {
	for _, versions := range []string{`null`, `[]`, `1`, `2`, `3`, `[1]`, `[1,2]`, `[3,1,2]`} {
		t.Run(versions, func(t *testing.T) {
			extra := ""
			if versions == `2` || versions == `[1,2]` || versions == `null` || versions == `[]` {
				extra = `,"idle_timeout":"17s","max_concurrent_streams":7`
			}
			if versions == `3` || versions == `[3,1,2]` {
				extra = `,"idle_timeout":"19s","max_concurrent_streams":9,"initial_packet_size":1300`
			}
			input := []byte(`{"listen":"127.0.0.1","listen_port":8443,"tls":{"enabled":true,"server_name":"fixture.invalid"},"version":` + versions + extra + `}`)
			var first, second HTTPInboundOptions
			if err := json.UnmarshalContext(context.Background(), input, &first); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatal("valid inbound variant failed canonicalization", err)
			}
			if err = json.UnmarshalContext(context.Background(), encoded, &second); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first.Versions(), second.Versions()) {
				t.Fatalf("inbound version selection changed: %#v -> %#v", first, second)
			}
			// An empty explicit list uses the omitted/default selection. JSON's
			// omitempty intentionally canonicalizes its slice representation.
			if len(first.Version) == 0 {
				first.Version = nil
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("inbound variant options changed: %#v -> %#v", first, second)
			}
		})
	}
}

func TestHTTPInvalidVersionsAndForeignVariantFieldsRemainRejected(t *testing.T) {
	for _, input := range []string{`{"version":-1}`, `{"version":4}`, `{"version":1,"idle_timeout":"1s"}`, `{"version":2,"initial_packet_size":1300}`} {
		for _, value := range []any{new(HTTPOutboundOptions), new(HTTPClient), new(HTTPClientOptions)} {
			if err := json.UnmarshalContext(context.Background(), []byte(input), value); err == nil {
				t.Fatalf("invalid version/foreign fields accepted: %s / %T", input, value)
			}
		}
	}
	for _, input := range []string{`{"version":0}`, `{"version":[1,0]}`, `{"version":[3,4]}`, `{"version":1,"idle_timeout":"1s"}`, `{"version":2,"initial_packet_size":1300}`} {
		var value HTTPInboundOptions
		if err := json.UnmarshalContext(context.Background(), []byte(input), &value); err == nil {
			t.Fatalf("invalid inbound variant accepted: %s", input)
		}
	}
	for _, value := range []any{HTTPOutboundOptions{Version: -1}, HTTPClient{Version: 4}, HTTPClientOptions{Version: 4}, HTTPInboundOptions{Version: []int{1, 0}}, HTTPInboundOptions{Version: []int{2, 4}}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatalf("invalid programmatic HTTP version encoded: %T", value)
		}
	}
	// The HTTP fix must not make null, scalar or array objects legal globally.
	for _, nonObject := range []any{nil, "value", 1, []int{1}} {
		if _, err := badjson.MarshallObjects(struct{}{}, nonObject); err == nil {
			t.Fatalf("object merger accepted %T", nonObject)
		}
	}
}

func TestHTTPClientNamedReferenceAndSharedMASQUEH1VariantPreserveShape(t *testing.T) {
	var reference HTTPClientOptions
	if err := json.UnmarshalContext(context.Background(), []byte(`"shared"`), &reference); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(reference)
	if err != nil || string(encoded) != `"shared"` {
		t.Fatal("named reference became object", string(encoded), err)
	}
	for _, value := range []any{MASQUEClientEndpointOptions{Version: 1}, MASQUEServerEndpointOptions{Version: []int{1}}} {
		encoded, err = json.Marshal(value)
		if err != nil {
			t.Fatal("shared H1 helper broke MASQUE", err)
		}
		var fields map[string]stdjson.RawMessage
		if err = stdjson.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["version"]; !ok {
			t.Fatal("MASQUE H1 version was lost")
		}
	}
}
