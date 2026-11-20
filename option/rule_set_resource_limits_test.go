package option

import (
	"strings"
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestRuleSetResourceLimitsRoundTripAndOmission(t *testing.T) {
	for _, raw := range []string{
		`{"type":"local","tag":"test","path":"test.srs"}`,
		`{"type":"remote","tag":"test","url":"https://example.com/test.srs","resource_limits":{"input_bytes":134217728,"decoded_bytes":536870912,"rules":200000,"entries":8000000,"string_bytes":2097152}}`,
	} {
		var parsed RuleSet
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, "resource_limits") {
			var again RuleSet
			if err := json.Unmarshal(data, &again); err != nil {
				t.Fatal(err)
			}
			if again.ResourceLimits == nil || *again.ResourceLimits != *parsed.ResourceLimits {
				t.Fatal("limits lost")
			}
		} else if strings.Contains(string(data), "resource_limits") {
			t.Fatal("old configuration gained a limits field")
		}
	}
}
