package badversion

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPolarisPatchContract(t *testing.T) {
	data, err := os.ReadFile("../../scripts/ci/testdata/polaris-versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Valid      []string
		Newer      [][2]string
		SameSeries [][2]string
	}
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	for _, name := range contract.Valid {
		t.Run(name, func(t *testing.T) {
			for _, input := range []string{name, "v" + name, name + "-deadbee"} {
				version := Parse(input)
				if version.String() != name || Parse(version.String()).String() != name {
					t.Fatalf("lost raw patch identity: %q -> %q", input, version.String())
				}
			}
			if !IsValid(name) {
				t.Fatalf("canonical version rejected: %q", name)
			}
		})
	}
	for _, pair := range contract.Newer {
		newer, older := Parse(pair[0]), Parse(pair[1])
		assertPolarisUpgradeOrdering(t, newer, older)
	}
	for _, pair := range contract.SameSeries {
		for _, names := range [][2]string{pair, {pair[1], pair[0]}} {
			a, b := Parse(names[0]), Parse(names[1])
			// Sharing the upstream series does not make distinct Polaris patches equal.
			if a.Major != b.Major || a.Minor != b.Minor || a.Patch != b.Patch ||
				a.PreReleaseIdentifier != b.PreReleaseIdentifier || a.PreReleaseVersion != b.PreReleaseVersion {
				t.Errorf("patch identity changed upstream series: %s, %s", names[0], names[1])
			}
		}
	}
}

func TestPolarisPatchIdentityIsNotMachineInteger(t *testing.T) {
	for _, name := range []string{
		"1.15.0-polaris-alpha.12.999999999999999999999999999999",
		"1.15.0-polaris-alpha.99999999999999999999",
		"1.15.0-polaris-alpha.99999999999999999999.99999999999999999999",
	} {
		version := Parse(name)
		if version.String() != name {
			t.Fatal("valid numeric prerelease identity was narrowed to an integer")
		}
		data, err := json.Marshal(version)
		if err != nil || string(data) != `"`+name+`"` {
			t.Fatal("large numeric prerelease identity lost in JSON")
		}
		var decoded Version
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.String() != name {
			t.Fatal("large numeric prerelease identity lost on JSON round trip")
		}
	}
	// The existing int series API saturates on overflow; it must not wrap or become zero.
	if Parse("1.15.0-polaris-alpha.99999999999999999999.1").PreReleaseVersion <= 13 {
		t.Fatal("large upstream prerelease number wrapped or became zero")
	}
	for _, name := range []string{"1.15.0-polaris-alpha.01", "1.15.0-polaris-alpha.١", "1.15.0-polaris-alpha.", "1.15.0-polaris-beta.00", "1.15.0-polaris-rc.-1", "1.15.0-alpha.12.1"} {
		if Parse(name).preReleaseVersionString != "" {
			t.Errorf("retained malformed or unbranded raw identity: %q", name)
		}
	}
	for _, suffix := range []string{".01", ".-1", ".1.2", ".", ".a", ".١"} {
		if Parse("1.15.0-polaris-alpha.12"+suffix).preReleaseVersionString != "" {
			t.Errorf("retained malformed Polaris patch identity: %q", suffix)
		}
	}
}

func TestPolarisPatchJSONRoundTrip(t *testing.T) {
	for _, name := range []string{"1.15.0-polaris-alpha.12.1", "1.15.0-polaris-alpha.12.2"} {
		data, err := json.Marshal(Parse(name))
		if err != nil || string(data) != `"`+name+`"` {
			t.Fatalf("marshal lost raw identity: %s, %v", data, err)
		}
		var version Version
		if err := json.Unmarshal(data, &version); err != nil || version.String() != name {
			t.Fatalf("unmarshal lost raw identity: %s, %v", version.String(), err)
		}
	}
}

func TestPolarisPatchPreservesUpstreamLegacySpelling(t *testing.T) {
	if Parse("v1.3.0-beta1").String() != "1.3.0-beta.1" || Parse("v1.3.0-beta.1").BadString() != "1.3-beta1" {
		t.Fatal("legacy upstream spelling changed")
	}
	if Parse("1.15.0-alpha.12-deadbee").String() != "1.15.0-alpha.12" {
		t.Fatal("upstream commit suffix parsing changed")
	}
}

func assertPolarisUpgradeOrdering(t *testing.T, newer, older Version) {
	t.Helper()
	if !newer.GreaterThan(older) || !newer.GreaterThanOrEqual(older) || newer.LessThan(older) || newer.LessThanOrEqual(older) ||
		older.GreaterThan(newer) || older.GreaterThanOrEqual(newer) || !older.LessThan(newer) || !older.LessThanOrEqual(newer) {
		t.Errorf("upgrade ordering changed: %s > %s", newer.String(), older.String())
	}
}

func TestPolarisPatchNumericOrdering(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.15.0-polaris-alpha.12.0", "1.15.0-polaris-alpha.12"},
		{"1.15.0-polaris-alpha.12.10", "1.15.0-polaris-alpha.12.9"},
		{"1.15.0-polaris-alpha.12.123", "1.15.0-polaris-alpha.12.10"},
		{"1.15.0-polaris-alpha.13", "1.15.0-polaris-alpha.12.999999999999999999999999999999"},
		{"1.15.0-polaris-alpha.12.1000000000000000000000000000000", "1.15.0-polaris-alpha.12.999999999999999999999999999999"},
		{"1.15.0-polaris-alpha.100000000000000000000", "1.15.0-polaris-alpha.99999999999999999999.99999999999999999999"},
		{"1.15.0-polaris-beta.1.10", "1.15.0-polaris-beta.1.9"},
		{"1.15.0-polaris-rc.1.10", "1.15.0-polaris-rc.1.9"},
	} {
		t.Run(pair[0]+">"+pair[1], func(t *testing.T) {
			newer, older := Parse(pair[0]), Parse(pair[1])
			assertPolarisUpgradeOrdering(t, newer, older)
			var decoded [2]Version
			for i, version := range [2]Version{newer, older} {
				data, err := json.Marshal(version)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &decoded[i]); err != nil {
					t.Fatal(err)
				}
			}
			assertPolarisUpgradeOrdering(t, decoded[0], decoded[1])
		})
	}
}

func TestPolarisPatchComparisonEquality(t *testing.T) {
	for _, pair := range [][2]Version{
		{Parse("1.15.0-polaris-alpha.12"), {Major: 1, Minor: 15, PreReleaseIdentifier: "polaris-alpha", PreReleaseVersion: 12}},
		{Parse("1.15.0-polaris-alpha.12.10"), Parse("v1.15.0-polaris-alpha.12.10-deadbee")},
		{Parse("1.3.0-beta.1"), Parse("v1.3.0-beta1")},
		{Parse("6.14"), {Major: 6, Minor: 14}},
	} {
		for _, versions := range [][2]Version{pair, {pair[1], pair[0]}} {
			a, b := versions[0], versions[1]
			if a.GreaterThan(b) || a.LessThan(b) || !a.GreaterThanOrEqual(b) || !a.LessThanOrEqual(b) {
				t.Errorf("equivalent version comparison changed: %s, %s", a.String(), b.String())
			}
		}
	}
}
