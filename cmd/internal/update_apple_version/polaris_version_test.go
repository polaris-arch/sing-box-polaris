package main

import (
	"testing"

	"github.com/sagernet/sing-box/common/badversion"
)

func TestPolarisAppleMarketingVersion(t *testing.T) {
	for input, expected := range map[string]string{
		"1.15.0-polaris-alpha.12": "1.15.0",
		"1.15.0-alpha.12":         "1.15.0-alpha.12",
		"1.15.0":                  "1.15.0",
	} {
		if actual := appleMarketingVersion(badversion.Parse(input)); actual != expected {
			t.Fatalf("%s: got %s, expected %s", input, actual, expected)
		}
	}
}
