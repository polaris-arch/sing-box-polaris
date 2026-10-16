package main

import "testing"

func TestCIVersionUpdateRequiresExplicitOptIn(t *testing.T) {
	for _, inCI := range []bool{false, true} {
		for _, nightly := range []bool{false, true} {
			for _, optIn := range []bool{false, true} {
				expected := inCI && !nightly && !optIn
				if requiresCommittedVersion(inCI, nightly, optIn) != expected {
					t.Fatalf("CI=%v nightly=%v explicit=%v", inCI, nightly, optIn)
				}
			}
		}
	}
}
