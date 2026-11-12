package box

import (
	"errors"
	"reflect"
	"testing"
)

func TestRuntimeDurabilityPersistsDetachedCanonicalSnapshot(t *testing.T) {
	failure := errors.New("durability failed")
	for _, test := range []struct {
		name       string
		persistErr error
	}{
		{"snapshot failure", failure},
		{"complete", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			identity := RuntimeIdentity{EffectiveDigest: "exact-effective-digest"}
			canonical := []byte("canonical")
			err := runtimePersistCommitted(identity, canonical, func(actual RuntimeIdentity, snapshot []byte) error {
				calls = append(calls, "persist")
				if actual != identity {
					t.Fatal("persistence identity changed")
				}
				snapshot[0] = 'X'
				return test.persistErr
			})
			if (err != nil) != (test.persistErr != nil) {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(calls, []string{"persist"}) {
				t.Fatalf("calls = %v", calls)
			}
			if string(canonical) != "canonical" {
				t.Fatal("persistence callback mutated canonical snapshot")
			}
		})
	}
}
