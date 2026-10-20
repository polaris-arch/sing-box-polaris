package box

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type runtimePersistenceFixture struct {
	calls       *[]string
	waitErr     error
	ackErr      error
	ackIdentity string
}

func (p *runtimePersistenceFixture) WaitPersistence(context.Context) error {
	*p.calls = append(*p.calls, "wait")
	return p.waitErr
}

func (p *runtimePersistenceFixture) AcknowledgePersistence(_ context.Context, identity string) error {
	*p.calls = append(*p.calls, "ack")
	p.ackIdentity = identity
	return p.ackErr
}

func TestRuntimeDurabilityWaitsForWriterAndExactAcknowledgement(t *testing.T) {
	failure := errors.New("durability failed")
	for _, test := range []struct {
		name                        string
		waitErr, persistErr, ackErr error
		want                        []string
	}{
		{"writer failure", failure, nil, nil, []string{"wait"}},
		{"snapshot failure", nil, failure, nil, []string{"wait", "persist"}},
		{"ack failure", nil, nil, failure, []string{"wait", "persist", "ack"}},
		{"complete", nil, nil, nil, []string{"wait", "persist", "ack"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			participant := &runtimePersistenceFixture{calls: &calls, waitErr: test.waitErr, ackErr: test.ackErr}
			identity := RuntimeIdentity{EffectiveDigest: "exact-effective-digest"}
			canonical := []byte("canonical")
			err := runtimePersistCommitted(context.Background(), identity, canonical, func(actual RuntimeIdentity, snapshot []byte) error {
				calls = append(calls, "persist")
				if actual != identity {
					t.Fatal("persistence identity changed")
				}
				snapshot[0] = 'X'
				return test.persistErr
			}, participant)
			wantErr := test.waitErr != nil || test.persistErr != nil || test.ackErr != nil
			if (err != nil) != wantErr {
				t.Fatalf("error = %v", err)
			}
			if !reflect.DeepEqual(calls, test.want) {
				t.Fatalf("calls = %v", calls)
			}
			if string(canonical) != "canonical" {
				t.Fatal("persistence callback mutated canonical snapshot")
			}
			if participant.ackIdentity != "" && participant.ackIdentity != identity.EffectiveDigest {
				t.Fatal("acknowledged a different configuration")
			}
		})
	}
}
