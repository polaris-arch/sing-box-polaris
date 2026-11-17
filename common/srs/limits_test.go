package srs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSRSByteLimitsAndContainerCompatibility(t *testing.T) {
	body := []byte{1, 0, ruleItemFinal, 0}
	encoded := craftRuleSet(body)
	limits := ReadLimits{InputBytes: int64(len(encoded)), DecodedBytes: int64(len(body))}
	container := bytes.NewReader(append(append([]byte(nil), encoded...), []byte("outside")...))
	if _, err := ReadContextWithLimits(context.Background(), container, false, limits); err != nil {
		t.Fatal(err)
	}
	tail, _ := io.ReadAll(container)
	if string(tail) != "outside" {
		t.Fatalf("consumed container trailer %q", tail)
	}
	for _, limit := range []ReadLimits{{InputBytes: int64(len(encoded) - 1)}, {DecodedBytes: int64(len(body) - 1)}} {
		if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(encoded), false, limit); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("expected byte budget error, got %v", err)
		}
	}
	// A tiny compressed representation must not bypass the decompressed budget.
	bomb := append([]byte{1, 0, ruleItemDomainKeyword, 1}, uvarint(100_000)...)
	bomb = append(bomb, bytes.Repeat([]byte{'x'}, 100_000)...)
	bomb = append(bomb, ruleItemFinal, 0)
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(craftRuleSet(bomb)), false, ReadLimits{DecodedBytes: 1024}); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
}

func TestSRSCountsAreRejectedBeforeTheirPayload(t *testing.T) {
	huge := uvarint(math.MaxUint64)
	hugeIPCount := make([]byte, 8)
	binary.BigEndian.PutUint64(hugeIPCount, math.MaxUint64)
	tests := []struct {
		name   string
		body   []byte
		limits ReadLimits
	}{
		{"top rules", huge, ReadLimits{}},
		{"logical children", append([]byte{1, 1, 0}, huge...), ReadLimits{}},
		{"string list", append([]byte{1, 0, ruleItemDomainKeyword}, huge...), ReadLimits{}},
		{"single string", append([]byte{1, 0, ruleItemDomainKeyword, 1}, huge...), ReadLimits{}},
		{"numeric list", append([]byte{1, 0, ruleItemPort}, huge...), ReadLimits{}},
		{"IP ranges", append([]byte{1, 0, ruleItemIPCIDR, 1}, hugeIPCount...), ReadLimits{}},
		{"prefixes", append([]byte{1, 0, ruleItemDefaultInterfaceAddress}, huge...), ReadLimits{}},
		{"interface map", append([]byte{1, 0, ruleItemNetworkInterfaceAddress}, huge...), ReadLimits{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadContextWithLimits(context.Background(), bytes.NewReader(craftRuleSet(tt.body)), false, tt.limits)
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("count reached payload or overflowed: %v", err)
			}
		})
	}
}

func TestSRSBudgetsAreCumulativeAndExplicitlyAdjustable(t *testing.T) {
	// Logical parent plus two empty children uses three rules, not just one top rule.
	body := []byte{1, 1, 0, 2, 0, ruleItemFinal, 0, 0, ruleItemFinal, 0, 0}
	data := craftRuleSet(body)
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), false, ReadLimits{Rules: 2}); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), false, ReadLimits{Rules: 3}); err != nil {
		t.Fatal(err)
	}
	// Two fields cannot each independently consume the entire entry allowance.
	body = []byte{1, 0, ruleItemDomainKeyword, 1, 1, 'a', ruleItemDomainRegex, 1, 1, 'b', ruleItemFinal, 0}
	data = craftRuleSet(body)
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), false, ReadLimits{Entries: 4}); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), false, ReadLimits{Entries: 5}); err != nil {
		t.Fatal(err)
	}
}

func TestReadContentRejectsOverflowWithoutTruncationSuccess(t *testing.T) {
	for _, n := range []int{0, 3, 4} {
		data, err := ReadContent(bytes.NewReader(bytes.Repeat([]byte{'x'}, n)), 3)
		if n <= 3 {
			if err != nil || len(data) != n {
				t.Fatalf("boundary: %v %q", err, data)
			}
		} else if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("overflow accepted: %v", err)
		}
	}
	if _, err := ReadContent(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative input budget")
	}
	if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(nil), false, ReadLimits{DecodedBytes: -1}); err == nil {
		t.Fatal("negative decode budget")
	}
}

func TestSRSDefaultLimitsAcceptVersionedWriterOutput(t *testing.T) {
	for version := uint8(1); version <= C.RuleSetVersionCurrent; version++ {
		var data bytes.Buffer
		rules := option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"example.com"}, DomainSuffix: []string{"example.org"}}}}}
		if err := Write(&data, rules, version); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(&data, false); err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
	}
}
