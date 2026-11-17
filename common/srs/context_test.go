package srs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestReadVerifiesChecksumAndRuleCount(t *testing.T) {
	var valid bytes.Buffer
	if err := Write(&valid, option.PlainRuleSet{}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	content := valid.Bytes()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated checksum", content[:len(content)-1]},
		{"extra decoded data", craftRuleSet([]byte{0, 1})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(tc.data), false); err == nil {
				t.Fatal("accepted incomplete stream")
			}
		})
	}
	corrupt := append([]byte(nil), content...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := Read(bytes.NewReader(corrupt), false); err == nil {
		t.Fatal("accepted corrupt checksum")
	}
	container := bytes.NewReader(append(append([]byte(nil), content...), []byte("container trailer")...))
	if _, err := Read(container, false); err != nil {
		t.Fatalf("outer trailing bytes compatibility: %v", err)
	}
	trailer, err := io.ReadAll(container)
	if err != nil || string(trailer) != "container trailer" {
		t.Fatalf("trailer consumed: %q, %v", trailer, err)
	}
}

func TestReadContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ReadContext(ctx, bytes.NewReader(craftRuleSet([]byte{0})), false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// Deterministically cancel while decoded bytes remain buffered, not at an IO
// boundary. This exercises inner varint/ReadByte loops as well as outer rules.
type readBudgetContext struct {
	context.Context
	remaining int
}

func (c *readBudgetContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}
func TestReadContextCancelsBufferedRules(t *testing.T) {
	body := uvarint(1000)
	for i := 0; i < 1000; i++ {
		body = append(body, 0, ruleItemFinal, 0)
	}
	data := craftRuleSet(body)
	if _, err := Read(bytes.NewReader(data), false); err != nil {
		t.Fatalf("invalid test fixture: %v", err)
	}
	ctx := &readBudgetContext{Context: context.Background(), remaining: 40}
	if _, err := ReadContext(ctx, bytes.NewReader(data), false); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
