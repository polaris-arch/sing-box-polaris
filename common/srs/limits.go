package srs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/varbin"
)

// ReadLimits are per-decoding admission limits, not a process RSS limit. Zero
// fields select the defaults. They do not change the SRS wire format. Trusted
// callers with larger datasets may explicitly increase individual limits.
// Domain matcher internals are bounded by DecodedBytes, rather than Entries.
type ReadLimits = option.RuleSetResourceLimits

const DefaultInputBytes int64 = 64 << 20

func DefaultReadLimits() ReadLimits {
	return ReadLimits{DefaultInputBytes, 256 << 20, 100_000, 4_000_000, 1 << 20}
}

var ErrResourceLimit = errors.New("SRS resource limit exceeded")

func limitError(kind string) error { return fmt.Errorf("%w: %s", ErrResourceLimit, kind) }

func ResolveReadLimits(l ReadLimits) (ReadLimits, error) {
	d := DefaultReadLimits()
	if l.InputBytes == 0 {
		l.InputBytes = d.InputBytes
	}
	if l.DecodedBytes == 0 {
		l.DecodedBytes = d.DecodedBytes
	}
	if l.Rules == 0 {
		l.Rules = d.Rules
	}
	if l.Entries == 0 {
		l.Entries = d.Entries
	}
	if l.StringBytes == 0 {
		l.StringBytes = d.StringBytes
	}
	if l.InputBytes < 0 || l.DecodedBytes < 0 {
		return l, errors.New("SRS byte limits must be positive")
	}
	return l, nil
}

// ReadSourceContextWithLimits applies input, rule count and logical depth
// limits before decoding a JSON rule-set. The remaining limits describe
// allocations and recovery from the binary representation.
func ReadSourceContextWithLimits(ctx context.Context, content []byte, limits ReadLimits) (option.PlainRuleSetCompat, error) {
	limits, err := ResolveReadLimits(limits)
	if err != nil {
		return option.PlainRuleSetCompat{}, err
	}
	return ReadSourceContextWithRuleBudget(ctx, content, limits.InputBytes, &limits.Rules)
}

// ReadSourceContextWithRuleBudget debits the declared rule nodes after a
// successful decode. A zero remaining budget admits only empty rule sets.
func ReadSourceContextWithRuleBudget(ctx context.Context, content []byte, inputBytes int64, remainingRules *uint64) (option.PlainRuleSetCompat, error) {
	var empty option.PlainRuleSetCompat
	if int64(len(content)) > inputBytes {
		return empty, limitError("input bytes")
	}
	remaining := *remainingRules
	decoder := json.NewDecoder(contextReader{ctx, bytes.NewReader(content)})
	token, err := decoder.Token()
	if err != nil {
		return empty, err
	}
	if token != json.Delim('{') {
		return empty, errors.New("rule-set source must be an object")
	}
	if err := checkSourceRuleObject(ctx, decoder, &remaining, 0); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	ruleSet, err := json.UnmarshalExtendedContext[option.PlainRuleSetCompat](ctx, content)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*remainingRules = remaining
	return ruleSet, nil
}

// Skip a value without materializing a second tree. The typed decoder below
// still validates every field and determines which condition is represented.
type skippedSourceValue struct{}

func (*skippedSourceValue) UnmarshalJSON([]byte) error { return nil }

func checkSourceRuleObject(ctx context.Context, decoder *json.Decoder, remaining *uint64, depth int) error {
	var skip skippedSourceValue
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		if name, ok := key.(string); !ok || !strings.EqualFold(name, "rules") {
			if err := decoder.Decode(&skip); err != nil {
				return err
			}
			continue
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil { // The typed format accepts null for a rule array.
			continue
		}
		if token != json.Delim('[') {
			return errors.New("rule-set source rules must be an array")
		}
		for decoder.More() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if *remaining == 0 {
				return limitError("rules")
			}
			if depth > maxLogicalRuleDepth {
				return errors.New("logical rule nested too deep")
			}
			*remaining--
			rule, err := decoder.Token()
			if err != nil {
				return err
			}
			if rule != json.Delim('{') {
				return errors.New("rule-set source rule must be an object")
			}
			if err := checkSourceRuleObject(ctx, decoder, remaining, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

// ReadContent bounds acquisition before io.ReadAll can grow without limit. It
// accepts exactly limit bytes and rejects one additional byte, never truncates.
func ReadContent(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("SRS input limit must be positive")
	}
	r := &byteLimitReader{reader: reader, remaining: limit, kind: "input bytes"}
	return io.ReadAll(r)
}

// LimitInput streams up to DefaultInputBytes and reports ErrResourceLimit when
// an additional input byte is read.
func LimitInput(reader io.Reader) io.Reader {
	return limitInput(reader, DefaultInputBytes)
}

type byteLimitReader struct {
	reader    io.Reader
	remaining int64
	kind      string
}

func (r *byteLimitReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n != 0 {
			return 0, limitError(r.kind)
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

// Preserve ByteReader exactly when the input supplies it. This avoids changing
// zlib's read-ahead behavior for callers carrying a trailer outside the stream.
type byteLimitByteReader struct {
	*byteLimitReader
	bytes io.ByteReader
}

func (r *byteLimitByteReader) ReadByte() (byte, error) {
	if r.remaining == 0 {
		return 0, limitError(r.kind)
	}
	b, err := r.bytes.ReadByte()
	if err == nil {
		r.remaining--
	}
	return b, err
}

func limitInput(reader io.Reader, max int64) io.Reader {
	limited := &byteLimitReader{reader: reader, remaining: max, kind: "input bytes"}
	if b, ok := reader.(io.ByteReader); ok {
		return &byteLimitByteReader{limited, b}
	}
	return limited
}

type decodeBudget struct {
	limits         ReadLimits
	rules, entries uint64
	recoveredBytes uint64
	ctx            context.Context
}
type budgetReader struct {
	varbin.Reader
	budget *decodeBudget
}

func resourceBudget(reader varbin.Reader) *decodeBudget {
	if r, ok := reader.(*budgetReader); ok {
		return r.budget
	}
	return nil // mmap and legacy helpers have their separate storage contract.
}

func claimEntries(reader varbin.Reader, count uint64) error {
	if b := resourceBudget(reader); b != nil {
		if count > b.limits.Entries-b.entries {
			return limitError("entries")
		}
		b.entries += count
	}
	return nil
}

func checkRules(reader varbin.Reader, count uint64) error {
	if b := resourceBudget(reader); b != nil && count > b.limits.Rules-b.rules {
		return limitError("rules")
	}
	return nil
}

func readLimitedSlice[T varbin.BaseData](reader varbin.Reader, order binary.ByteOrder) ([]T, error) {
	count, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	if err := claimEntries(reader, count); err != nil {
		return nil, err
	}
	return varbin.ReadSliceCount[T](reader, order, count)
}

func readLimitedString(reader varbin.Reader) ([]byte, error) {
	count, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	if b := resourceBudget(reader); b != nil && count > b.limits.StringBytes {
		return nil, limitError("string bytes")
	}
	return varbin.ReadSliceCount[byte](reader, binary.BigEndian, count)
}
