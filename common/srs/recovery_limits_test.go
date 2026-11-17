package srs

import (
	"bytes"
	"context"
	"errors"
	"github.com/sagernet/sing-box/common/ipset"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/domain"
)

func recoveryBudget(t *testing.T, limits ReadLimits) *budgetReader {
	t.Helper()
	limits, err := ResolveReadLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	return &budgetReader{Reader: bytes.NewReader(nil), budget: &decodeBudget{limits: limits, ctx: context.Background()}}
}

// A valid LOUDS chain with a leaf at each non-root node: O(n) encoded bytes,
// but n*(n+1)/2 total key bytes when expanded. Build it without giant strings.
func chainRecoveryFixture(n int) domain.Mmap {
	data := domain.Mmap{Leaves: make([]uint64, (n+1+63)/64), LabelBitmap: make([]uint64, (2*n+1+63)/64), Labels: bytes.Repeat([]byte{'a'}, n)}
	for node := 0; node < n; node++ {
		data.LabelBitmap[(2*node+1)/64] |= uint64(1) << uint((2*node+1)%64)
	}
	data.LabelBitmap[(2*n)/64] |= uint64(1) << uint((2*n)%64)
	for node := 1; node <= n; node++ {
		data.Leaves[node/64] |= uint64(1) << uint(node%64)
	}
	return data
}

func TestMatcherRecoveryRejectsQuadraticExpansionBeforeDump(t *testing.T) {
	data := chainRecoveryFixture(1000)
	r := recoveryBudget(t, ReadLimits{DecodedBytes: 10_000})
	if err := checkMatcherRecovery(r, data); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("quadratic expansion accepted: %v", err)
	}
	if r.budget.recoveredBytes != 0 || r.budget.entries != 0 {
		t.Fatal("failed preflight consumed budget")
	}
}

func TestMatcherRecoveryBudgetIsCumulative(t *testing.T) {
	data := chainRecoveryFixture(3) // 1+2+3 plus three four-byte decoration margins.
	r := recoveryBudget(t, ReadLimits{DecodedBytes: 36, Entries: 6, StringBytes: 3})
	for i := 0; i < 2; i++ {
		if err := checkMatcherRecovery(r, data); err != nil {
			t.Fatal(err)
		}
	}
	if r.budget.recoveredBytes != 36 || r.budget.entries != 6 {
		t.Fatal("wrong cumulative recovery accounting")
	}
	if err := checkMatcherRecovery(r, data); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("third matcher accepted: %v", err)
	}
	r = recoveryBudget(t, ReadLimits{StringBytes: 2})
	if err := checkMatcherRecovery(r, data); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("long key accepted: %v", err)
	}
	r = recoveryBudget(t, ReadLimits{Entries: 2})
	if err := checkMatcherRecovery(r, data); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("too many recovered keys: %v", err)
	}
}

func TestMatcherRecoveryChecksContextAndMalformedTopology(t *testing.T) {
	r := recoveryBudget(t, ReadLimits{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.budget.ctx = ctx
	if err := checkMatcherRecovery(r, chainRecoveryFixture(10)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, data := range []domain.Mmap{
		{},
		{Leaves: []uint64{1}, LabelBitmap: []uint64{1}}, // unsafe empty root key
		{Leaves: []uint64{0}, LabelBitmap: []uint64{3}}, // disconnected second node
		{Leaves: []uint64{0}, LabelBitmap: []uint64{2}}, // missing child terminator/label
		{LabelBitmap: []uint64{1}},                      // leaf storage absent
	} {
		r = recoveryBudget(t, ReadLimits{})
		if err := checkMatcherRecovery(r, data); err == nil {
			t.Fatal("malformed topology accepted")
		}
	}
}

func TestMatcherRecoveryAcceptsRealDomainAndAdGuardEncodings(t *testing.T) {
	r := recoveryBudget(t, ReadLimits{})
	matcher := domain.NewMatcher([]string{"a.example.com", "b.example.com"}, []string{"example.org"}, false)
	if err := checkMatcherRecovery(r, matcher.Mmap()); err != nil {
		t.Fatal(err)
	}
	adguard := domain.NewAdGuardMatcher([]string{"||example.com^", "|example.org^"})
	if err := checkMatcherRecovery(r, adguard.Mmap()); err != nil {
		t.Fatal(err)
	}
}

func TestIPSetRecoveryPreflightsRangeExpansion(t *testing.T) {
	set, err := ipset.FromRanges(nil, []ipset.Range6{{From: netip.MustParseAddr("::1").As16(), To: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe").As16()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := uint64(len(set.Prefixes()))
	if n != 254 {
		t.Fatalf("unexpected worst-case fixture prefixes %d", n)
	}
	for _, limits := range []ReadLimits{{Entries: n - 1}, {DecodedBytes: int64(n*128 - 1)}} {
		r := recoveryBudget(t, limits)
		if err := checkIPSetRecovery(r, set); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("expansion accepted: %v", err)
		}
		if r.budget.entries != 0 || r.budget.recoveredBytes != 0 {
			t.Fatal("failed preflight consumed budget")
		}
	}
	r := recoveryBudget(t, ReadLimits{Entries: n * 2, DecodedBytes: int64(n * 128 * 2)})
	for i := 0; i < 2; i++ {
		if err := checkIPSetRecovery(r, set); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkIPSetRecovery(r, set); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
}

func TestIPSetRecoveryBudgetAppliesToBothBinaryFields(t *testing.T) {
	set, err := ipset.FromRanges([]ipset.Range4{{From: 1, To: 0xfffffffe}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []byte{ruleItemSourceIPCIDR, ruleItemIPCIDR} {
		var body bytes.Buffer
		body.Write([]byte{1, 0, item})
		if err := writeIPSet(&body, set); err != nil {
			t.Fatal(err)
		}
		body.Write([]byte{ruleItemFinal, 0})
		data := craftRuleSet(body.Bytes())
		limits := ReadLimits{Entries: 3}
		if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), false, limits); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), true, limits); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("item %d unbounded recovery: %v", item, err)
		}
		limits.Entries = 1000
		recovered, err := ReadContextWithLimits(context.Background(), bytes.NewReader(data), true, limits)
		if err != nil {
			t.Fatal(err)
		}
		rule := recovered.Options.Rules[0].DefaultOptions
		if len(rule.IPCIDR)+len(rule.SourceIPCIDR) != len(set.Prefixes()) {
			t.Fatal("recovery changed prefix output")
		}
	}
}
