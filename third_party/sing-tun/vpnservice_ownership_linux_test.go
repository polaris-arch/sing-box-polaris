//go:build linux

package tun

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type vpnFixture struct {
	rules                   []netlink.Rule
	mutations               int
	listErr, addErr, delErr error
}

func (f *vpnFixture) ops() vpnRuleOps {
	return vpnRuleOps{
		list: func() ([]netlink.Rule, error) {
			result := make([]netlink.Rule, len(f.rules))
			for i := range f.rules {
				result[i] = *cloneBypassRule(&f.rules[i])
				result[i].MarkSet = false
				result[i].Type = 0
			}
			return result, f.listErr
		},
		add: func(r *netlink.Rule) error {
			f.mutations++
			if f.addErr != nil {
				return f.addErr
			}
			f.rules = append(f.rules, *cloneBypassRule(r))
			return nil
		},
		del: func(r *netlink.Rule) error {
			f.mutations++
			if f.delErr != nil {
				return f.delErr
			}
			if !r.MarkSet {
				return errors.New("lost mark selector")
			}
			for i := range f.rules {
				if vpnKey(&f.rules[i]) == vpnKey(r) {
					f.rules = append(f.rules[:i], f.rules[i+1:]...)
					return nil
				}
			}
			return unix.ENOENT
		},
	}
}
func vpnTestRule() *netlink.Rule {
	r := netlink.NewRule()
	r.Family = unix.AF_INET
	r.Priority = 11000
	r.Table = 700
	r.Mark = 0x100
	r.Mask = 0xff00
	r.MarkSet = true
	return r
}
func TestVPNOwnedStableAndCleanup(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	r := vpnTestRule()
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err != nil {
		t.Fatal(err)
	}
	foreign := cloneBypassRule(r)
	foreign.Mark++
	f.rules = append(f.rules, *foreign)
	before := f.mutations
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err != nil || f.mutations != before {
		t.Fatalf("churn: %v", err)
	}
	if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 || len(f.rules) != 1 || vpnKey(&f.rules[0]) != vpnKey(foreign) {
		t.Fatal("foreign touched or debt remains")
	}
}
func TestVPNForeignAndEEXISTNotOwned(t *testing.T) {
	for _, existing := range []bool{false, true} {
		f := &vpnFixture{addErr: unix.EEXIST}
		r := vpnTestRule()
		if existing {
			f.rules = []netlink.Rule{*r}
		}
		var receipts []*netlink.Rule
		if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err == nil || len(receipts) != 0 {
			t.Fatal("foreign adopted")
		}
		if existing && f.mutations != 0 {
			t.Fatal("preflight mutated")
		}
	}
}
func TestVPNQueryAndDeleteFailureRetainDebt(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	r := vpnTestRule()
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err != nil {
		t.Fatal(err)
	}
	f.listErr = errors.New("query failed")
	before := f.mutations
	if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err == nil || len(receipts) != 1 || f.mutations != before {
		t.Fatal("query failure lost debt")
	}
	f.listErr = nil
	f.delErr = unix.EPERM
	if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err == nil || len(receipts) != 1 {
		t.Fatal("delete failure lost debt")
	}
	f.delErr = nil
	if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err != nil || len(receipts) != 0 {
		t.Fatal("retry failed", err)
	}
}
func TestVPNSelectorChangeAndDuplicateFailClosed(t *testing.T) {
	for _, kind := range []string{"invert", "dport", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			f := &vpnFixture{}
			var receipts []*netlink.Rule
			r := vpnTestRule()
			if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "invert":
				f.rules[0].Invert = true
			case "dport":
				f.rules[0].Dport = netlink.NewRulePortRange(53, 53)
			case "duplicate":
				f.rules = append(f.rules, f.rules[0])
			}
			before := f.mutations
			if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err == nil || len(receipts) != 1 || f.mutations != before {
				t.Fatal("changed/ambiguous rule touched")
			}
		})
	}
}
func TestVPNSameTablePriorityDifferentMarksAndFamilies(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	a := vpnTestRule()
	b := cloneBypassRule(a)
	b.Mark++
	b.IifName = "lo"
	c := cloneBypassRule(a)
	c.Family = unix.AF_INET6
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{a, b, c}, f.ops()); err != nil {
		t.Fatal(err)
	}
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{b, c}, f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 || len(f.rules) != 2 {
		t.Fatal("incorrect subset cleanup")
	}
	before := f.mutations
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{b, c}, f.ops()); err != nil || before != f.mutations {
		t.Fatal("churn", err)
	}
}
func TestVPNPartialAddRetainsOnlySuccess(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	a := vpnTestRule()
	b := cloneBypassRule(a)
	b.Mark++
	ops := f.ops()
	add := ops.add
	ops.add = func(r *netlink.Rule) error {
		if r.Mark == b.Mark {
			return unix.EEXIST
		}
		return add(r)
	}
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{a, b}, ops); err == nil || len(receipts) != 1 || vpnKey(receipts[0]) != vpnKey(a) {
		t.Fatal("wrong partial receipt")
	}
	if err := reconcileVPNServiceRules(&receipts, nil, f.ops()); err != nil || len(f.rules) != 0 {
		t.Fatal("rollback failed", err)
	}
}
func TestVPNMissingRuleRecreatedAndReceiptCopied(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	r := vpnTestRule()
	r.Dport = netlink.NewRulePortRange(53, 53)
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r}, f.ops()); err != nil {
		t.Fatal(err)
	}
	r.Dport = netlink.NewRulePortRange(80, 80)
	if receipts[0].Dport.Start != 53 {
		t.Fatal("receipt aliases desired")
	}
	desired := cloneBypassRule(receipts[0])
	f.rules = nil
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{desired}, f.ops()); err != nil || len(f.rules) != 1 || len(receipts) != 1 {
		t.Fatal("missing repair failed", err)
	}
}
func TestVPNLargeStableSet(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	desired := make([]*netlink.Rule, 4096)
	for i := range desired {
		desired[i] = vpnTestRule()
		desired[i].Table += i
	}
	if err := reconcileVPNServiceRules(&receipts, desired, f.ops()); err != nil {
		t.Fatal(err)
	}
	before := f.mutations
	if err := reconcileVPNServiceRules(&receipts, desired, f.ops()); err != nil || f.mutations != before {
		t.Fatal("large stable churn", err)
	}
}

func TestVPNIdenticalDesiredDeduplicated(t *testing.T) {
	f := &vpnFixture{}
	var receipts []*netlink.Rule
	r := vpnTestRule()
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r, cloneBypassRule(r)}, f.ops()); err != nil || len(receipts) != 1 || f.mutations != 1 {
		t.Fatal("duplicate add", err)
	}
	conflict := cloneBypassRule(r)
	conflict.Invert = true
	if err := reconcileVPNServiceRules(&receipts, []*netlink.Rule{r, conflict}, f.ops()); err == nil || f.mutations != 1 {
		t.Fatal("conflicting desired accepted")
	}
}
