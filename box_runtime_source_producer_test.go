package box

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func runtimeTestLocalConfig(path string) []byte {
	inline := `{"type":"inline","tag":"sites","rules":[{"domain_suffix":["example.org"]}]}`
	local := fmt.Sprintf(`{"type":"local","tag":"sites","format":"source","path":%q}`, path)
	return []byte(strings.Replace(string(runtimeTestConfig(1080, "example.org")), inline, local, 1))
}

func runtimeTestSourceBytes(domain string) []byte {
	return []byte(fmt.Sprintf(`{"version":3,"rules":[{"domain_suffix":[%q]}]}`, domain))
}

func runtimeTestProducer(t *testing.T, f *runtimeTestFixture) *runtimeSourceProducer {
	t.Helper()
	f.box.runtime.access.Lock()
	defer f.box.runtime.access.Unlock()
	for _, resource := range f.box.runtime.resources {
		if resource.sourceProducer != nil {
			return resource.sourceProducer
		}
	}
	t.Fatal("actual source producer missing")
	return nil
}

func runtimeTestRequireCleanSourceAbort(t *testing.T, f *runtimeTestFixture, operation RuntimeConfigOperation, expected RuntimeIdentity) {
	t.Helper()
	if (operation.State != "ABORTING_UNAPPLIED" && operation.State != "ABORTED_UNAPPLIED") || operation.Before != expected || operation.Active != expected || f.identity() != expected {
		t.Fatalf("source candidate did not abort without publication: %+v", operation)
	}
	ctx := runtimeTestContext(t)
	for {
		status, err := f.box.GetRuntimeConfigStatus("actor-a", expected.Incarnation, operation.TransactionID)
		if err != nil || status.LookupState != "FOUND" || status.Operation == nil || status.Active != expected || status.Operation.Before != expected || status.Operation.Active != expected || status.Operation.TransactionID != operation.TransactionID {
			t.Fatalf("source abort lost its original identity or receipt: %+v / %v", status, err)
		}
		switch status.Operation.State {
		case "ABORTED_UNAPPLIED":
			return
		case "ABORTING_UNAPPLIED":
		default:
			t.Fatalf("source abort reached an unclean outcome: %+v", status.Operation)
		}
		select {
		case <-ctx.Done():
			t.Fatal("source candidate cleanup did not reach a clean abort")
		default:
			runtime.Gosched()
		}
	}
}

func TestRuntimeLocalProducerPublishesNewImmutableClosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newRuntimeTestFixture(t, runtimeTestLocalConfig(path), nil)
	committed := make(chan RuntimeIdentity, 8)
	if err := f.box.BindRuntimePersistence(func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	old, oldView := f.acquire(t)
	producer := runtimeTestProducer(t, f)
	if err := os.WriteFile(path, runtimeTestSourceBytes("new.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Signal the production callback path explicitly; event delivery timing from
	// the OS is not an ordering premise. The bounded queue coalesces both events.
	producer.signal()
	select {
	case id := <-committed:
		if id.Revision != 2 {
			t.Fatalf("source publication revision: %+v", id)
		}
	case <-runtimeTestContext(t).Done():
		t.Fatal("source transaction did not commit")
	}
	_, next := f.acquire(t)
	if next.componentIDs["rule-set:sites"] == oldView.componentIDs["rule-set:sites"] {
		t.Fatal("mutated old source instead of replacing its owner")
	}
	if next.componentIDs["outbound:a"] != oldView.componentIDs["outbound:a"] {
		t.Fatal("source-only update rebuilt independent outbound")
	}
	if runtimeTestProducer(t, f) != producer {
		t.Fatal("unchanged watcher identity was rebuilt")
	}
	if old.View().Identity().Revision != 1 {
		t.Fatal("old reader changed generation")
	}
	old.Release()
}

func TestRuntimeLocalSourceChangedAfterPlanPreservesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	_, request := f.plan(t, runtimeTestLocalConfig(path))
	if err := os.WriteFile(path, runtimeTestSourceBytes("changed.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTestRequireCleanSourceAbort(t, f, operation, request.Expected)
}

func TestRuntimeSourceSignalCoalescesAndStopsAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &runtimeSourceProducer{ctx: ctx, cancel: cancel, changed: make(chan struct{}, 1)}
	for range 100 {
		p.signal()
	}
	if len(p.changed) != 1 {
		t.Fatal("source notification backlog is not bounded")
	}
	<-p.changed
	p.stop()
	p.signal()
	if len(p.changed) != 0 {
		t.Fatal("stopped producer admitted work")
	}
}

func TestRuntimeSameConfigLocalContentChangeIsNotNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := runtimeTestLocalConfig(path)
	f := newRuntimeTestFixture(t, config, nil)
	f.start(t)
	// Isolate manual Plan from OS notification timing; both use the same snapshot path.
	runtimeTestProducer(t, f).stop()
	if err := os.WriteFile(path, runtimeTestSourceBytes("replacement.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, _ := f.plan(t, config)
	if plan.NoOp {
		t.Fatal("identical config bytes hid changed local resource content")
	}
}

func TestRuntimeNoOpLocalSourceDriftDoesNotCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := runtimeTestLocalConfig(path)
	f := newRuntimeTestFixture(t, config, nil)
	f.start(t)
	runtimeTestProducer(t, f).stop()
	plan, request := f.plan(t, config)
	if !plan.NoOp {
		t.Fatal("unchanged source should permit configuration-only no-op")
	}
	if err := os.WriteFile(path, runtimeTestSourceBytes("drift.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.identity()
	_, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err == nil {
		t.Fatal("source drift accepted a stale no-op receipt")
	}
	if f.identity() != before {
		t.Fatal("failed no-op changed active identity")
	}
}

func TestRuntimeEmptyLocalSourcesConstructConnectedGraph(t *testing.T) {
	for _, format := range []string{C.RuleSetFormatSource, C.RuleSetFormatBinary} {
		t.Run(format, func(t *testing.T) {
			content := []byte(`{"version":3,"rules":[]}`)
			if format == C.RuleSetFormatBinary {
				var binary bytes.Buffer
				if err := srs.Write(&binary, option.PlainRuleSet{}, C.RuleSetVersion3); err != nil {
					t.Fatal(err)
				}
				content = binary.Bytes()
			}
			path := filepath.Join(t.TempDir(), "empty.rules")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			config := strings.Replace(string(runtimeTestLocalConfig(path)), `"format":"source"`, fmt.Sprintf(`"format":%q`, format), 1)
			f := newRuntimeTestFixture(t, []byte(config), nil)
			f.start(t)
			_, view := f.acquire(t)
			set, loaded := view.router.RuleSet("sites")
			if !loaded || set.Metadata() != (adapter.RuleSetMetadata{}) {
				t.Fatal("empty source lost its declared runtime rule-set")
			}
			for _, metadata := range []adapter.InboundContext{
				{Destination: M.ParseSocksaddr("192.0.2.7:443")},
				{Destination: M.ParseSocksaddr("[2001:db8::7]:443")},
				{Domain: "example.org"},
			} {
				if set.Match(&metadata) {
					t.Fatal("empty materialized source matched traffic")
				}
			}
			f.box.runtime.access.Lock()
			frozen := f.box.runtime.options.Route.RuleSet[0]
			sources := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
			f.box.runtime.access.Unlock()
			if frozen.Type != C.RuleSetTypeInline || len(frozen.InlineOptions.Rules) != 0 || len(sources) != 1 || sources[0].digest != runtimeDigest(content) || !bytes.Equal(sources[0].content, content) {
				t.Fatal("empty local source was not frozen with exact accepted bytes")
			}
		})
	}
}

func TestRuntimeLocalEmptyConditionsReachPerRuleValidation(t *testing.T) {
	for _, test := range []struct {
		content string
		count   int
	}{
		{`{"version":3,"rules":[{}]}`, 1},
		{`{"version":3,"rules":[{"ip_cidr":[]}]}`, 1},
		{`{"version":3,"rules":[{}, {"domain":[]}]}`, 2},
		{`{"version":3,"rules":[{"type":"logical","mode":"and","rules":[{"domain":[]}]}]}`, 1},
	} {
		t.Run(test.content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			fixture, options := newRuntimeTestConstruction(t, runtimeTestLocalConfig(path), nil)
			frozen, sources, _, failures := runtimeSnapshotSources(fixture.ctx, fixture.ctx, options.Options, nil)
			if len(failures) != 0 || len(frozen.Route.RuleSet[0].InlineOptions.Rules) != test.count || len(sources) != 1 || !bytes.Equal(sources[0].content, []byte(test.content)) {
				t.Fatal("real local materialization lost the declared malformed rule elements")
			}
			instance, err, report := NewWithConstructionReport(options)
			if instance != nil {
				if closeErr := instance.CloseWithResult(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("empty condition rule admitted into runtime graph")
			}
			if err == nil || !strings.Contains(err.Error(), "missing conditions") {
				t.Fatalf("wrong rejection before per-rule validation: %v", err)
			}
			if !report.Attempted || report.CleanupError != nil {
				t.Fatalf("failed constructor did not finish actual cleanup: %+v", report)
			}
		})
	}
}

func TestRuntimeEmptySourceDoesNotReuseOwnerForInvalidRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	empty := []byte(`{"version":3,"rules":[]}`)
	if err := os.WriteFile(path, empty, 0o600); err != nil {
		t.Fatal(err)
	}
	config := runtimeTestLocalConfig(path)
	f := newRuntimeTestFixture(t, config, nil)
	f.start(t)
	// Keep manual Plan/Apply independent of asynchronous OS notifications.
	runtimeTestProducer(t, f).stop()
	_, oldView := f.acquire(t)
	before := f.identity()
	f.box.runtime.access.Lock()
	valid := f.box.runtime.options
	f.box.runtime.access.Unlock()
	_, validNodes, err := runtimeConfigNodes(f.ctx, valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		`{"version":3,"rules":[{}]}`,
		`{"version":3,"rules":[{"ip_cidr":[]}]}`,
	} {
		if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
			t.Fatal(err)
		}
		_, options := newRuntimeTestConstruction(t, config, nil)
		frozen, _, _, failures := runtimeSnapshotSources(f.ctx, f.ctx, options.Options, nil)
		if len(failures) != 0 || len(frozen.Route.RuleSet[0].InlineOptions.Rules) != 1 {
			t.Fatal("malformed source was silently reduced to an empty set")
		}
		_, invalidNodes, err := runtimeConfigNodes(f.ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		if invalidNodes["rule-set:sites"].node.fingerprint == validNodes["rule-set:sites"].node.fingerprint {
			t.Fatal("invalid rule reused the empty rule-set fingerprint")
		}
		plan, request := f.plan(t, config)
		if plan.NoOp {
			t.Fatal("malformed source admitted as unchanged")
		}
		operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
		if err != nil {
			t.Fatal(err)
		}
		runtimeTestRequireCleanSourceAbort(t, f, operation, before)
		_, current := f.acquire(t)
		if current.componentIDs["rule-set:sites"] != oldView.componentIDs["rule-set:sites"] {
			t.Fatal("failed source preparation replaced the original owner")
		}
		f.box.runtime.access.Lock()
		sources := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
		f.box.runtime.access.Unlock()
		if len(sources) != 1 || sources[0].digest != runtimeDigest(empty) || !bytes.Equal(sources[0].content, empty) {
			t.Fatal("rejected rule changed the accepted source snapshot")
		}
		f.box.runtime.access.Lock()
		preparing, finished := f.box.runtime.preparing, f.box.runtime.workDone
		f.box.runtime.access.Unlock()
		if preparing {
			runtimeTestWait(t, finished, "failed candidate cleanup")
		}
	}
}

func TestRuntimeLocalProducerEmptyTransitionsPreserveRetainedGraph(t *testing.T) {
	for _, format := range []string{C.RuleSetFormatSource, C.RuleSetFormatBinary} {
		t.Run(format, func(t *testing.T) {
			runtimeTestEmptySourceTransitions(t, format)
		})
	}
}

func runtimeTestEmptySourceTransitions(t *testing.T, format string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sites.json")
	empty := []byte(`{"version":3,"rules":[]}`)
	nonempty := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.7/32","2001:db8::7/128"]}]}`)
	config := runtimeTestLocalConfig(path)
	if format == C.RuleSetFormatBinary {
		var compiled bytes.Buffer
		if err := srs.Write(&compiled, option.PlainRuleSet{}, C.RuleSetVersion3); err != nil {
			t.Fatal(err)
		}
		empty = bytes.Clone(compiled.Bytes())
		plain, err := json.UnmarshalExtended[option.PlainRuleSetCompat](nonempty)
		if err != nil {
			t.Fatal(err)
		}
		compiled.Reset()
		if err := srs.Write(&compiled, plain.Options, C.RuleSetVersion3); err != nil {
			t.Fatal(err)
		}
		nonempty = bytes.Clone(compiled.Bytes())
		config = runtimeTestBinaryLocalConfig(path)
	}
	replace := func(content []byte) {
		t.Helper()
		if err := os.WriteFile(path+".next", content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
	}
	replace(empty)
	f := newRuntimeTestFixture(t, config, nil)
	committed := make(chan RuntimeIdentity, 8)
	if err := f.box.BindRuntimePersistence(func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	firstLease, first := f.acquire(t)
	producer := runtimeTestProducer(t, f)
	transition := func(content []byte, revision uint64) {
		t.Helper()
		replace(content)
		// Use the production notification/transaction path, as in the existing
		// producer regression; OS notification scheduling is not a barrier.
		producer.signal()
		select {
		case id := <-committed:
			if id.Revision != revision {
				t.Fatalf("source publication revision: %+v", id)
			}
		case <-runtimeTestContext(t).Done():
			t.Fatal("source transition did not commit")
		}
		f.box.runtime.access.Lock()
		sources := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
		f.box.runtime.access.Unlock()
		if len(sources) != 1 || sources[0].digest != runtimeDigest(content) || !bytes.Equal(sources[0].content, content) {
			t.Fatal("committed source digest does not describe accepted bytes")
		}
	}
	transition(nonempty, 2)
	secondLease, second := f.acquire(t)
	retained, exists := second.router.RuleSet("sites")
	if !exists || !retained.Metadata().ContainsIPCIDRRule {
		t.Fatal("nonempty source missing IP metadata")
	}
	entered, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var stopOnce sync.Once
	join := func() {
		stopOnce.Do(func() { close(stop) })
		<-done
	}
	go func() {
		defer close(done)
		close(entered)
		for {
			select {
			case <-stop:
				return
			default:
			}
			metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}
			if !retained.Match(&metadata) {
				t.Error("retained graph changed while source was emptied")
				return
			}
		}
	}()
	defer join()
	<-entered
	transition(empty, 3)
	thirdLease, third := f.acquire(t)
	current, exists := third.router.RuleSet("sites")
	if !exists || current.Metadata() != (adapter.RuleSetMetadata{}) || current.Match(&adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}) {
		t.Fatal("empty publication lost the tag or still matches")
	}
	initial, exists := first.router.RuleSet("sites")
	if !exists || initial.Match(&adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}) {
		t.Fatal("retained initial empty graph changed")
	}
	if first.componentIDs["rule-set:sites"] == second.componentIDs["rule-set:sites"] || second.componentIDs["rule-set:sites"] == third.componentIDs["rule-set:sites"] || first.componentIDs["outbound:a"] != third.componentIDs["outbound:a"] || runtimeTestProducer(t, f) != producer {
		t.Fatal("source transitions violated resource ownership/reuse")
	}
	if firstLease.View().Identity().Revision != 1 || secondLease.View().Identity().Revision != 2 || thirdLease.View().Identity().Revision != 3 {
		t.Fatal("retained graph identity changed")
	}
	join()
	firstLease.Release()
	secondLease.Release()
	thirdLease.Release()
	if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.box.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	runtimeTestWait(t, producer.done, "source producer close")
	runtimeTestWait(t, producer.eventsDone, "source watcher close")
	closed := f.identity()
	replace(nonempty)
	producer.signal()
	if _, retry := producer.refresh(); retry || f.identity() != closed {
		t.Fatal("closed source producer admitted a late update")
	}
	select {
	case id := <-committed:
		t.Fatalf("publication after close: %+v", id)
	default:
	}
}

func runtimeTestBinaryLocalConfig(path string) []byte {
	return []byte(strings.Replace(string(runtimeTestLocalConfig(path)), `"format":"source"`, `"format":"binary"`, 1))
}

func runtimeTestPrivateSRS(t *testing.T, kind string, second, nested bool, version uint8) []byte {
	t.Helper()
	name, address := "a.example", "192.0.2.7/32"
	if second {
		name, address = "b.example", "192.0.2.8/32"
	}
	if strings.HasSuffix(kind, "-v6") {
		address = "2001:db8::7/128"
		if second {
			address = "2001:db8::8/128"
		}
	}
	var leaf option.HeadlessRule
	if kind == "adguard" {
		leaf = option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{AdGuardDomain: []string{"||" + name + "^"}}}
	} else {
		key, value := "ip_cidr", address
		if kind == "domain" {
			key, value = "domain", name
		} else if strings.HasPrefix(kind, "source") {
			key = "source_ip_cidr"
		}
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{%q:[%q]}`, key, value)), &leaf); err != nil {
			t.Fatal(err)
		}
	}
	if nested {
		leaf = option.HeadlessRule{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{
			Mode: C.LogicalTypeAnd,
			Rules: []option.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeOr, Rules: []option.HeadlessRule{leaf},
			}}},
		}}
	}
	var compiled bytes.Buffer
	if err := srs.Write(&compiled, option.PlainRuleSet{Rules: []option.HeadlessRule{leaf}}, version); err != nil {
		t.Fatal(err)
	}
	return compiled.Bytes()
}

func runtimeTestAssertPrivateSRS(t *testing.T, kind string, rules []option.HeadlessRule) {
	t.Helper()
	for {
		if len(rules) != 1 {
			t.Fatal("private SRS rule cardinality changed")
		}
		if rules[0].Type == C.RuleTypeLogical {
			rules = rules[0].LogicalOptions.Rules
			continue
		}
		options := rules[0].DefaultOptions
		private := false
		switch kind {
		case "domain":
			private = options.DomainMatcher != nil && len(options.Domain) == 0 && len(options.DomainSuffix) == 0
		case "adguard":
			private = options.AdGuardDomainMatcher != nil && len(options.AdGuardDomain) == 0
		case "source", "source-v6":
			private = options.SourceIPSet != nil && len(options.SourceIPCIDR) == 0
		case "destination", "destination-v6":
			private = options.IPSet != nil && len(options.IPCIDR) == 0
		}
		if !private {
			t.Fatal("fixture did not reach the real non-recovered SRS predicate")
		}
		return
	}
}

func TestRuntimePrivateSRSFingerprintVersionsAndRoles(t *testing.T) {
	for _, nested := range []bool{false, true} {
		roles := make(map[string]string)
		for _, kind := range []string{"domain", "adguard", "source", "destination", "source-v6", "destination-v6"} {
			versions := []uint8{1, 2, 3, 4, 5}
			if kind == "adguard" {
				versions = []uint8{2, 3, 4, 5} // The format introduced AdGuard predicates in v2.
			}
			for _, version := range versions {
				t.Run(fmt.Sprintf("%s/v%d/nested=%t", kind, version, nested), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "sites.srs")
					var fingerprints [3]string
					for i, second := range []bool{false, false, true} {
						content := runtimeTestPrivateSRS(t, kind, second, nested, version)
						if err := os.WriteFile(path, content, 0o600); err != nil {
							t.Fatal(err)
						}
						fixture, options := newRuntimeTestConstruction(t, runtimeTestBinaryLocalConfig(path), nil)
						frozen, sources, _, failures := runtimeSnapshotSources(fixture.ctx, fixture.ctx, options.Options, nil)
						if len(failures) != 0 || len(sources) != 1 || sources[0].digest != runtimeDigest(content) {
							t.Fatal("actual SRS materialization failed")
						}
						runtimeTestAssertPrivateSRS(t, kind, frozen.Route.RuleSet[0].InlineOptions.Rules)
						_, nodes, err := runtimeConfigNodes(fixture.ctx, frozen)
						if err != nil {
							t.Fatal(err)
						}
						fingerprints[i] = nodes["rule-set:sites"].node.fingerprint
						set, err := R.NewRuleSet(fixture.ctx, logger.NOP(), "sites", frozen.Route.RuleSet[0])
						if err != nil {
							t.Fatal(err)
						}
						if err := set.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if fingerprints[0] != fingerprints[1] || fingerprints[0] == fingerprints[2] {
						t.Fatal("private matcher identity used addresses or ignored actual predicate data")
					}
					if version == 3 {
						roles[kind] = fingerprints[0]
					}
				})
			}
		}
		if roles["source"] == roles["destination"] || roles["source-v6"] == roles["destination-v6"] {
			t.Fatal("source and destination roles collided for the same address ranges")
		}
	}
}

func TestRuntimeNonemptySRSUpdatesAndInvalidCandidatesPreserveOwners(t *testing.T) {
	for _, test := range []struct {
		kind   string
		first  adapter.InboundContext
		second adapter.InboundContext
	}{
		{"domain", adapter.InboundContext{Domain: "a.example"}, adapter.InboundContext{Domain: "b.example"}},
		{"adguard", adapter.InboundContext{Domain: "a.example"}, adapter.InboundContext{Domain: "b.example"}},
		{"destination", adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.8:443")}},
		{"source", adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.7:1234")}, adapter.InboundContext{Source: M.ParseSocksaddr("192.0.2.8:1234")}},
		{"destination-v6", adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::7]:443")}, adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::8]:443")}},
		{"source-v6", adapter.InboundContext{Source: M.ParseSocksaddr("[2001:db8::7]:1234")}, adapter.InboundContext{Source: M.ParseSocksaddr("[2001:db8::8]:1234")}},
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", test.kind, nested), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "sites.srs")
				firstBytes := runtimeTestPrivateSRS(t, test.kind, false, nested, C.RuleSetVersion3)
				secondBytes := runtimeTestPrivateSRS(t, test.kind, true, nested, C.RuleSetVersion3)
				if err := os.WriteFile(path, firstBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				config := runtimeTestBinaryLocalConfig(path)
				f := newRuntimeTestFixture(t, config, nil)
				committed := make(chan RuntimeIdentity, 8)
				if err := f.box.BindRuntimePersistence(func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }); err != nil {
					t.Fatal(err)
				}
				f.start(t)
				oldLease, oldView := f.acquire(t)
				oldSet, ok := oldView.router.RuleSet("sites")
				if !ok || !oldSet.Match(&test.first) || oldSet.Match(&test.second) {
					t.Fatal("nonempty SRS did not supply the intended starting predicate")
				}
				oldOwner := runtimeTestResource(t, f, oldView.componentIDs["rule-set:sites"])
				metadata := oldSet.Metadata()
				before := f.identity()
				inline := `{"type":"inline","tag":"sites","rules":[{"domain_suffix":["example.org"]}]}`
				for _, malformed := range []struct{ rules, source string }{
					{`[{}]`, ""},
					{`[{"type":"logical","mode":"or","rules":[{"ip_cidr":[]}]}]`, ""},
					{`[{"ip_cidr":[]}]`, "source"},
					{`[{"type":"logical","mode":"and","rules":[{"domain":[]}]}]`, "source"},
				} {
					candidate := []byte(strings.Replace(string(runtimeTestConfig(1080, "example.org")), inline, `{"type":"inline","tag":"sites","rules":`+malformed.rules+`}`, 1))
					if malformed.source != "" {
						invalidPath := path + ".invalid.json"
						if err := os.WriteFile(invalidPath, []byte(`{"version":3,"rules":`+malformed.rules+`}`), 0o600); err != nil {
							t.Fatal(err)
						}
						candidate = runtimeTestLocalConfig(invalidPath)
					}
					_, request := f.plan(t, candidate)
					f.box.runtime.access.Lock()
					sequence := f.box.runtime.resourceSequence
					f.box.runtime.access.Unlock()
					operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
					if err != nil {
						t.Fatal(err)
					}
					runtimeTestRequireCleanSourceAbort(t, f, operation, before)
					f.box.runtime.access.Lock()
					var failed []*runtimeResource
					for id, resource := range f.box.runtime.catalog {
						if id.Sequence > sequence {
							failed = append(failed, resource)
						}
					}
					accepted := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
					preparing, done := f.box.runtime.preparing, f.box.runtime.workDone
					f.box.runtime.access.Unlock()
					for _, resource := range failed {
						if err := resource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
							t.Fatal(err)
						}
					}
					if preparing {
						runtimeTestWait(t, done, "failed SRS candidate cleanup")
					}
					lease, current := f.acquire(t)
					if current != oldView || oldSet.Metadata() != metadata || !oldSet.Match(&test.first) || oldSet.Match(&test.second) || len(accepted) != 1 || accepted[0].digest != runtimeDigest(firstBytes) || !bytes.Equal(accepted[0].content, firstBytes) {
						t.Fatal("rejected candidate changed identity, owner, metadata, matching or accepted bytes")
					}
					lease.Release()
				}
				if err := os.WriteFile(path+".next", secondBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".next", path); err != nil {
					t.Fatal(err)
				}
				runtimeTestProducer(t, f).signal()
				select {
				case id := <-committed:
					if id.Revision != 2 {
						t.Fatalf("private SRS update revision: %+v", id)
					}
				case <-runtimeTestContext(t).Done():
					t.Fatal("changed private SRS predicate did not publish")
				}
				newLease, newView := f.acquire(t)
				newSet, ok := newView.router.RuleSet("sites")
				if !ok || newSet.Metadata() != metadata || newSet.Match(&test.first) || !newSet.Match(&test.second) || newView.componentIDs["rule-set:sites"] == oldView.componentIDs["rule-set:sites"] || newView.componentIDs["outbound:a"] != oldView.componentIDs["outbound:a"] || !oldSet.Match(&test.first) {
					t.Fatal("private predicate update reused stale conditions or mutated a retained reader")
				}
				newOwner := runtimeTestResource(t, f, newView.componentIDs["rule-set:sites"])
				f.box.runtime.access.Lock()
				accepted := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
				f.box.runtime.access.Unlock()
				if len(accepted) != 1 || accepted[0].digest != runtimeDigest(secondBytes) || !bytes.Equal(accepted[0].content, secondBytes) {
					t.Fatal("new private SRS publication acknowledged wrong source bytes")
				}
				producer := runtimeTestProducer(t, f)
				producer.stop()
				runtimeTestWait(t, producer.done, "private SRS refresh tail")
				runtimeTestWait(t, producer.eventsDone, "private SRS event tail")
				// A route-only change reparses the same SRS into new matcher objects.
				// Its unchanged actual predicate must retain the rule-set owner.
				routeChange := []byte(strings.Replace(string(config), `"rule_set":"sites","action":"route","outbound":"select"`, `"rule_set":"sites","action":"route","outbound":"a"`, 1))
				if bytes.Equal(routeChange, config) {
					t.Fatal("route-only fixture did not change the actual configuration")
				}
				plan, request := f.plan(t, routeChange)
				if plan.NoOp {
					t.Fatal("same-predicate reuse was only a no-op receipt")
				}
				operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
				if err != nil || operation.State != "COMMITTED" {
					t.Fatalf("same SRS predicate could not commit route-only update: %+v / %v", operation, err)
				}
				lastLease, lastView := f.acquire(t)
				if lastView == newView || lastView.componentIDs["rule-set:sites"] != newView.componentIDs["rule-set:sites"] || lastView.componentIDs["route-router"] == newView.componentIDs["route-router"] {
					t.Fatal("fresh matcher allocations changed unchanged semantic owner")
				}
				oldLease.Release()
				if err := oldOwner.owner.WaitClosed(runtimeTestContext(t)); err != nil {
					t.Fatal(err)
				}
				newLease.Release()
				lastLease.Release()
				if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
					t.Fatal(err)
				}
				if err := f.box.CloseWithResult(); err != nil {
					t.Fatal(err)
				}
				if err := newOwner.owner.WaitClosed(runtimeTestContext(t)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
