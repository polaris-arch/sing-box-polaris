package box

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing/common/json"

	mdns "github.com/miekg/dns"
)

type r4ExactInvocation struct {
	active    RuntimeIdentity
	canonical []byte
}

func r4ExactNext(t *testing.T, calls <-chan r4ExactInvocation) r4ExactInvocation {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-runtimeTestContext(t).Done():
		t.Fatal("production exact-file callback did not make progress")
		return r4ExactInvocation{}
	}
}

func r4ExactRefresh(t *testing.T, p *runtimeSourceProducer) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); p.refresh() }()
	return done
}

func r4ExactRecord(t *testing.T, f *runtimeTestFixture, active RuntimeIdentity) *runtimePlanRecord {
	t.Helper()
	c := f.box.runtime
	c.access.Lock()
	defer c.access.Unlock()
	record := c.pendingPersistence
	if record == nil || record.actor != runtimeSourceProducerActor ||
		record.sourceProof == nil || record.operation == nil ||
		record.operation.Active != active || !record.persistenceTailEntered ||
		record.persistenceCallback == nil || record.operation.PersistenceMode != "exact_configuration_file" {
		t.Fatal("real source Apply did not retain its original exact-file record")
	}
	return record
}

func r4ExactDurable(t *testing.T, f *runtimeTestFixture, record *runtimePlanRecord, active RuntimeIdentity, canonical []byte, plans int) {
	t.Helper()
	c := f.box.runtime
	waitRetryState(t, c, func() bool { return !c.preparing && record.operation != nil && record.operation.Durable })
	c.access.Lock()
	defer c.access.Unlock()
	if c.active != active || record.operation.Active != active || record.operation.State != "COMMITTED" ||
		record.operation.PersistenceMode != "exact_configuration_file" ||
		!bytes.Equal(record.canonical, canonical) || c.pendingPersistence != nil ||
		c.plans[record.plan.TransactionID] != record || len(c.plans) != plans {
		t.Fatal("driver hid original-tail recovery behind another publication/record/binding")
	}
}

func r4ExactNoMoreCallbacks(t *testing.T, calls *atomic.Int32, baseline int32) {
	t.Helper()
	// Observe beyond two minimum production retry intervals. The final Stop
	// below joins the instance driver too; this timer is not a durability ACK.
	timer := time.NewTimer(750 * time.Millisecond)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if calls.Load() != baseline {
			t.Fatal("revoked/uncertain original callback replayed", calls.Load(), baseline)
		}
		select {
		case <-timer.C:
			return
		case <-tick.C:
		}
	}
}

func TestR4ExactSourceDriverRetriesOriginalRecordAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	entered := make(chan r4ExactInvocation, 8)
	first, retry := newRuntimeTestBarrier(), newRuntimeTestBarrier()
	defer first.open()
	defer retry.open()
	var calls atomic.Int32
	f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
		func(active RuntimeIdentity, canonical []byte) error {
			n := calls.Add(1)
			entered <- r4ExactInvocation{active, append([]byte(nil), canonical...)}
			if n == 1 {
				first.block()
				return errors.New("returned temporary directory-flush failure")
			}
			if n == 2 {
				retry.block()
			}
			return nil
		}, true, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	refreshed := r4ExactRefresh(t, p)
	originalCall := r4ExactNext(t, entered)
	original := r4ExactRecord(t, f, originalCall.active)
	c := f.box.runtime
	c.access.Lock()
	plans := len(c.plans)
	producer := original.sourceProof.producer
	participant := original.persistenceParticipant
	c.access.Unlock()
	if producer != p || originalCall.active.Revision != 2 ||
		originalCall.active.Incarnation != f.identity().Incarnation ||
		runtimeDigest(originalCall.canonical) != originalCall.active.EffectiveDigest {
		t.Fatal("original callback was not the authentic source publication")
	}
	first.open()
	runtimeTestWait(t, refreshed, "original source Apply returned known failure")
	repeated := r4ExactNext(t, entered)
	if repeated.active != originalCall.active || !bytes.Equal(repeated.canonical, originalCall.canonical) || calls.Load() != 2 {
		t.Fatal("production driver changed the original identity/control/incarnation/canonical bytes")
	}
	c.access.Lock()
	owned := c.preparing && original.retryInFlight && c.pendingPersistence == original &&
		original.sourceProof.producer == p && original.persistenceParticipant == participant && !original.operation.Durable
	c.access.Unlock()
	if !owned {
		t.Fatal("retry did not retain the original synchronous tail")
	}
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "owner_acknowledged", true); err == nil {
		t.Fatal("active exact-file mode/callback binding was replaced")
	}
	retry.open()
	r4ExactDurable(t, f, original, originalCall.active, originalCall.canonical, plans)
	r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
	runtimeTestWait(t, r4ExactRefresh(t, p), "second actual source event")
	next := r4ExactNext(t, entered)
	r3SourceSettled(t, f)
	if next.active.Revision != originalCall.active.Revision+1 || next.active.Incarnation != originalCall.active.Incarnation ||
		!bytes.Equal(next.canonical, originalCall.canonical) || calls.Load() != 3 {
		t.Fatal("first original tail recovery did not unblock the second immutable source update")
	}
	_, view := f.acquire(t)
	set, _ := view.router.RuleSet("sites")
	if !set.Match(&adapter.InboundContext{Domain: "third.example"}) {
		t.Fatal("second source resource was not actually published")
	}
}

func TestR4ExactSourceDriverOutlivesProducerAndLaterProducerHasNoOldTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "first.json")
	replacementPath := filepath.Join(t.TempDir(), "replacement.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	r3SourceWrite(t, replacementPath, runtimeTestSourceBytes("replacement.example"))
	var calls atomic.Int32
	entered := make(chan r4ExactInvocation, 8)
	retry := newRuntimeTestBarrier()
	defer retry.open()
	f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
		func(active RuntimeIdentity, canonical []byte) error {
			n := calls.Add(1)
			entered <- r4ExactInvocation{active, append([]byte(nil), canonical...)}
			if n == 1 {
				return errors.New("known returned file flush failure")
			}
			if n == 2 {
				retry.block()
			}
			return nil
		}, true, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	runtimeTestWait(t, r4ExactRefresh(t, p), "source Apply and production registration")
	originalCall := r4ExactNext(t, entered)
	original := r4ExactRecord(t, f, originalCall.active)
	f.box.runtime.access.Lock()
	plans := len(f.box.runtime.plans)
	f.box.runtime.access.Unlock()
	// This is the resource's genuine stop entry. It does not stop the Box.
	p.stop()
	runtimeTestWait(t, p.done, "retired producer worker")
	runtimeTestWait(t, p.eventsDone, "retired producer watcher")
	repeated := r4ExactNext(t, entered)
	if repeated.active != originalCall.active || !bytes.Equal(repeated.canonical, originalCall.canonical) {
		t.Fatal("retiring producer orphaned/transferred the original instance task")
	}
	f.box.runtime.access.Lock()
	sameOriginal := original.sourceProof.producer == p && original.retryInFlight
	f.box.runtime.access.Unlock()
	if !sameOriginal {
		t.Fatal("automatic retry rediscovered a replacement producer owner")
	}
	retry.open()
	r4ExactDurable(t, f, original, originalCall.active, originalCall.canonical, plans)

	// A genuinely new producer is created by a later ordinary publication only
	// after original recovery; that publication cannot mask original success.
	oldPath, _ := stdjson.Marshal(path)
	newPath, _ := stdjson.Marshal(replacementPath)
	nextConfig := bytes.Replace(originalCall.canonical, oldPath, newPath, 1)
	if bytes.Equal(nextConfig, originalCall.canonical) {
		t.Fatal("replacement path not present")
	}
	_, request := runtimeClientPlan(t, f, nextConfig)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || !op.Durable || op.Active.Revision != originalCall.active.Revision+1 {
		t.Fatal(op, err)
	}
	publicCall := r4ExactNext(t, entered)
	if publicCall.active != op.Active {
		t.Fatal("ordinary callback lost its own owner")
	}
	nextProducer := runtimeTestProducer(t, f)
	if nextProducer == p {
		t.Fatal("ordinary source-path replacement reused stopped producer")
	}
	r3SourceWrite(t, replacementPath, runtimeTestSourceBytes("fourth.example"))
	next := r4ExactNext(t, entered) // real watcher event, no privileged retry entry
	r3SourceSettled(t, f)
	f.box.runtime.access.Lock()
	oldStillOriginal := original.operation.Durable && original.operation.Active == originalCall.active && original.sourceProof.producer == p
	f.box.runtime.access.Unlock()
	if !oldStillOriginal || next.active.Revision != op.Active.Revision+1 || calls.Load() != 4 {
		t.Fatal("new producer took an old tail or lost its own next source event")
	}
}

func TestR4ExactSourceDriverRevokedByControlOrAcceptedOrdinaryIntent(t *testing.T) {
	for _, fence := range []string{"control", "accepted-clean-abort"} {
		t.Run(fence, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
			var calls atomic.Int32
			f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
				func(RuntimeIdentity, []byte) error { calls.Add(1); return errors.New("known returned failure") },
				true, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
			p := runtimeTestProducer(t, f)
			r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
			runtimeTestWait(t, r4ExactRefresh(t, p), "registered exact source tail")
			active := f.identity()
			original := r4ExactRecord(t, f, active)
			var baseline int32
			if fence == "control" {
				lease, view := f.acquire(t)
				selector := view.componentIDs["outbound:select"]
				if !f.box.runtime.SelectRuntimeOutbound(selector, "select", "b") {
					t.Fatal("real control change rejected")
				}
				lease.Release()
				if f.identity().ControlRevision != active.ControlRevision+1 {
					t.Fatal("control identity did not advance")
				}
				baseline = calls.Load()
			} else {
				candidate := bytes.Replace(r3SourceCanonical(f), []byte("\"server_port\":1080"), []byte("\"server_port\":1081"), 1)
				_, request := runtimeClientPlan(t, f, candidate)
				constructor := newRuntimeTestBarrier()
				defer constructor.open()
				f.setConstructorHook(func(*runtimeTestSocks) error {
					constructor.block()
					return errors.New("clean unpublished candidate abort")
				})
				result := make(chan RuntimeConfigOperation, 1)
				go func() {
					ctx := runtimeTestContext(t)
					for {
						operation, err := f.box.ApplyRuntimeConfig(ctx, "actor-a", request)
						if operation.TransactionID != "" || err == nil {
							result <- operation
							return
						}
						select {
						case <-ctx.Done():
							result <- operation
							return
						default:
							runtime.Gosched()
						}
					}
				}()
				runtimeTestWait(t, constructor.entered, "accepted ordinary candidate constructor")
				baseline = calls.Load()
				constructor.open()
				var operation RuntimeConfigOperation
				select {
				case operation = <-result:
				case <-runtimeTestContext(t).Done():
					t.Fatal("ordinary abort did not return")
				}
				runtimeTestRequireCleanSourceAbort(t, f, operation, active)
				if f.identity() != active {
					t.Fatal("constructor failure changed graph to conceal retry fence")
				}
			}
			r4ExactNoMoreCallbacks(t, &calls, baseline)
			f.box.runtime.access.Lock()
			falselySettled := original.operation.Durable
			f.box.runtime.access.Unlock()
			if falselySettled {
				t.Fatal("revoked original tail became durable")
			}
			if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != baseline {
				t.Fatal("Stop detached a revoked replay")
			}
		})
	}
}

func TestR4ExactSourceDriverNeverReplaysUnsafeOrUncertainCompletion(t *testing.T) {
	for _, failure := range []string{"nonrepeatable", "panic", "sticky-cleanup"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
			var calls atomic.Int32
			f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
				func(RuntimeIdentity, []byte) error {
					calls.Add(1)
					switch failure {
					case "panic":
						panic("original callback completion is uncertain")
					case "sticky-cleanup":
						return errors.Join(errors.New("unknown owner cleanup"), errRuntimeCleanupIncomplete)
					default:
						return errors.New("not declared repeat safe")
					}
				}, failure != "nonrepeatable", func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
			p := runtimeTestProducer(t, f)
			r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
			runtimeTestWait(t, r4ExactRefresh(t, p), "uncertain/unsafe source callback returned")
			r3SourceSettled(t, f)
			active := f.identity()
			if active.Revision != 2 || calls.Load() != 1 {
				t.Fatal("fixture did not enter exactly one real original callback")
			}
			r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
			if _, retry := p.refresh(); !retry || f.identity() != active {
				t.Fatal("unresolved original tail was superseded")
			}
			r4ExactNoMoreCallbacks(t, &calls, 1)
			f.box.runtime.access.Lock()
			var original *runtimePlanRecord
			for _, record := range f.box.runtime.plans {
				if record.sourceProof != nil && record.operation != nil && record.operation.Active == active {
					original = record
					break
				}
			}
			pending := original != nil && original.persistenceTailEntered && !original.operation.Durable
			f.box.runtime.access.Unlock()
			if !pending {
				t.Fatal("uncertain/unsafe original debt disappeared")
			}
			if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("Stop observed a detached unsafe replay")
			}
		})
	}
}

func TestR4ExactSourceDriverStopJoinsUnreturnedCallbackAndAdmittedRetry(t *testing.T) {
	for _, admission := range []string{"initial-unreturned", "automatic-retry-entered"} {
		t.Run(admission, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
			var calls atomic.Int32
			callback := newRuntimeTestBarrier()
			defer callback.open()
			f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
				func(RuntimeIdentity, []byte) error {
					n := calls.Add(1)
					if admission == "automatic-retry-entered" && n == 1 {
						return errors.New("known returned first failure")
					}
					callback.block()
					return nil
				}, true, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
			p := runtimeTestProducer(t, f)
			r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
			refreshed := r4ExactRefresh(t, p)
			runtimeTestWait(t, callback.entered, "actual synchronous persistence callback")
			active := f.identity()
			original := r4ExactRecord(t, f, active)
			expectedCalls := int32(1)
			if admission == "automatic-retry-entered" {
				expectedCalls = 2
				runtimeTestWait(t, refreshed, "first source Apply returned before automatic retry")
			}
			if calls.Load() != expectedCalls {
				t.Fatal("unreturned callback was concurrently replayed")
			}
			f.box.runtime.access.Lock()
			owned := f.box.runtime.preparing && !original.operation.Durable
			work := f.box.runtime.workDone
			f.box.runtime.access.Unlock()
			if !owned {
				t.Fatal("synchronous callback lost original work ownership")
			}
			ctx, cancel := context.WithCancel(context.Background())
			stopped := make(chan error, 1)
			go func() { stopped <- f.box.closeRuntimeResourcesContext(ctx) }()
			waitRetryState(t, f.box.runtime, func() bool { return f.box.runtime.stopped })
			cancel()
			if err := <-stopped; err == nil {
				t.Fatal("canceled observer falsely joined an unreturned callback")
			}
			select {
			case <-work:
				t.Fatal("Stop detached admitted synchronous work")
			default:
			}
			if f.box.RuntimeCleanupSnapshot().Done || calls.Load() != expectedCalls {
				t.Fatal("Stop claimed callback completion or replayed it")
			}
			callback.open()
			runtimeTestWait(t, refreshed, "original Apply after callback return")
			if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != expectedCalls {
				t.Fatal("Stop admitted a later replay")
			}
		})
	}
}

func TestR4ExactSourceDriverNewInstanceCannotInheritOriginalTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	var oldCalls atomic.Int32
	f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
		func(RuntimeIdentity, []byte) error {
			oldCalls.Add(1)
			return errors.New("old exact file flush failure")
		},
		true, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	runtimeTestWait(t, r4ExactRefresh(t, p), "old registered source tail")
	active := f.identity()
	original := r4ExactRecord(t, f, active)
	if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	before := oldCalls.Load()
	entered := make(chan RuntimeIdentity, 4)
	newer := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil,
		func(id RuntimeIdentity, _ []byte) error { entered <- id; return nil }, true)
	if newer.identity().Incarnation == active.Incarnation {
		t.Fatal("replacement fixture reused Box incarnation")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
	next := r3SourceCommit(t, entered, 2)
	r3SourceSettled(t, newer)
	f.box.runtime.access.Lock()
	oldDurable := original.operation.Durable
	f.box.runtime.access.Unlock()
	if next.Incarnation == active.Incarnation || oldCalls.Load() != before || oldDurable {
		t.Fatal("replacement instance/new producer inherited original callback authority")
	}
}

func TestR4ExactSourceDriverKeepsRealNamespaceWaitAndExactAcknowledgement(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "sites.json")
	r3SourceWrite(t, sourcePath, runtimeTestSourceBytes("first.example"))
	f, options := runtimeFakeIPCleanupConstruction(t, filepath.Join(root, "cache.db"), nil)
	encoded, err := json.MarshalContext(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := stdjson.Marshal([]map[string]string{{"type": "local", "tag": "sites", "format": "source", "path": sourcePath}})
	encoded = r3SourceRoute(t, encoded, map[string]stdjson.RawMessage{"rule_set": rules})
	if err := json.UnmarshalContext(f.ctx, encoded, &options.Options); err != nil {
		t.Fatal(err)
	}
	options.Context = adapter.ContextWithRuntimeRecoveryRoot(options.Context, root)
	runtimeFakeIPCleanupBox(t, f, options)
	entered := make(chan r4ExactInvocation, 8)
	var calls atomic.Int32
	retry := newRuntimeTestBarrier()
	secondCallback, thirdCallback := newRuntimeTestBarrier(), newRuntimeTestBarrier()
	retryReturned, secondReturned := make(chan struct{}), make(chan struct{})
	defer retry.open()
	defer secondCallback.open()
	defer thirdCallback.open()
	if err := f.box.BindRuntimePersistenceOptions(func(id RuntimeIdentity, content []byte) error {
		n := calls.Add(1)
		entered <- r4ExactInvocation{id, append([]byte(nil), content...)}
		if n == 1 {
			return errors.New("original file sync returned failure")
		}
		if n == 2 {
			retry.block()
			defer close(retryReturned)
		}
		if n == 3 {
			secondCallback.block()
			defer close(secondReturned)
		}
		if n == 4 {
			thirdCallback.block()
		}
		return nil
	}, "exact_configuration_file", true); err != nil {
		t.Fatal(err)
	}
	r3SourceHoldWorkerActivation(t, f)
	f.start(t)
	owner := f.box.runtime.fakeIPPersistence
	if owner == nil || !owner.ready {
		t.Fatal("real persistent namespace owner missing")
	}
	old, err := f.box.runtime.fakeIP.Borrow(netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	address, err := old.Create("retained.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "retained.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600},
		A:   net.IP(address.AsSlice()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(time.Now())
	// A genuine uncompleted answer retains the original migration's journal
	// handles through later publications, even if reclamation is requested.
	pendingAnswer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "retained.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600},
		A:   net.IP(address.AsSlice()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer pendingAnswer.Abort()
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, sourcePath, runtimeTestSourceBytes("second.example"))
	runtimeTestWait(t, r4ExactRefresh(t, p), "source publication after real namespace Wait")
	first := r4ExactNext(t, entered)
	original := r4ExactRecord(t, f, first.active)
	f.box.runtime.access.Lock()
	migration, actual := original.persistenceParticipant.(*fakeip.RangeMigration)
	plans := len(f.box.runtime.plans)
	f.box.runtime.access.Unlock()
	if !actual || migration == nil {
		t.Fatal("source driver lost actual namespace participant")
	}
	if original.plan.TransactionID == "" || original.operation.TransactionID != original.plan.TransactionID ||
		runtimeDigest(first.canonical) != first.active.EffectiveDigest {
		t.Fatal("original source receipt did not name its exact canonical transaction")
	}
	repeated := r4ExactNext(t, entered)
	if repeated.active != first.active || !bytes.Equal(repeated.canonical, first.canonical) {
		t.Fatal("namespace retry changed original receipt")
	}
	catalog, err := owner.journal.FakeIPRuntimeCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, link := range catalog.Links {
		if link.ID == original.plan.TransactionID {
			matches++
			if link.Acknowledged || link.EffectiveConfigurationID != first.active.EffectiveDigest {
				t.Fatal("callback failure fabricated exact namespace ACK")
			}
		}
	}
	if matches != 1 {
		t.Fatal("real namespace journal did not retain exact original transaction")
	}
	// Block the actual journal's writer, not an injected participant. A nil
	// callback return still cannot certify its exact durable namespace link.
	journalWrite, err := owner.journal.DB.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer journalWrite.Rollback()
	f.box.runtime.access.Lock()
	work := f.box.runtime.workDone
	f.box.runtime.access.Unlock()
	retry.open()
	runtimeTestWait(t, retryReturned, "original callback returned before real namespace ACK")
	select {
	case <-work:
		t.Fatal("driver bypassed blocked actual namespace ACK")
	case <-time.After(50 * time.Millisecond):
	}
	f.box.runtime.access.Lock()
	premature := original.operation.Durable || !f.box.runtime.preparing
	f.box.runtime.access.Unlock()
	if premature {
		t.Fatal("callback nil return fabricated durable namespace completion")
	}
	if err := journalWrite.Rollback(); err != nil {
		t.Fatal(err)
	}
	r4ExactDurable(t, f, original, first.active, first.canonical, plans)
	catalog, err = owner.journal.FakeIPRuntimeCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	matches = 0
	for _, link := range catalog.Links {
		if link.ID == original.plan.TransactionID && link.Acknowledged && link.EffectiveConfigurationID == first.active.EffectiveDigest {
			matches++
		}
	}
	if matches != 1 {
		t.Fatal("production retry did not perform the original exact namespace ACK")
	}
	f.box.runtime.access.Lock()
	same := original.persistenceParticipant == migration
	f.box.runtime.access.Unlock()
	if !same {
		t.Fatal("retry substituted namespace participant")
	}
	assertReceipt := func(record *runtimePlanRecord, call r4ExactInvocation) {
		t.Helper()
		status, err := f.box.GetRuntimeConfigStatus(runtimeSourceProducerActor, call.active.Incarnation, record.plan.TransactionID)
		if err != nil || status.LookupState != "FOUND" || status.Active != call.active || status.Operation == nil ||
			status.Operation.TransactionID != record.plan.TransactionID || status.Operation.Active != call.active ||
			!status.Operation.Durable || status.Operation.State != "COMMITTED" || status.PersistenceMode != "exact_configuration_file" ||
			status.DurableAppliedDigest != call.active.EffectiveDigest {
			t.Fatal("current Core receipt did not match its exact durable source transaction", status, err)
		}
	}
	assertReceipt(original, first)
	assertLink := func(record *runtimePlanRecord, call r4ExactInvocation, acknowledged bool) {
		t.Helper()
		catalog, err := owner.journal.FakeIPRuntimeCatalog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		matches := 0
		for _, link := range catalog.Links {
			if link.ID == record.plan.TransactionID {
				matches++
				if link.Acknowledged != acknowledged || link.EffectiveConfigurationID != call.active.EffectiveDigest {
					t.Fatal("actual namespace ACK did not match its exact source transaction", link, acknowledged)
				}
			}
		}
		if matches != 1 {
			t.Fatal("actual journal lost the exact source transaction", record.plan.TransactionID)
		}
	}
	r3SourceWrite(t, sourcePath, runtimeTestSourceBytes("third.example"))
	secondRefresh := r4ExactRefresh(t, p)
	next := r4ExactNext(t, entered)
	second := r4ExactRecord(t, f, next.active)
	f.box.runtime.access.Lock()
	secondMigration, actual := second.persistenceParticipant.(*fakeip.RangeMigration)
	distinct := actual && secondMigration != nil && secondMigration != migration &&
		second.plan.TransactionID != "" && second.plan.TransactionID != original.plan.TransactionID &&
		second.operation.TransactionID == second.plan.TransactionID
	f.box.runtime.access.Unlock()
	if !distinct || next.active.Incarnation != first.active.Incarnation || next.active.ControlRevision != first.active.ControlRevision ||
		next.active.EffectiveDigest != first.active.EffectiveDigest || !bytes.Equal(next.canonical, first.canonical) {
		t.Fatal("second material source update did not retain a distinct transaction for identical canonical bytes")
	}
	assertLink(second, next, false)
	// Keep the actual pre-migration namespace borrower and delivered answer
	// alive. Replaying its original ACK cannot acknowledge the newer link.
	if err := migration.AcknowledgePersistence(runtimeTestContext(t), first.active.EffectiveDigest); err != nil {
		t.Fatal("retained original namespace ACK could not be replayed", err)
	}
	if _, err := f.box.RetryRuntimePersistence(runtimeTestContext(t), runtimeSourceProducerActor, RuntimePersistenceRetry{
		ContractVersion: RuntimeConfigContractVersion, TransactionID: original.plan.TransactionID,
		Active: first.active, PersistenceMode: "exact_configuration_file",
	}); err == nil {
		t.Fatal("old original source retry acquired the newer source tail")
	}
	assertLink(original, first, true)
	assertLink(second, next, false)
	f.box.runtime.access.Lock()
	pending := !second.operation.Durable && f.box.runtime.preparing && f.box.runtime.pendingPersistence == second &&
		original.operation.Durable && original.operation.Active == first.active
	work = f.box.runtime.workDone
	f.box.runtime.access.Unlock()
	if !pending || calls.Load() != 3 {
		t.Fatal("old original retry/ACK falsely settled or replayed the newer source tail")
	}
	secondWrite, err := owner.journal.DB.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer secondWrite.Rollback()
	secondCallback.open()
	runtimeTestWait(t, secondReturned, "second callback returned before its exact namespace ACK")
	select {
	case <-work:
		t.Fatal("second source tail bypassed blocked actual namespace ACK")
	case <-time.After(50 * time.Millisecond):
	}
	f.box.runtime.access.Lock()
	premature = second.operation.Durable || !f.box.runtime.preparing || f.box.runtime.pendingPersistence != second
	f.box.runtime.access.Unlock()
	if premature {
		t.Fatal("second callback nil return fabricated exact namespace durability")
	}
	if err := secondWrite.Rollback(); err != nil {
		t.Fatal(err)
	}
	runtimeTestWait(t, secondRefresh, "second source event after original namespace ACK")
	r3SourceSettled(t, f)
	if next.active.Revision != first.active.Revision+1 || calls.Load() != 3 {
		t.Fatal("real namespace recovery did not unblock next source event")
	}
	r4ExactDurable(t, f, second, next.active, next.canonical, plans+1)
	assertReceipt(second, next)
	if err := f.box.runtime.fakeIP.ReclaimPersistence(runtimeTestContext(t)); err != nil {
		t.Fatal("actual namespace reclamation failed while original answer remained pending", err)
	}
	assertLink(original, first, true)
	assertLink(second, next, true)
	lease, view := f.acquire(t)
	set, _ := view.router.RuleSet("sites")
	matched := set != nil && set.Match(&adapter.InboundContext{Domain: "third.example"})
	lease.Release()
	if !matched {
		t.Fatal("second source event did not publish its actual material resource")
	}
	r3SourceWrite(t, sourcePath, runtimeTestSourceBytes("fourth.example"))
	thirdRefresh := r4ExactRefresh(t, p)
	thirdCall := r4ExactNext(t, entered)
	third := r4ExactRecord(t, f, thirdCall.active)
	f.box.runtime.access.Lock()
	thirdMigration, actual := third.persistenceParticipant.(*fakeip.RangeMigration)
	distinct = actual && thirdMigration != nil && thirdMigration != migration && thirdMigration != secondMigration &&
		third.plan.TransactionID != "" && third.plan.TransactionID != original.plan.TransactionID &&
		third.plan.TransactionID != second.plan.TransactionID && third.operation.TransactionID == third.plan.TransactionID
	f.box.runtime.access.Unlock()
	if !distinct || thirdCall.active.Incarnation != first.active.Incarnation || thirdCall.active.ControlRevision != first.active.ControlRevision ||
		thirdCall.active.Revision != next.active.Revision+1 || thirdCall.active.EffectiveDigest != first.active.EffectiveDigest ||
		!bytes.Equal(thirdCall.canonical, first.canonical) || calls.Load() != 4 {
		t.Fatal("third actual source event did not retain its own same-canonical transaction")
	}
	assertLink(third, thirdCall, false)
	thirdCallback.open()
	runtimeTestWait(t, thirdRefresh, "third actual source event after second exact namespace ACK")
	r4ExactDurable(t, f, third, thirdCall.active, thirdCall.canonical, plans+2)
	assertReceipt(third, thirdCall)
	assertLink(original, first, true)
	assertLink(second, next, true)
	assertLink(third, thirdCall, true)
	lease, view = f.acquire(t)
	set, _ = view.router.RuleSet("sites")
	matched = set != nil && set.Match(&adapter.InboundContext{Domain: "fourth.example"})
	lease.Release()
	if !matched {
		t.Fatal("third source event did not publish its actual material resource")
	}
	if retained, err := old.Create("retained.example", false); err != nil || retained != address {
		t.Fatal("actual original namespace borrower did not survive all three source events", retained, err)
	}
	if domain, found := f.box.runtime.fakeIP.RecognitionStore().Lookup(address); !found || domain != "retained.example" {
		t.Fatal("source persistence recovery discarded actual protected answer")
	}
	pendingAnswer.Abort()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
}
