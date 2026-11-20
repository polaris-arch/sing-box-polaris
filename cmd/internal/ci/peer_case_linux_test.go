package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPeerCaseScheduleStopsOnUncertainIdentity(t *testing.T) {
	schedule, err := decodePeerCaseSchedule()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	results := executePeerCaseSchedule(t.Context(), schedule, func(entry peerScheduledCase) (map[string]any, error) {
		calls++
		return nil, errors.New("private-path-canary")
	})
	if calls != 1 || len(results) != len(schedule) {
		t.Fatalf("unexpected scheduled execution: %d calls, %d receipts", calls, len(results))
	}
	if results[0]["status"] != "FAIL" || results[0]["identityUncertain"] != true ||
		results[0]["continuationSafe"] != false || results[0]["error"] != "non-public exception details withheld" {
		t.Fatalf("unexpected failing case: %#v", results[0])
	}
	for index, item := range results {
		if item["kind"] != schedule[index].Kind || item["mutation"] != schedule[index].Mutation {
			t.Fatalf("case receipt changed schedule identity: %#v", item)
		}
		if index == 0 {
			continue
		}
		blocked, _ := item["blockedByCase"].(map[string]any)
		if item["status"] != "NOT_RUN" || item["reason"] != "blocked_by_cleanup_or_identity" || blocked["index"] != 0 ||
			blocked["kind"] != schedule[0].Kind || blocked["mutation"] != schedule[0].Mutation {
			t.Fatalf("remaining case lost blocking evidence: %#v", item)
		}
	}
}

func TestPeerLogUsesSourceVerifiedPanicFrames(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module github.com/example/fixture\n",
		"owned.go": `package fixture
func Owned() {}
type Queue[T any] struct{}
func (Queue[T]) Value() {}
func (*Queue[T]) Push() {}
type Pair[T, U any] struct{}
func (*Pair[T, U]) Mix() {}
func Func[T any]() {}
`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := []byte("panic: private-text-canary K\nCONNECTION REFUSED\n" +
		"github.com/example/fixture.Untrusted(private-arg-canary)\n\t/private-path-canary/owned.go:8 +0x123\n" +
		"github.com/example/fixture.Owned(private-arg-canary)\n\t/private-path-canary/owned.go:2 +0x123\n" +
		"github.com/example/fixture.Value(private-arg-canary)\n\t/private-path-canary/owned.go:4 +0x123\n" +
		"github.com/example/fixture.Queue[private-type-canary].Value(private-arg-canary)\n\t/private-path-canary/owned.go:4 +0x123\n" +
		"github.com/example/fixture.(*Queue[...]).Push(private-arg-canary)\n\t/private-path-canary/owned.go:5 +0x123\n" +
		"github.com/example/fixture.Queue[...].Push(private-arg-canary)\n\t/private-path-canary/owned.go:5 +0x123\n" +
		"github.com/example/fixture.Mix(private-arg-canary)\n\t/private-path-canary/owned.go:7 +0x123\n" +
		"github.com/example/fixture.(*Pair[...]).Mix.func1(private-arg-canary)\n\t/private-path-canary/owned.go:7 +0x123\n" +
		"github.com/example/fixture.Func[private-type-canary](private-arg-canary)\n\t/private-path-canary/owned.go:8 +0x123\n" +
		"runtime cleanup snapshot: {\"schema\":\"runtime-cleanup-v1\",\"schema\":\"same\",\"secret\":\"private-json-canary\"}\n")
	safe := safePeerLog(raw, root)
	categories := safe["categories"].([]map[string]any)
	if len(categories) != 1 || categories[0]["category"] != "connection_refused" ||
		categories[0]["byteOffset"] != strings.Index(string(raw), "CONNECTION REFUSED") {
		t.Fatalf("diagnostic byte offsets must address the original private log: %#v", categories)
	}
	frames := safe["goFrames"].([]map[string]any)
	want := []struct {
		name string
		line int
	}{
		{"Owned", 2}, {"Queue.Value", 4}, {"(*Queue).Push", 5}, {"(*Pair).Mix.func1", 7}, {"Func", 8},
	}
	if len(frames) != len(want) || safe["cleanupSnapshotsRejected"] != 1 {
		t.Fatalf("unexpected panic evidence: %#v", safe)
	}
	for index, frame := range frames {
		if frame["symbol"] != "github.com/example/fixture."+want[index].name ||
			frame["file"] != "owned.go" || frame["line"] != want[index].line {
			t.Fatalf("unexpected source-verified frame: %#v", frame)
		}
	}
	data, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "canary") {
		t.Fatalf("non-public diagnostic material retained: %s", data)
	}
}

func TestPeerRelayEmptySocketTableDoesNotRetireLiveInode(t *testing.T) {
	slot := &peerRelaySlot{inode: "111"}
	slot.observeEmptyPort(map[string]bool{"111": true})
	if slot.retired || slot.matches("") || slot.matches("222") || !slot.matches("111") {
		t.Fatal("an empty table must drop the packet without retiring a still-owned inode")
	}
	slot.observeEmptyPort(map[string]bool{"222": true})
	if !slot.retired || slot.retirementReason == nil || *slot.retirementReason != "owned_inode_absent_port_unoccupied" ||
		slot.matches("111") || slot.matches("222") {
		t.Fatal("corroborated retirement must refuse the old and replacement inodes")
	}
}

func TestPeerRelayTimeoutRevokesSocketCustody(t *testing.T) {
	relay, err := startPeerRelay(1)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.revokeSockets()
	back, backPort, err := peerBoundSocket(unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	relay.socketMu.Lock()
	relay.sockets = append(relay.sockets, back)
	relay.socketMu.Unlock()

	// Hold the same state gate a worker uses to inspect the owning
	// process. Ordinary case retirement must time out and revoke both ports.
	state := &peerCase{
		protocol: peerProtocol{kind: "naive-h3"}, relay: relay, reservedTCP: -1, scope: &peerProcessScope{},
		receipt: map[string]any{"status": "RUNNING", "identityUncertain": false},
	}
	relay.stateGate.lock()
	retired := make(chan struct{})
	go func() {
		state.retire()
		close(retired)
	}()
	relayHeld := true
	defer func() {
		if relayHeld {
			relay.stateGate.unlock()
		}
		select {
		case <-retired:
		case <-time.After(6 * time.Second):
		}
	}()
	select {
	case <-relay.stop:
	case <-time.After(3 * time.Second):
		t.Fatal("case retirement blocked before stopping the observer")
	}
	// The preparation failure must release both ports before the joined
	// receipt, even while the worker remains blocked on the state gate.
	for _, port := range []int{relay.port, backPort} {
		fd, _, err := peerBoundSocket(unix.SOCK_DGRAM, port)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
	}
	select {
	case <-retired:
	case <-time.After(6 * time.Second):
		t.Fatal("case retirement blocked on the observer state gate")
	}
	observations, _ := state.receipt["udpObservers"].([]any)
	if !state.relayClosed || state.receipt["status"] != "FAIL" || state.receipt["continuationSafe"] != false ||
		state.receipt["identityUncertain"] != true || len(observations) != 1 {
		t.Fatalf("case retirement did not fail closed: %#v", state.receipt)
	}
	observation := observations[0].(map[string]any)
	if observation["threadJoined"] != false || observation["terminalAcknowledged"] != false ||
		observation["allSocketsClosed"] != true {
		t.Fatalf("timeout did not report only the proved cleanup facts: %v", observation)
	}
	if err := relay.withSockets(func() error {
		t.Error("revoked worker reached a raw descriptor")
		return nil
	}); !errors.Is(err, errPeerRelayStopped) {
		t.Fatalf("expected socket custody rejection, got %v", err)
	}
	relay.stateGate.unlock()
	relayHeld = false
	select {
	case <-relay.done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay worker did not terminate after its state lock was released")
	}
	for _, port := range []int{relay.port, backPort} {
		fd, _, err := peerBoundSocket(unix.SOCK_DGRAM, port)
		if err == nil {
			unix.Close(fd)
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			t.Fatalf("worker changed another socket's ownership: %v", err)
		}
	}
}

func TestPeerMetadataDeadlineReapsGitProcess(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("GITHUB_REPOSITORY", repository)
	t.Setenv("GITHUB_REPOSITORY_ID", repositoryID)
	t.Setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
	t.Setenv("GITHUB_SHA", strings.Repeat("a", 40))
	t.Setenv("GITHUB_WORKFLOW_SHA", strings.Repeat("a", 40))
	t.Setenv("GITHUB_RUN_ID", "1")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_REF", "refs/heads/test")
	t.Setenv("GITHUB_WORKFLOW_REF", repository+"/.github/workflows/build.yml@refs/heads/test")
	if err := os.WriteFile(filepath.Join(root, "git"), []byte("#!/bin/sh\nprintf '%s' \"$$\" > own-git.pid\nexec /bin/sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	facts := map[string]any{}
	started := time.Now()
	err := peerLocalContextWithin(ctx, root, root, facts, true)
	if !errors.Is(err, context.DeadlineExceeded) || len(facts) != 0 || time.Since(started) > 2*time.Second {
		t.Fatalf("timed-out checkout supplied unverified facts or overran its bound: %v, %v", facts, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "own-git.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("Git was not reaped before returning from its deadline: %v", err)
	}
}
