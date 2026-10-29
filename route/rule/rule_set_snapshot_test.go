package rule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestRuleSetSnapshotPublicationAndClose(t *testing.T) {
	var s ruleSetPublication
	_, err := s.publish(nil, adapter.RuleSetMetadata{ContainsIPCIDRRule: true}, "first")
	if err != nil {
		t.Fatal(err)
	}
	retained := s.loadSnapshot()
	_, err = s.publish(nil, adapter.RuleSetMetadata{}, "second")
	if err != nil {
		t.Fatal(err)
	}
	if retained.digest != "first" || !retained.metadata.ContainsIPCIDRRule || retained.revision != 1 {
		t.Fatal("retired snapshot mutated")
	}
	if s.loadSnapshot().digest != "second" || s.loadSnapshot().revision != 2 {
		t.Fatal("new publication missing")
	}
	s.closePublication()
	if _, err = s.publish(nil, adapter.RuleSetMetadata{}, "late"); err == nil {
		t.Fatal("publish after Close")
	}
	if !s.RuleSetStatus().Closed || s.RuleSetStatus().ActiveDigest != "" {
		t.Fatal("closed snapshot acknowledged")
	}
	if retained.digest != "first" {
		t.Fatal("Close mutated reader snapshot")
	}
}

func TestRuleSetSnapshotConcurrentReadPublishCleanupClose(t *testing.T) {
	var s ruleSetPublication
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				p := s.loadSnapshot()
				if p.digest == "ip" && !p.metadata.ContainsIPCIDRRule {
					t.Error("mixed generation")
				}
				_ = s.RuleSetStatus()
			}
		})
	}
	for range 100 {
		_, _ = s.publish(nil, adapter.RuleSetMetadata{ContainsIPCIDRRule: true}, "ip")
		s.cleanupPublication()
	}
	s.closePublication()
	wg.Wait()
}

func TestLocalRuleSetDigestRetainsAcceptedBytesOnInvalidReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	content := []byte(`{"version":3,"rules":[{"domain":["old.invalid"]}]}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &LocalRuleSet{ctx: context.Background(), logger: logger.NOP(), tag: "test", fileFormat: C.RuleSetFormatSource}
	if err := s.reloadFile(path); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	before := s.RuleSetStatus()
	if before.ActiveDigest != hex.EncodeToString(sum[:]) || before.Revision != 1 {
		t.Fatal(before)
	}
	if err := os.WriteFile(path, []byte(`{"broken"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadFile(path); err == nil {
		t.Fatal("invalid update accepted")
	}
	after := s.RuleSetStatus()
	if after.ActiveDigest != before.ActiveDigest || after.Revision != before.Revision || after.LastError == "" {
		t.Fatal(after)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadFile(path); err == nil {
		t.Fatal("closed set revived")
	}
}

func TestEmptyInlineRuleSetConstructsAndNeverMatches(t *testing.T) {
	for _, rules := range [][]option.HeadlessRule{nil, {}} {
		s, err := NewLocalRuleSet(context.Background(), logger.NOP(), "empty", option.RuleSet{
			Type:          C.RuleSetTypeInline,
			InlineOptions: option.PlainRuleSet{Rules: rules},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, metadata := range []adapter.InboundContext{
			{Destination: M.ParseSocksaddr("192.0.2.7:443")},
			{Destination: M.ParseSocksaddr("[2001:db8::7]:443")},
			{Domain: "example.org", Network: N.NetworkTCP},
		} {
			if s.Match(&metadata) {
				t.Fatalf("empty set matched %+v", metadata)
			}
		}
		if s.Metadata() != (adapter.RuleSetMetadata{}) || len(s.ExtractIPSet()) != 0 || s.RuleSetStatus().Revision != 1 {
			t.Fatal("empty snapshot was not published normally")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalRuleSetEmptyReloadPreservesRetainedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	empty := []byte(`{"version":3,"rules":[]}`)
	nonempty := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.7/32","2001:db8::7/128"]}]}`)
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
	s, err := NewLocalRuleSet(context.Background(), logger.NOP(), "local", option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Format:       C.RuleSetFormatSource,
		LocalOptions: option.LocalRuleSet{Path: path},
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	callbacks := 0
	s.RegisterCallback(func(adapter.RuleSet) { callbacks++ })
	check := func(content []byte, revision uint64, hasIP bool) {
		t.Helper()
		sum := sha256.Sum256(content)
		status := s.RuleSetStatus()
		if status.ActiveDigest != hex.EncodeToString(sum[:]) || status.Revision != revision || status.LastError != "" || s.Metadata().ContainsIPCIDRRule != hasIP {
			t.Fatalf("unexpected accepted snapshot: %+v / %+v", status, s.Metadata())
		}
	}
	check(empty, 1, false)
	replace(nonempty)
	if err := s.reloadFile(path); err != nil {
		t.Fatal(err)
	}
	check(nonempty, 2, true)
	retained := s.loadSnapshot()
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
			if retained.revision != 2 || !retained.metadata.ContainsIPCIDRRule || !matchAnyHeadlessRule(retained.rules, &metadata) {
				t.Error("retained nonempty reader changed during publication")
				return
			}
		}
	}()
	defer join()
	<-entered
	replace(empty)
	if err := s.reloadFile(path); err != nil {
		t.Fatal(err)
	}
	check(empty, 3, false)
	if callbacks != 2 || s.Match(&adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.7:443")}) {
		t.Fatal("empty transition matched or lost callbacks")
	}
	accepted := s.loadSnapshot()
	for _, malformed := range []struct {
		content string
		missing bool
	}{
		{`{"version":3,"rules":[{}]}`, true},
		{`{"version":3,"rules":[{"ip_cidr":[]}]}`, true},
		{`{"version":3,"rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":[]}]}]}`, true},
		{`{"version":3,"rules":{}}`, false},
		{`{"version":255,"rules":[]}`, false},
	} {
		replace([]byte(malformed.content))
		err := s.reloadFile(path)
		if err == nil || (malformed.missing && !strings.Contains(err.Error(), "missing conditions")) {
			t.Fatalf("malformed rule did not reach its validation: %s: %v", malformed.content, err)
		}
		if s.loadSnapshot() != accepted || callbacks != 2 || s.RuleSetStatus().LastError == "" {
			t.Fatal("rejected source changed accepted snapshot, bytes digest or callbacks")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	replace(nonempty)
	if err := s.reloadFile(path); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("late reload after Close: %v", err)
	}
	if !s.RuleSetStatus().Closed || s.RuleSetStatus().Revision != 3 || callbacks != 2 {
		t.Fatal("closed set admitted publication")
	}
	join()
}
