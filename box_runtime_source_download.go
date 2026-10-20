package box

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func runtimeHasRemoteSources(options option.Options) bool {
	if options.Route != nil {
		for _, source := range options.Route.RuleSet {
			if source.Type == C.RuleSetTypeRemote {
				return true
			}
		}
	}
	return false
}

// Remote bytes are explicitly fetched through the retained CURRENT revision,
// then bound immutably to the candidate. This avoids a fictitious candidate
// graph with placeholder rules or a process-default network fallback. This
// first slice rejects changes to the download routing/configuration itself.
func (s *Box) prepareRuntimeSourceDownload(expected RuntimeIdentity, candidate []byte, options option.Options) (*runtimeSourceDownloadSession, *RuntimePlanError) {
	c := s.runtime
	reject := func(code, message string) (*runtimeSourceDownloadSession, *RuntimePlanError) {
		return nil, &RuntimePlanError{Code: code, Path: "route.rule_set", Message: message}
	}
	c.access.Lock()
	if c.stopped || c.active != expected {
		c.access.Unlock()
		return reject("STALE_REVISION", "active configuration changed before source preparation")
	}
	before := append([]byte(nil), c.canonical...)
	previous := make(map[string]runtimeSourceSnapshot, len(c.currentSources))
	for _, source := range c.currentSources {
		source.content = append([]byte(nil), source.content...)
		previous[source.identity] = source
	}
	c.access.Unlock()
	if !runtimeSameDownloadConfiguration(before, candidate) {
		return reject("RESTART_REQUIRED", "source download routing changes require an explicit restart in this capability version")
	}
	if options.Route != nil {
		for _, source := range options.Route.RuleSet {
			if source.Type != C.RuleSetTypeRemote {
				continue
			}
			value := source.RemoteOptions.HTTPClient
			if source.RemoteOptions.DownloadDetour != "" || (value != nil && !value.IsEmpty() && value.Tag == "") {
				return reject("RESTART_REQUIRED", "inline source download transports are outside this runtime capability")
			}
		}
	}
	lease, err := c.store.Acquire()
	if err != nil {
		return reject("SOURCE_PREPARATION_UNAVAILABLE", "source download graph is unavailable")
	}
	view, ok := lease.View().(*runtimeView)
	if !ok || view.identity != expected.graphRevision() {
		lease.Release()
		return reject("STALE_REVISION", "source download graph changed")
	}
	id := view.componentIDs["http-manager"]
	c.access.Lock()
	resource := c.catalog[id]
	c.access.Unlock()
	if resource == nil || view.httpClients == nil {
		lease.Release()
		return reject("SOURCE_PREPARATION_UNAVAILABLE", "retained source HTTP owner is unavailable")
	}
	hash := sha256.New()
	runtimeHashField(hash, "active-source-download-v1")
	runtimeHashField(hash, fmt.Sprint(id.Incarnation, ":", id.Sequence))
	runtimeHashField(hash, resource.fingerprint)
	if options.Route != nil {
		for _, source := range options.Route.RuleSet {
			if source.Type != C.RuleSetTypeRemote {
				continue
			}
			encoded, encodeErr := json.Marshal(source.RemoteOptions.HTTPClient)
			if encodeErr != nil {
				lease.Release()
				return reject("INVALID_SOURCE", "source HTTP selection is invalid")
			}
			runtimeHashField(hash, string(encoded))
		}
	}
	var once sync.Once
	session := &runtimeSourceDownloadSession{ctx: adapter.ContextWithRuntimeLease(c.ctx, lease), candidateDigest: runtimeDigest(candidate), dependencyDigest: hex.EncodeToString(hash.Sum(nil)), previous: previous}
	session.resolve = func(_ context.Context, source option.RuleSet) (http.RoundTripper, error) {
		if source.RemoteOptions.DownloadDetour != "" {
			return nil, errors.New("source download detour was not prevalidated")
		}
		tag := ""
		if value := source.RemoteOptions.HTTPClient; value != nil && !value.IsEmpty() {
			if value.Tag == "" {
				return nil, errors.New("source inline transport was not prevalidated")
			}
			tag = value.Tag
		}
		return view.httpClients.RuntimePreparedTransport(tag)
	}
	// Every fetch is synchronous through response-body close. The managed
	// transport separately retains uncertain body/native ownership on failure;
	// releasing this batch lease cannot certify those retained tails as closed.
	session.closeAndWait = func() error { once.Do(lease.Release); return nil }
	return session, nil
}

func runtimeSameDownloadConfiguration(before, after []byte) bool {
	var old, next map[string]stdjson.RawMessage
	if stdjson.Unmarshal(before, &old) != nil || stdjson.Unmarshal(after, &next) != nil {
		return false
	}
	for _, key := range []string{"outbounds", "endpoints", "dns", "http_clients", "certificate", "certificate_providers", "ntp", "network_namespaces"} {
		if !bytes.Equal(old[key], next[key]) {
			return false
		}
	}
	var oldRoute, nextRoute map[string]stdjson.RawMessage
	if raw := old["route"]; len(raw) != 0 && stdjson.Unmarshal(raw, &oldRoute) != nil {
		return false
	}
	if raw := next["route"]; len(raw) != 0 && stdjson.Unmarshal(raw, &nextRoute) != nil {
		return false
	}
	keys := make(map[string]bool)
	for key := range oldRoute {
		keys[key] = true
	}
	for key := range nextRoute {
		keys[key] = true
	}
	for key := range keys {
		if key != "rules" && key != "rule_set" && !bytes.Equal(oldRoute[key], nextRoute[key]) {
			return false
		}
	}
	return true
}
