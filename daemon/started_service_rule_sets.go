package daemon

import (
	"context"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func validateRuleSetStatusTags(request *RuleSetStatusRequest) error {
	if request == nil || len(request.Tags) == 0 || len(request.Tags) > 256 {
		return status.Error(codes.InvalidArgument, "request requires 1..256 rule-set tags")
	}
	seen := make(map[string]bool, len(request.Tags))
	for _, tag := range request.Tags {
		if strings.TrimSpace(tag) == "" || len(tag) > 1024 || seen[tag] {
			return status.Error(codes.InvalidArgument, "empty, oversized or duplicate rule-set tag")
		}
		seen[tag] = true
	}
	return nil
}

// This read never parses requested content or changes the router. Holding the
// service lock pins the started instance epoch; a graph lease owns its rules
// for the whole bounded response.
func (s *StartedService) GetRuleSetStatus(ctx context.Context, request *RuleSetStatusRequest) (*RuleSetStatusResponse, error) {
	if err := validateRuleSetStatusTags(request); err != nil {
		return nil, err
	}
	if err := s.waitForStarted(ctx); err != nil {
		return nil, err
	}
	return s.readStartedRuleSetStatus(request.Tags)
}

// waitForStarted is only an admission wait. Reload may begin before this read
// lock is acquired, and may publish a new instance before updating startedAt.
// Status, instance, timestamp and rule reads must share this lock epoch.
func (s *StartedService) readStartedRuleSetStatus(tags []string) (*RuleSetStatusResponse, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.serviceStatus == nil || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil || s.startedAt.IsZero() || s.instance.closeStarted.Load() {
		return nil, status.Error(codes.Unavailable, "no active instance")
	}
	snapshot, _, release, err := s.instance.runtimeSnapshot()
	if err != nil {
		return nil, err
	}
	defer release()
	router := service.FromContext[adapter.Router](snapshot.ctx)
	if lease, ok := adapter.RuntimeLeaseFromContext(snapshot.ctx); ok {
		// The stable router intentionally exposes no raw graph rule-set leaves.
		router = lease.View().Router()
	}
	if router == nil {
		return nil, status.Error(codes.Unavailable, "router unavailable")
	}
	return collectRuleSetStatus(tags, s.startedAt.UnixNano(), router.RuleSet)
}

func collectRuleSetStatus(tags []string, instance int64, lookup func(string) (adapter.RuleSet, bool)) (*RuleSetStatusResponse, error) {
	result := &RuleSetStatusResponse{InstanceStartedAtUnixNano: instance}
	for _, tag := range tags {
		set, found := lookup(tag)
		if !found {
			return nil, status.Error(codes.NotFound, "rule-set not found: "+tag)
		}
		provider, ok := set.(adapter.RuleSetStatusProvider)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "rule-set status unavailable: "+tag)
		}
		loaded := provider.RuleSetStatus()
		result.RuleSets = append(result.RuleSets, &RuleSetLoadStatus{Tag: tag, ActiveDigest: loaded.ActiveDigest, Revision: loaded.Revision, WatcherState: loaded.WatcherState, LastError: loaded.LastError, Closed: loaded.Closed})
	}
	return result, nil
}
