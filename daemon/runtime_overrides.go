package daemon

import (
 box "github.com/sagernet/sing-box"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

func cloneRuntimeOverrides(value *OverrideOptions) *OverrideOptions {
 if value == nil { return nil }
 return &OverrideOptions{AutoRedirect: value.AutoRedirect, IncludePackage: append([]string(nil), value.IncludePackage...), ExcludePackage: append([]string(nil), value.ExcludePackage...)}
}
func appendRuntimeOverridePackages(configured, overrides []string) []string {
 result := append([]string(nil), configured...)
 seen := make(map[string]bool, len(result)+len(overrides))
 for _, value := range result { seen[value] = true }
 for _, value := range overrides { if !seen[value] { result = append(result, value); seen[value] = true } }
 return result
}
func (s *StartedService) runtimePlanInstance() (*box.Box, *OverrideOptions, error) {
 s.serviceAccess.RLock(); current := s.instance; s.serviceAccess.RUnlock()
 if current == nil || current.instance == nil { return nil, nil, status.Error(codes.Unavailable, "runtime unavailable") }
 // The Box and its startup overrides come from the same immutable instance.
 // A concurrent reload is rejected by the Box's existing expected identity.
 return current.instance, cloneRuntimeOverrides(current.runtimeOverrides), nil
}
