package tls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	C "github.com/sagernet/sing-box/constant"
)

type FingerprintProfile struct {
	ID                           string `json:"id"`
	DisplayName                  string `json:"displayName"`
	Client                       string `json:"client"`
	TemplateVersion              string `json:"templateVersion"`
	Selection                    string `json:"selection"`
	TemplateOffersX25519MLKEM768 *bool  `json:"templateOffersX25519MLKEM768"`
}

type FingerprintModule struct {
	Path    string             `json:"path"`
	Version string             `json:"version"`
	Sum     string             `json:"sum"`
	Replace *FingerprintModule `json:"replace,omitempty"`
}

type FingerprintCapabilities struct {
	Schema                             string               `json:"schema"`
	Enabled                            bool                 `json:"enabled"`
	CoreVersion                        string               `json:"coreVersion"`
	SourceCommit                       string               `json:"sourceCommit"`
	SourceModified                     *bool                `json:"sourceModified"`
	GoVersion                          string               `json:"goVersion"`
	RequiredGoVersion                  string               `json:"requiredGoVersion"`
	BuildTags                          string               `json:"buildTags"`
	OS                                 string               `json:"os"`
	Arch                               string               `json:"arch"`
	Modules                            []FingerprintModule  `json:"modules"`
	DefaultFingerprint                 string               `json:"defaultFingerprint"`
	Profiles                           []FingerprintProfile `json:"profiles"`
	LegacyChromeAliases                []string             `json:"legacyChromeAliases"`
	RandomSemantics                    string               `json:"randomSemantics"`
	RandomizedSemantics                string               `json:"randomizedSemantics"`
	ShadowTLSSessionIDWithECHSupported bool                 `json:"shadowTLSSessionIDWithECHSupported"`
	CurvePreferencesSupported          bool                 `json:"curvePreferencesSupported"`
	RealityX25519MLKEM768              string               `json:"realityX25519MLKEM768"`
	NegotiationEvidence                string               `json:"negotiationEvidence"`
}

func fingerprintModule(m *debug.Module) FingerprintModule {
	out := FingerprintModule{Path: m.Path, Version: m.Version, Sum: m.Sum}
	if m.Replace != nil {
		r := fingerprintModule(m.Replace)
		out.Replace = &r
	}
	return out
}

// FingerprintCapabilitiesJSON describes this loaded core, never a future release.
// Source/build-module fields remain empty when the linker omitted that evidence.
// A template's offer is not a measurement of a connection's negotiated group.
func FingerprintCapabilitiesJSON() (string, error) {
	enabled, profiles, aliases := fingerprintProfiles()
	out := FingerprintCapabilities{
		Schema: "polaris-tls-fingerprint-capabilities-v1", Enabled: enabled,
		CoreVersion: C.Version, GoVersion: runtime.Version(), RequiredGoVersion: C.ForkGoVersion,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Modules: []FingerprintModule{},
		DefaultFingerprint: "chrome", Profiles: profiles, LegacyChromeAliases: aliases,
		RandomSemantics:       "one browser Auto template selected per process; libbox instance restart does not reselect",
		RandomizedSemantics:   "weighted randomized generator with process-scoped seed; not a browser draw and not guaranteed different per connection",
		RealityX25519MLKEM768: "removed from supported groups and key shares before REALITY authentication",
		NegotiationEvidence:   "template offer only; negotiated group requires an actual completed TLS handshake",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				out.SourceCommit = s.Value
			}
			if s.Key == "-tags" {
				out.BuildTags = s.Value
			}
			if s.Key == "vcs.modified" {
				modified := s.Value != "false"
				out.SourceModified = &modified
			}
		}
		for _, m := range info.Deps {
			if m.Path == "github.com/refraction-networking/utls" || m.Path == "github.com/metacubex/utls" {
				out.Modules = append(out.Modules, fingerprintModule(m))
			}
		}
	}
	// Clean producer stamps also work with trimpath/buildvcs=false (gomobile).
	// Conflicts are errors; a version label is never converted into source proof.
	for _, source := range []string{C.SourceRevision, C.DirectoryRetirementSourceIdentity} {
		if source == "" {
			continue
		}
		decoded, err := hex.DecodeString(source)
		if err != nil || len(decoded) != 20 || source != strings.ToLower(source) {
			return "", fmt.Errorf("invalid clean-source build identity")
		}
		if out.SourceCommit != "" && out.SourceCommit != source {
			return "", fmt.Errorf("conflicting VCS/producer source identities")
		}
		if out.SourceModified != nil && *out.SourceModified {
			return "", fmt.Errorf("clean producer identity conflicts with modified VCS source")
		}
		out.SourceCommit = source
		clean := false
		out.SourceModified = &clean
	}
	b, err := json.Marshal(out)
	return string(b), err
}
