//go:build windows && with_tailscale

package directorywindows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func windowsEnvelopeHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func windowsEnvelopePath(path string) bool {
	v := filepath.VolumeName(path)
	return len(v) == 2 && v[1] == ':' && ((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) && filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) > 3 && !strings.ContainsAny(path, "/\x00") && !strings.Contains(path[2:], ":")
}

// Reuse the release producer's existing SourceRevision contract. No second
// desktop ldflag can drift from the release asset/index source identity.
func ValidateSource(expected, actual string, info *debug.BuildInfo) error {
	if !windowsEnvelopeHex(expected, 40) || !windowsEnvelopeHex(actual, 40) || expected != actual {
		return fmt.Errorf("Windows directory source identity mismatch or missing clean-source ldflag")
	}
	vcs := map[string]string{}
	if info != nil {
		for _, s := range info.Settings {
			if s.Key == "vcs" || strings.HasPrefix(s.Key, "vcs.") {
				if _, ok := vcs[s.Key]; ok {
					return fmt.Errorf("duplicate Windows directory VCS metadata")
				}
				vcs[s.Key] = s.Value
			}
		}
	}
	if len(vcs) > 0 && (vcs["vcs"] != "git" || vcs["vcs.revision"] != actual || vcs["vcs.modified"] != "false") {
		return fmt.Errorf("dirty, partial or conflicting Windows directory VCS identity")
	}
	return nil
}

// Inspect all string tokens, including non-Tailscale/log/cache fields and
// escaped/env-expanded spelling. Only native mapping may select this namespace.
func RejectReservedPaths(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid Windows directory config input: %w", err)
		}
		if s, ok := token.(string); ok && strings.Contains(strings.ToLower(os.ExpandEnv(s)), "tailscale-windows-v1") {
			return fmt.Errorf("explicit reserved Windows directory namespace is forbidden")
		}
	}
}

func Prepare(ctx context.Context, options option.Options, poisonRoot func(string) error) (context.Context, error) {
	raw := []byte(options.RawMessage)
	if len(raw) == 0 {
		var err error
		raw, err = sjson.MarshalContext(ctx, options)
		if err != nil {
			return nil, err
		}
	}
	if err := RejectReservedPaths(raw); err != nil {
		return nil, err
	}
	envelope := options.PolarisWindowsDirectory
	if envelope == nil {
		return ctx, nil
	}
	if envelope.Version != 1 || !windowsEnvelopePath(envelope.Root) || !windowsEnvelopeHex(envelope.RunNonce, 32) {
		return nil, fmt.Errorf("invalid Windows directory activation envelope")
	}
	if len(options.RawMessage) == 0 {
		return nil, fmt.Errorf("Windows directory activation requires original parsed config bytes")
	}
	info, _ := debug.ReadBuildInfo()
	if err := ValidateSource(envelope.ExpectedSource, C.SourceRevision, info); err != nil {
		return nil, err
	}
	if adapter.TailscaleDirectoryDomainFromContext(ctx) != nil || adapter.TailscaleDirectoryMappingFromContext(ctx) != nil {
		return nil, fmt.Errorf("Windows directory domain already supplied")
	}
	binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx)
	if binding != nil {
		if !(windowsEnvelopeHex(binding.RunNonce, 32) || windowsEnvelopeHex(binding.RunNonce, 64)) || !windowsEnvelopeHex(binding.ConfigDigest, 64) {
			return nil, fmt.Errorf("invalid original daemon directory binding")
		}
	}
	inputs := make([]adapter.TailscaleDirectoryMappingInput, 0)
	seen := map[string]bool{}
	for _, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		var ts *option.TailscaleEndpointOptions
		switch value := endpoint.Options.(type) {
		case *option.TailscaleEndpointOptions:
			ts = value
		case option.TailscaleEndpointOptions:
			copy := value
			ts = &copy
		}
		if ts == nil {
			return nil, fmt.Errorf("missing decoded Tailscale endpoint options")
		}
		if ts.SSHServer != nil && ts.SSHServer.Enabled {
			return nil, fmt.Errorf("Windows managed directory cannot admit unbounded SSH filesystem writers")
		}
		state, taildrop := os.ExpandEnv(ts.StateDirectory), os.ExpandEnv(ts.TaildropDirectory)
		relative, err := filepath.Rel(state, taildrop)
		if !windowsEnvelopePath(state) || !windowsEnvelopePath(taildrop) || filepath.Dir(state) != filepath.Join(envelope.Root, "tailscale") || err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) || seen[state] {
			return nil, fmt.Errorf("Tailscale configuration is outside Windows managed domain")
		}
		seen[state] = true
		inputs = append(inputs, adapter.TailscaleDirectoryMappingInput{StateDirectory: state, TaildropDirectory: taildrop})
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("Windows directory envelope has no Tailscale endpoints")
	}
	if poisonRoot == nil {
		return nil, fmt.Errorf("missing durable Windows directory revocation callback")
	}
	domain, err := adapter.NewTailscaleWindowsDirectoryDomain(envelope.Root, envelope.RunNonce)
	if err != nil {
		return nil, err
	}
	if err := domain.SetFailureHandler(func(error) error { return poisonRoot(domain.PhysicalRoot()) }); err != nil {
		return nil, err
	}
	if err := domain.Activate(); err != nil {
		return nil, err
	}
	mapping, err := adapter.NewTailscaleDirectoryMapping(domain, inputs)
	if err != nil {
		return nil, err
	}
	ctx = adapter.ContextWithTailscaleDirectoryDomain(ctx, domain)
	ctx = adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping)
	if binding == nil {
		sum := sha256.Sum256(options.RawMessage)
		ctx = service.ContextWithPtr(ctx, &adapter.TailscaleStoreRunBinding{RunNonce: envelope.RunNonce, ConfigDigest: hex.EncodeToString(sum[:])})
	}
	return ctx, nil
}
