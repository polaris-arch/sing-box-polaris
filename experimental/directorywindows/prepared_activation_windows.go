//go:build windows && with_tailscale

package directorywindows

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// PreparedActivation is an immutable, original-run-bound activation capability.
// Only its one-shot consumption state changes. No options graph, caller-owned
// slices, raw bytes or resource handles are retained. The domain and mapping are
// the exact newly created authority, not evidence of on-disk directory custody.
// A zero value cannot be installed through the package-private context key.
// Actual leases, disk poison checks and abort ownership belong to the lease plan.
type PreparedActivation struct {
	access        sync.Mutex
	consumed      bool
	rawDigest     [sha256.Size]byte
	optionsDigest [sha256.Size]byte
	envelope      option.WindowsDirectoryOptions
	binding       adapter.TailscaleStoreRunBinding
	projection    windowsDirectoryProjection
	domain        *adapter.TailscaleDirectoryDomain
	mapping       *adapter.TailscaleDirectoryMapping
}

type preparedActivationKey struct{}

type windowsDirectoryTagProjection struct {
	Type string
	Tag  string
}

type windowsDirectoryEndpointProjection struct {
	windowsDirectoryTagProjection
	StateDirectory    string
	TaildropDirectory string
	ExpandedState     string
	ExpandedTaildrop  string
	HasSSHServer      bool
	SSHServer         option.TailscaleSSHServerOptions
}

type windowsDirectoryProjection struct {
	endpoints []windowsDirectoryEndpointProjection
	outbounds []windowsDirectoryTagProjection
}

func (p windowsDirectoryProjection) equal(other windowsDirectoryProjection) bool {
	return slices.Equal(p.endpoints, other.endpoints) && slices.Equal(p.outbounds, other.outbounds)
}

type validatedWindowsActivation struct {
	rawDigest     [sha256.Size]byte
	optionsDigest [sha256.Size]byte
	envelope      option.WindowsDirectoryOptions
	binding       adapter.TailscaleStoreRunBinding
	projection    windowsDirectoryProjection
	inputs        []adapter.TailscaleDirectoryMappingInput
}

// HasPreparedActivation reports presence of the private handoff token, including
// a consumed or mismatched token. It is never a validation or an authority grant:
// callers must reject ValidatePreparedActivation errors, not fall back to fresh
// mapping or lease acquisition. JSON and a supplied mapping cannot mint a token.
func HasPreparedActivation(ctx context.Context) bool {
	activation, _ := ctx.Value(preparedActivationKey{}).(*PreparedActivation)
	return activation != nil
}

// PrepareActivation validates the whole candidate before creating its fresh
// in-memory authority. The caller must first install the ONE original run binding
// and apply all OOM/inbound overrides. It must retain the returned context, then
// acquire the actual leases under that authority before detaching the old Box.
// Supplied domains/mappings are unsupported, even if inactive; this path never
// speculatively calls Fail on an inherited old domain.
func PrepareActivation(ctx context.Context, options option.Options, poisonRoot func(string) error) (context.Context, error) {
	info, _ := debug.ReadBuildInfo()
	return prepareActivationWithSource(ctx, options, poisonRoot, C.SourceRevision, info)
}

// The explicit source arguments keep validation deterministic and independently
// testable. Only the exported entry point reads the actual compiled provenance;
// neither config nor a context value can select these arguments.
func prepareActivationWithSource(ctx context.Context, options option.Options, poisonRoot func(string) error, source string, info *debug.BuildInfo) (context.Context, error) {
	if HasPreparedActivation(ctx) {
		return nil, fmt.Errorf("prepared Windows directory activation already supplied")
	}
	if adapter.TailscaleDirectoryDomainFromContext(ctx) != nil || adapter.TailscaleDirectoryMappingFromContext(ctx) != nil {
		//nolint:staticcheck // ST1005: Windows is a proper noun; preserve the stable error contract.
		return nil, fmt.Errorf("Windows directory domain already supplied")
	}
	validated, err := validateWindowsActivationOptions(ctx, options, source, info)
	if err != nil {
		return nil, err
	}
	if poisonRoot == nil {
		return nil, fmt.Errorf("missing durable Windows directory revocation callback")
	}
	domain, err := adapter.NewTailscaleWindowsDirectoryDomain(validated.envelope.Root, validated.envelope.RunNonce)
	if err != nil {
		return nil, err
	}
	if err := domain.SetFailureHandler(func(error) error { return poisonRoot(domain.PhysicalRoot()) }); err != nil {
		return nil, err
	}
	if err := domain.Activate(); err != nil {
		return nil, err
	}
	mapping, err := adapter.NewTailscaleDirectoryMapping(domain, validated.inputs)
	if err != nil {
		return nil, err
	}
	activation := &PreparedActivation{
		rawDigest:     validated.rawDigest,
		optionsDigest: validated.optionsDigest,
		envelope:      validated.envelope,
		binding:       validated.binding,
		projection:    validated.projection,
		domain:        domain,
		mapping:       mapping,
	}
	ctx = adapter.ContextWithTailscaleDirectoryDomain(ctx, domain)
	ctx = adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping)
	return context.WithValue(ctx, preparedActivationKey{}, activation), nil
}

// ValidatePreparedActivation checks the complete handoff without consuming it.
// It does not inspect disk state or attest a lease. Prepare repeats the same
// validation and consumes the token exactly once before Box constructs resources.
func ValidatePreparedActivation(ctx context.Context, options option.Options) error {
	info, _ := debug.ReadBuildInfo()
	return validatePreparedActivation(ctx, options, C.SourceRevision, info, false)
}

func validatePreparedActivation(ctx context.Context, options option.Options, source string, info *debug.BuildInfo, consume bool) error {
	activation, _ := ctx.Value(preparedActivationKey{}).(*PreparedActivation)
	if activation == nil {
		return fmt.Errorf("missing prepared Windows directory activation")
	}
	// Serialization/projection validation can invoke option marshaling. Keep it
	// outside the one-shot mutex; the frozen token fields never change.
	validated, err := validateWindowsActivationOptions(ctx, options, source, info)
	if err != nil {
		return err
	}
	activation.access.Lock()
	defer activation.access.Unlock()
	if activation.consumed {
		return fmt.Errorf("prepared Windows directory activation already consumed")
	}
	if validated.rawDigest != activation.rawDigest || validated.optionsDigest != activation.optionsDigest || validated.envelope != activation.envelope || validated.binding != activation.binding || !validated.projection.equal(activation.projection) {
		return fmt.Errorf("prepared Windows directory activation binding or projection mismatch")
	}
	domain := adapter.TailscaleDirectoryDomainFromContext(ctx)
	mapping := adapter.TailscaleDirectoryMappingFromContext(ctx)
	if domain == nil || mapping == nil || domain != activation.domain || mapping != activation.mapping || mapping.Domain() != domain || !domain.Active() {
		return fmt.Errorf("prepared Windows directory activation lost original authority")
	}
	for _, input := range validated.inputs {
		state, taildrop, ok := mapping.Resolve(input.StateDirectory, input.TaildropDirectory)
		relative, err := filepath.Rel(input.StateDirectory, input.TaildropDirectory)
		expectedState := filepath.Join(domain.PhysicalRoot(), filepath.Base(input.StateDirectory))
		if !ok || err != nil || state != expectedState || taildrop != filepath.Join(expectedState, relative) {
			return fmt.Errorf("prepared Windows directory mapping mismatch")
		}
	}
	if consume {
		activation.consumed = true
	}
	return nil
}

func validateWindowsActivationOptions(ctx context.Context, options option.Options, source string, info *debug.BuildInfo) (*validatedWindowsActivation, error) {
	if len(options.RawMessage) == 0 {
		return nil, fmt.Errorf("prepared Windows directory activation requires original parsed config bytes")
	}
	if err := RejectReservedPaths(options.RawMessage); err != nil {
		return nil, err
	}
	if options.PolarisWindowsDirectory == nil {
		return nil, fmt.Errorf("missing Windows directory activation envelope")
	}
	envelope := *options.PolarisWindowsDirectory
	if envelope.Version != 1 || !windowsEnvelopePath(envelope.Root) || !windowsEnvelopeHex(envelope.RunNonce, 32) {
		return nil, fmt.Errorf("invalid Windows directory activation envelope")
	}
	if err := ValidateSource(envelope.ExpectedSource, source, info); err != nil {
		return nil, err
	}
	binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx)
	if binding == nil || !(windowsEnvelopeHex(binding.RunNonce, 32) || windowsEnvelopeHex(binding.RunNonce, 64)) || !windowsEnvelopeHex(binding.ConfigDigest, 64) {
		return nil, fmt.Errorf("missing or invalid original daemon directory binding")
	}
	projection, inputs, err := projectWindowsDirectories(options, envelope.Root)
	if err != nil {
		return nil, err
	}
	// Raw and runtime options need not serialize identically: daemon OOM and
	// inbound overrides were already applied. Compare the complete directory
	// projection against the submitted bytes, then freeze the runtime digest
	// separately to reject subsequent changes to serialized runtime options.
	rawOptions, err := rawWindowsDirectoryOptions(options.RawMessage)
	if err != nil {
		return nil, err
	}
	if rawOptions.PolarisWindowsDirectory == nil || *rawOptions.PolarisWindowsDirectory != envelope {
		return nil, fmt.Errorf("prepared Windows directory envelope differs from original config")
	}
	rawProjection, _, err := projectWindowsDirectories(rawOptions, envelope.Root)
	if err != nil {
		return nil, err
	}
	if !projection.equal(rawProjection) {
		return nil, fmt.Errorf("prepared Windows directory projection differs from original config")
	}
	runtimeOptions, err := sjson.MarshalContext(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := RejectReservedPaths(runtimeOptions); err != nil {
		return nil, err
	}
	return &validatedWindowsActivation{
		rawDigest:     sha256.Sum256(options.RawMessage),
		optionsDigest: sha256.Sum256(runtimeOptions),
		envelope:      envelope,
		binding:       *binding,
		projection:    projection,
		inputs:        inputs,
	}, nil
}

func normalizedWindowsDirectoryTag(tag string, index int) string {
	if tag == "" {
		return strconv.Itoa(index)
	}
	return tag
}

func projectWindowsDirectories(options option.Options, root string) (windowsDirectoryProjection, []adapter.TailscaleDirectoryMappingInput, error) {
	var projection windowsDirectoryProjection
	var inputs []adapter.TailscaleDirectoryMappingInput
	seenTags, seenPaths := make(map[string]bool), make(map[string]bool)
	for index, outbound := range options.Outbounds {
		tag := normalizedWindowsDirectoryTag(outbound.Tag, index)
		if seenTags[tag] {
			return projection, nil, fmt.Errorf("duplicate outbound/endpoint tag: %s", tag)
		}
		seenTags[tag] = true
		projection.outbounds = append(projection.outbounds, windowsDirectoryTagProjection{Type: outbound.Type, Tag: tag})
	}
	for index, endpoint := range options.Endpoints {
		tag := normalizedWindowsDirectoryTag(endpoint.Tag, index)
		if seenTags[tag] {
			return projection, nil, fmt.Errorf("duplicate outbound/endpoint tag: %s", tag)
		}
		seenTags[tag] = true
		entry := windowsDirectoryEndpointProjection{Type: endpoint.Type, Tag: tag}
		if endpoint.Type == C.TypeTailscale {
			var ts option.TailscaleEndpointOptions
			switch value := endpoint.Options.(type) {
			case *option.TailscaleEndpointOptions:
				if value == nil {
					return projection, nil, fmt.Errorf("missing decoded Tailscale endpoint options")
				}
				ts = *value
			case option.TailscaleEndpointOptions:
				ts = value
			default:
				return projection, nil, fmt.Errorf("missing decoded Tailscale endpoint options")
			}
			entry.StateDirectory, entry.TaildropDirectory = ts.StateDirectory, ts.TaildropDirectory
			entry.ExpandedState, entry.ExpandedTaildrop = os.ExpandEnv(ts.StateDirectory), os.ExpandEnv(ts.TaildropDirectory)
			if ts.SSHServer != nil {
				entry.HasSSHServer = true
				entry.SSHServer = *ts.SSHServer
			}
			if entry.SSHServer.Enabled {
				return projection, nil, fmt.Errorf("prepared Windows managed directory cannot admit unbounded SSH filesystem writers")
			}
			state, taildrop := entry.ExpandedState, entry.ExpandedTaildrop
			relative, err := filepath.Rel(state, taildrop)
			// Case aliases still name the same Windows directory; never reserve
			// two entries for the same logical/physical leaf under different tags.
			pathKey := strings.ToLower(state)
			if !windowsEnvelopePath(state) || !windowsEnvelopePath(taildrop) || filepath.Dir(state) != filepath.Join(root, "tailscale") || err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) || seenPaths[pathKey] {
				return projection, nil, fmt.Errorf("tailscale configuration is outside Windows managed domain")
			}
			seenPaths[pathKey] = true
			inputs = append(inputs, adapter.TailscaleDirectoryMappingInput{StateDirectory: state, TaildropDirectory: taildrop})
		}
		projection.endpoints = append(projection.endpoints, entry)
	}
	if len(inputs) == 0 {
		return projection, nil, fmt.Errorf("prepared Windows directory envelope has no Tailscale endpoints")
	}
	return projection, inputs, nil
}

// Decode only the directory-relevant original fields, without consulting an
// endpoint registry or comparing unrelated OOM/inbound override fields. The
// original decoder has already validated the full profile. Reserved namespace
// scanning above still visits every raw token, including duplicate object keys.
func rawWindowsDirectoryOptions(raw []byte) (option.Options, error) {
	var original struct {
		Envelope  *option.WindowsDirectoryOptions `json:"polaris_windows_directory"`
		Endpoints []json.RawMessage               `json:"endpoints"`
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &original); err != nil {
		return option.Options{}, err
	}
	options := option.Options{PolarisWindowsDirectory: original.Envelope}
	for _, rawEndpoint := range original.Endpoints {
		var endpoint struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(rawEndpoint, &endpoint); err != nil {
			return option.Options{}, err
		}
		value := option.Endpoint{Type: endpoint.Type, Tag: endpoint.Tag}
		if endpoint.Type == C.TypeTailscale {
			var directories struct {
				StateDirectory    string                            `json:"state_directory"`
				TaildropDirectory string                            `json:"taildrop_directory"`
				SSHServer         *option.TailscaleSSHServerOptions `json:"ssh_server"`
			}
			if err := json.Unmarshal(rawEndpoint, &directories); err != nil {
				return option.Options{}, err
			}
			value.Options = &option.TailscaleEndpointOptions{StateDirectory: directories.StateDirectory, TaildropDirectory: directories.TaildropDirectory, SSHServer: directories.SSHServer}
		}
		options.Endpoints = append(options.Endpoints, value)
	}
	for _, outbound := range original.Outbounds {
		options.Outbounds = append(options.Outbounds, option.Outbound{Type: outbound.Type, Tag: outbound.Tag})
	}
	return options, nil
}
