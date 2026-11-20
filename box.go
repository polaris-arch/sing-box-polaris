package box

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/internal/boxruntime"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

var _ adapter.SimpleLifecycle = (*Box)(nil)

// Box retains its public type and shares the exact address and state of its
// internal implementation.
type Box boxruntime.Box

type Options struct {
	option.Options
	Context                    context.Context
	PlatformLogWriter          log.PlatformWriter
	NetworkNamespaceHolderArgs []string
}

func (o Options) runtimeOptions() boxruntime.Options {
	return boxruntime.Options{
		Options:                    o.Options,
		Context:                    o.Context,
		PlatformLogWriter:          o.PlatformLogWriter,
		NetworkNamespaceHolderArgs: o.NetworkNamespaceHolderArgs,
		Host:                       instanceHost,
	}
}

// ConstructionReport describes what constructing a box left behind.
type ConstructionReport boxruntime.ConstructionReport

type (
	RuntimeCleanupDiagnostic                 = boxruntime.RuntimeCleanupDiagnostic
	RuntimeClientImpactPolicyVersion         = boxruntime.RuntimeClientImpactPolicyVersion
	RuntimeConfigApply                       = boxruntime.RuntimeConfigApply
	RuntimeConfigCapabilities                = boxruntime.RuntimeConfigCapabilities
	RuntimeConfigOperation                   = boxruntime.RuntimeConfigOperation
	RuntimeConfigPlan                        = boxruntime.RuntimeConfigPlan
	RuntimeConfigStatus                      = boxruntime.RuntimeConfigStatus
	RuntimeFieldCapability                   = boxruntime.RuntimeFieldCapability
	RuntimeIdentity                          = boxruntime.RuntimeIdentity
	RuntimeImpact                            = boxruntime.RuntimeImpact
	RuntimeOwnerAcknowledgementRequiredError = boxruntime.RuntimeOwnerAcknowledgementRequiredError
	RuntimePersistenceAcknowledgement        = boxruntime.RuntimePersistenceAcknowledgement
	RuntimePersistenceRetry                  = boxruntime.RuntimePersistenceRetry
	RuntimePlanError                         = boxruntime.RuntimePlanError
	RuntimeSelectorIntent                    = boxruntime.RuntimeSelectorIntent
)

const (
	RuntimeClientImpactPolicyExplicit = boxruntime.RuntimeClientImpactPolicyExplicit
	RuntimeClientImpactPolicyLegacy   = boxruntime.RuntimeClientImpactPolicyLegacy
	RuntimeConfigContractVersion      = boxruntime.RuntimeConfigContractVersion
	RuntimeExitIPProbeVersion         = boxruntime.RuntimeExitIPProbeVersion
)

var (
	ErrRuntimeExitIPNotAdmitted = boxruntime.ErrRuntimeExitIPNotAdmitted
	ErrRuntimeExitIPBusy        = boxruntime.ErrRuntimeExitIPBusy
	ErrRuntimeExitIPSuperseded  = boxruntime.ErrRuntimeExitIPSuperseded
	ErrRuntimeExitIPUnavailable = boxruntime.ErrRuntimeExitIPUnavailable
	ErrRuntimeExitIPUncertain   = boxruntime.ErrRuntimeExitIPUncertain
)

var instanceHost = &boxruntime.Host{
	PrepareDirectory: prepareWindowsDirectoryDomain,
	CheckDebug:       checkDebugOptions,
	StartDebug: func(options option.DebugOptions) (*http.Server, error) {
		applyDebugOptions(options)
		return startDebugHTTPServer(options)
	},
	Register: func(ctx context.Context, instance *boxruntime.Box) boxruntime.RuntimeAPI {
		public := (*Box)(instance)
		service.MustRegisterPtr(ctx, public)
		return public
	},
}

func Context(
	ctx context.Context,
	inboundRegistry adapter.InboundRegistry,
	outboundRegistry adapter.OutboundRegistry,
	endpointRegistry adapter.EndpointRegistry,
	dnsTransportRegistry adapter.DNSTransportRegistry,
	serviceRegistry adapter.ServiceRegistry,
	certificateProviderRegistry adapter.CertificateProviderRegistry,
) context.Context {
	return boxruntime.Context(ctx, inboundRegistry, outboundRegistry, endpointRegistry, dnsTransportRegistry, serviceRegistry, certificateProviderRegistry)
}

// New constructs a box. When construction fails, the resources acquired so
// far are released in the background, so the error or panic is propagated
// without waiting for cleanup.
func New(options Options) (*Box, error) {
	instance, err := boxruntime.New(options.runtimeOptions())
	return (*Box)(instance), err
}

// NewWithConstructionReport is like New, but waits for the cleanup of a
// failed construction and reports its result.
func NewWithConstructionReport(options Options) (*Box, error, ConstructionReport) {
	instance, err, report := boxruntime.NewWithConstructionReport(options.runtimeOptions())
	return (*Box)(instance), err, ConstructionReport(report)
}

// NewForValidationWithConstructionReport constructs an instance solely for
// configuration validation and disposal. The caller must close it without
// starting it. Unlike runtime preparation, this path runs the original
// constructors now, including their validation and original store census.
// It never invokes Start or runtime staging and does not prove live availability.
// Original constructors can acquire resources; their cleanup errors retain
// NewWithConstructionReport semantics, without claiming exact global disposal.
func NewForValidationWithConstructionReport(options Options) (*Box, ConstructionReport, error) {
	instance, report, err := boxruntime.NewForValidationWithConstructionReport(options.runtimeOptions())
	return (*Box)(instance), ConstructionReport(report), err
}

func (s *Box) PreStart() error {
	return (*boxruntime.Box)(s).PreStart()
}

func (s *Box) Start() error {
	return (*boxruntime.Box)(s).Start()
}

// Close closes the box. Only the first close returns the cleanup result;
// later calls return nil without waiting for it.
func (s *Box) Close() error {
	return (*boxruntime.Box)(s).Close()
}

// CloseWithResult closes the box if it is not closed yet and returns the
// result of the first close, waiting for it to complete if necessary. It
// preserves the cleanup result that Start and PreStart discard when they
// close the box after a failure.
func (s *Box) CloseWithResult() error {
	return (*boxruntime.Box)(s).CloseWithResult()
}

func (s *Box) Network() adapter.NetworkManager {
	return (*boxruntime.Box)(s).Network()
}

func (s *Box) Router() adapter.Router {
	return (*boxruntime.Box)(s).Router()
}

func (s *Box) Inbound() adapter.InboundManager {
	return (*boxruntime.Box)(s).Inbound()
}

func (s *Box) Outbound() adapter.OutboundManager {
	return (*boxruntime.Box)(s).Outbound()
}

func (s *Box) Endpoint() adapter.EndpointManager {
	return (*boxruntime.Box)(s).Endpoint()
}

func (s *Box) CreatedAt() time.Time {
	return (*boxruntime.Box)(s).CreatedAt()
}

func (s *Box) CloseIdleConnections() {
	(*boxruntime.Box)(s).CloseIdleConnections()
}

func (s *Box) LogFactory() log.Factory {
	return (*boxruntime.Box)(s).LogFactory()
}

func RuntimeUsesResourceGraph(ctx context.Context, options option.Options) bool {
	return boxruntime.RuntimeUsesResourceGraph(ctx, options)
}

func ContextWithRuntimeLogDisableColor(ctx context.Context) context.Context {
	return boxruntime.ContextWithRuntimeLogDisableColor(ctx)
}

func (s *Box) AcquireRuntimeAPI() (lease adapter.RuntimeLease, changed <-chan struct{}, connected bool, err error) {
	return (*boxruntime.Box)(s).AcquireRuntimeAPI()
}

func (s *Box) LookupPublicDNS(ctx context.Context, domain string) ([]netip.Addr, error) {
	return (*boxruntime.Box)(s).LookupPublicDNS(ctx, domain)
}

func (s *Box) AcquireDashboardHTTP(ctx context.Context, serviceTag string) (adapter.RuntimeDashboardHTTPLease, error) {
	return (*boxruntime.Box)(s).AcquireDashboardHTTP(ctx, serviceTag)
}

func (s *Box) RuntimeAPIIngressIdentity(tag string) (adapter.RuntimeAPIIdentity, error) {
	return (*boxruntime.Box)(s).RuntimeAPIIngressIdentity(tag)
}

func (s *Box) PlanRuntimeConfig(ctx context.Context, actor string, expected RuntimeIdentity, content []byte) (RuntimeConfigPlan, error) {
	return (*boxruntime.Box)(s).PlanRuntimeConfig(ctx, actor, expected, content)
}

func (s *Box) PlanRuntimeConfigWithSelections(ctx context.Context, actor string, expected RuntimeIdentity, content []byte, intents []RuntimeSelectorIntent) (RuntimeConfigPlan, error) {
	return (*boxruntime.Box)(s).PlanRuntimeConfigWithSelections(ctx, actor, expected, content, intents)
}

func (s *Box) PlanRuntimeConfigWithClientImpactPolicy(ctx context.Context, actor string, expected RuntimeIdentity, content []byte, intents []RuntimeSelectorIntent, version RuntimeClientImpactPolicyVersion) (RuntimeConfigPlan, error) {
	return (*boxruntime.Box)(s).PlanRuntimeConfigWithClientImpactPolicy(ctx, actor, expected, content, intents, version)
}

func (s *Box) ApplyRuntimeConfig(ctx context.Context, actor string, request RuntimeConfigApply) (RuntimeConfigOperation, error) {
	return (*boxruntime.Box)(s).ApplyRuntimeConfig(ctx, actor, request)
}

func (s *Box) RuntimeCapabilities() RuntimeConfigCapabilities {
	return (*boxruntime.Box)(s).RuntimeCapabilities()
}

func (s *Box) RuntimeCleanupSnapshot() RuntimeCleanupDiagnostic {
	return (*boxruntime.Box)(s).RuntimeCleanupSnapshot()
}

// ProbeRuntimeExitIP performs one bounded request on an exact currently selected
// proxy leaf. It does not route through a listener or modify a selector.
func (s *Box) ProbeRuntimeExitIP(ctx context.Context, expected RuntimeIdentity, leafTag string) ([]byte, error) {
	return (*boxruntime.Box)(s).ProbeRuntimeExitIP(ctx, expected, leafTag)
}

func (s *Box) AcquireRuntimeURLTest(ctx context.Context, tag string) (*urltest.RuntimeProbe, bool, error) {
	return (*boxruntime.Box)(s).AcquireRuntimeURLTest(ctx, tag)
}

func (s *Box) AcknowledgeRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceAcknowledgement) (RuntimeConfigOperation, error) {
	return (*boxruntime.Box)(s).AcknowledgeRuntimePersistence(ctx, actor, request)
}

func (s *Box) RetryRuntimePersistence(ctx context.Context, actor string, request RuntimePersistenceRetry) (RuntimeConfigOperation, error) {
	return (*boxruntime.Box)(s).RetryRuntimePersistence(ctx, actor, request)
}

func (s *Box) AcquireReferenceSnapshot() (route.RuntimeReferenceSnapshot, error) {
	return (*boxruntime.Box)(s).AcquireReferenceSnapshot()
}

func (s *Box) RegisterReferenceHook(hook *observable.Subscriber[struct{}]) (func() error, error) {
	return (*boxruntime.Box)(s).RegisterReferenceHook(hook)
}

func (s *Box) GetRuntimeConfigStatus(actor, incarnation, transaction string) (RuntimeConfigStatus, error) {
	return (*boxruntime.Box)(s).GetRuntimeConfigStatus(actor, incarnation, transaction)
}

func (s *Box) BindRuntimePersistenceOptions(persist func(RuntimeIdentity, []byte) error, mode string, retrySafe bool) error {
	return (*boxruntime.Box)(s).BindRuntimePersistenceOptions(persist, mode, retrySafe)
}

func (s *Box) TailscaleDirectoryScopes() []adapter.TailscaleDirectoryNode {
	return (*boxruntime.Box)(s).TailscaleDirectoryScopes()
}

func (s *Box) TailscaleDirectoryRetirement() []adapter.TailscaleDirectoryNode {
	return (*boxruntime.Box)(s).TailscaleDirectoryRetirement()
}

func (s *Box) CaptureTailscaleStateStores() []adapter.Endpoint {
	return (*boxruntime.Box)(s).CaptureTailscaleStateStores()
}

func (s *Box) TailscaleStateStoreScopes() []adapter.TailscaleStoreNode {
	return (*boxruntime.Box)(s).TailscaleStateStoreScopes()
}

func (s *Box) TailscaleStoreRetirement() []adapter.TailscaleStoreNode {
	return (*boxruntime.Box)(s).TailscaleStoreRetirement()
}
