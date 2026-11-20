package boxruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	proxyHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	RuntimeExitIPProbeVersion = 1
	runtimeExitIPProbeTimeout = 4 * time.Second
	runtimeExitIPDrainWindow  = 250 * time.Millisecond
	runtimeExitIPSelector     = "proxy-selector"
	runtimeExitIPHost         = "cloudflare.com"
	runtimeExitIPURL          = "https://" + runtimeExitIPHost + "/cdn-cgi/trace"
	runtimeExitIPMaxBody      = 8 << 10
	runtimeExitIPMaxResponse  = 32 << 10
)

var (
	ErrRuntimeExitIPNotAdmitted = errors.New("running exit probe unavailable before dial")
	ErrRuntimeExitIPBusy        = errors.New("running exit probe slot is still occupied")
	ErrRuntimeExitIPSuperseded  = errors.New("running exit probe superseded")
	ErrRuntimeExitIPUnavailable = errors.New("running exit probe failed")
	ErrRuntimeExitIPUncertain   = errors.New("running exit probe cleanup is unconfirmed")
)

// ProbeRuntimeExitIP performs one bounded request on an exact currently selected
// proxy leaf. It does not route through a listener or modify a selector.
func (s *Box) ProbeRuntimeExitIP(ctx context.Context, expected RuntimeIdentity, leafTag string) ([]byte, error) {
	return s.probeRuntimeExitIP(ctx, expected, leafTag, fetchRuntimeExitIP)
}

func (s *Box) probeRuntimeExitIP(ctx context.Context, expected RuntimeIdentity, leafTag string, fetch func(context.Context, adapter.Outbound) ([]byte, error)) ([]byte, error) {
	if s.runtime == nil {
		return nil, ErrRuntimeExitIPNotAdmitted
	}
	c := s.runtime
	now := time.Now()
	providerDeadline := now.Add(runtimeExitIPProbeTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok {
		// Keep time to close the actual socket and return its drain witness
		// while the authenticated transport can still carry it.
		beforeDrain := callerDeadline.Add(-runtimeExitIPDrainWindow)
		if !beforeDrain.After(now) {
			return nil, ErrRuntimeExitIPNotAdmitted
		}
		if beforeDrain.Before(providerDeadline) {
			providerDeadline = beforeDrain
		}
	}
	request, cancel := context.WithDeadline(ctx, providerDeadline)
	defer cancel()
	probe, err := c.admitRuntimeExitIP(request, cancel, expected, leafTag)
	if err != nil {
		return nil, err
	}
	defer func() {
		probe.Release()
		c.access.Lock()
		c.exitIPProbeCancel = nil
		c.access.Unlock()
	}()

	body, err := fetch(probe.Context(), probe.Outbound())
	c.access.Lock()
	if errors.Is(err, ErrRuntimeExitIPUncertain) {
		c.exitIPProbeUncertain = true
		c.access.Unlock()
		return nil, ErrRuntimeExitIPUncertain
	}
	current := !c.stopped && c.active == expected && probe.History().IsCurrent(probe.Epoch())
	ready := current && probe.IsCurrent()
	c.access.Unlock()
	if !current {
		return nil, ErrRuntimeExitIPSuperseded
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || !ready {
		return nil, ErrRuntimeExitIPUnavailable
	}
	return body, nil
}

func (c *runtimeCoordinator) admitRuntimeExitIP(ctx context.Context, cancel context.CancelFunc, expected RuntimeIdentity, leafTag string) (*urltest.RuntimeProbe, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.stopped || c.active != expected || expected.Revision == 0 ||
		c.clashMode != nil && strings.EqualFold(c.clashMode.Mode(), "direct") {
		return nil, ErrRuntimeExitIPNotAdmitted
	}
	if c.exitIPProbeCancel != nil || c.exitIPProbeUncertain {
		return nil, ErrRuntimeExitIPBusy
	}
	probe, bound, err := urltest.AcquireRuntimeProbeFromContext(c.ctx, ctx, leafTag)
	if !bound || err != nil {
		return nil, ErrRuntimeExitIPNotAdmitted
	}
	target := probe.Outbound()
	outbound, _ := probe.OutboundManager().Outbound(runtimeExitIPSelector)
	selector, isSelector := outbound.(*group.Selector)
	if !isSelector || !c.eligibleRuntimeExitIP(target) || selector.Selected(N.NetworkTCP) != target || !probe.IsCurrent() {
		probe.Release()
		return nil, ErrRuntimeExitIPNotAdmitted
	}
	c.exitIPProbeCancel = cancel
	return probe, nil
}

// Only audited concrete egresses without a user-configured outbound detour can
// carry the early request. Type tags alone also match opaque wrapper objects.
func (c *runtimeCoordinator) eligibleRuntimeExitIP(target adapter.Outbound) bool {
	switch target.(type) {
	case *socks.Outbound:
		found := false
		for _, node := range c.options.Outbounds {
			if node.Tag == target.Tag() {
				options, ok := node.Options.(*option.SOCKSOutboundOptions)
				// SOCKS4 would resolve the provider on the host.
				if !ok || options.Version == "4" {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	case *proxyHTTP.Outbound, *shadowsocks.Outbound, *trojan.Outbound, *vless.Outbound, *vmess.Outbound:
	default:
		return false
	}
	return len(target.Dependencies()) == 0 && slices.Contains(target.Network(), N.NetworkTCP)
}

// Keep the slot held until the actual request and its graph lease return, even
// when a change has already canceled its context.
func (c *runtimeCoordinator) cancelRuntimeExitIPProbeLocked() {
	if c.exitIPProbeCancel != nil {
		c.exitIPProbeCancel()
	}
}

func fetchRuntimeExitIP(ctx context.Context, target adapter.Outbound) (body []byte, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrRuntimeExitIPUnavailable
	}
	conn, err := target.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Fqdn: runtimeExitIPHost, Port: 443})
	if errors.Is(err, outboundAdapter.ErrRuntimeClosePending) || boxTLS.IsRuntimeCleanupIncomplete(err) {
		err = ErrRuntimeExitIPUncertain
	}
	if conn == nil {
		if err == nil {
			return nil, ErrRuntimeExitIPUncertain
		}
		return nil, err
	}
	closed := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { closed <- conn.Close() })
	defer func() {
		var closeErr error
		if stop() {
			closeErr = conn.Close()
		} else {
			closeErr = <-closed
		}
		if boxTLS.IsRuntimeCleanupIncomplete(closeErr) || closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) {
			body, resultErr = nil, ErrRuntimeExitIPUncertain
		}
	}()
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	secure := tls.Client(conn, &tls.Config{ServerName: runtimeExitIPHost, MinVersion: tls.VersionTLS12})
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, runtimeExitIPURL, nil)
	if err != nil {
		return nil, err
	}
	request.Close = true
	if err := request.Write(secure); err != nil {
		return nil, err
	}
	return readRuntimeExitIPResponse(secure, request)
}

func readRuntimeExitIPResponse(conn io.Reader, request *http.Request) ([]byte, error) {
	// Bound headers, transfer encoding overhead and the body independently.
	limited := &io.LimitedReader{R: conn, N: runtimeExitIPMaxResponse}
	response, err := http.ReadResponse(bufio.NewReader(limited), request)
	if err != nil {
		return nil, err
	}
	// The sole socket is closed by its owner. Do not drain a rejected body.
	if response.StatusCode != http.StatusOK || response.ContentLength > runtimeExitIPMaxBody {
		return nil, ErrRuntimeExitIPUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, runtimeExitIPMaxBody+1))
	if err != nil || limited.N == 0 || len(body) == 0 || len(body) > runtimeExitIPMaxBody {
		return nil, ErrRuntimeExitIPUnavailable
	}
	return body, nil
}
