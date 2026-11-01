// Polaris changes: joined NAT discovery and context-preserving gateway selection.
// Original source and complete license: UPSTREAM.json and LICENSE.

// Package nat implements NAT handling facilities
package nat

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
)

var ErrNoExternalAddress = errors.New("no external address")
var ErrNoInternalAddress = errors.New("no internal address")
var ErrNoNATFound = errors.New("no NAT found")

// protocol is either "udp" or "tcp"
type NAT interface {
	// Type returns the kind of NAT port mapping service that is used
	Type() string

	// GetDeviceAddress returns the internal address of the gateway device.
	GetDeviceAddress() (addr net.IP, err error)

	// GetExternalAddress returns the external address of the gateway device.
	GetExternalAddress() (addr net.IP, err error)

	// GetInternalAddress returns the address of the local host.
	GetInternalAddress() (addr net.IP, err error)

	// AddPortMapping maps a port on the local host to an external port.
	AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, timeout time.Duration) (mappedExternalPort int, err error)

	// DeletePortMapping removes a port mapping.
	DeletePortMapping(ctx context.Context, protocol string, internalPort int) (err error)
}

// DiscoverNATs returns all NATs discovered in the network. The result channel
// closes only after all discovery producers have returned, including native
// calls that do not support cancellation. Callers that stop consuming must
// cancel ctx, then wait for the channel to close before treating discovery as
// complete.
func DiscoverNATs(ctx context.Context) <-chan NAT {
	return discoverNATs(ctx, discoverUPNP_IG1, discoverUPNP_IG2, discoverNATPMP, discoverUPNP_GenIGDev)
}

// A producer runs synchronously in its owned worker. It must not detach native
// work or close the shared result channel; the coordinator owns both joins and
// channel closure.
type discoveryProducer func(context.Context, chan<- NAT)

func discoverNATs(ctx context.Context, producers ...discoveryProducer) <-chan NAT {
	nats := make(chan NAT)
	go func() {
		if ctx.Err() != nil {
			close(nats)
			return
		}
		var workers sync.WaitGroup
		workers.Add(len(producers))
		for _, producer := range producers {
			go func(producer discoveryProducer) {
				defer workers.Done()
				producer(ctx, nats)
			}(producer)
		}
		workers.Wait()
		close(nats)
	}()
	return nats
}

// DiscoverGateway attempts to find a gateway device.
func DiscoverGateway(ctx context.Context) (NAT, error) {
	return selectGateway(ctx, DiscoverNATs(ctx), getDefaultGateway)
}

type discoveryHTTPClientKey struct{}
type discoveryResolverKey struct{}

// DiscoverGatewayWithHTTPClient is the compatible caller-owned HTTP entry. The
// caller must keep this transport's captured dependency closure alive through
// all gateway operations, including terminal deletion. No global client is
// changed, and a nil transport cannot silently select http.DefaultTransport.
// An optional captured resolver is called synchronously during discovery;
// injected hostname devices fail closed without it and retain numeric metadata.
func DiscoverGatewayWithHTTPClient(ctx context.Context, client *http.Client, resolver ...func(context.Context, string) ([]net.IP, error)) (NAT, error) {
	if client == nil || client.Transport == nil {
		return nil, errors.New("NAT discovery requires an explicit caller-owned HTTP transport")
	}
	captured := *client
	ctx = context.WithValue(ctx, discoveryHTTPClientKey{}, &captured)
	if len(resolver) > 1 {
		return nil, errors.New("NAT discovery accepts one captured device resolver")
	}
	if len(resolver) == 1 && resolver[0] != nil {
		ctx = context.WithValue(ctx, discoveryResolverKey{}, resolver[0])
	}
	return DiscoverGateway(ctx)
}

func selectGateway(ctx context.Context, discovered <-chan NAT, defaultGateway func() (net.IP, error)) (NAT, error) {
	var nats []NAT
	for nat := range discovered {
		if ctx.Err() == nil {
			nats = append(nats, nat)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch len(nats) {
	case 0:
		return nil, ErrNoNATFound
	case 1:
		return nats[0], nil
	}
	gw, _ := defaultGateway()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bestNAT := nats[0]
	natGw, _ := bestNAT.GetDeviceAddress()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bestNATIsGw := gw != nil && natGw.Equal(gw)
	// 1. Prefer gateways discovered _last_. This is an OK heuristic for
	// discovering the most-upstream (furthest) NAT.
	// 2. Prefer gateways that actually match our known gateway address.
	// Some relays like to claim to be NATs even if they aren't.
	for _, nat := range nats[1:] {
		natGw, _ := nat.GetDeviceAddress()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		natIsGw := gw != nil && natGw.Equal(gw)

		if bestNATIsGw && !natIsGw {
			continue
		}

		bestNATIsGw = natIsGw
		bestNAT = nat
	}
	return bestNAT, nil
}

var randomMu sync.Mutex

var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomPort() int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return random.Intn(math.MaxUint16-10000) + 10000
}
