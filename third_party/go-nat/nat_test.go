package nat

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type discoveryTestNAT struct {
	name   string
	device func() (net.IP, error)
}

func (n *discoveryTestNAT) Type() string { return n.name }
func (n *discoveryTestNAT) GetDeviceAddress() (net.IP, error) {
	return n.device()
}
func (*discoveryTestNAT) GetExternalAddress() (net.IP, error) {
	panic("unexpected external-address operation")
}
func (*discoveryTestNAT) GetInternalAddress() (net.IP, error) {
	panic("unexpected internal-address operation")
}
func (*discoveryTestNAT) AddPortMapping(context.Context, string, int, string, time.Duration) (int, error) {
	panic("unexpected mapping operation")
}
func (*discoveryTestNAT) DeletePortMapping(context.Context, string, int) error {
	panic("unexpected mapping deletion")
}

func awaitDiscovery(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("owned discovery did not make progress")
	}
}

func TestDiscoverNATsCancellationJoinsAllFourLateProducers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	var producers []discoveryProducer
	var started, release, returned [4]chan struct{}
	for index := range started {
		started[index], release[index], returned[index] = make(chan struct{}), make(chan struct{}), make(chan struct{})
		index := index
		producers = append(producers, func(ctx context.Context, out chan<- NAT) {
			active.Add(1)
			defer active.Add(-1)
			close(started[index])
			<-ctx.Done()
			// Models a native call with no cancellation API. It may return a
			// late result, but still belongs to this exact producer's join.
			<-release[index]
			out <- &discoveryTestNAT{name: "late"}
			close(returned[index])
		})
	}
	t.Cleanup(func() {
		cancel()
		for _, gate := range release {
			select {
			case <-gate:
			default:
				close(gate)
			}
		}
	})
	nats := discoverNATs(ctx, producers...)
	for _, signal := range started {
		awaitDiscovery(t, signal)
	}
	if active.Load() != 4 {
		t.Fatal("not all four discovery producers are owned")
	}
	cancel()
	var count int
	var outstandingAtClose int32
	done := make(chan struct{})
	go func() {
		for range nats {
			count++
		}
		outstandingAtClose = active.Load()
		close(done)
	}()
	for index := range release {
		select {
		case <-done:
			t.Fatal("aggregate channel closed before a native producer returned")
		default:
		}
		close(release[index])
		awaitDiscovery(t, returned[index])
	}
	awaitDiscovery(t, done)
	if count != 4 || outstandingAtClose != 0 {
		t.Fatal("late results or producer completion lost", count, outstandingAtClose)
	}
}

func TestDiscoverNATsNormalCompletionAndEarlyProducerReturn(t *testing.T) {
	var active atomic.Int32
	var producers []discoveryProducer
	for index := range 4 {
		index := index
		producers = append(producers, func(_ context.Context, out chan<- NAT) {
			active.Add(1)
			defer active.Add(-1)
			if index == 0 {
				return // A producer whose native discovery returned an error.
			}
			out <- &discoveryTestNAT{name: "normal"}
		})
	}
	count := 0
	for range discoverNATs(context.Background(), producers...) {
		count++
	}
	if count != 3 || active.Load() != 0 {
		t.Fatal("early return bypassed the remaining producer joins", count, active.Load())
	}
}

func TestDiscoverGatewayCanceledContextNeverStartsDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var called atomic.Int32
	for range discoverNATs(ctx, func(context.Context, chan<- NAT) { called.Add(1) }) {
		t.Fatal("canceled discovery returned a NAT")
	}
	if called.Load() != 0 {
		t.Fatal("canceled discovery started a producer")
	}
	gateway, err := DiscoverGateway(ctx)
	if gateway != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("public canceled discovery lost context error", gateway, err)
	}
}

func TestDiscoverGatewayCancellationAfterPartialResultWaitsForNativeReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	partial, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var active atomic.Int32
	discovered := discoverNATs(ctx, func(ctx context.Context, out chan<- NAT) {
		active.Add(1)
		defer active.Add(-1)
		out <- &discoveryTestNAT{name: "partial"}
		close(partial)
		<-ctx.Done()
		<-release
	})
	var gateway NAT
	var result error
	go func() {
		gateway, result = selectGateway(ctx, discovered, func() (net.IP, error) {
			panic("canceled selection must not query routing")
		})
		close(done)
	}()
	awaitDiscovery(t, partial)
	cancel()
	select {
	case <-done:
		t.Fatal("gateway returned before native discovery completed")
	default:
	}
	close(release)
	awaitDiscovery(t, done)
	if gateway != nil || !errors.Is(result, context.Canceled) || active.Load() != 0 {
		t.Fatal("partial result escaped as a usable gateway", gateway, result, active.Load())
	}
}

func TestDiscoverGatewayContextErrorWinsForZeroOneAndManyResults(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		input := make(chan NAT, count)
		for range count {
			input <- &discoveryTestNAT{name: "stale"}
		}
		close(input)
		gateway, err := selectGateway(ctx, input, func() (net.IP, error) {
			panic("expired context must not query routing")
		})
		cancel()
		if gateway != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("deadline became no-NAT or stale success", count, gateway, err)
		}
	}
}

func TestDiscoverGatewayPreservesNormalSelection(t *testing.T) {
	for _, names := range [][]string{nil, {"other"}, {"other", "last"}, {"gateway", "other"}, {"gateway", "last-gateway"}} {
		input := make(chan NAT, len(names))
		for _, name := range names {
			name := name
			input <- &discoveryTestNAT{name: name, device: func() (net.IP, error) {
				if name == "gateway" || name == "last-gateway" {
					return net.IPv4(192, 0, 2, 1), nil
				}
				return net.IPv4(192, 0, 2, 2), nil
			}}
		}
		close(input)
		gateway, err := selectGateway(context.Background(), input, func() (net.IP, error) {
			if len(names) < 2 {
				t.Fatal("zero/single result unexpectedly queried routing")
			}
			return net.IPv4(192, 0, 2, 1), nil
		})
		if len(names) == 0 {
			if gateway != nil || !errors.Is(err, ErrNoNATFound) {
				t.Fatal(gateway, err)
			}
			continue
		}
		want := names[len(names)-1]
		if names[0] == "gateway" && want == "other" {
			want = "gateway"
		}
		if err != nil || gateway.Type() != want {
			t.Fatal("normal gateway preference changed", names, gateway, err)
		}
	}
}

func TestDiscoverGatewayCancellationDuringUncancelableSelection(t *testing.T) {
	for _, block := range []string{"route", "device"} {
		t.Run(block, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			wait := func() { close(entered); <-release }
			input := make(chan NAT, 2)
			input <- &discoveryTestNAT{device: func() (net.IP, error) {
				if block == "device" {
					wait()
				}
				return nil, nil
			}}
			input <- &discoveryTestNAT{device: func() (net.IP, error) { panic("late selection continued after cancellation") }}
			close(input)
			var gateway NAT
			var result error
			go func() {
				gateway, result = selectGateway(ctx, input, func() (net.IP, error) {
					if block == "route" {
						wait()
					}
					return nil, nil
				})
				close(done)
			}()
			awaitDiscovery(t, entered)
			cancel()
			select {
			case <-done:
				t.Fatal("selection detached uncancelable operation")
			default:
			}
			close(release)
			awaitDiscovery(t, done)
			if gateway != nil || !errors.Is(result, context.Canceled) {
				t.Fatal("selection returned a gateway after cancellation", gateway, result)
			}
		})
	}
}
