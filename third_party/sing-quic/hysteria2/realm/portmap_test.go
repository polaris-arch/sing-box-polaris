package realm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-nat"
	"github.com/sagernet/sing/common/logger"
)

func TestRealmCapturedSTUNResolverNormalizesAndFiltersActualFamilies(t *testing.T) {
	for _, family := range []struct {
		name       string
		ipv4, ipv6 bool
		count      int
	}{
		{"dual", true, true, 2}, {"v4", true, false, 1}, {"v6", false, true, 1},
	} {
		t.Run(family.name, func(t *testing.T) {
			calls := 0
			got, err := ResolveSTUNServers(context.Background(), []string{"captured.invalid:3478"}, func(_ context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
				calls++
				if host != "captured.invalid" || ipv4 != family.ipv4 || ipv6 != family.ipv6 {
					t.Error("captured resolver received another family policy")
				}
				return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8::1"), {}}, nil
			}, family.ipv4, family.ipv6)
			if err != nil || calls != 1 || len(got) != family.count {
				t.Fatal("captured address result changed", got, err, calls)
			}
			for _, address := range got {
				if !address.IsValid() || address.Port() != 3478 || address.Addr().Is4In6() || (address.Addr().Is4() && !family.ipv4) || (address.Addr().Is6() && !family.ipv6) {
					t.Fatal("wrong, mapped or invalid address reached discovery", address)
				}
			}
		})
	}
	if _, err := ResolveSTUNServers(context.Background(), []string{"captured.invalid"}, func(context.Context, string, bool, bool) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}, nil
	}, false, true); err == nil {
		t.Fatal("wrong-family-only DNS result entered an IPv6 discovery")
	}
}

type portMappingTestGateway struct {
	add              func(context.Context) (int, error)
	external         func() (net.IP, error)
	remove           func(context.Context) error
	adds, removes    atomic.Int32
	deleteDiagnostic error
}

func (g *portMappingTestGateway) PortMappingDeleteContextError() error { return g.deleteDiagnostic }

func TestPortMapperJoinedPositiveDeleteAfterDeadlineIsDiagnosticOnly(t *testing.T) {
	entered, elapsed, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	var g *portMappingTestGateway
	g = &portMappingTestGateway{remove: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		g.deleteDiagnostic = ctx.Err()
		close(elapsed)
		<-release
		// The NAT API's parsed terminal ACK has confirmed remote absence.
		return nil
	}}
	m := portMappingCreate(t, g, time.Minute)
	m.timeout = 10 * time.Millisecond
	go func() { done <- m.Close() }()
	portMappingWait(t, entered)
	portMappingWait(t, elapsed)
	select {
	case <-done:
		t.Fatal("unreturned native Delete declared complete")
	default:
	}
	finish()
	select {
	case err := <-done:
		if err != nil || !errors.Is(m.deleteContextErr, context.DeadlineExceeded) || g.removes.Load() != 1 {
			t.Fatal("confirmed joined deletion became permanent debt", err, m.deleteContextErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native Delete not joined")
	}
	if err := m.Close(); err != nil || g.removes.Load() != 1 {
		t.Fatal("confirmed deletion was retried or charged", err)
	}
}

func (*portMappingTestGateway) Type() string { return "test" }
func (*portMappingTestGateway) GetDeviceAddress() (net.IP, error) {
	return net.ParseIP("192.0.2.1"), nil
}
func (*portMappingTestGateway) GetInternalAddress() (net.IP, error) {
	return net.ParseIP("192.0.2.2"), nil
}
func (g *portMappingTestGateway) GetExternalAddress() (net.IP, error) {
	if g.external != nil {
		return g.external()
	}
	return net.ParseIP("192.0.2.3"), nil
}
func (g *portMappingTestGateway) AddPortMapping(ctx context.Context, protocol string, port int, description string, lifetime time.Duration) (int, error) {
	if protocol != "udp" || port != 23456 || description != portMappingDescription || lifetime <= 0 {
		return 0, errors.New("mapping identity changed")
	}
	g.adds.Add(1)
	if g.add != nil {
		return g.add(ctx)
	}
	return 23456, nil
}
func (g *portMappingTestGateway) DeletePortMapping(ctx context.Context, protocol string, port int) error {
	if protocol != "udp" || port != 23456 {
		return errors.New("delete identity changed")
	}
	g.removes.Add(1)
	if g.remove != nil {
		return g.remove(ctx)
	}
	return nil
}
func portMappingWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("mapper completion not joined")
	}
}
func portMappingCreate(t *testing.T, g *portMappingTestGateway, lifetime time.Duration) *PortMapper {
	t.Helper()
	m, err := newPortMapper(context.Background(), logger.NOP(), 23456, PortMappingOptions{Timeout: time.Second, Lifetime: lifetime}, func(context.Context) (nat.NAT, error) { return g, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestPortMapperInitialAddOrAddressFailureDeletesAndKeepsErrors(t *testing.T) {
	for _, stage := range []string{"add", "address"} {
		t.Run(stage, func(t *testing.T) {
			failure, deleteFailure := errors.New("mapping setup failed"), errors.New("delete failed")
			g := &portMappingTestGateway{remove: func(context.Context) error { return deleteFailure }}
			if stage == "add" {
				g.add = func(context.Context) (int, error) { return 0, failure }
			} else {
				g.external = func() (net.IP, error) { return nil, failure }
			}
			m, err := newPortMapper(context.Background(), logger.NOP(), 23456, PortMappingOptions{Timeout: time.Second}, func(context.Context) (nat.NAT, error) { return g, nil })
			if m != nil || !errors.Is(err, failure) || !errors.Is(err, deleteFailure) || g.adds.Load() != 1 || g.removes.Load() != 1 {
				t.Fatalf("partial setup was not cleaned: %v", err)
			}
		})
	}
}

func TestPortMapperRenewFailureSurvivesRecoveryAndClose(t *testing.T) {
	var calls atomic.Int32
	failure, deleteFailure := errors.New("renew failed"), errors.New("delete failed")
	g := &portMappingTestGateway{add: func(context.Context) (int, error) {
		if calls.Add(1) == 2 {
			return 0, failure
		}
		return 23456, nil
	}, remove: func(context.Context) error { return deleteFailure }}
	m := portMappingCreate(t, g, time.Minute)
	if _, err := m.Renew(context.Background()); !errors.Is(err, failure) {
		t.Fatal("renew failure lost", err)
	}
	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.KeepAliveContext(ctx); !errors.Is(err, deleteFailure) {
		t.Fatal("actual delete failure lost after recovery", err)
	}
	if err := m.Close(); !errors.Is(err, deleteFailure) || g.removes.Load() != 1 {
		t.Fatal("close not sticky/idempotent", err)
	}
	if !errors.Is(m.renewErr, failure) {
		t.Fatal("operational renewal history was lost")
	}
	if _, err := m.Renew(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed mapper renewed", err)
	}
}

func TestPortMapperCancellationJoinsRenewBeforeDelete(t *testing.T) {
	entered, canceled, release, deleted := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	g := &portMappingTestGateway{add: func(ctx context.Context) (int, error) {
		if calls.Add(1) == 1 {
			return 23456, nil
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return 0, ctx.Err()
	}, remove: func(context.Context) error { close(deleted); return nil }}
	m := portMappingCreate(t, g, 2*time.Millisecond)
	t.Cleanup(releaseNow)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var err error
	go func() { err = m.KeepAliveContext(ctx); close(done) }()
	portMappingWait(t, entered)
	cancel()
	portMappingWait(t, canceled)
	select {
	case <-deleted:
		t.Fatal("delete raced unfinished renewal")
	default:
	}
	select {
	case <-done:
		t.Fatal("renewal was detached")
	default:
	}
	releaseNow()
	portMappingWait(t, done)
	portMappingWait(t, deleted)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPortMapperCloseJoinsContextFreeAddressCall(t *testing.T) {
	entered, release, deleted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	g := &portMappingTestGateway{external: func() (net.IP, error) {
		if calls.Add(1) > 1 {
			close(entered)
			<-release
		}
		return net.ParseIP("192.0.2.3"), nil
	}, remove: func(context.Context) error { close(deleted); return nil }}
	m := portMappingCreate(t, g, time.Minute)
	t.Cleanup(releaseNow)
	renewed := make(chan struct{})
	go func() { _, _ = m.Renew(context.Background()); close(renewed) }()
	portMappingWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = m.Close(); close(closed) }()
	portMappingWait(t, m.ctx.Done())
	select {
	case <-closed:
		t.Fatal("uncancelable gateway call certified complete")
	default:
	}
	select {
	case <-deleted:
		t.Fatal("delete raced context-free gateway call")
	default:
	}
	releaseNow()
	portMappingWait(t, renewed)
	portMappingWait(t, closed)
	portMappingWait(t, deleted)
}

func TestPortMapperTimedOutDiscoveryCannotPublishFoundGateway(t *testing.T) {
	g := &portMappingTestGateway{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, err := newPortMapper(ctx, logger.NOP(), 23456, PortMappingOptions{Timeout: time.Second}, func(ctx context.Context) (nat.NAT, error) { <-ctx.Done(); return g, nil })
	var incomplete interface{ RuntimeCleanupIncomplete() bool }
	if m != nil || !errors.Is(err, context.Canceled) || errors.As(err, &incomplete) || g.adds.Load() != 0 || g.removes.Load() != 0 {
		t.Fatalf("joined canceled discovery created a mapping or false debt: %v", err)
	}
}

func TestPortMapperJoinedRenewFailureClearsOnlyAfterConfirmedDeletion(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewal", true: "initial"}[initial], func(t *testing.T) {
			failure := errors.New("mapping operation failed")
			var calls atomic.Int32
			g := &portMappingTestGateway{add: func(context.Context) (int, error) {
				if calls.Add(1) == 2 || initial {
					return 0, failure
				}
				return 23456, nil
			}}
			var incomplete interface{ RuntimeCleanupIncomplete() bool }
			if initial {
				m, err := newPortMapper(context.Background(), logger.NOP(), 23456, PortMappingOptions{}, func(context.Context) (nat.NAT, error) { return g, nil })
				if m != nil || !errors.Is(err, failure) || errors.As(err, &incomplete) || g.removes.Load() != 1 {
					t.Fatalf("cleaned initial failure became cleanup debt: %v", err)
				}
				return
			}
			m := portMappingCreate(t, g, time.Minute)
			if _, err := m.Renew(context.Background()); !errors.Is(err, failure) {
				t.Fatal("operation diagnosis lost", err)
			}
			if _, err := m.Renew(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil || g.removes.Load() != 1 || !errors.Is(m.renewErr, failure) {
				t.Fatalf("confirmed deletion retained false debt or erased history: %v", err)
			}
		})
	}
}

func TestPortMapperCancellationNeverStartsAddOrLateAddressQuery(t *testing.T) {
	g := &portMappingTestGateway{}
	m := portMappingCreate(t, g, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Renew(ctx); !errors.Is(err, context.Canceled) || g.adds.Load() != 1 {
		t.Fatal("canceled renewal invoked Add", err)
	}
	m.cancel()
	if _, err := m.Renew(context.Background()); !errors.Is(err, context.Canceled) || g.adds.Load() != 1 {
		t.Fatal("canceled mapper lifetime invoked Add", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	var addressCalls atomic.Int32
	g = &portMappingTestGateway{add: func(context.Context) (int, error) {
		cancel()
		return 23456, nil
	}, external: func() (net.IP, error) {
		addressCalls.Add(1)
		return net.ParseIP("192.0.2.3"), nil
	}}
	mapper, err := newPortMapper(ctx, logger.NOP(), 23456, PortMappingOptions{}, func(context.Context) (nat.NAT, error) { return g, nil })
	if mapper != nil || !errors.Is(err, context.Canceled) || g.adds.Load() != 1 || g.removes.Load() != 1 || addressCalls.Load() != 0 {
		t.Fatalf("late Add did not join cleanup before cancellation: %v", err)
	}
}

func TestPortMapperActualDeleteFailureRetainsIncompleteMarker(t *testing.T) {
	failure := errors.New("remote deletion unknown")
	g := &portMappingTestGateway{remove: func(context.Context) error { return failure }}
	m := portMappingCreate(t, g, time.Minute)
	for attempt := 0; attempt < 2; attempt++ {
		err := m.Close()
		var incomplete interface{ RuntimeCleanupIncomplete() bool }
		if !errors.Is(err, failure) || !errors.As(err, &incomplete) || !incomplete.RuntimeCleanupIncomplete() || g.removes.Load() != 1 {
			t.Fatalf("unconfirmed deletion was released or retried invisibly: %v", err)
		}
	}
}
