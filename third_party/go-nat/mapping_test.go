package nat

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/soap"
	natpmp "github.com/jackpal/go-nat-pmp"
)

type mappingTestPMP struct {
	call func(string, int, int, int) (*natpmp.AddPortMappingResult, error)
}

func (*mappingTestPMP) GetExternalAddress() (*natpmp.GetExternalAddressResult, error) {
	panic("unexpected external-address query")
}
func (c *mappingTestPMP) AddPortMapping(protocol string, internal, external, lifetime int) (*natpmp.AddPortMappingResult, error) {
	return c.call(protocol, internal, external, lifetime)
}

func TestNATPMPAddUsesActualAckAndRetainsFailedIntent(t *testing.T) {
	for _, mode := range []string{"create", "renew", "rpc-error", "nil-ack", "wrong-internal", "zero-port", "zero-lifetime", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel() // Separate owned mappers share only candidate-port selection.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			failure := errors.New("native RPC failed or reply lost")
			client := &mappingTestPMP{call: func(protocol string, internal, external, lifetime int) (*natpmp.AddPortMappingResult, error) {
				calls++
				if protocol != "udp" || internal != 4242 || lifetime != 60 || external <= 0 {
					t.Fatal("wrong create/renew request", protocol, internal, external, lifetime)
				}
				if mode == "renew" && external != 32000 {
					t.Fatal("renewal lost its previous suggestion")
				}
				ack := &natpmp.AddPortMappingResult{InternalPort: 4242, MappedExternalPort: 33000, PortMappingLifetimeInSeconds: 60}
				switch mode {
				case "rpc-error":
					return nil, failure
				case "nil-ack":
					return nil, nil
				case "wrong-internal":
					ack.InternalPort++
				case "zero-port":
					ack.MappedExternalPort = 0
				case "zero-lifetime":
					ack.PortMappingLifetimeInSeconds = 0
				case "late-cancel":
					cancel()
				}
				return ack, nil
			}}
			n := &natpmpNAT{c: client, ports: make(map[int]int)}
			if mode == "renew" {
				n.ports[4242] = 32000
			}
			port, err := n.AddPortMapping(ctx, "udp", 4242, "fixture", time.Minute)
			switch mode {
			case "create", "renew":
				if err != nil || port != 33000 || n.ports[4242] != port || calls != 1 {
					t.Fatal("actual gateway-assigned port was lost", port, err, n.ports, calls)
				}
			case "late-cancel":
				if !errors.Is(err, context.Canceled) || port != 33000 || n.ports[4242] != 33000 || calls != 1 {
					t.Fatal("late successful effect lost its cancellation/ownership", port, err, n.ports)
				}
			default:
				if err == nil || port != 0 || n.ports[4242] <= 0 || calls != 3 {
					t.Fatal("unconfirmed attempt disappeared", port, err, n.ports, calls)
				}
				if mode == "rpc-error" && !errors.Is(err, failure) {
					t.Fatal("native error lost", err)
				}
			}
			client.call = func(protocol string, internal, external, lifetime int) (*natpmp.AddPortMappingResult, error) {
				if protocol != "udp" || internal != 4242 || external != 0 || lifetime != 0 {
					t.Fatal("cleanup did not target the owned internal-port intent")
				}
				return &natpmp.AddPortMappingResult{InternalPort: 4242}, nil
			}
			if err := n.DeletePortMapping(context.Background(), "udp", 4242); err != nil || len(n.ports) != 0 {
				t.Fatal("confirmed cleanup did not retire owned intent", err, n.ports)
			}
		})
	}
}

func TestNATPMPDeleteRequiresExactAckAndKeepsDebtForRetry(t *testing.T) {
	for _, mode := range []string{"success-udp", "success-tcp", "rpc-error", "nil-ack", "wrong-internal", "nonzero-external", "nonzero-lifetime"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			failure := errors.New("delete reply missing")
			protocol := "udp"
			if mode == "success-tcp" {
				protocol = "tcp"
			}
			client := &mappingTestPMP{call: func(p string, internal, external, lifetime int) (*natpmp.AddPortMappingResult, error) {
				calls++
				if p != protocol || internal != 4242 || external != 0 || lifetime != 0 {
					t.Fatal("delete was not the exact RFC 6886 request")
				}
				ack := &natpmp.AddPortMappingResult{InternalPort: 4242}
				switch mode {
				case "rpc-error":
					return nil, failure
				case "nil-ack":
					return nil, nil
				case "wrong-internal":
					ack.InternalPort++
				case "nonzero-external":
					ack.MappedExternalPort = 32000
				case "nonzero-lifetime":
					ack.PortMappingLifetimeInSeconds = 1
				}
				return ack, nil
			}}
			n := &natpmpNAT{c: client, ports: map[int]int{4242: 32000}}
			err := n.DeletePortMapping(context.Background(), protocol, 4242)
			if mode == "success-udp" || mode == "success-tcp" {
				if err != nil || len(n.ports) != 0 {
					t.Fatal("confirmed deletion retained owned record", err, n.ports)
				}
				if err := n.DeletePortMapping(context.Background(), protocol, 4242); err != nil || calls != 1 {
					t.Fatal("completed deletion was not idempotent", err, calls)
				}
			} else {
				if err == nil || n.ports[4242] != 32000 {
					t.Fatal("failed deletion lost its debt", err, n.ports)
				}
				if mode == "rpc-error" && !errors.Is(err, failure) {
					t.Fatal("delete error lost", err)
				}
				client.call = func(string, int, int, int) (*natpmp.AddPortMappingResult, error) {
					calls++
					return &natpmp.AddPortMappingResult{InternalPort: 4242}, nil
				}
				if err := n.DeletePortMapping(context.Background(), protocol, 4242); err != nil || len(n.ports) != 0 || calls != 2 {
					t.Fatal("retry silently skipped lost ownership", err, n.ports, calls)
				}
			}
		})
	}
}

func TestNATPMPDeleteCanceledNativeCallJoinsAndResolvesValidAck(t *testing.T) {
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
	n := &natpmpNAT{ports: map[int]int{4242: 32000}, c: &mappingTestPMP{call: func(string, int, int, int) (*natpmp.AddPortMappingResult, error) {
		close(entered)
		<-release
		return &natpmp.AddPortMappingResult{InternalPort: 4242}, nil
	}}}
	var result error
	go func() { result = n.DeletePortMapping(ctx, "udp", 4242); close(done) }()
	awaitDiscovery(t, entered)
	cancel()
	select {
	case <-done:
		t.Fatal("uncancelable native deletion detached")
	default:
	}
	close(release)
	awaitDiscovery(t, done)
	if result != nil || len(n.ports) != 0 || !errors.Is(n.PortMappingDeleteContextError(), context.Canceled) {
		t.Fatal("valid late ACK did not resolve remote obligation and retain diagnosis", result, n.ports)
	}
}

type mappingTestUPNP struct {
	add   func(context.Context, uint16, string, uint16, string, uint32) error
	del   func(context.Context, uint16, string) error
	query func(context.Context, uint16, string) (uint16, string, error)
}

func (*mappingTestUPNP) GetExternalIPAddress() (string, error) {
	panic("unexpected external-address query")
}
func (c *mappingTestUPNP) AddPortMappingCtx(ctx context.Context, _ string, external uint16, protocol string, internal uint16, client string, _ bool, _ string, lifetime uint32) error {
	return c.add(ctx, external, protocol, internal, client, lifetime)
}
func (c *mappingTestUPNP) DeletePortMappingCtx(ctx context.Context, _ string, external uint16, protocol string) error {
	return c.del(ctx, external, protocol)
}

func (c *mappingTestUPNP) GetSpecificPortMappingEntryCtx(ctx context.Context, _ string, external uint16, protocol string) (uint16, string, bool, string, uint32, error) {
	if c.query != nil {
		port, client, err := c.query(ctx, external, protocol)
		return port, client, true, "fixture", 60, err
	}
	return 4242, "127.0.0.1", true, "fixture", 60, nil
}

func mappingUPNP(c *mappingTestUPNP) *upnp_NAT {
	// Numeric loopback address parsing and interface metadata only; fake SOAP
	// methods below never open a socket or contact a real gateway.
	return &upnp_NAT{c: c, ports: make(map[int]int), rootDevice: &goupnp.RootDevice{URLBase: url.URL{Host: "127.0.0.1:0"}}}
}

func TestUPNPAddPropagatesInternalAddressFailureWithoutMapping(t *testing.T) {
	u := mappingUPNP(&mappingTestUPNP{add: func(context.Context, uint16, string, uint16, string, uint32) error {
		t.Fatal("SOAP Add called after local address failure")
		return nil
	}})
	u.rootDevice.URLBase.Host = "["
	port, err := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute)
	if err == nil || port != 0 || len(u.ports) != 0 {
		t.Fatal("local address failure became successful zero port", port, err, u.ports)
	}
}

func TestUPNPCreateRenewAndUnknownEffectOwnership(t *testing.T) {
	for _, mode := range []string{"success", "conflict-then-success", "conflicts", "unknown", "late-cancel", "renew-success", "renew-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, deletions := 0, 0
			failure := errors.New("SOAP response lost")
			client := &mappingTestUPNP{add: func(_ context.Context, external uint16, protocol string, internal uint16, address string, lifetime uint32) error {
				calls++
				if protocol != "UDP" || internal != 4242 || external == 0 || address != "127.0.0.1" || lifetime != 60 {
					t.Fatal("incorrect UPnP request")
				}
				if (mode == "renew-success" || mode == "renew-failure") && external != 32000 {
					t.Fatal("renewal changed the owned external port")
				}
				switch mode {
				case "unknown", "renew-failure":
					return failure
				case "conflict-then-success", "conflicts":
					if calls == 1 || mode == "conflicts" {
						fault := &soap.SOAPFaultError{}
						fault.Detail.UPnPError.Errorcode = 718
						return fault
					}
				case "late-cancel":
					cancel()
				}
				return nil
			}, del: func(context.Context, uint16, string) error { deletions++; return nil }}
			u := mappingUPNP(client)
			if mode == "renew-success" || mode == "renew-failure" {
				u.rememberMapping(4242, 32000, net.ParseIP("127.0.0.1"), "udp", false)
			}
			port, err := u.AddPortMapping(ctx, "udp", 4242, "fixture", time.Minute)
			switch mode {
			case "unknown":
				if !errors.Is(err, errMappingUnconfirmed) || !errors.Is(err, failure) || calls != 1 || u.ports[4242] <= 0 {
					t.Fatal("ambiguous creation lost debt or retried into more mappings", err, calls, u.ports)
				}
				if _, err := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute); !errors.Is(err, errMappingUnconfirmed) || calls != 1 {
					t.Fatal("unknown mapping silently adopted/replaced", err, calls)
				}
				if err := u.DeletePortMapping(context.Background(), "udp", 4242); !errors.Is(err, errMappingUnconfirmed) || deletions != 0 || u.ports[4242] <= 0 {
					t.Fatal("unknown external port was deleted or declared absent", err, deletions)
				}
			case "renew-failure":
				if !errors.Is(err, failure) || calls != 1 || u.ports[4242] != 32000 {
					t.Fatal("failed renewal abandoned or migrated the old lease", err, calls, u.ports)
				}
			case "conflicts":
				if err == nil || calls != 3 || len(u.ports) != 0 {
					t.Fatal("confirmed rejections acquired a foreign lease", err, calls, u.ports)
				}
			default:
				if port <= 0 || u.ports[4242] != port || u.uncertain[4242] {
					t.Fatal("acknowledged creation lost ownership", port, err, u.ports)
				}
				if mode == "late-cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("late successful effect hid cancellation", err)
				}
				if mode != "late-cancel" && err != nil {
					t.Fatal(err)
				}
				if mode == "conflict-then-success" && calls != 2 {
					t.Fatal("confirmed-conflict retry behavior changed", calls)
				}
			}
		})
	}
}

func TestUPNPDeleteFailureKeepsRecordButLateConfirmedReplyResolves(t *testing.T) {
	for _, mode := range []string{"success", "failure", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			failure := errors.New("delete response lost")
			client := &mappingTestUPNP{del: func(_ context.Context, external uint16, protocol string) error {
				calls++
				if external != 32000 || protocol != "UDP" {
					t.Fatal("deletion changed owned external port/protocol")
				}
				if mode == "failure" && calls == 1 {
					return failure
				}
				if mode == "late-cancel" && calls == 1 {
					cancel()
				}
				return nil
			}}
			u := mappingUPNP(client)
			u.rememberMapping(4242, 32000, net.ParseIP("127.0.0.1"), "udp", false)
			err := u.DeletePortMapping(ctx, "udp", 4242)
			if mode == "success" || mode == "late-cancel" {
				if err != nil || len(u.ports) != 0 {
					t.Fatal("confirmed deletion did not retire record", err, u.ports)
				}
				if err := u.DeletePortMapping(context.Background(), "udp", 4242); err != nil || calls != 1 {
					t.Fatal("completed deletion was not idempotent", err, calls)
				}
			} else {
				if err == nil || u.ports[4242] != 32000 {
					t.Fatal("failed deletion lost its retry authority", err, u.ports)
				}
				if !errors.Is(err, failure) {
					t.Fatal("delete cause lost", err)
				}
				if err := u.DeletePortMapping(context.Background(), "udp", 4242); err != nil || calls != 2 || len(u.ports) != 0 {
					t.Fatal("retry silently skipped a lost record", err, calls, u.ports)
				}
			}
		})
	}
}

func mappingSOAPFault(code int) error {
	fault := &soap.SOAPFaultError{}
	fault.Detail.UPnPError.Errorcode = code
	return fault
}

func TestUPNPRenewConflictNeverDeletesForeignOrUnprovenEntry(t *testing.T) {
	for _, mode := range []string{"foreign-client", "foreign-port", "same-target", "query-error", "absent", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			adds, deletes := 0, 0
			failure := errors.New("query response unknown")
			client := &mappingTestUPNP{
				add: func(context.Context, uint16, string, uint16, string, uint32) error {
					adds++
					if adds == 1 {
						return nil
					}
					return mappingSOAPFault(718)
				},
				del: func(context.Context, uint16, string) error { deletes++; return nil },
				query: func(context.Context, uint16, string) (uint16, string, error) {
					switch mode {
					case "foreign-client":
						return 4242, "127.0.0.2", nil
					case "foreign-port":
						return 4243, "127.0.0.1", nil
					case "query-error":
						return 0, "", failure
					case "absent":
						return 0, "", mappingSOAPFault(714)
					case "malformed":
						return 4242, "not-an-IP", nil
					default:
						return 4242, "127.0.0.1", nil
					}
				},
			}
			u := mappingUPNP(client)
			if _, err := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute); upnpFaultCode(err) != 718 {
				t.Fatal("renewal conflict lost", err)
			}
			err := u.DeletePortMapping(context.Background(), "udp", 4242)
			resolved := mode == "foreign-client" || mode == "foreign-port" || mode == "absent"
			if deletes != 0 || (err == nil) != resolved || (len(u.ports) == 0) != resolved {
				t.Fatal("stale ACK authorized destructive delete or lost debt", mode, err, deletes, u.ports)
			}
		})
	}
}

func TestUPNPDeleteAlwaysVerifiesCurrentIdentityAndHonorsConfirmedAbsence(t *testing.T) {
	for _, mode := range []string{"owned", "foreign", "absent-query", "absent-delete", "delete-denied", "query-missing", "unknown-create", "unknown-absent"} {
		t.Run(mode, func(t *testing.T) {
			deletes := 0
			client := &mappingTestUPNP{
				query: func(_ context.Context, external uint16, protocol string) (uint16, string, error) {
					if external != 32000 || protocol != "UDP" {
						t.Error("query lost exact mapping key")
					}
					if mode == "foreign" {
						return 4242, "127.0.0.2", nil
					}
					if mode == "absent-query" || mode == "unknown-absent" {
						return 0, "", mappingSOAPFault(714)
					}
					if mode == "query-missing" {
						return 0, "", errors.New("response lost")
					}
					return 4242, "127.0.0.1", nil
				},
				del: func(context.Context, uint16, string) error {
					deletes++
					if mode == "absent-delete" {
						return mappingSOAPFault(714)
					}
					if mode == "delete-denied" {
						return mappingSOAPFault(606)
					}
					return nil
				},
			}
			u := mappingUPNP(client)
			u.rememberMapping(4242, 32000, net.ParseIP("127.0.0.1"), "udp", mode == "unknown-create" || mode == "unknown-absent")
			err := u.DeletePortMapping(context.Background(), "udp", 4242)
			resolved := mode == "owned" || mode == "foreign" || mode == "absent-query" || mode == "absent-delete" || mode == "unknown-absent"
			if (err == nil) != resolved || (len(u.ports) == 0) != resolved {
				t.Fatal("identity/absence classification", mode, err, u.ports)
			}
			wantDelete := mode == "owned" || mode == "absent-delete" || mode == "delete-denied"
			if (deletes == 1) != wantDelete {
				t.Fatal("foreign/unknown entry was destructively deleted", mode, deletes)
			}
		})
	}
}

type mappingTestCleanupFailure struct{ error }

func (mappingTestCleanupFailure) RuntimeCleanupIncomplete() bool { return true }
func (e mappingTestCleanupFailure) Unwrap() error                { return e.error }

func TestUPNPDefiniteAddRejectionsNeverAcquireLease(t *testing.T) {
	for _, code := range []int{401, 402, 600, 601, 602, 605, 606, 715, 716, 724, 725, 726, 727, 728, 729, 732, 501, 603, 604, 999} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			calls := 0
			u := mappingUPNP(&mappingTestUPNP{add: func(context.Context, uint16, string, uint16, string, uint32) error {
				calls++
				return mappingSOAPFault(code)
			}})
			_, err := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute)
			known := code != 501 && code != 603 && code != 604 && code != 999
			if err == nil || calls != 1 || (len(u.ports) == 0) != known {
				t.Fatal("definite rejection or unknown create misclassified", code, err, u.ports)
			}
		})
	}
	for _, err := range []error{errors.Join(mappingSOAPFault(725), errors.New("transport close failed")), mappingTestCleanupFailure{mappingSOAPFault(725)}} {
		u := mappingUPNP(&mappingTestUPNP{add: func(context.Context, uint16, string, uint16, string, uint32) error { return err }})
		if _, result := u.AddPortMapping(context.Background(), "udp", 4242, "fixture", time.Minute); !errors.Is(result, errMappingUnconfirmed) || len(u.ports) == 0 {
			t.Fatal("cleanup failure erased by nested SOAP rejection", result)
		}
	}
}

type mappingTestDeadline struct {
	context.Context
	done chan struct{}
}

func (c mappingTestDeadline) Done() <-chan struct{} { return c.done }
func (c mappingTestDeadline) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestNATPMPJoinedLateDeadlineRequiresRealTerminalAck(t *testing.T) {
	for _, mode := range []string{"valid", "nil", "wrong-internal", "nonzero-external", "nonzero-lifetime", "negative"} {
		t.Run(mode, func(t *testing.T) {
			ctx := mappingTestDeadline{Context: context.Background(), done: make(chan struct{})}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			t.Cleanup(finish)
			n := &natpmpNAT{ports: map[int]int{4242: 32000}, c: &mappingTestPMP{call: func(string, int, int, int) (*natpmp.AddPortMappingResult, error) {
				close(entered)
				<-release
				ack := &natpmp.AddPortMappingResult{InternalPort: 4242}
				switch mode {
				case "nil":
					return nil, nil
				case "wrong-internal":
					ack.InternalPort++
				case "nonzero-external":
					ack.MappedExternalPort = 32000
				case "nonzero-lifetime":
					ack.PortMappingLifetimeInSeconds = 1
				case "negative":
					return nil, errors.New("negative native result")
				}
				return ack, nil
			}}}
			go func() { done <- n.DeletePortMapping(ctx, "udp", 4242) }()
			awaitDiscovery(t, entered)
			close(ctx.done)
			select {
			case <-done:
				t.Fatal("native API was detached on deadline")
			default:
			}
			finish()
			select {
			case err := <-done:
				if (err == nil) != (mode == "valid") || (len(n.ports) == 0) != (mode == "valid") || !errors.Is(n.PortMappingDeleteContextError(), context.DeadlineExceeded) {
					t.Fatal("late terminal result classification", mode, err, n.ports)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("native delete did not join")
			}
		})
	}
}

func TestConfirmedNoMappingHasNoCleanupDebtAfterContextElapsed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, gateway := range []NAT{&natpmpNAT{}, &upnp_NAT{}} {
		if err := gateway.DeletePortMapping(ctx, "udp", 4242); err != nil {
			t.Fatal("known empty obligation became cancellation debt", err)
		}
	}
}

func TestInvalidMappingRequestsCannotCreateWideOrUnintendedLeases(t *testing.T) {
	for _, request := range []struct {
		protocol string
		port     int
		lifetime time.Duration
	}{
		{"unknown", 4242, time.Minute}, {"udp", 0, time.Minute},
		{"udp", -1, time.Minute}, {"udp", 65536, time.Minute},
		{"udp", 4242, -time.Second}, {"udp", 4242, time.Millisecond},
		{"udp", 4242, time.Duration(1<<32) * time.Second},
	} {
		n := &natpmpNAT{c: &mappingTestPMP{call: func(string, int, int, int) (*natpmp.AddPortMappingResult, error) {
			t.Fatal("invalid request reached NAT-PMP")
			return nil, nil
		}}}
		if _, err := n.AddPortMapping(context.Background(), request.protocol, request.port, "fixture", request.lifetime); err == nil || len(n.ports) != 0 {
			t.Fatal("invalid NAT-PMP request accepted", request, err)
		}
		u := mappingUPNP(&mappingTestUPNP{})
		if _, err := u.AddPortMapping(context.Background(), request.protocol, request.port, "fixture", request.lifetime); err == nil || len(u.ports) != 0 {
			t.Fatal("invalid UPnP request accepted", request, err)
		}
	}
}

func TestMappingPreCanceledAndInvalidPMPDeleteDoNotCallNative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &mappingTestPMP{call: func(string, int, int, int) (*natpmp.AddPortMappingResult, error) {
		t.Fatal("invalid/canceled request reached native mapping API")
		return nil, nil
	}}
	n := &natpmpNAT{c: client, ports: map[int]int{4242: 32000}}
	if _, err := n.AddPortMapping(ctx, "udp", 4242, "fixture", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := n.DeletePortMapping(ctx, "udp", 4242); !errors.Is(err, context.Canceled) || n.ports[4242] != 32000 {
		t.Fatal(err, n.ports)
	}
	for _, internal := range []int{0, -1, 65536} {
		n.ports[internal] = 32000
		if err := n.DeletePortMapping(context.Background(), "udp", internal); err == nil {
			t.Fatal("invalid owned port could become protocol-wide deletion", internal)
		}
	}
	u := mappingUPNP(&mappingTestUPNP{})
	u.rememberMapping(4242, 32000, net.ParseIP("127.0.0.1"), "udp", false)
	if _, err := u.AddPortMapping(ctx, "udp", 4242, "fixture", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := u.DeletePortMapping(ctx, "udp", 4242); !errors.Is(err, context.Canceled) || u.ports[4242] != 32000 {
		t.Fatal(err, u.ports)
	}
}
