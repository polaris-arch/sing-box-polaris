package route

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuntimeLeaseTruncationAndBudgetsPreserveCompleteAcceptedTable(t *testing.T) {
	oldAddress := netip.MustParseAddr("192.0.2.7")
	nativeAddress := netip.MustParseAddr("192.0.2.8")
	nativeMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	root := t.TempDir()
	oldPath := filepath.Join(root, "old.leases")
	if err := os.WriteFile(oldPath, []byte("0 02:00:00:00:00:01 192.0.2.7 old-host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := &runtimeNeighbor{leaseFiles: []string{oldPath}, read: func() ([]adapter.NeighborEntry, error) {
		return []adapter.NeighborEntry{{Address: nativeAddress, MACAddress: nativeMAC}}, nil
	}}
	if err := n.refresh(); err != nil {
		t.Fatal(err)
	}
	nativeMAC = net.HardwareAddr{2, 0, 0, 0, 0, 9}
	validPrefix := "0 02:00:00:00:00:03 192.0.2.9 partial-host *\n"
	records := new(strings.Builder)
	for index := 0; index <= runtimeLeaseMaxRecords; index++ {
		fmt.Fprintf(records, "0 02:00:00:00:00:03 10.%d.%d.%d host-%d *\n", (index>>16)&255, (index>>8)&255, index&255, index)
	}
	for _, row := range []struct {
		name, content string
		target        error
	}{
		{"overlong-line", validPrefix + strings.Repeat("x", bufio.MaxScanTokenSize) + "\n" + validPrefix, bufio.ErrTooLong},
		{"per-file-byte-budget", strings.Repeat("x", runtimeLeaseFileBytes+1), errRuntimeLeaseBudget},
		{"line-budget", strings.Repeat("\n", runtimeLeaseMaxLines+1), errRuntimeLeaseBudget},
		{"record-budget", records.String(), errRuntimeLeaseBudget},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(root, row.name+".leases")
			if err := os.WriteFile(path, []byte(row.content), 0o600); err != nil {
				t.Fatal(err)
			}
			n.leaseFiles = []string{path}
			if err := n.refresh(); !errors.Is(err, row.target) {
				t.Fatal("partial sample accepted", err, row.target)
			}
			if name, ok := n.LookupHostname(oldAddress); !ok || name != "old-host" {
				t.Fatal("old complete lease table lost", name, ok)
			}
			if _, ok := n.LookupHostname(netip.MustParseAddr("192.0.2.9")); ok {
				t.Fatal("partial new lease table published")
			}
			mac, ok := n.LookupMAC(nativeAddress)
			if !ok || mac[5] != 2 {
				t.Fatal("native half of failed refresh was published", mac, ok)
			}
		})
	}
	// Each file is within its limit, but all selected files share one budget.
	n.leaseFiles = nil
	block := strings.Repeat("#"+strings.Repeat("x", 1022)+"\n", runtimeLeaseFileBytes/1024)
	for index := 0; index < 5; index++ {
		path := filepath.Join(root, fmt.Sprintf("aggregate-%d.leases", index))
		if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
			t.Fatal(err)
		}
		n.leaseFiles = append(n.leaseFiles, path)
	}
	if err := n.refresh(); !errors.Is(err, errRuntimeLeaseBudget) {
		t.Fatal("aggregate file budget ignored", err)
	}
	if name, ok := n.LookupHostname(oldAddress); !ok || name != "old-host" {
		t.Fatal("aggregate failure replaced last table", name, ok)
	}
	// Failed first preparation has no accepted table at all.
	fresh := &runtimeNeighbor{leaseFiles: []string{filepath.Join(root, "overlong-line.leases")}, read: n.read}
	if err := fresh.Start(); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatal("first prepare accepted truncation", err)
	}
	if _, ok := fresh.LookupHostname(oldAddress); ok {
		t.Fatal("failed first prepare exposed a sample")
	}
}

type runtimeLeaseReadFault struct {
	prefix  io.Reader
	failure error
}

func (r *runtimeLeaseReadFault) Read(p []byte) (int, error) {
	n, err := r.prefix.Read(p)
	if err == io.EOF {
		return n, r.failure
	}
	return n, err
}

func TestRuntimeLeaseAllFormatsPropagateMidReadFailure(t *testing.T) {
	failed := errors.New("isolated lease read failed")
	for _, name := range []string{"dnsmasq.leases", "dhcpd.leases", "kea-leases4.csv", "kea-leases6.csv", "dhcpd_leases"} {
		t.Run(name, func(t *testing.T) {
			budget := &runtimeLeaseReadBudget{ctx: context.Background(), remaining: runtimeLeaseTotalBytes}
			input := &runtimeLeaseReader{reader: &runtimeLeaseReadFault{prefix: strings.NewReader("header\n0 02:00:00:00:00:01 192.0.2.7 prefix *\n"), failure: failed}, budget: budget, remaining: runtimeLeaseFileBytes}
			err := parseRuntimeLeaseFile(name, input, make(map[netip.Addr]net.HardwareAddr), make(map[netip.Addr]string), make(map[string]string))
			if !errors.Is(err, failed) {
				t.Fatal("parser discarded Scanner.Err", name, err)
			}
		})
	}
}

type runtimeLeaseReadBarrier struct {
	entered chan struct{}
	release chan struct{}
}

func (r *runtimeLeaseReadBarrier) Read(p []byte) (int, error) {
	close(r.entered)
	<-r.release
	return copy(p, "0 02:00:00:00:00:01 192.0.2.7 late *\n"), io.EOF
}

func TestRuntimeLeaseCancellationWaitsForActualReadAndRejectsItsLateBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	barrier := &runtimeLeaseReadBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	reader := &runtimeLeaseReader{reader: barrier, budget: &runtimeLeaseReadBudget{ctx: ctx, remaining: runtimeLeaseTotalBytes}, remaining: runtimeLeaseFileBytes}
	result := make(chan error, 1)
	go func() {
		result <- parseRuntimeLeaseFile("dnsmasq.leases", reader, make(map[netip.Addr]net.HardwareAddr), make(map[netip.Addr]string), make(map[string]string))
	}()
	<-barrier.entered
	cancel()
	select {
	case err := <-result:
		t.Fatal("uncancellable read returned before actual completion", err)
	default:
	}
	close(barrier.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("late bytes lost cancellation", err)
	}
	nativeCalls := 0
	n := &runtimeNeighbor{read: func() ([]adapter.NeighborEntry, error) { nativeCalls++; return nil, nil }}
	if err := n.refreshContext(ctx); !errors.Is(err, context.Canceled) || nativeCalls != 0 {
		t.Fatal("canceled preparation entered native read", err, nativeCalls)
	}
}

func TestRuntimeLeaseBudgetCountsActualReadNotOnlyStatSize(t *testing.T) {
	input := &runtimeLeaseReader{reader: strings.NewReader("growing file"), budget: &runtimeLeaseReadBudget{ctx: context.Background(), remaining: 5}, remaining: runtimeLeaseFileBytes}
	if _, err := io.ReadAll(input); !errors.Is(err, errRuntimeLeaseBudget) {
		t.Fatal("growing file escaped aggregate read budget", err)
	}
}

func TestRuntimeNeighborRetirementJoinsNativeReadAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	p := &RuntimePlatform{ctx: ctx, cancel: cancel, neighbor: &runtimeNeighbor{read: func() ([]adapter.NeighborEntry, error) { close(entered); <-release; return nil, nil }}}
	refreshed := make(chan struct{})
	go func() { p.Refresh(ctx); close(refreshed) }()
	<-entered
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	<-ctx.Done()
	select {
	case <-closed:
		t.Fatal("neighbor retirement claimed completion under native I/O")
	default:
	}
	close(release)
	<-refreshed
	<-closed
}
