package route

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
)

var errRuntimeLeaseBudget = errors.New("runtime DHCP lease sample exceeds its finite read budget")

const (
	runtimeLeaseFileBytes  = 4 << 20
	runtimeLeaseTotalBytes = 16 << 20
	runtimeLeaseMaxLines   = 100000
	runtimeLeaseMaxRecords = 65536
)

type runtimeLeaseReadBudget struct {
	ctx       context.Context
	remaining int64
	lines     int
}
type runtimeLeaseReader struct {
	reader    io.Reader
	budget    *runtimeLeaseReadBudget
	remaining int64
}

func (r *runtimeLeaseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.budget.ctx.Err(); err != nil {
		return 0, err
	}
	available := min(r.remaining, r.budget.remaining)
	if available < 0 {
		return 0, errRuntimeLeaseBudget
	}
	// At the exact boundary, read at most one extra byte to distinguish EOF
	// from a growing/truncated sample. It is never admitted as successful input.
	if int64(len(p)) > available+1 {
		p = p[:int(available+1)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	r.budget.remaining -= int64(n)
	if int64(n) > available {
		return 0, errRuntimeLeaseBudget
	}
	if canceled := r.budget.ctx.Err(); canceled != nil {
		return n, errors.Join(canceled, err)
	}
	return n, err
}

type runtimeLeaseScanner struct {
	scanner *bufio.Scanner
	budget  *runtimeLeaseReadBudget
	records func() bool
	err     error
}

func newRuntimeLeaseScanner(reader io.Reader, leases map[netip.Addr]net.HardwareAddr, hosts map[netip.Addr]string, macHosts map[string]string) *runtimeLeaseScanner {
	s := &runtimeLeaseScanner{scanner: bufio.NewScanner(reader)}
	if bounded, ok := reader.(*runtimeLeaseReader); ok {
		s.budget = bounded.budget
		s.records = func() bool {
			return len(leases) <= runtimeLeaseMaxRecords && len(hosts) <= runtimeLeaseMaxRecords && len(macHosts) <= runtimeLeaseMaxRecords
		}
	}
	return s
}
func (s *runtimeLeaseScanner) Scan() bool {
	if s.err != nil {
		return false
	}
	if s.budget != nil {
		if s.err = s.budget.ctx.Err(); s.err != nil {
			return false
		}
		if !s.records() {
			s.err = errRuntimeLeaseBudget
			return false
		}
	}
	if !s.scanner.Scan() {
		s.err = s.scanner.Err()
		return false
	}
	if s.budget != nil {
		s.budget.lines++
		if s.budget.lines > runtimeLeaseMaxLines {
			s.err = errRuntimeLeaseBudget
			return false
		}
	}
	return true
}
func (s *runtimeLeaseScanner) Text() string { return s.scanner.Text() }
func (s *runtimeLeaseScanner) Err() error   { return s.err }
