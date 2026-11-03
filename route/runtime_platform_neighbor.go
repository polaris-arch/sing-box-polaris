package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

// Reuse the native table readers and lease parsers. No legacy Start callback
// cache or unjoined subscription goroutine stands in for a fresh read.
type runtimeNeighbor struct {
	access          sync.RWMutex
	leaseFiles      []string
	neighborIPToMAC map[netip.Addr]net.HardwareAddr
	leaseIPToMAC    map[netip.Addr]net.HardwareAddr
	ipToHostname    map[netip.Addr]string
	macToHostname   map[string]string
	read            func() ([]adapter.NeighborEntry, error)
}

func newRuntimeNeighbor(files []string) (*runtimeNeighbor, error) {
	paths, err := runtimeNativeNeighborLeaseFiles(files)
	if err != nil {
		return nil, err
	}
	return &runtimeNeighbor{leaseFiles: paths, read: runtimeReadNeighborEntries}, nil
}
func (r *runtimeNeighbor) refresh() error { return r.refreshContext(context.Background()) }
func (r *runtimeNeighbor) refreshContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(r.leaseFiles) > 64 {
		return errRuntimeLeaseBudget
	}
	budget := &runtimeLeaseReadBudget{ctx: ctx, remaining: runtimeLeaseTotalBytes}

	entries, err := r.read()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	neighbors := make(map[netip.Addr]net.HardwareAddr, len(entries))
	for _, entry := range entries {
		neighbors[entry.Address] = slices.Clone(entry.MACAddress)
	}
	leases := make(map[netip.Addr]net.HardwareAddr)
	hosts := make(map[netip.Addr]string)
	macHosts := make(map[string]string)
	for _, path := range r.leaseFiles {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return os.ErrInvalid
		}
		if info.Size() < 0 || info.Size() > runtimeLeaseFileBytes || info.Size() > budget.remaining {
			return errors.Join(errRuntimeLeaseBudget, file.Close())
		}
		err = parseRuntimeLeaseFile(path, &runtimeLeaseReader{reader: file, budget: budget, remaining: runtimeLeaseFileBytes}, leases, hosts, macHosts)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.access.Lock()
	r.neighborIPToMAC = neighbors
	r.leaseIPToMAC = leases
	r.ipToHostname = hosts
	r.macToHostname = macHosts
	r.access.Unlock()
	return nil
}
func (r *runtimeNeighbor) Start() error { return r.refresh() }
func (*runtimeNeighbor) Close() error   { return nil }
func (r *runtimeNeighbor) LookupMAC(address netip.Addr) (net.HardwareAddr, bool) {
	r.access.RLock()
	defer r.access.RUnlock()
	mac, ok := r.neighborIPToMAC[address]
	if !ok {
		mac, ok = r.leaseIPToMAC[address]
	}
	if !ok {
		return extractMACFromEUI64(address)
	}
	return slices.Clone(mac), true
}
func (r *runtimeNeighbor) LookupAddresses(name string) []netip.Addr {
	r.access.RLock()
	defer r.access.RUnlock()
	return lookupAddressesByHostname(name, r.ipToHostname, r.macToHostname, r.neighborIPToMAC, r.leaseIPToMAC)
}
func (r *runtimeNeighbor) LookupHostname(address netip.Addr) (string, bool) {
	r.access.RLock()
	defer r.access.RUnlock()
	if name, ok := r.ipToHostname[address]; ok {
		return name, true
	}
	mac, ok := r.neighborIPToMAC[address]
	if !ok {
		mac, ok = r.leaseIPToMAC[address]
	}
	if !ok {
		mac, ok = extractMACFromEUI64(address)
	}
	if !ok {
		return "", false
	}
	name, ok := r.macToHostname[mac.String()]
	return name, ok
}
