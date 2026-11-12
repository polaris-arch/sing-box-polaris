package adapter

import "net/netip"

// FakeIPStorageSnapshot is a detached copy of the fake-IP cache image.
type FakeIPStorageSnapshot struct {
	Metadata *FakeIPMetadata
	Mappings map[netip.Addr]string
}
