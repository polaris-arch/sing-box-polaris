//go:build linux || darwin

package route

import (
	"os"
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

func runtimeReadNeighborEntries() ([]adapter.NeighborEntry, error) { return ReadNeighborEntries() }
func runtimeNativeNeighborLeaseFiles(files []string) ([]string, error) {
	if len(files) > 0 {
		return slices.Clone(files), nil
	}
	var selected []string
	for _, path := range defaultLeaseFiles {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			selected = append(selected, path)
		}
	}
	return selected, nil
}
