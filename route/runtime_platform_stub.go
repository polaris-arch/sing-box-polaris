//go:build !linux && !darwin

package route

import (
	"os"

	"github.com/sagernet/sing-box/adapter"
)

func runtimeReadNeighborEntries() ([]adapter.NeighborEntry, error) { return nil, os.ErrInvalid }
func runtimeNativeNeighborLeaseFiles([]string) ([]string, error)   { return nil, os.ErrInvalid }
