//go:build with_tailscale && !darwin && !linux && !windows

package tailscale

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Unsupported platforms can run legacy endpoints but cannot produce directory
// retirement evidence. No cross-process exclusion is claimed here.
type directoryLease struct {
	Identity    string
	Incarnation string
	Epoch       string
	Managed     bool
}

func acquireDirectoryLease(directory string) (*directoryLease, error) {
	rawBase := strings.TrimRight(directory, "/\\")
	rawBase = rawBase[strings.LastIndexAny(rawBase, "/\\")+1:]
	if !validDirectoryServerID(rawBase) {
		return nil, fmt.Errorf("directory lease: invalid target basename")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if absolute == filepath.Dir(absolute) || !validDirectoryServerID(filepath.Base(absolute)) {
		return nil, fmt.Errorf("directory lease: invalid server directory")
	}
	return &directoryLease{}, nil
}

func validDirectoryServerID(serverID string) bool {
	return serverID != "" && serverID != "." && serverID != ".." &&
		utf8.ValidString(serverID) &&
		!strings.ContainsRune(serverID, 0) && !strings.ContainsAny(serverID, "/\\") &&
		filepath.Base(serverID) == serverID
}

func (*directoryLease) Close() error { return nil }

func acquireMappedDirectory(logical, physical string) (string, *directoryLease, error) {
	if !filepath.IsAbs(logical) || !filepath.IsAbs(physical) || filepath.Clean(logical) != logical || filepath.Clean(physical) != physical ||
		!validDirectoryServerID(filepath.Base(logical)) || filepath.Base(logical) != filepath.Base(physical) || logical == physical {
		return "", nil, fmt.Errorf("directory lease: invalid directory mapping")
	}
	actual := physical
	if info, err := os.Lstat(logical); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", nil, fmt.Errorf("directory lease: unsafe existing logical target")
		}
		actual = logical
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	lease, err := acquireDirectoryLease(actual)
	return actual, lease, err
}

// Unsupported platforms cannot promise durable cross-process domain revocation.
func PoisonDirectoryDomain(root string) error {
	return fmt.Errorf("directory lease: durable domain revocation is unsupported")
}
