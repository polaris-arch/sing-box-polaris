//go:build with_tailscale

package tailscale

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Directory retirement covers only the original node's filesystem subtree.
// Silently marking an external Taildrop writer Unknown is insufficient: it
// could still write a different node while that node consumes a valid receipt.
func ownedTaildropRelative(stateDirectory, taildropDirectory string) (string, error) {
	relative, err := filepath.Rel(filepath.Clean(stateDirectory), filepath.Clean(taildropDirectory))
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("tailscale: taildrop_directory must be a strict child of this endpoint's state_directory for safe directory retirement; external files are not moved")
	}
	return relative, nil
}
