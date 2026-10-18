package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// TailscaleStoreRunBinding is installed by the original daemon Instance before
// box construction. It is not a caller-supplied native disposal certificate.
type TailscaleStoreRunBinding struct {
	RunNonce     string
	ConfigDigest string
}

// TailscaleStoreNode reports only the original endpoint's StateStore writer.
// No keys, profile preferences, auth key or authorization URL are exported.
type TailscaleStoreNode struct {
	Tag                string `json:"tag"`
	StateDirectory     string `json:"stateDirectory"`
	StateFile          string `json:"stateFile"`
	WriterState        string `json:"writerState"`
	StateFileState     string `json:"stateFileState"`
	StateFileRevision  string `json:"stateFileRevision"`
	ProfileState       string `json:"profileState"`
	ProfileFingerprint string `json:"profileFingerprint"`
	RunNonce           string `json:"-"`
	ConfigDigest       string `json:"-"`
}

type TailscaleStateStoreOwner interface {
	TailscaleStateStoreScope() TailscaleStoreNode
	RetireTailscaleStateStore(deadline time.Time) TailscaleStoreNode
}

// TailscaleStoreConstructionObserver belongs to one original validation call.
// Registration happens before the guard admits any delegate/read/write. A false
// result permanently seals that same guard before constructor handoff.
type TailscaleStoreConstructionObserver struct {
	Observe func(TailscaleStoreNode, func(time.Time) TailscaleStoreNode) bool
}

// CanonicalTailscaleStateDirectory resolves existing parents without creating
// the lazy FileStore directory. Constructor and validation use the same body.
func CanonicalTailscaleStateDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	remaining := []string{}
	parent := absolute
	for {
		canonical, err := filepath.EvalSymlinks(parent)
		if err == nil {
			for _, component := range slices.Backward(remaining) {
				canonical = filepath.Join(canonical, component)
			}
			return canonical, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", err
		}
		remaining = append(remaining, filepath.Base(parent))
		parent = next
	}
}
