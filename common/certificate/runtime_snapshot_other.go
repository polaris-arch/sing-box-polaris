//go:build !(darwin && cgo)

package certificate

type snapshotPlatform struct{}

func newSnapshotPlatform([]byte) (snapshotPlatform, error) { return snapshotPlatform{}, nil }
func (snapshotPlatform) release()                          {}
