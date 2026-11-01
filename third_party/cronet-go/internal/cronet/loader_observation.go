//go:build with_purego

package cronet

// LibraryObservation describes bytes held by the loader. It is diagnostic data,
// never admission authority. Hashing occurs only on an explicit observation.
type LibraryObservation struct {
	Path   string
	Bytes  int64
	SHA256 string
}
