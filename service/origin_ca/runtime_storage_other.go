//go:build !unix

package originca

import "os"

const (
	originStorageReadFlags      = os.O_RDONLY
	originStorageDirectoryFlags = originStorageReadFlags
)

// Windows retains Go's native Root sharing/alias contract. Unix nonblocking
// flags are not portable numeric flags. js/plan9 runtime directory storage is
// already unavailable; these flags do not assert Unix FIFO semantics on WASI.
func originOpenStorageRoot(name string) (*os.Root, error) { return os.OpenRoot(name) }
