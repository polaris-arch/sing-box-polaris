//go:build !unix

package certificate

import "os"

// Windows opens the handle without reading or waiting for pipe data; Unix FIFO
// flags do not apply. Keep os.Root's confinement and native sharing contract.
const (
	runtimeStorageOpenFlags          = os.O_RDONLY
	runtimeStorageDirectoryOpenFlags = runtimeStorageOpenFlags
)
