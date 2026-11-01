//go:build with_purego

package cronet

import "github.com/sagernet/cronet-go/internal/cronet"

// LibraryObservation is diagnostic byte identity, not execution authority.
type LibraryObservation = cronet.LibraryObservation

// ObserveSelectedLibrary hashes the loader's captured object on demand. The
// boolean reports selector presence even when capture failed. A nonempty path
// asserts the same object; it cannot replace the captured selection. No selector
// returns false without loading, searching for, opening, or hashing a library.
func ObserveSelectedLibrary(path string) (LibraryObservation, bool, error) {
	return cronet.ObserveSelectedLibrary(path)
}

func LoadLibrary(path string) error {
	return cronet.LoadLibrary(path)
}
