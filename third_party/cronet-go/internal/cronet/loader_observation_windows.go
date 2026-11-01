//go:build with_purego && windows

package cronet

import (
	"fmt"
	"os"
)

var sealedFDSelectorPresent = func() bool {
	_, present := os.LookupEnv("POLARIS_CRONET_LIBRARY_FD")
	return present
}()

func ObserveSelectedLibrary(string) (LibraryObservation, bool, error) {
	if sealedFDSelectorPresent {
		return LibraryObservation{}, true, fmt.Errorf("cronet: explicit sealed library FD is unsupported on this platform")
	}
	return LibraryObservation{}, false, nil
}
