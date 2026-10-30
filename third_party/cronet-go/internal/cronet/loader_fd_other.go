//go:build with_purego && (darwin || ios || android)

package cronet

import (
	"fmt"
	"os"
)

type explicitLibrarySelection struct {
	present bool
	path    string
	err     error
}

func captureExplicitLibrary() explicitLibrarySelection {
	_, present := os.LookupEnv("POLARIS_CRONET_LIBRARY_FD")
	selection := explicitLibrarySelection{present: present}
	if present {
		selection.err = fmt.Errorf("cronet: explicit sealed library FD is unsupported on this platform")
	}
	return selection
}

func (s explicitLibrarySelection) resolvePath(path string) (string, error) {
	if s.present {
		return "", s.err
	}
	return path, nil
}

func (s explicitLibrarySelection) observe(path string) (LibraryObservation, bool, error) {
	_, err := s.resolvePath(path)
	return LibraryObservation{}, s.present, err
}
