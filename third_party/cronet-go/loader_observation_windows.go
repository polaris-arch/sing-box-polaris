//go:build with_purego && windows

package cronet

import "github.com/sagernet/cronet-go/internal/cronet"

func ObserveSelectedLibraryVerified(path, expected string) (LibraryObservation, bool, error) {
	return cronet.ObserveSelectedLibraryVerified(path, expected)
}
