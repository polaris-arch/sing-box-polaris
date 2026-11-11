//go:build with_naive_outbound && with_purego && windows

package main

import (
	"os"

	"github.com/sagernet/cronet-go"
)

func observeSelectedCronetLibrary(path, expected string) (cronet.LibraryObservation, bool, error) {
	if _, explicit := os.LookupEnv("POLARIS_CRONET_LIBRARY_PATH"); !explicit {
		return cronet.ObserveSelectedLibrary(path)
	}
	return cronet.ObserveSelectedLibraryVerified(path, expected)
}
