//go:build with_naive_outbound && with_purego && !windows

package main

import "github.com/sagernet/cronet-go"

func observeSelectedCronetLibrary(path, _ string) (cronet.LibraryObservation, bool, error) {
	return cronet.ObserveSelectedLibrary(path)
}
