//go:build with_naive_outbound && !with_purego

package main

import "fmt"

const cronetLinkage = "static-cgo"

func prepareCronetLibrary(path, digest string) (string, string, error) {
	verified, err := prepareCronetLibraryObservation(path, digest)
	return verified.Path, verified.SHA256, err
}

func prepareCronetLibraryObservation(path, digest string) (cronetLibraryVerification, error) {
	if path != "" || digest != "" {
		return cronetLibraryVerification{}, fmt.Errorf("this build links Cronet statically; --library/--sha256 do not apply")
	}
	return cronetLibraryVerification{}, nil
}
