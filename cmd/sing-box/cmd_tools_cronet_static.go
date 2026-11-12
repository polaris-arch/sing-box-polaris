//go:build with_naive_outbound && !with_purego

package main

import "fmt"

const cronetLinkage = "static-cgo"

func prepareCronetLibraryObservation(path, digest string) (cronetLibraryVerification, error) {
	if path != "" || digest != "" {
		return cronetLibraryVerification{}, fmt.Errorf("this build links Cronet statically; --library/--sha256 do not apply")
	}
	return cronetLibraryVerification{}, nil
}
