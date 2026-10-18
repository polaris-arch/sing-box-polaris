//go:build with_naive_outbound && !with_purego

package main

import "fmt"

const cronetLinkage = "static-cgo"

func prepareCronetLibrary(path, digest string) (string, string, error) {
	if path != "" || digest != "" {
		return "", "", fmt.Errorf("this build links Cronet statically; --library/--sha256 do not apply")
	}
	return "", "", nil
}
