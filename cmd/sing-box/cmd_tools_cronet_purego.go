//go:build with_naive_outbound && with_purego

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sagernet/cronet-go"
)

const cronetLinkage = "shared-purego"

func verifyCronetLibraryFile(path, expected string) (string, string, error) {
	verified, err := verifyCronetLibraryFileObservation(path, expected)
	return verified.Path, verified.SHA256, err
}

func verifyCronetLibraryFileObservation(path, expected string) (cronetLibraryVerification, error) {
	if path == "" {
		return cronetLibraryVerification{}, fmt.Errorf("--library is required; no environment or system library fallback")
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return cronetLibraryVerification{}, fmt.Errorf("--sha256 must be a 64-hex expected digest")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	// Reject special files before Open: opening a FIFO can block without a writer.
	info, err := os.Stat(resolved)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	if !info.Mode().IsRegular() {
		return cronetLibraryVerification{}, fmt.Errorf("Cronet library must be a regular file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	if !info.Mode().IsRegular() {
		return cronetLibraryVerification{}, fmt.Errorf("Cronet library must be a regular file")
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return cronetLibraryVerification{}, err
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != hex.EncodeToString(decoded) {
		return cronetLibraryVerification{}, fmt.Errorf("Cronet library SHA-256 mismatch: got %s, want %s", actual, expected)
	}
	return cronetLibraryVerification{Path: resolved, SHA256: actual, Bytes: info.Size(), Selection: "standalone-path"}, nil
}

func prepareCronetLibrary(path, expected string) (string, string, error) {
	verified, err := prepareCronetLibraryObservation(path, expected)
	return verified.Path, verified.SHA256, err
}

func prepareCronetLibraryObservation(path, expected string) (cronetLibraryVerification, error) {
	observation, selected, err := cronet.ObserveSelectedLibrary(path)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	if selected {
		decoded, err := hex.DecodeString(expected)
		if err != nil || len(decoded) != sha256.Size {
			return cronetLibraryVerification{}, fmt.Errorf("--sha256 must be a 64-hex expected digest")
		}
		if observation.SHA256 != hex.EncodeToString(decoded) {
			return cronetLibraryVerification{}, fmt.Errorf("Cronet captured library SHA-256 mismatch: got %s, want %s", observation.SHA256, expected)
		}
		if err := cronet.LoadLibrary(""); err != nil {
			return cronetLibraryVerification{}, err
		}
		return cronetLibraryVerification{Path: observation.Path, SHA256: observation.SHA256, Bytes: observation.Bytes, Selection: "captured-sealed-fd"}, nil
	}
	verified, err := verifyCronetLibraryFileObservation(path, expected)
	if err != nil {
		return cronetLibraryVerification{}, err
	}
	if err = cronet.LoadLibrary(verified.Path); err != nil {
		return cronetLibraryVerification{}, err
	}
	return verified, nil
}
