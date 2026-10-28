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
	if path == "" {
		return "", "", fmt.Errorf("--library is required; no environment or system library fallback")
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return "", "", fmt.Errorf("--sha256 must be a 64-hex expected digest")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", err
	}
	// Reject special files before Open: opening a FIFO can block without a writer.
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("Cronet library must be a regular file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("Cronet library must be a regular file")
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return "", "", err
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != hex.EncodeToString(decoded) {
		return "", "", fmt.Errorf("Cronet library SHA-256 mismatch: got %s, want %s", actual, expected)
	}
	return resolved, actual, nil
}

func prepareCronetLibrary(path, expected string) (string, string, error) {
	resolved, digest, err := verifyCronetLibraryFile(path, expected)
	if err != nil {
		return "", "", err
	}
	if err = cronet.LoadLibrary(resolved); err != nil {
		return "", "", err
	}
	return resolved, digest, nil
}
