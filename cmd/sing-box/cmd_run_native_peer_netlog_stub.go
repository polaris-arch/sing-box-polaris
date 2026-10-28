//go:build !linux || !with_naive_outbound

package main

func startNativePeerNetLog() (func() error, error) {
	return nil, nil
}
