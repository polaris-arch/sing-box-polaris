//go:build !linux && !darwin

package main

import "context"

func prepareNativeSmoke(context.Context, string, map[string]any, map[string][]byte, *nativeSmokeExecution) error {
	return nil
}
