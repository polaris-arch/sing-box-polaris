//go:build !linux

package main

import (
	"context"
	"fmt"
)

func localNative(context.Context, []string) error {
	return fmt.Errorf("local native execution requires Linux amd64")
}
