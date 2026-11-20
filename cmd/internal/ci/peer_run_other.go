//go:build !linux

package main

import (
	"context"
	"fmt"
)

func peerRun(context.Context, []string) error {
	return fmt.Errorf("controlled peer execution must be nonroot Linux")
}
