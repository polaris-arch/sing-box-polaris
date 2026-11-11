//go:build !windows

package box

import (
	"fmt"
	"net"
	"testing"
)

func clientShapeIPv6CollisionHolder(t *testing.T, port int) net.Listener {
	t.Helper()
	holder, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Fatal("bind IPv6 collision holder", err)
	}
	return holder
}
