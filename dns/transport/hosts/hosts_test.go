package hosts

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

func TestHosts(t *testing.T) {
	t.Parallel()
	require.Equal(t, []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}, NewFile(context.Background(), "testdata/hosts").Lookup("localhost"))
	if runtime.GOOS != "windows" {
		defaultPathResolved, err := defaultPath()
		if err != nil {
			t.Fatal(E.Cause(err, "resolve default hosts path"))
		}
		content, readErr := os.ReadFile(defaultPathResolved)
		require.NoError(t, readErr)
		hFile := NewFile(context.Background(), defaultPathResolved)
		if len(hFile.Lookup("localhost")) == 0 {
			t.Fatal("failed to resolve localhost: ", defaultPathResolved, ": \n", string(content))
		}
	}
}

func TestHostsLookupReturnsImmutableSnapshotAndCloseSealsReads(t *testing.T) {
	file := NewFile(context.Background(), "testdata/hosts")
	first := file.Lookup("localhost")
	if len(first) == 0 {
		t.Fatal("missing hosts fixture")
	}
	original := first[0]
	first[0] = netip.MustParseAddr("192.0.2.99")
	if next := file.Lookup("localhost"); len(next) == 0 || next[0] != original {
		t.Fatal("lookup exposed mutable cached addresses")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if addresses := file.Lookup("localhost"); addresses != nil {
		t.Fatal("file admitted a read after close")
	}
}
