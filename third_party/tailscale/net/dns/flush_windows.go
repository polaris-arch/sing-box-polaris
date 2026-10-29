// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type resolverCacheFlushProcedure interface {
	Find() error
	Call(...uintptr) (uintptr, uintptr, error)
}

// Keep the native procedure private and replaceable by tests without loading a DLL.
var resolverCacheDLL = windows.NewLazySystemDLL("dnsapi.dll")
var resolverCacheFlush resolverCacheFlushProcedure = resolverCacheDLL.NewProc("DnsFlushResolverCache")

func flushCaches() error {
	// Call panics if the procedure is missing unless Find succeeds first.
	if err := resolverCacheFlush.Find(); err != nil {
		return fmt.Errorf("find DnsFlushResolverCache: %w", err)
	}
	result, _, lastErr := resolverCacheFlush.Call()
	// The result is a 32-bit BOOL. LastError can be stale after success.
	if int32(result) != 0 {
		return nil
	}
	if lastErr == nil || lastErr == windows.ERROR_SUCCESS {
		return fmt.Errorf("DnsFlushResolverCache: returned FALSE without a last error")
	}
	return fmt.Errorf("DnsFlushResolverCache: %w", lastErr)
}

// Flush clears the local resolver cache.
//
// Only Windows has a public dns.Flush, needed in router_windows.go. Other
// platforms like Linux need a different flush implementation depending on
// the DNS manager. There is a FlushCaches method on the manager which
// can be used on all platforms.
func Flush() error {
	return flushCaches()
}
