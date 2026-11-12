//go:build !windows

package cachefile

import "syscall"

// noFollow refuses a symbolic link at the cache path itself.
const noFollow = syscall.O_NOFOLLOW
