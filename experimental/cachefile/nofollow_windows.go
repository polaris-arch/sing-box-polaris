package cachefile

import "syscall"

// noFollow opens a reparse point at the cache path itself, never its target.
const noFollow = syscall.FILE_FLAG_OPEN_REPARSE_POINT
