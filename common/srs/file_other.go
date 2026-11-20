//go:build !unix

package srs

import "os"

const readFileFlags = os.O_RDONLY
