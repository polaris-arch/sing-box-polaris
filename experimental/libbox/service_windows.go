package libbox

import "os"

func closeDup(fd int) error { return os.ErrInvalid }

func dup(fd int) (nfd int, err error) {
	return 0, os.ErrInvalid
}
