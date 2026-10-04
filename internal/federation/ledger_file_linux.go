//go:build linux

package federation

import (
	"os"
	"syscall"
)

// privateLedgerFile validates the opened inode before bbolt reads or writes it.
// O_NOFOLLOW rejects the final symlink atomically; O_NONBLOCK prevents a replaced
// FIFO from hanging startup. The deployment must protect the parent directory.
func privateLedgerFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
