// Package main's private file helpers anchor every operation to an opened
// directory descriptor. Path components are opened with O_NOFOLLOW and
// validated before the final file is opened relative to that descriptor.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const trustedPeopleKeyringPath = "/etc/baobab/iam/people-dev/trusted-reviewers.json"

func fileStat(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, err
	}
	return st, nil
}

// openSecureDirectory resolves every component without following symlinks.
// Ancestors must be root- or expected-owner-controlled and not group/other
// writable. The final directory must have the specified owner and exact mode.
func openSecureDirectory(path string, expectedOwner uint32, finalMode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("secure directory path must be clean and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		_ = unix.Close(fd)
		return nil, errors.New("secure directory path has no components")
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("invalid secure directory component")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open secure directory component %q: %w", part, openErr)
		}
		fd = next
		st, statErr := fileStat(fd)
		if statErr != nil {
			_ = unix.Close(fd)
			return nil, statErr
		}
		mode := uint32(st.Mode) & 07777
		last := i == len(parts)-1
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != expectedOwner) || mode&0022 != 0 {
			_ = unix.Close(fd)
			return nil, errors.New("secure directory component has unsafe type, owner or write permissions")
		}
		if last && (st.Uid != expectedOwner || mode != finalMode) {
			_ = unix.Close(fd)
			return nil, errors.New("secure directory owner or mode does not match policy")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openPrivateFileAt(dir *os.File, name string, owner, mode uint32, flags int) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, '\x00') {
		return nil, errors.New("private file name must be one path component")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := fileStat(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner ||
		uint32(st.Mode)&07777 != mode || st.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, errors.New("private file type, owner, mode or link count does not match policy")
	}
	return os.NewFile(uintptr(fd), name), nil
}

func decodePrivateJSON(file *os.File, target any) error {
	st, err := fileStat(int(file.Fd()))
	if err != nil {
		return err
	}
	if st.Size <= 0 || st.Size > 32768 {
		return errors.New("private governance file size is outside the permitted bound")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 32769))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing private governance data")
	}
	return nil
}

// loadApproval reads an owner-controlled 0600 file from an owner-only 0700
// directory. The opened descriptor, not a prior pathname stat, is validated.
func loadApproval(path string, target any) error {
	uid := uint32(os.Geteuid())
	dir, err := openSecureDirectory(filepath.Dir(path), uid, 0700)
	if err != nil {
		return err
	}
	defer dir.Close()
	file, err := openPrivateFileAt(dir, filepath.Base(path), uid, 0600, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	return decodePrivateJSON(file, target)
}

// loadTrustedKeyring deliberately has no caller-selectable path. Infrastructure
// provisions this root-owned read-only trust anchor independently of the
// approval submitter; the runtime identity cannot replace it.
func loadTrustedKeyring(target any) error {
	dir, err := openSecureDirectory(filepath.Dir(trustedPeopleKeyringPath), 0, 0755)
	if err != nil {
		return err
	}
	defer dir.Close()
	file, err := openPrivateFileAt(dir, filepath.Base(trustedPeopleKeyringPath), 0, 0400, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	return decodePrivateJSON(file, target)
}

type secureCredential struct {
	file *os.File
	dir  *os.File
	name string
}

func (s *secureCredential) Write(p []byte) (int, error) { return s.file.Write(p) }
func (s *secureCredential) Sync() error {
	if err := s.file.Sync(); err != nil {
		return err
	}
	return s.dir.Sync()
}
func (s *secureCredential) Close() error { return s.file.Close() }
func (s *secureCredential) Cleanup() error {
	closeErr := s.file.Close()
	unlinkErr := unix.Unlinkat(int(s.dir.Fd()), s.name, 0)
	dirSyncErr := s.dir.Sync()
	dirCloseErr := s.dir.Close()
	return errors.Join(closeErr, unlinkErr, dirSyncErr, dirCloseErr)
}
func (s *secureCredential) CloseDirectory() error { return s.dir.Close() }

// createSecureCredential reserves and verifies the credential file relative
// to an already-open, owner-only custody directory before any issuer mutation.
func createSecureCredential(path string) (*secureCredential, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("absolute clean credential custody path required")
	}
	uid := uint32(os.Geteuid())
	dir, err := openSecureDirectory(filepath.Dir(path), uid, 0700)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, '\x00') {
		_ = dir.Close()
		return nil, errors.New("invalid credential filename")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	st, err := fileStat(fd)
	if err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(dir.Fd()), name, 0)
		_ = dir.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid || uint32(st.Mode)&07777 != 0600 || st.Nlink != 1 {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(dir.Fd()), name, 0)
		_ = dir.Close()
		return nil, errors.New("created credential file failed descriptor custody validation")
	}
	return &secureCredential{file: os.NewFile(uintptr(fd), name), dir: dir, name: name}, nil
}
