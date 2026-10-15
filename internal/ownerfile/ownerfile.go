// Package ownerfile opens the files and directories qory-github keeps a secret in, or
// reads one from: a private key, a webhook secret, the local store. Each must be the
// user's that qory-github runs as, and grant group and others no permission.
package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// Open opens the file at path with flag and, when it creates the file, perm, never
// through a symbolic link and without waiting on a pipe, and checks what it opened: a
// file that is not a regular one, that grants group or others any permission, or that
// belongs to another user than the one the program runs as is refused and closed. what
// names the file in an error, such as "the private key file"; an error never says what
// the file contains.
func Open(path string, flag int, perm fs.FileMode, what string) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s %s is a symbolic link; use the path of the file itself", what, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s %s is not a regular file", what, path)
	}
	if err := owned(info, path, what, "0600"); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ReadFile reads the file at path as [Open] opens it, and refuses one larger than max
// having read at most one byte more. holds is what the file holds, as the error for a
// larger file says it, such as "a key".
func ReadFile(path string, max int, what, holds string) ([]byte, error) {
	f, err := Open(path, os.O_RDONLY, 0, what)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s %s is larger than %s", what, path, holds)
	}
	return b, nil
}

// Dir makes the directory at path, 0700, when it does not exist, its parent existing,
// and checks it: one that is a symbolic link, that is not a directory, that grants group
// or others any permission, or that belongs to another user than the one the program
// runs as is refused. what names it in an error, such as "the state directory".
func Dir(path, what string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w", what, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symbolic link; use the path of the directory itself", what, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s is not a directory", what, path)
	}
	return owned(info, path, what, "0700")
}

// owned refuses a file or directory that grants group or others any permission, saying
// to make it mode, or that belongs to another user than the one the program runs as.
func owned(info fs.FileInfo, path, what, mode string) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s %s is %s: group or others have permissions on it; make it %s", what, path, info.Mode().Perm(), mode)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s %s belongs to another user than the one qory-github runs as", what, path)
	}
	return nil
}
