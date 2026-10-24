// Package ownerfile opens the files and directories the program, qory-github or
// qory-github-server, keeps a secret in, or reads one from: a
// private key, a webhook secret, an access key's secret, the local store. Each must be
// the user's that the program runs as, and grant group and others no permission.
package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Program is the program's name, which an error about a file that belongs to another
// user names: qory-github unless the program sets its name at start, as
// qory-github-server does.
var Program = "qory-github"

// Open opens the file at path with flag and, when it creates the file, perm, never
// through a symbolic link and without waiting on a pipe, and checks what it opened: a
// file that is not a regular one, that grants group or others any permission, or that
// belongs to another user than the one the program runs as is refused and closed. what
// names the file in an error, such as "the private key file"; an error never says what
// the file contains. path is opened as it is given, so the system resolves each .. in
// it through the links before it, and a trailing slash opens no file; a final link is
// refused.
func Open(path string, flag int, perm fs.FileMode, what string) (*os.File, error) {
	return open(path, flag, perm, what, true)
}

// open is [Open], whose errors say the path when shown is set, and otherwise name the
// file by what alone and give an [fs.PathError]'s cause without its path.
func open(path string, flag int, perm fs.FileMode, what string, shown bool) (*os.File, error) {
	subject, cause := what+" "+path, func(err error) error { return err }
	if !shown {
		subject, cause = what, pathless
	}
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; use the path of the file itself", subject)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, cause(err))
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", what, cause(err))
	}
	if err := Check(info, subject); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Check refuses the file info describes as [Open] refuses what it opened: a file that is
// not a regular one, that grants group or others any permission, or that belongs to
// another user than the one the program runs as. info is the Stat of an open file, so
// what is checked is the file open, whatever its path names now. subject names it in an
// error, such as "the store /var/lib/qory-github/qory-github.db".
func Check(info fs.FileInfo, subject string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", subject)
	}
	return owned(info, subject, "0600")
}

// pathless is err without the path, the [fs.PathError]'s cause when it is one.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// ReadFile reads the file at path as [Open] opens it, and refuses one larger than max
// having read at most one byte more. holds is what the file holds, as the error for a
// larger file says it, such as "a key".
func ReadFile(path string, max int, what, holds string) ([]byte, error) {
	return readFile(path, max, what, holds, true)
}

// ReadNamed reads the file at path as [ReadFile] does, for a file a setting names, such
// as "the file access_key_secret_file names": an error names the file by what alone and
// never says the path, so a secret pasted in place of the path is never quoted.
func ReadNamed(path string, max int, what, holds string) ([]byte, error) {
	return readFile(path, max, what, holds, false)
}

func readFile(path string, max int, what, holds string, shown bool) ([]byte, error) {
	f, err := open(path, os.O_RDONLY, 0, what, shown)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		if !shown {
			err = pathless(err)
		}
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(b) > max {
		subject := what
		if shown {
			subject += " " + path
		}
		return nil, fmt.Errorf("%s is larger than %s", subject, holds)
	}
	return b, nil
}

// Dir makes the directory at path, 0700, when it does not exist, its parent existing,
// and checks it: one that is a symbolic link, that is not a directory, that grants group
// or others any permission, or that belongs to another user than the one the program
// runs as is refused, and so is a path whose last part is . or .. . what names it in an
// error, such as "the state directory". The path checked is path without its trailing
// slashes, / itself kept, since Lstat of link/ would read the directory the link
// points to; nothing else in it is changed, so the system still resolves each .. before
// the last part through the links before it. An error names path as it is given.
func Dir(path, what string) error {
	clean := strings.TrimRight(path, "/")
	if clean == "" && path != "" {
		clean = "/"
	}
	// A last part . or .. names the directory through another, a link's target
	// among them, so link/. would be checked as what link points to.
	if base := filepath.Base(clean); base == "." || base == ".." {
		return fmt.Errorf("%s %s ends in . or ..; name the directory itself", what, path)
	}
	if err := os.Mkdir(clean, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w", what, given(err, path))
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("%s: %w", what, given(err, path))
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symbolic link; use the path of the directory itself", what, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s is not a directory", what, path)
	}
	return owned(info, what+" "+path, "0700")
}

// given is err with the path of the [fs.PathError] it is, if it is one, set back to path
// as the person who runs the program gave it, since the call it failed was handed path
// without its trailing slashes.
func given(err error, path string) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		pe.Path = path
	}
	return err
}

// owned refuses a file or directory that grants group or others any permission, saying
// to make it mode, or that belongs to another user than the one the program runs as.
// subject names it in the error.
func owned(info fs.FileInfo, subject, mode string) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is %s: group or others have permissions on it; make it %s", subject, info.Mode().Perm(), mode)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s belongs to another user than the one %s runs as", subject, Program)
	}
	return nil
}
