// Package setupcmd is what the setup commands of qory-github and qory-github-starter
// share past their flags: the run of [github.Setup] up to the App it created and where
// its key is, what it prints on the way, the check of the key file's path, the browser
// that opens setup's page, and the random suffix of an App's default name.
package setupcmd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/qory-github"
)

// Create checks the key file's path, see [CheckKeyFile], starts s, prints the line that
// says to approve the App in the browser and where its page is, and waits for the App.
// It returns the App and the absolute path of the file its key is in; when the key is
// not in [github.Setup.KeyFile] it has printed where it is instead, see [MovedLine].
func Create(ctx context.Context, s github.Setup, stdout io.Writer) (*github.App, string, error) {
	if err := CheckKeyFile(s.KeyFile); err != nil {
		return nil, "", err
	}
	page, wait, err := s.Start(ctx)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(stdout, "Approve the App in the browser. If none opened, open %s\n", page)
	app, err := wait()
	if err != nil {
		return nil, "", err
	}
	abs, _ := filepath.Abs(app.KeyFile)
	if app.Moved != nil {
		fmt.Fprint(stdout, MovedLine(abs, s.KeyFile, app.Moved))
	}
	return app, abs, nil
}

// MovedLine is the line setup prints when the key is in abs, beside file, since file
// could not be written, or was written and its sync failed, and why: the error of the
// [*fs.PathError] that moved wraps, or "it exists".
func MovedLine(abs, file string, moved error) string {
	what, why := "written", moved.Error()
	var pe *fs.PathError
	switch {
	case errors.Is(moved, fs.ErrExist):
		why = "it exists"
	case errors.As(moved, &pe):
		why = pe.Err.Error()
		if pe.Op == "sync" {
			what = "written or synced"
		}
	}
	return fmt.Sprintf("\nThe key is in %s, since %s could not be %s: %s.\n", abs, file, what, why)
}

// CheckKeyFile refuses a key file's path that what setup prints cannot contain as it is
// written: one that is not UTF-8, or that contains a control character, C0, DEL or C1.
// It runs before setup creates a directory or the App, so nothing is created for a path
// setup refuses.
func CheckKeyFile(p string) error {
	p, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("the key file's path %q is not UTF-8; choose another with --key-file", p)
	}
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return fmt.Errorf("the key file's path %q contains a control character; choose another with --key-file", p)
	}
	return nil
}

// Browse opens a URL in the machine's browser. It never fails the setup: the URL is
// printed as well. A command opens setup's page through a variable a test replaces, so
// a test never opens a browser.
func Browse(u string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	cmd := exec.Command(name, u)
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
	return nil
}

// RandomSuffix is six hex digits, so a default App name is likely free.
func RandomSuffix() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
