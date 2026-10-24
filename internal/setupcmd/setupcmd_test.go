package setupcmd

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSetupPrintsWhereAKeyWhoseSyncFailedIs pins the line setup prints when the key file
// was written and its sync failed, for the error setup's exchange moves the key with
// (the github package's TestSetupSyncsTheKeyFileBeforeItClosesIt fails a file's sync
// with EIO and checks the key goes beside it): the file could not be written or synced.
// A file that could not be written for another reason keeps the line it has.
func TestSetupPrintsWhereAKeyWhoseSyncFailedIs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "github-app.pem")
	beside := file + ".0123456789abcdef"
	for _, tc := range []struct {
		moved error
		want  string
	}{
		{fmt.Errorf("the key file could not be synced to disk: %w", &fs.PathError{Op: "sync", Path: file, Err: syscall.EIO}), "\nThe key is in " + beside + ", since " + file + " could not be written or synced: input/output error.\n"},
		{fmt.Errorf("the key file: %w", &fs.PathError{Op: "write", Path: file, Err: syscall.ENOSPC}), "\nThe key is in " + beside + ", since " + file + " could not be written: " + syscall.ENOSPC.Error() + ".\n"},
		{fmt.Errorf("the key file: %w", &fs.PathError{Op: "open", Path: file, Err: syscall.EACCES}), "\nThe key is in " + beside + ", since " + file + " could not be written: " + syscall.EACCES.Error() + ".\n"},
	} {
		if got := MovedLine(beside, file, tc.moved); got != tc.want {
			t.Errorf("%v: setup prints %q, want %q", tc.moved, got, tc.want)
		}
	}
}
