package ownerfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnErrorNamesThePathAsItIsGiven pins that an error names the path as it is given.
func TestAnErrorNamesThePathAsItIsGiven(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "k.pem")
	os.WriteFile(file, []byte("k"), 0o600)
	link := filepath.Join(dir, "link.pem")
	os.Symlink(file, link)
	loose := filepath.Join(dir, "loose.pem")
	os.WriteFile(loose, []byte("k"), 0o644)
	os.Chmod(loose, 0o644)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o755)
	os.Chmod(sub, 0o755)
	dirLink := filepath.Join(dir, "dirlink")
	os.Symlink(sub, dirLink)
	for _, tc := range []struct {
		path, want string
		read       bool
	}{
		{dir + "//./link.pem", dir + "//./link.pem is a symbolic link", true},
		{dir + "//loose.pem", dir + "//loose.pem is -rw-r--r--", true},
		{dir + "//./none.pem", "open " + dir + "//./none.pem: no such file", true},
		{dirLink + "/", dirLink + "/ is a symbolic link", false},
		// A path that does not end in a slash is checked as the system resolves it:
		// here the directory the link points to.
		{dirLink + "//.", dirLink + "//. is -rwxr-xr-x", false},
		{sub + "//", sub + "// is -rwxr-xr-x", false},
		{dir + "//none/sub", "mkdir " + dir + "//none/sub: no such file", false},
	} {
		var err error
		if tc.read {
			_, err = ReadFile(tc.path, 10, "the file", "a key")
		} else {
			err = Dir(tc.path, "the directory")
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.path, err, tc.want)
		}
	}
	if b, err := ReadFile(dir+"//./k.pem", 10, "the file", "a key"); err != nil || string(b) != "k" {
		t.Errorf("%q %v", b, err)
	}
}
