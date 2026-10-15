package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
)

// accessKeyHelp is the help of access-key enrol, which has no section on the program's
// page: the command is switched on by QORY_FEATURES alone, see [factory].
var accessKeyHelp = help{
	short: "Enrol the work source's access key with a code from Qory Apiary",
	use:   "qory-github access-key enrol --secret-file FILE [--] SERVER CODE",
	long: `Enrol a new access key for this work source with an enrolment code an owner or
administrator in Qory Apiary created on the integration's page in Organisation
settings. The code is valid for 15 minutes and used once.

qory-github makes the key, prints its fingerprint and sends Qory Apiary, at SERVER, the
public key. Qory Apiary's signed answer gives the key its id and lists Qory Apiary's
public key. Only then is the secret written, to --secret-file, which only you may
read. enrol never writes over a file that exists, and never prints the secret.

Then enrol prints the settings to add to serve's settings: apiary_url, access_key_id,
access_key_secret_file and apiary_public_key.`,
	example: `  qory-github access-key enrol --secret-file /etc/qory-github/access-key-secret https://apiary.example.com "$code"`,
}

// enrol's test seams: the key it makes; the access key's name, from this machine's host
// name; and the client it posts with, nil for accesskey's.
var (
	generateKey = accesskey.Generate
	hostname    = os.Hostname
	enrolClient *http.Client
)

// accessKey runs access-key's one verb, enrol. -h alone prints enrol's help.
func accessKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && slices.Contains([]string{"-h", "-help", "--h", "--help"}, args[0]) {
		return accessKeyHelp.parse(flag.NewFlagSet("access-key", flag.ContinueOnError), args, stderr)
	}
	if len(args) == 0 || args[0] != "enrol" {
		return errors.New("access-key has one command, enrol: qory-github access-key enrol --secret-file FILE SERVER CODE")
	}
	return enrol(ctx, args[1:], stdout, stderr)
}

// enrol is access-key enrol. The lines for a person go to stderr, and the settings alone
// to stdout. An error never contains the secret or the code.
func enrol(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("access-key enrol", flag.ContinueOnError)
	secretFile := fs.String("secret-file", "", "where the access key's secret is written; a file that exists is refused (required)")
	if err := accessKeyHelp.parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("want two arguments, the server and the code")
	}
	if *secretFile == "" {
		return errors.New("--secret-file is required")
	}
	server := strings.TrimSuffix(fs.Arg(0), "/")
	if err := checkServer(server); err != nil {
		return err
	}
	code, err := accesskey.NormaliseCode(fs.Arg(1))
	if err != nil {
		// NormaliseCode's error can quote a part of the code, which no error contains.
		return errors.New("the code is not an enrolment code: qec_, 26 characters, then a dot and a fingerprint, as Qory Apiary shows it")
	}
	// Everything that can be checked of the secret file is checked before the code is
	// used: once Qory Apiary answers, the code is spent.
	file, err := filepath.Abs(*secretFile)
	if err != nil {
		return fmt.Errorf("the secret file: %w", err)
	}
	if err := checkSecretPath(file); err != nil {
		return err
	}
	if err := checkSecretFile(file); err != nil {
		return err
	}
	name := accessKeyName()
	key, err := generateKey()
	if err != nil {
		return err
	}
	if key.PublicKey().Fixture() {
		return errors.New("the new key is one of the Forager contract's published fixture keys, whose secret anyone can read; no key was kept")
	}
	fingerprint := key.Fingerprint()
	fmt.Fprintf(stderr, "access key fingerprint %s\n", fingerprint)
	req, err := accesskey.NewEnrolmentRequest(key, code, name, time.Now())
	if err != nil {
		return err
	}
	ans, err := req.Post(ctx, enrolClient, server, "qory-github/"+version)
	if err != nil {
		return enrolFailed(err, fingerprint)
	}
	// Only an adapter's key is a work source's: a code for a node, a node pool or a
	// gateway enrolled a key no work source uses, and its secret is not kept.
	if ans.NodeKind != "adapter" {
		return fmt.Errorf("Qory Apiary enrolled the key as %s in the %s %s, which is not a work source: the code was not made on the integration's page; no secret was written: have an owner or administrator in Qory Apiary revoke the key %s, and enrol with a code made on the integration's page in Organisation settings", ans.AccessKeyID, ans.NodeKind, ans.NodeID, fingerprint)
	}
	if ans.Pin.Fixture() {
		return fmt.Errorf("Qory Apiary's answer lists the Forager contract's published fixture key, whose secret anyone can read: it is no server to pin; no secret was written: have an owner or administrator in Qory Apiary revoke the key %s", fingerprint)
	}
	fmt.Fprintf(stderr, "enrolled as %s in the work source %s\n", ans.AccessKeyID, ans.NodeID)
	if err := writeSecretFile(file, []byte(key.Secret()+"\n")); err != nil {
		return fmt.Errorf("the key is enrolled as %s, and %w; the secret was not kept: enrol a key again with a new code, and have an owner or administrator in Qory Apiary revoke the key %s", ans.AccessKeyID, err, fingerprint)
	}
	fmt.Fprintf(stderr, "wrote the access key's secret to %s\n", file)
	fragment, err := enrolledSettings(server, ans.AccessKeyID, file, ans.Pin)
	if err != nil {
		return err
	}
	fmt.Fprintln(stderr, "add these settings to serve's settings:")
	fmt.Fprint(stdout, fragment)
	fmt.Fprintf(stderr, "compare the fingerprint %s with the one Qory Apiary shows on the integration's page; the key is active\n", fingerprint)
	return nil
}

// checkServer takes Qory Apiary's origin, as accesskey's enrolment posts to it: an https
// URL of a host and an optional port, and for a test an http one to localhost,
// 127.0.0.1 or [::1], with nothing after but a slash, which the caller removes. The
// error names the rule, never the URL, which may hold what does not belong in it.
func checkServer(server string) error {
	const shape = "the server is neither an https URL of a host and an optional port nor, for a test, an http one to localhost, 127.0.0.1 or [::1], with nothing after"
	lower := strings.ToLower(server)
	if accesskey.ContainsSecret(server) || strings.Contains(lower, strings.ToLower(accesskey.CodePrefix)) {
		return errors.New(shape)
	}
	u, err := url.Parse(server)
	if err != nil || u.Opaque != "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(server, "#") {
		return errors.New(shape)
	}
	switch h := u.Hostname(); {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1"):
		return nil
	}
	return errors.New(shape)
}

// accessKeyName is the access key's name in Qory Apiary: this machine's host name, or its
// first label when the whole does not fit an access key's name, or else qory-github.
func accessKeyName() string {
	if host, err := hostname(); err == nil {
		if name := accesskey.DefaultName(host); name != "" {
			return name
		}
	}
	return "qory-github"
}

// enrolFailed words an enrolment that got no verified 201, on the refusal's code alone,
// never on an HTTP status: an answer that does not verify may come from anyone on the
// path. Nothing was written, so an enrolment that may have succeeded cannot be finished:
// its key is to be revoked.
func enrolFailed(err error, fingerprint string) error {
	lost := "; no secret was written: get a new code, and have an owner or administrator in Qory Apiary revoke the key " + fingerprint + " should it have been enrolled"
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) {
		return fmt.Errorf("the enrolment did not complete: %w%s", err, lost)
	}
	switch ref.Code {
	case accesskey.CodeUnauthorized:
		return errors.New("this code was used or has expired; if you did not use it, tell your administrator in Qory Apiary, who must revoke the key it enrolled. Enrolling needs a new code")
	case accesskey.CodeKeyInvalid:
		names := ""
		if len(ref.Names) > 0 {
			names = " (" + strings.Join(ref.Names, ", ") + ")"
		}
		return fmt.Errorf("Qory Apiary refused the key%s. Enrolling needs a new code", names)
	case accesskey.CodeKeyLimit:
		return errors.New("the work source already holds two keys: once an owner or administrator in Qory Apiary has revoked one, the same command, run within the code's 15 minutes, succeeds")
	case accesskey.CodeRateLimited:
		return errors.New("Qory Apiary refused the attempt: this code was tried too often; run the same command again later, within the code's 15 minutes")
	case accesskey.CodeAnswerUnsigned:
		return fmt.Errorf("Qory Apiary did not enrol the key (HTTP %d, unsigned)%s", ref.Status, lost)
	}
	return fmt.Errorf("the enrolment did not complete: %w%s", err, lost)
}

// enrolledSettings is what enrol prints for serve's settings: the four members, one per
// line, as they go into the settings' JSON object, with no braces around them.
func enrolledSettings(server, id, file string, pin accesskey.Pin) (string, error) {
	var b strings.Builder
	members := []struct {
		name  string
		value any
	}{
		{"apiary_url", server},
		{"access_key_id", id},
		{"access_key_secret_file", file},
		{"apiary_public_key", pin},
	}
	for i, m := range members {
		v, err := json.Marshal(m.value)
		if err != nil {
			return "", err
		}
		sep := ","
		if i == len(members)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "  %q: %s%s\n", m.name, v, sep)
	}
	return b.String(), nil
}

// checkSecretPath refuses a secret file's absolute path that the settings enrol prints
// cannot contain as it is written, as setup refuses its key file's: one that is not
// UTF-8, or that contains a control character, C0, DEL or C1.
func checkSecretPath(p string) error {
	if !utf8.ValidString(p) {
		return fmt.Errorf("the secret file's path %q is not UTF-8; choose another with --secret-file", p)
	}
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return fmt.Errorf("the secret file's path %q contains a control character; choose another with --secret-file", p)
	}
	return nil
}

// checkSecretFile refuses a secret file that exists, or whose directory does not, before
// the code is used.
func checkSecretFile(file string) error {
	if _, err := os.Lstat(file); err == nil {
		return secretExistsError(file)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the secret file: %w", err)
	}
	// A directory that is a file fails the Lstat above, as not a directory.
	if _, err := os.Stat(filepath.Dir(file)); err != nil {
		return fmt.Errorf("the secret file's directory: %w", err)
	}
	return nil
}

// secretExistsError is a secret file that exists; it matches [fs.ErrExist].
type secretExistsError string

// Error is the file that exists and what to do about it.
func (e secretExistsError) Error() string {
	return "the secret file " + string(e) + " exists; choose another or move it away"
}

// Is matches [fs.ErrExist].
func (e secretExistsError) Is(target error) bool { return target == fs.ErrExist }

// secretFile is the file a secret is written to: an [*os.File], or in a test one whose
// calls fail.
type secretFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// createSecretFile creates the file a secret is written to, 0600, and only where no file
// exists. A test replaces it.
var createSecretFile = func(path string) (secretFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// writeSecretFile writes the access key's secret where only its owner reads it, and never
// over a file that exists, as the App's key file is written: the secret is synced to
// disk before the file is closed, and then, as far as the system allows, so is the
// directory the file is in. A file that could not be written whole, or whose sync
// failed, is removed; a file on a filesystem that cannot sync one, see
// [syncUnsupported], is kept unsynced. No error contains the secret.
func writeSecretFile(path string, secret []byte) error {
	f, err := createSecretFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return secretExistsError(path)
		}
		return fmt.Errorf("the secret file: %w", err)
	}
	if _, err := f.Write(secret); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("the secret file: %w", err)
	}
	if err := f.Sync(); err != nil && !syncUnsupported(err) {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("the secret file could not be synced to disk: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("the secret file: %w", err)
	}
	// The directory's entry for the file is synced too where the system can sync a
	// directory; where it cannot, the file itself is on disk all the same.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// syncUnsupported is whether a file's sync failed because its filesystem cannot sync a
// file, as some FUSE and network filesystems answer: EINVAL, ENOTSUP, EOPNOTSUPP or
// ENOSYS.
func syncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS)
}
