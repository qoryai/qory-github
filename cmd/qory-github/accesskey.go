package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
access_key_secret_file, apiary_public_key and adapter_id.`,
	example: `  qory-github access-key enrol --secret-file /etc/qory-github/access-key-secret https://apiary.example.com "$code"`,
}

// enrol's test seams: the key it makes; the access key's name, from this machine's host
// name; and the client it posts with, nil for accesskey's.
var (
	generateKey = accesskey.Generate
	hostname    = os.Hostname
	enrolClient *http.Client
)

// enrolFlags are enrol's flags: --secret-file, set in secretFile.
func enrolFlags() (fs *flag.FlagSet, secretFile *string) {
	fs = flag.NewFlagSet("access-key enrol", flag.ContinueOnError)
	secretFile = fs.String("secret-file", "", "where the access key's secret is written; a file that exists is refused (required)")
	return fs, secretFile
}

// accessKey runs access-key's one verb, enrol. -h alone prints enrol's help, with its
// flags.
func accessKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && slices.Contains([]string{"-h", "-help", "--h", "--help"}, args[0]) {
		fs, _ := enrolFlags()
		return accessKeyHelp.parse(fs, args, stderr)
	}
	if len(args) == 0 || args[0] != "enrol" {
		return errors.New("access-key has one command, enrol: qory-github access-key enrol --secret-file FILE SERVER CODE")
	}
	return enrol(ctx, args[1:], stdout, stderr)
}

// enrol is access-key enrol. The lines for a person go to stderr, and the settings alone
// to stdout. An error never contains the secret or the code.
func enrol(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, secretFile := enrolFlags()
	if err := accessKeyHelp.parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("want two arguments, the server and the code")
	}
	if *secretFile == "" {
		return errors.New("--secret-file is required")
	}
	// A path that holds what starts a code or a secret, as given or made absolute, is
	// refused before anything else, with an error that does not quote it.
	pathHolds := errors.New("the secret file's path contains what starts an enrolment code or a secret; choose another with --secret-file")
	if hasCodeOrSecret(*secretFile) {
		return pathHolds
	}
	file, err := filepath.Abs(*secretFile)
	if err != nil {
		return fmt.Errorf("the secret file: %w", err)
	}
	if hasCodeOrSecret(file) {
		return pathHolds
	}
	server, err := checkServer(strings.TrimSuffix(fs.Arg(0), "/"))
	if err != nil {
		return err
	}
	code, err := accesskey.NormaliseCode(fs.Arg(1))
	if err != nil {
		// NormaliseCode's error can quote a part of the code, which no error contains.
		return errors.New("the code is not an enrolment code: qec_, 26 characters, then a dot and a fingerprint, as Qory Apiary shows it")
	}
	// The secret file is checked before the code is sent: its path, that no file is
	// there, and that its directory exists and can be written. Qory Apiary's 201 spends
	// the code, and a refusal leaves it as it was, so a secret that cannot be written
	// after the 201 needs a new code.
	if err := checkSecretPath(file); err != nil {
		return err
	}
	if err := checkSecretFile(file); err != nil {
		return err
	}
	if err := checkWritable(filepath.Dir(file)); err != nil {
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
		return enrolFailed(err, server, fingerprint)
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
	fragment, err := enrolledSettings(server, ans.AccessKeyID, file, ans.Pin, ans.NodeID)
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
// 127.0.0.1 or [::1], with nothing after but a slash, which the caller removes. A host
// is taken in ASCII alone, an international name in its xn-- form. It returns the
// origin with its scheme and the ASCII letters of its host in lower case, an IPv6
// zone kept as it is, as the settings hold it. The error names the rule, never the
// URL, which may hold what does not belong in it, and so is the origin refused when,
// in lower case, it holds what starts a code or a secret.
func checkServer(server string) (string, error) {
	shape := errors.New("the server is neither an https URL of a host and an optional port nor, for a test, an http one to localhost, 127.0.0.1 or [::1], with nothing after")
	if hasCodeOrSecret(server) {
		return "", shape
	}
	u, err := url.Parse(server)
	if err != nil || u.Opaque != "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(server, "#") {
		return "", shape
	}
	for i := 0; i < len(u.Host); i++ {
		if u.Host[i] >= utf8.RuneSelf {
			return "", errors.New("the server's host holds a character that is not ASCII; give an international name in its ASCII form, xn--")
		}
	}
	// url.Parse has the scheme in lower case already.
	origin := (&url.URL{Scheme: u.Scheme, Host: lowerHost(u.Host)}).String()
	if hasCodeOrSecret(origin) {
		return "", shape
	}
	if !hostShape(u.Host) {
		return "", shape
	}
	switch h := strings.ToLower(u.Hostname()); {
	case u.Scheme == "https":
		return origin, nil
	case u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1"):
		return origin, nil
	}
	return "", shape
}

// zoneShape is an IPv6 zone, the name of an interface.
var zoneShape = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// hostShape reports whether host, as url.Parse decodes it, is a host and an optional
// port: a name or an IPv4 address of letters, digits, dots and dashes, or an IPv6
// address in brackets with an optional zone of the same and underscores; and, after a
// colon, a port from 1 to 65535 written as Go writes the number.
func hostShape(host string) bool {
	name, port := host, ""
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		name, port = host[:i], host[i+1:]
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if strings.HasPrefix(name, "[") {
		addr, ok := strings.CutSuffix(name[1:], "]")
		if !ok {
			return false
		}
		if a, zone, found := strings.Cut(addr, "%"); found {
			if !zoneShape.MatchString(zone) {
				return false
			}
			addr = a
		}
		ip := net.ParseIP(addr)
		return ip != nil && strings.Contains(addr, ":")
	}
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// lowerHost is an ASCII host with its letters in lower case, but for the zone of an
// IPv6 address, from its % to its ], which names an interface as the system spells it.
func lowerHost(host string) string {
	b := []byte(host)
	zone := false
	for i, c := range b {
		switch {
		case c == '%' && strings.HasPrefix(host, "["):
			zone = true
		case c == ']':
			zone = false
		case !zone && 'A' <= c && c <= 'Z':
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// hasCodeOrSecret reports whether a value holds what starts an enrolment code, qec_, an
// access key secret, qak_, or a run key, qrk_, in any case.
func hasCodeOrSecret(v string) bool {
	return accesskey.ContainsSecret(v) || strings.Contains(strings.ToLower(v), strings.ToLower(accesskey.CodePrefix))
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
// path, and so may a 401, which is never signed, so its text names Qory Apiary's
// reasons beside a refusal by another server on the way. A verified refusal leaves the code as it was, so the same command can use it
// again. Nothing was written, so an enrolment that may have succeeded behind an answer
// that did not verify cannot be finished: its key is to be revoked.
func enrolFailed(err error, server, fingerprint string) error {
	lost := "; no secret was written: get a new code, and have an owner or administrator in Qory Apiary revoke the key " + fingerprint + " should it have been enrolled"
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) {
		return fmt.Errorf("the enrolment did not complete: %w%s", err, lost)
	}
	switch ref.Code {
	case accesskey.CodeUnauthorized:
		// Qory Apiary answers every code it does not accept with one 401, whatever the
		// reason, and anything on the path can answer one too; only a used code has
		// enrolled a key.
		return fmt.Errorf("the server at %s answered 401: Qory Apiary answers so when the code was used, has expired or was cancelled, is no code of the Qory Apiary at %s, or its record fails Qory Apiary's integrity check; when its maker can no longer make codes; when what the code was made for was deleted, its workspace or organisation is marked for deletion, or its organisation is not in use; when Qory Apiary has the feature factory off; or when this machine's clock is more than 5 minutes off. Something in front of Qory Apiary, or a server that is not Qory Apiary, may also have refused the request. If the code was used and not by you, tell an owner or administrator in Qory Apiary, who must revoke the key it enrolled", server, server)
	case accesskey.CodeKeyInvalid:
		names := ""
		if len(ref.Names) > 0 {
			names = " (" + strings.Join(ref.Names, ", ") + ")"
		}
		return fmt.Errorf("Qory Apiary refused the key%s; the code is not used: the same command, run within the code's 15 minutes, makes a new key", names)
	case accesskey.CodeKeyLimit:
		return errors.New("the work source already holds two keys: have an owner or administrator in Qory Apiary revoke one, then run the same command again within the code's 15 minutes")
	case accesskey.CodeRateLimited:
		return errors.New("Qory Apiary refused the attempt: this code was tried too often; run the same command again later, within the code's 15 minutes")
	case accesskey.CodeAnswerUnsigned:
		return fmt.Errorf("Qory Apiary's answer did not verify (HTTP %d)%s", ref.Status, lost)
	}
	return fmt.Errorf("the enrolment did not complete: %w%s", err, lost)
}

// enrolledSettings is what enrol prints for serve's settings: the five members, one per
// line, as they go into the settings' JSON object, with no braces around them.
// adapter_id is the work source the key is enrolled in, which a connect pass names.
func enrolledSettings(server, id, file string, pin accesskey.Pin, adapter string) (string, error) {
	var b strings.Builder
	members := []struct {
		name  string
		value any
	}{
		{"apiary_url", server},
		{"access_key_id", id},
		{"access_key_secret_file", file},
		{"apiary_public_key", pin},
		{"adapter_id", adapter},
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

// removeProbe removes checkWritable's probe file. A test replaces it.
var removeProbe = os.Remove

// checkWritable refuses a directory the secret file cannot be created in, by creating a
// file of a random name there, only where none exists, and removing it. A probe that
// cannot be closed or removed is refused too, and the error names it, so none is left
// behind unsaid.
func checkWritable(dir string) error {
	b := make([]byte, 8)
	rand.Read(b)
	probe := filepath.Join(dir, ".qory-github-"+hex.EncodeToString(b))
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("the secret file's directory %s cannot be written: %w", dir, cause(err))
	}
	closeErr := f.Close()
	if err := removeProbe(probe); err != nil {
		return fmt.Errorf("the secret file's directory %s: the file %s made to check it can be written could not be removed: %w", dir, probe, cause(err))
	}
	if closeErr != nil {
		return fmt.Errorf("the secret file's directory %s cannot be written: %w", dir, cause(closeErr))
	}
	return nil
}

// cause is the error of the [*fs.PathError] err is, if it is one, without its path.
func cause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
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
