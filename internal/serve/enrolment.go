package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/enrol"
	"github.com/qoryai/qory-github/internal/ownerfile"
	"github.com/qoryai/qory-github/internal/store"
)

// The files of the enrolment serve keeps in the state directory, each 0600 and the
// user's that serve runs as, in the directory [ownerfile.Dir] keeps 0700:
// enrolmentFile holds Qory Apiary's answer, the access key's id, the adapter's id and
// the pin, and accessKeyFile the key's secret. pendingKeyFile holds the secret of a key
// made for an enrolment that has not finished, and enrolmentTemp enrolmentFile while it
// is written, before it is renamed into place.
const (
	enrolmentFile  = "enrolment.json"
	enrolmentTemp  = "enrolment.json.tmp"
	accessKeyFile  = "access-key"
	pendingKeyFile = "access-key.pending"
)

// maxEnrolmentFile is the most enrolmentFile may hold; one byte more is read to tell a
// larger file apart. What serve writes there is far shorter.
const maxEnrolmentFile = 64 << 10

// maxCodeFile is the most the enrolment code file may hold; one byte more is read to
// tell a larger file apart. A code is under a hundred characters.
const maxCodeFile = 4 << 10

// The waits of an enrolment at first start: the code file is read every enrolPoll
// while it does not exist, or holds a code Qory Apiary refused, until its content
// changes; an attempt that got no verified answer is tried again after enrolBackoff,
// doubled after each such attempt up to enrolBackoffMax; and each attempt waits
// enrolTimeout at most for Qory Apiary's answer.
const (
	enrolPoll       = 5 * time.Second
	enrolBackoff    = 2 * time.Second
	enrolBackoffMax = time.Minute
	enrolTimeout    = 10 * time.Second
)

// AdapterKind is what serve and qory-github-server's access-key enrol enrol: an
// adapter's key, which they call an integration's, and the words the errors of
// [enrol.Kind.CheckCode] and [enrol.Kind.Post] name it with. A code for a node, a node
// pool or a gateway is refused. programVersion is the program's version, which the
// enrolment request's User-Agent carries. The kind has no help, which access-key enrol
// adds.
func AdapterKind(programVersion string) enrol.Kind {
	return enrol.Kind{
		Program:   "qory-github-server",
		NodeKind:  "adapter",
		Noun:      "integration",
		ANoun:     "an integration",
		Tab:       "the adapter's Access key tab",
		TabIn:     "the adapter's Access key tab in Instance settings",
		Admin:     "an instance admin of Qory Apiary",
		Settings:  "serve's settings",
		IDMember:  "adapter_id",
		UserAgent: "qory-github/" + programVersion,
	}
}

// enrolment is the adapter's enrolment in Qory Apiary, from the settings or from the
// state directory: the access key's id and the key, the pin and the adapter's id.
type enrolment struct {
	keyID     string
	key       *accesskey.Key
	pin       accesskey.Pin
	adapterID string
}

// credentials hold the enrolment every request to Qory Apiary is signed with, and every
// answer and connect pass checked under: a re-enrolment replaces it whole, see
// [reenroller], and the requests that follow use the new one. It is safe for
// concurrent use.
type credentials struct {
	mu sync.RWMutex
	e  enrolment
}

// get is the enrolment in use.
func (c *credentials) get() enrolment {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.e
}

// set replaces the enrolment in use with e.
func (c *credentials) set(e enrolment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.e = e
}

// keptEnrolment is enrolmentFile's JSON: Qory Apiary's answer to the enrolment, as
// serve keeps it, and the fingerprint of the key it enrolled, which tells which of
// accessKeyFile and pendingKeyFile holds that key after a crash, see [loadKept].
type keptEnrolment struct {
	AccessKeyID     string          `json:"access_key_id"`
	AdapterID       string          `json:"adapter_id"`
	ApiaryPublicKey json.RawMessage `json:"apiary_public_key"`
	Fingerprint     string          `json:"fingerprint"`
}

// fingerprintShape is an access key's fingerprint, 16 bytes in base64url without
// padding, as [accesskey.PublicKey.Fingerprint] writes it.
var fingerprintShape = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// hasKeptEnrolment reports whether the state directory dir holds an enrolment file, or
// something at its name that [loadKept] then reads, and refuses when it is no such
// file. It makes nothing.
func hasKeptEnrolment(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, enrolmentFile))
	return !errors.Is(err, fs.ErrNotExist)
}

// checkEnrolmentSource refuses settings that give no enrolment in Qory Apiary when the
// state directory holds none either and no enrolment code file is set, so serve has no
// way to one. It makes nothing, the state directory included.
func (s Settings) checkEnrolmentSource() error {
	if s.GivesEnrolment() || s.EnrolmentCodeFile != "" || hasKeptEnrolment(s.StateDir) {
		return nil
	}
	src := source{s.env}
	m := missingIn(groups[0], func(string) bool { return false })
	listed := make([]string, len(m))
	for i, name := range m {
		listed[i] = src.listed(name)
	}
	return fmt.Errorf("%s give no enrolment in Qory Apiary, the state directory holds none, and %s is not set: give %s, or set %s for serve to enrol at its first start", src.what(), src.name("enrolment_code_file"), strings.Join(listed, ", "), src.name("enrolment_code_file"))
}

// enrolmentOf is the adapter's enrolment when the settings give none: the one kept in
// the state directory, see [loadKept], or else a new one, which serve makes with the
// code in the file enrolment_code_file names, see [enroller.run]. The code file is
// never read here when the state directory holds an enrolment. It returns too, when
// enrolment_code_file is set, the enroller that a [reenroller] looks at the code file
// with from then on, which skips the code this start enrolled with. The state
// directory is open, and checked, as [store.Open] opens it. An error that ctx is done
// is ctx's.
func (s Settings) enrolmentOf(ctx context.Context, opts Options, log *slog.Logger) (enrolment, *enroller, error) {
	var e *enroller
	if s.EnrolmentCodeFile != "" {
		server, err := enrol.CheckServer(s.ApiaryURL)
		if err != nil {
			return enrolment{}, nil, err
		}
		e = &enroller{
			kind: AdapterKind(opts.ProgramVersion), server: server, codeFile: s.EnrolmentCodeFile,
			dir: s.StateDir, log: log, wait: opts.enrolWait, transport: opts.enrolTransport,
		}
		if e.wait == nil {
			e.wait = wait
		}
		if e.transport == nil {
			e.transport = http.DefaultTransport
		}
	}
	if hasKeptEnrolment(s.StateDir) {
		got, err := loadKept(s.StateDir, log)
		if e != nil {
			e.again = true
		}
		return got, e, err
	}
	got, err := e.run(ctx)
	e.again = true
	return got, e, err
}

// wait waits d, or until ctx is done, and then returns ctx's error.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// staleKey is the line of a pending key an enrolment that did not finish left, which
// serve drops: Qory Apiary may have enrolled it before the enrolment stopped.
const staleKey = "a key from an enrolment that did not finish is dropped: should Qory Apiary list it, have an instance admin of Qory Apiary revoke it"

// loadKept reads the enrolment kept in the state directory dir: enrolmentFile, read as
// [ownerfile.ReadFile] reads a file, and the key whose fingerprint it names, in
// accessKeyFile, read as the access key secret's file is. It resolves what a crash
// during an enrolment, at first start or a re-enrolment, can leave, since enrolmentFile
// is written, through enrolmentTemp, only after Qory Apiary's 201 to the key in
// pendingKeyFile, and that key renamed onto accessKeyFile only after that:
//   - enrolmentTemp is a write that did not finish, and is removed;
//   - accessKeyFile holds the named key: a pendingKeyFile beside it is a key an
//     enrolment that did not finish made, which is dropped, its fingerprint logged on
//     log;
//   - pendingKeyFile holds the named key: the rename did not happen, and it is made
//     now, over the key accessKeyFile holds, if any;
//   - neither holds it: an error.
func loadKept(dir string, log *slog.Logger) (enrolment, error) {
	path := filepath.Join(dir, enrolmentFile)
	b, err := ownerfile.ReadFile(path, maxEnrolmentFile, "the enrolment file", "an enrolment")
	if err != nil {
		return enrolment{}, err
	}
	shape := fmt.Errorf("the enrolment file %s does not hold access_key_id, adapter_id, apiary_public_key and fingerprint as serve writes them", path)
	var doc keptEnrolment
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return enrolment{}, shape
	}
	p, err := pin(doc.ApiaryPublicKey)
	if err != nil || accesskey.CheckID(doc.AccessKeyID) != nil || !adapterIDShape.MatchString(doc.AdapterID) || !fingerprintShape.MatchString(doc.Fingerprint) {
		return enrolment{}, shape
	}
	if err := os.Remove(filepath.Join(dir, enrolmentTemp)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return enrolment{}, fmt.Errorf("the state directory: %w", err)
	}
	keyPath, pendingPath := filepath.Join(dir, accessKeyFile), filepath.Join(dir, pendingKeyFile)
	var key *accesskey.Key
	if _, err := os.Lstat(keyPath); !errors.Is(err, fs.ErrNotExist) {
		if key, err = keptKey(keyPath); err != nil {
			return enrolment{}, err
		}
	}
	pending, pendingThere := readPending(pendingPath)
	switch {
	case key != nil && key.Fingerprint() == doc.Fingerprint:
		if pendingThere {
			if pending != nil {
				log.Warn(staleKey, slog.String("fingerprint", pending.Fingerprint()))
			}
			if err := os.Remove(pendingPath); err != nil {
				return enrolment{}, fmt.Errorf("the state directory: %w", err)
			}
		}
	case pending != nil && pending.Fingerprint() == doc.Fingerprint:
		if err := rename(pendingPath, keyPath); err != nil {
			return enrolment{}, fmt.Errorf("the state directory: the enrolled key could not be moved to %s: %w", accessKeyFile, err)
		}
		syncDir(dir)
		if key, err = keptKey(keyPath); err != nil {
			return enrolment{}, err
		}
	default:
		return enrolment{}, fmt.Errorf("the enrolment file %s names the key %s, which neither %s nor %s in the state directory holds", path, doc.Fingerprint, accessKeyFile, pendingKeyFile)
	}
	return enrolment{keyID: doc.AccessKeyID, key: key, pin: p, adapterID: doc.AdapterID}, nil
}

// keptKey reads the access key in the file at path in the state directory, as the
// access key secret's file is read.
func keptKey(path string) (*accesskey.Key, error) {
	return secretSource{file: path, in: "the file " + filepath.Base(path) + " in the state directory"}.accessKey()
}

// readPending reads the key in pendingKeyFile at path, and whether a file is there: a
// file that cannot be read as a key the user's that serve runs as, or holds no key, is
// there with no key.
func readPending(path string) (*accesskey.Key, bool) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	b, err := ownerfile.ReadFile(path, maxAccessKeyFile, "the pending access key file", "an access key secret")
	if err != nil {
		return nil, true
	}
	k, err := accesskey.ParseSecret(string(trimLineBreak(b)))
	if err != nil {
		return nil, true
	}
	return k, true
}

// enroller enrols the adapter with the code in the code file, and keeps the key and
// Qory Apiary's answer in the state directory: at first start, until it is enrolled,
// and, once again is set, at each look a [reenroller] makes, beside the enrolment in
// use.
type enroller struct {
	kind     enrol.Kind
	server   string
	codeFile string
	dir      string
	log      *slog.Logger
	// wait waits between the attempts, as [wait] does, and transport carries the
	// enrolment requests.
	wait      func(context.Context, time.Duration) error
	transport http.RoundTripper
	// again is whether the adapter is enrolled already, so a look ends where a first
	// start waits, see [enroller.run]. refused is the code file's content last refused,
	// or used by the enrolment that succeeded, which is not tried again.
	again   bool
	refused []byte
}

// codeFileName names the code file in a line or an error: by its setting, never its
// path.
const codeFileName = "the file enrolment_code_file names"

// errNoEnrolment is a re-enrolment's look that found no code to enrol with, or one
// tried already, or ended without an enrolment for a reason it logged.
var errNoEnrolment = errors.New("no new enrolment")

// after is what the line of a refused code says follows: at first start, a wait for a
// new code; once enrolled, the key in use stays until the next look.
func (e *enroller) after() string {
	if e.again {
		return "; the key in use stays, and serve looks at " + codeFileName + " again when Qory Apiary next answers a request 401"
	}
	return "; waiting for a new code in " + codeFileName
}

// run enrols the adapter, and returns its enrolment once it is kept.
//
// At first start, it refuses a state directory that holds an access key but no
// enrolment file, before anything is sent, and replaces a pending key a crashed
// attempt left, logging its fingerprint, since Qory Apiary may have enrolled it. Then,
// until it is enrolled or ctx is done:
//   - it reads the code file with a bounded read, every [enrolPoll] while it does not
//     exist, with one line for the wait;
//   - it takes the code, one line with its line break trimmed, only when it is an
//     adapter's, and otherwise waits for the file's content to change;
//   - it makes a key, written to pendingKeyFile before it is sent, and posts the
//     enrolment to Qory Apiary.
//
// On Qory Apiary's 201 it keeps the enrolment, see [enroller.keep]. A 401, a code that
// was used, has expired or was cancelled, a signed 409 key_limit, and a 201 for another
// kind of key, are logged once, and the file's content must change before the next
// attempt. A signed 409 key_invalid is tried again with a new key; a signed 429 after
// its Retry-After, held to between [minRetryAfter] and [maxRetryAfter], or, without
// one serve can read, as the next outcome; and every other outcome, an error of the
// network or an answer that did not verify among them, after a wait that doubles from
// [enrolBackoff] to [enrolBackoffMax]. When the file goes away after an attempt that
// got no verified answer, the pending key is dropped and its fingerprint logged: Qory
// Apiary deletes the code once an enrolment makes a key live, which may be that key.
//
// Once again is set, the enrolment in use stays untouched until the 201: where a first
// start waits, for a file that does not exist, cannot be read or holds the content
// refused or used last, run drops its pending key and ends with [errNoEnrolment],
// which the next look follows; the tries again after key_invalid, a 429 or no verified
// answer are made as at first start, while the file is there. The code and the key's
// secret are never in a line or an error.
func (e *enroller) run(ctx context.Context) (enrolment, error) {
	if !e.again {
		if _, err := os.Lstat(filepath.Join(e.dir, accessKeyFile)); err == nil {
			return enrolment{}, fmt.Errorf("the state directory holds an access key, %s, but no %s, which names it in Qory Apiary; move %s away for serve to enrol a new key", accessKeyFile, enrolmentFile, accessKeyFile)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return enrolment{}, fmt.Errorf("the state directory: %w", err)
		}
		if err := e.dropStale(); err != nil {
			return enrolment{}, err
		}
	}
	var (
		key       *accesskey.Key
		uncertain bool
		missing   bool
		problem   string
		backoff   = enrolBackoff
	)
	next := func() time.Duration {
		d := backoff
		backoff = min(2*backoff, enrolBackoffMax)
		return d
	}
	// drop removes the pending key, and logs its fingerprint when the last attempt with
	// it got no verified answer, so Qory Apiary may have enrolled it.
	drop := func() {
		if key == nil {
			return
		}
		if uncertain {
			e.log.Warn(staleKey, slog.String("fingerprint", key.Fingerprint()))
		}
		os.Remove(filepath.Join(e.dir, pendingKeyFile))
		key, uncertain = nil, false
	}
	// stop is what a look does where a first start waits: it drops the pending key and
	// ends.
	stop := func() (enrolment, error) {
		drop()
		return enrolment{}, errNoEnrolment
	}
	for {
		raw, err := readCodeFile(e.codeFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if uncertain {
				drop()
			}
			if e.again {
				return stop()
			}
			if !missing {
				e.log.Info("waiting for an enrolment code: " + codeFileName + " does not exist yet")
				missing = true
			}
			if err := e.wait(ctx, enrolPoll); err != nil {
				return enrolment{}, err
			}
			continue
		case err != nil:
			if err.Error() != problem {
				then := "; waiting for it"
				if e.again {
					then = e.after()
				}
				e.log.Warn("the enrolment code cannot be read"+then, slog.String("error", err.Error()))
				problem = err.Error()
			}
			if e.again {
				return stop()
			}
			if err := e.wait(ctx, enrolPoll); err != nil {
				return enrolment{}, err
			}
			continue
		}
		missing, problem = false, ""
		if e.refused != nil && bytes.Equal(raw, e.refused) {
			if e.again {
				return stop()
			}
			if err := e.wait(ctx, enrolPoll); err != nil {
				return enrolment{}, err
			}
			continue
		}
		e.refused = nil
		code, err := e.kind.CheckCode(string(trimLineBreak(raw)))
		if err != nil {
			e.log.Warn(codeFileName+" holds no enrolment code of an adapter"+e.after(), slog.String("error", err.Error()))
			e.refused = raw
			continue
		}
		if key == nil {
			if key, err = e.newPending(); err != nil {
				return enrolment{}, err
			}
		}
		rec := &retryAfterRecorder{base: e.transport}
		ans, err := e.kind.Post(ctx, enrol.Seams{Client: &http.Client{Timeout: enrolTimeout, Transport: rec}}, e.server, code, key)
		if err == nil {
			got, err := e.keep(ans, key)
			e.refused = raw
			return got, err
		}
		if ctx.Err() != nil {
			return enrolment{}, ctx.Err()
		}
		wasUncertain := uncertain
		uncertain = false
		fingerprint := slog.String("fingerprint", key.Fingerprint())
		var failed *enrol.Error
		var ref *accesskey.Refusal
		errors.As(err, &failed)
		errors.As(err, &ref)
		var d time.Duration
		switch {
		case failed != nil && failed.Enrolled:
			e.refused, backoff = raw, enrolBackoff
			e.logEnrolledElsewhere(failed, key)
			key, uncertain = nil, false
			continue
		case ref != nil && ref.Code == accesskey.CodeUnauthorized:
			e.log.Warn("Qory Apiary, or something in front of it, refused the enrolment code with a 401, as Qory Apiary answers a code that was used, has expired or was cancelled" + e.after())
			e.refused, backoff, uncertain = raw, enrolBackoff, wasUncertain
			continue
		case ref != nil && ref.Code == accesskey.CodeKeyLimit:
			e.log.Error("the adapter already holds two keys in Qory Apiary: have an instance admin of Qory Apiary revoke one" + e.after())
			e.refused, backoff, uncertain = raw, enrolBackoff, wasUncertain
			continue
		case ref != nil && ref.Code == accesskey.CodeKeyInvalid:
			d = next()
			e.log.Warn("Qory Apiary refused the key; trying again with a new key", slog.Any("names", ref.Names), fingerprint, slog.Duration("retry_in", d))
			uncertain = wasUncertain
			drop()
		case ref != nil && ref.Code == accesskey.CodeRateLimited:
			uncertain = wasUncertain
			asked, read := askedWait(rec.get(), time.Now())
			switch {
			case !read:
				d = next()
				e.log.Warn("Qory Apiary refused the attempt: the code was tried too often, and it asked for no wait serve can read; trying again after a wait that doubles", slog.Duration("retry_in", d))
			case asked < minRetryAfter || asked > maxRetryAfter:
				d = min(max(asked, minRetryAfter), maxRetryAfter)
				e.log.Warn("Qory Apiary refused the attempt: the code was tried too often; trying again after the wait it asked for, held to between a second and an hour", slog.Duration("retry_in", d))
			default:
				d = asked
				e.log.Warn("Qory Apiary refused the attempt: the code was tried too often; trying again after the wait it asked for", slog.Duration("retry_in", d))
			}
		default:
			cause := err
			if failed != nil && failed.Cause != nil {
				cause = failed.Cause
			}
			d = next()
			uncertain = true
			e.log.Warn("the enrolment did not complete; trying again", slog.String("error", cause.Error()), slog.Duration("retry_in", d))
		}
		if err := e.wait(ctx, d); err != nil {
			return enrolment{}, err
		}
	}
}

// askedWait reads Retry-After, v, as seconds or an HTTP date, and reports whether it
// read a wait: none for an empty or unreadable v. The wait is as v gives it, not held
// to [minRetryAfter] and [maxRetryAfter].
func askedWait(v string, now time.Time) (time.Duration, bool) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		return time.Duration(min(n, int64(math.MaxInt64/time.Second))) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}

// logEnrolledElsewhere removes the pending key's file, which holds key, and logs the
// verified 201 failed reports, which enrolled key in a way serve does not use: for
// another kind of node than an adapter, or with a pin that lists a published fixture
// key. The line names the 201's access key id and node, and key's fingerprint, says
// whether the key's secret was removed from the state directory, and asks for the
// key's revoke. It never holds the code or the secret.
func (e *enroller) logEnrolledElsewhere(failed *enrol.Error, key *accesskey.Key) {
	removed := "its secret is removed from the state directory"
	attrs := []any{slog.String("access_key_id", failed.AccessKeyID), slog.String("node_kind", failed.NodeKind), slog.String("node_id", failed.NodeID), slog.String("fingerprint", key.Fingerprint())}
	if err := os.Remove(filepath.Join(e.dir, pendingKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		removed = "its secret could not be removed from " + pendingKeyFile + " in the state directory, which still holds it"
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	why := "for a node of another kind than an adapter"
	if failed.FixturePin {
		why = "with an answer whose pin lists a published fixture key, whose secret anyone can read"
	}
	e.log.Error("Qory Apiary enrolled the key "+why+", so serve does not use it: "+removed+"; have an instance admin of Qory Apiary revoke the key"+e.after(), attrs...)
}

// dropStale removes what an attempt at first start that did not finish left in the
// state directory: enrolmentTemp, and pendingKeyFile, whose key's fingerprint it logs
// when it reads one, since Qory Apiary may have enrolled it before the attempt
// stopped.
func (e *enroller) dropStale() error {
	if err := os.Remove(filepath.Join(e.dir, enrolmentTemp)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the state directory: %w", err)
	}
	path := filepath.Join(e.dir, pendingKeyFile)
	k, there := readPending(path)
	if !there {
		return nil
	}
	if k != nil {
		e.log.Warn(staleKey, slog.String("fingerprint", k.Fingerprint()))
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("the state directory: %w", err)
	}
	return nil
}

// newPending makes a new key, as [enrol.NewKey] makes one, and writes its secret to
// pendingKeyFile, beside accessKeyFile, in place of a pending key there.
func (e *enroller) newPending() (*accesskey.Key, error) {
	path := filepath.Join(e.dir, pendingKeyFile)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("the state directory: %w", err)
	}
	key, err := enrol.NewKey(enrol.Seams{})
	if err != nil {
		return nil, err
	}
	if err := writeNew(path, []byte(key.Secret()+"\n"), "the pending access key file"); err != nil {
		return nil, err
	}
	return key, nil
}

// errNotMoved is a re-enrolment whose enrolment file names the new key, which could
// not be renamed onto accessKeyFile: the new enrolment is in use, and the next look,
// or the next start, makes the rename, see [loadKept].
type errNotMoved struct{ err error }

func (e errNotMoved) Error() string {
	return fmt.Sprintf("the enrolment is kept in %s, and its key could not be moved from %s to %s: %v; the next start moves it", enrolmentFile, pendingKeyFile, accessKeyFile, e.err)
}

// errNotKept is a 201 whose enrolment could not be kept in the state directory: the
// key is enrolled in Qory Apiary, and serve does not use it. In a re-enrolment, the
// enrolment in use and its files stay as they were.
type errNotKept struct{ err error }

func (e errNotKept) Error() string { return e.err.Error() }

// errNotReadBack is an enrolment whose files are both in place, enrolmentFile naming
// the new key in accessKeyFile, which could not be read back as a start reads them,
// see [loadKept]: the next start reads those files, so a re-enrolment puts the new
// enrolment in use.
type errNotReadBack struct{ err error }

func (e errNotReadBack) Error() string {
	return fmt.Sprintf("the enrolment is kept in %s and its key in %s, but could not be read back: %v", enrolmentFile, accessKeyFile, e.err)
}

// keep keeps Qory Apiary's 201 to the enrolment of key: it writes enrolmentFile through
// enrolmentTemp, renamed into place over the enrolment there, if any, then renames
// pendingKeyFile onto accessKeyFile, over the key there, if any, which is so dropped
// last, syncing the directory after each rename, so a start finds the one enrolment or
// the other whole, see [loadKept]. At first start it logs the enrolment. It returns the
// enrolment as loadKept reads it back. An error before the enrolment file is in
// place is an [errNotKept]; a rename of the key that fails after it is an
// [errNotMoved], and a read back that fails after both renames an [errNotReadBack],
// these two with the new enrolment.
func (e *enroller) keep(ans *accesskey.EnrolmentAnswer, key *accesskey.Key) (enrolment, error) {
	fingerprint := key.Fingerprint()
	lost := func(err error) error {
		then := ", and start serve with a new code"
		if e.again {
			os.Remove(filepath.Join(e.dir, pendingKeyFile))
			then = ""
		}
		return errNotKept{fmt.Errorf("the key %s is enrolled as %s in the adapter %s, and could not be kept in the state directory: %w; have an instance admin of Qory Apiary revoke it%s", fingerprint, ans.AccessKeyID, ans.NodeID, err, then)}
	}
	pinJSON, err := json.Marshal(ans.Pin)
	if err != nil {
		return enrolment{}, lost(err)
	}
	b, err := json.MarshalIndent(keptEnrolment{AccessKeyID: ans.AccessKeyID, AdapterID: ans.NodeID, ApiaryPublicKey: pinJSON, Fingerprint: fingerprint}, "", "  ")
	if err != nil {
		return enrolment{}, lost(err)
	}
	temp, final := filepath.Join(e.dir, enrolmentTemp), filepath.Join(e.dir, enrolmentFile)
	os.Remove(temp)
	if err := writeNew(temp, append(b, '\n'), "the enrolment file"); err != nil {
		return enrolment{}, lost(err)
	}
	if err := rename(temp, final); err != nil {
		os.Remove(temp)
		return enrolment{}, lost(err)
	}
	syncDir(e.dir)
	written := enrolment{keyID: ans.AccessKeyID, key: key, pin: ans.Pin, adapterID: ans.NodeID}
	if err := rename(filepath.Join(e.dir, pendingKeyFile), filepath.Join(e.dir, accessKeyFile)); err != nil {
		return written, errNotMoved{err}
	}
	syncDir(e.dir)
	if !e.again {
		e.log.Info("enrolled in Qory Apiary", slog.String("access_key_id", ans.AccessKeyID), slog.String("adapter_id", ans.NodeID), slog.String("fingerprint", fingerprint))
	}
	got, err := readBack(e.dir, e.log)
	if err != nil {
		return written, errNotReadBack{err}
	}
	return got, nil
}

// readBack reads the enrolment keep wrote back, as a start reads it: [loadKept], or in
// a test a read that fails.
var readBack = loadKept

// rename renames the enrolment file and the pending key into place, in keep and in
// [loadKept]: [os.Rename], or in a test a rename that fails.
var rename = os.Rename

// reenrolDebounce is how long a look at the code file waits after the 401 that asked
// for it, so the 401s of a burst, one for each request under way, ask for one look.
const reenrolDebounce = 5 * time.Second

// reenroller enrols a new key beside the one in use, for an adapter whose enrolment is
// kept in the state directory and whose settings set enrolment_code_file. Qory Apiary,
// installed with the adapter, writes the code file only while the adapter holds no
// live key, and deletes it once a key is live: in the request that makes the key
// live, or, failing that, at a check it makes every few seconds. So a code there says
// the adapter holds no live key, as after its keys were revoked, but for the code
// serve enrolled with last, which Qory Apiary may not have deleted yet, and which a
// look never tries again. reenroller looks at the file at start, and after each 401
// Qory Apiary answers a request with, which itself changes no state; it never looks
// otherwise. A look that finds a code, not one tried already, enrols a new key as
// [enroller.run] does once enrolled, and, after Qory Apiary's 201, replaces the
// enrolment in creds, which every request to Qory Apiary and every connect pass then
// uses. One look runs at a time, beside serving, which goes on with the enrolment in
// use until the 201. There is no other way to replace the key: Qory Apiary's revoke
// is the rotation.
type reenroller struct {
	e     *enroller
	creds *credentials
	log   *slog.Logger
	kick  chan struct{}
	// notMoved is whether the enrolment in use is the one enrolmentFile names while its
	// key is still in pendingKeyFile, see [errNotMoved]: the next look moves it before
	// anything else, and makes no pending key over it.
	notMoved bool
	// inUse, when set, puts a new enrolment in use, see [Run]: in another adapter
	// record than the one in use, it drops what the store holds for the old record,
	// see [ownState], and returns that drop's error, and it puts the enrolment in use
	// whatever the error; then the adapter is declared again under it. Without it,
	// the enrolment is put in creds alone.
	inUse func(enrolment) error
}

// newReenroller is the reenroller that looks with e, which skips the code the first
// start enrolled with, and replaces the enrolment in creds.
func newReenroller(e *enroller, creds *credentials, log *slog.Logger) *reenroller {
	return &reenroller{e: e, creds: creds, log: log, kick: make(chan struct{}, 1)}
}

// refused asks for a look at the code file, after a 401. It never waits: asks made
// while one is waiting are one.
func (r *reenroller) refused() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// run looks at the code file once, then after each ask, [reenrolDebounce] after it, the
// asks made meanwhile taken as one, until ctx is done.
func (r *reenroller) run(ctx context.Context) {
	r.look(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.kick:
		}
		if r.e.wait(ctx, reenrolDebounce) != nil {
			return
		}
		select {
		case <-r.kick:
		default:
		}
		r.look(ctx)
	}
}

// look enrols a new key with the code in the code file, if there is one not tried
// already, and puts the new enrolment in use once it is kept.
//
// After an [errNotMoved], the look first moves the key in use from pendingKeyFile onto
// accessKeyFile, as a start does, see [loadKept], and looks at the code file only once
// that is done, so the only copy on disk of the key in use is never removed.
func (r *reenroller) look(ctx context.Context) {
	if r.notMoved {
		if _, err := loadKept(r.e.dir, r.log); err != nil {
			// While notMoved is set nothing makes a pending key, and each of loadKept's
			// moves removes it, so a file there is the key in use, whatever it reads as.
			if _, there := readPending(filepath.Join(r.e.dir, pendingKeyFile)); there {
				r.log.Error("the key in use is still not in its file; serve tries again at the next look, and looks for no code until then", slog.String("error", err.Error()))
			} else {
				r.log.Error("the key in use was moved into its file, but the state directory could not be read back as a start reads it; serve tries again at the next look, and looks for no code until then", slog.String("error", err.Error()))
			}
			return
		}
		r.notMoved = false
		r.log.Info("the key in use is now in its file, in place of the old one, dropped", slog.String("fingerprint", r.creds.get().key.Fingerprint()))
	}
	old := r.creds.get()
	got, err := r.e.run(ctx)
	attrs := func() []any {
		return []any{slog.String("access_key_id", got.keyID), slog.String("adapter_id", got.adapterID), slog.String("fingerprint", got.key.Fingerprint()), slog.String("old_fingerprint", old.key.Fingerprint())}
	}
	var (
		notMoved    errNotMoved
		notKept     errNotKept
		notReadBack errNotReadBack
	)
	switch {
	case errors.Is(err, errNoEnrolment) || ctx.Err() != nil:
		return
	case errors.As(err, &notMoved):
		r.use(old, got)
		r.notMoved = true
		r.log.Error("enrolled in Qory Apiary with a new key, which signs every request from now on, but could not be moved into its file, which still holds the old key: serve moves it at the next look, and a start moves it", append(attrs(), slog.String("error", err.Error()))...)
		return
	case errors.As(err, &notKept):
		r.log.Error("a new key is enrolled in Qory Apiary but could not be kept in the state directory, so serve does not use it, and the key in use stays: have an instance admin of Qory Apiary revoke the new key", slog.String("error", err.Error()))
		return
	case errors.As(err, &notReadBack):
		r.use(old, got)
		r.log.Error("enrolled in Qory Apiary with a new key, which is in its file and signs every request from now on in place of the old one, dropped, but the state directory's files could not be read back as a start reads them", append(attrs(), slog.String("error", err.Error()))...)
		return
	case err != nil:
		r.log.Error("a new key could not be enrolled; the key in use stays", slog.String("error", err.Error()))
		return
	}
	r.use(old, got)
	r.log.Info("enrolled in Qory Apiary with a new key, which signs every request from now on in place of the old one, dropped", attrs()...)
}

// use puts got, the new enrolment, in use in place of old, through inUse when it is
// set. When got's pin or adapter id is not old's, a line names both, the pin by its
// keys' fingerprints. When its adapter id is another, the adapter is a new record in
// Qory Apiary, and inUse drops what the store holds for the old record.
func (r *reenroller) use(old, got enrolment) {
	if got.adapterID != old.adapterID || pinFingerprints(got.pin) != pinFingerprints(old.pin) {
		r.log.Warn("the new key's enrolment changes what serve trusts or which adapter it is in Qory Apiary: Qory Apiary's pin, the adapter's id, or both",
			slog.String("old_adapter_id", old.adapterID), slog.String("adapter_id", got.adapterID),
			slog.String("old_pin", pinFingerprints(old.pin)), slog.String("pin", pinFingerprints(got.pin)))
	}
	if r.inUse == nil {
		r.creds.set(got)
		return
	}
	if err := r.inUse(got); err != nil {
		r.log.Error("what the store holds for the old adapter could not be dropped; a start drops it", slog.String("error", err.Error()))
	}
}

// pinFingerprints are the fingerprints of the pin's keys, sorted and joined by commas,
// so two pins that hold the same keys in another order have the same.
func pinFingerprints(p accesskey.Pin) string {
	fps := make([]string, 0, len(p))
	for _, k := range p.Keys() {
		fps = append(fps, k.Fingerprint())
	}
	slices.Sort(fps)
	return strings.Join(fps, ",")
}

// keyAdapterID is the key in the store's adapter namespace of the adapter record in
// Qory Apiary that the store's state belongs to, see [ownState].
const keyAdapterID = "adapter_id"

// recordState is what the store holds for one adapter record in Qory Apiary, which a
// new record does not have: the installations' links to its connections, the linked
// collections, their pulls and the environment_refs sent for them, what serve keeps of
// its connections, the connect flows and their passes' nonces, the copy of the
// record's grants, and in the adapter namespace the change feed's cursor and the sync
// interval. What belongs to the GitHub
// App stays: the deliveries, the installations' repositories, the installations GitHub
// announced or deleted, and the instance id.
var recordState = store.Owner{
	Namespaces: []string{nsInstallations, nsCollections, nsPulls, nsEnvironments, nsForbidden, nsReplaced, nsPasses, nsConnectSessions, nsConnectNonces, nsGrants},
	Keys:       map[string][]string{nsAdapter: {keyCursor, keySyncInterval}},
}

// ownState records in st that its state is the adapter record adapterID's. When st
// holds another record's, as after a re-enrolment that made the adapter a new record
// in Qory Apiary, whose old record's installations Qory Apiary has ended, it drops
// [recordState] in the same transaction, and logs the two ids and how many values it
// dropped from each namespace. A store that names no record yet is recorded as
// adapterID's, and nothing is dropped.
func ownState(st *store.Store, adapterID string, log *slog.Logger) error {
	previous, dropped, err := st.SetOwner(nsAdapter, keyAdapterID, adapterID, recordState)
	if err != nil {
		return fmt.Errorf("the store: %w", err)
	}
	if previous == "" || previous == adapterID {
		return nil
	}
	counts := make([]any, 0, len(dropped))
	for _, ns := range append(append([]string(nil), recordState.Namespaces...), nsAdapter) {
		counts = append(counts, slog.Int(ns, dropped[ns]))
	}
	log.Warn("the adapter is enrolled as another adapter in Qory Apiary, so serve dropped the data in its store for the old one: the installations' links, the linked collections, their pulls and the environment_refs sent for them, the connections' state, the connect flows, the copy of the grants, the change feed's cursor and the sync interval",
		slog.String("old_adapter_id", previous), slog.String("adapter_id", adapterID), slog.Group("dropped", counts...))
	return nil
}

// readCodeFile reads the enrolment code file at path: never more than [maxCodeFile]
// and one byte, and without waiting on a pipe. Core writes the file as another user,
// readable by all, so neither its owner nor its mode is checked; a file that is not a
// regular one is refused. An error that the file does not exist matches
// [fs.ErrNotExist]. No error says the path or what the file holds.
func readCodeFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", codeFileName, pathless(err))
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", codeFileName, pathless(err))
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New(codeFileName + " is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCodeFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", codeFileName, pathless(err))
	}
	if len(b) > maxCodeFile {
		return nil, errors.New(codeFileName + " is larger than an enrolment code")
	}
	return b, nil
}

// pathless is err without its path, the [fs.PathError]'s cause when it is one.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// writeNew writes b to a new file at path, 0600 and the user's that serve runs as,
// opened as [ownerfile.Open] opens a file and never over one that exists, and syncs it
// to disk before it is closed: a file on a filesystem that cannot sync one, see
// [enrol.SyncUnsupported], is kept unsynced. A file that could not be written whole is
// removed. what names the file in an error, which never says what it holds.
func writeNew(path string, b []byte, what string) error {
	f, err := ownerfile.Open(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600, what)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("%s: %w", what, pathless(err))
	}
	if err := f.Sync(); err != nil && !enrol.SyncUnsupported(err) {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("%s could not be synced to disk: %w", what, pathless(err))
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("%s: %w", what, pathless(err))
	}
	return nil
}

// syncDir syncs the directory dir, so the renames in it are on disk, where the system
// can sync a directory.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// retryAfterRecorder carries requests through base and keeps the Retry-After of the
// last answer, which [accesskey.EnrolmentRequest.Post] does not return: serve waits
// that long after a signed 429.
type retryAfterRecorder struct {
	base  http.RoundTripper
	mu    sync.Mutex
	value string
}

// RoundTrip carries req through base, and keeps its answer's Retry-After.
func (r *retryAfterRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err == nil {
		r.mu.Lock()
		r.value = resp.Header.Get("Retry-After")
		r.mu.Unlock()
	}
	return resp, err
}

// get is the last answer's Retry-After, or nothing.
func (r *retryAfterRecorder) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.value
}
