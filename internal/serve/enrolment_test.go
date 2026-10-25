package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// The 26 characters of the two enrolment codes the tests use, which no line or error
// may contain.
const (
	codeCore  = "0123456789ABCDEFGHJKMNPQRS"
	codeCore2 = "SRQPNMKJHGFEDCBA9876543210"
)

// enrolCode is an adapter's enrolment code with the 26 characters core, for the Qory
// Apiary whose key is server, as core writes it to the code file.
func enrolCode(core string, server *accesskey.Key) string {
	return accesskey.CodePrefixAdapter + core + "." + server.Fingerprint()
}

// enrolEnv is a state directory, 0700 as [store.Open] makes it, a code file's path in
// a directory beside it, a fake Qory Apiary and the settings that name the three, with
// no enrolment.
type enrolEnv struct {
	t        *testing.T
	dir      string
	codeFile string
	apiary   *fakeApiary
	settings Settings
	log      *syncBuffer
	// waits are the waits the enroller asked for, and onWait runs at each, numbered
	// from 1.
	mu     sync.Mutex
	waits  []time.Duration
	onWait func(n int)
}

func newEnrolEnv(t *testing.T) *enrolEnv {
	t.Helper()
	dir := t.TempDir()
	e := &enrolEnv{t: t, dir: dir, codeFile: filepath.Join(dir, "run", "github.code"), apiary: newFakeApiary(t, newKey(t)), log: &syncBuffer{}}
	os.Mkdir(filepath.Dir(e.codeFile), 0o755)
	s := settingsFiles(t, dir, newKey(t), e.apiary.srv.URL, nil)
	s.AccessKeyID, s.AccessKeySecretFile, s.ApiaryPublicKey, s.AdapterID = "", "", nil, ""
	s.EnrolmentCodeFile = e.codeFile
	e.settings = s
	if err := os.Mkdir(s.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

// writeCode writes content to the code file, readable by all, as core writes it.
func (e *enrolEnv) writeCode(content string) {
	e.t.Helper()
	tmp := e.codeFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Rename(tmp, e.codeFile); err != nil {
		e.t.Fatal(err)
	}
}

// opts are the options the enroller runs with: a wait that notes the duration, runs
// onWait and returns at once, but for ctx.
func (e *enrolEnv) opts() Options {
	return Options{ProgramVersion: testVersion, feedSleep: shortSleep, enrolWait: func(ctx context.Context, d time.Duration) error {
		e.mu.Lock()
		e.waits = append(e.waits, d)
		n, on := len(e.waits), e.onWait
		e.mu.Unlock()
		if on != nil {
			on(n)
		}
		if n > 1000 {
			e.t.Error("the enroller waits for ever")
			return context.Canceled
		}
		return ctx.Err()
	}}
}

// shortSleep waits 20ms, or until ctx is done, in place of the change feed reader's
// waits, so a test that runs serve whole sees the requests the feed sends again after
// a 401 within its time.
func shortSleep(ctx context.Context, _ time.Duration) error {
	return wait(ctx, 20*time.Millisecond)
}

// enrol runs the enrolment of the settings, as Run does after it opens the store.
func (e *enrolEnv) enrol() (enrolment, error) {
	e.t.Helper()
	got, _, err := e.settings.enrolmentOf(context.Background(), e.opts(), slog.New(slog.NewJSONHandler(e.log, nil)))
	return got, err
}

// waited are the waits the enroller asked for.
func (e *enrolEnv) waited() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Duration(nil), e.waits...)
}

// lines are the log's lines whose message contains msg.
func (e *enrolEnv) lines(msg string) []map[string]any {
	var found []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(e.log.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && strings.Contains(fmt.Sprint(m["msg"]), msg) {
			found = append(found, m)
		}
	}
	return found
}

// noCode fails the test when one of outputs contains a code's characters, a part of
// them, or an access key secret.
func noCode(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, v := range []string{codeCore, codeCore2, codeCore[:13], codeCore[13:], codeCore2[:13], codeCore2[13:], accesskey.SecretPrefix} {
			if strings.Contains(o, v) {
				t.Errorf("an output contains a code or a secret, %s: %s", v, o)
			}
		}
	}
}

// checkKept checks the enrolment kept in the state directory: its files, each 0600, and
// that it is got, the key the fake enrolled last, under the fake's key.
func (e *enrolEnv) checkKept(got enrolment) {
	e.t.Helper()
	sent := e.apiary.enrolled()
	if len(sent) == 0 {
		e.t.Fatal("nothing was enrolled")
	}
	last := sent[len(sent)-1]
	if got.keyID != testKeyID || got.adapterID != testAdapterID || len(got.pin) != 1 || got.pin[0] != pinOf(e.apiary.server)[0] || got.key.PublicKey().String() != last.PublicKey {
		e.t.Errorf("the enrolment %s %s %v, key %s; enrolled %s", got.keyID, got.adapterID, got.pin, got.key.PublicKey(), last.PublicKey)
	}
	for _, name := range []string{enrolmentFile, accessKeyFile} {
		info, err := os.Lstat(filepath.Join(e.settings.StateDir, name))
		if err != nil || info.Mode() != 0o600 {
			e.t.Errorf("%s: %v %v", name, info, err)
		}
	}
	for _, name := range []string{pendingKeyFile, enrolmentTemp} {
		if _, err := os.Lstat(filepath.Join(e.settings.StateDir, name)); !errors.Is(err, os.ErrNotExist) {
			e.t.Errorf("%s is left: %v", name, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(e.settings.StateDir, enrolmentFile))
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil || len(doc) != 4 || doc["fingerprint"] != got.key.Fingerprint() || doc["access_key_id"] != testKeyID || doc["adapter_id"] != testAdapterID {
		e.t.Errorf("enrolment.json: %s", b)
	}
	noCode(e.t, e.log.String(), string(b))
}

func TestServeEnrolsAtFirstStartAndKeepsTheAnswer(t *testing.T) {
	e := newEnrolEnv(t)
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	sent := e.apiary.enrolled()
	if len(sent) != 1 || sent[0].Code != enrolCode(codeCore, e.apiary.server) {
		t.Errorf("enrolled %d times, the code %q", len(sent), sent[0].Code)
	}
	lines := e.lines("enrolled in Qory Apiary")
	if len(lines) != 1 || lines[0]["access_key_id"] != testKeyID || lines[0]["adapter_id"] != testAdapterID || lines[0]["fingerprint"] != got.key.Fingerprint() {
		t.Errorf("the log: %s", e.log.String())
	}
	if len(e.waited()) != 0 {
		t.Errorf("waited %v", e.waited())
	}
	// The next start reads the state directory and never the code file, even one that
	// holds what is no code.
	e.writeCode("garbage that is no code\n")
	again, err := e.enrol()
	if err != nil || again.keyID != got.keyID || again.key.PublicKey() != got.key.PublicKey() || again.adapterID != got.adapterID {
		t.Errorf("the kept enrolment: %+v, %v", again, err)
	}
	os.Remove(e.codeFile)
	os.Mkdir(e.codeFile, 0o700)
	if _, err := e.enrol(); err != nil {
		t.Errorf("the code file is read: %v", err)
	}
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
}

func TestServeWaitsForTheCodeFile(t *testing.T) {
	e := newEnrolEnv(t)
	e.onWait = func(n int) {
		if n == 3 {
			e.writeCode(enrolCode(codeCore, e.apiary.server))
		}
	}
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	if w := e.waited(); len(w) != 3 || w[0] != enrolPoll || w[2] != enrolPoll {
		t.Errorf("waited %v", w)
	}
	if n := len(e.lines("waiting for an enrolment code")); n != 1 {
		t.Errorf("%d waiting lines: %s", n, e.log.String())
	}
}

// TestServeWaitsForANewCodeAfterARefusal pins that a 401, a signed 409 key_limit and a
// code of another kind are each logged once, and the code file's content must change
// before the next attempt.
func TestServeWaitsForANewCodeAfterARefusal(t *testing.T) {
	for name, tc := range map[string]struct {
		first enrolAnswer
		code  func(server *accesskey.Key) string
		msg   string
		sent  int
	}{
		"401":       {enrolAnswer{status: http.StatusUnauthorized}, nil, "refused the enrolment code with a 401", 2},
		"key_limit": {enrolAnswer{status: http.StatusConflict, refusal: accesskey.CodeKeyLimit}, nil, "already holds two keys", 2},
		"a node's code": {enrolAnswer{}, func(server *accesskey.Key) string {
			return accesskey.CodePrefixNode + codeCore + "." + server.Fingerprint()
		}, "holds no enrolment code of an adapter", 1},
		"not a code": {enrolAnswer{}, func(*accesskey.Key) string { return "qeci_" + codeCore[:20] }, "holds no enrolment code of an adapter", 1},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnrolEnv(t)
			e.apiary.enrolReply = func(n int) enrolAnswer {
				if n == 1 && tc.first.status != 0 {
					return tc.first
				}
				return enrolAnswer{status: http.StatusCreated}
			}
			first := enrolCode(codeCore, e.apiary.server)
			if tc.code != nil {
				first = tc.code(e.apiary.server)
			}
			e.writeCode(first + "\n")
			e.onWait = func(n int) {
				if n == 4 {
					e.writeCode(enrolCode(codeCore2, e.apiary.server) + "\n")
				}
			}
			got, err := e.enrol()
			if err != nil {
				t.Fatal(err)
			}
			e.checkKept(got)
			sent := e.apiary.enrolled()
			if len(sent) != tc.sent || sent[len(sent)-1].Code != enrolCode(codeCore2, e.apiary.server) {
				t.Errorf("enrolled %d times", len(sent))
			}
			if w := e.waited(); len(w) != 4 || w[0] != enrolPoll || w[3] != enrolPoll {
				t.Errorf("waited %v", w)
			}
			if n := len(e.lines(tc.msg)); n != 1 {
				t.Errorf("%d lines %q: %s", n, tc.msg, e.log.String())
			}
		})
	}
}

func TestServeTriesANewKeyAfterKeyInvalid(t *testing.T) {
	e := newEnrolEnv(t)
	e.apiary.enrolReply = func(n int) enrolAnswer {
		if n == 1 {
			return enrolAnswer{status: http.StatusConflict, refusal: accesskey.CodeKeyInvalid}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	sent := e.apiary.enrolled()
	if len(sent) != 2 || sent[0].PublicKey == sent[1].PublicKey || sent[0].Code != sent[1].Code {
		t.Errorf("enrolled %d times, the keys %v", len(sent), sent)
	}
	if w := e.waited(); len(w) != 1 || w[0] != enrolBackoff {
		t.Errorf("waited %v", w)
	}
	if n := len(e.lines("trying again with a new key")); n != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
}

func TestServeHonoursRetryAfter(t *testing.T) {
	e := newEnrolEnv(t)
	e.apiary.enrolReply = func(n int) enrolAnswer {
		switch n {
		case 1:
			return enrolAnswer{status: http.StatusTooManyRequests, refusal: accesskey.CodeRateLimited, retryAfter: "7"}
		case 2:
			return enrolAnswer{status: http.StatusTooManyRequests, refusal: accesskey.CodeRateLimited}
		case 3:
			return enrolAnswer{status: http.StatusTooManyRequests, refusal: accesskey.CodeRateLimited, retryAfter: "7200"}
		case 4:
			return enrolAnswer{status: http.StatusTooManyRequests, refusal: accesskey.CodeRateLimited, retryAfter: "soon"}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	// A 429 without a Retry-After serve can read waits as an attempt without an answer
	// does, and one that asks for more than an hour waits an hour.
	want := []time.Duration{7 * time.Second, enrolBackoff, time.Hour, 2 * enrolBackoff}
	if w := e.waited(); fmt.Sprint(w) != fmt.Sprint(want) {
		t.Errorf("waited %v, want %v", w, want)
	}
	sent := e.apiary.enrolled()
	if len(sent) != 5 || sent[0].PublicKey != sent[4].PublicKey {
		t.Errorf("enrolled %d times", len(sent))
	}
	lines := e.lines("the code was tried too often")
	wantMsgs := []string{
		"Qory Apiary refused the attempt: the code was tried too often; trying again after the wait it asked for",
		"Qory Apiary refused the attempt: the code was tried too often, and it asked for no wait serve can read; trying again after a wait that doubles",
		"Qory Apiary refused the attempt: the code was tried too often; trying again after the wait it asked for, held to between a second and an hour",
		"Qory Apiary refused the attempt: the code was tried too often, and it asked for no wait serve can read; trying again after a wait that doubles",
	}
	if len(lines) != len(wantMsgs) {
		t.Fatalf("the log: %s", e.log.String())
	}
	for i, l := range lines {
		if l["msg"] != wantMsgs[i] {
			t.Errorf("line %d: %v", i, l["msg"])
		}
	}
}

// TestServeBacksOffWithoutAnAnswer pins that an attempt that got no answer, or one that
// did not verify, is tried again after a wait that doubles up to a minute, with the
// same key.
func TestServeBacksOffWithoutAnAnswer(t *testing.T) {
	e := newEnrolEnv(t)
	e.apiary.enrolReply = func(n int) enrolAnswer {
		switch {
		case n == 2:
			return enrolAnswer{status: http.StatusBadGateway}
		case n < 8:
			return enrolAnswer{drop: true}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	if w := e.waited(); fmt.Sprint(w) != fmt.Sprint(want) {
		t.Errorf("waited %v, want %v", w, want)
	}
	sent := e.apiary.enrolled()
	for _, r := range sent {
		if r.PublicKey != sent[0].PublicKey {
			t.Errorf("a new key was made")
		}
	}
	lines := e.lines("the enrolment did not complete")
	if len(lines) != 7 || !strings.Contains(fmt.Sprint(lines[1]["error"]), "answer_unsigned") {
		t.Errorf("the log: %s", e.log.String())
	}
}

// TestServeRetriesAfterACrash pins the two crashes an enrolment can leave: after the
// pending key is written, the next start replaces it and logs its fingerprint; after
// enrolment.json is written and before the key is renamed, the next start finishes
// the rename.
func TestServeRetriesAfterACrash(t *testing.T) {
	e := newEnrolEnv(t)
	stale := newKey(t)
	writeFile(t, filepath.Join(e.settings.StateDir, pendingKeyFile), stale.Secret()+"\n", 0o600)
	writeFile(t, filepath.Join(e.settings.StateDir, enrolmentTemp), "{", 0o600)
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	if got.key.PublicKey() == stale.PublicKey() {
		t.Error("the stale key is used")
	}
	lines := e.lines("did not finish is dropped")
	if len(lines) != 1 || lines[0]["fingerprint"] != stale.Fingerprint() {
		t.Errorf("the log: %s", e.log.String())
	}
	noCode(t, e.log.String())

	// A crash between the two renames: the next start moves the pending key into place.
	dir := e.settings.StateDir
	os.Rename(filepath.Join(dir, accessKeyFile), filepath.Join(dir, pendingKeyFile))
	again, err := e.enrol()
	if err != nil || again.key.PublicKey() != got.key.PublicKey() {
		t.Fatalf("%+v %v", again, err)
	}
	e.checkKept(again)
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
}

func TestServeRefusesWhatItCannotEnrolWith(t *testing.T) {
	e := newEnrolEnv(t)
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	// An access key without enrolment.json is never written over.
	writeFile(t, filepath.Join(e.settings.StateDir, accessKeyFile), newKey(t).Secret()+"\n", 0o600)
	if _, err := e.enrol(); err == nil || err.Error() != "the state directory holds an access key, access-key, but no enrolment.json, which names it in Qory Apiary; move access-key away for serve to enrol a new key" {
		t.Errorf("err %v", err)
	}
	os.Remove(filepath.Join(e.settings.StateDir, accessKeyFile))
	// An enrolment.json serve did not write is refused, and the code file is not read.
	for _, content := range []string{"{}", `{"access_key_id":"ak_0123456789abcdef","adapter_id":"na_0123456789abcdef","apiary_public_key":[],"extra":1}`, "not json"} {
		writeFile(t, filepath.Join(e.settings.StateDir, enrolmentFile), content, 0o600)
		if _, err := e.enrol(); err == nil || !strings.Contains(err.Error(), "does not hold access_key_id, adapter_id, apiary_public_key and fingerprint as serve writes them") {
			t.Errorf("%s: err %v", content, err)
		}
	}
	// One others may read is refused.
	e2 := newEnrolEnv(t)
	e2.writeCode(enrolCode(codeCore, e2.apiary.server))
	if _, err := e2.enrol(); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(e2.settings.StateDir, enrolmentFile), 0o644)
	if _, err := e2.enrol(); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("err %v", err)
	}
	os.Chmod(filepath.Join(e2.settings.StateDir, enrolmentFile), 0o600)
	os.Chmod(filepath.Join(e2.settings.StateDir, accessKeyFile), 0o640)
	if _, err := e2.enrol(); err == nil || !strings.Contains(err.Error(), "group or others") || strings.Contains(err.Error(), "qak_") {
		t.Errorf("err %v", err)
	}
	if n := len(e.apiary.enrolled()) + len(e2.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
	noCode(t, e.log.String(), e2.log.String())
}

// TestRunRefusesSettingsWithNoWayToAnEnrolment pins that Run refuses settings that give
// no enrolment when the state directory holds none and no code file is set, before it
// reads a secret or makes the state directory, and in the environment's words.
func TestRunRefusesSettingsWithNoWayToAnEnrolment(t *testing.T) {
	e := newEnrolEnv(t)
	s := e.settings
	s.EnrolmentCodeFile, s.StateDir = "", filepath.Join(e.dir, "none")
	err := Run(context.Background(), s, Options{ProgramVersion: testVersion})
	if err == nil || err.Error() != "the settings give no enrolment in Qory Apiary, the state directory holds none, and enrolment_code_file is not set: give access_key_id, access_key_secret_file, apiary_public_key, adapter_id, or set enrolment_code_file for serve to enrol at its first start" {
		t.Errorf("err %v", err)
	}
	s.env = true
	err = Run(context.Background(), s, Options{ProgramVersion: testVersion})
	if err == nil || err.Error() != "the settings in the environment give no enrolment in Qory Apiary, the state directory holds none, and QORY_GITHUB_ENROLMENT_CODE_FILE is not set: give QORY_GITHUB_ACCESS_KEY_ID, QORY_GITHUB_ACCESS_KEY_SECRET or QORY_GITHUB_ACCESS_KEY_SECRET_FILE, QORY_GITHUB_APIARY_PUBLIC_KEY, QORY_GITHUB_ADAPTER_ID, or set QORY_GITHUB_ENROLMENT_CODE_FILE for serve to enrol at its first start" {
		t.Errorf("err %v", err)
	}
	if _, err := os.Stat(s.StateDir); !os.IsNotExist(err) {
		t.Errorf("the state directory is made: %v", err)
	}
}

// runServe runs serve with s on a loopback port until the returned function stops it,
// and returns once it listens.
func runServe(t *testing.T, s Settings, opts Options, log *syncBuffer) func() {
	t.Helper()
	opts.Log = slog.New(slog.NewJSONHandler(log, nil))
	opts.ProgramVersion = testVersion
	addr := make(chan net.Addr, 1)
	opts.Listening = func(a net.Addr) { addr <- a }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, opts) }()
	// returned is whether Run's error was received already, as when it returns before
	// it listens, so stop does not wait for it a second time.
	var once sync.Once
	returned := false
	stop := func() {
		once.Do(func() {
			cancel()
			if returned {
				return
			}
			if err := <-done; err != nil {
				t.Errorf("Run: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	select {
	case <-addr:
	case err := <-done:
		returned = true
		t.Fatalf("Run returned before it listened: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("Run does not listen: %s", log.String())
	}
	return stop
}

// TestRunEnrolsThenServesWithTheKeptEnrolment runs serve whole without an enrolment in
// its settings: it enrols with the code, declares the adapter signed with the new key,
// and a restart serves with the kept enrolment without reading the code file.
func TestRunEnrolsThenServesWithTheKeptEnrolment(t *testing.T) {
	e := newEnrolEnv(t)
	os.Remove(e.settings.StateDir)
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	for i := range 2 {
		stop := runServe(t, e.settings, e.opts(), e.log)
		eventually(t, "declared", func() bool { return len(e.apiary.sent(routeAdapter)) > i })
		stop()
		e.writeCode("garbage\n")
	}
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
	if n := len(e.lines("enrolled in Qory Apiary")); n != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
	info, err := os.Lstat(e.settings.StateDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the state directory: %v %v", info, err)
	}
	kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(kept)
}

// TestRunStopsWhileItWaitsForACode pins that a stop while serve waits for its code ends
// Run without an error, and that serve listens while it waits.
func TestRunStopsWhileItWaitsForACode(t *testing.T) {
	e := newEnrolEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	opts := e.opts()
	opts.Log = slog.New(slog.NewJSONHandler(e.log, nil))
	e.onWait = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	listened := false
	opts.Listening = func(net.Addr) { listened = true }
	if err := Run(ctx, e.settings, opts); err != nil || !listened {
		t.Errorf("err %v, listened %v", err, listened)
	}
}

// TestRunWithTheEnrolmentInItsSettingsNeverEnrols pins that settings that give the
// enrolment are used as they are: the code file is not read, and the state directory
// keeps no enrolment.
func TestRunWithTheEnrolmentInItsSettingsNeverEnrols(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.EnrolmentCodeFile = filepath.Join(dir, "github.code")
	writeFile(t, s.EnrolmentCodeFile, enrolCode(codeCore, apiary.server)+"\n", 0o644)
	log := &syncBuffer{}
	stop := runServe(t, s, Options{}, log)
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	stop()
	if n := len(apiary.enrolled()); n != 0 {
		t.Errorf("enrolled %d times", n)
	}
	for _, name := range []string{enrolmentFile, accessKeyFile, pendingKeyFile} {
		if _, err := os.Lstat(filepath.Join(s.StateDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadCodeFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "code")
	if _, err := readCodeFile(file); !errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), dir) {
		t.Errorf("err %v", err)
	}
	writeFile(t, file, strings.Repeat("a", maxCodeFile+1), 0o644)
	if _, err := readCodeFile(file); err == nil || err.Error() != "the file enrolment_code_file names is larger than an enrolment code" {
		t.Errorf("err %v", err)
	}
	if _, err := readCodeFile(dir); err == nil || err.Error() != "the file enrolment_code_file names is not a regular file" {
		t.Errorf("err %v", err)
	}
	// Others' file, readable by all, is taken.
	writeFile(t, file, "x\n", 0o644)
	if b, err := readCodeFile(file); err != nil || string(b) != "x\n" {
		t.Errorf("%q %v", b, err)
	}
}

// stateBytes are the files of the enrolment kept in the state directory dir, by name.
func stateBytes(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{enrolmentFile, accessKeyFile, pendingKeyFile, enrolmentTemp} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			out[name] = string(b)
		}
	}
	return out
}

// enrolled enrols e's adapter at first start with the first code, as a start would,
// and removes the code file, as core does once the key is live.
func (e *enrolEnv) enrolled() enrolment {
	e.t.Helper()
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	got, err := e.enrol()
	if err != nil {
		e.t.Fatal(err)
	}
	os.Remove(e.codeFile)
	return got
}

// reenroller is a reenroller for e's state directory, which holds an enrolment, and
// the credentials it replaces the enrolment in.
func (e *enrolEnv) reenroller() (*reenroller, *credentials) {
	e.t.Helper()
	log := slog.New(slog.NewJSONHandler(e.log, nil))
	got, en, err := e.settings.enrolmentOf(context.Background(), e.opts(), log)
	if err != nil || en == nil || !en.again {
		e.t.Fatalf("%v %v", en, err)
	}
	creds := &credentials{e: got}
	return newReenroller(en, creds, log), creds
}

// TestServeReenrolsAtStartWhenACodeIsThere runs serve whole on a state directory that
// holds an enrolment, its key revoked and a new code in the file: serve serves with the
// kept enrolment, enrols a new key beside it, swaps the two, and every later request
// is signed with the new key and its access key id.
func TestServeReenrolsAtStartWhenACodeIsThere(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.apiary.revoke(old.key.PublicKey())
	e.apiary.enrolKeyIDs = []string{"ak_fedcba9876543210"}
	e.writeCode(enrolCode(codeCore2, e.apiary.server) + "\n")
	stop := runServe(t, e.settings, e.opts(), e.log)
	eventually(t, "re-enrolled", func() bool { return len(e.lines("with a new key")) == 1 })
	eventually(t, "a request with the new key", func() bool {
		for _, r := range e.apiary.sent("GET " + routeChanges) {
			if r.keyID == "ak_fedcba9876543210" {
				return true
			}
		}
		return false
	})
	stop()
	sent := e.apiary.enrolled()
	if len(sent) != 2 || sent[1].Code != enrolCode(codeCore2, e.apiary.server) {
		t.Fatalf("enrolled %d times", len(sent))
	}
	kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler))
	if err != nil || kept.keyID != "ak_fedcba9876543210" || kept.key.PublicKey().String() != sent[1].PublicKey || kept.key.PublicKey() == old.key.PublicKey() {
		t.Errorf("the kept enrolment %+v, %v", kept, err)
	}
	if _, ok := stateBytes(t, e.settings.StateDir)[pendingKeyFile]; ok {
		t.Error("the pending key is left")
	}
	line := e.lines("with a new key")[0]
	if line["fingerprint"] != kept.key.Fingerprint() || line["old_fingerprint"] != old.key.Fingerprint() || line["access_key_id"] != "ak_fedcba9876543210" {
		t.Errorf("the line %v", line)
	}
	noCode(t, e.log.String())
}

// TestServeA401WithNoCodeChangesNothing pins that a 401, with no code file there, makes
// no enrolment and changes nothing in the state directory.
func TestServeA401WithNoCodeChangesNothing(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	before := stateBytes(t, e.settings.StateDir)
	e.apiary.revoke(old.key.PublicKey())
	stop := runServe(t, e.settings, e.opts(), e.log)
	eventually(t, "401s", func() bool { return e.apiary.unauthorizedCount() >= 2 })
	stop()
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
	if after := stateBytes(t, e.settings.StateDir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Error("the state directory changed")
	}
}

// TestServeA401WithACodeReenrolsBesideServing pins that a 401 with a code in the file
// enrols a new key while serving goes on with the old one, which signs the requests
// until Qory Apiary's 201, and the new one after, swapped whole into its files. The
// state directory is only read while the enrolment is under way, since a start's read
// would drop its pending key.
func TestServeA401WithACodeReenrolsBesideServing(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	before := stateBytes(t, e.settings.StateDir)
	e.apiary.enrolKeyIDs = []string{"ak_fedcba9876543210"}
	stop := runServe(t, e.settings, e.opts(), e.log)
	eventually(t, "declared", func() bool { return len(e.apiary.sent(routeAdapter)) > 0 })
	hold := make(chan struct{})
	e.apiary.mu.Lock()
	e.apiary.enrolHold = hold
	e.apiary.mu.Unlock()
	e.apiary.revoke(old.key.PublicKey())
	e.writeCode(enrolCode(codeCore2, e.apiary.server) + "\n")
	eventually(t, "the enrolment sent", func() bool { return len(e.apiary.enrolled()) == 2 })
	// While Qory Apiary has not answered, the old key signs, and the kept enrolment is
	// the old one, beside the pending key.
	n := e.apiary.unauthorizedCount()
	eventually(t, "a request with the old key", func() bool { return e.apiary.unauthorizedCount() > n })
	during := stateBytes(t, e.settings.StateDir)
	if during[enrolmentFile] != before[enrolmentFile] || during[accessKeyFile] != before[accessKeyFile] || during[pendingKeyFile] == "" {
		t.Error("the kept enrolment changed before the 201")
	}
	close(hold)
	eventually(t, "swapped", func() bool {
		return len(e.lines("with a new key, which signs every request from now on in place of the old one, dropped")) == 1
	})
	eventually(t, "a request with the new key", func() bool {
		for _, r := range e.apiary.sent("GET " + routeChanges) {
			if r.keyID == "ak_fedcba9876543210" {
				return true
			}
		}
		return false
	})
	stop()
	if n := len(e.apiary.enrolled()); n != 2 {
		t.Errorf("enrolled %d times", n)
	}
	if lines := e.lines("could not be moved into its file"); len(lines) != 0 {
		t.Errorf("the log: %s", e.log.String())
	}
	sent := e.apiary.enrolled()
	kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler))
	if err != nil || kept.keyID != "ak_fedcba9876543210" || kept.key.PublicKey().String() != sent[1].PublicKey {
		t.Errorf("the kept enrolment %+v, %v", kept, err)
	}
	if b := stateBytes(t, e.settings.StateDir); len(b) != 2 {
		t.Errorf("the state directory holds %d files", len(b))
	}
	noCode(t, e.log.String())
}

// TestServeAUsedCodeKeepsTheKey pins that a code still in the file after the enrolment
// that used it, as before core deletes it, is tried once at a look: Qory Apiary's 401
// keeps the enrolment in use, with one line, and no later look tries it again.
func TestServeAUsedCodeKeepsTheKey(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	e.apiary.enrolReply = func(n int) enrolAnswer {
		if n > 1 {
			return enrolAnswer{status: http.StatusUnauthorized}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	before := stateBytes(t, e.settings.StateDir)
	r, creds := e.reenroller()
	for range 5 {
		r.look(context.Background())
	}
	if n := len(e.apiary.enrolled()); n != 2 {
		t.Errorf("enrolled %d times", n)
	}
	if creds.get().key.PublicKey() != old.key.PublicKey() {
		t.Error("the key in use changed")
	}
	if after := stateBytes(t, e.settings.StateDir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("the state directory changed: %v", after)
	}
	lines := e.lines("refused the enrolment code with a 401")
	if len(lines) != 1 || !strings.HasSuffix(fmt.Sprint(lines[0]["msg"]), "; the key in use stays, and serve looks at the file enrolment_code_file names again when Qory Apiary next answers a request 401") {
		t.Errorf("the log: %s", e.log.String())
	}
	if len(e.waited()) != 0 {
		t.Errorf("waited %v", e.waited())
	}
	noCode(t, e.log.String())
}

// TestServeAFailedReenrolmentLeavesTheEnrolment pins that a look whose enrolment fails,
// for any reason, leaves the enrolment in use and the state directory as they were.
func TestServeAFailedReenrolmentLeavesTheEnrolment(t *testing.T) {
	for name, a := range map[string]enrolAnswer{
		"key_limit":   {status: http.StatusConflict, refusal: accesskey.CodeKeyLimit},
		"another 401": {status: http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnrolEnv(t)
			old := e.enrolled()
			e.apiary.enrolReply = func(n int) enrolAnswer {
				if n > 1 {
					return a
				}
				return enrolAnswer{status: http.StatusCreated}
			}
			before := stateBytes(t, e.settings.StateDir)
			e.writeCode(enrolCode(codeCore2, e.apiary.server))
			r, creds := e.reenroller()
			r.look(context.Background())
			if creds.get().key.PublicKey() != old.key.PublicKey() || fmt.Sprint(stateBytes(t, e.settings.StateDir)) != fmt.Sprint(before) {
				t.Error("the enrolment changed")
			}
		})
	}
	// No verified answer: the look tries while the file is there, and drops its key once
	// core deletes the file, logging the key's fingerprint, since it may be enrolled.
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{drop: true} }
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	e.onWait = func(n int) {
		if n == 2 {
			os.Remove(e.codeFile)
		}
	}
	before := stateBytes(t, e.settings.StateDir)
	r, creds := e.reenroller()
	r.look(context.Background())
	if creds.get().key.PublicKey() != old.key.PublicKey() || fmt.Sprint(stateBytes(t, e.settings.StateDir)) != fmt.Sprint(before) {
		t.Error("the enrolment changed")
	}
	sent := e.apiary.enrolled()
	lines := e.lines("did not finish is dropped")
	if len(lines) != 1 || len(sent) != 3 {
		t.Errorf("enrolled %d times; the log: %s", len(sent), e.log.String())
	} else if pub, _ := accesskey.ParsePublicKey(sent[2].PublicKey); lines[0]["fingerprint"] != pub.Fingerprint() {
		t.Errorf("the line %v", lines[0])
	}
	// A 201 that cannot be kept, before the enrolment file is in place: the enrolment
	// in use stays, the new key's secret is removed, and the error asks for its revoke.
	e2 := newEnrolEnv(t)
	old2 := e2.enrolled()
	before2 := stateBytes(t, e2.settings.StateDir)
	e2.writeCode(enrolCode(codeCore2, e2.apiary.server))
	r2, creds2 := e2.reenroller()
	rename = func(string, string) error { return errors.New("a rename that fails") }
	r2.look(context.Background())
	rename = os.Rename
	if creds2.get().key.PublicKey() != old2.key.PublicKey() || fmt.Sprint(stateBytes(t, e2.settings.StateDir)) != fmt.Sprint(before2) {
		t.Error("the enrolment changed")
	}
	lines = e2.lines("a new key is enrolled in Qory Apiary but could not be kept in the state directory, so serve does not use it, and the key in use stays: have an instance admin of Qory Apiary revoke the new key")
	if len(lines) != 1 || !strings.Contains(fmt.Sprint(lines[0]["error"]), "is enrolled as "+testKeyID+" in the adapter "+testAdapterID+", and could not be kept in the state directory: ") || !strings.HasSuffix(fmt.Sprint(lines[0]["error"]), "; have an instance admin of Qory Apiary revoke it") {
		t.Errorf("the log: %s", e2.log.String())
	}
	if len(e2.lines("a new key could not be enrolled")) != 0 {
		t.Errorf("the log: %s", e2.log.String())
	}
	noCode(t, e.log.String(), e2.log.String())
}

// TestServeAnEnrolmentNotReadBackIsSaidTruly pins an enrolment kept whole, its files
// in place, that cannot be read back as a start reads them: a look puts the new
// enrolment, which the next start reads, in use, and says so; a first start stops
// with an error that says the files are in place.
func TestServeAnEnrolmentNotReadBackIsSaidTruly(t *testing.T) {
	defer func() { readBack = loadKept }()
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	r, creds := e.reenroller()
	readBack = func(string, *slog.Logger) (enrolment, error) { return enrolment{}, errors.New("a read that fails") }
	r.look(context.Background())
	readBack = loadKept
	sent := e.apiary.enrolled()
	got := creds.get()
	if len(sent) != 2 || got.key.PublicKey().String() != sent[1].PublicKey || got.key.PublicKey() == old.key.PublicKey() {
		t.Fatalf("the new key is not in use: %d", len(sent))
	}
	if kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler)); err != nil || kept.key.PublicKey() != got.key.PublicKey() || kept.keyID != got.keyID {
		t.Errorf("the kept enrolment %+v, %v", kept, err)
	}
	lines := e.lines("enrolled in Qory Apiary with a new key, which is in its file and signs every request from now on in place of the old one, dropped, but the state directory's files could not be read back as a start reads them")
	if len(lines) != 1 || lines[0]["error"] != "the enrolment is kept in enrolment.json and its key in access-key, but could not be read back: a read that fails" ||
		lines[0]["fingerprint"] != got.key.Fingerprint() || lines[0]["old_fingerprint"] != old.key.Fingerprint() || len(e.lines("could not be enrolled")) != 0 {
		t.Errorf("the log: %s", e.log.String())
	}
	e2 := newEnrolEnv(t)
	e2.writeCode(enrolCode(codeCore, e2.apiary.server))
	readBack = func(string, *slog.Logger) (enrolment, error) { return enrolment{}, errors.New("a read that fails") }
	if _, err := e2.enrol(); err == nil || err.Error() != "the enrolment is kept in enrolment.json and its key in access-key, but could not be read back: a read that fails" {
		t.Errorf("err %v", err)
	}
	noCode(t, e.log.String(), e2.log.String())
}

// TestServeASwapCutShortIsFinishedAtTheNextStart pins the swap's order: the enrolment
// file names the new key before the key's file holds it, the old key is dropped last,
// and a rename of the key that fails puts the new enrolment in use and leaves a state
// the next start finishes.
func TestServeASwapCutShortIsFinishedAtTheNextStart(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	var seen map[string]string
	rename = func(from, to string) error {
		if filepath.Base(to) != accessKeyFile {
			return os.Rename(from, to)
		}
		seen = stateBytes(t, e.settings.StateDir)
		return errors.New("a rename that fails")
	}
	defer func() { rename = os.Rename }()
	r, creds := e.reenroller()
	r.look(context.Background())
	sent := e.apiary.enrolled()
	if len(sent) != 2 || creds.get().key.PublicKey().String() != sent[1].PublicKey {
		t.Fatalf("the new key is not in use: %d", len(sent))
	}
	// At the rename, enrolment.json names the new key, and access-key still holds the
	// old one beside the pending new one.
	var doc map[string]any
	json.Unmarshal([]byte(seen[enrolmentFile]), &doc)
	oldKey, _ := accesskey.ParseSecret(strings.TrimSpace(seen[accessKeyFile]))
	newKey, _ := accesskey.ParseSecret(strings.TrimSpace(seen[pendingKeyFile]))
	if oldKey == nil || newKey == nil || oldKey.PublicKey() != old.key.PublicKey() || doc["fingerprint"] != newKey.Fingerprint() {
		t.Errorf("the state at the rename: %v", doc)
	}
	if lines := e.lines("but could not be moved into its file"); len(lines) != 1 || !strings.HasSuffix(fmt.Sprint(lines[0]["error"]), "; the next start moves it") {
		t.Errorf("the log: %s", e.log.String())
	}
	rename = os.Rename
	kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler))
	if err != nil || kept.key.PublicKey() != newKey.PublicKey() || kept.keyID != testKeyID {
		t.Fatalf("%+v %v", kept, err)
	}
	if b := stateBytes(t, e.settings.StateDir); b[accessKeyFile] != seen[pendingKeyFile] || b[pendingKeyFile] != "" {
		t.Error("the next start did not move the key")
	}
}

// TestServeResolvesEachCrashWindow pins what the next start finds and does for each
// point an enrolment can stop at, see [loadKept].
func TestServeResolvesEachCrashWindow(t *testing.T) {
	a, p := newKey(t), newKey(t)
	server := newKey(t)
	doc := func(k *accesskey.Key) string {
		pin, _ := json.Marshal(pinOf(server))
		return `{"access_key_id":"` + testKeyID + `","adapter_id":"` + testAdapterID + `","apiary_public_key":` + string(pin) + `,"fingerprint":"` + k.Fingerprint() + `"}`
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  *accesskey.Key
		err   string
		stale bool
	}{
		"kept whole":                     {map[string]string{enrolmentFile: doc(a), accessKeyFile: a.Secret()}, a, "", false},
		"a pending key, before the 201":  {map[string]string{enrolmentFile: doc(a), accessKeyFile: a.Secret(), pendingKeyFile: p.Secret(), enrolmentTemp: "{"}, a, "", true},
		"the enrolment file in place":    {map[string]string{enrolmentFile: doc(p), accessKeyFile: a.Secret(), pendingKeyFile: p.Secret()}, p, "", false},
		"the first start's rename":       {map[string]string{enrolmentFile: doc(p), pendingKeyFile: p.Secret()}, p, "", false},
		"a key the enrolment never made": {map[string]string{enrolmentFile: doc(p), accessKeyFile: a.Secret()}, nil, "names the key " + p.Fingerprint() + ", which neither access-key nor access-key.pending in the state directory holds", false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			os.Mkdir(dir, 0o700)
			for f, c := range tc.files {
				writeFile(t, filepath.Join(dir, f), c+"\n", 0o600)
			}
			var log syncBuffer
			got, err := loadKept(dir, slog.New(slog.NewJSONHandler(&log, nil)))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Errorf("err %v", err)
				}
				return
			}
			if err != nil || got.key.PublicKey() != tc.want.PublicKey() {
				t.Fatalf("%v %v", got.key, err)
			}
			b := stateBytes(t, dir)
			if len(b) != 2 || b[accessKeyFile] != tc.want.Secret()+"\n" {
				t.Errorf("the state directory holds %d files", len(b))
			}
			if stale := strings.Contains(log.String(), p.Fingerprint()) && strings.Contains(log.String(), "did not finish is dropped"); stale != tc.stale {
				t.Errorf("the log: %s", log.String())
			}
		})
	}
}

// TestServeLooksOnceAtATimeUnderABurst pins that a burst of 401s, while a look waits
// for Qory Apiary's answer, makes no second enrolment: one look runs at a time, and
// the looks after the swap skip the code it used.
func TestServeLooksOnceAtATimeUnderABurst(t *testing.T) {
	e := newEnrolEnv(t)
	e.enrolled()
	hold := make(chan struct{})
	e.apiary.enrolHold = hold
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	r, creds := e.reenroller()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx) }()
	eventually(t, "the enrolment sent", func() bool { return len(e.apiary.enrolled()) == 2 })
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() { defer wg.Done(); r.refused() }()
	}
	wg.Wait()
	close(hold)
	eventually(t, "swapped", func() bool { return len(e.lines("with a new key")) == 1 })
	for range 20 {
		r.refused()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	sent := e.apiary.enrolled()
	if len(sent) != 2 || creds.get().key.PublicKey().String() != sent[1].PublicKey {
		t.Errorf("enrolled %d times", len(sent))
	}
}

// TestRunWithTheEnrolmentInItsSettingsNeverLooks pins that with the enrolment in the
// settings a 401 never makes serve look at the code file, even with a code there.
func TestRunWithTheEnrolmentInItsSettingsNeverLooks(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	apiary.revoke(access.PublicKey())
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.EnrolmentCodeFile = filepath.Join(dir, "github.code")
	writeFile(t, s.EnrolmentCodeFile, enrolCode(codeCore, apiary.server)+"\n", 0o644)
	log := &syncBuffer{}
	stop := runServe(t, s, Options{feedSleep: shortSleep, enrolWait: func(context.Context, time.Duration) error { return nil }}, log)
	eventually(t, "401s", func() bool { return apiary.unauthorizedCount() >= 2 })
	stop()
	if n := len(apiary.enrolled()); n != 0 {
		t.Errorf("enrolled %d times", n)
	}
	if strings.Contains(log.String(), "enrolment_code_file") {
		t.Errorf("the log: %s", log.String())
	}
}

// TestRunWithoutACodeFileSaysSoOnA401 pins that with the enrolment kept in the state
// directory and no code file set, a 401 is said once to make no look.
func TestRunWithoutACodeFileSaysSoOnA401(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.apiary.revoke(old.key.PublicKey())
	s := e.settings
	s.EnrolmentCodeFile = ""
	stop := runServe(t, s, e.opts(), e.log)
	eventually(t, "401s", func() bool { return e.apiary.unauthorizedCount() >= 2 })
	stop()
	if lines := e.lines("Qory Apiary answered a request 401; enrolment_code_file is not set, so serve looks for no code to enrol a new key with"); len(lines) != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
}

// TestServeEnrolsOverTLS pins that the enrolment goes over https with Go's TLS
// verification: a client that trusts the server's certificate enrols, and the
// default transport, which does not, gets no answer.
func TestServeEnrolsOverTLS(t *testing.T) {
	e := newEnrolEnv(t)
	e.apiary.srv.Close()
	e.apiary.srv = httptest.NewTLSServer(e.apiary)
	e.settings.ApiaryURL = e.apiary.srv.URL
	if !strings.HasPrefix(e.settings.ApiaryURL, "https://127.0.0.1:") {
		t.Fatal(e.settings.ApiaryURL)
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	// The default transport does not trust the test's certificate.
	ctx, cancel := context.WithCancel(context.Background())
	opts := e.opts()
	opts.enrolWait = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	if _, _, err := e.settings.enrolmentOf(ctx, opts, slog.New(slog.NewJSONHandler(e.log, nil))); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if lines := e.lines("the enrolment did not complete"); len(lines) != 1 || !strings.Contains(fmt.Sprint(lines[0]["error"]), "certificate") {
		t.Errorf("the log: %s", e.log.String())
	}
	if n := len(e.apiary.enrolled()); n != 0 {
		t.Errorf("enrolled %d times", n)
	}
	// A transport that trusts it enrols.
	opts = e.opts()
	opts.enrolTransport = e.apiary.srv.Client().Transport
	got, _, err := e.settings.enrolmentOf(context.Background(), opts, slog.New(slog.NewJSONHandler(e.log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
}

// TestServeRemovesAKeyEnrolledInAWayItDoesNotUse pins that a verified 201 for another
// kind of node, or whose pin lists a published fixture key, removes the pending key's
// secret at once, and logs serve's line, which names the access key, the node and the
// fingerprint, says the secret was removed and asks for the revoke.
func TestServeRemovesAKeyEnrolledInAWayItDoesNotUse(t *testing.T) {
	// The Forager contract's fixture access key, whose secret is published.
	fixture, err := accesskey.ParseSecret("qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	if err != nil || !fixture.PublicKey().Fixture() {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		server     *accesskey.Key
		first      enrolAnswer
		msg        string
		kind, node string
	}{
		"a pool's 201": {nil, enrolAnswer{status: http.StatusCreated, kind: "pool", node: "np_0123456789abcdef"},
			"Qory Apiary enrolled the key for a node of another kind than an adapter, so serve does not use it: its secret is removed from the state directory; have an instance admin of Qory Apiary revoke the key; waiting for a new code in the file enrolment_code_file names", "pool", "np_0123456789abcdef"},
		"a fixture pin": {fixture, enrolAnswer{status: http.StatusCreated},
			"Qory Apiary enrolled the key with an answer whose pin lists a published fixture key, whose secret anyone can read, so serve does not use it: its secret is removed from the state directory; have an instance admin of Qory Apiary revoke the key; waiting for a new code in the file enrolment_code_file names", "adapter", testAdapterID},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnrolEnv(t)
			if tc.server != nil {
				e.apiary.server = tc.server
			}
			e.apiary.enrolReply = func(n int) enrolAnswer {
				if n == 1 {
					return tc.first
				}
				return enrolAnswer{status: http.StatusCreated}
			}
			var pendingAfter bool
			e.onWait = func(n int) {
				if n == 1 {
					_, err := os.Lstat(filepath.Join(e.settings.StateDir, pendingKeyFile))
					pendingAfter = err == nil
					e.apiary.server = newKey(t)
					e.writeCode(enrolCode(codeCore2, e.apiary.server))
				}
			}
			e.writeCode(enrolCode(codeCore, e.apiary.server))
			got, err := e.enrol()
			if err != nil {
				t.Fatal(err)
			}
			if pendingAfter {
				t.Error("the pending key's secret is left after the 201")
			}
			sent := e.apiary.enrolled()
			lines := e.lines("Qory Apiary enrolled the key")
			first, _ := accesskey.ParsePublicKey(sent[0].PublicKey)
			if len(lines) != 1 || lines[0]["msg"] != tc.msg || lines[0]["access_key_id"] != testKeyID || lines[0]["node_kind"] != tc.kind || lines[0]["node_id"] != tc.node || lines[0]["fingerprint"] != first.Fingerprint() || lines[0]["error"] != nil {
				t.Errorf("the log: %s", e.log.String())
			}
			if got.key.PublicKey() == first {
				t.Error("the key enrolled elsewhere is used")
			}
			noCode(t, e.log.String())
		})
	}
}

// TestServeNamesAKeyThatMayBeLiveAfterARefusal pins that an attempt that got no answer,
// whose key Qory Apiary may so have enrolled, followed by a refusal of the code, still
// logs that key's fingerprint when serve drops it: once enrolled, at the end of the
// look; at first start, when the code file goes away.
func TestServeNamesAKeyThatMayBeLiveAfterARefusal(t *testing.T) {
	for _, refusal := range []enrolAnswer{{status: http.StatusUnauthorized}, {status: http.StatusConflict, refusal: accesskey.CodeKeyLimit}} {
		t.Run("once enrolled, "+fmt.Sprint(refusal.status), func(t *testing.T) {
			e := newEnrolEnv(t)
			old := e.enrolled()
			e.apiary.enrolReply = func(n int) enrolAnswer {
				switch n {
				case 1:
					return enrolAnswer{status: http.StatusCreated}
				case 2:
					return enrolAnswer{drop: true}
				}
				return refusal
			}
			e.writeCode(enrolCode(codeCore2, e.apiary.server))
			before := stateBytes(t, e.settings.StateDir)
			r, creds := e.reenroller()
			r.look(context.Background())
			sent := e.apiary.enrolled()
			pub, _ := accesskey.ParsePublicKey(sent[len(sent)-1].PublicKey)
			lines := e.lines("did not finish is dropped")
			if len(sent) != 3 || len(lines) != 1 || lines[0]["fingerprint"] != pub.Fingerprint() {
				t.Errorf("enrolled %d times; the log: %s", len(sent), e.log.String())
			}
			if creds.get().key.PublicKey() != old.key.PublicKey() || fmt.Sprint(stateBytes(t, e.settings.StateDir)) != fmt.Sprint(before) {
				t.Error("the enrolment changed")
			}
		})
		t.Run("at first start, "+fmt.Sprint(refusal.status), func(t *testing.T) {
			e := newEnrolEnv(t)
			e.apiary.enrolReply = func(n int) enrolAnswer {
				switch n {
				case 1:
					return enrolAnswer{drop: true}
				case 2:
					return refusal
				}
				return enrolAnswer{status: http.StatusCreated}
			}
			e.writeCode(enrolCode(codeCore, e.apiary.server))
			e.onWait = func(n int) {
				switch n {
				case 2:
					os.Remove(e.codeFile)
				case 3:
					e.writeCode(enrolCode(codeCore2, e.apiary.server))
				}
			}
			got, err := e.enrol()
			if err != nil {
				t.Fatal(err)
			}
			e.checkKept(got)
			sent := e.apiary.enrolled()
			first, _ := accesskey.ParsePublicKey(sent[0].PublicKey)
			lines := e.lines("did not finish is dropped")
			if len(sent) != 3 || len(lines) != 1 || lines[0]["fingerprint"] != first.Fingerprint() || got.key.PublicKey() == first {
				t.Errorf("enrolled %d times; the log: %s", len(sent), e.log.String())
			}
		})
	}
}

// TestServeMovesTheKeyInUseBeforeItLooksAgain pins that after a re-enrolment whose key
// could not be moved into its file, the next look moves it before anything else, so
// the pending file, the only copy on disk of the key in use, is never removed, and a
// later re-enrolment and a start both find a whole enrolment.
func TestServeMovesTheKeyInUseBeforeItLooksAgain(t *testing.T) {
	e := newEnrolEnv(t)
	e.enrolled()
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	rename = func(from, to string) error {
		if filepath.Base(to) == accessKeyFile {
			return errors.New("a rename that fails")
		}
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	r, creds := e.reenroller()
	r.look(context.Background())
	second := creds.get()
	lines := e.lines("could not be moved into its file")
	if len(lines) != 1 || lines[0]["msg"] != "enrolled in Qory Apiary with a new key, which signs every request from now on, but could not be moved into its file, which still holds the old key: serve moves it at the next look, and a start moves it" || len(e.lines("in place of the old one, dropped")) != 0 {
		t.Errorf("the log: %s", e.log.String())
	}
	rename = os.Rename
	// A new code: the next look moves the key in use first, then enrols a third key.
	third := "qeci_" + strings.Repeat("Z", 26) + "." + e.apiary.server.Fingerprint()
	e.writeCode(third)
	r.look(context.Background())
	if n := len(e.lines("the key in use is now in its file, in place of the old one, dropped")); n != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
	sent := e.apiary.enrolled()
	if len(sent) != 3 || creds.get().key.PublicKey().String() != sent[2].PublicKey || creds.get().key.PublicKey() == second.key.PublicKey() {
		t.Fatalf("enrolled %d times", len(sent))
	}
	kept, err := loadKept(e.settings.StateDir, slog.New(slog.DiscardHandler))
	if err != nil || kept.key.PublicKey() != creds.get().key.PublicKey() {
		t.Errorf("%v %v", kept.key, err)
	}
	noCode(t, e.log.String())
}

// TestServeKeepsTheEnrolmentFileBeforeTheKey pins keep's order, at first start and at
// a re-enrolment: enrolment.json is renamed into place before the key is renamed onto
// access-key, which drops the old key last.
func TestServeKeepsTheEnrolmentFileBeforeTheKey(t *testing.T) {
	var order []string
	rename = func(from, to string) error {
		order = append(order, filepath.Base(to))
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	e := newEnrolEnv(t)
	e.enrolled()
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	r, _ := e.reenroller()
	r.look(context.Background())
	if want := []string{enrolmentFile, accessKeyFile, enrolmentFile, accessKeyFile}; fmt.Sprint(order) != fmt.Sprint(want) {
		t.Errorf("renamed %v, want %v", order, want)
	}
}

// TestServeRemovesAKeyEnrolledElsewhereOnceEnrolled pins B1's line at a re-enrolment:
// the pending key's secret is removed, the line says so and asks for the revoke, and
// the key in use stays.
func TestServeRemovesAKeyEnrolledElsewhereOnceEnrolled(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.apiary.enrolReply = func(n int) enrolAnswer {
		if n == 2 {
			return enrolAnswer{status: http.StatusCreated, kind: "pool", node: "np_0123456789abcdef"}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	before := stateBytes(t, e.settings.StateDir)
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	r, creds := e.reenroller()
	r.look(context.Background())
	lines := e.lines("Qory Apiary enrolled the key")
	if len(lines) != 1 || lines[0]["msg"] != "Qory Apiary enrolled the key for a node of another kind than an adapter, so serve does not use it: its secret is removed from the state directory; have an instance admin of Qory Apiary revoke the key; the key in use stays, and serve looks at the file enrolment_code_file names again when Qory Apiary next answers a request 401" || lines[0]["node_id"] != "np_0123456789abcdef" {
		t.Errorf("the log: %s", e.log.String())
	}
	if creds.get().key.PublicKey() != old.key.PublicKey() || fmt.Sprint(stateBytes(t, e.settings.StateDir)) != fmt.Sprint(before) {
		t.Error("the enrolment changed, or the pending key is left")
	}
}

// TestServeSaysWhenItCannotRemoveAKeyEnrolledElsewhere pins B1's line when the pending
// key's file cannot be removed: it says the state directory still holds the secret.
func TestServeSaysWhenItCannotRemoveAKeyEnrolledElsewhere(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes a file from a directory it may not write")
	}
	e := newEnrolEnv(t)
	dir := e.settings.StateDir
	e.apiary.enrolReply = func(n int) enrolAnswer {
		if n == 1 {
			os.Chmod(dir, 0o500)
			return enrolAnswer{status: http.StatusCreated, kind: "pool", node: "np_0123456789abcdef"}
		}
		return enrolAnswer{status: http.StatusCreated}
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	var left bool
	e.onWait = func(n int) {
		if n == 1 {
			_, err := os.Lstat(filepath.Join(dir, pendingKeyFile))
			left = err == nil
			os.Chmod(dir, 0o700)
			e.writeCode(enrolCode(codeCore2, e.apiary.server))
		}
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server))
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
	lines := e.lines("Qory Apiary enrolled the key")
	if !left || len(lines) != 1 || lines[0]["msg"] != "Qory Apiary enrolled the key for a node of another kind than an adapter, so serve does not use it: its secret could not be removed from access-key.pending in the state directory, which still holds it; have an instance admin of Qory Apiary revoke the key; waiting for a new code in the file enrolment_code_file names" || lines[0]["error"] == nil {
		t.Errorf("left %v; the log: %s", left, e.log.String())
	}
	noCode(t, e.log.String())
}

// TestServeEnrolsFromAnotherUsersCodeFile pins that the code file, which core writes as
// the user nobody, 0644, has no owner or mode check, unlike the secret files: serve
// enrols from it.
func TestServeEnrolsFromAnotherUsersCodeFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chowning the code file to another user needs root")
	}
	e := newEnrolEnv(t)
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	if err := os.Chown(e.codeFile, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.codeFile, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := e.enrol()
	if err != nil {
		t.Fatal(err)
	}
	e.checkKept(got)
}

// TestServeWaitsBeforeALookAndTakesTheAsksMeanwhileAsOne pins the reenroller's wait
// after an ask: it asks for [reenrolDebounce], and the asks made during the wait make
// the one look after it, with no second wait and look. A code file that cannot be read
// is said once at each look, which ends there.
func TestServeWaitsBeforeALookAndTakesTheAsksMeanwhileAsOne(t *testing.T) {
	e := newEnrolEnv(t)
	e.enrolled()
	if err := os.Mkdir(e.codeFile, 0o755); err != nil {
		t.Fatal(err)
	}
	waiting, release := make(chan struct{}), make(chan struct{})
	e.onWait = func(n int) {
		if n == 1 {
			close(waiting)
			<-release
		}
	}
	r, _ := e.reenroller()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx) }()
	defer func() { cancel(); <-done }()
	const unreadable = "the enrolment code cannot be read; the key in use stays, and serve looks at the file enrolment_code_file names again when Qory Apiary next answers a request 401"
	eventually(t, "the look at start", func() bool { return len(e.lines(unreadable)) == 1 })
	r.refused()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("no wait after the ask")
	}
	r.refused()
	r.refused()
	close(release)
	eventually(t, "the look after the wait", func() bool { return len(e.lines(unreadable)) == 2 })
	time.Sleep(100 * time.Millisecond)
	if w := e.waited(); len(w) != 1 || w[0] != reenrolDebounce || len(e.lines(unreadable)) != 2 {
		t.Errorf("waited %v; the log: %s", w, e.log.String())
	}
	if n := len(e.apiary.enrolled()); n != 1 {
		t.Errorf("enrolled %d times", n)
	}
}

// otherAdapterID is the id of a new adapter record in Qory Apiary, as after a Remove.
const otherAdapterID = "na_fedcba9876543210"

// seedRecordState opens the store in dir, records it as the adapter record owner's,
// keeps a value in each namespace of [recordState], the cursor, the sync interval,
// the instance id, a repository, an installation GitHub deleted and one not linked,
// and closes it.
func seedRecordState(t *testing.T, dir, owner string) {
	t.Helper()
	st := openStore(t, dir)
	defer st.Close()
	if err := ownState(st, owner, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	for _, ns := range recordState.Namespaces {
		if err := st.Put(ns, "k", []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
	}
	for _, kv := range [][2]string{{nsAdapter, keyCursor}, {nsAdapter, keySyncInterval}, {nsAdapter, keyInstanceID}, {nsRepositories, "7"}, {nsDeleted, "7"}, {nsUnlinked, "7"}} {
		if err := st.Put(kv[0], kv[1], []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
	}
}

// recordStateLeft is how many of the values [seedRecordState] keeps for the adapter
// record are left in the store in dir, in the namespaces of [recordState] and in the
// adapter namespace, a value the feed wrote since not among them, whether the
// instance id and the installations' values, which belong to the App, are, and the
// record the store names.
func recordStateLeft(t *testing.T, dir string) (left, leftInAdapter int, appKept bool, owner string) {
	t.Helper()
	st := openStore(t, dir)
	defer st.Close()
	seeded := func(ns, k string) bool {
		b, err := st.Get(ns, k)
		return err == nil && string(b) == "v"
	}
	for _, ns := range recordState.Namespaces {
		if seeded(ns, "k") {
			left++
		}
	}
	for _, k := range []string{keyCursor, keySyncInterval} {
		if seeded(nsAdapter, k) {
			leftInAdapter++
		}
	}
	b, _ := st.Get(nsAdapter, keyAdapterID)
	return left, leftInAdapter, seeded(nsAdapter, keyInstanceID) && seeded(nsRepositories, "7") && seeded(nsDeleted, "7") && seeded(nsUnlinked, "7"), string(b)
}

// TestOwnStateDropsAnotherRecordsStateAlone pins what a new adapter record drops of
// the store, and that the same record drops nothing and says nothing.
func TestOwnStateDropsAnotherRecordsStateAlone(t *testing.T) {
	want := []string{nsInstallations, nsCollections, nsPulls, nsEnvironments, nsForbidden, nsReplaced, nsPasses, nsConnectSessions, nsConnectNonces, nsGrants}
	if fmt.Sprint(recordState.Namespaces) != fmt.Sprint(want) || fmt.Sprint(recordState.Keys) != fmt.Sprint(map[string][]string{nsAdapter: {keyCursor, keySyncInterval}}) {
		t.Errorf("a new record drops %v", recordState)
	}
	dir := filepath.Join(t.TempDir(), "state")
	seedRecordState(t, dir, testAdapterID)
	all := len(recordState.Namespaces)
	var log syncBuffer
	st := openStore(t, dir)
	// The same record keeps everything, and says nothing.
	if err := ownState(st, testAdapterID, slog.New(slog.NewJSONHandler(&log, nil))); err != nil || log.String() != "" {
		t.Fatalf("%v %s", err, log.String())
	}
	st.Close()
	if left, inAdapter, app, owner := recordStateLeft(t, dir); left != all || inAdapter != 2 || !app || owner != testAdapterID {
		t.Fatalf("left %d and %d, the App's kept %v, the record %s", left, inAdapter, app, owner)
	}
	// Another record drops the old one's state, and keeps the App's.
	st = openStore(t, dir)
	if err := ownState(st, otherAdapterID, slog.New(slog.NewJSONHandler(&log, nil))); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if left, inAdapter, app, owner := recordStateLeft(t, dir); left != 0 || inAdapter != 0 || !app || owner != otherAdapterID {
		t.Errorf("left %d and %d, the App's kept %v, the record %s", left, inAdapter, app, owner)
	}
	var line map[string]any
	json.Unmarshal([]byte(log.String()), &line)
	dropped, _ := line["dropped"].(map[string]any)
	if line["msg"] != "the adapter is enrolled as another adapter in Qory Apiary, so serve dropped the data in its store for the old one: the installations' links, the linked collections, their pulls and the environment_refs sent for them, the connections' state, the connect flows, the copy of the grants, the change feed's cursor and the sync interval" ||
		line["old_adapter_id"] != testAdapterID || line["adapter_id"] != otherAdapterID || dropped[nsInstallations] != 1.0 || dropped[nsAdapter] != 2.0 || len(dropped) != all+1 {
		t.Errorf("the log: %s", log.String())
	}
}

// TestOwnStateDropsTheSentEnvironmentRef pins that a new adapter record drops the
// environment_ref sent for a collection, so a push after the re-enrolment lists the
// collection to the new record again, and that the line says it.
func TestOwnStateDropsTheSentEnvironmentRef(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	if err := ownState(st, testAdapterID, slog.New(slog.NewJSONHandler(&log, nil))); err != nil {
		t.Fatal(err)
	}
	if err := keepEnvironment(st, gadgetsRef, "env-1"); err != nil {
		t.Fatal(err)
	}
	if env, err := sentEnvironment(st, gadgetsRef); err != nil || env != "env-1" {
		t.Fatalf("the environment_ref kept: %q, %v", env, err)
	}
	if err := ownState(st, otherAdapterID, slog.New(slog.NewJSONHandler(&log, nil))); err != nil {
		t.Fatal(err)
	}
	if env, err := sentEnvironment(st, gadgetsRef); err != nil || env != "" {
		t.Errorf("the environment_ref left: %q, %v", env, err)
	}
	var line map[string]any
	json.Unmarshal([]byte(log.String()), &line)
	dropped, _ := line["dropped"].(map[string]any)
	if msg, _ := line["msg"].(string); !strings.Contains(msg, "environment_refs") || dropped[nsEnvironments] != 1.0 {
		t.Errorf("the log: %s", log.String())
	}
}

// TestServeLogsAPinOrAnIDChange pins the line of a re-enrolment whose 201 lists another
// pin or names another adapter, and that one with neither says nothing of it.
func TestServeLogsAPinOrAnIDChange(t *testing.T) {
	for name, tc := range map[string]struct {
		newServer bool
		node      string
		logs      bool
	}{
		"neither":    {false, "", false},
		"the pin":    {true, "", true},
		"the id":     {false, otherAdapterID, true},
		"pin and id": {true, otherAdapterID, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnrolEnv(t)
			old := e.enrolled()
			if tc.newServer {
				e.apiary.server = newKey(t)
			}
			e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{status: http.StatusCreated, node: tc.node} }
			e.writeCode(enrolCode(codeCore2, e.apiary.server))
			r, creds := e.reenroller()
			r.look(context.Background())
			got := creds.get()
			lines := e.lines("changes what serve trusts")
			if !tc.logs {
				if len(lines) != 0 {
					t.Errorf("the log: %s", e.log.String())
				}
				return
			}
			if len(lines) != 1 || lines[0]["msg"] != "the new key's enrolment changes what serve trusts or which adapter it is in Qory Apiary: Qory Apiary's pin, the adapter's id, or both" ||
				lines[0]["old_adapter_id"] != old.adapterID || lines[0]["adapter_id"] != got.adapterID ||
				lines[0]["old_pin"] != pinFingerprints(old.pin) || lines[0]["pin"] != pinFingerprints(got.pin) {
				t.Errorf("the log: %s", e.log.String())
			}
			if tc.node != "" && got.adapterID != tc.node || tc.newServer && pinFingerprints(got.pin) == pinFingerprints(old.pin) {
				t.Errorf("the enrolment in use %s %v", got.adapterID, got.pin)
			}
			noCode(t, e.log.String())
		})
	}
}

// TestRunDropsTheOldRecordsStateAtANewRecord runs serve whole, declared with the old
// key: a re-enrolment that makes the adapter a new record drops what the store held
// for the old one; one in the same record keeps everything; and after each, the
// adapter is declared again, signed with the new key.
func TestRunDropsTheOldRecordsStateAtANewRecord(t *testing.T) {
	for _, node := range []string{otherAdapterID, testAdapterID} {
		t.Run(node, func(t *testing.T) {
			e := newEnrolEnv(t)
			old := e.enrolled()
			seedRecordState(t, e.settings.StateDir, testAdapterID)
			e.apiary.enrolKeyIDs = []string{"ak_fedcba9876543210"}
			e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{status: http.StatusCreated, node: node} }
			stop := runServe(t, e.settings, e.opts(), e.log)
			eventually(t, "declared", func() bool { return len(e.apiary.sent(routeAdapter)) > 0 })
			e.apiary.revoke(old.key.PublicKey())
			e.writeCode(enrolCode(codeCore2, e.apiary.server))
			withNewKey := func(route string) int {
				n := 0
				for _, r := range e.apiary.sent(route) {
					if r.keyID == "ak_fedcba9876543210" {
						n++
					}
				}
				return n
			}
			eventually(t, "a read of the feed with the new key", func() bool { return withNewKey("GET "+routeChanges) > 0 })
			stop()
			// The feed writes its cursor as it reads, so the same record's is not checked,
			// and it replaces the copy of the grants with Qory Apiary's at its start, so
			// the seeded grant is gone in the same record too.
			left, inAdapter, app, owner := recordStateLeft(t, e.settings.StateDir)
			dropLines := e.lines("so serve dropped the data in its store for the old one")
			if node == otherAdapterID {
				if left != 0 || inAdapter != 0 || !app || owner != otherAdapterID || len(dropLines) != 1 || withNewKey(routeAdapter) == 0 {
					t.Errorf("left %d and %d, the App's kept %v, the record %s, declared %d times; the log: %s", left, inAdapter, app, owner, withNewKey(routeAdapter), e.log.String())
				}
			} else if left != len(recordState.Namespaces)-1 || !app || owner != testAdapterID || len(dropLines) != 0 || withNewKey(routeAdapter) == 0 {
				t.Errorf("left %d, the App's kept %v, the record %s, declared %d times; the log: %s", left, app, owner, withNewKey(routeAdapter), e.log.String())
			}
			noCode(t, e.log.String())
		})
	}
}

// TestANewRecordStoresTheAppAfterItsDeclaration pins that a re-enrolment that makes
// the adapter a new record stores the App in use there only after the adapter is
// declared there, signed with the new key: the fake, as Qory Apiary does, refuses a
// secret that the source role of the record's latest description does not list, and
// a new record has none before its first start-up body.
func TestANewRecordStoresTheAppAfterItsDeclaration(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	e.apiary.enrolKeyIDs = []string{"ak_fedcba9876543210"}
	e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{status: http.StatusCreated, node: otherAdapterID} }
	stop := runServe(t, e.settings, e.opts(), e.log)
	eventually(t, "declared", func() bool { return len(e.apiary.sent(routeAdapter)) > 0 })
	before := len(e.apiary.uploaded())
	e.apiary.revoke(old.key.PublicKey())
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	eventually(t, "the App stored in the new record", func() bool { return len(e.apiary.uploaded()) > before })
	stop()
	e.apiary.mu.Lock()
	declaredAt, uploadedAt := -1, -1
	for i, r := range e.apiary.requests {
		if r.method != http.MethodPost || r.keyID != "ak_fedcba9876543210" {
			continue
		}
		if r.target == routeAdapter && declaredAt < 0 {
			declaredAt = i
		}
		if r.target == routeSecrets && uploadedAt < 0 {
			uploadedAt = i
		}
	}
	listed := e.apiary.described[otherAdapterID]
	e.apiary.mu.Unlock()
	if declaredAt < 0 || uploadedAt < declaredAt || len(listed) != 4 {
		t.Errorf("declared in the new record at %d, uploaded at %d, with the secrets %v listed", declaredAt, uploadedAt, listed)
	}
	if got, err := appOf(e.apiary.uploaded()[before]); err != nil || got.id != testApp().id || got.slug != testApp().slug {
		t.Errorf("the new record stores the App %v: %v", got, err)
	}
	if lines := e.lines("storing the GitHub App in the new adapter"); len(lines) != 0 {
		t.Errorf("the log: %v", lines)
	}
}

// TestRunFinishesADropAStopCutShort pins that a start that finds the enrolment of a
// new record beside a store that holds the old record's state, as a stop between the
// swap and the drop leaves, drops that state before it serves.
func TestRunFinishesADropAStopCutShort(t *testing.T) {
	e := newEnrolEnv(t)
	e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{status: http.StatusCreated, node: otherAdapterID} }
	e.enrolled()
	seedRecordState(t, e.settings.StateDir, testAdapterID)
	stop := runServe(t, e.settings, e.opts(), e.log)
	stop()
	if left, inAdapter, app, owner := recordStateLeft(t, e.settings.StateDir); left != 0 || inAdapter != 0 || !app || owner != otherAdapterID || len(e.lines("so serve dropped the data in its store for the old one")) != 1 {
		t.Errorf("left %d and %d, the App's kept %v, the record %s; the log: %s", left, inAdapter, app, owner, e.log.String())
	}
}

// TestServeSaysWhenItCannotDropTheOldRecordsState pins that a new record's enrolment
// whose drop of the old record's state fails is put in use, with a line that says a
// start drops it.
func TestServeSaysWhenItCannotDropTheOldRecordsState(t *testing.T) {
	e := newEnrolEnv(t)
	e.enrolled()
	e.apiary.enrolReply = func(int) enrolAnswer { return enrolAnswer{status: http.StatusCreated, node: otherAdapterID} }
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	r, creds := e.reenroller()
	var put []string
	r.inUse = func(got enrolment) error {
		creds.set(got)
		put = append(put, got.adapterID)
		return errors.New("a drop that fails")
	}
	r.look(context.Background())
	lines := e.lines("what the store holds for the old adapter could not be dropped; a start drops it")
	if len(put) != 1 || put[0] != otherAdapterID || creds.get().adapterID != otherAdapterID || len(lines) != 1 || lines[0]["error"] != "a drop that fails" {
		t.Errorf("put %v; the log: %s", put, e.log.String())
	}
}

// TestServeSaysTrulyWhetherTheKeyInUseIsInItsFile pins the line of a look that cannot
// move the key in use into its file first: it says the key is still not there while
// access-key.pending is there, whether or not it reads as a key, and that it was moved
// when the rename went through and what follows failed.
func TestServeSaysTrulyWhetherTheKeyInUseIsInItsFile(t *testing.T) {
	e := newEnrolEnv(t)
	e.enrolled()
	e.writeCode(enrolCode(codeCore2, e.apiary.server))
	keyPath := filepath.Join(e.settings.StateDir, accessKeyFile)
	rename = func(from, to string) error {
		if filepath.Base(to) == accessKeyFile {
			return errors.New("a rename that fails")
		}
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	r, _ := e.reenroller()
	r.look(context.Background())
	r.look(context.Background())
	const still = "the key in use is still not in its file; serve tries again at the next look, and looks for no code until then"
	const moved = "the key in use was moved into its file, but the state directory could not be read back as a start reads it; serve tries again at the next look, and looks for no code until then"
	if len(e.lines(still)) != 1 || len(e.lines(moved)) != 0 {
		t.Fatalf("the log: %s", e.log.String())
	}
	// A pending file that is there but cannot be read as a key is still the key in use.
	pendingPath := filepath.Join(e.settings.StateDir, pendingKeyFile)
	if err := os.Chmod(pendingPath, 0o644); err != nil {
		t.Fatal(err)
	}
	r.look(context.Background())
	if len(e.lines(still)) != 2 || len(e.lines(moved)) != 0 {
		t.Fatalf("the log: %s", e.log.String())
	}
	if err := os.Chmod(pendingPath, 0o600); err != nil {
		t.Fatal(err)
	}
	// The rename goes through, and the key's file, readable by others, is refused.
	rename = func(from, to string) error {
		if err := os.Rename(from, to); err != nil {
			return err
		}
		return os.Chmod(to, 0o644)
	}
	r.look(context.Background())
	if len(e.lines(still)) != 2 || len(e.lines(moved)) != 1 {
		t.Fatalf("the log: %s", e.log.String())
	}
	rename = os.Rename
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	r.look(context.Background())
	if len(e.lines("the key in use is now in its file, in place of the old one, dropped")) != 1 || len(e.lines(still)) != 2 || len(e.lines(moved)) != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
	noCode(t, e.log.String())
}

// TestServeComparesAPinAsASet pins that a new enrolment whose pin holds the same keys
// in another order logs no change of what serve trusts, and one with another key does.
func TestServeComparesAPinAsASet(t *testing.T) {
	e := newEnrolEnv(t)
	old := e.enrolled()
	r, creds := e.reenroller()
	a, b, c := pinOf(newKey(t))[0], pinOf(newKey(t))[0], pinOf(newKey(t))[0]
	old.pin = accesskey.Pin{a, b}
	got := old
	got.pin = accesskey.Pin{b, a}
	r.use(old, got)
	if len(e.lines("changes what serve trusts")) != 0 || fmt.Sprint(creds.get().pin) != fmt.Sprint(got.pin) {
		t.Errorf("the log: %s", e.log.String())
	}
	got.pin = accesskey.Pin{b, c}
	r.use(old, got)
	if len(e.lines("changes what serve trusts")) != 1 {
		t.Errorf("the log: %s", e.log.String())
	}
}
