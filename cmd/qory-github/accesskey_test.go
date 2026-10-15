package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// codeCore is the 26 characters of the enrolment codes the tests use, which no output
// may contain.
const codeCore = "0123456789ABCDEFGHJKMNPQRS"

// fakeApiary is Qory Apiary's enrolment endpoint as enrol uses it. It answers each
// enrolment with status and, for a 201, the access key id, an id of kind, and its
// signing key listed; answer may change the body and the signature before they are sent.
type fakeApiary struct {
	url      string
	signer   *accesskey.Key
	requests atomic.Int32
	got      atomic.Pointer[accesskey.EnrolmentRequest]
}

// answer is what the fake sends: the status, the body and the signature, which a test
// may change from the correctly signed ones it is handed.
type answer func(status int, body []byte, sig string) (int, []byte, string)

func newFakeApiary(t *testing.T, status int, kind, nodeID string, change answer) *fakeApiary {
	t.Helper()
	signer, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeApiary{signer: signer}
	listed := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != accesskey.EnrolmentPath {
			http.NotFound(w, r)
			return
		}
		var req accesskey.EnrolmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.VerifyProof() {
			t.Errorf("the enrolment request does not verify: %v", err)
			w.WriteHeader(http.StatusConflict)
			return
		}
		f.got.Store(&req)
		var doc any
		switch status {
		case http.StatusCreated:
			doc = map[string]any{"version": 1, "access_key_id": "ak_0123456789abcdef", "node_id": nodeID, "node_kind": kind, "stored_secrets": false, "apiary_public_key": listed}
		case http.StatusUnauthorized:
			w.WriteHeader(status)
			return
		default:
			doc = map[string]any{"error": "key_limit", "apiary_public_key": listed}
		}
		body, _ := json.Marshal(doc)
		sig := signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: status, RequestSignature: req.Proof, Body: body})
		st := status
		if change != nil {
			st, body, sig = change(status, body, sig)
		}
		w.Header().Set(accesskey.HeaderSignature, sig)
		w.WriteHeader(st)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// code is an enrolment code that carries the fingerprint of key, as a person copies it.
func code(key *accesskey.Key) string {
	return "qec_" + codeCore[:13] + "-" + codeCore[13:] + "." + key.Fingerprint()
}

// enrolRun runs access-key enrol with factory on, and a fixed host name.
func enrolRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("QORY_FEATURES", "factory")
	defer func(h func() (string, error)) { hostname = h }(hostname)
	hostname = func() (string, error) { return "adapter-host.example.com", nil }
	var out, errs bytes.Buffer
	c := run(context.Background(), append([]string{"access-key", "enrol"}, args...), &out, &errs)
	return c, out.String(), errs.String()
}

// noLeak fails the test when an output contains the secret, the code or its 26
// characters.
func noLeak(t *testing.T, secret, code string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, v := range []string{secret, code, codeCore, codeCore[:13], codeCore[13:]} {
			if v != "" && strings.Contains(o, v) {
				t.Errorf("an output contains a secret or the code: %q", o)
			}
		}
		if strings.Contains(o, accesskey.SecretPrefix) {
			t.Errorf("an output contains %s: %q", accesskey.SecretPrefix, o)
		}
	}
}

func TestEnrolWritesTheSecretAndPrintsTheSettings(t *testing.T) {
	f := newFakeApiary(t, http.StatusCreated, "adapter", "na_0123456789abcdef", nil)
	file := filepath.Join(t.TempDir(), "access-key-secret")
	c := code(f.signer)
	status, out, errs := enrolRun(t, "--secret-file", file, f.url+"/", c)
	if status != 0 {
		t.Fatalf("exit %d: %s", status, errs)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the secret file: %v, %v", info, err)
	}
	b, _ := os.ReadFile(file)
	key, err := accesskey.ParseSecret(strings.TrimSuffix(string(b), "\n"))
	if err != nil || !strings.HasSuffix(string(b), "\n") || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("the secret file holds no secret: %v", err)
	}
	got := f.got.Load()
	if got.PublicKey != key.PublicKey().String() || got.Name != "adapter-host.example.com" || got.Code != "qec_"+codeCore+"."+f.signer.Fingerprint() {
		t.Errorf("enrolled %s named %q with the code %q; the secret file holds %s", got.PublicKey, got.Name, got.Code, key.PublicKey())
	}
	pin, _ := json.Marshal(accesskey.Pin{{Alg: "ed25519", PublicKey: f.signer.PublicKey().String()}})
	fileJSON, _ := json.Marshal(file)
	wantOut := `  "apiary_url": "` + f.url + `",
  "access_key_id": "ak_0123456789abcdef",
  "access_key_secret_file": ` + string(fileJSON) + `,
  "apiary_public_key": ` + string(pin) + `
`
	if out != wantOut {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, wantOut)
	}
	// The settings are members of serve's settings object.
	var settings map[string]any
	if err := json.Unmarshal([]byte("{"+out+"}"), &settings); err != nil || len(settings) != 4 {
		t.Errorf("the settings are not four members of a JSON object: %v", err)
	}
	fp := key.Fingerprint()
	wantErrs := "access key fingerprint " + fp + "\n" +
		"enrolled as ak_0123456789abcdef in the work source na_0123456789abcdef\n" +
		"wrote the access key's secret to " + file + "\n" +
		"add these settings to serve's settings:\n" +
		"compare the fingerprint " + fp + " with the one Qory Apiary shows on the integration's page; the key is active\n"
	if errs != wantErrs {
		t.Errorf("stderr:\n%s\nwant:\n%s", errs, wantErrs)
	}
	noLeak(t, key.Secret(), c, out, errs)
}

// TestEnrolRefusesWhatItCannotWriteBeforeAnyRequest pins that a secret file that exists,
// or whose directory does not, and a server that is not Qory Apiary's origin over https
// are refused before the code is sent.
func TestEnrolRefusesWhatItCannotWriteBeforeAnyRequest(t *testing.T) {
	f := newFakeApiary(t, http.StatusCreated, "adapter", "na_0123456789abcdef", nil)
	dir := t.TempDir()
	exists := filepath.Join(dir, "exists")
	os.WriteFile(exists, []byte("kept\n"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(filepath.Join(dir, "nowhere"), link)
	file := filepath.Join(dir, "secret")
	c := code(f.signer)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--secret-file", exists, f.url, c}, "the secret file " + exists + " exists; choose another or move it away"},
		{[]string{"--secret-file", link, f.url, c}, "the secret file " + link + " exists; choose another or move it away"},
		{[]string{"--secret-file", filepath.Join(dir, "none", "secret"), f.url, c}, "the secret file's directory: stat " + filepath.Join(dir, "none") + ": no such file or directory"},
		{[]string{"--secret-file", filepath.Join(exists, "secret"), f.url, c}, "the secret file: lstat " + filepath.Join(exists, "secret") + ": not a directory"},
		{[]string{"--secret-file", filepath.Join(dir, "sec\nret"), f.url, c}, "the secret file's path " + strconv.Quote(filepath.Join(dir, "sec\nret")) + " contains a control character; choose another with --secret-file"},
		{[]string{"--secret-file", filepath.Join(dir, "sec\u009bret"), f.url, c}, "the secret file's path " + strconv.Quote(filepath.Join(dir, "sec\u009bret")) + " contains a control character; choose another with --secret-file"},
		{[]string{"--secret-file", filepath.Join(dir, "sec\xffret"), f.url, c}, "the secret file's path " + strconv.Quote(filepath.Join(dir, "sec\xffret")) + " is not UTF-8; choose another with --secret-file"},
		{[]string{"--secret-file", file, "http://apiary.example.com", c}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, "ftp://apiary.example.com", c}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, "https://apiary.example.com/enrol", c}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, "https://user@apiary.example.com", c}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, "https://apiary.example.com?a=1", c}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, c, f.url}, "the server is neither an https URL"},
		{[]string{"--secret-file", file, f.url, "qec_" + codeCore + "U." + f.signer.Fingerprint()}, "the code is not an enrolment code"},
		{[]string{"--secret-file", file, f.url, "qec_" + codeCore + ".!" + f.signer.Fingerprint()}, "the code is not an enrolment code"},
		{[]string{"--secret-file", file, f.url}, "want two arguments, the server and the code"},
		{[]string{f.url, c}, "--secret-file is required"},
	} {
		status, out, errs := enrolRun(t, tc.args...)
		if status != 1 || out != "" || !strings.HasPrefix(errs, "qory-github access-key: "+tc.want) || strings.Count(errs, "\n") != 1 {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tc.args, status, out, errs)
		}
		noLeak(t, "", c, out, errs)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
	if b, _ := os.ReadFile(exists); string(b) != "kept\n" {
		t.Errorf("the file that exists was written: %q", b)
	}
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a secret file was written: %v", err)
	}
}

// TestEnrolRefusesAnAnswerItCannotTrust pins that an answer whose signature does not
// verify under the key the code names, a refusal, and a key enrolled for another kind
// than an adapter write nothing, and say so in one line without the code.
func TestEnrolRefusesAnAnswerItCannotTrust(t *testing.T) {
	other, _ := accesskey.Generate()
	for name, tc := range map[string]struct {
		status       int
		kind, nodeID string
		change       answer
		otherCode    bool
		want         string
	}{
		"a bad signature": {status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: func(s int, b []byte, sig string) (int, []byte, string) {
			return s, b, other.SignAnswer(accesskey.Answer{Enrolment: true, Status: s, Body: b})
		}, want: "Qory Apiary did not enrol the key (HTTP 201, unsigned); no secret was written: get a new code, and have an owner or administrator in Qory Apiary revoke the key "},
		"a changed body": {status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: func(s int, b []byte, sig string) (int, []byte, string) {
			return s, bytes.Replace(b, []byte("ak_0123456789abcdef"), []byte("ak_0123456789abcdeg"), 1), sig
		}, want: "Qory Apiary did not enrol the key (HTTP 201, unsigned)"},
		"no signature": {status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: func(s int, b []byte, _ string) (int, []byte, string) {
			return s, b, ""
		}, want: "Qory Apiary did not enrol the key (HTTP 201, unsigned)"},
		"another server's key in the code": {status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", otherCode: true,
			want: "Qory Apiary did not enrol the key (HTTP 201, unsigned)"},
		"a node's code": {status: http.StatusCreated, kind: "node", nodeID: "nd_0123456789abcdef",
			want: "Qory Apiary enrolled the key as ak_0123456789abcdef in the node nd_0123456789abcdef, which is not a work source: the code was not made on the integration's page; no secret was written: have an owner or administrator in Qory Apiary revoke the key "},
		"a gateway's code": {status: http.StatusCreated, kind: "gateway", nodeID: "ng_0123456789abcdef",
			want: "Qory Apiary enrolled the key as ak_0123456789abcdef in the gateway ng_0123456789abcdef, which is not a work source"},
		"a kind that does not match the id": {status: http.StatusCreated, kind: "adapter", nodeID: "nd_0123456789abcdef",
			want: `the enrolment did not complete: the enrolment answer: node_kind "adapter" does not match the node id nd_0123456789abcdef; no secret was written`},
		"a used code": {status: http.StatusUnauthorized,
			want: "this code was used or has expired; if you did not use it, tell your administrator in Qory Apiary, who must revoke the key it enrolled. Enrolling needs a new code"},
		"two keys held": {status: http.StatusConflict,
			want: "the work source already holds two keys: once an owner or administrator in Qory Apiary has revoked one, the same command, run within the code's 15 minutes, succeeds"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeApiary(t, tc.status, tc.kind, tc.nodeID, tc.change)
			file := filepath.Join(t.TempDir(), "secret")
			c := code(f.signer)
			if tc.otherCode {
				c = code(other)
			}
			var made *accesskey.Key
			defer func(g func() (*accesskey.Key, error)) { generateKey = g }(generateKey)
			generateKey = func() (*accesskey.Key, error) {
				k, err := accesskey.Generate()
				made = k
				return k, err
			}
			status, out, errs := enrolRun(t, "--secret-file", file, f.url, c)
			if status != 1 || out != "" || !strings.Contains(errs, "\nqory-github access-key: "+tc.want) || strings.Count(errs, "\n") > 3 {
				t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
			}
			if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a secret file was written: %v", err)
			}
			noLeak(t, made.Secret(), c, out, errs)
		})
	}
}

// failingFile is a secret file whose write fails.
type failingFile struct{}

func (failingFile) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }
func (failingFile) Sync() error               { return nil }
func (failingFile) Close() error              { return nil }

// TestEnrolSaysASecretItCouldNotWrite pins that a secret that could not be written once
// the key is enrolled is said to be lost, without the secret, and the file is removed.
func TestEnrolSaysASecretItCouldNotWrite(t *testing.T) {
	f := newFakeApiary(t, http.StatusCreated, "adapter", "na_0123456789abcdef", nil)
	file := filepath.Join(t.TempDir(), "secret")
	defer func(c func(string) (secretFile, error)) { createSecretFile = c }(createSecretFile)
	createSecretFile = func(path string) (secretFile, error) {
		os.WriteFile(path, nil, 0o600)
		return failingFile{}, nil
	}
	var made *accesskey.Key
	defer func(g func() (*accesskey.Key, error)) { generateKey = g }(generateKey)
	generateKey = func() (*accesskey.Key, error) {
		k, err := accesskey.Generate()
		made = k
		return k, err
	}
	c := code(f.signer)
	status, out, errs := enrolRun(t, "--secret-file", file, f.url, c)
	want := "qory-github access-key: the key is enrolled as ak_0123456789abcdef, and the secret file: no space left on device; the secret was not kept: enrol a key again with a new code, and have an owner or administrator in Qory Apiary revoke the key " + made.Fingerprint() + "\n"
	if status != 1 || out != "" || !strings.HasSuffix(errs, want) {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the secret file was kept: %v", err)
	}
	noLeak(t, made.Secret(), c, out, errs)
}

// TestWriteSecretFileNeverWritesOverAFile pins that the secret file is created, never
// written over, even one that appears after enrol checked it.
func TestWriteSecretFileNeverWritesOverAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte("kept\n"), 0o600)
	err := writeSecretFile(file, []byte("qak_new\n"))
	if err == nil || err.Error() != "the secret file "+file+" exists; choose another or move it away" || !errors.Is(err, os.ErrExist) {
		t.Errorf("err %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "kept\n" {
		t.Errorf("the file was written over: %q", b)
	}
}

// usageWithoutFactory is the usage as it was before access-key, which it stays without
// factory.
const usageWithoutFactory = `qory-github mints GitHub App access tokens for Qory's gateway. The agent works on
GitHub and never holds the access token.

usage:
  qory-github <command> [flags]

commands:
  describe     Print the integration's description, for qory
  credential   Mint an access token for a run's repositories
  setup        Create the GitHub App and write its private key

qory-github <command> -h prints a command's help.

More: https://github.com/qoryai/qory-github/blob/main/README.md
`

// TestAccessKeyIsAbsentWithoutFactory pins that, unless QORY_FEATURES names factory,
// access-key is in no usage, which is as it was, and is answered as a command the
// program does not know.
func TestAccessKeyIsAbsentWithoutFactory(t *testing.T) {
	f := newFakeApiary(t, http.StatusCreated, "adapter", "na_0123456789abcdef", nil)
	file := filepath.Join(t.TempDir(), "secret")
	for _, features := range []string{"", "all", "all-security,factory", "factory2", "factory,all"} {
		t.Setenv("QORY_FEATURES", features)
		var out, errs bytes.Buffer
		if code := run(context.Background(), nil, &out, &errs); code != 2 || errs.String() != usageWithoutFactory {
			t.Errorf("QORY_FEATURES=%q: exit %d, usage:\n%s", features, code, errs.String())
		}
		for _, args := range [][]string{{"access-key"}, {"access-key", "-h"}, {"access-key", "enrol", "-h"}, {"access-key", "enrol", "--secret-file", file, f.url, code(f.signer)}} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || errs.String() != usageWithoutFactory || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, %q", features, args, code, errs.String())
			}
		}
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

func TestAccessKeyIsPresentWithFactory(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	var out, errs bytes.Buffer
	if code := run(context.Background(), nil, &out, &errs); code != 2 || !strings.Contains(errs.String(), "\n  serve        Take the GitHub App's webhook deliveries\n  access-key   Enrol the work source's access key with a code from Qory Apiary\n\n") {
		t.Errorf("exit %d, the usage lists no access-key:\n%s", code, errs.String())
	}
	for _, args := range [][]string{{"access-key", "-h"}, {"access-key", "enrol", "-h"}} {
		errs.Reset()
		if code := run(context.Background(), args, &out, &errs); code != 2 || !strings.Contains(errs.String(), "qory-github access-key enrol --secret-file FILE [--] SERVER CODE") || strings.Contains(errs.String(), "More:") {
			t.Errorf("%v exits %d:\n%s", args, code, errs.String())
		}
	}
	for _, args := range [][]string{{"access-key"}, {"access-key", "create"}} {
		errs.Reset()
		if code := run(context.Background(), args, io.Discard, &errs); code != 1 || errs.String() != "qory-github access-key: access-key has one command, enrol: qory-github access-key enrol --secret-file FILE SERVER CODE\n" {
			t.Errorf("%v exits %d: %q", args, code, errs.String())
		}
	}
}
