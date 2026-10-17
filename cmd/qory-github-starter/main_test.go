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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/starter"
)

// codeCore is the 26 characters of the enrolment codes the tests use, which no output
// may contain.
const codeCore = "0123456789ABCDEFGHJKMNPQRS"

// poolID is the node pool the fake enrols every key in.
const poolID = "np_0123456789abcdef"

// fakeApiary is Qory Apiary's enrolment endpoint as enrol uses it.
type fakeApiary struct {
	url      string
	signer   *accesskey.Key
	requests atomic.Int32
	got      atomic.Pointer[accesskey.EnrolmentRequest]
}

// reply is how the fake answers: a 201 names the access key ak_0123456789abcdef in the
// node nodeID of kind; a 401 is unsigned and empty; any other status is a refusal with
// the code refusal. Each but the 401 is signed under the fake's key.
type reply struct {
	status       int
	kind, nodeID string
	refusal      string
}

// poolEnrolled is a reply that enrols the key in a node pool.
var poolEnrolled = reply{status: http.StatusCreated, kind: "pool", nodeID: poolID}

func newFakeApiary(t *testing.T, rp reply) *fakeApiary {
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
		switch rp.status {
		case http.StatusCreated:
			doc = map[string]any{"version": 1, "access_key_id": "ak_0123456789abcdef", "node_id": rp.nodeID, "node_kind": rp.kind, "stored_secrets": false, "apiary_public_key": listed}
		case http.StatusUnauthorized:
			w.WriteHeader(rp.status)
			return
		default:
			doc = map[string]any{"error": rp.refusal, "apiary_public_key": listed}
		}
		body, _ := json.Marshal(doc)
		w.Header().Set(accesskey.HeaderSignature, signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: rp.status, RequestSignature: req.Proof, Body: body}))
		w.WriteHeader(rp.status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// codeOf is an enrolment code with prefix that carries the fingerprint of key, as a
// person copies it.
func codeOf(prefix string, key *accesskey.Key) string {
	return prefix + codeCore[:13] + "-" + codeCore[13:] + "." + key.Fingerprint()
}

// poolCode is a node pool's enrolment code for the fake.
func poolCode(f *fakeApiary) string { return codeOf(accesskey.CodePrefixPool, f.signer) }

// enrolRun runs access-key enrol with factory on and a fixed host name, and returns the
// exit status, stdout, stderr and the key enrol made, nil when it made none.
func enrolRun(t *testing.T, args ...string) (int, string, string, *accesskey.Key) {
	t.Helper()
	t.Setenv("QORY_FEATURES", "factory")
	defer func(h func() (string, error)) { hostname = h }(hostname)
	hostname = func() (string, error) { return "pool-host.example.com", nil }
	var made *accesskey.Key
	defer func(g func() (*accesskey.Key, error)) { generateKey = g }(generateKey)
	generateKey = func() (*accesskey.Key, error) {
		k, err := accesskey.Generate()
		made = k
		return k, err
	}
	var out, errs bytes.Buffer
	c := run(context.Background(), append([]string{"access-key", "enrol"}, args...), &out, &errs)
	return c, out.String(), errs.String(), made
}

// noLeak fails the test when an output contains the secret, the code or its 26
// characters, or what starts a secret.
func noLeak(t *testing.T, key *accesskey.Key, code string, outputs ...string) {
	t.Helper()
	secret := ""
	if key != nil {
		secret = key.Secret()
	}
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

// usageWithoutFactory is the usage without factory: the usage line alone, with no
// description and no command.
const usageWithoutFactory = `usage:
  qory-github-starter <command> [flags]
`

// usageWithFactory is the usage with factory, which lists access-key.
const usageWithFactory = `qory-github-starter serves a node pool of Qory Apiary with GitHub Actions: it claims
the pool's runs and starts a workflow run for each.

usage:
  qory-github-starter <command> [flags]

commands:
  access-key   Enrol the node pool's access key with a code from Qory Apiary

qory-github-starter <command> -h prints a command's help.
`

// TestTheProgramIsAbsentWithoutFactory pins that, unless QORY_FEATURES names factory,
// the program knows no command: whatever it is run with, it prints the usage that lists
// none and describes nothing, naming no hidden feature, command or what the program
// does, on standard error, exits 2, and sends nothing.
func TestTheProgramIsAbsentWithoutFactory(t *testing.T) {
	f := newFakeApiary(t, poolEnrolled)
	file := filepath.Join(t.TempDir(), "secret")
	for _, features := range []string{"", " ", "all", "all-security", "all-security,factory", " all-factory", "factory2", "observability,security", "factory,all", "factory, all-security"} {
		t.Setenv("QORY_FEATURES", features)
		for _, args := range [][]string{nil, {"bogus"}, {"-h"}, {"--help"}, {"help"}, {"serve"}, {"serve", "--settings", "/none.json"}, {"setup"}, {"template"},
			{"access-key"}, {"access-key", "-h"}, {"access-key", "enrol", "-h"}, {"access-key", "enrol", "--secret-file", file, f.url, poolCode(f)}} {
			var out, errs bytes.Buffer
			code := run(context.Background(), args, &out, &errs)
			if code != 2 || errs.String() != usageWithoutFactory || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, %q", features, args, code, errs.String())
			}
			for _, hidden := range []string{"factory", "access-key", "enrol", "settings", "setup", "template", "serve", "Qory Apiary", "node pool", "GitHub", "Actions", "claim", "workflow", "run for each"} {
				if strings.Contains(errs.String(), hidden) {
					t.Errorf("QORY_FEATURES=%q %v: the usage names %s", features, args, hidden)
				}
			}
		}
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a secret file was written: %v", err)
	}
}

// TestAccessKeyIsPresentWithFactory pins the usage with factory, which lists access-key
// alone, access-key's help, and the error of a verb it does not know.
func TestAccessKeyIsPresentWithFactory(t *testing.T) {
	for _, features := range []string{"factory", "observability, factory ", " factory,"} {
		t.Setenv("QORY_FEATURES", features)
		for _, args := range [][]string{nil, {"bogus"}, {"-h"}, {"serve"}, {"setup"}, {"template"}} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || errs.String() != usageWithFactory || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, usage:\n%s", features, args, code, errs.String())
			}
		}
		for _, args := range [][]string{{"access-key", "-h"}, {"access-key", "enrol", "-h"}} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || !strings.HasPrefix(errs.String(), accessKeyHelp.Long+"\n\nusage:\n  qory-github-starter access-key enrol --secret-file FILE [--] SERVER CODE\n") ||
				!strings.Contains(errs.String(), "\nflags:\n  -secret-file string\n    \twhere the access key's secret is written; a file that exists is refused (required)\n") ||
				!strings.HasSuffix(errs.String(), "\nexamples:\n  qory-github-starter access-key enrol --secret-file /etc/qory-github-starter/access-key-secret https://apiary.example.com \"$code\"\n") || out.Len() != 0 {
				t.Errorf("%v exits %d:\n%s", args, code, errs.String())
			}
		}
		for _, args := range [][]string{{"access-key"}, {"access-key", "create"}} {
			var errs bytes.Buffer
			if code := run(context.Background(), args, io.Discard, &errs); code != 1 || errs.String() != "qory-github-starter access-key: access-key has one command, enrol: qory-github-starter access-key enrol --secret-file FILE SERVER CODE\n" {
				t.Errorf("%v exits %d: %q", args, code, errs.String())
			}
		}
	}
}

// TestEnrolWritesTheSecretAndPrintsTheSettings pins the happy path: a node pool's code
// enrols a key named after the host, its secret is written 0600 and alone, and the
// settings printed are five members the starter's settings read, pool_id among them.
func TestEnrolWritesTheSecretAndPrintsTheSettings(t *testing.T) {
	f := newFakeApiary(t, poolEnrolled)
	file := filepath.Join(t.TempDir(), "access-key-secret")
	c := poolCode(f)
	status, out, errs, made := enrolRun(t, "--secret-file", file, f.url+"/", c)
	if status != 0 {
		t.Fatalf("exit %d: %s", status, errs)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the secret file: %v, %v", info, err)
	}
	if b, _ := os.ReadFile(file); string(b) != made.Secret()+"\n" {
		t.Error("the secret file does not hold the key's secret and one line end")
	}
	got := f.got.Load()
	if got.PublicKey != made.PublicKey().String() || got.Name != "pool-host.example.com" || got.Code != "qecp_"+codeCore+"."+f.signer.Fingerprint() {
		t.Errorf("enrolled %s named %q with the code %q", got.PublicKey, got.Name, got.Code)
	}
	pin, _ := json.Marshal(accesskey.Pin{{Alg: "ed25519", PublicKey: f.signer.PublicKey().String()}})
	fileJSON, _ := json.Marshal(file)
	wantOut := `  "apiary_url": "` + f.url + `",
  "access_key_id": "ak_0123456789abcdef",
  "access_key_secret_file": ` + string(fileJSON) + `,
  "apiary_public_key": ` + string(pin) + `,
  "pool_id": "` + poolID + `"
`
	if out != wantOut {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, wantOut)
	}
	fp := made.Fingerprint()
	wantErrs := "access key fingerprint " + fp + "\n" +
		"enrolled as ak_0123456789abcdef in the node pool " + poolID + "\n" +
		"wrote the access key's secret to " + file + "\n" +
		"add these settings to the starter's settings:\n" +
		"compare the fingerprint " + fp + " with the one Qory Apiary shows on the node pool's Access key tab; the key is active\n"
	if errs != wantErrs {
		t.Errorf("stderr:\n%s\nwant:\n%s", errs, wantErrs)
	}
	noLeak(t, made, c, out, errs)

	// The settings printed, with the starter's other fields, are settings the starter
	// reads, and the secret file is one it reads.
	settings := filepath.Join(t.TempDir(), "starter.json")
	doc := "{" + out + `, "listen": "127.0.0.1:8080", "public_url": "https://starter.example.com", "state_dir": "/var/lib/qory-github-starter",
  "app_id": 1, "private_key_file": "/etc/qory-github-starter/app.pem", "repository": "example-org/runners", "workflow": "qory-runner.yml", "ref": "main"}`
	if err := os.WriteFile(settings, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := starter.ReadSettings(settings)
	if err != nil || s.PoolID != poolID || s.ApiaryURL != f.url || s.AccessKeySecretFile != file {
		t.Errorf("the starter's settings: %+v, %v", s, err)
	}
	if k, err := starter.ReadAccessKeySecret(file); err != nil || k.PublicKey().String() != made.PublicKey().String() {
		t.Errorf("the secret file does not read back: %v", err)
	}
}

// TestEnrolRefusesEveryOtherKindBeforeAnyRequest pins that a node's, a gateway's or an
// integration's code, its prefix in either case, is refused with one line that names
// its kind and not the code, before the secret file's directory is probed, a key is
// made or anything is sent.
func TestEnrolRefusesEveryOtherKindBeforeAnyRequest(t *testing.T) {
	f := newFakeApiary(t, poolEnrolled)
	for prefix, what := range map[string]string{
		accesskey.CodePrefixNode:    "a node",
		accesskey.CodePrefixGateway: "a gateway",
		accesskey.CodePrefixAdapter: "an integration",
	} {
		for _, p := range []string{prefix, strings.ToUpper(prefix)} {
			dir := t.TempDir()
			c := codeOf(p, f.signer)
			status, out, errs, made := enrolRun(t, "--secret-file", filepath.Join(dir, "secret"), f.url, c)
			want := "qory-github-starter access-key: this code is for " + what + ": use a code from the node pool's Access key tab\n"
			if status != 1 || out != "" || errs != want || made != nil {
				t.Errorf("%s: exit %d, stdout %q, stderr %q, a key made: %v; want %q", p, status, out, errs, made != nil, want)
			}
			noLeak(t, nil, c, out, errs)
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("%s: the directory holds %v", p, entries)
			}
		}
	}
	// A code that is no enrolment code is refused the same way, naming the pool's
	// prefix.
	c := "qec_" + codeCore + "." + f.signer.Fingerprint()
	status, out, errs, made := enrolRun(t, "--secret-file", filepath.Join(t.TempDir(), "secret"), f.url, c)
	if want := "qory-github-starter access-key: the code is not an enrolment code: qecp_, 26 characters, then a dot and a fingerprint, as Qory Apiary shows it\n"; status != 1 || errs != want || made != nil {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// TestEnrolKeepsNoSecretOfAnotherKindOrARefusal pins that a key Qory Apiary enrolled in
// another kind than a node pool, and an enrolment Qory Apiary refused, write nothing and
// say so in the starter's words, without the secret or the code.
func TestEnrolKeepsNoSecretOfAnotherKindOrARefusal(t *testing.T) {
	for name, tc := range map[string]struct {
		reply reply
		want  string
	}{
		"an integration's key for a pool's code": {reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef"},
			"Qory Apiary enrolled the key as ak_0123456789abcdef for an integration na_0123456789abcdef, which is not a node pool: the code was not made on the node pool's Access key tab; no secret was written: have a workspace admin of Qory Apiary revoke the key {fp}, and enrol with a code made on the node pool's Access key tab\n"},
		"a node's key for a pool's code": {reply{status: http.StatusCreated, kind: "node", nodeID: "nd_0123456789abcdef"},
			"Qory Apiary enrolled the key as ak_0123456789abcdef for a node nd_0123456789abcdef, which is not a node pool: the code was not made on the node pool's Access key tab; no secret was written: have a workspace admin of Qory Apiary revoke the key {fp}, and enrol with a code made on the node pool's Access key tab\n"},
		"a gateway's key for a pool's code": {reply{status: http.StatusCreated, kind: "gateway", nodeID: "ng_0123456789abcdef"},
			"Qory Apiary enrolled the key as ak_0123456789abcdef for a gateway ng_0123456789abcdef, which is not a node pool: the code was not made on the node pool's Access key tab; no secret was written: have a workspace admin of Qory Apiary revoke the key {fp}, and enrol with a code made on the node pool's Access key tab\n"},
		"two keys held": {reply{status: http.StatusConflict, refusal: "key_limit"},
			"the node pool already holds two keys: have a workspace admin of Qory Apiary revoke one, then run the same command again within the code's 15 minutes"},
		"a used code": {reply{status: http.StatusUnauthorized}, "the server at {server} answered 401: "},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeApiary(t, tc.reply)
			file := filepath.Join(t.TempDir(), "secret")
			c := poolCode(f)
			status, out, errs, made := enrolRun(t, "--secret-file", file, f.url, c)
			want := "access key fingerprint " + made.Fingerprint() + "\nqory-github-starter access-key: " + strings.NewReplacer("{fp}", made.Fingerprint(), "{server}", f.url).Replace(tc.want)
			if status != 1 || out != "" || !strings.HasPrefix(errs, want) || f.requests.Load() != 1 {
				t.Errorf("exit %d, %d requests, stdout %q, stderr:\n%s\nwant:\n%s", status, f.requests.Load(), out, errs, want)
			}
			if tc.reply.status == http.StatusUnauthorized && !strings.HasSuffix(errs, "If the code was used and not by you, tell a workspace admin of Qory Apiary, who must revoke the key it enrolled\n") {
				t.Errorf("the 401 names no workspace admin: %s", errs)
			}
			if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a secret file was written: %v", err)
			}
			noLeak(t, made, c, out, errs)
		})
	}
}

// TestEnrolNeverWritesOverAFile pins that a secret file that exists is refused before
// anything is sent, and left as it was.
func TestEnrolNeverWritesOverAFile(t *testing.T) {
	f := newFakeApiary(t, poolEnrolled)
	exists := filepath.Join(t.TempDir(), "exists")
	if err := os.WriteFile(exists, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := poolCode(f)
	status, out, errs, made := enrolRun(t, "--secret-file", exists, f.url, c)
	if want := "qory-github-starter access-key: the secret file " + exists + " exists; choose another or move it away\n"; status != 1 || out != "" || errs != want || made != nil {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if b, _ := os.ReadFile(exists); string(b) != "kept\n" {
		t.Errorf("the file that exists was written: %q", b)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
	noLeak(t, nil, c, out, errs)
}
