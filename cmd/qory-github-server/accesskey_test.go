package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/qoryai/forager/accesskey"
)

// codeCore is the 26 characters of the enrolment codes the tests use, which no output
// may contain.
const codeCore = "0123456789ABCDEFGHJKMNPQRS"

// fakeApiary is Qory Apiary's enrolment endpoint as enrol uses it, answering each
// enrolment as its reply says.
type fakeApiary struct {
	url      string
	signer   *accesskey.Key
	requests atomic.Int32
	got      atomic.Pointer[accesskey.EnrolmentRequest]
}

// reply is how the fake answers. A 201 names the access key ak_0123456789abcdef in the
// node nodeID of kind; a 401 is unsigned and empty; any other status is a refusal with
// the code refusal. Each but the 401 lists the signer's key, then extra's, and is
// signed under the signer, a new key when it is nil; pad adds that many spaces after
// the body before it is signed; hook runs before the answer is sent, and change may
// change the status, the body and the signature then.
type reply struct {
	status       int
	kind, nodeID string
	refusal      string
	signer       *accesskey.Key
	extra        []*accesskey.Key
	pad          int
	hook         func()
	change       answer
}

// adapterEnrolled is a reply that enrols the key in an adapter.
var adapterEnrolled = reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef"}

// answer is what the fake sends: the status, the body and the signature, which a test
// may change from the correctly signed ones it is handed.
type answer func(status int, body []byte, sig string) (int, []byte, string)

func newFakeApiary(t *testing.T, rp reply) *fakeApiary {
	t.Helper()
	signer := rp.signer
	if signer == nil {
		var err error
		if signer, err = accesskey.Generate(); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakeApiary{signer: signer}
	listed := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	for _, k := range rp.extra {
		listed = append(listed, accesskey.ServerKey{Alg: "ed25519", PublicKey: k.PublicKey().String()})
	}
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
		if rp.hook != nil {
			rp.hook()
		}
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
		body = append(body, bytes.Repeat([]byte(" "), rp.pad)...)
		sig := signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: rp.status, RequestSignature: req.Proof, Body: body})
		st := rp.status
		if rp.change != nil {
			st, body, sig = rp.change(st, body, sig)
		}
		w.Header().Set(accesskey.HeaderSignature, sig)
		if st/100 == 3 {
			w.Header().Set("Location", "https://elsewhere.example.com/")
		}
		w.WriteHeader(st)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// code is an integration's enrolment code that carries the fingerprint of key, as a
// person copies it.
func code(key *accesskey.Key) string {
	return codeOf(accesskey.CodePrefixAdapter, key)
}

// codeOf is an enrolment code with prefix that carries the fingerprint of key, as a
// person copies it.
func codeOf(prefix string, key *accesskey.Key) string {
	return prefix + codeCore[:13] + "-" + codeCore[13:] + "." + key.Fingerprint()
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
	f := newFakeApiary(t, adapterEnrolled)
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
	if got.PublicKey != key.PublicKey().String() || got.Name != "adapter-host.example.com" || got.Code != "qeci_"+codeCore+"."+f.signer.Fingerprint() {
		t.Errorf("enrolled %s named %q with the code %q; the secret file holds %s", got.PublicKey, got.Name, got.Code, key.PublicKey())
	}
	pin, _ := json.Marshal(accesskey.Pin{{Alg: "ed25519", PublicKey: f.signer.PublicKey().String()}})
	fileJSON, _ := json.Marshal(file)
	wantOut := `  "apiary_url": "` + f.url + `",
  "access_key_id": "ak_0123456789abcdef",
  "access_key_secret_file": ` + string(fileJSON) + `,
  "apiary_public_key": ` + string(pin) + `,
  "adapter_id": "na_0123456789abcdef"
`
	if out != wantOut {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, wantOut)
	}
	// The settings are members of serve's settings object.
	var settings map[string]any
	if err := json.Unmarshal([]byte("{"+out+"}"), &settings); err != nil || len(settings) != 5 {
		t.Errorf("the settings are not five members of a JSON object: %v", err)
	}
	fp := key.Fingerprint()
	wantErrs := "access key fingerprint " + fp + "\n" +
		"enrolled as ak_0123456789abcdef in the integration na_0123456789abcdef\n" +
		"wrote the access key's secret to " + file + "\n" +
		"add these settings to serve's settings:\n" +
		"compare the fingerprint " + fp + " with the one Qory Apiary shows on the integration's Access key tab in Organisation settings; the key is active\n"
	if errs != wantErrs {
		t.Errorf("stderr:\n%s\nwant:\n%s", errs, wantErrs)
	}
	noLeak(t, key.Secret(), c, out, errs)
}

// serverShape is the error of a server that is not Qory Apiary's origin.
const serverShape = "the server is neither an https URL of a host and an optional port nor, for a test, an http one to localhost, 127.0.0.1 or [::1], with nothing after"

// TestEnrolRefusesWhatItCannotWriteBeforeAnyRequest pins that a secret file that exists,
// or whose directory does not, and a server that is not Qory Apiary's origin over https
// are refused before the code is sent.
func TestEnrolRefusesWhatItCannotWriteBeforeAnyRequest(t *testing.T) {
	f := newFakeApiary(t, adapterEnrolled)
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
		{[]string{"--secret-file", filepath.Join(dir, "qeci_x"), f.url, c}, "the secret file's path contains what starts an enrolment code or a secret; choose another with --secret-file"},
		{[]string{"--secret-file", filepath.Join(dir, "QAK_x"), f.url, c}, "the secret file's path contains what starts an enrolment code or a secret; choose another with --secret-file"},
		{[]string{"--secret-file", filepath.Join(dir, "x-qrk_"), "http://apiary.example.com", c}, "the secret file's path contains what starts an enrolment code or a secret; choose another with --secret-file"},
		{[]string{"--secret-file", file, "http://apiary.example.com", c}, serverShape},
		{[]string{"--secret-file", file, "ftp://apiary.example.com", c}, serverShape},
		{[]string{"--secret-file", file, "https://apiary.example.com/enrol", c}, serverShape},
		{[]string{"--secret-file", file, "https://user@apiary.example.com", c}, serverShape},
		{[]string{"--secret-file", file, "https://apiary.example.com?a=1", c}, serverShape},
		{[]string{"--secret-file", file, c, f.url}, serverShape},
		{[]string{"--secret-file", file, f.url, "qeci_" + codeCore + "U." + f.signer.Fingerprint()}, notACode},
		{[]string{"--secret-file", file, f.url, "qeci_" + codeCore + ".!" + f.signer.Fingerprint()}, notACode},
		{[]string{"--secret-file", file, f.url}, "want two arguments, the server and the code"},
		{[]string{f.url, c}, "--secret-file is required"},
	} {
		status, out, errs := enrolRun(t, tc.args...)
		if status != 1 || out != "" || errs != "qory-github-server access-key: "+tc.want+"\n" {
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

// notACode is the error of a code that is not an enrolment code.
const notACode = "the code is not an enrolment code: qeci_, 26 characters, then a dot and a fingerprint, as Qory Apiary shows it"

// TestEnrolRefusesWhatIsNotAnEnrolmentCode pins that a code with the prefix enrolment
// codes had before, qec_, one with an unknown prefix, and a malformed code of each kind
// are refused with the one error that quotes no part of the code, and nothing is sent.
func TestEnrolRefusesWhatIsNotAnEnrolmentCode(t *testing.T) {
	f := newFakeApiary(t, adapterEnrolled)
	fp := f.signer.Fingerprint()
	for _, c := range []string{
		"qec_" + codeCore + "." + fp,
		"QEC_" + codeCore + "." + fp,
		"qecx_" + codeCore + "." + fp,
		"qak_" + codeCore + "." + fp,
		codeCore + "." + fp,
		"qeci_" + codeCore + "Z." + fp,
		"qeci_" + codeCore[:25] + "." + fp,
		"qeci_" + codeCore,
	} {
		file := filepath.Join(t.TempDir(), "secret")
		status, out, errs := enrolRun(t, "--secret-file", file, f.url, c)
		if want := "qory-github-server access-key: " + notACode + "\n"; status != 1 || out != "" || errs != want {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", c, status, out, errs)
		}
		noLeak(t, "", c, out, errs)
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a secret file was written: %v", c, err)
		}
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// TestHasCodeOrSecretFindsEachPrefix pins that what starts an enrolment code of each
// kind, an access key secret or a run key is found anywhere in a value, in any case,
// and that the prefix enrolment codes had before is not.
func TestHasCodeOrSecretFindsEachPrefix(t *testing.T) {
	for _, p := range []string{accesskey.CodePrefixNode, accesskey.CodePrefixPool, accesskey.CodePrefixGateway, accesskey.CodePrefixAdapter, accesskey.SecretPrefix, "qrk_"} {
		for _, v := range []string{p, strings.ToUpper(p), strings.ToUpper(p[:2]) + p[2:], "/etc/qory-github/" + p + "x", "https://" + strings.ToUpper(p) + "x.example.com"} {
			if !hasCodeOrSecret(v) {
				t.Errorf("%q: not found", v)
			}
		}
	}
	for _, v := range []string{"/etc/qory-github/access-key-secret", "https://apiary.example.com", "qec_x", "qeca_x", "qec-i_x"} {
		if hasCodeOrSecret(v) {
			t.Errorf("%q: found", v)
		}
	}
}

// fixtureSigner is the Forager contract's published fixture signing key of the server,
// from the seed its known answers publish.
func fixtureSigner(t *testing.T) *accesskey.Key {
	t.Helper()
	seed, _ := base64.RawURLEncoding.DecodeString("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A")
	k, err := accesskey.NewKey(seed)
	if err != nil || !k.PublicKey().Fixture() {
		t.Fatalf("the seed is not a fixture key's: %v", err)
	}
	return k
}

// TestEnrolRefusesAnAnswerItCannotTrust pins that an answer whose signature does not
// verify under the key the code names, a refusal, and a key enrolled for another kind
// than an adapter or under a published fixture key write nothing, and say so in one line
// without the secret or the code. {fp} in want is the new key's fingerprint.
func TestEnrolRefusesAnAnswerItCannotTrust(t *testing.T) {
	other, _ := accesskey.Generate()
	const unverified = "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary's answer did not verify (HTTP %d); no secret was written: get a new code, and have an owner or administrator in Qory Apiary revoke the key {fp} should it have been enrolled\n"
	// corrupt flips one bit of the answer's signature, which is otherwise the right one.
	corrupt := func(s int, b []byte, sig string) (int, []byte, string) {
		raw, _ := base64.RawURLEncoding.DecodeString(sig)
		raw[10] ^= 1
		return s, b, base64.RawURLEncoding.EncodeToString(raw)
	}
	for name, tc := range map[string]struct {
		reply     reply
		otherCode bool
		want      string
	}{
		"a bad signature": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: corrupt},
			want: fmt.Sprintf(unverified, 201)},
		"a changed body": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: func(s int, b []byte, sig string) (int, []byte, string) {
			return s, bytes.Replace(b, []byte("ak_0123456789abcdef"), []byte("ak_0123456789abcdeg"), 1), sig
		}}, want: fmt.Sprintf(unverified, 201)},
		"no signature": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", change: func(s int, b []byte, _ string) (int, []byte, string) {
			return s, b, ""
		}}, want: fmt.Sprintf(unverified, 201)},
		"another server's key in the code": {reply: adapterEnrolled, otherCode: true,
			want: fmt.Sprintf(unverified, 201)},
		"a signed redirect": {reply: reply{status: http.StatusTemporaryRedirect, refusal: "key_limit"},
			want: fmt.Sprintf(unverified, 307)},
		"an answer larger than 64 KiB": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", pad: accesskey.MaxAnswer},
			want: fmt.Sprintf(unverified, 201)},
		"a node's key for an integration's code": {reply: reply{status: http.StatusCreated, kind: "node", nodeID: "nd_0123456789abcdef"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary enrolled the key as ak_0123456789abcdef in the node nd_0123456789abcdef, which is not an integration: the code was not made on the integration's Access key tab; no secret was written: have an owner or administrator in Qory Apiary revoke the key {fp}, and enrol with a code made on the integration's Access key tab in Organisation settings\n"},
		"a gateway's key for an integration's code": {reply: reply{status: http.StatusCreated, kind: "gateway", nodeID: "ng_0123456789abcdef"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary enrolled the key as ak_0123456789abcdef in the gateway ng_0123456789abcdef, which is not an integration: the code was not made on the integration's Access key tab; no secret was written: have an owner or administrator in Qory Apiary revoke the key {fp}, and enrol with a code made on the integration's Access key tab in Organisation settings\n"},
		"a kind that does not match the id": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "nd_0123456789abcdef"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: the enrolment did not complete: the enrolment answer: node_kind \"adapter\" does not match the node id nd_0123456789abcdef; no secret was written: get a new code, and have an owner or administrator in Qory Apiary revoke the key {fp} should it have been enrolled\n"},
		"a fixture key pinned": {reply: reply{status: http.StatusCreated, kind: "adapter", nodeID: "na_0123456789abcdef", signer: fixtureSigner(t)},
			want: "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary's answer lists the Forager contract's published fixture key, whose secret anyone can read: it is no server to pin; no secret was written: have an owner or administrator in Qory Apiary revoke the key {fp}\n"},
		"a used code": {reply: reply{status: http.StatusUnauthorized},
			want: "access key fingerprint {fp}\nqory-github-server access-key: the server at {server} answered 401: Qory Apiary answers so when the code was used, has expired or was cancelled, is no code of the Qory Apiary at {server}, or its record fails Qory Apiary's integrity check; when its maker can no longer make codes; when what the code was made for was deleted, its workspace or organisation is marked for deletion, or its organisation is not in use; when Qory Apiary has the feature factory off; or when this machine's clock is more than 5 minutes off. Something in front of Qory Apiary, or a server that is not Qory Apiary, may also have refused the request. If the code was used and not by you, tell an owner or administrator in Qory Apiary, who must revoke the key it enrolled\n"},
		"a key refused": {reply: reply{status: http.StatusConflict, refusal: "key_invalid"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary refused the key; the code is not used: the same command, run within the code's 15 minutes, makes a new key\n"},
		"two keys held": {reply: reply{status: http.StatusConflict, refusal: "key_limit"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: the integration already holds two keys: have an owner or administrator in Qory Apiary revoke one, then run the same command again within the code's 15 minutes\n"},
		"too many attempts": {reply: reply{status: http.StatusTooManyRequests, refusal: "rate_limited"},
			want: "access key fingerprint {fp}\nqory-github-server access-key: Qory Apiary refused the attempt: this code was tried too often; run the same command again later, within the code's 15 minutes\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeApiary(t, tc.reply)
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
			if want := strings.NewReplacer("{fp}", made.Fingerprint(), "{server}", f.url).Replace(tc.want); status != 1 || out != "" || errs != want {
				t.Errorf("exit %d, stdout %q, stderr:\n%s\nwant:\n%s", status, out, errs, want)
			}
			if n := f.requests.Load(); n != 1 {
				t.Errorf("%d requests, want 1", n)
			}
			if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a secret file was written: %v", err)
			}
			noLeak(t, made.Secret(), c, out, errs)
		})
	}
}

// TestEnrolPinsOnlyTheKeyTheCodeNames pins that a correctly signed answer that lists
// another key beside the one the code names is taken, and the settings pin the code's
// key alone.
func TestEnrolPinsOnlyTheKeyTheCodeNames(t *testing.T) {
	extra, _ := accesskey.Generate()
	rp := adapterEnrolled
	rp.extra = []*accesskey.Key{extra}
	f := newFakeApiary(t, rp)
	file := filepath.Join(t.TempDir(), "secret")
	status, out, errs := enrolRun(t, "--secret-file", file, f.url, code(f.signer))
	pin, _ := json.Marshal(accesskey.Pin{{Alg: "ed25519", PublicKey: f.signer.PublicKey().String()}})
	if status != 0 || !strings.Contains(out, `"apiary_public_key": `+string(pin)+",\n") || strings.Contains(out, extra.PublicKey().String()) {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
}

// TestEnrolPrintsTheServerInLowerCase pins that apiary_url has the scheme and the host
// in lower case, as the settings hold it, whatever case the operator typed.
func TestEnrolPrintsTheServerInLowerCase(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://Apiary.Example.com":       "https://apiary.example.com",
		"Https://APIARY.example.com:8443/": "https://apiary.example.com:8443",
		"HTTP://LocalHost:8080":            "http://localhost:8080",
		"http://[::1]:8080":                "http://[::1]:8080",
	} {
		got, err := checkServer(strings.TrimSuffix(in, "/"))
		if err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", in, got, err, want)
		}
	}
	f := newFakeApiary(t, adapterEnrolled)
	file := filepath.Join(t.TempDir(), "secret")
	server := strings.Replace(f.url, "http://127.0.0.1", "HTTP://127.0.0.1", 1)
	status, out, errs := enrolRun(t, "--secret-file", file, server, code(f.signer))
	if status != 0 || !strings.HasPrefix(out, `  "apiary_url": "`+f.url+`",`) {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
}

// TestCheckServerTakesAnASCIIHostAlone pins that a host that is not ASCII, once
// decoded, is refused with a fixed error, before its letters are put in lower case, so
// a dotted capital I or a Kelvin sign never becomes an i or a k, and that an IPv6
// zone keeps its case.
func TestCheckServerTakesAnASCIIHostAlone(t *testing.T) {
	const notASCII = "the server's host holds a character that is not ASCII; give an international name in its ASCII form, xn--"
	for in, want := range map[string]string{
		"https://%C4%B0.example":        notASCII,
		"https://qa%E2%84%AA_x":         notASCII,
		"https://qa%E2%84%AA_x.example": notASCII,
		"https://\u212aelvin.example":   notASCII,
		"https://QAK_x.example":         serverShape,
		"https://apiary.example%2ecom":  serverShape,
	} {
		got, err := checkServer(in)
		if got != "" || err == nil || err.Error() != want {
			t.Errorf("%s: %q, %v; want %q", in, got, err, want)
		}
	}
	if got, err := checkServer("https://[FE80::1%25EN0]"); err != nil || got != "https://[fe80::1%25EN0]" {
		t.Errorf("an IPv6 zone: %q, %v", got, err)
	}
	if got, err := checkServer("https://[FE80::1%25EN0]:8443"); err != nil || got != "https://[fe80::1%25EN0]:8443" {
		t.Errorf("an IPv6 zone and a port: %q, %v", got, err)
	}
	f := newFakeApiary(t, adapterEnrolled)
	file := filepath.Join(t.TempDir(), "secret")
	status, out, errs := enrolRun(t, "--secret-file", file, "https://qa%E2%84%AA_x", code(f.signer))
	if status != 1 || out != "" || errs != "qory-github-server access-key: "+notASCII+"\n" || f.requests.Load() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q, %d requests", status, out, errs, f.requests.Load())
	}
}

// TestCheckServerTakesAHostAndAPortAlone pins that a host outside letters, digits, dots
// and dashes, or a bracketed IPv6 address, an empty host, and a port that is empty or
// outside 1 to 65535 are refused, and that a host and port of the right shape are taken.
func TestCheckServerTakesAHostAndAPortAlone(t *testing.T) {
	for _, in := range []string{
		"https://apiary.example.com:", "https://:", "https://:443", "https://apiary.example.com:0",
		"https://apiary.example.com:65536", "https://apiary.example.com:0443", "https://apiary.example.com:+443",
		"https://a]b", "https://%25", "https://a_b.example", "https://a b.example", "https://a!b.example",
		"https://[fe80::1", "https://[apiary.example.com]", "https://[127.0.0.1]", "https://[fe80::1%25]",
		"https://[fe80::1%25a!b]", "https://[::1]:", "https://[::1]:70000",
	} {
		if got, err := checkServer(in); got != "" || err == nil || err.Error() != serverShape {
			t.Errorf("%s: %q, %v", in, got, err)
		}
	}
	for in, want := range map[string]string{
		"https://apiary.example.com:1":     "https://apiary.example.com:1",
		"https://apiary.example.com:65535": "https://apiary.example.com:65535",
		"https://xn--bcher-kva.example":    "https://xn--bcher-kva.example",
		"https://192.0.2.1:8443":           "https://192.0.2.1:8443",
		"https://[2001:DB8::1]:8443":       "https://[2001:db8::1]:8443",
		"https://[fe80::1%25en0.1_a-b]":    "https://[fe80::1%25en0.1_a-b]",
		"http://[::1]:8080":                "http://[::1]:8080",
	} {
		if got, err := checkServer(in); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestEnrolRefusesAServerOnlyItsOriginShowsACodeIn pins the case that only the check of
// the origin as it is printed catches: a zone that spells qak_ only once decoded.
func TestEnrolRefusesAServerOnlyItsOriginShowsACodeIn(t *testing.T) {
	const server = "https://[fe80::1%25q%61k_x]"
	if hasCodeOrSecret(server) {
		t.Fatal("the server as given already shows qak_")
	}
	f := newFakeApiary(t, adapterEnrolled)
	file := filepath.Join(t.TempDir(), "secret")
	status, out, errs := enrolRun(t, "--secret-file", file, server, code(f.signer))
	if status != 1 || out != "" || errs != "qory-github-server access-key: "+serverShape+"\n" || f.requests.Load() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q, %d requests", status, out, errs, f.requests.Load())
	}
}

// TestEnrolRefusesARelativePathThatBecomesACodeOrSecret pins that the secret file's
// path is checked as it is made absolute, too.
func TestEnrolRefusesARelativePathThatBecomesACodeOrSecret(t *testing.T) {
	f := newFakeApiary(t, adapterEnrolled)
	dir := filepath.Join(t.TempDir(), "qak_dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	status, out, errs := enrolRun(t, "--secret-file", "secret", f.url, code(f.signer))
	if want := "qory-github-server access-key: the secret file's path contains what starts an enrolment code or a secret; choose another with --secret-file\n"; status != 1 || out != "" || errs != want || f.requests.Load() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the directory holds %v", entries)
	}
}

// TestEnrolRefusesAProbeItCannotRemove pins that the probe file that checks the
// directory can be written is named, and the code not sent, when it cannot be removed.
func TestEnrolRefusesAProbeItCannotRemove(t *testing.T) {
	f := newFakeApiary(t, adapterEnrolled)
	dir := t.TempDir()
	var probe string
	defer func(r func(string) error) { removeProbe = r }(removeProbe)
	removeProbe = func(p string) error {
		probe = p
		return &os.PathError{Op: "remove", Path: p, Err: syscall.EBUSY}
	}
	status, out, errs := enrolRun(t, "--secret-file", filepath.Join(dir, "secret"), f.url, code(f.signer))
	want := "qory-github-server access-key: the secret file's directory " + dir + ": the file " + probe + " made to check it can be written could not be removed: " + syscall.EBUSY.Error() + "\n"
	if status != 1 || out != "" || errs != want || f.requests.Load() != 0 || filepath.Dir(probe) != dir {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
}

// TestEnrolNeverWritesThroughALinkPlantedMeanwhile pins that a symbolic link planted at
// the secret file's path while the enrolment is under way is not followed, and the
// secret written nowhere.
func TestEnrolNeverWritesThroughALinkPlantedMeanwhile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret")
	target := filepath.Join(dir, "target")
	rp := adapterEnrolled
	rp.hook = func() { os.Symlink(target, file) }
	f := newFakeApiary(t, rp)
	status, out, errs := enrolRun(t, "--secret-file", file, f.url, code(f.signer))
	if status != 1 || out != "" || !strings.Contains(errs, "\nqory-github-server access-key: the key is enrolled as ak_0123456789abcdef, and the secret file "+file+" exists; choose another or move it away; the secret was not kept: enrol a key again with a new code, and have an owner or administrator in Qory Apiary revoke the key ") {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the secret was written through the link: %v", err)
	}
}

// TestEnrolRefusesADirectoryItCannotWriteBeforeAnyRequest pins that the secret file's
// directory is found unwritable before the code is sent.
func TestEnrolRefusesADirectoryItCannotWriteBeforeAnyRequest(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes in any directory")
	}
	f := newFakeApiary(t, adapterEnrolled)
	dir := filepath.Join(t.TempDir(), "read-only")
	os.Mkdir(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	status, out, errs := enrolRun(t, "--secret-file", filepath.Join(dir, "secret"), f.url, code(f.signer))
	if want := "qory-github-server access-key: the secret file's directory " + dir + " cannot be written: permission denied\n"; status != 1 || out != "" || errs != want {
		t.Errorf("exit %d, stdout %q, stderr %q", status, out, errs)
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the directory holds %v", entries)
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
	f := newFakeApiary(t, adapterEnrolled)
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
	want := "qory-github-server access-key: the key is enrolled as ak_0123456789abcdef, and the secret file: no space left on device; the secret was not kept: enrol a key again with a new code, and have an owner or administrator in Qory Apiary revoke the key " + made.Fingerprint() + "\n"
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

// TestAccessKeyIsAbsentWithoutFactory pins that, unless QORY_FEATURES names factory,
// access-key is in no usage and is answered as a command the program does not know, and
// sends nothing.
func TestAccessKeyIsAbsentWithoutFactory(t *testing.T) {
	f := newFakeApiary(t, adapterEnrolled)
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
	if code := run(context.Background(), nil, &out, &errs); code != 2 || errs.String() != usageWithFactory {
		t.Errorf("exit %d, the usage:\n%s", code, errs.String())
	}
	for _, args := range [][]string{{"access-key", "-h"}, {"access-key", "enrol", "-h"}} {
		errs.Reset()
		if code := run(context.Background(), args, &out, &errs); code != 2 || !strings.Contains(errs.String(), "qory-github-server access-key enrol --secret-file FILE [--] SERVER CODE") || !strings.Contains(errs.String(), "\nflags:\n  -secret-file string\n    \twhere the access key's secret is written; a file that exists is refused (required)\n") || strings.Contains(errs.String(), "More:") {
			t.Errorf("%v exits %d:\n%s", args, code, errs.String())
		}
	}
	for _, args := range [][]string{{"access-key"}, {"access-key", "create"}} {
		errs.Reset()
		if code := run(context.Background(), args, io.Discard, &errs); code != 1 || errs.String() != "qory-github-server access-key: access-key has one command, enrol: qory-github-server access-key enrol --secret-file FILE SERVER CODE\n" {
			t.Errorf("%v exits %d: %q", args, code, errs.String())
		}
	}
}
