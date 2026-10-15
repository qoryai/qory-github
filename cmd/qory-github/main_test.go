package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/qoryai/integrations/conformance"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/ownerfile"
	"gopkg.in/yaml.v3"
)

const token = "ghs_faketokenthatmustnotleak"

// fakeAPI is GitHub's API as the command uses it, answering the mint with status.
func fakeAPI(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			io.WriteString(w, `{"id":42}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			w.WriteHeader(status)
			if status == 201 {
				io.WriteString(w, `{"token":"`+token+`","expires_at":"2026-09-25T21:00:00Z"}`)
			} else {
				io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func keyFile(t *testing.T) (string, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, b
}

// settings is a settings document for the command line, with these fields added.
func settings(t *testing.T, fields map[string]any) string {
	t.Helper()
	doc := map[string]any{"app_id": 123456}
	for k, v := range fields {
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCredentialPrintsOneDocumentAndNothingElse(t *testing.T) {
	file, _ := keyFile(t)
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": fakeAPI(t, 201)}), "--", "acme/shop"}, &out, &errs)
	if code != 0 || errs.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("standard output is not one document: %v\n%s", err, out.String())
	}
	if doc["token"] != token || doc["version"] != float64(1) {
		t.Errorf("doc %v", doc)
	}
	if err := conformance.Credential(out.Bytes()); err != nil {
		t.Error(err)
	}
}

// TestCredentialNeverReadsStandardInput runs credential with its settings on the
// command line and standard input open, with something written to it, and checks that
// it mints and leaves standard input as it found it: the settings come from --settings
// alone, and credential never waits for standard input.
func TestCredentialNeverReadsStandardInput(t *testing.T) {
	file, _ := keyFile(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	unread := settings(t, map[string]any{"private_key_file": "/nonexistent/app.pem"})
	if _, err := io.WriteString(w, unread); err != nil {
		t.Fatal(err)
	}
	defer func(f *os.File) { os.Stdin = f }(os.Stdin)
	os.Stdin = r
	var out, errs bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": fakeAPI(t, 201)}), "--", "acme/shop"}, &out, &errs)
	}()
	select {
	case code := <-done:
		if code != 0 || errs.Len() != 0 {
			t.Fatalf("exit %d: %s", code, errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("credential waits on standard input")
	}
	if err := conformance.Credential(out.Bytes()); err != nil {
		t.Error(err)
	}
	w.Close()
	left, err := io.ReadAll(r)
	if err != nil || string(left) != unread {
		t.Errorf("standard input was read: %q left of %q, %v", left, unread, err)
	}
}

// TestCredentialsHelpSaysWhatItReadsFromItsEnvironment pins what the help says of the
// environment: no setting and no secret come from it. Go's HTTP client still reads the
// proxy variables, HTTPS_PROXY and NO_PROXY, and on Linux crypto/x509 reads SSL_CERT_FILE
// and SSL_CERT_DIR, so the help claims no more than that.
func TestCredentialsHelpSaysWhatItReadsFromItsEnvironment(t *testing.T) {
	var out, errs bytes.Buffer
	run(context.Background(), []string{"credential", "-h"}, &out, &errs)
	help := strings.Join(strings.Fields(errs.String()), " ")
	if !strings.Contains(help, "credential reads no setting and no secret from its environment.") || strings.Contains(help, "reads nothing from its environment") {
		t.Errorf("the help says\n%s", errs.String())
	}
}

func TestAFailureIsOneLineWithNoSecret(t *testing.T) {
	file, pemBytes := keyFile(t)
	// noAPI is an API on loopback that settings the command refuses never reach: a
	// request to it fails the test, and no row falls back to https://api.github.com.
	noSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GitHub's API is called for settings that are refused: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(noSrv.Close)
	noAPI := noSrv.URL
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"github refuses", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": fakeAPI(t, 403)}), "acme/shop"}, "403: Resource not accessible by integration"},
		{"two owners", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": noAPI}), "acme/shop,other/lib"}, "share an owner"},
		{"no settings", []string{"credential", "acme/shop"}, "--settings is required"},
		{"no key", []string{"credential", "--settings", settings(t, map[string]any{"api_url": noAPI}), "acme/shop"}, "missing property 'private_key_file'"},
		{"the key on the command line", []string{"credential", "--settings", settings(t, map[string]any{"private_key": string(pemBytes), "api_url": noAPI}), "acme/shop"}, "contain private_key, a secret"},
		{"admin", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": noAPI, "permissions": map[string]string{"contents": "admin"}}), "acme/shop"}, "/permissions/contents: value must be one of 'read', 'write'"},
		{"administration", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": noAPI, "permissions": map[string]string{"administration": "read"}}), "acme/shop"}, "/permissions: invalid propertyName 'administration'"},
		{"an argument like a flag", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": noAPI}), "--", "-acme/shop"}, `"-acme/shop" is not owner/name`},
		{"a flag of old", []string{"credential", "--app-id", "123456", "--private-key-file", file, "acme/shop"}, "flag provided but not defined"},
		{"no App id", []string{"credential", "--settings", `{"private_key_file":"/nonexistent/app.pem","api_url":"` + noAPI + `"}`, "--", "acme/shop"}, "missing property 'app_id'"},
		{"empty settings", []string{"credential", "--settings", "", "--", "acme/shop"}, "--settings is required"},
		{"settings of -", []string{"credential", "--settings", "-", "--", "acme/shop"}, "the settings are not one JSON document"},
		{"two documents", []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": noAPI}) + "\n{}", "--", "acme/shop"}, "something other than white space follows it"},
		{"a key not escaped", []string{"credential", "--settings", `{"app_id":123456,"api_url":"` + noAPI + `","private_key":"` + string(pemBytes) + `"}`, "--", "acme/shop"}, "not one JSON document: it breaks at byte"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			code := run(context.Background(), tc.args, &out, &errs)
			if tc.name == "a flag of old" {
				if code != 1 && code != 2 || out.Len() != 0 {
					t.Fatalf("exit %d, stdout %q", code, out.String())
				}
				return
			}
			if code != 1 || out.Len() != 0 {
				t.Fatalf("exit %d, stdout %q", code, out.String())
			}
			if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
				t.Error(err)
			}
			line := errs.String()
			if strings.Count(line, "\n") != 1 || !strings.HasPrefix(line, "qory-github credential: ") || !strings.Contains(line, tc.want) {
				t.Errorf("stderr %q", line)
			}
			if strings.Contains(line, token) || strings.Contains(line, "PRIVATE KEY") || bytes.Contains([]byte(line), pemBytes[40:80]) || strings.Contains(line, "secretvalue") {
				t.Errorf("stderr contains a secret: %q", line)
			}
		})
	}
}

// TestAFailureToReachGitHubNeverSaysTheRequest runs credential with an API nothing
// listens on and an installation, a setting, and checks that the one line on standard
// error says what failed, and never the installation's id, the path nor the URL.
func TestAFailureToReachGitHubNeverSaysTheRequest(t *testing.T) {
	file, _ := keyFile(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	api := srv.URL
	srv.Close()
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "installation_id": 778899, "api_url": api}), "--", "acme/shop"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	if !strings.HasPrefix(errs.String(), "qory-github credential: ") || !strings.Contains(errs.String(), ": GitHub's API could not be reached: ") {
		t.Errorf("stderr %q", errs.String())
	}
	for _, v := range []string{"778899", "/app/", "installations/", "access_tokens", api} {
		if strings.Contains(errs.String(), v) {
			t.Errorf("stderr contains %q: %q", v, errs.String())
		}
	}
}

// TestCredentialRefusesAnotherOwnersInstallation runs credential with an installation
// GitHub says is another account's, and checks the one line on standard error, which
// says neither the id nor the login, and that no token is minted.
func TestCredentialRefusesAnotherOwnersInstallation(t *testing.T) {
	file, _ := keyFile(t)
	var minted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/app/installations/778899":
			io.WriteString(w, `{"id":778899,"account":{"login":"otherlogin"}}`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			minted.Store(true)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"token":"`+token+`","expires_at":"2026-09-25T21:00:00Z"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "installation_id": 778899, "api_url": srv.URL}), "--", "acme/shop"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	if want := "qory-github credential: installation_id is not the App's installation on the repositories' owner; set that owner's installation, or leave installation_id out\n"; errs.String() != want {
		t.Errorf("stderr %q, want %q", errs.String(), want)
	}
	if minted.Load() {
		t.Error("a token was minted with another account's installation")
	}
}

// TestCredentialFollowsNoRedirect has GitHub's API answer the installation's lookup for
// acme/shop with a 301 to another repository's, as it answers for a repository that was
// renamed, and checks the one line on standard error, that the redirect's target is
// never requested and that no token is minted.
func TestCredentialFollowsNoRedirect(t *testing.T) {
	file, _ := keyFile(t)
	var followed, minted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/shop/installation":
			w.Header().Set("Location", "/repos/acme/renamed/installation")
			w.WriteHeader(http.StatusMovedPermanently)
			io.WriteString(w, `{"message":"Moved Permanently","url":"/repos/acme/renamed/installation"}`)
		case "/repos/acme/renamed/installation":
			followed.Store(true)
			io.WriteString(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			minted.Store(true)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"token":"`+token+`","expires_at":"2026-09-25T21:00:00Z"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": srv.URL}), "--", "acme/shop"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	if want := "qory-github credential: GitHub answered with a redirect; the repository may have moved or been renamed, so name its new owner/name in the policy's credential argument\n"; errs.String() != want {
		t.Errorf("stderr %q, want %q", errs.String(), want)
	}
	if followed.Load() || minted.Load() {
		t.Errorf("the redirect was followed: %v, a token minted: %v", followed.Load(), minted.Load())
	}
}

// TestCredentialSaysARedirectOnTheCheckIsNoMove runs credential with an installation_id
// that GitHub's API answers the check of with a 301, and checks the one line on standard
// error says the check was redirected, not that a repository moved, since the check
// names none, that the redirect's target is never requested and that no token is minted.
func TestCredentialSaysARedirectOnTheCheckIsNoMove(t *testing.T) {
	file, _ := keyFile(t)
	var followed, minted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/778899":
			w.Header().Set("Location", "/app/installations/42")
			w.WriteHeader(http.StatusMovedPermanently)
			io.WriteString(w, `{"message":"Moved Permanently","url":"/app/installations/42"}`)
		case "/app/installations/42":
			followed.Store(true)
			io.WriteString(w, `{"id":42,"account":{"login":"acme"}}`)
		default:
			if strings.HasSuffix(r.URL.Path, "/access_tokens") {
				minted.Store(true)
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "installation_id": 778899, "api_url": srv.URL}), "--", "acme/shop"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	if want := "qory-github credential: checking installation_id: GitHub answered with a redirect, which is never followed\n"; errs.String() != want {
		t.Errorf("stderr %q, want %q", errs.String(), want)
	}
	if followed.Load() || minted.Load() {
		t.Errorf("the redirect was followed: %v, a token minted: %v", followed.Load(), minted.Load())
	}
}

// TestAFailureFromGitHubIsOneLine has GitHub's API refuse the mint with a message that
// contains control characters, Unicode line separators and a bidirectional formatting
// character, and checks that the failure is still one line on standard error, with each
// of them escaped.
func TestAFailureFromGitHubIsOneLine(t *testing.T) {
	file, _ := keyFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/installation") {
			io.WriteString(w, `{"id":42}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"message":"a\r\nb\rc\td\u007fe\u0085f\u2028g\u2029h\ni\u202ej"}`)
	}))
	t.Cleanup(srv.Close)
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"credential", "--settings", settings(t, map[string]any{"private_key_file": file, "api_url": srv.URL}), "--", "acme/shop"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Error(err)
	}
	line := strings.TrimSuffix(errs.String(), "\n")
	if i := strings.IndexFunc(line, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Bidi_Control, r)
	}); i >= 0 {
		t.Errorf("stderr contains %q: %q", []rune(line[i:])[0], errs.String())
	}
	if want := `403: a b\rc\td\x7fe\u0085f\u2028g\u2029h i\u202ej` + "\n"; !strings.HasSuffix(errs.String(), want) {
		t.Errorf("stderr %q, want it to end in %q", errs.String(), want)
	}
}

// TestDescribeConformsAndIsPinned checks what describe prints against the integration
// contract and pins it to testdata/describe.json, so a change to the description is a
// change to that file too. The contract's fixture fixtures/github.json is the
// description of 0.1.0, an example of the contract's; this copy is the program's.
func TestDescribeConformsAndIsPinned(t *testing.T) {
	// The pinned copy is the description of a build with no version, whatever version
	// the test binary's build info contains.
	defer func(v string) { version = v }(version)
	version = "dev"
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"describe"}, &out, &errs); code != 0 || errs.Len() != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if err := conformance.Description(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.ReadFile("../../testdata/describe.json")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(pinned) {
		t.Errorf("describe prints\n%s\nand testdata/describe.json contains\n%s", out.String(), pinned)
	}
	out.Reset()
	errs.Reset()
	code := run(context.Background(), []string{"describe", "--settings", "{}"}, &out, &errs)
	if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
		t.Errorf("describe with settings: %v", err)
	}
}

// fakeGitHub answers the manifest flow's exchange with the App 123456 and a key.
func fakeGitHub(t *testing.T) string {
	t.Helper()
	_, pemBytes := keyFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/abc/conversions" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		answer := map[string]any{"id": 123456, "slug": "qory-github-test", "client_id": "Iv1.test", "html_url": "https://github.com/apps/qory-github-test", "pem": string(pemBytes)}
		if fakeClientSecret != "" {
			answer["client_secret"] = fakeClientSecret
		}
		json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// testClientSecret is the client secret GitHub hands out with the App.
const testClientSecret = "a-client-secret-of-the-app"

// fakeClientSecret is the client secret fakeGitHub answers with; empty, it answers
// without one.
var fakeClientSecret = testClientSecret

// approve is the browser and the person: it reads the local page's state and follows
// GitHub's redirect with a code.
func approve(local string) error {
	resp, err := http.Get(local)
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	state := regexp.MustCompile(`state=([0-9a-f]+)`).FindSubmatch(b)
	if state == nil {
		return fmt.Errorf("the page contains no state:\n%s", b)
	}
	u, err := url.Parse(local)
	if err != nil {
		return err
	}
	resp, err = http.Get(u.Scheme + "://" + u.Host + "/callback?code=abc&state=" + string(state[1]))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestSetupPrintsTheDeclarationAndThePolicy runs setup whole and pins what it prints once
// the App is created: where it is installed, the integration's declaration, and the
// policy that allows GitHub's hosts and selects the credential qory expands it into.
func TestSetupPrintsTheDeclarationAndThePolicy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "github-app.pem")
	s := github.Setup{Name: "qory-github-test", KeyFile: file, Web: "https://github.com", Client: github.Client{API: fakeGitHub(t)}, Open: approve, Wait: time.Minute}
	var out bytes.Buffer
	if err := runSetup(context.Background(), s, &out); err != nil {
		t.Fatal(err)
	}
	integrations, policy, err := declaration(123456, file)
	if err != nil {
		t.Fatal(err)
	}
	_, printed, _ := strings.Cut(out.String(), "\n\n")
	want := `The App 123456 (qory-github-test) is created, and its private key is in ` + file + `.

Install it on the repositories your agents work on:
  https://github.com/apps/qory-github-test/installations/new

Then declare the integration in the machine's configuration, ~/.config/qory/forager.yaml:

` + integrations + `
qory expands the declaration into the gateway's credential github. A run's policy selects it
with the repositories the run works on, and allows GitHub's hosts beside the others the
run reaches:

` + policy
	if printed != want {
		t.Errorf("setup prints\n%s\nwant\n%s", printed, want)
	}
}

// TestADeclarationExpandsToWhatTheCredentialReads expands the declaration setup prints
// as the integration contract describes and hands the adapter's settings word to the
// command, a key file whose path has a quote and a dollar sign in it.
func TestADeclarationExpandsToWhatTheCredentialReads(t *testing.T) {
	file := filepath.Join(t.TempDir(), "it's ${argument}.pem")
	integrations, _, err := declaration(123456, file)
	if err != nil {
		t.Fatal(err)
	}
	credentials := expand(t, integrations)
	var c struct {
		Credentials map[string]struct {
			Adapter  []string `yaml:"adapter"`
			Argument string   `yaml:"argument"`
			Hosts    []string `yaml:"hosts"`
		} `yaml:"credentials"`
	}
	if err := yaml.Unmarshal([]byte(credentials), &c); err != nil {
		t.Fatalf("%v\n%s", err, credentials)
	}
	def := c.Credentials["github"]
	if len(def.Adapter) != 6 || def.Adapter[2] != "--settings" || def.Adapter[4] != "--" || def.Adapter[5] != "${argument}" || strings.Contains(def.Adapter[3], "${argument}") {
		t.Fatalf("adapter %q", def.Adapter)
	}
	s, err := github.ReadSettings(def.Adapter[3])
	if err != nil || s.AppID != "123456" || s.PrivateKeyFile != file {
		t.Errorf("settings %+v, %v", s, err)
	}
	d := github.Describe(version)
	if def.Argument != d.Roles.Credential.Argument || strings.Join(def.Hosts, " ") != strings.Join(d.Roles.Credential.Hosts, " ") {
		t.Errorf("definition %+v", def)
	}
}

// TestSetupRefusesAKeyPathItCannotDeclare pins that setup refuses, in one line and
// before the App is created, a key file's path the declaration cannot contain as it is
// written: a control character, C0, DEL or C1, or bytes that are not UTF-8.
func TestSetupRefusesAKeyPathItCannotDeclare(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"new\nline", "control character"},
		{"nul\x00", "control character"},
		{"del\x7f", "control character"},
		{"c1\u0085", "control character"},
		{"latin1\xe9", "not UTF-8"},
	} {
		opened := false
		s := github.Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), tc.name+".pem"), Client: github.Client{API: "http://127.0.0.1:1"}, Open: func(string) error { opened = true; return nil }, Wait: time.Second}
		var out bytes.Buffer
		err := runSetup(context.Background(), s, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "\n") || opened || out.Len() != 0 {
			t.Errorf("%q: %v, opened %v, printed %q", tc.name, err, opened, out.String())
		}
	}
}

// TestSetupCreatesNothingForARefusedPath pins that a default key file under a home
// whose path setup refuses is refused before ~/.config/qory is created.
func TestSetupCreatesNothingForARefusedPath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "h\x01me")
	t.Setenv("HOME", home)
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"setup"}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "control character") || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errs.String())
	}
	if _, err := os.Stat(home); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("setup created %s: %v", home, err)
	}
}

// TestSetupRefusesAnotherURLBeforeAnything runs setup with an API or a website it
// refuses and checks that it fails in one line, before it creates the key's directory,
// listens, opens the browser or sends a request, and never says the URL.
func TestSetupRefusesAnotherURLBeforeAnything(t *testing.T) {
	// Should a URL get past the checks, setup opens no browser and waits no longer than
	// the test's context.
	defer func(o func(string) error) { opener = o }(opener)
	opener = func(string) error {
		t.Error("setup opens the browser")
		return nil
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"setup", "--api-url", "https://ghe.acme.example/api/v3"}, "qory-github setup: the API is neither https://api.github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported\n"},
		{[]string{"setup", "--api-url", "http://api.github.com"}, "qory-github setup: the API is neither https://api.github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported\n"},
		{[]string{"setup", "--web-url", "https://ghe.acme.example"}, "qory-github setup: the web URL is neither https://github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported\n"},
		{[]string{"setup", "--web-url", "https://github.com:443"}, "qory-github setup: the web URL is neither https://github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported\n"},
	} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var out, errs bytes.Buffer
		code := run(ctx, tc.args, &out, &errs)
		cancel()
		if err := conformance.Failure(code, out.Bytes(), errs.Bytes()); err != nil {
			t.Errorf("%q: %v", tc.args, err)
		}
		if errs.String() != tc.want {
			t.Errorf("%q: stderr %q, want %q", tc.args, errs.String(), tc.want)
		}
		if _, err := os.Stat(filepath.Join(home, ".config")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%q: setup created %s: %v", tc.args, filepath.Join(home, ".config"), err)
		}
	}
}

// TestSetupPrintsWhereAMovedKeyIs creates the key file while the person approves, so the
// key goes beside it, and pins the line setup prints: where the key is, the file that
// could not be written once, and why.
func TestSetupPrintsWhereAMovedKeyIs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "github-app.pem")
	open := func(local string) error {
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			return err
		}
		return approve(local)
	}
	s := github.Setup{Name: "qory-github-test", KeyFile: file, Web: "https://github.com", Client: github.Client{API: fakeGitHub(t)}, Open: open, Wait: time.Minute}
	var out bytes.Buffer
	if err := runSetup(context.Background(), s, &out); err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`\nThe key is in (\S+), since (\S+) could not be written: it exists\.\n`).FindStringSubmatch(out.String())
	if line == nil || !strings.HasPrefix(line[1], file+".") || line[2] != file || strings.Contains(out.String(), "choose another") {
		t.Errorf("setup prints\n%s", out.String())
	}
}

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
		if got := movedLine(beside, file, tc.moved); got != tc.want {
			t.Errorf("%v: setup prints %q, want %q", tc.moved, got, tc.want)
		}
	}
}

// TestTheReadmesShowWhatSetupPrints pins README.md to what setup prints for its default
// key file: the declaration and the policy, and no credential definition.
func TestTheReadmesShowWhatSetupPrints(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	integrations, policy, err := declaration(123456, "/home/dev/.config/qory/github-app.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readme, []byte("```yaml\n"+integrations+"```")) || !bytes.Contains(readme, []byte("```yaml\n"+policy+"```")) {
		t.Errorf("README.md does not show what setup prints:\n%s\n%s", integrations, policy)
	}
	if bytes.Contains(readme, []byte("    adapter: [")) {
		t.Error("README.md shows a credential definition, which qory expands from the declaration")
	}
}

// expand is a declaration as the integration contract's reader expands it (§Declaring an
// integration, step 4), in the order declared: for each key, the credential of the same
// key, with the adapter [<program>, credential, --settings, <json>, --, "${argument}"],
// the program qory-<key> when none is declared, <json> the settings, {} when none are
// declared, as compact JSON with every $ written \u0024, in a single-quoted scalar, and
// the argument and the hosts of qory-github's description. The contract's example,
// with an integration of another program beside it, is tested in qoryai/integrations.
func expand(t *testing.T, integrations string) string {
	t.Helper()
	var doc struct {
		Gateway struct {
			Integrations yaml.Node `yaml:"integrations"`
		} `yaml:"gateway"`
	}
	if err := yaml.Unmarshal([]byte(integrations), &doc); err != nil || doc.Gateway.Integrations.Kind != yaml.MappingNode {
		t.Fatalf("%v\n%s", err, integrations)
	}
	var b strings.Builder
	b.WriteString("credentials:\n")
	nodes := doc.Gateway.Integrations.Content
	for i := 0; i+1 < len(nodes); i += 2 {
		key := nodes[i].Value
		var decl struct {
			Program  string         `yaml:"program"`
			Settings map[string]any `yaml:"settings"`
		}
		if err := nodes[i+1].Decode(&decl); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if decl.Program == "" {
			decl.Program = "qory-" + key
		}
		if decl.Settings == nil {
			decl.Settings = map[string]any{}
		}
		var settings bytes.Buffer
		enc := json.NewEncoder(&settings)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(decl.Settings); err != nil {
			t.Fatal(err)
		}
		if decl.Program != "qory-github" {
			t.Fatalf("%s: the program %s is not qory-github", key, decl.Program)
		}
		d := github.Describe(version)
		word := strings.ReplaceAll(strings.TrimSuffix(settings.String(), "\n"), "$", `\u0024`)
		fmt.Fprintf(&b, `  %s:
    adapter: [%s, credential, --settings, %s, --, "${argument}"]
    argument: %s
    hosts: [%s]
`, key, decl.Program, quote(word), quote(d.Roles.Credential.Argument), strings.Join(d.Roles.Credential.Hosts, ", "))
	}
	return b.String()
}

// quote is YAML's single-quoted scalar, in which nothing is an escape but the quote,
// doubled.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func TestNoCommandIsUsage(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run(context.Background(), nil, &out, &errs); code != 2 || !strings.Contains(errs.String(), "usage:") {
		t.Errorf("exit %d: %s", code, errs.String())
	}
}

// usageBefore is the usage as it was before serve and access-key, which it is whatever
// QORY_FEATURES says.
const usageBefore = `qory-github mints GitHub App access tokens for Qory's gateway. The agent works on
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

// TestQoryGithubHasNoServeOrAccessKey pins that serve and access-key, which are
// qory-github-server's, are in no usage of qory-github and are answered as commands it
// does not know, whatever QORY_FEATURES says, factory on among them.
func TestQoryGithubHasNoServeOrAccessKey(t *testing.T) {
	for _, features := range []string{"", "all", "all-security,factory", "factory2", "factory,all", "factory", "observability, factory ", " factory,"} {
		t.Setenv("QORY_FEATURES", features)
		var out, errs bytes.Buffer
		if code := run(context.Background(), nil, &out, &errs); code != 2 || errs.String() != usageBefore || out.Len() != 0 {
			t.Errorf("QORY_FEATURES=%q: exit %d, usage:\n%s", features, code, errs.String())
		}
		for _, args := range [][]string{
			{"serve"}, {"serve", "-h"}, {"serve", "--settings", "/none.json"},
			{"access-key"}, {"access-key", "-h"}, {"access-key", "enrol", "-h"}, {"access-key", "enrol", "--secret-file", "/none", "https://apiary.example.com", "qec_0"},
		} {
			var out, errs bytes.Buffer
			if code := run(context.Background(), args, &out, &errs); code != 2 || errs.String() != usageBefore || out.Len() != 0 {
				t.Errorf("QORY_FEATURES=%q %v: exit %d, %q", features, args, code, errs.String())
			}
		}
	}
}

// setupWhole runs setup whole, with the flags args after the fake API and the App's
// name, as the command line does, approving in place of the browser and person. It
// returns the exit status, what setup printed on stdout and stderr, and the manifest
// the page posts.
func setupWhole(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	var manifest string
	saved := opener
	t.Cleanup(func() { opener = saved })
	opener = func(local string) error {
		resp, err := http.Get(local)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := regexp.MustCompile(`name="manifest" value="([^"]+)"`).FindSubmatch(b)
		if m == nil {
			return fmt.Errorf("the page contains no manifest:\n%s", b)
		}
		manifest = html.UnescapeString(string(m[1]))
		return approve(local)
	}
	var out, errs bytes.Buffer
	code := run(context.Background(), append([]string{"setup", "--api-url", fakeGitHub(t), "--name", "qory-github-test"}, args...), &out, &errs)
	return code, out.String(), errs.String(), manifest
}

// setupPrinted is what setup printed at ce7d970, before Connect, for the App 123456
// whose key is in file.
func setupPrinted(t *testing.T, file string) string {
	t.Helper()
	integrations, policy, err := declaration(123456, file)
	if err != nil {
		t.Fatal(err)
	}
	return `The App 123456 (qory-github-test) is created, and its private key is in ` + file + `.

Install it on the repositories your agents work on:
  https://github.com/apps/qory-github-test/installations/new

Then declare the integration in the machine's configuration, ~/.config/qory/forager.yaml:

` + integrations + `
qory expands the declaration into the gateway's credential github. A run's policy selects it
with the repositories the run works on, and allows GitHub's hosts beside the others the
run reaches:

` + policy
}

// manifestBefore is the manifest setup posted at ce7d970, before Connect, with the
// redirect URL redirect.
func manifestBefore(redirect string) string {
	return `{"default_events":[],"default_permissions":{"contents":"write","metadata":"read","pull_requests":"write"},"hook_attributes":{"active":false,"url":"https://github.com/qoryai/qory-github"},"name":"qory-github-test","public":false,"redirect_url":"` + redirect + `","url":"https://github.com/qoryai/qory-github"}`
}

// setupFlagsBefore are setup's flags as -h printed them at ce7d970.
const setupFlagsBefore = `flags:
  -api-url string
    	GitHub's API: https://api.github.com, or for a test http or https on a loopback host (default "https://api.github.com")
  -key-file string
    	where the private key is written (default ~/.config/qory/github-app.pem)
  -name string
    	the App's name (default qory-github- and six random hex digits)
  -org string
    	create the App under this organisation
  -web-url string
    	GitHub's website: https://github.com, or for a test http or https on a loopback host (default "https://github.com")
`

// TestSetupWithoutFactoryIsAsItWas pins that, unless QORY_FEATURES names factory, setup
// takes the flags it took, posts the manifest it posted and prints what it printed
// before Connect, and keeps no client secret; and that with factory but no
// --public-url it does the same.
func TestSetupWithoutFactoryIsAsItWas(t *testing.T) {
	for _, features := range []string{"", "all", "factory"} {
		t.Setenv("QORY_FEATURES", features)
		dir := t.TempDir()
		file := filepath.Join(dir, "github-app.pem")
		code, out, errs, manifest := setupWhole(t, "--key-file", file)
		first, printed, _ := strings.Cut(out, "\n\n")
		page := strings.TrimPrefix(first, "Approve the App in the browser. If none opened, open ")
		if code != 0 || errs != "" || printed != setupPrinted(t, file) || page == first {
			t.Errorf("QORY_FEATURES=%q: exit %d, stderr %q, setup prints\n%s", features, code, errs, out)
		}
		u, _ := url.Parse(page)
		if manifest != manifestBefore(u.Scheme+"://"+u.Host+"/callback") {
			t.Errorf("QORY_FEATURES=%q: the manifest %s", features, manifest)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 || strings.Contains(out, testClientSecret) {
			t.Errorf("QORY_FEATURES=%q: the directory holds %v", features, entries)
		}
		var help bytes.Buffer
		run(context.Background(), []string{"setup", "-h"}, &bytes.Buffer{}, &help)
		_, flags, _ := strings.Cut(help.String(), "\nflags:\n")
		flags, _, _ = strings.Cut(flags, "\nexamples:")
		if features != "factory" && "flags:\n"+flags != setupFlagsBefore {
			t.Errorf("QORY_FEATURES=%q: setup -h prints the flags\n%s", features, flags)
		}
	}
	t.Setenv("QORY_FEATURES", "")
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"setup", "--public-url", "https://qory-github.example.com"}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "flag provided but not defined: -public-url") {
		t.Errorf("--public-url without factory: exit %d, %q", code, errs.String())
	}
}

// TestSetupWithFactoryKeepsTheClientSecretForConnect pins that with factory and
// --public-url the App gets what Connect needs, its client secret is written beside the
// key for its owner alone and never printed, and setup prints serve's settings for it.
func TestSetupWithFactoryKeepsTheClientSecretForConnect(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	dir := t.TempDir()
	file := filepath.Join(dir, "github-app.pem")
	code, out, errs, manifest := setupWhole(t, "--key-file", file, "--public-url", "https://qory-github.example.com/")
	secretFile := filepath.Join(dir, "github-app.client-secret")
	path, _ := json.Marshal(secretFile)
	_, printed, _ := strings.Cut(out, "\n\n")
	want := setupPrinted(t, file) + `
The App's client secret is in ` + secretFile + `, which only you may read. Add these settings to
qory-github-server serve's settings, for Connect:

  "client_id": "Iv1.test",
  "client_secret_file": ` + string(path) + `
`
	if code != 0 || errs != "" || printed != want || strings.Contains(out, testClientSecret) {
		t.Errorf("exit %d, stderr %q, setup prints\n%s\nwant\n%s", code, errs, printed, want)
	}
	var m map[string]any
	json.Unmarshal([]byte(manifest), &m)
	urls, _ := json.Marshal(m["callback_urls"])
	if len(m) != 11 || m["setup_url"] != "https://qory-github.example.com/v1/connect/return" || m["setup_on_update"] != true ||
		string(urls) != `["https://qory-github.example.com/v1/connect/authorized"]` || m["request_oauth_on_install"] != false {
		t.Errorf("the manifest %s", manifest)
	}
	info, err := os.Stat(secretFile)
	b, _ := os.ReadFile(secretFile)
	if err != nil || info.Mode().Perm() != 0o600 || string(b) != testClientSecret+"\n" {
		t.Errorf("the client secret file: %v %v %q", info, err, b)
	}
	// A client secret file that exists, or a public URL that is not https of a host, an
	// optional port and an optional path, is refused before any App is created.
	for _, args := range [][]string{
		{"--key-file", filepath.Join(dir, "other.pem"), "--public-url", "http://qory-github.example.com"},
		{"--key-file", filepath.Join(dir, "other.pem"), "--public-url", "https://qory-github.example.com/#a"},
		{"--key-file", filepath.Join(dir, "other.pem"), "--public-url", "https://qory-github.example.com:0"},
		{"--key-file", file + ".2", "--public-url", "https://qory-github.example.com"},
	} {
		want := "--public-url is not an https URL of a host, an optional port and an optional path, without a user, a query or a fragment"
		if args[1] == file+".2" {
			os.WriteFile(file+".2.client-secret", nil, 0o600)
			want = "client-secret"
		}
		var out, errs bytes.Buffer
		if code := run(context.Background(), append([]string{"setup", "--api-url", "http://127.0.0.1:1"}, args...), &out, &errs); code != 1 || out.Len() != 0 || !strings.Contains(errs.String(), want) {
			t.Errorf("%v: exit %d, %q %q", args, code, out.String(), errs.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "other.pem")); err == nil {
		t.Error("a key is written")
	}
}

// TestSetupSaysAfterItsOutputThatTheClientSecretIsNotKept pins that when GitHub answers
// without a client secret, setup still prints the App, its install page and the
// declaration, then fails saying where to generate the client secret.
func TestSetupSaysAfterItsOutputThatTheClientSecretIsNotKept(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	fakeClientSecret = ""
	t.Cleanup(func() { fakeClientSecret = testClientSecret })
	dir := t.TempDir()
	file := filepath.Join(dir, "github-app.pem")
	code, out, errs, _ := setupWhole(t, "--key-file", file, "--public-url", "https://qory-github.example.com")
	_, printed, _ := strings.Cut(out, "\n\n")
	if code != 1 || printed != setupPrinted(t, file) ||
		!strings.Contains(errs, "the App's client secret was not kept: GitHub's answer holds no client id, or no client secret setup can keep; generate a client secret at ") {
		t.Errorf("exit %d, stderr %q, setup prints\n%s", code, errs, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "github-app.client-secret")); err == nil {
		t.Error("a client secret file is written")
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the key: %v", err)
	}
}

// othersFile is a file's info as Stat gives it, 0600 and another user's.
type othersFile struct{ fs.FileInfo }

func (othersFile) Mode() fs.FileMode { return 0o600 }
func (othersFile) Sys() any          { return &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)} }

// TestAnotherUsersFileNamesQoryGithub pins that a key file that belongs to another user
// is refused with an error that names qory-github, as it did before qory-github-server.
func TestAnotherUsersFileNamesQoryGithub(t *testing.T) {
	err := ownerfile.Check(othersFile{}, "the private key file /k.pem")
	if want := "the private key file /k.pem belongs to another user than the one qory-github runs as"; err == nil || err.Error() != want {
		t.Errorf("err %v, want %q", err, want)
	}
}
