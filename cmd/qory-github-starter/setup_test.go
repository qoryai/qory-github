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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/starter"
)

// fakeSetupGitHub is GitHub's API as the starter's setup reaches it: the manifest
// flow's exchange answers the App 123456 and a key. It records each request's method,
// path and User-Agent.
type fakeSetupGitHub struct {
	url string
	key *rsa.PrivateKey

	mu       sync.Mutex
	requests []string
	agents   []string
}

func newFakeSetupGitHub(t *testing.T) *fakeSetupGitHub {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSetupGitHub{key: k}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.agents = append(f.agents, r.Header.Get("User-Agent"))
		f.mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/abc/conversions" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": 123456, "slug": "qory-github-starter-test", "client_id": "Iv1.test", "html_url": "https://github.com/apps/qory-github-starter-test",
			"pem": string(pemBytes), "client_secret": "not-kept", "webhook_secret": nil})
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// sent are the requests f received and their User-Agents.
func (f *fakeSetupGitHub) sent() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...), append([]string(nil), f.agents...)
}

// approveSetup is the browser and the person: it reads the local page, returns the
// manifest it posts and where, and follows GitHub's redirect with the state and a code.
func approveSetup(local string) (manifest, action string, err error) {
	resp, err := http.Get(local)
	if err != nil {
		return "", "", err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="manifest" value="([^"]+)"`).FindSubmatch(b)
	a := regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(b)
	if m == nil || a == nil {
		return "", "", fmt.Errorf("the page contains no form:\n%s", b)
	}
	manifest, action = html.UnescapeString(string(m[1])), html.UnescapeString(string(a[1]))
	au, err := url.Parse(action)
	if err != nil {
		return "", "", err
	}
	u, err := url.Parse(local)
	if err != nil {
		return "", "", err
	}
	resp, err = http.Get(u.Scheme + "://" + u.Host + "/callback?code=abc&state=" + au.Query().Get("state"))
	if err != nil {
		return "", "", err
	}
	resp.Body.Close()
	return manifest, action, nil
}

// setupRun runs setup whole with factory on, the flags args after the fake's API,
// approving in place of the browser and the person. It returns the exit status, what
// setup printed on stdout and stderr, the manifest the page posts and where; manifest
// and action are empty when no page was opened.
func setupRun(t *testing.T, f *fakeSetupGitHub, args ...string) (code int, out, errs, manifest, action string) {
	t.Helper()
	t.Setenv("QORY_FEATURES", "factory")
	saved := opener
	t.Cleanup(func() { opener = saved })
	opener = func(local string) error {
		var err error
		manifest, action, err = approveSetup(local)
		return err
	}
	var o, e bytes.Buffer
	code = run(context.Background(), append([]string{"setup", "--api-url", f.url}, args...), &o, &e)
	return code, o.String(), e.String(), manifest, action
}

// TestSetupCreatesTheStartersApp runs setup whole and pins the manifest the page posts,
// byte for byte, where it posts it, what setup prints, the key file it writes, and that
// the settings it prints, with the starter's other fields, are settings the starter
// reads, and its key file one it reads.
func TestSetupCreatesTheStartersApp(t *testing.T) {
	f := newFakeSetupGitHub(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "github-app.pem")
	code, out, errs, manifest, action := setupRun(t, f, "--key-file", file, "--name", "qory-github-starter-test")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q, stdout\n%s", code, errs, out)
	}
	first, printed, _ := strings.Cut(out, "\n")
	page, ok := strings.CutPrefix(first, "Approve the App in the browser. If none opened, open ")
	u, err := url.Parse(page)
	if !ok || err != nil || u.Scheme != "http" || !regexp.MustCompile(`^/[0-9a-f]{32}$`).MatchString(u.Path) {
		t.Fatalf("setup prints first %q", first)
	}
	wantManifest := `{"default_events":[],"default_permissions":{"actions":"write","metadata":"read"},"hook_attributes":{"active":false,"url":"https://github.com/qoryai/qory-github"},"name":"qory-github-starter-test","public":false,"redirect_url":"` +
		u.Scheme + "://" + u.Host + `/callback","url":"https://github.com/qoryai/qory-github"}`
	if manifest != wantManifest {
		t.Errorf("the manifest is\n%s\nwant\n%s", manifest, wantManifest)
	}
	if a, _ := url.Parse(action); a == nil || a.Scheme != "https" || a.Host != "github.com" || a.Path != "/settings/apps/new" || a.Query().Get("state") == "" {
		t.Errorf("the page posts to %s", action)
	}
	fileJSON, _ := json.Marshal(file)
	want := `
The App 123456 (qory-github-starter-test) is created, and its private key is in ` + file + `.

Install it on the one repository the starter's settings name as repository:
  https://github.com/apps/qory-github-starter-test/installations/new

Then add these to the starter's settings:

  "app_id": 123456,
  "private_key_file": ` + string(fileJSON) + `,
  "api_url": "` + f.url + `"
`
	if printed != want {
		t.Errorf("setup prints\n%s\nwant\n%s", printed, want)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key file: %v, %v", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %v", entries)
	}
	if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "not-kept") {
		t.Errorf("setup printed the key or the client secret:\n%s", out)
	}
	requests, agents := f.sent()
	if len(requests) != 1 || requests[0] != "POST /app-manifests/abc/conversions" || agents[0] != "qory-github-starter/"+version {
		t.Errorf("the requests %q with the User-Agents %q", requests, agents)
	}

	// The settings printed, with the starter's other fields, are settings the starter
	// reads, and the key file is one it reads.
	_, members, _ := strings.Cut(printed, "the starter's settings:\n\n")
	settings := filepath.Join(t.TempDir(), "starter.json")
	doc := `{"apiary_url": "https://apiary.example.com", "access_key_id": "ak_0123456789abcdef", "access_key_secret_file": "/etc/qory-github-starter/access-key-secret",
  "apiary_public_key": [{"alg": "ed25519", "public_key": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}],
  "listen": "127.0.0.1:8080", "public_url": "https://starter.example.com", "state_dir": "/var/lib/qory-github-starter",
  "repository": "example-org/runners", "workflow": "qory-runner.yml", "ref": "main",
` + members + `}`
	if err := os.WriteFile(settings, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := starter.ReadSettings(settings)
	if err != nil || s.AppID != "123456" || s.PrivateKeyFile != file || s.APIURL != f.url {
		t.Fatalf("the starter's settings: %+v, %v", s, err)
	}
	if k, err := starter.ReadPrivateKey(s.PrivateKeyFile); err != nil || !k.Equal(f.key) {
		t.Errorf("the key file does not read back: %v", err)
	}
}

// TestSetupNamesTheStartersAppByDefault pins the App's name without --name:
// qory-github-starter- and six random hex digits.
func TestSetupNamesTheStartersAppByDefault(t *testing.T) {
	f := newFakeSetupGitHub(t)
	code, _, errs, manifest, _ := setupRun(t, f, "--key-file", filepath.Join(t.TempDir(), "github-app.pem"))
	var m struct{ Name string }
	if json.Unmarshal([]byte(manifest), &m); code != 0 || !regexp.MustCompile(`^qory-github-starter-[0-9a-f]{6}$`).MatchString(m.Name) {
		t.Errorf("exit %d, stderr %q, the default name is %q", code, errs, m.Name)
	}
}

// TestSetupRefusesBeforeAnything pins that setup refuses, with one line on stderr and
// before it listens, opens the browser or sends a request: no --key-file, an argument, a
// key file that exists, a key file's path that the settings cannot contain, an API or a
// website that is not GitHub's, and a flag it does not take.
func TestSetupRefusesBeforeAnything(t *testing.T) {
	f := newFakeSetupGitHub(t)
	dir := t.TempDir()
	exists := filepath.Join(dir, "exists.pem")
	if err := os.WriteFile(exists, []byte("someone's"), 0o600); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(dir, "a\nb.pem")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "qory-github-starter setup: --key-file is required\n"},
		{[]string{"--key-file", filepath.Join(dir, "a.pem"), "extra"}, "qory-github-starter setup: setup takes no arguments\n"},
		{[]string{"--key-file", exists}, "qory-github-starter setup: the key file " + exists + " exists; choose another or move it away\n"},
		{[]string{"--key-file", control}, fmt.Sprintf("qory-github-starter setup: the key file's path %q contains a control character; choose another with --key-file\n", control)},
		{[]string{"--key-file", filepath.Join(dir, "a.pem"), "--web-url", "https://github.example.com"}, "qory-github-starter setup: the web URL is neither https://github.com nor, for a test, http or https on a loopback host; GitHub Enterprise Server is not supported\n"},
	} {
		saved := opener
		opener = func(string) error { t.Error("setup opened the browser"); return nil }
		code, out, errs, _, _ := setupRun(t, f, tc.args...)
		opener = saved
		if code != 1 || out != "" || errs != tc.want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q, want %q", tc.args, code, out, errs, tc.want)
		}
	}
	// An API that is not GitHub's is refused before it is reached.
	t.Setenv("QORY_FEATURES", "factory")
	saved := opener
	opener = func(string) error { t.Error("setup opened the browser"); return nil }
	defer func() { opener = saved }()
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"setup", "--api-url", "https://api.github.example.com", "--key-file", filepath.Join(dir, "a.pem")}, &out, &errs); code != 1 || out.Len() != 0 ||
		!strings.HasPrefix(errs.String(), "qory-github-starter setup: ") || strings.Count(errs.String(), "\n") != 1 {
		t.Errorf("another API: exit %d, %q %q", code, out.String(), errs.String())
	}
	errs.Reset()
	if code := run(context.Background(), []string{"setup", "--public-url", "https://starter.example.com", "--key-file", filepath.Join(dir, "a.pem")}, &out, &errs); code != 1 ||
		!strings.HasPrefix(errs.String(), "flag provided but not defined: -public-url\nusage:\n  qory-github-starter setup --key-file FILE [--org ORG] [--name NAME]\n") ||
		!strings.HasSuffix(errs.String(), "qory-github-starter setup: flag provided but not defined: -public-url\n") {
		t.Errorf("--public-url: exit %d, %q", code, errs.String())
	}
	if requests, _ := f.sent(); len(requests) != 0 {
		t.Errorf("setup sent %q", requests)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %v", entries)
	}
	if _, err := os.Lstat(filepath.Join(dir, "a.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a key file was written: %v", err)
	}
}

// setupHelpText is setup's whole -h output.
const setupHelpText = `Create the starter's GitHub App, and write its private key.

setup opens GitHub in the browser with the App filled in: private, no webhook, actions
write, metadata read. You approve it there; nothing is created without you. setup
waits ten minutes at most.

The private key goes to --key-file, which only you may read. setup never writes over a
file that exists, and never prints the key. GitHub hands the key out once: when the
file cannot be written, the key goes beside it, and setup prints where.

Then setup prints where to install the App, and the two settings to add to the
starter's settings: app_id and private_key_file. Install the App on the one repository
the starter's settings name as repository.

usage:
  qory-github-starter setup --key-file FILE [--org ORG] [--name NAME]

flags:
  -api-url string
    	GitHub's API: https://api.github.com, or for a test http or https on a loopback host (default "https://api.github.com")
  -key-file string
    	where the private key is written; a file that exists is refused (required)
  -name string
    	the App's name (default qory-github-starter- and six random hex digits)
  -org string
    	create the App under this organisation
  -web-url string
    	GitHub's website: https://github.com, or for a test http or https on a loopback host (default "https://github.com")

examples:
  qory-github-starter setup --key-file /etc/qory-github-starter/github-app.pem              # under your account
  qory-github-starter setup --org acme --key-file /etc/qory-github-starter/github-app.pem   # under the organisation acme
`

// TestSetupHelpIsPinned pins setup's whole -h output with factory on, and that it opens
// nothing.
func TestSetupHelpIsPinned(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	saved := opener
	opener = func(string) error { t.Error("setup opened the browser"); return nil }
	defer func() { opener = saved }()
	for _, args := range [][]string{{"setup", "-h"}, {"setup", "--help"}} {
		var out, errs bytes.Buffer
		if code := run(context.Background(), args, &out, &errs); code != 2 || out.Len() != 0 || errs.String() != setupHelpText {
			t.Errorf("%q: exit %d, stderr\n%s\nwant\n%s", args, code, errs.String(), setupHelpText)
		}
	}
}

// TestSetupPrintsAPIURLOnlyWhenItIsGiven pins that setup hands the settings it prints
// the --api-url given, and none without it, and what it prints for each: app_id and
// private_key_file, and api_url only when it is given, with the value given.
func TestSetupPrintsAPIURLOnlyWhenItIsGiven(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	saved := setupRunner
	defer func() { setupRunner = saved }()
	for _, tc := range []struct {
		args       []string
		api, given string
	}{
		{nil, "https://api.github.com", ""},
		{[]string{"--api-url", "https://api.github.com/"}, "https://api.github.com/", "https://api.github.com/"},
		{[]string{"--api-url", "http://127.0.0.1:1"}, "http://127.0.0.1:1", "http://127.0.0.1:1"},
	} {
		var api, given string
		ran := false
		setupRunner = func(_ context.Context, s github.Setup, apiURL string, _ io.Writer) error {
			ran, api, given = true, s.Client.API, apiURL
			return nil
		}
		var out, errs bytes.Buffer
		code := run(context.Background(), append([]string{"setup", "--key-file", filepath.Join(t.TempDir(), "github-app.pem")}, tc.args...), &out, &errs)
		if code != 0 || !ran || api != tc.api || given != tc.given {
			t.Errorf("%q: exit %d, %q, ran %v, the API %q, the api_url printed %q", tc.args, code, errs.String(), ran, api, given)
		}
	}
	setupRunner = saved

	// Without --api-url the settings printed are app_id and private_key_file alone.
	f := newFakeSetupGitHub(t)
	file := filepath.Join(t.TempDir(), "github-app.pem")
	open := func(local string) error { _, _, err := approveSetup(local); return err }
	s := github.Setup{Name: "qory-github-starter-test", KeyFile: file, Web: "https://github.com", Client: gitHub(f.url), Open: open, Starter: true}
	var out bytes.Buffer
	if err := runSetup(context.Background(), s, "", &out); err != nil {
		t.Fatal(err)
	}
	fileJSON, _ := json.Marshal(file)
	if _, printed, _ := strings.Cut(out.String(), "\n"); !strings.HasSuffix(printed, `
Then add these to the starter's settings:

  "app_id": 123456,
  "private_key_file": `+string(fileJSON)+`
`) {
		t.Errorf("setup prints\n%s", out.String())
	}
}

// TestSetupPrintsWhereAMovedKeyIs runs setup whole with a key file that appears once the
// page is open, and pins what it prints: the line that says where the key is instead
// and why, and the settings with that file as private_key_file.
func TestSetupPrintsWhereAMovedKeyIs(t *testing.T) {
	t.Setenv("QORY_FEATURES", "factory")
	f := newFakeSetupGitHub(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "github-app.pem")
	saved := opener
	defer func() { opener = saved }()
	opener = func(local string) error {
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			return err
		}
		_, _, err := approveSetup(local)
		return err
	}
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"setup", "--api-url", f.url, "--key-file", file, "--name", "qory-github-starter-test"}, &out, &errs); code != 0 || errs.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, errs.String())
	}
	_, printed, _ := strings.Cut(out.String(), "\n")
	beside := regexp.MustCompile(`^\nThe key is in (\S+), since `).FindStringSubmatch(printed)
	if beside == nil || !regexp.MustCompile(`^`+regexp.QuoteMeta(file)+`\.[0-9a-f]{16}$`).MatchString(beside[1]) {
		t.Fatalf("setup prints\n%s", out.String())
	}
	besideJSON, _ := json.Marshal(beside[1])
	want := `
The key is in ` + beside[1] + `, since ` + file + ` could not be written: it exists.

The App 123456 (qory-github-starter-test) is created, and its private key is in ` + beside[1] + `.

Install it on the one repository the starter's settings name as repository:
  https://github.com/apps/qory-github-starter-test/installations/new

Then add these to the starter's settings:

  "app_id": 123456,
  "private_key_file": ` + string(besideJSON) + `,
  "api_url": "` + f.url + `"
`
	if printed != want {
		t.Errorf("setup prints\n%s\nwant\n%s", printed, want)
	}
	if k, err := starter.ReadPrivateKey(beside[1]); err != nil || !k.Equal(f.key) {
		t.Errorf("the key beside the file does not read back: %v", err)
	}
	if b, err := os.ReadFile(file); err != nil || len(b) != 0 {
		t.Errorf("the file that appeared was written over: %d bytes, %v", len(b), err)
	}
}
