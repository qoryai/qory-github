package github

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// page reads the local page as the browser does: the form's action and the manifest.
func readPage(t *testing.T, local string) (string, map[string]any) {
	t.Helper()
	resp, err := http.Get(local)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	action := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(string(b))
	value := regexp.MustCompile(`name="manifest" value="([^"]+)"`).FindStringSubmatch(string(b))
	if action == nil || value == nil {
		t.Fatalf("the page contains no form:\n%s", b)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(value[1])), &m); err != nil {
		t.Fatal(err)
	}
	return html.UnescapeString(action[1]), m
}

// origin is the local page's scheme and host, where GitHub's redirect comes back to.
func origin(local string) string {
	u, err := url.Parse(local)
	if err != nil {
		panic(err)
	}
	return u.Scheme + "://" + u.Host
}

// TestSetupServesItsPageAtARandomPathAlone reads the local page at the URL setup opens,
// and at every other path a process on the machine might try, and checks that the state
// the page carries is in the page alone: any other path is not found, the redirect's
// path without the state is refused, and the page's path for another host is refused.
func TestSetupServesItsPageAtARandomPathAlone(t *testing.T) {
	var opened string
	s := Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), "app.pem"), Web: "https://github.com", Client: Client{API: unreachable(t)}, Open: func(u string) error { opened = u; return nil }, Wait: time.Minute}
	local, _, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(local)
	if opened != local || !regexp.MustCompile(`^/[0-9a-f]{32}$`).MatchString(u.Path) {
		t.Fatalf("setup opened %q and returned %q, want a random path", opened, local)
	}
	action, _ := readPage(t, local)
	a, _ := url.Parse(action)
	state := a.Query().Get("state")
	if len(state) != 32 {
		t.Fatalf("the page's state is %q", state)
	}
	paths := []string{"/", "", "/index.html", u.Path + "/", u.Path[:len(u.Path)-1], u.Path + "x", "/" + strings.Repeat("0", 32)}
	if upper := "/" + strings.ToUpper(u.Path[1:]); upper != u.Path {
		paths = append(paths, upper)
	}
	for _, tc := range []struct {
		path, host string
		want       int
	}{
		{"/callback", "", http.StatusBadRequest},
		{u.Path, "qory.attacker.test:" + u.Port(), http.StatusMisdirectedRequest},
		{u.Path, "localhost:" + u.Port(), http.StatusMisdirectedRequest},
	} {
		req, _ := http.NewRequest("GET", origin(local)+tc.path, nil)
		if tc.host != "" {
			req.Host = tc.host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want || strings.Contains(string(b), state) || strings.Contains(string(b), "manifest") {
			t.Errorf("GET %q for %q answered %d, want %d:\n%s", tc.path, tc.host, resp.StatusCode, tc.want, b)
		}
	}
	for _, path := range paths {
		resp, err := http.Get(origin(local) + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || strings.Contains(string(b), state) || strings.Contains(string(b), "manifest") {
			t.Errorf("GET %q answered %d:\n%s", path, resp.StatusCode, b)
		}
	}
}

func TestSetupCreatesTheAppAndWritesItsKeyForItsOwnerAlone(t *testing.T) {
	c := serve(t, &fakeGitHub{})
	file := filepath.Join(t.TempDir(), "app.pem")
	var opened string
	s := Setup{Org: "acme", Name: "qory-github-test", KeyFile: file, Web: "https://github.com", Client: c, Open: func(u string) error { opened = u; return nil }, Wait: time.Minute}
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opened != local {
		t.Errorf("opened %q, the page is %q", opened, local)
	}
	action, manifest := readPage(t, local)
	u, _ := url.Parse(action)
	if u.Host != "github.com" || u.Path != "/organizations/acme/settings/apps/new" || u.Query().Get("state") == "" {
		t.Errorf("the form posts to %s", action)
	}
	perms, _ := json.Marshal(manifest["default_permissions"])
	hook, _ := manifest["hook_attributes"].(map[string]any)
	if manifest["public"] != false || hook["active"] != false || string(perms) != `{"contents":"write","metadata":"read","pull_requests":"write"}` || manifest["redirect_url"] != origin(local)+"/callback" {
		t.Errorf("manifest %v", manifest)
	}

	callback := origin(local) + "/callback?state=" + u.Query().Get("state") + "&code="
	// A redirect without the state the page sent is not answered, nor one whose code is
	// not a code, nor one for another host than the listener's address.
	for _, tc := range []struct {
		url, host string
		want      int
	}{
		{origin(local) + "/callback?code=abc&state=wrong", "", 400},
		{callback + "a%20b", "", 400},
		{callback + "..%2Fx", "", 400},
		{callback + "abc", "qory.attacker.test:" + u.Port(), 421},
		{callback + "abc", "localhost" + strings.TrimPrefix(u.Host, "127.0.0.1"), 421},
		{local, "qory.attacker.test", 421},
	} {
		req, _ := http.NewRequest("GET", tc.url, nil)
		if tc.host != "" {
			req.Host = tc.host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != tc.want {
			t.Errorf("%s for %q answered %v %v, want %d", tc.url, tc.host, resp.StatusCode, err, tc.want)
		}
	}
	resp, err := http.Get(callback + "abc")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the redirect answered %v %v", resp.StatusCode, err)
	}
	app, err := wait()
	if err != nil {
		t.Fatal(err)
	}
	if app.ID != 123456 || app.Slug != "qory-github-test" || app.KeyFile != file || app.Moved != nil || app.InstallURL("https://github.com") != "https://github.com/apps/qory-github-test/installations/new" {
		t.Errorf("app %+v", app)
	}
	// Once the wait returned, nothing listens.
	if resp, err := http.Get(callback + "abc"); err == nil {
		t.Errorf("a redirect after the wait answered %d", resp.StatusCode)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key file %v %v", info.Mode(), err)
	}
	if k, err := ReadKeyFile(file); err != nil || !k.Equal(key(t)) {
		t.Errorf("the key file contains %v", err)
	}
}

// TestSetupNeverLosesTheKey pins that a key GitHub hands out once is kept when the file
// cannot be written: beside it, or else the error identifies where to make another.
func TestSetupNeverLosesTheKey(t *testing.T) {
	c := serve(t, &fakeGitHub{})
	dir := t.TempDir()
	file := filepath.Join(dir, "app.pem")
	os.WriteFile(file, []byte("someone's"), 0o600)
	app, err := Setup{KeyFile: file, Client: c}.exchange(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "someone's" {
		t.Errorf("the key file contains %q", b)
	}
	if filepath.Dir(app.KeyFile) != dir || !regexp.MustCompile(`^app\.pem\.[0-9a-f]{16}$`).MatchString(filepath.Base(app.KeyFile)) || app.Moved == nil || !strings.Contains(app.Moved.Error(), "exists") {
		t.Fatalf("app %+v", app)
	}
	if k, err := ReadKeyFile(app.KeyFile); err != nil || !k.Equal(key(t)) {
		t.Errorf("the key beside it contains %v", err)
	}

	// A directory that is a file cannot be written to, not even by root; one that is
	// read-only cannot be by anyone else.
	blocked := []string{filepath.Join(dir, "app.pem", "app.pem")}
	if os.Geteuid() != 0 {
		readOnly := filepath.Join(dir, "read-only")
		os.Mkdir(readOnly, 0o500)
		blocked = append(blocked, filepath.Join(readOnly, "app.pem"))
	}
	body := strings.Split(string(keyPEM(t)), "\n")[1]
	for _, file := range blocked {
		_, err = Setup{Org: "acme", KeyFile: file, Web: "https://github.com", Client: c}.exchange(context.Background(), "abc")
		if err == nil || !strings.Contains(err.Error(), "the App 123456 (qory-github-test, https://github.com/apps/qory-github-test) is created") || !strings.HasSuffix(err.Error(), "generate a private key at https://github.com/organizations/acme/settings/apps/qory-github-test") {
			t.Fatalf("err %v", err)
		}
		if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("the error contains the key: %v", err)
		}
	}
}

func TestSetupNeverWritesOverAKeyFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(file, []byte("someone's"), 0o600)
	if _, _, err := (Setup{KeyFile: file}).Start(context.Background()); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("err %v", err)
	}
	// And a file that appears while the person approves is not written over either.
	if err := writeKeyFile(file, []byte("new")); err == nil {
		t.Error("written over")
	}
	if b, _ := os.ReadFile(file); string(b) != "someone's" {
		t.Errorf("the file contains %q", b)
	}
}

// recordingFile is a key file that records what writeKeyFile calls on it, in order, and
// whose Sync fails with syncErr when it is set, as a disk's that cannot keep the key.
type recordingFile struct {
	*os.File
	syncErr error
	calls   []string
}

func (r *recordingFile) Write(b []byte) (int, error) {
	r.calls = append(r.calls, "write")
	return r.File.Write(b)
}

func (r *recordingFile) Sync() error {
	r.calls = append(r.calls, "sync")
	if r.syncErr != nil {
		return r.syncErr
	}
	return r.File.Sync()
}

func (r *recordingFile) Close() error {
	r.calls = append(r.calls, "close")
	return r.File.Close()
}

// TestSetupSyncsTheKeyFileBeforeItClosesIt writes a key and checks it is synced to disk
// before the file is closed. A sync that fails is reported and the file it could not
// keep is removed, so setup's exchange writes the key beside it; a filesystem that
// cannot sync a file keeps the key unsynced.
func TestSetupSyncsTheKeyFileBeforeItClosesIt(t *testing.T) {
	defer func(c func(string) (keyFile, error)) { createKeyFile = c }(createKeyFile)
	var file *recordingFile
	syncErr := func(path string) error { return nil }
	createKeyFile = func(path string) (keyFile, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		file = &recordingFile{File: f, syncErr: syncErr(path)}
		return file, nil
	}
	failsWith := func(errno syscall.Errno) func(string) error {
		return func(path string) error { return &fs.PathError{Op: "sync", Path: path, Err: errno} }
	}
	dir := t.TempDir()
	body := strings.Split(string(keyPEM(t)), "\n")[1]
	kept := filepath.Join(dir, "kept.pem")
	if err := writeKeyFile(kept, keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(file.calls, " "); got != "write sync close" {
		t.Errorf("writeKeyFile called %s, want write sync close", got)
	}
	if k, err := ReadKeyFile(kept); err != nil || !k.Equal(key(t)) {
		t.Errorf("the key file contains %v", err)
	}

	// A filesystem that cannot sync a file says so, and the key is kept unsynced.
	for i, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.ENOSYS} {
		unsynced := filepath.Join(dir, "unsynced-"+strconv.Itoa(i)+".pem")
		syncErr = failsWith(errno)
		if err := writeKeyFile(unsynced, keyPEM(t)); err != nil {
			t.Errorf("%v: err %v", errno, err)
		}
		if got := strings.Join(file.calls, " "); got != "write sync close" {
			t.Errorf("%v: writeKeyFile called %s, want write sync close", errno, got)
		}
		if k, err := ReadKeyFile(unsynced); err != nil || !k.Equal(key(t)) {
			t.Errorf("%v: the key file contains %v", errno, err)
		}
	}

	// Any other failure is reported, and the file is removed.
	failing := filepath.Join(dir, "failing.pem")
	syncErr = failsWith(syscall.EIO)
	err := writeKeyFile(failing, keyPEM(t))
	if err == nil || err.Error() != "the key file could not be synced to disk: sync "+failing+": input/output error" || !errors.Is(err, syscall.EIO) {
		t.Errorf("a failing sync: err %v", err)
	}
	if got := strings.Join(file.calls, " "); got != "write sync close" {
		t.Errorf("a failing sync: writeKeyFile called %s, want write sync close", got)
	}
	if _, err := os.Stat(failing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file whose sync failed is kept: %v", err)
	}

	// setup's exchange then writes the key beside the file, and runSetup reads why from
	// the *fs.PathError it wraps.
	moving := filepath.Join(dir, "moving.pem")
	syncErr = func(path string) error {
		if path == moving {
			return failsWith(syscall.EIO)(path)
		}
		return nil
	}
	app, err := Setup{KeyFile: moving, Client: serve(t, &fakeGitHub{})}.exchange(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	var pe *fs.PathError
	if !strings.HasPrefix(app.KeyFile, moving+".") || !errors.Is(app.Moved, syscall.EIO) || !errors.As(app.Moved, &pe) || pe.Op != "sync" || pe.Err != syscall.EIO {
		t.Errorf("app %+v", app)
	}
	if _, err := os.Stat(moving); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file whose sync failed is kept: %v", err)
	}
	if k, err := ReadKeyFile(app.KeyFile); err != nil || !k.Equal(key(t)) {
		t.Errorf("the key beside it contains %v", err)
	}

	// When the file beside it cannot be synced either, the error names the App and where
	// to generate another key, and neither file is left.
	lost := filepath.Join(dir, "lost.pem")
	syncErr = failsWith(syscall.EIO)
	_, err = Setup{Org: "acme", KeyFile: lost, Web: "https://github.com", Client: serve(t, &fakeGitHub{})}.exchange(context.Background(), "abc")
	want := regexp.MustCompile(`^the App 123456 \(qory-github-test, https://github\.com/apps/qory-github-test\) is created, but its private key could not be written: the key file could not be synced to disk: sync ` + regexp.QuoteMeta(lost) + `: input/output error, and beside it: the key file could not be synced to disk: sync ` + regexp.QuoteMeta(lost) + `\.[0-9a-f]{16}: input/output error; generate a private key at https://github\.com/organizations/acme/settings/apps/qory-github-test$`)
	if err == nil || !want.MatchString(err.Error()) {
		t.Errorf("both syncs failing: err %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "PRIVATE KEY")) {
		t.Errorf("the error contains the key: %v", err)
	}
	if left, _ := filepath.Glob(lost + "*"); len(left) != 0 {
		t.Errorf("files whose sync failed are kept: %v", left)
	}
}

// webURLs are URLs of GitHub's website and whether setup takes them: GitHub's, and for a
// test a loopback host, and nothing else.
var webURLs = map[string]bool{
	"https://github.com":              true,
	"https://github.com/":             true,
	"http://127.0.0.1":                true,
	"http://127.0.0.1:8080/":          true,
	"https://127.1.2.3:8443":          true,
	"http://[::1]:9000":               true,
	"http://localhost:3000":           true,
	"https://localhost/":              true,
	"":                                false,
	"github.com":                      false,
	"https://github.acme.example":     false,
	"https://ghe.acme.example/":       false,
	"https://example.com":             false,
	"https://api.github.com":          false,
	"http://github.com":               false,
	"https://github.com:443":          false,
	"https://github.com:8443":         false,
	"https://github.com/login":        false,
	"https://github.com//":            false,
	"https://secretvalue@github.com":  false,
	"https://github.com?secretvalue":  false,
	"https://github.com#secretvalue":  false,
	"HTTPS://github.com":              false,
	"https://GitHub.com":              false,
	"https://github.com.":             false,
	"https://github.com.acme.example": false,
	"http://10.0.0.1":                 false,
	"http://127.0.0.256":              false,
	"http://127.0.0.1:65536":          false,
	"http://127.0.0.1/x":              false,
	"http://localhost.acme.example":   false,
}

// TestSetupTakesGitHubsWebsiteAlone runs each URL of webURLs through CheckWebURL and
// checks an error never contains the URL.
func TestSetupTakesGitHubsWebsiteAlone(t *testing.T) {
	for web, ok := range webURLs {
		err := CheckWebURL(web)
		if (err == nil) != ok {
			t.Errorf("CheckWebURL(%q): %v", web, err)
		}
		if err != nil && (web != "" && strings.Contains(strings.ReplaceAll(err.Error(), WebURL, ""), web) || strings.Contains(err.Error(), "secretvalue")) {
			t.Errorf("%q: the error contains the URL: %v", web, err)
		}
	}
	if got := (App{Slug: "qory-github-test"}).InstallURL("https://github.com/"); got != "https://github.com/apps/qory-github-test/installations/new" {
		t.Errorf("the install URL is %s", got)
	}
}

// TestSetupRefusesAnotherWebsiteOrAPIBeforeAnything starts setup with a website or an
// API it refuses and checks that it fails before it listens, opens a page or sends a
// request; and that the exchange of a code refuses such an API before it sends it.
func TestSetupRefusesAnotherWebsiteOrAPIBeforeAnything(t *testing.T) {
	for _, tc := range []struct{ web, api, want string }{
		{"https://ghe.acme.example", "", "the web URL is neither https://github.com"},
		{"https://github.com//", "", "the web URL is neither https://github.com"},
		{"https://github.com/", "https://ghe.acme.example/api/v3", "the API is neither https://api.github.com"},
		{"", "https://api.github.com:8443", "the API is neither https://api.github.com"},
	} {
		tr := &sentTransport{}
		opened := false
		s := Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), "app.pem"), Web: tc.web, Client: Client{API: tc.api, HTTP: &http.Client{Transport: tr}}, Open: func(string) error { opened = true; return nil }, Wait: time.Second}
		local, wait, err := s.Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) || local != "" || wait != nil || opened || tr.sent {
			t.Errorf("web %q, API %q: %v, page %q, opened %v, sent %v", tc.web, tc.api, err, local, opened, tr.sent)
		}
	}
	for api, ok := range apiURLs {
		if ok || api == "" {
			continue
		}
		tr := &sentTransport{}
		s := Setup{KeyFile: filepath.Join(t.TempDir(), "app.pem"), Client: Client{API: api, HTTP: &http.Client{Transport: tr}}}
		if _, err := s.exchange(context.Background(), "abc"); err == nil || !strings.Contains(err.Error(), "the API is neither https://api.github.com") || tr.sent {
			t.Errorf("exchange through %q: %v, sent %v", api, err, tr.sent)
		}
	}
}

// unreachable is a loopback API nothing listens on: a request to it is refused.
func unreachable(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	api := "http://" + ln.Addr().String()
	ln.Close()
	return api
}

// TestSetupNeverSaysTheCodeItExchanges follows GitHub's redirect with a code, which an
// unused code stays good for and which GitHub exchanges for the App's private key, to a
// setup whose API cannot be reached, and checks that the error says what failed and
// never the code, nor the path it is sent in.
func TestSetupNeverSaysTheCodeItExchanges(t *testing.T) {
	const code = "secretcode7788990011"
	s := Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), "app.pem"), Web: "https://github.com", Client: Client{API: unreachable(t)}, Wait: time.Minute}
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	action, _ := readPage(t, local)
	u, _ := url.Parse(action)
	resp, err := http.Get(origin(local) + "/callback?state=" + u.Query().Get("state") + "&code=" + code)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the redirect answered %v %v", resp.StatusCode, err)
	}
	_, err = wait()
	if err == nil || !strings.HasPrefix(err.Error(), "exchanging the code for the App: GitHub's API could not be reached: ") {
		t.Fatalf("err %v", err)
	}
	for _, v := range []string{code, "secretcode", "/app-manifests", "conversions"} {
		if strings.Contains(err.Error(), v) {
			t.Errorf("the error contains %q: %v", v, err)
		}
	}
}

// TestTheManifestWithoutAPublicURLIsAsItWas pins the manifest without
// [Setup.PublicURL], byte for byte: private, no webhook, no events, contents and pull
// requests write, metadata read.
func TestTheManifestWithoutAPublicURLIsAsItWas(t *testing.T) {
	b, err := json.Marshal(Manifest("qory-github-test", "http://127.0.0.1:1/callback"))
	want := `{"default_events":[],"default_permissions":{"contents":"write","metadata":"read","pull_requests":"write"},"hook_attributes":{"active":false,"url":"https://github.com/qoryai/qory-github"},"name":"qory-github-test","public":false,"redirect_url":"http://127.0.0.1:1/callback","url":"https://github.com/qoryai/qory-github"}`
	if err != nil || string(b) != want {
		t.Errorf("the manifest is\n%s\nwant\n%s", b, want)
	}
}

// TestTheManifestWithAPublicURLIsTheAppServeNeeds reads the manifest on setup's page
// with [Setup.PublicURL] and pins it whole: public, Connect's URLs, no description, a
// webhook that is active at serve's webhook path, its events and its permissions.
func TestTheManifestWithAPublicURLIsTheAppServeNeeds(t *testing.T) {
	dir := t.TempDir()
	s := Setup{Name: "qory-github-test", KeyFile: filepath.Join(dir, "app.pem"), Web: "https://github.com", Client: Client{API: unreachable(t)}, Wait: time.Millisecond,
		PublicURL: "https://Qory-GitHub.example.com/base//", ClientSecretFile: filepath.Join(dir, "app.client-secret"), WebhookSecretFile: filepath.Join(dir, "app.webhook-secret")}
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, m := readPage(t, local)
	wait()
	b, _ := json.Marshal(m)
	want := `{"callback_urls":["https://qory-github.example.com/base/v1/connect/authorized"],` +
		`"default_events":["issues","issue_comment","repository","workflow_run","pull_request","push"],` +
		`"default_permissions":{"actions":"write","administration":"read","checks":"write","contents":"write","issues":"write","members":"read","metadata":"read","pull_requests":"write"},` +
		`"hook_attributes":{"active":true,"url":"https://qory-github.example.com/base/github/webhook"},` +
		`"name":"qory-github-test","public":true,"redirect_url":"` + origin(local) + `/callback","request_oauth_on_install":false,` +
		`"setup_on_update":true,"setup_url":"https://qory-github.example.com/base/v1/connect/return","url":"https://github.com/qoryai/qory-github"}`
	if string(b) != want {
		t.Errorf("the manifest is\n%s\nwant\n%s", b, want)
	}
}

// starterManifestWant is the starter's App, [StarterManifest], byte for byte, with the
// redirect URL redirect: private, no webhook, no events, actions write and metadata read
// and nothing else.
func starterManifestWant(redirect string) string {
	return `{"default_events":[],"default_permissions":{"actions":"write","metadata":"read"},"hook_attributes":{"active":false,"url":"https://github.com/qoryai/qory-github"},"name":"qory-github-starter-test","public":false,"redirect_url":"` + redirect + `","url":"https://github.com/qoryai/qory-github"}`
}

// TestTheStartersManifestIsTheStartersApp pins [StarterManifest] byte for byte.
func TestTheStartersManifestIsTheStartersApp(t *testing.T) {
	b, err := json.Marshal(StarterManifest("qory-github-starter-test", "http://127.0.0.1:1/callback"))
	if want := starterManifestWant("http://127.0.0.1:1/callback"); err != nil || string(b) != want {
		t.Errorf("the manifest is\n%s\nwant\n%s", b, want)
	}
}

// TestServeManifestIsAsItWas pins what [serveManifest] makes of [Manifest] byte for
// byte, called as it is, beside [TestTheManifestWithAPublicURLIsTheAppServeNeeds], which
// reads it on setup's page.
func TestServeManifestIsAsItWas(t *testing.T) {
	m := Manifest("qory-github-test", "http://127.0.0.1:1/callback")
	serveManifest(m, "https://qory-github.example.com/base")
	b, err := json.Marshal(m)
	want := `{"callback_urls":["https://qory-github.example.com/base/v1/connect/authorized"],` +
		`"default_events":["issues","issue_comment","repository","workflow_run","pull_request","push"],` +
		`"default_permissions":{"actions":"write","administration":"read","checks":"write","contents":"write","issues":"write","members":"read","metadata":"read","pull_requests":"write"},` +
		`"hook_attributes":{"active":true,"url":"https://qory-github.example.com/base/github/webhook"},` +
		`"name":"qory-github-test","public":true,"redirect_url":"http://127.0.0.1:1/callback","request_oauth_on_install":false,` +
		`"setup_on_update":true,"setup_url":"https://qory-github.example.com/base/v1/connect/return","url":"https://github.com/qoryai/qory-github"}`
	if err != nil || string(b) != want {
		t.Errorf("the manifest is\n%s\nwant\n%s", b, want)
	}
}

// TestSetupForTheStarterPostsTheStartersManifest runs setup with [Setup.Starter] and
// pins the manifest its page posts, byte for byte, where it posts it, and that once the
// App is approved its key is written and nothing else is kept or set on it.
func TestSetupForTheStarterPostsTheStartersManifest(t *testing.T) {
	f := &fakeGitHub{webhookSecret: "a-webhook-secret-github-made-0123"}
	dir := t.TempDir()
	file := filepath.Join(dir, "app.pem")
	s := Setup{Org: "acme", Name: "qory-github-starter-test", KeyFile: file, Web: "https://github.com", Client: serve(t, f), Wait: time.Minute, Starter: true}
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	action, m := readPage(t, local)
	b, _ := json.Marshal(m)
	if want := starterManifestWant(origin(local) + "/callback"); string(b) != want {
		t.Errorf("the manifest is\n%s\nwant\n%s", b, want)
	}
	u, _ := url.Parse(action)
	if u.Host != "github.com" || u.Path != "/organizations/acme/settings/apps/new" || u.Query().Get("state") == "" {
		t.Errorf("the form posts to %s", action)
	}
	resp, err := http.Get(origin(local) + "/callback?state=" + u.Query().Get("state") + "&code=abc")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the redirect answered %v %v", resp, err)
	}
	resp.Body.Close()
	app, err := wait()
	if err != nil || app.ID != 123456 || app.KeyFile != file || app.ClientSecretFile != "" || app.WebhookSecretFile != "" || app.ClientSecretErr != nil || app.WebhookSecretErr != nil {
		t.Fatalf("app %+v, err %v", app, err)
	}
	if k, err := ReadKeyFile(file); err != nil || !k.Equal(key(t)) {
		t.Errorf("the key file: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %v", entries)
	}
	if _, bodies := f.hookRequests(); len(bodies) != 0 {
		t.Error("setup set a webhook secret on the starter's App")
	}
}

// TestSetupForTheStarterTakesNoPublicURL pins that [Setup.Starter] with
// [Setup.PublicURL] is refused before anything listens or opens.
func TestSetupForTheStarterTakesNoPublicURL(t *testing.T) {
	dir := t.TempDir()
	s := serveSetup(dir, Client{API: unreachable(t)})
	s.Starter = true
	s.Open = func(string) error { t.Error("setup opened the page"); return nil }
	if _, _, err := s.Start(context.Background()); err == nil || err.Error() != "the starter's App takes no public URL" {
		t.Errorf("Start: %v", err)
	}
	if err := s.Check(); err == nil || err.Error() != "the starter's App takes no public URL" {
		t.Errorf("Check: %v", err)
	}
}

// pageAndAnswers runs s and returns setup's local page, byte for byte, its form's
// action, and the bodies of the answers to a redirect without the state and to a
// request for the page under another host than the listener's, and that address.
func pageAndAnswers(t *testing.T, s Setup) (body, action, badRedirect, misdirected, host string) {
	t.Helper()
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer wait()
	get := func(u, host string, status int) string {
		req, _ := http.NewRequest("GET", u, nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Errorf("GET %s for %q answered %d, want %d", u, host, resp.StatusCode, status)
		}
		return string(b)
	}
	body = get(local, "", http.StatusOK)
	action, _ = readPage(t, local)
	u, _ := url.Parse(local)
	return body, action, get(origin(local)+"/callback?code=abc&state=wrong", "", http.StatusBadRequest), get(local, "qory.attacker.test:"+u.Port(), http.StatusMisdirectedRequest), u.Host
}

// setupPage is setup's local page, byte for byte, for program, with the form's action
// and the manifest's value as the page has them, escaped.
func setupPage(program, action, manifest string) string {
	return `<!doctype html>
<meta charset="utf-8"><title>` + program + ` setup</title>
<form id="f" method="post" action="` + action + `">
<input type="hidden" name="manifest" value="` + manifest + `">
<button type="submit">Create the GitHub App</button>
</form>
<script>document.getElementById("f").submit()</script>
`
}

// TestSetupsPageAndAnswersNameTheProgram pins setup's local page and its answers to a
// redirect without the state and to another host, byte for byte: without
// [Setup.Starter] they name qory-github, as they did before qory-github-starter's
// setup, and with it they name qory-github-starter.
func TestSetupsPageAndAnswersNameTheProgram(t *testing.T) {
	for _, tc := range []struct {
		starter bool
		program string
	}{{false, "qory-github"}, {true, "qory-github-starter"}} {
		s := Setup{Name: "qory-github-test", KeyFile: filepath.Join(t.TempDir(), "app.pem"), Web: "https://github.com", Client: Client{API: unreachable(t)}, Wait: time.Millisecond, Starter: tc.starter}
		body, _, bad, misdirected, host := pageAndAnswers(t, s)
		action := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(body)
		value := regexp.MustCompile(`name="manifest" value="([^"]+)"`).FindStringSubmatch(body)
		if action == nil || value == nil || body != setupPage(tc.program, action[1], value[1]) {
			t.Errorf("%s: the page is\n%s", tc.program, body)
		}
		if want := tc.program + " answers only GitHub's redirect containing the state it sent and a code\n"; bad != want {
			t.Errorf("%s: a redirect without the state is answered %q, want %q", tc.program, bad, want)
		}
		if want := tc.program + " answers only requests to " + host + "\n"; misdirected != want {
			t.Errorf("%s: another host is answered %q, want %q", tc.program, misdirected, want)
		}
	}
}

// serveSetup is a Setup with [Setup.PublicURL] whose files are in dir, reaching c.
func serveSetup(dir string, c Client) Setup {
	return Setup{KeyFile: filepath.Join(dir, "app.pem"), Web: "https://github.com", Client: c, PublicURL: "https://qory-github.example.com",
		ClientSecretFile: filepath.Join(dir, "app.client-secret"), WebhookSecretFile: filepath.Join(dir, "app.webhook-secret")}
}

// hookRequests are the Authorization headers and bodies of the PATCH /app/hook/config
// requests f received.
func (f *fakeGitHub) hookRequests() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.hookAuth), slices.Clone(f.hookBodies)
}

// TestSetupKeepsTheWebhookSecretGitHubHandsOut pins that a webhook secret in GitHub's
// answer is written to the webhook secret file, 0600, as it is, and that nothing is
// set on the App.
func TestSetupKeepsTheWebhookSecretGitHubHandsOut(t *testing.T) {
	const secret = "a-webhook-secret-github-made-0123"
	f := &fakeGitHub{webhookSecret: secret}
	s := serveSetup(t.TempDir(), serve(t, f))
	app, err := s.exchange(context.Background(), "abc")
	if err != nil || app.WebhookSecretErr != nil || app.ClientSecretErr != nil || app.WebhookSecretFile != s.WebhookSecretFile {
		t.Fatalf("app %+v, err %v", app, err)
	}
	info, err := os.Stat(s.WebhookSecretFile)
	b, _ := os.ReadFile(s.WebhookSecretFile)
	if err != nil || info.Mode().Perm() != 0o600 || string(b) != secret+"\n" {
		t.Errorf("the webhook secret file: %v %v %q", info, err, b)
	}
	if _, bodies := f.hookRequests(); len(bodies) != 0 {
		t.Errorf("setup set a webhook secret: %q", bodies)
	}
}

// TestSetupSetsAWebhookSecretWhenGitHubHandsOutNone pins that when GitHub's answer holds
// no webhook secret, setup makes one, 32 random bytes in hex, sets it on the App's
// webhook as the App, and writes the same secret to the file.
func TestSetupSetsAWebhookSecretWhenGitHubHandsOutNone(t *testing.T) {
	f := &fakeGitHub{}
	s := serveSetup(t.TempDir(), serve(t, f))
	app, err := s.exchange(context.Background(), "abc")
	if err != nil || app.WebhookSecretErr != nil || app.WebhookSecretFile != s.WebhookSecretFile {
		t.Fatalf("app %+v, err %v", app, err)
	}
	auth, bodies := f.hookRequests()
	if len(bodies) != 1 {
		t.Fatalf("setup sent %d PATCH /app/hook/config", len(bodies))
	}
	jwt, ok := strings.CutPrefix(auth[0], "Bearer ")
	if !ok {
		t.Fatalf("the PATCH is authenticated with %q", auth[0])
	}
	if claims := verifyJWT(t, jwt); claims["iss"] != appID {
		t.Errorf("the App's token is issued by %v", claims["iss"])
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil || len(body) != 1 {
		t.Fatalf("the PATCH's body is %s", bodies[0])
	}
	secret := body["secret"]
	if raw, err := hex.DecodeString(secret); err != nil || len(raw) != 32 || secret != strings.ToLower(secret) {
		t.Errorf("the secret set is not 32 bytes in hex: %d characters, %v", len(secret), err)
	}
	info, err := os.Stat(s.WebhookSecretFile)
	b, _ := os.ReadFile(s.WebhookSecretFile)
	if err != nil || info.Mode().Perm() != 0o600 || string(b) != secret+"\n" {
		t.Errorf("the webhook secret file: %v %v, the secret set is not the file's", info, err)
	}
	// GitHub's 200 is enough, whatever its body: not JSON, JSON of another shape, or
	// none.
	for _, answer := range []string{"ok", "[]", ""} {
		f3 := &fakeGitHub{hookAnswer: answer, hookNoBody: answer == ""}
		s3 := serveSetup(t.TempDir(), serve(t, f3))
		if app, err := s3.exchange(context.Background(), "abc"); err != nil || app.WebhookSecretErr != nil || app.WebhookSecretFile != s3.WebhookSecretFile {
			t.Errorf("a 200 with %q: app %+v, err %v", answer, app, err)
		}
	}
	// Another App gets another secret.
	f2 := &fakeGitHub{}
	if _, err := serveSetup(t.TempDir(), serve(t, f2)).exchange(context.Background(), "abc"); err != nil {
		t.Fatal(err)
	}
	if _, bodies2 := f2.hookRequests(); len(bodies2) != 1 || bodies2[0] == bodies[0] {
		t.Error("two Apps got one secret")
	}
}

// TestSetupWritesNoWebhookSecretGitHubDoesNotHave pins that when GitHub does not
// confirm the webhook secret, no file is written, the App and its key are kept, and the
// error says GitHub did not confirm it, what to do, serve's settings among it, and what
// serve does until then, never the secret, even when GitHub's answer quotes it.
func TestSetupWritesNoWebhookSecretGitHubDoesNotHave(t *testing.T) {
	for _, echo := range []bool{false, true} {
		f := &fakeGitHub{hookStatus: http.StatusForbidden, hookEcho: echo}
		s := serveSetup(t.TempDir(), serve(t, f))
		app, err := s.exchange(context.Background(), "abc")
		if err != nil || app.WebhookSecretErr == nil || app.WebhookSecretFile != "" || app.ClientSecretFile != s.ClientSecretFile {
			t.Fatalf("echo %v: app %+v, err %v", echo, app, err)
		}
		_, bodies := f.hookRequests()
		var body map[string]string
		json.Unmarshal([]byte(bodies[0]), &body)
		message := "Resource not accessible by integration"
		if echo {
			message = `Invalid request: {"secret":"[the secret]"}`
		}
		want := "GitHub did not confirm the App's webhook secret, so no webhook secret file is written: setting the App's webhook secret: GitHub answered 403: " + message +
			"; set a webhook secret at https://github.com/settings/apps/qory-github-test, write the same secret to " + s.WebhookSecretFile + ", 0600, and name that file as webhook_secret_file in qory-github-server serve's settings: until then serve takes none of the App's deliveries"
		if got := app.WebhookSecretErr.Error(); got != want || strings.Contains(got, body["secret"]) || body["secret"] == "" {
			t.Errorf("echo %v: the error is\n%s\nwant\n%s", echo, got, want)
		}
		if _, err := os.Lstat(s.WebhookSecretFile); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("echo %v: a webhook secret file is written: %v", echo, err)
		}
		if k, err := ReadKeyFile(s.KeyFile); err != nil || !k.Equal(key(t)) {
			t.Errorf("echo %v: the key file: %v", echo, err)
		}
	}
}

// TestSetupKeepsNoWebhookSecretServeCannotUse pins that a webhook secret in GitHub's
// answer that serve would refuse, shorter than 16 bytes, too large for serve's file or
// with white space in it, is not written, nothing is set on the App, and the error says
// what to do; and that the longest secret serve's file holds is kept.
func TestSetupKeepsNoWebhookSecretServeCannotUse(t *testing.T) {
	longest := strings.Repeat("a", MaxWebhookSecretFile-1)
	f := &fakeGitHub{webhookSecret: longest}
	s := serveSetup(t.TempDir(), serve(t, f))
	if app, err := s.exchange(context.Background(), "abc"); err != nil || app.WebhookSecretErr != nil || app.WebhookSecretFile != s.WebhookSecretFile {
		t.Errorf("the longest secret: app %+v, err %v", app, err)
	}
	if b, _ := os.ReadFile(s.WebhookSecretFile); string(b) != longest+"\n" {
		t.Errorf("the longest secret's file holds %d bytes", len(b))
	}
	for _, secret := range []string{"fifteen-bytes-x", "a secret with spaces", longest + "a"} {
		f := &fakeGitHub{webhookSecret: secret}
		s := serveSetup(t.TempDir(), serve(t, f))
		app, err := s.exchange(context.Background(), "abc")
		want := "the App's webhook secret was not kept: GitHub's answer holds a webhook secret qory-github-server serve cannot use; set a webhook secret at https://github.com/settings/apps/qory-github-test, write the same secret to " + s.WebhookSecretFile + ", 0600, and name that file as webhook_secret_file in qory-github-server serve's settings"
		if err != nil || app.WebhookSecretErr == nil || app.WebhookSecretErr.Error() != want || app.WebhookSecretFile != "" {
			t.Errorf("%d bytes: app %+v, err %v", len(secret), app, err)
		}
		if _, err := os.Lstat(s.WebhookSecretFile); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%d bytes: a webhook secret file is written: %v", len(secret), err)
		}
		if _, bodies := f.hookRequests(); len(bodies) != 0 {
			t.Errorf("%d bytes: setup set a webhook secret", len(secret))
		}
	}
}

// TestSetupNeverWritesOverAWebhookSecretFile pins that a webhook secret file that exists
// is refused before anything is created, and that one that appears while the person
// approves is not written over, for a secret GitHub hands out or one setup sets.
func TestSetupNeverWritesOverAWebhookSecretFile(t *testing.T) {
	dir := t.TempDir()
	s := serveSetup(dir, Client{API: unreachable(t)})
	os.WriteFile(s.WebhookSecretFile, []byte("someone's"), 0o600)
	if local, wait, err := s.Start(context.Background()); err == nil || err.Error() != "the webhook secret file "+s.WebhookSecretFile+" exists; choose another or move it away" || local != "" || wait != nil {
		t.Errorf("err %v", err)
	}
	s.WebhookSecretFile = ""
	if _, _, err := s.Start(context.Background()); err == nil || err.Error() != "no webhook secret file" {
		t.Errorf("no webhook secret file: err %v", err)
	}
	for _, handed := range []string{"", "a-webhook-secret-github-made-0123"} {
		f := &fakeGitHub{webhookSecret: handed}
		s := serveSetup(t.TempDir(), serve(t, f))
		os.WriteFile(s.WebhookSecretFile, []byte("someone's"), 0o600)
		app, err := s.exchange(context.Background(), "abc")
		want := "the App's webhook secret was not kept: the webhook secret file " + s.WebhookSecretFile + " exists; choose another or move it away; set a new webhook secret at https://github.com/settings/apps/qory-github-test, write the same secret to a file only you may read, and name that file as webhook_secret_file in qory-github-server serve's settings"
		if err != nil || app.WebhookSecretErr == nil || app.WebhookSecretErr.Error() != want || app.WebhookSecretFile != "" {
			t.Errorf("%q: app %+v, err %v", handed, app, err)
		}
		if b, _ := os.ReadFile(s.WebhookSecretFile); string(b) != "someone's" {
			t.Errorf("%q: the file contains %q", handed, b)
		}
	}
}

// TestSetupWithoutAPublicURLKeepsNoWebhookSecret pins that without [Setup.PublicURL]
// nothing is set on the App and no secret is written beside the key.
func TestSetupWithoutAPublicURLKeepsNoWebhookSecret(t *testing.T) {
	for _, handed := range []string{"", "a-webhook-secret-github-made-0123"} {
		f := &fakeGitHub{webhookSecret: handed}
		dir := t.TempDir()
		app, err := Setup{KeyFile: filepath.Join(dir, "app.pem"), Client: serve(t, f)}.exchange(context.Background(), "abc")
		if err != nil || app.WebhookSecretFile != "" || app.WebhookSecretErr != nil || app.ClientSecretFile != "" || app.ClientSecretErr != nil {
			t.Errorf("%q: app %+v, err %v", handed, app, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%q: the directory holds %v", handed, entries)
		}
		if _, bodies := f.hookRequests(); len(bodies) != 0 {
			t.Errorf("%q: setup set a webhook secret", handed)
		}
	}
}

// TestSetupThatLosesTheKeySaysNoSecretIsKept pins that with [Setup.PublicURL], when the
// key can be written nowhere, the error says neither secret is kept and what to do, and
// nothing is set on the App.
func TestSetupThatLosesTheKeySaysNoSecretIsKept(t *testing.T) {
	f := &fakeGitHub{}
	dir := t.TempDir()
	blocked := filepath.Join(dir, "file")
	os.WriteFile(blocked, nil, 0o600)
	s := serveSetup(blocked, serve(t, f))
	_, err := s.exchange(context.Background(), "abc")
	if err == nil || !strings.HasSuffix(err.Error(), ", so neither its client secret nor its webhook secret was kept; generate a private key and a client secret at https://github.com/settings/apps/qory-github-test, and set a webhook secret there") {
		t.Errorf("err %v", err)
	}
	if _, bodies := f.hookRequests(); len(bodies) != 0 {
		t.Error("setup set a webhook secret")
	}
}

// TestEachCallAfterTheApprovalHasATimeout pins that the exchange and the
// setting of the webhook secret are not bound by what is left of the wait for the
// person's approval, that each is bound by afterApprovalTimeout, and that each still
// ends when the caller's context does.
func TestEachCallAfterTheApprovalHasATimeout(t *testing.T) {
	// An approval near the end of the wait: the answers take longer than the wait.
	f := &fakeGitHub{exchangeDelay: 300 * time.Millisecond, hookDelay: 300 * time.Millisecond}
	s := serveSetup(t.TempDir(), serve(t, f))
	s.Name, s.Wait = "qory-github-test", 200*time.Millisecond
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	action, _ := readPage(t, local)
	u, _ := url.Parse(action)
	resp, err := http.Get(origin(local) + "/callback?state=" + u.Query().Get("state") + "&code=abc")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the redirect answered %v %v", resp.StatusCode, err)
	}
	app, err := wait()
	if err != nil || app.WebhookSecretErr != nil || app.WebhookSecretFile != s.WebhookSecretFile {
		t.Fatalf("a late approval: app %+v, err %v", app, err)
	}

	// Each call has afterApprovalTimeout alone.
	defer func(d time.Duration) { afterApprovalTimeout = d }(afterApprovalTimeout)
	afterApprovalTimeout = 100 * time.Millisecond
	slowHook := &fakeGitHub{hookDelay: time.Second}
	s = serveSetup(t.TempDir(), serve(t, slowHook))
	app, err = s.exchange(context.Background(), "abc")
	if err != nil || app.WebhookSecretErr == nil || !strings.HasPrefix(app.WebhookSecretErr.Error(), "GitHub did not confirm the App's webhook secret, so no webhook secret file is written: setting the App's webhook secret: GitHub's API could not be reached: ") {
		t.Errorf("a slow PATCH: app %+v, err %v", app, err)
	}
	if _, err := os.Lstat(s.WebhookSecretFile); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a slow PATCH: a webhook secret file is written: %v", err)
	}
	slowExchange := &fakeGitHub{exchangeDelay: time.Second}
	s = serveSetup(t.TempDir(), serve(t, slowExchange))
	if _, err := s.exchange(context.Background(), "abc"); err == nil || !strings.HasPrefix(err.Error(), "exchanging the code for the App: GitHub's API could not be reached: ") {
		t.Errorf("a slow exchange: err %v", err)
	}

	// The caller's context still ends them.
	afterApprovalTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = serveSetup(t.TempDir(), serve(t, &fakeGitHub{}))
	if _, err := s.exchange(ctx, "abc"); err == nil || !strings.HasPrefix(err.Error(), "exchanging the code for the App: GitHub's API could not be reached: ") {
		t.Errorf("a cancelled context: err %v", err)
	}
}

// TestAnAccountIsLookedUpWithoutAToken looks handles up with a fake GitHub and pins
// the answers: an organisation and a user by their login as GitHub writes it, and
// ErrNoAccount for GitHub's 404 and for an account of another kind; a handle not of
// GitHub's shape is never sent; any other answer is an error that says what failed.
// No request carries a token.
func TestAnAccountIsLookedUpWithoutAToken(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.EscapedPath())
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/users/ACME":
			io.WriteString(w, `{"login":"acme","type":"Organization"}`)
		case "/users/octocat":
			io.WriteString(w, `{"login":"octocat","type":"User"}`)
		case "/users/mona-bot":
			io.WriteString(w, `{"login":"mona-bot","type":"Bot"}`)
		case "/users/other":
			io.WriteString(w, `{"login":"someone-else","type":"User"}`)
		case "/users/kelvin":
			io.WriteString(w, `{"login":"\u212Aelvin","type":"User"}`)
		case "/users/down":
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `{"message":"Bad Gateway"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"Not Found"}`)
		}
	}))
	defer srv.Close()
	c := Client{API: srv.URL}
	for _, tc := range []struct{ handle, login, kind string }{
		{"ACME", "acme", AccountOrganization},
		{"octocat", "octocat", AccountUser},
	} {
		login, kind, err := c.Account(context.Background(), tc.handle)
		if login != tc.login || kind != tc.kind || err != nil {
			t.Errorf("%s: %q %q %v", tc.handle, login, kind, err)
		}
	}
	// "other" answers another account's login, and "kelvin" one whose K is the Kelvin
	// sign, which folds to k in Unicode alone.
	for _, handle := range []string{"nobody", "mona-bot", "other", "kelvin"} {
		if _, _, err := c.Account(context.Background(), handle); err != ErrNoAccount {
			t.Errorf("%s: %v", handle, err)
		}
	}
	paths = nil
	for _, handle := range []string{"", "-acme", "acme-", "ac--me", "acme/x", "acme x", "../acme", "acme%2F", "\u00e9", strings.Repeat("a", 40)} {
		if _, _, err := c.Account(context.Background(), handle); err != ErrNoAccount {
			t.Errorf("%q: %v", handle, err)
		}
	}
	if _, _, err := c.Account(context.Background(), strings.Repeat("a", 39)); err != ErrNoAccount || len(paths) != 1 {
		t.Fatalf("39 letters: %v, %v", err, paths)
	}
	if paths[0] != "GET /users/"+strings.Repeat("a", 39) {
		t.Errorf("handles not of GitHub's shape were sent: %v", paths)
	}
	if _, _, err := c.Account(context.Background(), "down"); err == nil || err.Error() != "looking up the GitHub account: GitHub answered 502: Bad Gateway" {
		t.Errorf("down: %v", err)
	}
	tr := &sentTransport{}
	if _, _, err := (Client{API: "https://ghe.acme.example", HTTP: &http.Client{Transport: tr}}).Account(context.Background(), "acme"); err == nil || tr.sent {
		t.Errorf("another API: %v, sent %v", err, tr.sent)
	}
}
