package github

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
// path without the state is refused, and the page's own path for another host is
// refused.
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
	// not a code, nor one for another host than the listener's own address.
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
