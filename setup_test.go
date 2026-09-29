package github

import (
	"context"
	"encoding/json"
	"html"
	"io"
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

func TestSetupCreatesTheAppAndWritesItsKeyForItsOwnerAlone(t *testing.T) {
	c := serve(t, &fakeGitHub{})
	file := filepath.Join(t.TempDir(), "app.pem")
	var opened string
	s := Setup{Org: "acme", Name: "qory-github-test", KeyFile: file, Web: "https://github.invalid", Client: c, Open: func(u string) error { opened = u; return nil }, Wait: time.Minute}
	local, wait, err := s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opened != local {
		t.Errorf("opened %q, the page is %q", opened, local)
	}
	action, manifest := readPage(t, local)
	u, _ := url.Parse(action)
	if u.Host != "github.invalid" || u.Path != "/organizations/acme/settings/apps/new" || u.Query().Get("state") == "" {
		t.Errorf("the form posts to %s", action)
	}
	perms, _ := json.Marshal(manifest["default_permissions"])
	hook, _ := manifest["hook_attributes"].(map[string]any)
	if manifest["public"] != false || hook["active"] != false || string(perms) != `{"contents":"write","metadata":"read","pull_requests":"write"}` || manifest["redirect_url"] != strings.TrimSuffix(local, "/")+"/callback" {
		t.Errorf("manifest %v", manifest)
	}

	callback := strings.TrimSuffix(local, "/") + "/callback?state=" + u.Query().Get("state") + "&code="
	// A redirect without the state the page sent is not answered, nor one whose code is
	// not a code, nor one for another host than the listener's own address.
	for _, tc := range []struct {
		url, host string
		want      int
	}{
		{strings.TrimSuffix(local, "/") + "/callback?code=abc&state=wrong", "", 400},
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
	if app.ID != 123456 || app.Slug != "qory-github-test" || app.KeyFile != file || app.Moved != nil || app.InstallURL("https://github.invalid") != "https://github.invalid/apps/qory-github-test/installations/new" {
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
		_, err = Setup{Org: "acme", KeyFile: file, Web: "https://github.invalid", Client: c}.exchange(context.Background(), "abc")
		if err == nil || !strings.Contains(err.Error(), "the App 123456 (qory-github-test, https://github.invalid/apps/qory-github-test) is created") || !strings.HasSuffix(err.Error(), "generate a private key at https://github.invalid/organizations/acme/settings/apps/qory-github-test") {
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
