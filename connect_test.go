package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserTokenSaysNoCodeNoSecretAndFollowsNoRedirect(t *testing.T) {
	const code, secret, token = "a-code-that-must-not-leak", "a-secret-that-must-not-leak", "ghu_a-token"
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/login/oauth/access_token" || r.Method != http.MethodPost || !strings.Contains(string(b), "code="+code) || r.Header.Get("Accept") != "application/json" {
			t.Errorf("%s %s %s", r.Method, r.URL.Path, b)
		}
		answer(w)
	}))
	defer srv.Close()
	c := Client{API: srv.URL}
	if c.Web() != srv.URL || (Client{}).Web() != WebURL {
		t.Errorf("the website %s", c.Web())
	}
	for name, tc := range map[string]struct {
		answer func(w http.ResponseWriter)
		want   string
	}{
		"a token":     {func(w http.ResponseWriter) { io.WriteString(w, `{"access_token":"`+token+`"}`) }, ""},
		"a bad code":  {func(w http.ResponseWriter) { io.WriteString(w, `{"error":"bad_verification_code"}`) }, "GitHub answered bad_verification_code"},
		"an odd code": {func(w http.ResponseWriter) { io.WriteString(w, `{"error":"`+secret+`"}`) }, "exchanging the sign-in's code: GitHub answered an error"},
		"a redirect": {func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.example.com/?code="+code)
			w.WriteHeader(http.StatusFound)
		}, "GitHub answered 302"},
		"a token with a space": {func(w http.ResponseWriter) { io.WriteString(w, `{"access_token":"a b"}`) }, "GitHub answered without a token"},
		"a token and an error": {func(w http.ResponseWriter) {
			io.WriteString(w, `{"access_token":"`+token+`","error":"bad_verification_code"}`)
		}, "GitHub answered bad_verification_code"},
		"a token and an odd error": {func(w http.ResponseWriter) {
			io.WriteString(w, `{"access_token":"`+token+`","error":"`+secret+`"}`)
		}, "exchanging the sign-in's code: GitHub answered an error"},
	} {
		answer = tc.answer
		got, err := c.UserToken(context.Background(), "Iv1.test", []byte(secret), code, "https://qory-github.example.com/v1/connect/authorized")
		switch {
		case tc.want == "" && (err != nil || got != token):
			t.Errorf("%s: %q %v", name, got, err)
		case tc.want != "" && (err == nil || got != "" || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		case err != nil && (strings.Contains(err.Error(), code) || strings.Contains(err.Error(), secret)):
			t.Errorf("%s: the error says the code or the secret: %v", name, err)
		}
	}
}

func TestTheUserListingsReadEveryPageOnce(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghu_a-token" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.RequestURI() {
		case "/user/installations?per_page=100":
			w.Header().Set("Link", `<`+srv.URL+`/user/installations?per_page=100&page=2>; rel="next"`)
			io.WriteString(w, `{"installations":[{"id":7}]}`)
		case "/user/installations?per_page=100&page=2":
			io.WriteString(w, `{"installations":[{"id":42}]}`)
		case "/user/installations/42/repositories?per_page=100":
			// The next page repeats this one.
			w.Header().Set("Link", `<`+srv.URL+`/user/installations/42/repositories?per_page=100>; rel="next"`)
			io.WriteString(w, `{"repositories":[{"full_name":"acme/widgets"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := Client{API: srv.URL}
	ids, err := c.UserInstallations(context.Background(), "ghu_a-token")
	if err != nil || len(ids) != 2 || ids[0] != 7 || ids[1] != 42 {
		t.Errorf("%v %v", ids, err)
	}
	if _, err := c.UserRepositories(context.Background(), "ghu_a-token", 42); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Errorf("err %v", err)
	}
	if _, err := c.UserInstallations(context.Background(), "ghu_another"); err == nil || strings.Contains(err.Error(), "ghu_another") {
		t.Errorf("err %v", err)
	}
}

func TestThePublicURLIsAnHTTPSURLOfAHostAnOptionalPortAndAnOptionalPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://qory-github.example.com":              "https://qory-github.example.com",
		"https://qory-github.example.com/":             "https://qory-github.example.com",
		"https://qory-github.example.com//":            "https://qory-github.example.com",
		"https://qory-github.example.com/github///":    "https://qory-github.example.com/github",
		"HTTPS://Qory-GitHub.Example.com:8443/GitHub/": "https://qory-github.example.com:8443/GitHub",
		"https://qory-github.example.com/a%20b":        "https://qory-github.example.com/a%20b",
		"https://[2001:db8::1]:443":                    "https://[2001:db8::1]:443",
	} {
		if got, err := CheckPublicURL(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "http://qory-github.example.com", "https://", "https:///github", "https://:443",
		"https://qory-github.example.com#", "https://qory-github.example.com/#a", "https://qory-github.example.com?",
		"https://qory-github.example.com/?a", "https://user@qory-github.example.com", "https:qory-github.example.com",
		"https://qory-github.example.com:", "https://qory-github.example.com:0", "https://qory-github.example.com:65536",
		"https://qory-github.example.com:01", "https://qory-github.example.com:x", "https://qory github.example.com",
		"https://qory-github.example.com/a\nb", " https://qory-github.example.com",
	} {
		if got, err := CheckPublicURL(in); err == nil || err.Error() != "is not an https URL of a host, an optional port and an optional path, without a user, a query or a fragment" {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}
