package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestUserTokenSaysNoCodeNoSecretAndFollowsNoRedirect(t *testing.T) {
	const code, secret, token = "a-code-that-must-not-leak", "a-secret-that-must-not-leak", "ghu_a-token"
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/login/oauth/access_token" || r.Method != http.MethodPost || !strings.Contains(string(b), "code="+code) || r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "example-program/1.2.3" {
			t.Errorf("%s %s %s %q", r.Method, r.URL.Path, b, r.Header.Get("User-Agent"))
		}
		answer(w)
	}))
	defer srv.Close()
	c := Client{API: srv.URL, UserAgent: "example-program/1.2.3"}
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
		case CodeRefused(err) != (tc.want != ""):
			t.Errorf("%s: refused %v", name, CodeRefused(err))
		}
	}
	// GitHub out of reach is no refusal of the code.
	srv.Close()
	if _, err := c.UserToken(context.Background(), "Iv1.test", []byte(secret), code, "https://qory-github.example.com/v1/connect/authorized"); err == nil || CodeRefused(err) {
		t.Errorf("err %v", err)
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
			io.WriteString(w, `{"installations":[{"id":7,"account":{"login":"alice","id":1001,"type":"User"},"suspended_at":null,"permissions":{"issues":"write"}}]}`)
		case "/user/installations?per_page=100&page=2":
			io.WriteString(w, `{"installations":[{"id":42,"account":{"login":"acme","id":500,"type":"Organization"},"suspended_at":"2026-10-01T00:00:00Z"}]}`)
		case "/user":
			io.WriteString(w, `{"login":"alice","id":1001,"type":"User"}`)
		case "/user/memberships/orgs/acme":
			io.WriteString(w, `{"state":"active","role":"admin","organization":{"login":"acme","id":500},"user":{"login":"alice","id":1001}}`)
		case "/user/memberships/orgs/octo-org":
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := Client{API: srv.URL}
	ins, err := c.UserInstallations(context.Background(), "ghu_a-token")
	want := []UserInstallation{
		{ID: 7, Account: Account{Login: "alice", ID: 1001, Type: "User"}, Permissions: map[string]string{"issues": "write"}},
		{ID: 42, Account: Account{Login: "acme", ID: 500, Type: "Organization"}, Suspended: true},
	}
	if err != nil || !reflect.DeepEqual(ins, want) {
		t.Errorf("%+v %v", ins, err)
	}
	if _, err := c.UserInstallations(context.Background(), "ghu_another"); err == nil || strings.Contains(err.Error(), "ghu_another") {
		t.Errorf("err %v", err)
	}
	if u, err := c.User(context.Background(), "ghu_a-token"); err != nil || u != (Account{Login: "alice", ID: 1001, Type: "User"}) {
		t.Errorf("%+v %v", u, err)
	}
	if m, err := c.OrgMembership(context.Background(), "ghu_a-token", "acme"); err != nil || m != (Membership{State: "active", Role: "admin", Organization: 500, Person: 1001}) {
		t.Errorf("%+v %v", m, err)
	}
	if _, err := c.OrgMembership(context.Background(), "ghu_a-token", "octo-org"); !Refused(err) || Gone(err) {
		t.Errorf("err %v", err)
	}
	if _, err := c.OrgMembership(context.Background(), "ghu_a-token", "other"); !Gone(err) || Refused(err) {
		t.Errorf("err %v", err)
	}
	// A login that is not one is never put in a path.
	if _, err := c.OrgMembership(context.Background(), "ghu_a-token", "../user"); err == nil || Gone(err) {
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
