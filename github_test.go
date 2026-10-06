package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/qoryai/runner/contracts"
)

// The token and the App the fake GitHub hands out: synthetic, and what no error may
// contain.
const (
	fakeToken = "ghs_faketokenthatmustnotleak"
	appID     = "123456"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

// key is one RSA key for the whole test binary, generated here.
func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func keyPEM(t *testing.T) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key(t))})
}

// fakeGitHub is GitHub's API as far as minting and the manifest flow use it. It records
// the requests it receives.
type fakeGitHub struct {
	t             *testing.T
	installations map[string]int64 // owner/name -> installation id
	status        int              // the mint's status; zero is 201
	mu            sync.Mutex
	auth          []string
	mint          map[string]any
	mintPath      string
	lookups       []string
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	switch {
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/installation"):
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/installation")
		f.lookups = append(f.lookups, repo)
		id, ok := f.installations[repo]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id})
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/app/installations/"):
		f.mintPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&f.mint)
		if f.status != 0 {
			w.WriteHeader(f.status)
			io.WriteString(w, `{"message":"Bad credentials"}`)
			return
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"token": fakeToken, "expires_at": "2026-09-25T21:00:00Z"})
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/app-manifests/"):
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"id": 123456, "slug": "qory-github-test", "html_url": "https://github.com/apps/qory-github-test", "client_id": "Iv1.test", "pem": string(keyPEM(f.t)), "client_secret": "not-kept", "webhook_secret": nil})
	default:
		w.WriteHeader(404)
	}
}

func serve(t *testing.T, f *fakeGitHub) Client {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return Client{API: srv.URL, Now: func() time.Time { return time.Unix(1_790_000_000, 0) }}
}

// verifyJWT checks a token's signature against the test key and returns its claims.
func verifyJWT(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key(t).PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	var header, claims map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(h, &header)
	json.Unmarshal(c, &claims)
	if header["alg"] != "RS256" {
		t.Errorf("alg is %v", header["alg"])
	}
	return claims
}

func TestTheAppsTokenIsSignedAndIssuedAMinuteBack(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	token, err := AppJWT(appID, key(t), now)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyJWT(t, token)
	if claims["iss"] != appID || claims["iat"] != float64(now.Unix()-60) || claims["exp"] != float64(now.Unix()+540) {
		t.Errorf("claims %v", claims)
	}
}

func TestMintLooksTheInstallationUpAndAsksForTheRepositoriesAlone(t *testing.T) {
	f := &fakeGitHub{installations: map[string]int64{"acme/shop": 42, "acme/lib": 42}}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/shop,acme/lib")
	a, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), Repositories: repos, Permissions: map[string]string{"contents": "read"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.lookups, " ") != "acme/shop acme/lib" || f.mintPath != "/app/installations/42/access_tokens" {
		t.Errorf("looked up %v, minted at %s", f.lookups, f.mintPath)
	}
	got, _ := json.Marshal(f.mint)
	if string(got) != `{"permissions":{"contents":"read"},"repositories":["shop","lib"]}` {
		t.Errorf("the mint requested %s", got)
	}
	for _, h := range f.auth {
		verifyJWT(t, strings.TrimPrefix(h, "Bearer "))
	}
	if a.Token != fakeToken || a.ExpiresAt != "2026-09-25T21:00:00Z" {
		t.Errorf("answer %+v", a)
	}
}

func TestMintWithAnInstallationLooksNothingUp(t *testing.T) {
	f := &fakeGitHub{}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/shop")
	if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(f.mint)
	if len(f.lookups) != 0 || f.mintPath != "/app/installations/7/access_tokens" || string(got) != `{"permissions":{"contents":"write","pull_requests":"write"},"repositories":["shop"]}` {
		t.Errorf("lookups %v, mint %s %s", f.lookups, f.mintPath, got)
	}
}

func TestMintRefusesRepositoriesInTwoInstallations(t *testing.T) {
	c := serve(t, &fakeGitHub{installations: map[string]int64{"acme/shop": 1, "acme/lib": 2}})
	repos, _ := ParseRepositories("acme/shop,acme/lib")
	if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), Repositories: repos}); err == nil || !strings.Contains(err.Error(), "different installations") {
		t.Errorf("err %v", err)
	}
}

func TestAMintGitHubRefusesSaysWhyAndCarriesNoSecret(t *testing.T) {
	f := &fakeGitHub{status: 401}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/shop")
	_, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos})
	if err == nil || !strings.Contains(err.Error(), "401: Bad credentials") {
		t.Fatalf("err %v", err)
	}
	jwt := strings.TrimPrefix(f.auth[0], "Bearer ")
	body := strings.Split(string(keyPEM(t)), "\n")[1]
	for _, secret := range []string{jwt, strings.Split(jwt, ".")[2], body, "PRIVATE KEY", "Bearer"} {
		if len(secret) < 6 || strings.Contains(err.Error(), secret) {
			t.Errorf("the error contains %.12q: %v", secret, err)
		}
	}
}

// TestTheAnswerIsTheRunnersCredentialDocument validates the answer against the runner's
// published schema, so the adapter and the contract cannot drift apart.
func TestTheAnswerIsTheRunnersCredentialDocument(t *testing.T) {
	c := serve(t, &fakeGitHub{installations: map[string]int64{"acme/shop": 42, "acme/lib": 42}})
	repos, _ := ParseRepositories("acme/shop,acme/lib")
	a, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), Repositories: repos})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(a)
	doc, err := contracts.Decode("answer.json", b)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := contracts.Compile("credential.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("the runner's schema refuses the answer: %v\n%s", err, b)
	}
	want := `{"version":1,"token":"` + fakeToken + `","expires_at":"2026-09-25T21:00:00Z","apply":[` +
		`{"hosts":["github.com"],"scheme":"basic","username":"x-access-token","paths":["/acme/shop.git/*","/acme/shop/*","/acme/lib.git/*","/acme/lib/*"]},` +
		`{"hosts":["api.github.com"],"scheme":"bearer","paths":["/repos/acme/shop","/repos/acme/shop/*","/repos/acme/lib","/repos/acme/lib/*","/graphql"]}],` +
		`"placeholders":["GH_TOKEN","GITHUB_TOKEN"]}`
	if string(b) != want {
		t.Errorf("answer\n%s\nwant\n%s", b, want)
	}
}

func TestOneRunsRepositoriesShareAnOwner(t *testing.T) {
	for _, arg := range []string{"acme/shop,other/lib", "acme/shop,acme/shop", "acme", "acme/", "/shop", "acme/..", "acme/shop.git", "ac me/shop", "-acme/shop", "acme/shop/x"} {
		if _, err := ParseRepositories(arg); err == nil {
			t.Errorf("%q was accepted", arg)
		}
	}
	got, err := ParseRepositories("acme/shop,ACME/lib")
	if err != nil || len(got) != 2 {
		t.Errorf("%v %v", got, err)
	}
}

// TestTheArgumentPatternIsTheParser walks arguments through the credential role's
// pattern, matched whole as the runner matches it, and through ParseRepositories. They
// agree but where the README states the program refuses what the pattern lets through: a
// dot segment, a name ending in .git, two owners and a repository listed twice.
func TestTheArgumentPatternIsTheParser(t *testing.T) {
	whole := regexp.MustCompile(`^(?:` + Describe("").Roles.Credential.Argument + `)$`)
	owner39, name100 := strings.Repeat("a", 39), strings.Repeat("b", 100)
	for _, tc := range []struct {
		arg     string
		ok      bool
		refused string // the parser refuses what the pattern lets through, and why
	}{
		{"acme/shop", true, ""},
		{"acme/shop,acme/lib", true, ""},
		{"a-b/c_d.e", true, ""},
		{"ACME/.github", true, ""},
		{"a/-", true, ""},
		{"acme/shop.gitx", true, ""},
		{owner39 + "/" + name100, true, ""},
		{owner39 + "a/shop", false, ""},
		{"acme/" + name100 + "b", false, ""},
		{"-acme/shop", false, ""},
		{".acme/shop", false, ""},
		{"_acme/shop", false, ""},
		{"ac.me/shop", false, ""},
		{"acme/sh op", false, ""},
		{"acme/shop/x", false, ""},
		{"acme/", false, ""},
		{"/shop", false, ""},
		{"acme", false, ""},
		{"acme/shop,", false, ""},
		{",acme/shop", false, ""},
		{"", false, ""},
		{"acme/.", false, "a dot segment"},
		{"acme/..", false, "a dot segment"},
		{"acme/shop.git", false, "ends in .git"},
		{"acme/shop,other/lib", false, "two owners"},
		{"acme/shop,ACME/SHOP", false, "listed twice"},
	} {
		_, err := ParseRepositories(tc.arg)
		if (err == nil) != tc.ok {
			t.Errorf("%q: the parser returns %v", tc.arg, err)
		}
		if matched := whole.MatchString(tc.arg); matched != (tc.ok || tc.refused != "") {
			t.Errorf("%q: the pattern matches %v, the parser returns %v", tc.arg, matched, err)
		}
	}
}

func TestARunsTokenIsNeverGivenAdminNorMoreThanTheRepositories(t *testing.T) {
	c := serve(t, &fakeGitHub{})
	repos, _ := ParseRepositories("acme/shop")
	for _, perms := range []map[string]string{
		{"contents": "admin"}, {"Contents": "read"}, {"administration": "read"}, {"organization_administration": "read"},
		{"members": "read"}, {"secrets": "write"}, {"environments": "write"}, {"contents": "write", "repository_hooks": "write"}, {},
	} {
		if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: perms}); err == nil {
			t.Errorf("%v accepted", perms)
		}
	}
	for _, name := range RunPermissions {
		if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{name: "read"}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// apiURLs are URLs of the API and whether the App's own token may go there: GitHub's
// API, and for a test a loopback host, and nothing else.
var apiURLs = map[string]bool{
	"https://api.github.com":                  true,
	"https://api.github.com/":                 true,
	"https://api.github.com:443":              true,
	"https://api.github.com:443/":             true,
	"http://127.0.0.1":                        true,
	"http://127.0.0.1:8080":                   true,
	"http://127.0.0.1:65535/":                 true,
	"http://127.255.255.254:1":                true,
	"https://127.0.0.1:8443":                  true,
	"http://[::1]:9000":                       true,
	"https://[::1]/":                          true,
	"http://localhost":                        true,
	"http://localhost:3000/":                  true,
	"https://localhost:8443":                  true,
	"":                                        false,
	"api.github.com":                          false,
	"https://example.com":                     false,
	"https://github.com":                      false,
	"https://github.acme.example":             false,
	"https://github.acme.example/api/v3":      false,
	"https://ghe.acme.example/api/v3/":        false,
	"http://api.github.com":                   false,
	"https://api.github.com/api/v3":           false,
	"https://api.github.com/x":                false,
	"https://api.github.com//":                false,
	"https://api.github.com:8443":             false,
	"https://api.github.com:0443":             false,
	"https://secretvalue@api.github.com":      false,
	"https://user:secretvalue@api.github.com": false,
	"https://api.github.com?secretvalue":      false,
	"https://api.github.com/?":                false,
	"https://api.github.com#secretvalue":      false,
	"HTTPS://api.github.com":                  false,
	"https://API.GITHUB.COM":                  false,
	"https://api.github.com.":                 false,
	"https://api.github.com.acme.example":     false,
	" https://api.github.com":                 false,
	"https://api.github.com\n":                false,
	"http://10.0.0.1:8080":                    false,
	"http://192.168.1.10":                     false,
	"http://128.0.0.1":                        false,
	"http://127.0.0.256":                      false,
	"http://127.0.0":                          false,
	"http://127.0.0.01":                       false,
	"http://127.0.0.1:0":                      false,
	"http://127.0.0.1:65536":                  false,
	"http://127.0.0.1/api":                    false,
	"http://localhost.acme.example":           false,
	"http://127.0.0.1.acme.example":           false,
	"http://localhost@acme.example":           false,
	"http://LOCALHOST":                        false,
	"http://[::2]":                            false,
	"http://[::ffff:127.0.0.1]":               false,
	"http://::1":                              false,
	"ftp://127.0.0.1":                         false,
}

// TestTheAppsTokenGoesToGitHubsAPIAlone runs each URL of apiURLs through the settings,
// whose schema refuses it, and through CheckAPIURL, which the settings and Mint call,
// and checks that they agree and that an error never contains the URL.
func TestTheAppsTokenGoesToGitHubsAPIAlone(t *testing.T) {
	for api, ok := range apiURLs {
		err := CheckAPIURL(api)
		if (err == nil) != ok {
			t.Errorf("CheckAPIURL(%q): %v", api, err)
		}
		doc, _ := json.Marshal(map[string]any{"app_id": 123456, "private_key_file": "/k.pem", "api_url": api})
		s, serr := ReadSettings(strings.NewReader(string(doc)))
		switch {
		case ok && (serr != nil || s.APIURL != api):
			t.Errorf("the settings refuse %q: %v", api, serr)
		case !ok && (serr == nil || !strings.Contains(serr.Error(), "/api_url: does not match")):
			t.Errorf("the settings' schema takes %q: %v", api, serr)
		}
		for _, e := range []error{err, serr} {
			if leaks(e, api) {
				t.Errorf("%q: the error contains the URL: %v", api, e)
			}
		}
	}
}

// leaks is whether err contains the URL api, or a secret in it, besides the URL the rule
// itself names.
func leaks(err error, api string) bool {
	if err == nil {
		return false
	}
	e := strings.ReplaceAll(err.Error(), APIURL, "")
	api = strings.TrimSpace(api)
	return api != "" && strings.Contains(e, api) || strings.Contains(e, "secretvalue")
}

// sentTransport is a client's transport that records a request and sends nothing.
type sentTransport struct{ sent bool }

func (s *sentTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.sent = true
	return nil, errors.New("not sent")
}

// TestMintRefusesAnotherAPIBeforeAnythingIsSent mints through every API apiURLs refuses
// that a request could reach and checks that Mint refuses it, names the rule, and sends
// nothing, whatever the settings let through.
func TestMintRefusesAnotherAPIBeforeAnythingIsSent(t *testing.T) {
	repos, _ := ParseRepositories("acme/shop")
	for api, ok := range apiURLs {
		if ok || api == "" {
			continue
		}
		tr := &sentTransport{}
		c := Client{API: api, HTTP: &http.Client{Transport: tr}}
		_, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos})
		if err == nil || !strings.Contains(err.Error(), "neither https://api.github.com nor, for a test, http or https on a loopback host") || tr.sent {
			t.Errorf("%q: err %v, sent %v", api, err, tr.sent)
		}
		if leaks(err, api) {
			t.Errorf("%q: the error contains the URL: %v", api, err)
		}
	}
	tr := &sentTransport{}
	if _, err := (Client{HTTP: &http.Client{Transport: tr}}).Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}); err == nil || !tr.sent {
		t.Errorf("the default API: err %v, sent %v", err, tr.sent)
	}
}

func TestAKeyFileOthersMayReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o610} {
		open := filepath.Join(dir, "open.pem")
		os.Remove(open)
		os.WriteFile(open, keyPEM(t), mode)
		os.Chmod(open, mode)
		if _, err := ReadKeyFile(open); err == nil || !strings.Contains(err.Error(), "others may read it") {
			t.Errorf("%s: err %v", mode, err)
		}
	}
	own := filepath.Join(dir, "own.pem")
	os.WriteFile(own, keyPEM(t), 0o600)
	if k, err := ReadKeyFile(own); err != nil || !k.Equal(key(t)) {
		t.Errorf("err %v", err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key(t))
	if k, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil || !k.Equal(key(t)) {
		t.Errorf("PKCS #8: %v", err)
	}
	if _, err := ParseKey([]byte("not a key")); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Errorf("err %v", err)
	}
}

// TestAKeyFileIsReadFromWhatWasOpened pins that what is not the owner's own regular file
// is refused without being read, and without waiting on a pipe.
func TestAKeyFileIsReadFromWhatWasOpened(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "own.pem")
	os.WriteFile(own, keyPEM(t), 0o600)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(own, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir.pem")
	os.Mkdir(sub, 0o700)
	large := filepath.Join(dir, "large.pem")
	os.WriteFile(large, append(keyPEM(t), make([]byte, maxKeyFile)...), 0o600)
	for path, want := range map[string]string{
		link:                           "symbolic link",
		fifo:                           "not a regular file",
		sub:                            "not a regular file",
		large:                          "larger than a key",
		filepath.Join(dir, "none.pem"): "no such file",
	} {
		done := make(chan error, 1)
		go func() { _, err := ReadKeyFile(path); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: err %v, want %q", filepath.Base(path), err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the read waits", filepath.Base(path))
		}
	}
}

// TestAKeyFileOfAnotherUserIsRefused needs root to change a file's owner, which CI's
// container is.
func TestAKeyFileOfAnotherUserIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a file's owner needs root")
	}
	theirs := filepath.Join(t.TempDir(), "theirs.pem")
	os.WriteFile(theirs, keyPEM(t), 0o600)
	if err := os.Chown(theirs, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(theirs); err == nil || !strings.Contains(err.Error(), "belongs to another user") {
		t.Errorf("err %v", err)
	}
}

func TestTheDescriptionSaysWhatThePackageDoes(t *testing.T) {
	d := Describe("dev")
	if d.Version != 1 || d.Name != "github" || d.ProgramVersion != "dev" || d.Roles.Credential == nil {
		t.Fatalf("description %+v", d)
	}
	if strings.Join(d.Roles.Credential.Hosts, " ") != GitHost+" "+APIHost {
		t.Errorf("hosts %v", d.Roles.Credential.Hosts)
	}
	if strings.Join(d.Domains, " ") != "software" {
		t.Errorf("domains %v", d.Domains)
	}
	var s struct {
		Properties map[string]struct {
			WriteOnly     bool `json:"writeOnly"`
			Default       any  `json:"default"`
			PropertyNames struct {
				Enum []string `json:"enum"`
			} `json:"propertyNames"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(d.Settings, &s); err != nil {
		t.Fatal(err)
	}
	for name, p := range s.Properties {
		if p.WriteOnly != (name == "private_key") {
			t.Errorf("%s writeOnly is %v", name, p.WriteOnly)
		}
	}
	if got, _ := json.Marshal(s.Properties["permissions"].Default); string(got) != `{"contents":"write","pull_requests":"write"}` || len(DefaultPermissions) != 2 {
		t.Errorf("the schema's default permissions are %s", got)
	}
	if got := s.Properties["permissions"].PropertyNames.Enum; !slices.Equal(got, RunPermissions) {
		t.Errorf("the schema's permissions are %v, a run's %v", got, RunPermissions)
	}
	if s.Properties["api_url"].Default != APIURL {
		t.Errorf("the schema's default API is %v", s.Properties["api_url"].Default)
	}
}

func TestReadSettings(t *testing.T) {
	s, err := ReadSettings(strings.NewReader(`{"app_id":123456,"installation_id":42,"permissions":{"contents":"read"},"api_url":"http://127.0.0.1:1","private_key_file":"/k.pem"}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.AppID != "123456" || s.InstallationID != 42 || s.Permissions["contents"] != "read" || s.APIURL != "http://127.0.0.1:1" || s.PrivateKeyFile != "/k.pem" {
		t.Errorf("settings %+v", s)
	}
	if s, err := ReadSettings(strings.NewReader(`{"app_id":"Iv1.abc","private_key_file":"/k.pem"}`)); err != nil || s.AppID != "Iv1.abc" || s.Permissions != nil {
		t.Errorf("settings %+v, %v", s, err)
	}
}

func TestReadSettingsRefusesWhatTheSchemaRefusesAndNeverSaysAValue(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{`{"private_key":"-----BEGIN RSA PRIVATE KEY-----"}`, "missing property 'app_id'"},
		{`{}`, "missing property 'app_id'"},
		{`{"app_id":"123456"}`, "missing property 'private_key_file', or missing property 'private_key'"},
		{`{"private_key_file":"/k.pem"}`, "missing property 'app_id'"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"contents":"admin"}}`, "/permissions/contents: value must be one of 'read', 'write'"},
		{`{"app_id":"123456","private_key_file":"/k.pem","key":"secretvalue"}`, "additional properties 'key' not allowed"},
		{`{"app_id":"not an id secretvalue","private_key_file":"/k.pem"}`, "/app_id: does not match"},
		{`{"app_id":true,"private_key_file":"/k.pem"}`, "/app_id: got boolean, want integer or string"},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"secretvalue"}`, "/api_url: does not match"},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"http://api.github.com"}`, "/api_url: does not match"},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"https://secretvalue@api.github.com"}`, "/api_url: does not match"},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"https://secretvalue.example/api/v3"}`, "/api_url: does not match"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{}}`, "/permissions: minProperties"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"administration":"read"}}`, "/permissions: invalid propertyName 'administration'"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"organization_administration":"read"}}`, "invalid propertyName 'organization_administration'"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"members":"read"}}`, "invalid propertyName 'members'"},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"secrets":"write"}}`, "invalid propertyName 'secrets'"},
		{`["app_id"]`, "got array, want object"},
		{`{"app_id":1} {}`, "not one JSON document"},
	} {
		_, err := ReadSettings(strings.NewReader(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.doc, err)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "secretvalue") || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: the error contains a value: %v", tc.doc, err)
		}
	}
}

// TestReadSettingsTakesTheKeyItself reads the settings on standard input, the key itself
// among them, with white space around the document, and up to 64 KiB of input.
func TestReadSettingsTakesTheKeyItself(t *testing.T) {
	pemBytes := keyPEM(t)
	doc, err := json.Marshal(map[string]any{"app_id": 123456, "installation_id": 42, "private_key": string(pemBytes)})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		string(doc),
		string(doc) + "\n",
		" \t\r\n" + string(doc) + " \t\r\n",
		string(doc) + strings.Repeat(" ", maxSettings-len(doc)),
	} {
		s, err := ReadSettings(strings.NewReader(in))
		if err != nil || s.AppID != appID || s.InstallationID != 42 || s.PrivateKey != string(pemBytes) || s.PrivateKeyFile != "" {
			t.Errorf("%d bytes: settings %+v, %v", len(in), s, err)
		}
	}
	s, err := ReadSettings(strings.NewReader(`{"app_id":"Iv1.abc","private_key_file":"/k.pem"}`))
	if err != nil || s.AppID != "Iv1.abc" || s.PrivateKeyFile != "/k.pem" || s.PrivateKey != "" {
		t.Errorf("settings %+v, %v", s, err)
	}
}

// TestReadSettingsRefusesInputAndNeverSaysAValue refuses input that is not one settings
// document of 64 KiB at most, and a secret beside its file, with an error that contains
// no part of the input.
func TestReadSettingsRefusesInputAndNeverSaysAValue(t *testing.T) {
	secret := `"-----BEGIN RSA PRIVATE KEY-----\nsecretvalue\n-----END RSA PRIVATE KEY-----\n"`
	doc := `{"app_id":123456,"private_key":` + secret + `}`
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", "the settings on standard input are empty"},
		{"white space", " \t\r\n ", "the settings on standard input are empty"},
		{"two documents", doc + ` {"app_id":"secretvalue"}`, "something other than white space follows it"},
		{"something after", doc + "secretvalue", "something other than white space follows it"},
		{"a white space JSON has not", doc + "\v", "something other than white space follows it"},
		{"cut short", `{"app_id":123456,"private_key":` + secret, "it ends before the document does"},
		{"a key not escaped", `{"app_id":123456,"private_key":"-----BEGIN RSA PRIVATE KEY-----` + "\nsecretvalue\n" + `"}`, "it breaks at byte 64"},
		{"larger than 64 KiB", doc + strings.Repeat(" ", maxSettings+1-len(doc)), "larger than 64 KiB, 65536 bytes"},
		{"the key and its file", `{"app_id":123456,"private_key_file":"/k.pem","private_key":` + secret + `}`, "contain both private_key and private_key_file; a secret has one source"},
		{"no key", `{"app_id":123456}`, "missing property 'private_key_file', or missing property 'private_key'"},
		{"an unknown setting", `{"app_id":123456,"private_key":` + secret + `,"key":"secretvalue"}`, "additional properties 'key' not allowed"},
		{"not an object", `["secretvalue"]`, "got array, want object"},
	} {
		_, err := ReadSettings(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "secretvalue") || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: the error contains a value: %v", tc.name, err)
		}
	}
}

// TestASettingsErrorLocatesANameAsAJSONPointer pins the location of a refused setting
// whose name contains ~ or /: escaped as a JSON pointer escapes it, so /permissions/a/b
// is never what the location reads for the name a/b.
func TestASettingsErrorLocatesANameAsAJSONPointer(t *testing.T) {
	for name, want := range map[string]string{
		`a/b`:   `the settings are invalid: /permissions/a~1b: value must be one of 'read', 'write'`,
		`a~b`:   `the settings are invalid: /permissions/a~0b: value must be one of 'read', 'write'`,
		`a~1b`:  `the settings are invalid: /permissions/a~01b: value must be one of 'read', 'write'`,
		`~/`:    `the settings are invalid: /permissions/~0~1: value must be one of 'read', 'write'`,
		`a/\nb`: `the settings are invalid: /permissions/"a~1\nb": value must be one of 'read', 'write'`,
		`a"b`:   `the settings are invalid: /permissions/"a\"b": value must be one of 'read', 'write'`,
	} {
		_, err := ReadSettings(strings.NewReader(`{"app_id":123456,"private_key_file":"/k.pem","permissions":{"` + strings.ReplaceAll(name, `"`, `\"`) + `":"admin"}}`))
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: %v, want it to begin %s", name, err, want)
		}
	}
}

// TestASettingsErrorEscapesTheNamesItReports hands in settings whose names contain a
// line break, a tab, DEL, C1 or a Unicode line or paragraph separator. A name an error
// reports is escaped, so the error is one line with none of those characters in it.
func TestASettingsErrorEscapesTheNamesItReports(t *testing.T) {
	for _, name := range []string{`a\nb`, `a\rb`, `a\tb`, `a\u007fb`, `a\u0085b`, `a\u2028b`, `a\u2029b`} {
		for doc, want := range map[string]string{
			`{"app_id":123456,"private_key_file":"/k.pem","permissions":{"` + name + `":"admin"}}`: `/permissions/"a\`,
			`{"app_id":123456,"private_key_file":"/k.pem","permissions":{"` + name + `":"read"}}`:  `invalid propertyName 'a\`,
			`{"app_id":123456,"private_key_file":"/k.pem","` + name + `":1}`:                       `additional properties 'a\`,
		} {
			_, err := ReadSettings(strings.NewReader(doc))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v", doc, err)
				continue
			}
			if i := strings.IndexFunc(err.Error(), func(r rune) bool {
				return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
			}); i >= 0 {
				t.Errorf("%s: the error contains %q: %q", doc, []rune(err.Error()[i:])[0], err)
			}
		}
	}
}
