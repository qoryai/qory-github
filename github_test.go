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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/qoryai/forager/contracts"
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
	accounts      map[int64]string // installation id -> the login of its account
	status        int              // the mint's status; zero is 201
	mu            sync.Mutex
	auth          []string
	mint          map[string]any
	mintPath      string
	lookups       []string
	checks        []string // the installations' paths read
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
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/app/installations/"):
		f.checks = append(f.checks, r.URL.Path)
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/app/installations/"), 10, 64)
		login, ok := f.accounts[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "account": map[string]any{"login": login, "type": "Organization"}})
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
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}}
	c := serve(t, f)
	repos, _ := ParseRepositories("acme/shop")
	if _, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos}); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(f.mint)
	if len(f.lookups) != 0 || strings.Join(f.checks, " ") != "/app/installations/7" || f.mintPath != "/app/installations/7/access_tokens" || string(got) != `{"permissions":{"contents":"write","pull_requests":"write"},"repositories":["shop"]}` {
		t.Errorf("lookups %v, checks %v, mint %s %s", f.lookups, f.checks, f.mintPath, got)
	}
}

// TestMintChecksTheInstallationIsTheOwners mints with an installation the request names
// and checks that a token is minted only when GitHub says it is the App's installation
// on the repositories' owner, the login in any case; an installation of another account,
// one GitHub does not know of the App and one whose account has no login are refused in
// one line that says neither id nor login, and nothing reaches the mint.
func TestMintChecksTheInstallationIsTheOwners(t *testing.T) {
	const refused = "installation_id is not the App's installation on the repositories' owner; set that owner's installation, or leave installation_id out"
	for _, tc := range []struct {
		name     string
		accounts map[int64]string
		repos    string
		ok       bool
	}{
		{"the owner's", map[int64]string{778899: "acme"}, "acme/shop", true},
		{"the owner's, in another case", map[int64]string{778899: "ACME"}, "Acme/shop,acme/lib", true},
		{"another account's", map[int64]string{778899: "otherlogin"}, "acme/shop", false},
		{"an account whose login begins the owner's", map[int64]string{778899: "acme-other"}, "acme/shop", false},
		{"an account with no login", map[int64]string{778899: ""}, "acme/shop", false},
		{"not the App's, a 404", map[int64]string{}, "acme/shop", false},
	} {
		f := &fakeGitHub{accounts: tc.accounts}
		c := serve(t, f)
		repos, _ := ParseRepositories(tc.repos)
		a, err := c.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 778899, Repositories: repos})
		if strings.Join(f.checks, " ") != "/app/installations/778899" || len(f.lookups) != 0 {
			t.Errorf("%s: checked %v, looked up %v", tc.name, f.checks, f.lookups)
		}
		if tc.ok {
			if err != nil || a.Token != fakeToken || f.mintPath != "/app/installations/778899/access_tokens" {
				t.Errorf("%s: %v, minted at %q", tc.name, err, f.mintPath)
			}
			continue
		}
		if err == nil || err.Error() != refused {
			t.Errorf("%s: err %v, want %s", tc.name, err, refused)
		}
		if f.mintPath != "" || f.mint != nil {
			t.Errorf("%s: a token was minted at %s", tc.name, f.mintPath)
		}
	}
	// Another failure of the check says what failed, and never the id.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	}))
	t.Cleanup(srv.Close)
	repos, _ := ParseRepositories("acme/shop")
	_, err := Client{API: srv.URL}.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 778899, Repositories: repos})
	if err == nil || err.Error() != "checking installation_id: GitHub answered 401: Bad credentials" {
		t.Errorf("err %v", err)
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
	f := &fakeGitHub{accounts: map[int64]string{7: "acme"}, status: 401}
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

// TestAMintGitHubCannotBeReachedSaysWhatFailedAndNeverTheRequest mints through an API
// that cannot be reached, with an installation and without, and checks that the error
// names the request and says why, and never says the path, the installation's id among
// it, nor the URL.
func TestAMintGitHubCannotBeReachedSaysWhatFailedAndNeverTheRequest(t *testing.T) {
	api := unreachable(t)
	repos, _ := ParseRepositories("acme/shop")
	for _, tc := range []struct {
		id   int64
		want string
	}{
		{0, "finding the App's installation on acme/shop: GitHub's API could not be reached: "},
		{778899, "GitHub's API could not be reached: "},
	} {
		_, err := Client{API: api}.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: tc.id, Repositories: repos})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("installation %d: err %v", tc.id, err)
		}
		for _, v := range []string{"778899", "/app/", "/repos/", "access_tokens", "installations/", api, "http://"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("installation %d: the error contains %q: %v", tc.id, v, err)
			}
		}
	}
}

// TestARequestsErrorLeavesTheRequestOut pins unsent: a *url.Error is kept without its
// URL, and an error that says the path all the same is left out whole.
func TestARequestsErrorLeavesTheRequestOut(t *testing.T) {
	path := "/app-manifests/secretcode7788990011/conversions"
	refused := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&url.Error{Op: "Post", URL: "http://127.0.0.1:1" + path, Err: refused}, refused.Error()},
		{&url.Error{Op: "Post", URL: "http://127.0.0.1:1" + path, Err: errors.New("no route to " + path)}, errRequestLeftOut.Error()},
		{errors.New("Post " + path), errRequestLeftOut.Error()},
		{refused, refused.Error()},
	} {
		if got := unsent(tc.err, path); got.Error() != tc.want {
			t.Errorf("unsent(%v) = %v, want %s", tc.err, got, tc.want)
		}
	}
	if err := unsent(&url.Error{Op: "Get", URL: "http://127.0.0.1:1/", Err: context.DeadlineExceeded}, "/"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unsent drops what the error wraps: %v", err)
	}
}

// redirecting is GitHub's API answering a request for from with a redirect, of status,
// to the same path under to, on the same server: what it records is whether the
// redirect was followed to its target, and whether a token was minted.
type redirecting struct {
	from, to       string
	status         int
	mu             sync.Mutex
	followed, mint bool
}

func (rd *redirecting) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	switch {
	case r.URL.Path == rd.from:
		w.Header().Set("Location", rd.to)
		w.WriteHeader(rd.status)
		io.WriteString(w, `{"message":"Moved Permanently","url":"`+rd.to+`"}`)
		return
	case strings.HasPrefix(r.URL.Path, "/moved/"):
		rd.followed = true
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/repos/acme/shop/installation"):
		io.WriteString(w, `{"id":42}`)
	case strings.HasSuffix(r.URL.Path, "/app/installations/42"):
		io.WriteString(w, `{"id":42,"account":{"login":"acme"}}`)
	case strings.HasSuffix(r.URL.Path, "/access_tokens"):
		rd.mint = true
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"`+fakeToken+`","expires_at":"2026-09-25T21:00:00Z"}`)
	case strings.HasSuffix(r.URL.Path, "/conversions"):
		w.WriteHeader(201)
		io.WriteString(w, `{"id":123456,"slug":"qory-github-test"}`)
	default:
		w.WriteHeader(404)
	}
}

// TestNoRedirectIsFollowed has GitHub's API answer each request a mint and setup's
// exchange make with a redirect, to a target on the same server, which would be handed
// the App's token or the code, and checks that none is followed, whatever client the
// request goes through, that no token is minted after one, and the line each fails with.
func TestNoRedirectIsFollowed(t *testing.T) {
	const moved = "GitHub answered with a redirect; the repository may have moved or been renamed, so name its new owner/name in the policy's credential argument"
	for _, tc := range []struct {
		from           string
		status         int
		installationID int64
		client         *http.Client
	}{
		{"/repos/acme/shop/installation", 301, 0, nil},
		{"/repos/acme/shop/installation", 302, 0, &http.Client{}},
		{"/repos/acme/shop/installation", 308, 0, nil},
		{"/app/installations/42", 307, 42, nil},
		{"/app/installations/42/access_tokens", 307, 42, nil},
		{"/app/installations/42/access_tokens", 308, 42, &http.Client{}},
		{"/app/installations/42/access_tokens", 303, 0, nil},
	} {
		rd := &redirecting{from: tc.from, to: "/moved" + tc.from, status: tc.status}
		srv := httptest.NewServer(rd)
		repos, _ := ParseRepositories("acme/shop")
		_, err := Client{API: srv.URL, HTTP: tc.client}.Mint(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: tc.installationID, Repositories: repos})
		srv.Close()
		if err == nil || err.Error() != moved {
			t.Errorf("%d for %s: err %v, want %s", tc.status, tc.from, err, moved)
		}
		if rd.followed || rd.mint {
			t.Errorf("%d for %s: followed %v, minted %v", tc.status, tc.from, rd.followed, rd.mint)
		}
	}
	for _, status := range []int{301, 307, 308} {
		rd := &redirecting{from: "/app-manifests/abc/conversions", to: "/moved/app-manifests/abc/conversions", status: status}
		srv := httptest.NewServer(rd)
		_, err := Setup{KeyFile: filepath.Join(t.TempDir(), "app.pem"), Client: Client{API: srv.URL}}.exchange(context.Background(), "abc")
		srv.Close()
		if want := "exchanging the code for the App: GitHub answered with a redirect, which setup never follows, so the code is sent nowhere else"; err == nil || err.Error() != want {
			t.Errorf("%d: err %v, want %s", status, err, want)
		}
		if rd.followed {
			t.Errorf("%d: the exchange followed the redirect", status)
		}
	}
}

// TestTheAnswerIsTheGatewaysCredentialDocument validates the answer against the gateway's
// published schema, so the adapter and the contract cannot drift apart.
func TestTheAnswerIsTheGatewaysCredentialDocument(t *testing.T) {
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
		t.Fatalf("the gateway's schema refuses the answer: %v\n%s", err, b)
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
// pattern, matched whole as the gateway matches it, and through ParseRepositories. They
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
	c := serve(t, &fakeGitHub{accounts: map[int64]string{7: "acme"}})
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

// TestMintRefusesAnAppIdThatIsNotOneAndNeverSaysIt mints with App ids Mint refuses, a
// library's caller's that the settings' schema has not seen, and checks that the error
// never says the id, and that nothing is sent.
func TestMintRefusesAnAppIdThatIsNotOneAndNeverSaysIt(t *testing.T) {
	repos, _ := ParseRepositories("acme/shop")
	for _, id := range []string{"", "secretvalue-1", "secretvalue/1", strings.Repeat("secretvalue", 6)} {
		tr := &sentTransport{}
		_, err := Client{HTTP: &http.Client{Transport: tr}}.Mint(context.Background(), Request{AppID: id, Key: key(t), InstallationID: 7, Repositories: repos})
		if err == nil || err.Error() != "the App id is not an id, 1 to 64 letters, digits or dots" || tr.sent {
			t.Errorf("%q: err %v, sent %v", id, err, tr.sent)
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
		s, serr := ReadSettings(string(doc))
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
	s, err := ReadSettings(`{"app_id":123456,"installation_id":42,"permissions":{"contents":"read"},"api_url":"http://127.0.0.1:1","private_key_file":"/k.pem"}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.AppID != "123456" || s.InstallationID != 42 || s.Permissions["contents"] != "read" || s.APIURL != "http://127.0.0.1:1" || s.PrivateKeyFile != "/k.pem" {
		t.Errorf("settings %+v", s)
	}
	if s, err := ReadSettings(`{"app_id":"Iv1.abc","private_key_file":"/k.pem"}`); err != nil || s.AppID != "Iv1.abc" || s.Permissions != nil {
		t.Errorf("settings %+v, %v", s, err)
	}
}

// TestReadSettingsRefusesWhatTheSchemaRefusesAndNeverSaysAValue hands in settings that
// each keyword of the schema refuses, and checks the error says where and what, and
// never the value: neither secretvalue, nor a case's own value, a number in any of the
// ways Go writes it among them, nor the validator's own words for a length.
func TestReadSettingsRefusesWhatTheSchemaRefusesAndNeverSaysAValue(t *testing.T) {
	for _, tc := range []struct {
		doc, want string
		value     []string // what the error may not contain besides secretvalue
	}{
		{`{"app_id":"123456","private_key_file":"/k.pem","private_key":"-----BEGIN RSA PRIVATE KEY-----"}`, "contain private_key, a secret", nil},
		{`{"private_key":"-----BEGIN RSA PRIVATE KEY-----"}`, "contain private_key", nil},
		{`{"app_id":"123456"}`, "missing property 'private_key_file', or missing property 'private_key'", nil},
		{`{"private_key_file":"/k.pem"}`, "missing property 'app_id'", nil},
		{`{}`, "missing property 'app_id'", nil},
		{`{"app_id":-778899,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: is less than 1", []string{"778899", "778,899", "minimum"}},
		{`{"app_id":0,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: is less than 1", []string{"got"}},
		{`{"app_id":778899001122334455667788,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: is greater than 9007199254740991", []string{"778899", "7.788", "maximum"}},
		{`{"app_id":` + strings.Repeat("7788990011", 7) + `,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: is greater than 9007199254740991", []string{"778899", "7.788"}},
		{`{"app_id":7.788e99,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: is greater than 9007199254740991", []string{"7788", "7.788", "e99", "e+99"}},
		{`{"app_id":7788.5,"private_key_file":"/k.pem"}`, "the settings are invalid: /app_id: got number, want integer or string", []string{"7788"}},
		{`{"app_id":123456,"installation_id":-778899,"private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: is less than 1", []string{"778899", "778,899"}},
		{`{"app_id":123456,"installation_id":9007199254740992,"private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: is greater than 9007199254740991", []string{"9007199254740992", "9.007"}},
		{`{"app_id":123456,"installation_id":9223372036854775808,"private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: is greater than 9007199254740991", []string{"9223372036854775808", "9.223"}},
		{`{"app_id":123456,"installation_id":1e19,"private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: is greater than 9007199254740991", []string{"1e19", "1e+19", "10000000000000000000"}},
		{`{"app_id":123456,"installation_id":7788.5,"private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: got number, want integer", []string{"7788"}},
		{`{"app_id":123456,"installation_id":"secretvalue","private_key_file":"/k.pem"}`, "the settings are invalid: /installation_id: got string, want integer", nil},
		{`{"app_id":123456,"private_key_file":""}`, "the settings are invalid: /private_key_file: is shorter than 1 character", []string{"got", "minLength"}},
		{`{"app_id":123456,"private_key":""}`, "contain private_key, a secret", []string{"got", "minLength"}},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"contents":"secretvalue"}}`, "/permissions/contents: value must be one of 'read', 'write'", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"contents":"admin"}}`, "/permissions/contents: value must be one of 'read', 'write'", []string{"admin"}},
		{`{"app_id":"123456","private_key_file":"/k.pem","key":"secretvalue"}`, "additional properties 'key' not allowed", nil},
		{`{"app_id":"not an id secretvalue","private_key_file":"/k.pem"}`, "/app_id: does not match", nil},
		{`{"app_id":true,"private_key_file":"/k.pem"}`, "/app_id: got boolean, want integer or string", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"secretvalue"}`, "/api_url: does not match", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"http://api.github.com"}`, "/api_url: does not match", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"https://secretvalue@api.github.com"}`, "/api_url: does not match", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","api_url":"https://secretvalue.example/api/v3"}`, "/api_url: does not match", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{}}`, "/permissions: has fewer than 1 property", []string{"got", "minProperties"}},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"administration":"read"}}`, "/permissions: invalid propertyName 'administration'", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"organization_administration":"read"}}`, "invalid propertyName 'organization_administration'", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"members":"read"}}`, "invalid propertyName 'members'", nil},
		{`{"app_id":"123456","private_key_file":"/k.pem","permissions":{"secrets":"write"}}`, "invalid propertyName 'secrets'", nil},
		{`["app_id"]`, "got array, want object", nil},
		{`{"app_id":1} {}`, "not one JSON document", nil},
	} {
		_, err := ReadSettings(tc.doc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.doc, err)
			continue
		}
		for _, v := range append(tc.value, "PRIVATE KEY", "secretvalue", "\n") {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: the error contains %q: %v", tc.doc, v, err)
			}
		}
	}
}

// TestReadSettingsTakesAnIntegerAsTheSchemaDoes reads an id written as the schema reads
// an integer, whatever its notation, up to the schema's maximum, the largest integer
// every JSON reader holds exactly.
func TestReadSettingsTakesAnIntegerAsTheSchemaDoes(t *testing.T) {
	for _, tc := range []struct {
		doc            string
		app            string
		installationID int64
	}{
		{`{"app_id":123456,"installation_id":42,"private_key_file":"/k.pem"}`, "123456", 42},
		{`{"app_id":123456.0,"installation_id":42.0,"private_key_file":"/k.pem"}`, "123456", 42},
		{`{"app_id":1.23456e5,"installation_id":4.2E1,"private_key_file":"/k.pem"}`, "123456", 42},
		{`{"app_id":9007199254740991,"installation_id":9007199254740991,"private_key_file":"/k.pem"}`, "9007199254740991", 9007199254740991},
		{`{"app_id":"1.0","private_key_file":"/k.pem"}`, "1.0", 0},
	} {
		s, err := ReadSettings(tc.doc)
		if err != nil || s.AppID != tc.app || s.InstallationID != tc.installationID {
			t.Errorf("%s: settings %+v, %v", tc.doc, s, err)
		}
	}
}

// TestReadSettingsRefusesWhatIsNotOneDocumentAndNeverSaysAValue refuses settings that
// are not one JSON document, with an error that says where the document breaks and
// contains no part of it.
func TestReadSettingsRefusesWhatIsNotOneDocumentAndNeverSaysAValue(t *testing.T) {
	secret := `"-----BEGIN RSA PRIVATE KEY-----\nsecretvalue\n-----END RSA PRIVATE KEY-----\n"`
	doc := `{"app_id":123456,"private_key_file":"/k.pem"}`
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", "the settings are empty"},
		{"white space", " \t\r\n ", "the settings are empty"},
		{"two documents", doc + ` {"app_id":"secretvalue"}`, "something other than white space follows it"},
		{"something after", doc + "secretvalue", "something other than white space follows it"},
		{"a white space JSON has not", doc + "\v", "something other than white space follows it"},
		{"cut short", `{"app_id":123456,"private_key":` + secret, "it ends before the document does"},
		{"a key not escaped", `{"app_id":123456,"private_key":"-----BEGIN RSA PRIVATE KEY-----` + "\nsecretvalue\n" + `"}`, "it breaks at byte 64"},
		{"not JSON", "secretvalue", "it breaks at byte 1"},
		{"the key", `{"app_id":123456,"private_key":` + secret + `}`, "contain private_key, a secret"},
		{"the key and its file", `{"app_id":123456,"private_key_file":"/k.pem","private_key":` + secret + `}`, "contain private_key, a secret"},
		{"an unknown setting", `{"app_id":123456,"private_key_file":"/k.pem","key":"secretvalue"}`, "additional properties 'key' not allowed"},
		{"not an object", `["secretvalue"]`, "got array, want object"},
	} {
		_, err := ReadSettings(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "secretvalue") || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: the error contains a value: %v", tc.name, err)
		}
	}
}

// TestASettingsErrorEscapesTheNamesItReports hands in settings whose names contain a
// line break, a tab, DEL, C1 or a Unicode line or paragraph separator, on the command
// line. A name an error reports is escaped, so the error is one line with none of those
// characters in it.
func TestASettingsErrorEscapesTheNamesItReports(t *testing.T) {
	for _, name := range []string{`a\nb`, `a\rb`, `a\tb`, `a\u007fb`, `a\u0085b`, `a\u2028b`, `a\u2029b`} {
		for doc, want := range map[string]string{
			`{"app_id":123456,"private_key_file":"/k.pem","permissions":{"` + name + `":"admin"}}`: `/permissions/"a\`,
			`{"app_id":123456,"private_key_file":"/k.pem","permissions":{"` + name + `":"read"}}`:  `invalid propertyName 'a\`,
			`{"app_id":123456,"private_key_file":"/k.pem","` + name + `":1}`:                       `additional properties 'a\`,
		} {
			_, err := ReadSettings(doc)
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
