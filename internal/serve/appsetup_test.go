package serve

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// The App the fake GitHub's conversion answers, and its secrets, none of which may
// leak.
const (
	setupAppID        = 777001
	setupSlug         = "qory-acme"
	setupClientID     = "Iv1.setup0123456789"
	setupClientSecret = "a-setup-client-secret-that-must-not-leak"
	setupHookSecret   = "a-setup-webhook-secret-that-must-not-leak"
	setupCode         = "a-setup-code-that-must-not-leak"
	foreignCookie     = "a-foreign-cookie-that-must-not-leak"
)

// setupGitHub is GitHub's API and website as the App setup reaches them: the lookup
// of an account, the exchange of the manifest flow's code, and the setting of the
// App's webhook secret.
type setupGitHub struct {
	srv *httptest.Server

	mu sync.Mutex
	// accounts are the accounts by login, and their kinds.
	accounts map[string]string
	// webhookSecret is the conversion's webhook_secret, or null when empty. owner and
	// ownerKind are the App's owner. convStatus and hookStatus answer the exchange
	// and the webhook secret's setting with that status in place of 201 and 200.
	// answer, when set, changes the conversion's answer before it is sent.
	answer            func(map[string]any)
	webhookSecret     string
	owner, ownerKind  string
	convStatus        int
	hookStatus        int
	conversions       []string
	hookSecrets       []string
	cookies           []string
	convHold, convGot chan struct{}
	// appChecks counts the checks of the App at start, GET /app.
	appChecks int
}

func newSetupGitHub(t *testing.T) *setupGitHub {
	t.Helper()
	g := &setupGitHub{accounts: map[string]string{"acme": github.AccountOrganization, "alice": github.AccountUser}, owner: "acme", ownerKind: github.AccountOrganization}
	g.srv = httptest.NewServer(g)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *setupGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if c := r.Header.Get("Cookie"); c != "" {
		g.cookies = append(g.cookies, c)
	}
	hold, got := g.convHold, g.convGot
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/users/"):
		login := strings.TrimPrefix(r.URL.Path, "/users/")
		g.mu.Lock()
		kind, ok := g.accounts[strings.ToLower(login)]
		g.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"login": strings.ToLower(login), "type": kind})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/app-manifests/") && strings.HasSuffix(r.URL.Path, "/conversions"):
		if got != nil {
			got <- struct{}{}
		}
		if hold != nil {
			<-hold
		}
		g.mu.Lock()
		g.conversions = append(g.conversions, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app-manifests/"), "/conversions"))
		status, secret, owner, kind, change := g.convStatus, g.webhookSecret, g.owner, g.ownerKind, g.answer
		g.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, `{"message":"failed"}`)
			return
		}
		ans := map[string]any{
			"id": setupAppID, "slug": setupSlug, "client_id": setupClientID, "html_url": "https://github.com/apps/" + setupSlug,
			"pem": appKeyPEM(), "client_secret": setupClientSecret, "webhook_secret": nil, "owner": map[string]any{"login": owner, "type": kind},
		}
		if secret != "" {
			ans["webhook_secret"] = secret
		}
		if change != nil {
			change(ans)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ans)
	case r.Method == http.MethodGet && r.URL.Path == "/app":
		g.mu.Lock()
		g.appChecks++
		g.mu.Unlock()
		answerApp(w, r)
	case r.Method == http.MethodPatch && r.URL.Path == "/app/hook/config":
		var body struct {
			Secret string `json:"secret"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		g.hookSecrets = append(g.hookSecrets, body.Secret)
		status := g.hookStatus
		g.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			status = http.StatusUnauthorized
		}
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, `{"message":"failed"}`)
			return
		}
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (g *setupGitHub) checks() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.appChecks
}

func (g *setupGitHub) converted() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.conversions...)
}

func (g *setupGitHub) patched() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.hookSecrets...)
}

// setupPayload is a setup pass's payload as Qory Apiary writes it.
func setupPayload(adapter, nonce string, expires time.Time) string {
	return `{"version":1,"adapter_id":"` + adapter + `","nonce":"` + nonce + `","expires_at":"` + contracts.FormatTime(expires) + `"}`
}

// signSetupPass is a setup pass of payload p signed with key.
func signSetupPass(key *accesskey.Key, p string) string {
	sig := key.Sign(append([]byte(contracts.SetupDomain+"\n"), p...))
	return base64.RawURLEncoding.EncodeToString([]byte(p)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jar is a browser's cookies for the setup, which a test sends itself: Go's jar sends
// no Secure cookie over plain HTTP.
type jar map[string]string

// take keeps the cookies an answer sets, and drops those it clears.
func (j jar) take(h http.Header) {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.MaxAge < 0 {
			delete(j, c.Name)
		} else {
			j[c.Name] = c.Value
		}
	}
}

// header is the Cookie header of j, with a foreign cookie, which serve must ignore.
func (j jar) header() string {
	parts := []string{"qory_session=" + foreignCookie}
	for k, v := range j {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

// setupRig is an App setup on a store in a temporary directory, with the fake GitHub,
// Qory Apiary's server key, which signs the setup passes, and its log.
type setupRig struct {
	t      *testing.T
	gh     *setupGitHub
	server *accesskey.Key
	setup  *appSetup
	log    *syncBuffer
	dir    string
	kept   chan *app
}

func newSetupRig(t *testing.T, active bool) *setupRig {
	t.Helper()
	dir := t.TempDir()
	st := openStore(t, filepath.Join(dir, "state"))
	server := newKey(t)
	gh := newSetupGitHub(t)
	log := &syncBuffer{}
	rig := &setupRig{t: t, gh: gh, server: server, log: log, dir: filepath.Join(dir, "state"), kept: make(chan *app, 2)}
	rig.setup = &appSetup{
		Store: st, GitHub: github.Client{API: gh.srv.URL}, PublicURL: "https://qory-github.example.com", ApiaryPublicURL: "https://apiary.example.com",
		StateDir: rig.dir, Active: active, Log: slog.New(slog.NewJSONHandler(log, nil)),
		creds: &credentials{e: enrolment{pin: pinOf(server), adapterID: testAdapterID}},
		setUp: func(a *app) { rig.kept <- a }, refusalEvery: time.Nanosecond,
	}
	return rig
}

// pass is a valid setup pass, new each call, that expires in ten minutes.
func (rig *setupRig) pass() string {
	return signSetupPass(rig.server, setupPayload(testAdapterID, newNonce(), time.Now().Add(10*time.Minute)))
}

// do sends a request to the setup with j's cookies, and keeps those the answer sets.
func (rig *setupRig) do(j jar, method, target string, form url.Values) *httptest.ResponseRecorder {
	rig.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Cookie", j.header())
	w := httptest.NewRecorder()
	rig.setup.ServeHTTP(w, r)
	j.take(w.Header())
	return w
}

var (
	tokenField  = regexp.MustCompile(`name="token" value="([A-Za-z0-9_-]{43})"`)
	formAction  = regexp.MustCompile(`<form id="f" method="post" action="([^"]+)">`)
	manifestVal = regexp.MustCompile(`name="manifest" value="([^"]+)"`)
)

// begin takes a pass in a new browser and shows the account form, and returns the
// browser and the form's token.
func (rig *setupRig) begin(pass string) (jar, string) {
	rig.t.Helper()
	j := jar{}
	w := rig.do(j, http.MethodGet, "/setup?state="+pass, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/continue" {
		rig.t.Fatalf("the pass answered %d %v %s", w.Code, w.Header(), w.Body)
	}
	w = rig.do(j, http.MethodGet, "/setup/continue", nil)
	m := tokenField.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || m == nil {
		rig.t.Fatalf("the account form answered %d %s", w.Code, w.Body)
	}
	return j, m[1]
}

// account posts the account form, and returns the manifest page's action and manifest.
func (rig *setupRig) account(j jar, token, handle string) (*httptest.ResponseRecorder, string, map[string]any) {
	rig.t.Helper()
	w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "account": {handle}})
	a, m := formAction.FindStringSubmatch(w.Body.String()), manifestVal.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || a == nil || m == nil {
		rig.t.Fatalf("the account answered %d %s", w.Code, w.Body)
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &manifest); err != nil {
		rig.t.Fatal(err)
	}
	return w, html.UnescapeString(a[1]), manifest
}

// stateOf is the state the manifest page's action carries.
func stateOf(t *testing.T, action string) string {
	t.Helper()
	u, err := url.Parse(action)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("the action %s", action)
	}
	return u.Query().Get("state")
}

// TestTheSetupFlowKeepsTheAppGitHubCreated runs the App setup whole for an
// organisation, and for a user, against the fake GitHub: every page, its headers and
// its sentences, the manifest it posts and where, the App kept as GitHub's answer
// says it, the cookie at each step, and the lines it logs, none of which, nor any
// answer, holds the pass, the code, a cookie or a secret.
func TestTheSetupFlowKeepsTheAppGitHubCreated(t *testing.T) {
	for _, tc := range []struct {
		handle, org string
		signIn      bool
	}{{"Acme", "acme", false}, {"alice", "", true}} {
		rig := newSetupRig(t, true)
		pass := rig.pass()
		j := jar{}
		w := rig.do(j, http.MethodGet, "/setup?state="+pass, nil)
		ck := (&http.Response{Header: w.Header()}).Cookies()
		if w.Code != http.StatusSeeOther || len(ck) != 1 || ck[0].Name != setupCookie || ck[0].Path != "/setup" || !ck[0].HttpOnly || !ck[0].Secure ||
			ck[0].SameSite != http.SameSiteLaxMode || ck[0].MaxAge != 900 || ck[0].Expires.IsZero() || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("the pass answered %d %v", w.Code, w.Header())
		}
		w = rig.do(j, http.MethodGet, "/setup/continue", nil)
		body := w.Body.String()
		for _, want := range []string{"<h1>Set up the GitHub App</h1>", "GitHub account for the App, an organisation or a user", ">Continue</button>", `action="/setup/continue"`} {
			if !strings.Contains(body, want) {
				t.Errorf("the account form lacks %q: %s", want, body)
			}
		}
		if csp := w.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; frame-ancestors 'none'; form-action 'self'" {
			t.Errorf("the account form's policy is %q", csp)
		}
		token := tokenField.FindStringSubmatch(body)[1]
		w, action, manifest := rig.account(j, token, tc.handle)
		body = w.Body.String()
		login := strings.ToLower(tc.handle)
		if !strings.Contains(body, "<p>GitHub opens with the App filled in, named qory-"+login+"; you can change the name there.</p>") || !strings.Contains(body, ">Create the GitHub App</button>") {
			t.Errorf("the manifest page: %s", body)
		}
		if got := strings.Contains(body, "<p>Sign in to GitHub as "+login+" to create the App.</p>"); got != tc.signIn {
			t.Errorf("the manifest page's sign-in line is there %v: %s", got, body)
		}
		sum := sha256.Sum256([]byte(github.SubmitScript))
		wantCSP := "default-src 'none'; frame-ancestors 'none'; form-action " + rig.gh.srv.URL + "; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if csp := w.Header().Get("Content-Security-Policy"); csp != wantCSP || !strings.Contains(body, "<script>"+github.SubmitScript+"</script>") {
			t.Errorf("the manifest page's policy is %q, want %q", csp, wantCSP)
		}
		wantAction := github.ManifestAction(rig.gh.srv.URL, tc.org, stateOf(t, action))
		if action != wantAction {
			t.Errorf("the manifest page posts to %s, want %s", action, wantAction)
		}
		hook, _ := manifest["hook_attributes"].(map[string]any)
		if manifest["name"] != "qory-"+login || manifest["redirect_url"] != "https://qory-github.example.com/setup/created" ||
			hook["url"] != "https://qory-github.example.com/github/webhook" || hook["active"] != true || manifest["setup_url"] != "https://qory-github.example.com/v1/connect/return" {
			t.Errorf("the manifest is %v", manifest)
		}
		w = rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		body = w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "<p>The GitHub App "+setupSlug+" is set up. Organisations install it with Install in Qory Apiary.</p>") ||
			!strings.Contains(body, `<a href="https://apiary.example.com">Back to Qory Apiary</a>`) || strings.Contains(body, "webhooks") {
			t.Errorf("the end answered %d %s", w.Code, body)
		}
		if _, ok := j[setupCookie]; ok {
			t.Error("the cookie is kept after the setup")
		}
		var kept *app
		select {
		case kept = <-rig.kept:
		default:
			t.Fatal("no App was handed on")
		}
		if kept.id != "777001" || kept.slug != setupSlug || kept.clientID != setupClientID || string(kept.clientSecret) != setupClientSecret || !kept.key.Equal(appKey()) || !kept.webhookActive || !kept.confirmed {
			t.Errorf("the App handed on is %+v", kept)
		}
		// GitHub made no webhook secret, so one was made and set on the App.
		if p := rig.gh.patched(); len(p) != 1 || p[0] != string(kept.webhookSecret) || len(p[0]) != 64 {
			t.Errorf("the webhook secrets set: %v", p)
		}
		if c := rig.gh.converted(); len(c) != 1 || c[0] != setupCode {
			t.Errorf("the conversions: %v", c)
		}
		loaded, err := loadApp(rig.dir)
		if err != nil || loaded.numericID != setupAppID || loaded.slug != setupSlug || loaded.owner != "acme" || loaded.ownerKind != github.AccountOrganization ||
			string(loaded.webhookSecret) != string(kept.webhookSecret) || !loaded.confirmed || !loaded.webhookActive {
			t.Errorf("the App kept is %+v, %v", loaded, err)
		}
		for _, name := range []string{appFile, appKeyFile, appWebhookFile, appClientFile} {
			if info, err := os.Lstat(filepath.Join(rig.dir, name)); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v", name, info, err)
			}
		}
		if _, err := os.Lstat(filepath.Join(rig.dir, appTemp)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is left: %v", appTemp, err)
		}
		logged := rig.log.String()
		for _, want := range []string{`"msg":"setup started"`, `"msg":"GitHub created the App","app_id":777001,"slug":"qory-acme","html_url":"https://github.com/apps/qory-acme"`, `"msg":"the GitHub App is set up","app_id":777001,"slug":"qory-acme","webhook_active":true`} {
			if !strings.Contains(logged, want) {
				t.Errorf("the log lacks %s: %s", want, logged)
			}
		}
		noSetupLeak(t, logged, string(kept.webhookSecret), pass)
		if c := rig.gh.cookies; len(c) != 0 {
			t.Errorf("GitHub was sent cookies: %v", c)
		}
		// Every setup pass is refused once the App is kept, at an address without it.
		w = rig.do(jar{}, http.MethodGet, "/setup?state="+rig.pass(), nil)
		j2 := jar{}
		j2.take(w.Header())
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" {
			t.Errorf("a pass after the setup answered %d %v", w.Code, w.Header())
		}
		w = rig.do(j2, http.MethodGet, "/setup/refused", nil)
		if w.Code != http.StatusConflict || w.Body.String() != "This adapter's GitHub App is set up already.\n" {
			t.Errorf("the refusal shows %d %q", w.Code, w.Body)
		}
	}
}

// noSetupLeak reports a log that holds a pass, the code, a cookie, the private key or
// a secret.
func noSetupLeak(t *testing.T, s string, more ...string) {
	t.Helper()
	for _, bad := range append([]string{setupCode, foreignCookie, setupClientSecret, setupHookSecret, "PRIVATE KEY", "__Secure-qory_github_setup="}, more...) {
		if bad != "" && strings.Contains(s, bad) {
			t.Errorf("%q leaks: %s", bad, s)
		}
	}
}

// TestASetupWithoutAPublicAddressMakesTheWebhookInactive pins that with public_address
// false the manifest's webhook is inactive at the placeholder address Manifest gives,
// the App is kept with its webhook inactive, and the end page says GitHub sends it no
// webhooks.
func TestASetupWithoutAPublicAddressMakesTheWebhookInactive(t *testing.T) {
	rig := newSetupRig(t, false)
	j, token := rig.begin(rig.pass())
	_, action, manifest := rig.account(j, token, "acme")
	hook, _ := manifest["hook_attributes"].(map[string]any)
	if len(hook) != 2 || hook["url"] != "https://github.com/qoryai/qory-github" || hook["active"] != false {
		t.Errorf("the manifest's webhook is %v", hook)
	}
	w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
	if !strings.Contains(w.Body.String(), "<p>GitHub sends this App no webhooks: changes on GitHub arrive with each pull.</p>") {
		t.Errorf("the end page: %s", w.Body)
	}
	if a, err := loadApp(rig.dir); err != nil || a.webhookActive {
		t.Errorf("the App kept: %+v %v", a, err)
	}
}

// TestTheSetupPassIsCheckedStepByStep pins each refusal of a setup pass, at an address
// without the pass, with its page and status: one forged, malformed, of another
// payload, for another adapter, expired or too far ahead, whose nonce is not kept, and
// one taken already. A pass signed under a two-key pin by either key passes.
func TestTheSetupPassIsCheckedStepByStep(t *testing.T) {
	rig := newSetupRig(t, true)
	now := time.Now()
	other := newKey(t)
	invalid := "This setup link is not valid. Press Set up in Qory Apiary again.\n"
	expiredNonce := newNonce()
	for name, tc := range map[string]struct {
		pass   string
		status int
		page   string
		reason string
	}{
		"forged":                               {signSetupPass(other, setupPayload(testAdapterID, newNonce(), now.Add(time.Minute))), 400, invalid, "signature"},
		"malformed":                            {"not a pass", 400, invalid, "pass"},
		"two dots":                             {"a.b.c", 400, invalid, "pass"},
		"connect pass":                         {signPass(rig.server, payload(testAdapterID, testConnection, newNonce(), now.Add(time.Minute))), 400, invalid, "signature"},
		"connect payload under setup's domain": {signSetupPass(rig.server, payload(testAdapterID, testConnection, newNonce(), now.Add(time.Minute))), 400, invalid, "payload"},
		"version 2":                            {signSetupPass(rig.server, strings.Replace(setupPayload(testAdapterID, newNonce(), now.Add(time.Minute)), `"version":1`, `"version":2`, 1)), 400, invalid, "payload"},
		"another adapter":                      {signSetupPass(rig.server, setupPayload("na_fedcba9876543210", newNonce(), now.Add(time.Minute))), 403, "This setup link is for another adapter. Press Set up on this adapter's page in Qory Apiary.\n", "adapter"},
		"expired":                              {signSetupPass(rig.server, setupPayload(testAdapterID, expiredNonce, now.Add(-time.Second))), 400, "This setup link has expired. Press Set up in Qory Apiary again.\n", "expired"},
		"too far ahead":                        {signSetupPass(rig.server, setupPayload(testAdapterID, newNonce(), now.Add(16*time.Minute))), 400, "This setup link has expired. Press Set up in Qory Apiary again.\n", "expired"},
	} {
		j := jar{}
		w := rig.do(j, http.MethodGet, "/setup?state="+url.QueryEscape(tc.pass), nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" || j[setupCookie] != "" {
			t.Errorf("%s: answered %d %v", name, w.Code, w.Header())
			continue
		}
		w = rig.do(j, http.MethodGet, "/setup/refused", nil)
		if w.Code != tc.status || w.Body.String() != tc.page {
			t.Errorf("%s: shows %d %q", name, w.Code, w.Body)
		}
		if !strings.Contains(rig.log.String(), `"reason":"`+tc.reason+`"`) {
			t.Errorf("%s: the log lacks the reason %s: %s", name, tc.reason, rig.log.String())
		}
	}
	if _, err := rig.setup.Store.Get(nsSetupNonces, expiredNonce); err == nil {
		t.Error("an expired pass's nonce is kept")
	}
	// A pass is taken once.
	pass := rig.pass()
	rig.begin(pass)
	j := jar{}
	rig.do(j, http.MethodGet, "/setup?state="+pass, nil)
	if w := rig.do(j, http.MethodGet, "/setup/refused", nil); w.Code != 400 || w.Body.String() != "This setup link was used already. Press Set up in Qory Apiary again.\n" {
		t.Errorf("a pass taken again shows %d %q", w.Code, w.Body)
	}
	// Under a pin of two keys, a pass either signs passes.
	rig.setup.creds.set(enrolment{pin: append(pinOf(other), pinOf(rig.server)...), adapterID: testAdapterID})
	for _, k := range []*accesskey.Key{other, rig.server} {
		rig.begin(signSetupPass(k, setupPayload(testAdapterID, newNonce(), now.Add(time.Minute))))
	}
	noSetupLeak(t, rig.log.String(), pass)
}

// TestTheContractsSignedSetupPassVerifies checks the contract's signed setup pass at
// its time under its fixture server key, its tampered twin refused, and that a setup
// pass never verifies as a connect pass, nor a connect pass as a setup pass.
func TestTheContractsSignedSetupPassVerifies(t *testing.T) {
	var keys struct {
		ServerKey struct {
			PublicKey string `json:"public_key"`
		} `json:"server_key"`
	}
	readFixture(t, "keys.json", &keys)
	var setupDoc, connectDoc struct {
		Pass     string `json:"pass"`
		Tampered string `json:"tampered"`
	}
	readFixture(t, "setup-pass.json", &setupDoc)
	readFixture(t, "connect-pass.json", &connectDoc)
	en := enrolment{pin: accesskey.Pin{{Alg: "ed25519", PublicKey: keys.ServerKey.PublicKey}}, adapterID: "na_f1xt0re000000000"}
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	p, expires, rf := checkSetupPass(setupDoc.Pass, at, en)
	if rf != nil || p.Nonce != "EBESExQVFhcYGRobHB0eHw" || p.AdapterID != "na_f1xt0re000000000" || !expires.Equal(at.Add(15*time.Minute)) {
		t.Errorf("%+v %v %v", p, expires, rf)
	}
	if _, _, rf := checkSetupPass(setupDoc.Tampered, at, en); rf != &setupRefuseSignature {
		t.Errorf("the tampered pass: %v", rf)
	}
	if _, _, rf := checkSetupPass(connectDoc.Pass, at, en); rf != &setupRefuseSignature {
		t.Errorf("the connect pass as a setup pass: %v", rf)
	}
	c := &Connect{Pin: en.pin, AdapterID: en.adapterID}
	if _, _, rf := c.checkPass(setupDoc.Pass, at, c.enrolment()); rf != &refuseSignature {
		t.Errorf("the setup pass as a connect pass: %v", rf)
	}
}

// TestPOSTToTheSetupIsRefusedUnread pins that POST /setup answers 405 without reading
// its body, and that the account form needs the session's cookie and its token.
func TestPOSTToTheSetupIsRefusedUnread(t *testing.T) {
	rig := newSetupRig(t, true)
	body := &countingReader{r: strings.NewReader("state=" + rig.pass() + "&_csrf_token=x")}
	r := httptest.NewRequest(http.MethodPost, "/setup", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	rig.setup.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed || w.Body.String() != "This address answers only GET requests.\n" || w.Header().Get("Allow") != "GET" || body.n != 0 {
		t.Errorf("POST /setup answered %d %q, read %d", w.Code, w.Body, body.n)
	}
	noSession := "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.\n"
	// A form without the cookie finds no session, and its body is not read.
	body = &countingReader{r: strings.NewReader("account=acme&token=x")}
	r = httptest.NewRequest(http.MethodPost, "/setup/continue", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	rig.setup.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || w.Body.String() != noSession || body.n != 0 {
		t.Errorf("a form without the cookie answered %d %q, read %d", w.Code, w.Body, body.n)
	}
	j, token := rig.begin(rig.pass())
	for _, form := range []url.Values{{"account": {"acme"}}, {"account": {"acme"}, "token": {strings.Repeat("A", 43)}}, {"account": {"acme"}, "token": {token, token}}} {
		if w := rig.do(j, http.MethodPost, "/setup/continue", form); w.Code != http.StatusBadRequest || w.Body.String() != noSession {
			t.Errorf("%v answered %d %q", form, w.Code, w.Body)
		}
	}
	// The session lasts a refused form: the right token goes on.
	w, _, _ = rig.account(j, token, "acme")
	if w.Code != http.StatusOK {
		t.Errorf("the form answered %d", w.Code)
	}
	if w := rig.do(j, http.MethodPut, "/setup/continue", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" {
		t.Errorf("PUT answered %d %v", w.Code, w.Header())
	}
}

// countingReader counts the bytes read from r.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestAnUnknownAccountShowsTheFormAgain pins that an account GitHub has none by shows
// the form again, with the line that says so, and the flow goes on.
func TestAnUnknownAccountShowsTheFormAgain(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	for _, handle := range []string{"nobody", "not a handle", strings.Repeat("a", 40)} {
		w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "account": {handle}})
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<p>GitHub has no account by that name.</p>") || !strings.Contains(w.Body.String(), token) {
			t.Errorf("%q answered %d %s", handle, w.Code, w.Body)
		}
	}
	rig.account(j, token, "acme")
}

// TestAWrongStateOrCodeIsRefusedWithoutAnExchange pins that GitHub's redirect needs the
// session's state, in constant time, and a code of GitHub's shape, and that the code
// is never exchanged otherwise; the refusal ends the flow.
func TestAWrongStateOrCodeIsRefusedWithoutAnExchange(t *testing.T) {
	rig := newSetupRig(t, true)
	for _, q := range []func(state string) string{
		func(string) string { return "code=" + setupCode + "&state=" + strings.Repeat("A", 43) },
		func(state string) string { return "code=" + setupCode },
		func(state string) string { return "state=" + state },
		func(state string) string { return "code=a%2Fb&state=" + state },
		func(state string) string { return "code=" + setupCode + "&code=x&state=" + state },
	} {
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, "acme")
		w := rig.do(j, http.MethodGet, "/setup/created?"+q(stateOf(t, action)), nil)
		if w.Code != http.StatusBadRequest || w.Body.String() != "This setup link is not valid. Press Set up in Qory Apiary again.\n" || j[setupCookie] != "" {
			t.Errorf("%s answered %d %q", q("S"), w.Code, w.Body)
		}
	}
	// A redirect before the account form has no state to match.
	j, _ := rig.begin(rig.pass())
	if w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state=", nil); w.Code != http.StatusBadRequest {
		t.Errorf("a redirect before the form answered %d", w.Code)
	}
	if c := rig.gh.converted(); len(c) != 0 {
		t.Errorf("exchanged %v", c)
	}
}

// TestANewerPassReplacesTheOpenFlow pins that a valid pass taken later replaces the
// flow under way: the older flow's form and GitHub's redirect for it are refused with
// the page that says to delete its App, its code never exchanged, and the newer flow
// sets the App up.
func TestANewerPassReplacesTheOpenFlow(t *testing.T) {
	rig := newSetupRig(t, true)
	ja, tokenA := rig.begin(rig.pass())
	_, actionA, _ := rig.account(ja, tokenA, "acme")
	jb, tokenB := rig.begin(rig.pass())
	replaced := "A newer setup replaced this one. If you created an App on GitHub for it, delete it at " + rig.gh.srv.URL + "/organizations/acme/settings/apps.\n"
	w := rig.do(ja, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, actionA), nil)
	if w.Code != http.StatusConflict || w.Body.String() != replaced || ja[setupCookie] != "" {
		t.Errorf("the older flow's redirect answered %d %q", w.Code, w.Body)
	}
	if c := rig.gh.converted(); len(c) != 0 {
		t.Errorf("the older flow's code was exchanged: %v", c)
	}
	// The older flow's form, in a browser that is still at it, is refused as well.
	jc, _ := rig.begin(rig.pass())
	rig.begin(rig.pass())
	if w := rig.do(jc, http.MethodGet, "/setup/continue", nil); w.Code != http.StatusConflict || !strings.HasPrefix(w.Body.String(), "A newer setup replaced this one.") || !strings.Contains(w.Body.String(), rig.gh.srv.URL+"/settings/apps.") {
		t.Errorf("a replaced flow's form answered %d %q", w.Code, w.Body)
	}
	// The newest pass now is the fourth's: B's is replaced too, and goes back.
	if w := rig.do(jb, http.MethodPost, "/setup/continue", url.Values{"token": {tokenB}, "account": {"acme"}}); w.Code != http.StatusConflict {
		t.Errorf("B's form answered %d", w.Code)
	}
	je, tokenE := rig.begin(rig.pass())
	_, actionE, _ := rig.account(je, tokenE, "acme")
	if w := rig.do(je, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, actionE), nil); w.Code != http.StatusOK {
		t.Errorf("the newest flow answered %d %s", w.Code, w.Body)
	}
	if c := rig.gh.converted(); len(c) != 1 {
		t.Errorf("exchanged %v", c)
	}
}

// TestTwoRedirectsAtOnceKeepOneApp sends GitHub's redirect twice at once, as a browser
// that reloads, and checks the code is exchanged once and the App kept once.
func TestTwoRedirectsAtOnceKeepOneApp(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	rig.gh.convHold, rig.gh.convGot = make(chan struct{}), make(chan struct{}, 2)
	waiting := make(chan struct{}, 2)
	rig.setup.waits = func() { waiting <- struct{}{} }
	target := "/setup/created?code=" + setupCode + "&state=" + stateOf(t, action)
	cookie := j.header()
	codes := make(chan int, 2)
	for range 2 {
		go func() {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.Header.Set("Cookie", cookie)
			w := httptest.NewRecorder()
			rig.setup.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	// One exchanges the code, holding the lock, while the other waits for it.
	<-rig.gh.convGot
	<-waiting
	close(rig.gh.convHold)
	a, b := <-codes, <-codes
	if !(a == 200 && b == 409 || a == 409 && b == 200) {
		t.Errorf("the redirects answered %d and %d", a, b)
	}
	if c := rig.gh.converted(); len(c) != 1 {
		t.Errorf("exchanged %d times", len(c))
	}
	if len(rig.kept) != 1 {
		t.Errorf("handed on %d Apps", len(rig.kept))
	}
}

// TestANewerPassWhileTheRedirectWaitsEndsIt pins the check, under the lock, that the
// redirect's session is still the flow's: a newer pass that moves the flow pointer
// while the redirect waits for the lock ends the redirect's flow before its code is
// exchanged.
func TestANewerPassWhileTheRedirectWaitsEndsIt(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	target := "/setup/created?code=" + setupCode + "&state=" + stateOf(t, action)
	waiting := make(chan struct{}, 1)
	rig.setup.waits = func() { waiting <- struct{}{} }
	rig.setup.lock <- struct{}{}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- rig.do(j, http.MethodGet, target, nil) }()
	// The redirect passes its first check and waits for the lock; the newer pass's
	// start, which holds the lock, moves the pointer.
	<-waiting
	if err := rig.setup.Store.Put(nsSetup, keyFlow, []byte(sessionKey("a newer session")), sessionFor); err != nil {
		t.Fatal(err)
	}
	<-rig.setup.lock
	w := <-done
	if w.Code != http.StatusConflict || !strings.HasPrefix(w.Body.String(), "A newer setup replaced this one.") {
		t.Errorf("the redirect answered %d %q", w.Code, w.Body)
	}
	if c := rig.gh.converted(); len(c) != 0 {
		t.Errorf("the code was exchanged: %v", c)
	}
}

// TestAPassWhileAnAppIsKeptIsRefused pins the check, under the lock, that no App is
// kept: a pass that waits for the lock while a setup keeps its App is refused with
// the page that says the App is set up, and starts no session.
func TestAPassWhileAnAppIsKeptIsRefused(t *testing.T) {
	rig := newSetupRig(t, true)
	pass := rig.pass()
	waiting := make(chan struct{}, 1)
	rig.setup.waits = func() { waiting <- struct{}{} }
	rig.setup.init()
	rig.setup.lock <- struct{}{}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- rig.do(jar{}, http.MethodGet, "/setup?state="+pass, nil) }()
	<-waiting
	rig.setup.kept.Store(true)
	<-rig.setup.lock
	w := <-done
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" {
		t.Errorf("the pass answered %d %v", w.Code, w.Header())
	}
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, setupCookie+"=") && !strings.HasPrefix(c, setupCookie+"=;") {
			t.Errorf("a session started: %s", c)
		}
	}
	if !strings.Contains(rig.log.String(), `"reason":"set_up"`) || strings.Contains(rig.log.String(), `"msg":"setup started"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
}

// TestAKeptAppFoundAtTheRedirectIsNotReplaced pins that GitHub's redirect is refused
// with the page that says the App is set up, its code not exchanged, when app.json is
// in the state directory though no App was marked kept.
func TestAKeptAppFoundAtTheRedirectIsNotReplaced(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	if err := keepApp(rig.dir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
	if w.Code != http.StatusConflict || w.Body.String() != "This adapter's GitHub App is set up already.\n" {
		t.Errorf("the redirect answered %d %q", w.Code, w.Body)
	}
	if c := rig.gh.converted(); len(c) != 0 {
		t.Errorf("the code was exchanged: %v", c)
	}
}

// TestAnAppThatCannotBeKeptSaysToDeleteIt pins the pages of a setup whose App GitHub
// created, or may have, and serve did not keep: the exchange failing, and the commit
// failing at its rename, which leaves no file behind.
func TestAnAppThatCannotBeKeptSaysToDeleteIt(t *testing.T) {
	rig := newSetupRig(t, true)
	rig.gh.convStatus = http.StatusInternalServerError
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
	if w.Code != http.StatusBadGateway || w.Body.String() != "GitHub may have created an App; delete it at "+rig.gh.srv.URL+"/organizations/acme/settings/apps, then press Set up in Qory Apiary again.\n" || j[setupCookie] != "" {
		t.Errorf("a failed exchange answered %d %q", w.Code, w.Body)
	}
	rig.gh.convStatus = 0
	rename = func(string, string) error { return errors.New("no rename") }
	t.Cleanup(func() { rename = os.Rename })
	j, token = rig.begin(rig.pass())
	_, action, _ = rig.account(j, token, "acme")
	w = rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
	if w.Code != http.StatusInternalServerError || w.Body.String() != "GitHub created the App qory-acme, and this server could not keep it. Delete it at "+rig.gh.srv.URL+"/organizations/acme/settings/apps/qory-acme, then press Set up in Qory Apiary again.\n" {
		t.Errorf("a failed commit answered %d %q", w.Code, w.Body)
	}
	if entries, _ := os.ReadDir(rig.dir); len(entries) != 1 || entries[0].Name() != store.FileName {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the state directory holds %v", names)
	}
	if len(rig.kept) != 0 || rig.setup.kept.Load() {
		t.Error("an App not kept was handed on")
	}
	if !strings.Contains(rig.log.String(), `"msg":"setup failed","step":"created","what":"keep"`) || !strings.Contains(rig.log.String(), `"what":"conversion"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	noSetupLeak(t, rig.log.String())
}

// TestGitHubsAnswerIsCheckedBeforeTheAppIsKept pins each check of GitHub's answer to
// the code's exchange: a private key that is not one, a slug, client id, client secret
// or webhook secret serve cannot keep, and what looks like an access key secret or a
// run key in the key or a secret. Each ends the flow with the page that says to delete
// the App, at its settings page, or at the account's Apps when the slug is not one
// serve takes, keeps no file, and logs an error that names no file of the state
// directory and no secret: the private key's says the key is not one, and every other
// names GitHub's answer. An owner's login that is not one, or one longer than 39
// characters, makes the page name the session's account; one of 39 characters is the
// account the page names.
func TestGitHubsAnswerIsCheckedBeforeTheAppIsKept(t *testing.T) {
	const accessKey = "qak_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
	const (
		qak = "GitHub's answer holds what looks like an access key secret, qak_, which belongs nowhere in it"
		qrk = "GitHub's answer holds what looks like a run key, qrk_, which belongs nowhere in it"
	)
	long, login := strings.Repeat("a", 4<<10), strings.Repeat("a", 39)
	for name, tc := range map[string]struct {
		change func(map[string]any)
		err    string
		noSlug bool
		owner  string
	}{
		"a private key that is not PEM":               {func(a map[string]any) { a["pem"] = "not a key" }, "the private key is not PEM", false, ""},
		"an access key secret beside the private key": {func(a map[string]any) { a["pem"] = accessKey + "\n" + appKeyPEM() }, qak, false, ""},
		"a run key beside the private key":            {func(a map[string]any) { a["pem"] = "QRK_secret value\n" + appKeyPEM() }, qrk, false, ""},
		"a slug serve does not take":                  {func(a map[string]any) { a["slug"] = "qory acme" }, "GitHub's answer holds no App slug setup can keep", true, ""},
		"no client id":                                {func(a map[string]any) { a["client_id"] = "" }, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"a client id serve does not take":             {func(a map[string]any) { a["client_id"] = "Iv1/x" }, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"no client secret":                            {func(a map[string]any) { a["client_secret"] = "" }, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"a client secret with a space":                {func(a map[string]any) { a["client_secret"] = "a client secret" }, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"a client secret of 4 KiB":                    {func(a map[string]any) { a["client_secret"] = long }, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"an owner's login that is not one": {func(a map[string]any) {
			a["owner"] = map[string]any{"login": "acme/x", "type": github.AccountOrganization}
			a["client_id"] = ""
		}, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"an owner's login of 40 characters": {func(a map[string]any) {
			a["owner"] = map[string]any{"login": login + "b", "type": github.AccountOrganization}
			a["client_id"] = ""
		}, "GitHub's answer holds no client id, or no client secret setup can keep", false, ""},
		"an owner's login of 39 characters": {func(a map[string]any) {
			a["owner"] = map[string]any{"login": login, "type": github.AccountOrganization}
			a["client_id"] = ""
		}, "GitHub's answer holds no client id, or no client secret setup can keep", false, login},
		"an access key secret as the client secret":  {func(a map[string]any) { a["client_secret"] = accessKey }, qak, false, ""},
		"a webhook secret under 16 bytes":            {func(a map[string]any) { a["webhook_secret"] = "fifteen-bytes.." }, "GitHub's answer holds a webhook secret qory-github-server serve cannot use", false, ""},
		"a webhook secret of 4 KiB":                  {func(a map[string]any) { a["webhook_secret"] = long }, "GitHub's answer holds a webhook secret qory-github-server serve cannot use", false, ""},
		"a webhook secret with a line break":         {func(a map[string]any) { a["webhook_secret"] = setupHookSecret + "\n" }, "GitHub's answer holds a webhook secret qory-github-server serve cannot use", false, ""},
		"an access key secret as the webhook secret": {func(a map[string]any) { a["webhook_secret"] = accessKey }, qak, false, ""},
		"a run key as the webhook secret":            {func(a map[string]any) { a["webhook_secret"] = "qrk_-a-pasted-run-key" }, qrk, false, ""},
	} {
		rig := newSetupRig(t, true)
		rig.gh.answer = tc.change
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, "acme")
		w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		owner := "acme"
		if tc.owner != "" {
			owner = tc.owner
		}
		page, status := "GitHub created the App qory-acme, and this server could not keep it. Delete it at "+rig.gh.srv.URL+"/organizations/"+owner+"/settings/apps/qory-acme, then press Set up in Qory Apiary again.\n", http.StatusInternalServerError
		if tc.noSlug {
			page, status = "GitHub may have created an App; delete it at "+rig.gh.srv.URL+"/organizations/acme/settings/apps, then press Set up in Qory Apiary again.\n", http.StatusBadGateway
		}
		if w.Code != status || w.Body.String() != page || j[setupCookie] != "" {
			t.Errorf("%s: answered %d %q", name, w.Code, w.Body)
		}
		want, _ := json.Marshal(tc.err)
		if !strings.Contains(rig.log.String(), `"msg":"setup failed","step":"created","what":"keep","error":`+string(want)) {
			t.Errorf("%s: the log %s", name, rig.log.String())
		}
		if strings.Contains(rig.log.String(), "state directory") || strings.Contains(rig.log.String(), "the file app-") {
			t.Errorf("%s: the log names a file: %s", name, rig.log.String())
		}
		if entries, _ := os.ReadDir(rig.dir); len(entries) != 1 {
			t.Errorf("%s: the state directory holds %v", name, entries)
		}
		if len(rig.kept) != 0 || rig.setup.kept.Load() {
			t.Errorf("%s: an App not kept was handed on", name)
		}
		noSetupLeak(t, rig.log.String(), accessKey, "QRK_secret", "qrk_-a-pasted")
	}
}

// TestTheLargestPrivateKeyLoadAppReadsIsKept pins keep's bound on the private key in
// GitHub's answer: one whose file, with the line break keepApp writes at its end, is
// [github.MaxKeyFile] bytes is kept and read back, also with a line break at its end in
// the answer, which is not part of it, and one a byte larger is refused, keeping no
// file and logging no secret.
func TestTheLargestPrivateKeyLoadAppReadsIsKept(t *testing.T) {
	largest := appKeyPEM() + strings.Repeat("a", github.MaxKeyFile-1-len(appKeyPEM()))
	for name, tc := range map[string]struct {
		pem  string
		kept bool
	}{
		"the largest":                    {largest, true},
		"one byte larger":                {largest + "a", false},
		"the largest, with a line break": {largest + "\r\n", true},
	} {
		rig := newSetupRig(t, true)
		rig.gh.answer = func(a map[string]any) { a["pem"] = tc.pem }
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, "acme")
		w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		_, err := loadApp(rig.dir)
		if tc.kept && (w.Code != http.StatusOK || err != nil) {
			t.Errorf("%s: answered %d %q, and the App read back: %v", name, w.Code, w.Body, err)
		}
		if !tc.kept {
			if w.Code != http.StatusInternalServerError || !strings.Contains(rig.log.String(), `"what":"keep","error":"GitHub's answer holds a private key larger than setup can keep"`) {
				t.Errorf("%s: answered %d %q, the log %s", name, w.Code, w.Body, rig.log.String())
			}
			if entries, _ := os.ReadDir(rig.dir); len(entries) != 1 {
				t.Errorf("%s: the state directory holds %v", name, entries)
			}
		}
		noSetupLeak(t, rig.log.String())
	}
}

// TestAnUnconfirmedWebhookSecretKeepsTheApp pins that an App whose webhook secret
// GitHub does not confirm is kept all the same, marked so, with the line that says
// serve sets it again at its next start.
func TestAnUnconfirmedWebhookSecretKeepsTheApp(t *testing.T) {
	rig := newSetupRig(t, true)
	rig.gh.hookStatus = http.StatusBadGateway
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	if w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil); w.Code != http.StatusOK {
		t.Fatalf("answered %d %s", w.Code, w.Body)
	}
	a, err := loadApp(rig.dir)
	if err != nil || a.confirmed {
		t.Errorf("the App kept: %+v %v", a, err)
	}
	if !strings.Contains(rig.log.String(), `"msg":"GitHub did not confirm the App's webhook secret; serve sets it again at its next start"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	noSetupLeak(t, rig.log.String(), string(a.webhookSecret))
	// The secret GitHub's answer holds, when it holds one, is kept as it is, and nothing
	// is set.
	rig = newSetupRig(t, true)
	rig.gh.webhookSecret = setupHookSecret
	j, token = rig.begin(rig.pass())
	_, action, _ = rig.account(j, token, "acme")
	rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
	if a, err := loadApp(rig.dir); err != nil || string(a.webhookSecret) != setupHookSecret || !a.confirmed || len(rig.gh.patched()) != 0 {
		t.Errorf("the App kept: %+v %v", a, err)
	}
}

// TestASessionThatEndedFindsNone pins that every step past the pass needs a session,
// and that a cookie the setup did not set is not one.
func TestASessionThatEndedFindsNone(t *testing.T) {
	rig := newSetupRig(t, true)
	for _, target := range []string{"/setup/continue", "/setup/created?code=" + setupCode + "&state=x"} {
		w := rig.do(jar{connectCookie: randomID()}, http.MethodGet, target, nil)
		if w.Code != http.StatusBadRequest || w.Body.String() != "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.\n" {
			t.Errorf("%s answered %d %q", target, w.Code, w.Body)
		}
	}
	if w := rig.do(jar{}, http.MethodGet, "/setup/other", nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown path answered %d", w.Code)
	}
}
