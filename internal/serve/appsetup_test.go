package serve

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// appChecks counts the checks of the App at start, GET /app, and lookups the
	// lookups of an account, GET /users/<login>.
	appChecks int
	lookups   int
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
		g.lookups++
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

func (g *setupGitHub) looked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lookups
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

// withMember is the payload p, one JSON object, with the raw member m added last.
func withMember(p, m string) string {
	return strings.TrimSuffix(p, "}") + "," + m + "}"
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
// Qory Apiary's server key, which signs the setup passes, and its log. Its uploads of
// the App to Qory Apiary are recorded in stored, each failing with fail's error for
// the try n, numbered from 1, when fail is set; its waits between tries are recorded
// in waits, and last no time.
type setupRig struct {
	t      *testing.T
	gh     *setupGitHub
	server *accesskey.Key
	setup  *appSetup
	log    *syncBuffer
	dir    string
	kept   chan *app

	mu     sync.Mutex
	tries  int
	stored []*app
	fail   func(n int) error
	waits  []time.Duration
	// released, when set, is received from before each wait ends.
	released chan struct{}
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
		Active: active, Log: slog.New(slog.NewJSONHandler(log, nil)), Upload: rig.upload, UploadFor: time.Minute,
		creds: &credentials{e: enrolment{pin: pinOf(server), adapterID: testAdapterID}},
		setUp: func(a *app) { rig.kept <- a }, refusalEvery: time.Nanosecond, wait: rig.wait,
	}
	// The tries of an upload end when the test does, as they end when serve stops.
	ctx, cancel := context.WithCancel(context.Background())
	rig.setup.ctx = ctx
	t.Cleanup(func() {
		cancel()
		rig.setup.stop()
	})
	return rig
}

// upload is the rig's upload of the App a to Qory Apiary.
func (rig *setupRig) upload(_ context.Context, a *app) error {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	rig.tries++
	if rig.fail != nil {
		if err := rig.fail(rig.tries); err != nil {
			return err
		}
	}
	rig.stored = append(rig.stored, a)
	return nil
}

// wait is the rig's wait between tries: it records d, and ends at once, after a receive
// from released when that is set, or when ctx is done.
func (rig *setupRig) wait(ctx context.Context, d time.Duration) error {
	rig.mu.Lock()
	rig.waits = append(rig.waits, d)
	released := rig.released
	rig.mu.Unlock()
	if released != nil {
		select {
		case <-released:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// storedApp is the last App the rig stored in Qory Apiary, or nil.
func (rig *setupRig) storedApp() *app {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.stored) == 0 {
		return nil
	}
	return rig.stored[len(rig.stored)-1]
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

// begin takes a pass in a new browser and shows Start, and returns the browser and
// the form's token.
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
		rig.t.Fatalf("Start answered %d %s", w.Code, w.Body)
	}
	return j, m[1]
}

// account posts Start for a private App under the organisation org, with no name, and
// returns the manifest page's action and manifest.
func (rig *setupRig) account(j jar, token, org string) (*httptest.ResponseRecorder, string, map[string]any) {
	rig.t.Helper()
	return rig.accountAs(j, token, org, installPrivate)
}

// accountAs posts Start under the organisation org with install, and no name, and
// returns the manifest page's action and manifest.
func (rig *setupRig) accountAs(j jar, token, org, install string) (*httptest.ResponseRecorder, string, map[string]any) {
	rig.t.Helper()
	return rig.startAs(j, token, url.Values{"organisation": {org}, "install": {install}})
}

// startAs posts Start with form and the token, and returns the manifest page's action
// and manifest.
func (rig *setupRig) startAs(j jar, token string, form url.Values) (*httptest.ResponseRecorder, string, map[string]any) {
	rig.t.Helper()
	form.Set("token", token)
	w := rig.do(j, http.MethodPost, "/setup/continue", form)
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
// organisation's public App with a name, and for a private App under the person signed
// in on GitHub with no name, against the fake GitHub: every page, its headers and its
// sentences, the manifest it posts and where, the App stored in Qory Apiary as GitHub's
// answer says it, the cookie at each step, and the lines it logs, none of which, nor
// any answer, contains the pass, the code, a cookie or a secret. Nothing but the store
// is written to the state directory.
func TestTheSetupFlowKeepsTheAppGitHubCreated(t *testing.T) {
	for _, tc := range []struct {
		org, wantOrg, install, name, owner, ownerKind, done, next, signIn, press string
	}{
		{
			"Acme", "acme", installPublic, "qory-acme", "acme", github.AccountOrganization,
			"Any GitHub account can install it.",
			"In Qory Apiary, each organisation installs the App, with Install in Settings › Integrations or with Connect on the Work source step. GitHub's install page then lists the GitHub accounts you can install it on.",
			"If GitHub asks you to sign in, sign in as an owner of acme.", "Press Create GitHub App for acme. GitHub then brings you back here.",
		},
		{
			"", "", installPrivate, "", "alice", github.AccountUser,
			"Only alice can install it.",
			"In Qory Apiary, the organisation installs the App, with Install in Settings › Integrations or with Connect on the Work source step. GitHub's install page then asks which repositories the App may reach.",
			"If GitHub asks you to sign in, sign in as the user who will own the App.", "Press Create GitHub App. GitHub then brings you back here.",
		},
	} {
		rig := newSetupRig(t, true)
		rig.gh.owner, rig.gh.ownerKind = tc.owner, tc.ownerKind
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
		for _, want := range []string{
			"<title>Start · Set up the GitHub App</title>", `<p class="q-su-where">Connect Qory Apiary › GitHub</p>`, `<h1 class="q-su-h1">Set up the GitHub App</h1>`,
			`<p id="set-up-step" class="q-su-count-wide">Step 1 of 3</p>`, `<p class="q-su-count-bar">Step 1 of 3: Start</p>`,
			`<span class="q-su-step is-current" aria-current="step"><span class="q-su-mark" aria-hidden="true"></span><span class="q-su-nm">Start</span></span>`,
			`<label class="label" for="organisation">GitHub organisation (optional)</label>`, `<label class="label" for="name">App name</label>`,
			`id="name" name="name" type="text" value=""`, `<legend class="label">Who can install the App</legend>`,
			`<button class="btn btn-md btn-primary" type="submit">Continue on GitHub</button>`, `method="post" action="/setup/continue"`,
			`<h2 id="set-up-context-h" class="q-context-h">About this step</h2>`, `<a class="q-brand" href="https://apiary.example.com">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("Start lacks %q: %s", want, body)
			}
		}
		for _, line := range []string{
			"You create the GitHub App that this Qory Apiary instance's GitHub adapter uses to work with GitHub. GitHub's page opens next, where you create it, and GitHub then sends you back here.",
			"Leave it empty to create the App under your GitHub user.",
			"Up to 34 characters. Leave it empty to name the App on GitHub's page.",
			"What the App may do on an account that installs it Read and write issues and their comments Read and write code and pull requests Start GitHub Actions workflows, and write checks Read an organisation's members Read repository settings and metadata",
			"Owner. The organisation or user that owns the App holds its settings and keys on GitHub. An organisation keeps the App when a person leaves. An App owned by your user leaves with you. Sign in on github.com in this browser first: as an owner of the organisation, or as the user who will own the App.",
			"Who can install. A private App can be installed only by its owner. A public App can be installed by any GitHub account. Either way, the GitHub adapter uses only installations made with Install or Connect in Qory Apiary. You can change this later on GitHub, in the App's settings under Advanced.",
			"Nothing is installed yet. The App reaches no repository until an organisation in Qory Apiary installs it.",
		} {
			if !shows(body, line) {
				t.Errorf("Start does not show %q: %s", line, visible(body))
			}
		}
		if csp := w.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self'; font-src 'self'" {
			t.Errorf("Start's policy is %q", csp)
		}
		token := tokenField.FindStringSubmatch(body)[1]
		w, action, manifest := rig.startAs(j, token, url.Values{"organisation": {tc.org}, "install": {tc.install}, "name": {tc.name}})
		body = w.Body.String()
		for _, line := range []string{"Opening GitHub…", "Open GitHub", "Step 2 of 3", "On GitHub " + tc.signIn + " Check the App name. If GitHub says the name is taken, change it. " + tc.press,
			"When you press Create GitHub App, GitHub sends you back here with a one-time code. The GitHub adapter exchanges the code with GitHub for the App's ID, private key and secrets, and stores them in Qory Apiary. You copy nothing."} {
			if !shows(body, line) {
				t.Errorf("the manifest page does not show %q: %s", line, visible(body))
			}
		}
		if !strings.Contains(body, "<title>On GitHub · Set up the GitHub App</title>") || !strings.Contains(body, `<button class="btn btn-md btn-primary" type="submit">Open GitHub</button>`) {
			t.Errorf("the manifest page: %s", body)
		}
		sum := sha256.Sum256([]byte(github.SubmitScript))
		wantCSP := "default-src 'none'; frame-ancestors 'none'; form-action " + rig.gh.srv.URL + "; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; style-src 'self'; font-src 'self'"
		if csp := w.Header().Get("Content-Security-Policy"); csp != wantCSP || !strings.Contains(body, "<script>"+github.SubmitScript+"</script>") || strings.Count(body, "<script") != 1 {
			t.Errorf("the manifest page's policy is %q, want %q", csp, wantCSP)
		}
		wantAction := github.ManifestAction(rig.gh.srv.URL, tc.wantOrg, stateOf(t, action))
		if action != wantAction {
			t.Errorf("the manifest page posts to %s, want %s", action, wantAction)
		}
		hook, _ := manifest["hook_attributes"].(map[string]any)
		name, named := manifest["name"]
		if named != (tc.name != "") || (named && name != tc.name) || manifest["redirect_url"] != "https://qory-github.example.com/setup/created" ||
			hook["url"] != "https://qory-github.example.com/v1/events" || hook["active"] != true || manifest["setup_url"] != "https://qory-github.example.com/v1/connect/return" ||
			manifest["public"] != (tc.install == installPublic) {
			t.Errorf("the manifest is %v", manifest)
		}
		w = rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		body = w.Body.String()
		for _, line := range []string{
			"The GitHub App " + setupSlug + " is set up and connected to Qory Apiary: its keys are stored there. " + tc.done + " The GitHub step in your Qory Apiary tab now shows Set up.",
			"Next " + tc.next, "Step 3 of 3",
			"GitHub sent the App's ID, private key and secrets to the GitHub adapter, which stored them in Qory Apiary. There is nothing to copy. You can close this tab. Your first Qory Apiary tab updates without a reload.",
		} {
			if !shows(body, line) {
				t.Errorf("the end page does not show %q: %s", line, visible(body))
			}
		}
		if w.Code != http.StatusOK || !strings.Contains(body, `<a class="btn btn-md btn-primary" href="https://apiary.example.com">Back to Qory Apiary</a>`) || strings.Contains(body, "webhooks") ||
			!strings.Contains(body, "<strong>"+setupSlug+"</strong>") || w.Header().Get("Content-Security-Policy") != pageCSP("") {
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
			// The secret is a generated value, so the output shows its length alone.
			shown := make([]string, len(p))
			for i, v := range p {
				shown[i] = fmt.Sprintf("[secret of %d bytes, the App's: %v]", len(v), v == string(kept.webhookSecret))
			}
			t.Errorf("the webhook secrets set: %v", shown)
		}
		if c := rig.gh.converted(); len(c) != 1 || c[0] != setupCode {
			t.Errorf("the conversions: %v", c)
		}
		stored := rig.storedApp()
		if stored == nil || stored != kept || stored.numericID != setupAppID || stored.slug != setupSlug || stored.owner != tc.owner || stored.ownerKind != tc.ownerKind ||
			string(stored.pem) != strings.TrimSpace(appKeyPEM()) || !stored.confirmed || !stored.webhookActive || rig.tries != 1 {
			t.Errorf("the App stored is %+v after %d tries", stored, rig.tries)
		}
		if entries, _ := os.ReadDir(rig.dir); len(entries) != 1 || entries[0].Name() != store.FileName {
			t.Errorf("the state directory contains %v", entries)
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
		refusalShown(t, w, http.StatusConflict, "The GitHub App is set up already", "Qory Apiary has this App's keys. No action needed.", "https://apiary.example.com")
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
	if !strings.Contains(w.Body.String(), "<p>GitHub sends this App no webhooks, because the GitHub adapter has no public address. Changes on GitHub arrive with each pull.</p>") {
		t.Errorf("the end page: %s", w.Body)
	}
	if a := rig.storedApp(); a == nil || a.webhookActive {
		t.Errorf("the App stored: %+v", a)
	}
}

// TestASetupAtAHostOnlyPublicURLSendsItsAddresses runs the App setup with public_url
// the adapter's host name, with and without a trailing slash, as the settings take it:
// the cookies are for /setup, the redirects and the form's action are /setup and the
// paths under it, and the manifest's redirect, webhook, Setup URL and callback URL are
// the origin followed by one slash and their path.
func TestASetupAtAHostOnlyPublicURLSendsItsAddresses(t *testing.T) {
	for _, in := range []string{"https://github.example.com", "https://github.example.com/"} {
		publicURL, err := checkPublicURL(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		rig := newSetupRig(t, true)
		rig.setup.PublicURL = publicURL
		j := jar{}
		w := rig.do(j, http.MethodGet, "/setup?state="+rig.pass(), nil)
		ck := (&http.Response{Header: w.Header()}).Cookies()
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/continue" || len(ck) != 1 || ck[0].Name != setupCookie || ck[0].Path != "/setup" {
			t.Fatalf("%s: the pass answered %d %v", in, w.Code, w.Header())
		}
		w = rig.do(j, http.MethodGet, "/setup/continue", nil)
		if !strings.Contains(w.Body.String(), `action="/setup/continue"`) {
			t.Errorf("%s: Start: %s", in, w.Body)
		}
		token := tokenField.FindStringSubmatch(w.Body.String())[1]
		_, _, manifest := rig.account(j, token, "acme")
		hook, _ := manifest["hook_attributes"].(map[string]any)
		callbacks, _ := manifest["callback_urls"].([]any)
		if manifest["redirect_url"] != "https://github.example.com/setup/created" || hook["url"] != "https://github.example.com/v1/events" ||
			manifest["setup_url"] != "https://github.example.com/v1/connect/return" ||
			len(callbacks) != 1 || callbacks[0] != "https://github.example.com/v1/connect/authorized" {
			t.Errorf("%s: the manifest is %v", in, manifest)
		}
		w = rig.do(jar{}, http.MethodGet, "/setup?state=x", nil)
		ck = (&http.Response{Header: w.Header()}).Cookies()
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" || len(ck) != 1 || ck[0].Name != setupPageCookie || ck[0].Path != "/setup" {
			t.Errorf("%s: a refused pass answered %d %v", in, w.Code, w.Header())
		}
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
	invalid := "This set-up link is not valid. Press Set up in Qory Apiary again."
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
		"another adapter":                      {signSetupPass(rig.server, setupPayload("na_fedcba9876543210", newNonce(), now.Add(time.Minute))), 403, "This set-up link is for another adapter. Press Set up on the GitHub adapter's page in Qory Apiary.", "adapter"},
		"expired":                              {signSetupPass(rig.server, setupPayload(testAdapterID, expiredNonce, now.Add(-time.Second))), 400, "This set-up link has expired. Press Set up in Qory Apiary again.", "expired"},
		"too far ahead":                        {signSetupPass(rig.server, setupPayload(testAdapterID, newNonce(), now.Add(16*time.Minute))), 400, "This set-up link has expired. Press Set up in Qory Apiary again.", "expired"},
	} {
		j := jar{}
		w := rig.do(j, http.MethodGet, "/setup?state="+url.QueryEscape(tc.pass), nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" || j[setupCookie] != "" {
			t.Errorf("%s: answered %d %v", name, w.Code, w.Header())
			continue
		}
		w = rig.do(j, http.MethodGet, "/setup/refused", nil)
		refusalShown(t, w, tc.status, "This set-up link cannot be used", tc.page, "https://apiary.example.com")
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
	refusalShown(t, rig.do(j, http.MethodGet, "/setup/refused", nil), 400, "This set-up link cannot be used", "This set-up link was used already. Press Set up in Qory Apiary again.", "https://apiary.example.com")
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
	if p.OrganisationSlug != "" {
		t.Errorf("the pass without organisation_slug has the slug %q", p.OrganisationSlug)
	}
	var slugDoc struct {
		Pass     string `json:"pass"`
		Tampered string `json:"tampered"`
	}
	readFixture(t, "setup-pass-organisation-slug.json", &slugDoc)
	p, expires, rf = checkSetupPass(slugDoc.Pass, at, en)
	if rf != nil || p.OrganisationSlug != "acme-org" || p.Nonce != "EBESExQVFhcYGRobHB0eHw" || !expires.Equal(at.Add(15*time.Minute)) {
		t.Errorf("the pass with organisation_slug: %+v %v %v", p, expires, rf)
	}
	if _, _, rf := checkSetupPass(slugDoc.Tampered, at, en); rf != &setupRefuseSignature {
		t.Errorf("the tampered pass with organisation_slug: %v", rf)
	}
}

// TestASetupPassMayHaveTheOrganisationSlug pins that a setup pass is taken with
// organisation_slug of the contract's shape, 1 to 40 characters, and refused, with the
// page for a link that is not valid, when the slug has another shape or type, or when
// the pass has any other member the contract does not define.
func TestASetupPassMayHaveTheOrganisationSlug(t *testing.T) {
	rig := newSetupRig(t, true)
	now := time.Now()
	for _, slug := range []string{`"a"`, `"acme-org"`, `"a--b"`, `"acme\u002dorg"`, `"` + strings.Repeat("a", 40) + `"`} {
		pass := signSetupPass(rig.server, withMember(setupPayload(testAdapterID, newNonce(), now.Add(time.Minute)), `"organisation_slug":`+slug))
		if p, _, rf := checkSetupPass(pass, now, rig.setup.creds.get()); rf != nil || p.OrganisationSlug == "" {
			t.Errorf("%s: %+v %v", slug, p, rf)
		}
	}
	invalid := "This set-up link is not valid. Press Set up in Qory Apiary again."
	for name, member := range map[string]string{
		"upper case":         `"organisation_slug":"Acme-Org"`,
		"41 characters":      `"organisation_slug":"` + strings.Repeat("a", 41) + `"`,
		"leading hyphen":     `"organisation_slug":"-acme"`,
		"trailing hyphen":    `"organisation_slug":"acme-"`,
		"line feed":          `"organisation_slug":"acme\n"`,
		"empty":              `"organisation_slug":""`,
		"space":              `"organisation_slug":"acme org"`,
		"null":               `"organisation_slug":null`,
		"number":             `"organisation_slug":5`,
		"array":              `"organisation_slug":["acme"]`,
		"unknown member":     `"organisation_name":"acme"`,
		"another member too": `"organisation_slug":"acme","extra":1`,
	} {
		pass := signSetupPass(rig.server, withMember(setupPayload(testAdapterID, newNonce(), now.Add(time.Minute)), member))
		j := jar{}
		w := rig.do(j, http.MethodGet, "/setup?state="+url.QueryEscape(pass), nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/refused" || j[setupCookie] != "" {
			t.Errorf("%s: answered %d %v", name, w.Code, w.Header())
			continue
		}
		refusalShown(t, rig.do(j, http.MethodGet, "/setup/refused", nil), 400, "This set-up link cannot be used", invalid, "https://apiary.example.com")
	}
	if n := strings.Count(rig.log.String(), `"reason":"payload"`); n != 12 {
		t.Errorf("%d refusals for the payload, want 12: %s", n, rig.log.String())
	}
}

// TestStartFillsTheAppNameFromThePass pins that Start fills the name field with qory-
// and the pass's organisation_slug, with the hint for a filled name, that the filled
// name reaches the manifest, and that the form shown again keeps the hint.
func TestStartFillsTheAppNameFromThePass(t *testing.T) {
	rig := newSetupRig(t, true)
	filled := "qory- and your Qory Apiary organisation's name, in lower case with hyphens. Up to 34 characters. You can change it here or on GitHub's page."
	pass := signSetupPass(rig.server, withMember(setupPayload(testAdapterID, newNonce(), time.Now().Add(10*time.Minute)), `"organisation_slug":"acme-org"`))
	j, token := rig.begin(pass)
	body := rig.do(j, http.MethodGet, "/setup/continue", nil).Body.String()
	if !strings.Contains(body, `id="name" name="name" type="text" value="qory-acme-org"`) || !shows(body, filled) || shows(body, "Leave it empty to name the App") {
		t.Errorf("Start with the slug acme-org: %s", body)
	}
	w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {"acme"}, "install": {"neither"}, "name": {"qory-acme-org"}})
	if body := w.Body.String(); !strings.Contains(body, `value="qory-acme-org"`) || !shows(body, filled) || strings.Contains(body, `name="manifest"`) {
		t.Errorf("Start shown again: %d %s", w.Code, body)
	}
	_, _, manifest := rig.startAs(j, token, url.Values{"organisation": {"acme"}, "install": {installPrivate}, "name": {"qory-acme-org"}})
	if manifest["name"] != "qory-acme-org" {
		t.Errorf("the manifest's name is %v", manifest["name"])
	}
}

// TestPOSTToTheSetupIsRefusedUnread pins that POST /setup answers 405 without reading
// its body, and that Start's form needs the session's cookie and its token.
func TestPOSTToTheSetupIsRefusedUnread(t *testing.T) {
	rig := newSetupRig(t, true)
	body := &countingReader{r: strings.NewReader("state=" + rig.pass() + "&_csrf_token=x")}
	r := httptest.NewRequest(http.MethodPost, "/setup", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	rig.setup.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed || !shows(w.Body.String(), "This address answers only GET requests.") || w.Header().Get("Allow") != "GET" || body.n != 0 {
		t.Errorf("POST /setup answered %d %q, read %d", w.Code, w.Body, body.n)
	}
	noSession := "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again."
	// A form without the cookie finds no session, and its body is not read.
	body = &countingReader{r: strings.NewReader("organisation=acme&token=x")}
	r = httptest.NewRequest(http.MethodPost, "/setup/continue", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	rig.setup.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !shows(w.Body.String(), noSession) || body.n != 0 {
		t.Errorf("a form without the cookie answered %d %q, read %d", w.Code, w.Body, body.n)
	}
	j, token := rig.begin(rig.pass())
	for _, form := range []url.Values{{"organisation": {"acme"}}, {"organisation": {"acme"}, "token": {strings.Repeat("A", 43)}}, {"organisation": {"acme"}, "token": {token, token}}} {
		refusalShown(t, rig.do(j, http.MethodPost, "/setup/continue", form), http.StatusBadRequest, "No set-up is under way in this browser", noSession, "https://apiary.example.com")
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

// fieldError is the start of the line Start shows under its field id when the form
// refused it.
func fieldError(id string) string {
	return `<p id="` + id + `-error" class="field-error"><svg class="ic"`
}

// TestAnUnknownAccountShowsTheFormAgain pins that an organisation GitHub has no
// account by shows the form again, with the line that says so under the field and the
// name typed in it, and the flow goes on.
func TestAnUnknownAccountShowsTheFormAgain(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	for _, org := range []string{"nobody", "not a handle", strings.Repeat("a", 40)} {
		w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {org}, "install": {installPrivate}})
		body := w.Body.String()
		if w.Code != http.StatusOK || !shows(body, "GitHub has no account by that name.") || !strings.Contains(body, fieldError("organisation")) ||
			!strings.Contains(body, `value="`+html.EscapeString(org)+`"`) || !strings.Contains(body, `aria-describedby="organisation-error" aria-invalid="true"`) ||
			!strings.Contains(body, token) || strings.Contains(body, `name="manifest"`) {
			t.Errorf("%q answered %d %s", org, w.Code, body)
		}
	}
	rig.account(j, token, "acme")
}

// TestAPersonalAccountShowsTheFormAgain pins that a user's login in the organisation
// field shows the form again, with the line that names the login as GitHub writes it,
// and posts no manifest.
func TestAPersonalAccountShowsTheFormAgain(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {"Alice"}, "install": {installPublic}})
	body := w.Body.String()
	if w.Code != http.StatusOK || !shows(body, "alice is a personal GitHub account. Leave the field empty to create the App under your account.") ||
		!strings.Contains(body, fieldError("organisation")) || strings.Contains(body, `name="manifest"`) || !strings.Contains(body, publicOn) {
		t.Errorf("a user's login answered %d %s", w.Code, body)
	}
	if n := rig.gh.looked(); n != 1 {
		t.Errorf("the account was looked up %d times", n)
	}
}

// TestAnEmptyOrganisationCreatesTheAppUnderThePerson pins that Start with no
// organisation, or only white space, looks nothing up on GitHub and posts the manifest
// to the App settings of the person signed in on GitHub; an organisation posts it to
// the organisation's.
func TestAnEmptyOrganisationCreatesTheAppUnderThePerson(t *testing.T) {
	for org, want := range map[string]string{"": "", "  ": "", " acme ": "acme", "ACME": "acme"} {
		rig := newSetupRig(t, true)
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, org)
		if wantAction := github.ManifestAction(rig.gh.srv.URL, want, stateOf(t, action)); action != wantAction {
			t.Errorf("%q: posts to %s, want %s", org, action, wantAction)
		}
		if n := rig.gh.looked(); n != map[bool]int{true: 0, false: 1}[want == ""] {
			t.Errorf("%q: looked up %d times", org, n)
		}
	}
}

// The select's two options, as Start shows them, with the private App's option
// checked and with the public App's.
const (
	privateOption = `<input class="q-pick-radio" type="radio" name="install" value="private" required checked>`
	publicOption  = `<input class="q-pick-radio" type="radio" name="install" value="public">`
	privateOff    = `<input class="q-pick-radio" type="radio" name="install" value="private" required>`
	publicOn      = `<input class="q-pick-radio" type="radio" name="install" value="public" checked>`
	chooseLine    = "Choose who can install the App."
)

// TestTheAccountFormAsksWhoCanInstallTheApp pins Start's fields in order: the
// organisation, the select of who can install the App, with the private App's option
// first and checked, and the name, before the button; and that a form shown again
// keeps the public App's option checked when it was chosen.
func TestTheAccountFormAsksWhoCanInstallTheApp(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	body := rig.do(j, http.MethodGet, "/setup/continue", nil).Body.String()
	org := strings.Index(body, `name="organisation"`)
	private := strings.Index(body, privateOption)
	public := strings.Index(body, publicOption)
	name := strings.Index(body, `name="name"`)
	button := strings.Index(body, ">Continue on GitHub</button>")
	if org < 0 || private < org || public < private || name < public || button < name || !strings.Contains(body, `<details class="q-pick">`) {
		t.Errorf("Start: %s", body)
	}
	w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {"nobody"}, "install": {installPublic}})
	body = w.Body.String()
	if w.Code != http.StatusOK || !shows(body, "GitHub has no account by that name.") || !strings.Contains(body, privateOff) || !strings.Contains(body, publicOn) {
		t.Errorf("the form again answered %d %s", w.Code, body)
	}
}

// TestTheChoiceSetsWhetherTheAppIsPublic pins that the private App's option posts a
// manifest with public false, and the public App's one with public true.
func TestTheChoiceSetsWhetherTheAppIsPublic(t *testing.T) {
	for install, want := range map[string]bool{installPrivate: false, installPublic: true} {
		rig := newSetupRig(t, true)
		j, token := rig.begin(rig.pass())
		_, _, manifest := rig.accountAs(j, token, "acme", install)
		if got, ok := manifest["public"].(bool); !ok || got != want {
			t.Errorf("%s: the manifest's public is %v", install, manifest["public"])
		}
	}
}

// TestAMissingOrUnknownChoiceShowsTheFormAgain pins that a form whose install is not
// exactly one of its two values shows the form again, with the line that says what to
// do and the private App's option selected, without looking the organisation up with
// GitHub, and that the flow goes on.
func TestAMissingOrUnknownChoiceShowsTheFormAgain(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	for _, install := range [][]string{nil, {""}, {"Private"}, {"true"}, {"private "}, {installPrivate, installPublic}, {installPublic, installPublic}} {
		form := url.Values{"token": {token}, "organisation": {"acme"}}
		if install != nil {
			form["install"] = install
		}
		w := rig.do(j, http.MethodPost, "/setup/continue", form)
		body := w.Body.String()
		if w.Code != http.StatusOK || !shows(body, chooseLine) || !strings.Contains(body, privateOption) || !strings.Contains(body, token) || strings.Contains(body, `name="manifest"`) {
			t.Errorf("%q answered %d %s", install, w.Code, body)
		}
	}
	if n := rig.gh.looked(); n != 0 {
		t.Errorf("the account was looked up on GitHub %d times", n)
	}
	rig.account(j, token, "acme")
}

// TestTheAppNameIsCheckedBeforeGitHubOpens pins the name's checks: more than 34
// characters, or a control character, shows the form again with the line under the
// name and the name as typed; 34 characters, white space at either end, and an empty
// name pass, and an empty name posts a manifest without a name.
func TestTheAppNameIsCheckedBeforeGitHubOpens(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	for name, line := range map[string]string{
		strings.Repeat("a", 35): "Shorten the name to 34 characters or fewer. GitHub refuses longer App names.",
		strings.Repeat("é", 35): "Shorten the name to 34 characters or fewer. GitHub refuses longer App names.",
		"qory-acme\nprod":       "Remove the line break or tab from the name.",
		"qory\tacme":            "Remove the line break or tab from the name.",
		"qory-acme\x7f":         "Remove the line break or tab from the name.",
		"qory-acme\u0085suffix": "Remove the line break or tab from the name.",
	} {
		w := rig.do(j, http.MethodPost, "/setup/continue", url.Values{"token": {token}, "organisation": {"acme"}, "install": {installPrivate}, "name": {name}})
		body := w.Body.String()
		if w.Code != http.StatusOK || !shows(body, line) || !strings.Contains(body, fieldError("name")) || strings.Contains(body, `name="manifest"`) ||
			!strings.Contains(body, `aria-describedby="name-error" aria-invalid="true"`) {
			t.Errorf("%q answered %d %s", name, w.Code, body)
		}
	}
	for name, want := range map[string]string{strings.Repeat("a", 34): strings.Repeat("a", 34), strings.Repeat("é", 34): strings.Repeat("é", 34), "  qory-acme ": "qory-acme"} {
		_, _, manifest := rig.startAs(j, token, url.Values{"organisation": {"acme"}, "install": {installPrivate}, "name": {name}})
		if manifest["name"] != want {
			t.Errorf("%q: the manifest's name is %v", name, manifest["name"])
		}
	}
	for _, name := range []string{"", "   "} {
		_, _, manifest := rig.startAs(j, token, url.Values{"organisation": {"acme"}, "install": {installPrivate}, "name": {name}})
		if _, ok := manifest["name"]; ok || manifest["redirect_url"] != "https://qory-github.example.com/setup/created" {
			t.Errorf("%q: the manifest is %v", name, manifest)
		}
	}
}

// TestTheDefaultAppNameHasGitHubsShape pins the default App name: qory- and the Qory
// Apiary organisation's name in lower case, each run of other characters or of hyphens
// one hyphen, no hyphen at either end, cut at 34 characters with no hyphen at the end
// after the cut; and no name for an organisation's name that is empty or has no letter
// or digit.
func TestTheDefaultAppNameHasGitHubsShape(t *testing.T) {
	for org, want := range map[string]string{
		"":                             "",
		"!!!":                          "",
		"Acme Corp":                    "qory-acme-corp",
		"acme-corp":                    "qory-acme-corp",
		"  Acme   Corp!  ":             "qory-acme-corp",
		"-Acme-":                       "qory-acme",
		"Café Ünïon 2026":              "qory-caf-n-on-2026",
		"Acme_Corp.Example":            "qory-acme-corp-example",
		"a--b":                         "qory-a-b",
		"a-!-b":                        "qory-a-b",
		"--acme---org--":               "qory-acme-org",
		"acme-org":                     "qory-acme-org",
		strings.Repeat("x", 40):        "qory-" + strings.Repeat("x", 29),
		strings.Repeat("x", 28) + " y": "qory-" + strings.Repeat("x", 28),
		// Slugs of 40 characters whose cut at 34 lands on a hyphen.
		strings.Repeat("x", 28) + "-" + strings.Repeat("y", 11):  "qory-" + strings.Repeat("x", 28),
		strings.Repeat("x", 28) + "--" + strings.Repeat("y", 10): "qory-" + strings.Repeat("x", 28),
		strings.Repeat("x", 27) + "--" + strings.Repeat("y", 11): "qory-" + strings.Repeat("x", 27) + "-y",
	} {
		got := defaultAppName(org)
		if got != want || len(got) > 34 || strings.HasSuffix(got, "-") || strings.Contains(got, "--") {
			t.Errorf("%q: %q, want %q", org, got, want)
		}
	}
}

// TestStartFillsTheDefaultAppName pins that Start fills the name field with a default
// App name, and then shows its hint, and that with no default the field is empty with
// the hint that says GitHub's page names the App.
func TestStartFillsTheDefaultAppName(t *testing.T) {
	rig := newSetupRig(t, true)
	w := httptest.NewRecorder()
	rig.setup.startPage(w, startView{Token: "t", Name: defaultAppName("Acme Corp"), Default: true})
	body := w.Body.String()
	if !strings.Contains(body, `id="name" name="name" type="text" value="qory-acme-corp"`) ||
		!shows(body, "qory- and your Qory Apiary organisation's name, in lower case with hyphens. Up to 34 characters. You can change it here or on GitHub's page.") ||
		shows(body, "Leave it empty to name the App") {
		t.Errorf("Start with a default name: %s", body)
	}
	j, _ := rig.begin(rig.pass())
	body = rig.do(j, http.MethodGet, "/setup/continue", nil).Body.String()
	if !strings.Contains(body, `id="name" name="name" type="text" value=""`) || !shows(body, "Up to 34 characters. Leave it empty to name the App on GitHub's page.") {
		t.Errorf("Start with no default name: %s", body)
	}
}

// TestTheChoiceChangesOnlyWithTheAccountForm pins that the choice is kept in the
// session by the account form alone: GitHub's redirect with install=public and
// public=true added to its query keeps the private App's end page, and a second post
// of the form with another choice gives a new state, so GitHub's redirect for the
// first manifest page is refused without an exchange.
func TestTheChoiceChangesOnlyWithTheAccountForm(t *testing.T) {
	rig := newSetupRig(t, true)
	j, token := rig.begin(rig.pass())
	_, first, _ := rig.account(j, token, "acme")
	_, second, manifest := rig.accountAs(j, token, "acme", installPublic)
	if manifest["public"] != true || stateOf(t, first) == stateOf(t, second) {
		t.Errorf("the second post: %s %v", second, manifest)
	}
	w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, first), nil)
	if w.Code != http.StatusBadRequest || len(rig.gh.converted()) != 0 {
		t.Errorf("the first page's redirect answered %d %s", w.Code, w.Body)
	}
	j, token = rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	w = rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action)+"&install=public&public=true", nil)
	if w.Code != http.StatusOK || !shows(w.Body.String(), "Only acme can install it.") {
		t.Errorf("the redirect answered %d %s", w.Code, w.Body)
	}
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
		if w.Code != http.StatusBadRequest || !shows(w.Body.String(), "This set-up link is not valid. Press Set up in Qory Apiary again.") || j[setupCookie] != "" {
			t.Errorf("%s answered %d %q", q("S"), w.Code, w.Body)
		}
	}
	// A redirect before Start is sent has no state to match.
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
	apps := rig.gh.srv.URL + "/organizations/acme/settings/apps"
	replaced := "A newer setup replaced this one. If you created an App on GitHub for it, delete it at " + apps + "."
	w := rig.do(ja, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, actionA), nil)
	refusalShown(t, w, http.StatusConflict, "A newer set-up replaced this one", replaced, "https://apiary.example.com")
	if !strings.Contains(w.Body.String(), `<a class="q-link" href="`+apps+`">`+apps+`</a>`) || ja[setupCookie] != "" {
		t.Errorf("the older flow's redirect answered %d %q", w.Code, w.Body)
	}
	if c := rig.gh.converted(); len(c) != 0 {
		t.Errorf("the older flow's code was exchanged: %v", c)
	}
	// The older flow's form, in a browser that is still at it, is refused as well.
	jc, _ := rig.begin(rig.pass())
	rig.begin(rig.pass())
	if w := rig.do(jc, http.MethodGet, "/setup/continue", nil); w.Code != http.StatusConflict || !shows(w.Body.String(), "A newer setup replaced this one. If you created an App on GitHub for it, delete it at "+rig.gh.srv.URL+"/settings/apps.") {
		t.Errorf("a replaced flow's form answered %d %q", w.Code, w.Body)
	}
	// The newest pass now is the fourth's: B's is replaced too, and goes back.
	if w := rig.do(jb, http.MethodPost, "/setup/continue", url.Values{"token": {tokenB}, "organisation": {"acme"}}); w.Code != http.StatusConflict {
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
	if w.Code != http.StatusConflict || !shows(w.Body.String(), "A newer setup replaced this one.") {
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

// TestAnAppThatCannotBeKeptSaysToDeleteIt pins the page of a setup whose code's
// exchange failed, so GitHub may have created an App: it links to the organisation's
// Apps, or to the Apps of the person signed in on GitHub when Start had no
// organisation.
func TestAnAppThatCannotBeKeptSaysToDeleteIt(t *testing.T) {
	for org, path := range map[string]string{"acme": "/organizations/acme/settings/apps", "": "/settings/apps"} {
		rig := newSetupRig(t, true)
		rig.gh.convStatus = http.StatusInternalServerError
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, org)
		w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		apps := rig.gh.srv.URL + path
		refusalShown(t, w, http.StatusBadGateway, "The GitHub App could not be stored", "GitHub may have created an App; delete it at "+apps+", then press Set up in Qory Apiary again.", "https://apiary.example.com")
		if !strings.Contains(w.Body.String(), `<a class="q-link" href="`+apps+`">`+apps+`</a>`) || j[setupCookie] != "" {
			t.Errorf("%q: a failed exchange answered %d %q", org, w.Code, w.Body)
		}
		if !strings.Contains(rig.log.String(), `"what":"conversion"`) {
			t.Errorf("the log: %s", rig.log.String())
		}
		noSetupLeak(t, rig.log.String())
	}
}

// TestGitHubsAnswerIsCheckedBeforeTheAppIsKept pins each check of GitHub's answer to
// the code's exchange: a private key that is not one, a slug, client id, client secret
// or webhook secret serve cannot keep, and what looks like an access key secret or a
// run key in the key or a secret. Each ends the flow with the page that says to delete
// the App, at its settings page, or at the account's Apps when the slug is not one
// serve takes, stores nothing in Qory Apiary, and logs an error that names no file
// of the state directory and no secret: the private key's says the key is not one, and every other
// names GitHub's answer. An owner's login that is not one, or one longer than 39
// characters, makes the page link to the session's organisation; one of 39 characters
// is the account the page links to.
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
		page, status := "GitHub created the App qory-acme, and this server could not use it. Delete it at "+rig.gh.srv.URL+"/organizations/"+owner+"/settings/apps/qory-acme, then press Set up in Qory Apiary again.", http.StatusInternalServerError
		if tc.noSlug {
			page, status = "GitHub may have created an App; delete it at "+rig.gh.srv.URL+"/organizations/acme/settings/apps, then press Set up in Qory Apiary again.", http.StatusBadGateway
		}
		refusalShown(t, w, status, "The GitHub App could not be stored", page, "https://apiary.example.com")
		if j[setupCookie] != "" {
			t.Errorf("%s: the cookie is kept", name)
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
		if len(rig.kept) != 0 || rig.setup.kept.Load() || rig.storedApp() != nil {
			t.Errorf("%s: an App not kept was handed on", name)
		}
		noSetupLeak(t, rig.log.String(), accessKey, "QRK_secret", "qrk_-a-pasted")
	}
}

// TestTheLargestPrivateKeyQoryApiaryStoresIsKept pins keep's bound on the private key
// in GitHub's answer: one of [contracts.SecretValueMaxBytes] bytes, the most Qory
// Apiary stores in a secret, is stored and read back, also with a line break at its
// end in the answer, which is not part of it, and one a byte larger is refused,
// storing nothing and logging no secret.
func TestTheLargestPrivateKeyQoryApiaryStoresIsKept(t *testing.T) {
	largest := strings.TrimSpace(appKeyPEM()) + "\n" + strings.Repeat("a", contracts.SecretValueMaxBytes-1-len(strings.TrimSpace(appKeyPEM())))
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
		stored := rig.storedApp()
		if tc.kept {
			if w.Code != http.StatusOK || stored == nil || len(stored.pem) != contracts.SecretValueMaxBytes {
				t.Errorf("%s: answered %d %q", name, w.Code, w.Body)
			} else if _, err := appOf(must(stored.plaintext())); err != nil {
				t.Errorf("%s: the App stored is not read back: %v", name, err)
			}
		}
		if !tc.kept {
			if w.Code != http.StatusInternalServerError || stored != nil || !strings.Contains(rig.log.String(), `"what":"keep","error":"GitHub's answer contains a private key larger than setup can store in Qory Apiary"`) {
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
// GitHub does not confirm is stored all the same, marked so, with the line that says
// serve sets it again at its next start.
func TestAnUnconfirmedWebhookSecretKeepsTheApp(t *testing.T) {
	rig := newSetupRig(t, true)
	rig.gh.hookStatus = http.StatusBadGateway
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	if w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil); w.Code != http.StatusOK {
		t.Fatalf("answered %d %s", w.Code, w.Body)
	}
	a := rig.storedApp()
	if a == nil || a.confirmed {
		t.Fatalf("the App stored: %+v", a)
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
	if a := rig.storedApp(); a == nil || string(a.webhookSecret) != setupHookSecret || !a.confirmed || len(rig.gh.patched()) != 0 {
		t.Errorf("the App stored: %+v", a)
	}
}

// TestASessionThatEndedFindsNone pins that every step past the pass needs a session,
// and that a cookie the setup did not set is not one.
func TestASessionThatEndedFindsNone(t *testing.T) {
	rig := newSetupRig(t, true)
	for _, target := range []string{"/setup/continue", "/setup/created?code=" + setupCode + "&state=x"} {
		w := rig.do(jar{connectCookie: randomID()}, http.MethodGet, target, nil)
		refusalShown(t, w, http.StatusBadRequest, "No set-up is under way in this browser", "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.", "https://apiary.example.com")
	}
	if w := rig.do(jar{}, http.MethodGet, "/setup/other", nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown path answered %d", w.Code)
	}
}

// must is v; it panics when err is set.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// createdAfterFailedUpload runs a setup whose first upload fails, and returns the
// browser and the answer to GitHub's redirect.
func (rig *setupRig) createdAfterFailedUpload() (jar, *httptest.ResponseRecorder) {
	rig.t.Helper()
	j, token := rig.begin(rig.pass())
	_, action, _ := rig.account(j, token, "acme")
	return j, rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(rig.t, action), nil)
}

// errUpload is an upload's failure, as Qory Apiary's 503 makes one.
var errUpload = errors.New("storing the GitHub App in Qory Apiary: Qory Apiary answered 503")

// TestAFailedUploadIsTriedAgainUntilItSucceeds pins that a first upload that fails
// sends the browser to the status page, which says the setup tries again and reloads
// itself, that every setup pass is refused meanwhile, and that the App is set up once
// an upload succeeds: the status page then says so and ends the session. The waits
// double from 2 seconds to 30, and no line or page contains a secret.
func TestAFailedUploadIsTriedAgainUntilItSucceeds(t *testing.T) {
	rig := newSetupRig(t, true)
	now := time.Now().UTC().Truncate(time.Minute)
	rig.setup.now = func() time.Time { return now }
	rig.released = make(chan struct{})
	rig.fail = func(n int) error {
		if n <= 6 {
			return errUpload
		}
		return nil
	}
	j, w := rig.createdAfterFailedUpload()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/status" || j[setupCookie] == "" {
		t.Fatalf("the redirect answered %d %v %s", w.Code, w.Header(), w.Body)
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == setupCookie && (ck.Path != "/setup" || !ck.HttpOnly || !ck.Secure) {
			t.Errorf("the session's cookie is %v, want the path /setup", ck)
		}
	}
	w = rig.do(j, http.MethodGet, "/setup/status", nil)
	body := w.Body.String()
	if w.Code != http.StatusAccepted || !strings.Contains(body, `<meta http-equiv="refresh" content="10">`) ||
		!strings.Contains(body, "<p>Storing the App in Qory Apiary failed. The GitHub adapter tries again until "+uploadTime(now.Add(time.Minute))+", and this page reloads every 10 seconds to show the result.</p>") ||
		!shows(body, "Step 3 of 3") || !shows(body, "You can close this tab. Your first Qory Apiary tab updates without a reload.") || shows(body, "There is nothing to copy.") ||
		!strings.Contains(body, `<a class="btn btn-md" href="https://apiary.example.com">Back to Qory Apiary</a>`) || w.Header().Get("Content-Security-Policy") != pageCSP("") {
		t.Errorf("the status page answered %d %s", w.Code, body)
	}
	// Another setup is refused while the tries go on.
	w = rig.do(jar{}, http.MethodGet, "/setup?state="+rig.pass(), nil)
	j2 := jar{}
	j2.take(w.Header())
	refusalShown(t, rig.do(j2, http.MethodGet, "/setup/refused", nil), http.StatusConflict, "An earlier set-up is still running",
		"Wait until the earlier setup ends, then press Set up in Qory Apiary again if the GitHub adapter's GitHub App is still not set up. An earlier setup is storing its App in Qory Apiary.", "https://apiary.example.com")
	for range 6 {
		rig.released <- struct{}{}
	}
	select {
	case a := <-rig.kept:
		if a.numericID != setupAppID || rig.storedApp() != a {
			t.Errorf("handed on %+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the App is not set up")
	}
	w = rig.do(j, http.MethodGet, "/setup/status", nil)
	if w.Code != http.StatusOK || !shows(w.Body.String(), "The GitHub App qory-acme is set up and connected to Qory Apiary: its keys are stored there. Only acme can install it.") || j[setupCookie] != "" {
		t.Errorf("the status page answered %d %s", w.Code, w.Body)
	}
	rig.mu.Lock()
	waits := slices.Clone(rig.waits)
	rig.mu.Unlock()
	if want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}; !slices.Equal(waits, want) {
		t.Errorf("waited %v, want %v", waits, want)
	}
	logged := rig.log.String()
	for _, want := range []string{
		`"level":"WARN","msg":"storing the GitHub App in Qory Apiary failed; the setup tries again","app_id":777001,"slug":"qory-acme","until":"` + contracts.FormatTime(now.Add(time.Minute)) + `","error":"storing the GitHub App in Qory Apiary: Qory Apiary answered 503"`,
		`"level":"WARN","msg":"storing the GitHub App in Qory Apiary failed again; the setup tries again","app_id":777001`,
		`"msg":"the GitHub App is set up","app_id":777001`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the log lacks %s: %s", want, logged)
		}
	}
	noSetupLeak(t, logged)
}

// TestAnUploadThatFailsForGoodSaysWhichAppToDelete pins that when every try fails
// until upload_retry_seconds have passed, the App's secrets are dropped, the line says
// which App to delete on GitHub, the status page says so with the App's settings page
// and ends the session, and a new setup may start.
func TestAnUploadThatFailsForGoodSaysWhichAppToDelete(t *testing.T) {
	rig := newSetupRig(t, true)
	now := time.Now().UTC().Truncate(time.Minute)
	rig.setup.now = func() time.Time { return now }
	// The tries end at a deadline of the real clock, upload_retry_seconds after the
	// first failure: a short one ends them here.
	rig.setup.UploadFor = 50 * time.Millisecond
	rig.fail = func(int) error { return errUpload }
	rig.setup.wait = func(ctx context.Context, _ time.Duration) error { return wait(ctx, 5*time.Millisecond) }
	j, w := rig.createdAfterFailedUpload()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/status" {
		t.Fatalf("the redirect answered %d %v", w.Code, w.Header())
	}
	const line = `"level":"ERROR","msg":"storing the GitHub App in Qory Apiary failed for good: delete the App on GitHub, then press Set up in Qory Apiary again","app_id":777001,"slug":"qory-acme","settings_url":"`
	eventually(t, "the tries end", func() bool { return strings.Contains(rig.log.String(), line) })
	if !strings.Contains(rig.log.String(), line+rig.gh.srv.URL+`/organizations/acme/settings/apps/qory-acme"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	w = rig.do(j, http.MethodGet, "/setup/status", nil)
	body := w.Body.String()
	if w.Code != http.StatusBadGateway || j[setupCookie] != "" ||
		!strings.Contains(body, "<p>Delete the GitHub App qory-acme on GitHub, then press Set up in Qory Apiary again. The GitHub adapter could not store the App in Qory Apiary by "+uploadTime(now)+".</p>") ||
		!strings.Contains(body, `<a class="btn btn-md btn-primary" href="`+rig.gh.srv.URL+`/organizations/acme/settings/apps/qory-acme">Open the App's settings on GitHub</a>`) ||
		!strings.Contains(body, `<a class="btn btn-md" href="https://apiary.example.com">Back to Qory Apiary</a>`) || strings.Contains(body, "About this step") || !shows(body, "Step 3 of 3") {
		t.Errorf("the status page answered %d %q", w.Code, w.Body)
	}
	rig.setup.mu.Lock()
	p := rig.setup.pending
	rig.setup.mu.Unlock()
	if p == nil || p.app.key != nil || p.app.pem != nil || p.app.webhookSecret != nil || p.app.clientSecret != nil || len(rig.kept) != 0 || rig.setup.kept.Load() {
		t.Errorf("the App's secrets stay in memory, or the App is set up: %+v", p)
	}
	// A new setup may start.
	if j, _ := rig.begin(rig.pass()); j[setupCookie] == "" {
		t.Error("no new setup starts")
	}
	noSetupLeak(t, rig.log.String())
}

// TestTheStatusPageNeedsTheSessionThatSetTheAppUp pins that the status page, without
// the session whose upload is tried again, is refused as a step without a session.
func TestTheStatusPageNeedsTheSessionThatSetTheAppUp(t *testing.T) {
	rig := newSetupRig(t, true)
	rig.released = make(chan struct{})
	rig.fail = func(int) error { return errUpload }
	rig.createdAfterFailedUpload()
	for _, j := range []jar{{}, {setupCookie: randomID()}} {
		w := rig.do(j, http.MethodGet, "/setup/status", nil)
		refusalShown(t, w, http.StatusBadRequest, "No set-up is under way in this browser", "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.", "https://apiary.example.com")
	}
}

// TestTheOwnerIsGitHubsAnswer pins whose App the setup keeps: the owner GitHub's answer
// to the code's exchange has, with or without an organisation on Start; the
// organisation when the answer has no owner serve takes; and, with neither, no App,
// with the page that says to delete it at the App's settings page of the person signed
// in on GitHub.
func TestTheOwnerIsGitHubsAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		org, owner, kind  string
		wantOwner, wantKd string
	}{
		"an organisation's App":            {"acme", "acme", github.AccountOrganization, "acme", github.AccountOrganization},
		"another owner in the answer":      {"acme", "other-org", github.AccountOrganization, "other-org", github.AccountOrganization},
		"no owner serve takes, with org":   {"acme", "acme/x", github.AccountOrganization, "acme", github.AccountOrganization},
		"a user's App":                     {"", "alice", github.AccountUser, "alice", github.AccountUser},
		"an organisation's App, no org":    {"", "acme", github.AccountOrganization, "acme", github.AccountOrganization},
		"no owner serve takes, no org":     {"", "acme/x", github.AccountUser, "", ""},
		"an owner of another kind, no org": {"", "acme", "Bot", "", ""},
	} {
		rig := newSetupRig(t, true)
		rig.gh.owner, rig.gh.ownerKind = tc.owner, tc.kind
		j, token := rig.begin(rig.pass())
		_, action, _ := rig.account(j, token, tc.org)
		w := rig.do(j, http.MethodGet, "/setup/created?code="+setupCode+"&state="+stateOf(t, action), nil)
		stored := rig.storedApp()
		if tc.wantOwner == "" {
			settings := rig.gh.srv.URL + "/settings/apps/" + setupSlug
			refusalShown(t, w, http.StatusInternalServerError, "The GitHub App could not be stored",
				"GitHub created the App qory-acme, and this server could not use it. Delete it at "+settings+", then press Set up in Qory Apiary again.", "https://apiary.example.com")
			if stored != nil || !strings.Contains(w.Body.String(), `<a class="q-link" href="`+settings+`">`) ||
				!strings.Contains(rig.log.String(), `"what":"keep","error":"GitHub's answer contains no owner setup can keep, and the setup has no organisation"`) || len(rig.gh.patched()) != 0 {
				t.Errorf("%s: answered %d, stored %+v, log %s", name, w.Code, stored, rig.log.String())
			}
			continue
		}
		if w.Code != http.StatusOK || stored == nil || stored.owner != tc.wantOwner || stored.ownerKind != tc.wantKd {
			t.Errorf("%s: answered %d, stored %+v", name, w.Code, stored)
		}
	}
}
