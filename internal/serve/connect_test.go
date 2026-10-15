package serve

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// connectRig is the adapter whole, as [wired] makes it, with Connect in front of the
// receiver, its passes signed by the fake Qory Apiary's server key.
type connectRig struct {
	*wired
	c       *Connect
	h       http.Handler
	signer  *accesskey.Key
	secrets []string
}

func newConnectRig(t *testing.T) *connectRig {
	t.Helper()
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	rig := &connectRig{wired: w, signer: w.apiary.server}
	rig.c = rig.connect(w.st)
	t.Cleanup(rig.c.stop)
	rig.h = rig.c.Route(w.mux)
	// Every refusal is logged, so a test reads each.
	rig.c.refusals.every = 0
	return rig
}

// connect is a Connect on st, as Run makes it.
func (rig *connectRig) connect(st *store.Store) *Connect {
	rig.adapter.Store = st
	return &Connect{
		Store: st, Adapter: rig.adapter, Pin: pinOf(rig.signer), AdapterID: testAdapterID, ClientID: testClientID, ClientSecret: []byte(clientSecret),
		PublicURL: "https://qory-github.example.com", ApiaryURL: rig.apiary.srv.URL, Log: rig.adapter.Log,
	}
}

// payload is a pass's payload as Qory Apiary writes it, its members in the
// contract's order.
func payload(adapter, nonce string, expires time.Time) string {
	return `{"version":1,"adapter_id":"` + adapter + `","nonce":"` + nonce + `","expires_at":"` + contracts.FormatTime(expires) + `"}`
}

// newNonce is 128 random bits in base64url, as a pass's nonce is.
func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// signPass is a pass of payload p signed with key.
func signPass(key *accesskey.Key, p string) string {
	sig := key.Sign(append([]byte(contracts.ConnectDomain+"\n"), p...))
	return base64.RawURLEncoding.EncodeToString([]byte(p)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// pass is a valid pass, new each call, that expires in ten minutes.
func (rig *connectRig) pass() string {
	p := signPass(rig.signer, payload(testAdapterID, newNonce(), time.Now().Add(10*time.Minute)))
	rig.secrets = append(rig.secrets, p)
	return p
}

// browser is one browser: it keeps the connect cookie as the answers set and drop it.
type browser struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (rig *connectRig) browser(t *testing.T) *browser { return &browser{t: t, h: rig.h} }

// get requests target, a path and its query, with the cookie the browser holds.
func (b *browser) get(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if b.cookie != nil {
		r.AddCookie(&http.Cookie{Name: b.cookie.Name, Value: b.cookie.Value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, r)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name != connectCookie {
			continue
		}
		if ck.MaxAge < 0 {
			b.cookie = nil
		} else {
			b.cookie = ck
		}
	}
	return rec
}

// start runs the first step with the pass and returns the state GitHub's install page
// was handed, which it sends on to the Setup URL.
func (b *browser) start(pass string) string {
	b.t.Helper()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	if rec.Code != http.StatusSeeOther {
		b.t.Fatalf("connect: %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("state")
}

// signIn runs the first two steps with the pass and returns the state of the sign-in
// GitHub was asked for.
func (b *browser) signIn(pass string) string {
	b.t.Helper()
	install := b.start(pass)
	rec := b.get("/v1/connect/return?installation_id=42&setup_action=install&state=" + install)
	if rec.Code != http.StatusSeeOther {
		b.t.Fatalf("return: %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("state")
}

// connect runs every step and returns the last answer.
func (b *browser) connect(pass string) *httptest.ResponseRecorder {
	b.t.Helper()
	state := b.signIn(pass)
	return b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + url.QueryEscape(state))
}

// refused checks that rec is the refusal rf: its status and its page, plain text,
// never to be kept.
func refused(t *testing.T, rec *httptest.ResponseRecorder, rf refusal) {
	t.Helper()
	if rec.Code != rf.status || rec.Body.String() != rf.page+"\n" || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("answered %d %q, want %d %q", rec.Code, rec.Body, rf.status, rf.page)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("the headers %v", rec.Header())
	}
}

// noLeak checks that the log holds no secret, no pass, no code and no token.
func (rig *connectRig) noLeak(t *testing.T, more ...string) {
	t.Helper()
	log := rig.log.String()
	for _, s := range append(append([]string{clientSecret, signInCode, userToken, ghToken}, rig.secrets...), more...) {
		if s != "" && strings.Contains(log, s) {
			t.Errorf("the log holds %q:\n%s", s, log)
		}
	}
}

func TestThePassIsCheckedStepByStep(t *testing.T) {
	rig := newConnectRig(t)
	now := time.Now().Truncate(time.Second)
	good := payload(testAdapterID, newNonce(), now.Add(10*time.Minute))
	b64 := base64.RawURLEncoding.EncodeToString
	other := newKey(t)
	for name, tc := range map[string]struct {
		pass string
		want *refusal
	}{
		"too long":                   {signPass(rig.signer, good) + strings.Repeat("A", contracts.ConnectPassMaxLength), &refusePass},
		"no dot":                     {b64([]byte(good)), &refusePass},
		"padding":                    {signPass(rig.signer, good) + "=", &refusePass},
		"another alphabet":           {strings.Replace(signPass(rig.signer, good), "-", "+", 1) + "+", &refusePass},
		"signed by another key":      {signPass(other, good), &refuseSignature},
		"signed without the domain":  {b64([]byte(good)) + "." + b64(rig.signer.Sign([]byte(good))), &refuseSignature},
		"not JSON, signed by others": {signPass(other, "not JSON {"), &refuseSignature},
		"not JSON":                   {signPass(rig.signer, "not JSON {"), &refusePayload},
		"version 2":                  {signPass(rig.signer, strings.Replace(good, `"version":1`, `"version":2`, 1)), &refusePayload},
		"an unknown member":          {signPass(rig.signer, strings.TrimSuffix(good, "}")+`,"org":"acme"}`), &refusePayload},
		"a member missing":           {signPass(rig.signer, `{"version":1,"adapter_id":"`+testAdapterID+`","expires_at":"`+contracts.FormatTime(now.Add(time.Minute))+`"}`), &refusePayload},
		"two documents":              {signPass(rig.signer, good+"{}"), &refusePayload},
		"a short nonce":              {signPass(rig.signer, payload(testAdapterID, "AAAA", now.Add(time.Minute))), &refusePayload},
		"a local time":               {signPass(rig.signer, strings.Replace(good, "Z\"", "+00:00\"", 1)), &refusePayload},
		"another adapter":            {signPass(rig.signer, payload("na_fedcba9876543210", newNonce(), now.Add(time.Minute))), &refuseAdapter},
		"expired":                    {signPass(rig.signer, payload(testAdapterID, newNonce(), now.Add(-time.Second))), &refuseExpired},
		"too far ahead":              {signPass(rig.signer, payload(testAdapterID, newNonce(), now.Add(16*time.Minute))), &refuseExpired},
		"expiring now":               {signPass(rig.signer, payload(testAdapterID, newNonce(), now)), nil},
		"good":                       {signPass(rig.signer, good), nil},
	} {
		_, _, rf := rig.c.checkPass(tc.pass, now)
		if rf != tc.want {
			got, want := "nil", "nil"
			if rf != nil {
				got = rf.why
			}
			if tc.want != nil {
				want = tc.want.why
			}
			t.Errorf("%s: refused as %q, want %q", name, got, want)
		}
	}
	// Each refusal is the page, and starts no session.
	b := rig.browser(t)
	refused(t, b.get("/v1/connect?state="+url.QueryEscape(signPass(other, good))), refusePass)
	refused(t, b.get("/v1/connect"), refusePass)
	refused(t, b.get("/v1/connect?state=a&state=b"), refusePass)
	if b.cookie != nil {
		t.Error("a refused pass set a cookie")
	}
	if !strings.Contains(rig.log.String(), `"reason":"the pass's signature does not verify under the pin"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	// A line break in a pass, which Go's decoder would skip, is refused before decoding.
	ok := signPass(rig.signer, good)
	for _, bad := range []string{ok[:10] + "\n" + ok[10:], ok[:10] + "\r" + ok[10:], ok + " ", ok[:10] + "%" + ok[10:]} {
		if _, _, rf := rig.c.checkPass(bad, now); rf != &refusePass {
			t.Errorf("%q: refused as %v", bad, rf)
		}
	}
	// A key after a rotation: either key of the pin verifies.
	rig.c.Pin = append(pinOf(other), rig.c.Pin...)
	if _, _, rf := rig.c.checkPass(signPass(rig.signer, good), now); rf != nil {
		t.Errorf("a pin of two keys refuses the pass: %s", rf.why)
	}
	if _, _, rf := rig.c.checkPass(signPass(other, good), now); rf != nil {
		t.Errorf("a pin of two keys refuses the pass: %s", rf.why)
	}
	rig.noLeak(t)
}

func TestAPassIsTakenOnceEvenAfterARestart(t *testing.T) {
	rig := newConnectRig(t)
	pass := rig.pass()
	if rec := rig.browser(t).get("/v1/connect?state=" + url.QueryEscape(pass)); rec.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	refused(t, rig.browser(t).get("/v1/connect?state="+url.QueryEscape(pass)), refuseUsed)
	// serve stops and starts again on the same store: the nonce is kept.
	dir := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := rig.connect(st)
	pass = rig.pass()
	if rec := (&browser{t: t, h: c.Route(rig.mux)}).get("/v1/connect?state=" + url.QueryEscape(pass)); rec.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	c.stop()
	st.Close()
	st = openStore(t, dir)
	c = rig.connect(st)
	defer c.stop()
	refused(t, (&browser{t: t, h: c.Route(rig.mux)}).get("/v1/connect?state="+url.QueryEscape(pass)), refuseUsed)
	rig.noLeak(t)
}

func TestTheSessionsCookie(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	pass := rig.pass()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	// The install page is handed a random state, which the Setup URL brings back.
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || loc.Scheme+"://"+loc.Host+loc.Path != rig.gh.srv.URL+"/apps/"+testSlug+"/installations/new" ||
		len(loc.Query()) != 1 || !idShape.MatchString(loc.Query().Get("state")) || strings.Contains(pass, loc.Query().Get("state")) || rec.Body.Len() != 0 {
		t.Fatalf("%d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("the headers %v", rec.Header())
	}
	ck := b.cookie
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/v1/connect" || ck.MaxAge <= 0 || ck.MaxAge > 600 || !idShape.MatchString(ck.Value) {
		t.Fatalf("the cookie %+v", ck)
	}
	if strings.Contains(ck.Value, pass) || strings.Contains(pass, ck.Value) {
		t.Error("the cookie carries the pass")
	}
	// The store keeps the session by its id's hash alone.
	if _, err := rig.st.Get(nsConnectSessions, ck.Value); err == nil {
		t.Error("the session is kept under its id")
	}
	if _, err := rig.st.Get(nsConnectSessions, sessionKey(ck.Value)); err != nil {
		t.Errorf("the session: %v", err)
	}
	// Under a public URL with a path, the pages and the cookie are under it.
	c := rig.connect(rig.st)
	defer c.stop()
	c.PublicURL = "https://acme.example.com/github"
	pb := &browser{t: t, h: c.Route(rig.mux)}
	if rec := pb.get("/github/v1/connect?state=" + url.QueryEscape(rig.pass())); rec.Code != http.StatusSeeOther || pb.cookie == nil || pb.cookie.Path != "/github/v1/connect" {
		t.Errorf("%d %+v", rec.Code, pb.cookie)
	}
	if rec := pb.get("/v1/connect?state=" + url.QueryEscape(rig.pass())); rec.Code != http.StatusNotFound {
		t.Errorf("the page outside the public URL's path answered %d", rec.Code)
	}
}

func TestAReturnWithoutACookieIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	refused(t, b.get("/v1/connect/return?installation_id=42&setup_action=install"), refuseNoSession)
	refused(t, b.get("/v1/connect/authorized?code="+signInCode+"&state=x"), refuseNoSession)
	// A cookie the store does not know is no session either, and is dropped.
	b.cookie = &http.Cookie{Name: connectCookie, Value: strings.Repeat("A", 43)}
	rec := b.get("/v1/connect/return?installation_id=42&setup_action=install")
	refused(t, rec, refuseNoSession)
	if b.cookie != nil {
		t.Error("the cookie is not dropped")
	}
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
}

func TestTheSetupURLsAnswerIsChecked(t *testing.T) {
	rig := newConnectRig(t)
	for target, want := range map[string]refusal{
		"/v1/connect/return?setup_action=request&state=S":                                             refuseWaits,
		"/v1/connect/return?installation_id=42&state=S":                                               refuseAnswer,
		"/v1/connect/return?installation_id=-1&setup_action=install&state=S":                          refuseAnswer,
		"/v1/connect/return?installation_id=<b>&setup_action=install&state=S":                         refuseAnswer,
		"/v1/connect/return?installation_id=42&setup_action=uninstall&state=S":                        refuseAnswer,
		"/v1/connect/return?installation_id=42&setup_action=install":                                  refuseInstall,
		"/v1/connect/return?installation_id=42&setup_action=install&state=" + strings.Repeat("A", 43): refuseInstall,
		"/v1/connect/return?installation_id=42&setup_action=install&state=S&state=S":                  refuseInstall,
	} {
		b := rig.browser(t)
		install := b.start(rig.pass())
		rec := b.get(strings.ReplaceAll(target, "state=S", "state="+install))
		refused(t, rec, want)
		if b.cookie != nil || strings.Contains(rec.Body.String(), "<b>") {
			t.Errorf("%s: the cookie %v, the page %q", target, b.cookie, rec.Body)
		}
	}
	// The sign-in GitHub is asked for: the App's client id, a new state, and the
	// callback URL under the public URL.
	b := rig.browser(t)
	install := b.start(rig.pass())
	rec := b.get("/v1/connect/return?installation_id=42&setup_action=update&state=" + install)
	u, _ := url.Parse(rec.Header().Get("Location"))
	q := u.Query()
	if rec.Code != http.StatusSeeOther || u.Scheme+"://"+u.Host != rig.gh.srv.URL || u.Path != "/login/oauth/authorize" || q.Get("client_id") != testClientID ||
		!idShape.MatchString(q.Get("state")) || q.Get("state") == install || q.Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" || len(q) != 3 {
		t.Errorf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
	// The session's installation is set once: the same one again starts the sign-in
	// again, another is refused and ends the session.
	if rec := b.get("/v1/connect/return?installation_id=42&setup_action=update&state=" + install); rec.Code != http.StatusSeeOther {
		t.Errorf("the same installation again: %d %s", rec.Code, rec.Body)
	}
	refused(t, b.get("/v1/connect/return?installation_id=43&setup_action=install&state="+install), refuseOnce)
	if b.cookie != nil {
		t.Error("the cookie is kept")
	}
}

func TestAStateThatIsNotTheSessionsIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	state := b.signIn(rig.pass())
	cookie := b.cookie
	refused(t, b.get("/v1/connect/authorized?code="+signInCode+"&state="+strings.Repeat("A", 43)), refuseState)
	if b.cookie != nil {
		t.Error("the cookie is kept")
	}
	// The session ended: its cookie and the right state are refused now.
	b.cookie = cookie
	refused(t, b.get("/v1/connect/authorized?code="+signInCode+"&state="+state), refuseNoSession)
	if ok, _ := Linked(rig.st, 42); ok || len(rig.gh.exchanges) != 0 {
		t.Errorf("linked %v, exchanged %d codes", ok, len(rig.gh.exchanges))
	}
	// A sign-in GitHub did not complete is refused.
	b = rig.browser(t)
	state = b.signIn(rig.pass())
	refused(t, b.get("/v1/connect/authorized?error=access_denied&state="+state), refuseDenied)
	// A code GitHub does not take.
	b = rig.browser(t)
	state = b.signIn(rig.pass())
	refused(t, b.get("/v1/connect/authorized?code=another-code&state="+state), refuseSignIn)
	if !strings.Contains(rig.log.String(), "GitHub answered bad_verification_code") {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t, cookie.Value, state, "another-code")
}

func TestAPersonWhoseTokenDoesNotListTheInstallationIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	rig.gh.userInstallations = []int64{7}
	refused(t, rig.browser(t).connect(rig.pass()), refuseNoAccess)
	if ok, _ := Linked(rig.st, 42); ok || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Error("linked or listed")
	}
	rig.noLeak(t)
}

func TestAPersonWhoCannotReadOneRepositoryIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	rig.gh.userRepos = []string{"acme/widgets"}
	refused(t, rig.browser(t).connect(rig.pass()), refuseCannot)
	if ok, _ := Linked(rig.st, 42); ok || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Error("linked or listed")
	}
	if !strings.Contains(rig.log.String(), `"unread":1`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t)
}

func TestASecondInstallationIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	if err := Link(rig.st, 41); err != nil {
		t.Fatal(err)
	}
	refused(t, rig.browser(t).connect(rig.pass()), refuseAnother)
	if ok, _ := Linked(rig.st, 42); ok || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Error("linked or listed")
	}
	if ok, _ := Linked(rig.st, 41); !ok {
		t.Error("the installation linked before is not")
	}
}

func TestAConnectLinksTheInstallationAndSendsItsRepositories(t *testing.T) {
	rig := newConnectRig(t)
	// GitHub announces the installation before its link: it is kept as not linked, and
	// nothing of it is listed.
	rig.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 42}})
	if _, err := rig.st.Get(nsUnlinked, "42"); err != nil || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Fatalf("the installation made on GitHub: %v, %d listings", err, len(rig.apiary.sent(routeCollections)))
	}
	b := rig.browser(t)
	rec := b.connect(rig.pass())
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != rig.apiary.srv.URL+"/integrations/na_0123456789abcdef" || rec.Body.Len() != 0 {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if b.cookie != nil {
		t.Error("the cookie is kept")
	}
	if n := 0; rig.st.Each(nsConnectSessions, func(string, []byte) error { n++; return nil }) != nil || n != 0 {
		t.Errorf("%d sessions are kept", n)
	}
	if ok, _ := Linked(rig.st, 42); !ok {
		t.Error("not linked")
	}
	if _, err := rig.st.Get(nsUnlinked, "42"); err == nil {
		t.Error("the installation is still kept unlinked")
	}
	sent := rig.apiary.sent(routeCollections)
	if len(sent) != 1 {
		t.Fatalf("%d listings sent", len(sent))
	}
	cols, _ := json.Marshal(sent[0].body["collections"])
	if !strings.Contains(string(cols), `"ref":"acme/widgets"`) || !strings.Contains(string(cols), `"ref":"acme/gadgets"`) {
		t.Errorf("sent %s", sent[0].raw)
	}
	if inst, ok, _ := reachOf(rig.st, "acme/widgets"); !ok || inst != 42 {
		t.Errorf("the repository's installation is %d", inst)
	}
	if len(rig.gh.exchanges) != 1 || rig.gh.exchanges[0].Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" {
		t.Errorf("exchanged %v", rig.gh.exchanges)
	}
	if !strings.Contains(rig.log.String(), `"msg":"connected","installation":42,"again":false,"repositories":2`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	if !strings.Contains(rig.log.String(), `"msg":"the installation is not linked to Qory Apiary, so nothing of it is listed until a person connects it","installation":42`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t)
}

func TestAReconnectListsAndFillsAgain(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42)
	setReach(rig.st, "acme/widgets", 42)
	linkCollection(rig.st, "acme/widgets")
	rig.gh.issues = []map[string]any{ghIssue(1, 0)}
	if rec := rig.browser(t).connect(rig.pass()); rec.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(rig.apiary.sent(routeCollections)) != 1 {
		t.Errorf("%d listings sent", len(rig.apiary.sent(routeCollections)))
	}
	eventually(t, "filled again", func() bool { return len(rig.apiary.sent(routeItems)) == 1 })
	if !strings.Contains(rig.log.String(), `"again":true`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t)
}

func TestTheConnectPagesBounds(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	// GET alone.
	for _, m := range []string{http.MethodPost, http.MethodHead, http.MethodPut} {
		r := httptest.NewRequest(m, "/v1/connect/authorized", nil)
		rec := httptest.NewRecorder()
		rig.h.ServeHTTP(rec, r)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
	// A query too long, or not one.
	refused(t, b.get("/v1/connect?state="+strings.Repeat("A", maxConnectQuery)), refuseQuery)
	refused(t, b.get("/v1/connect?state=%zz"), refuseQuery)
	// Nothing the request carries is in a page.
	rec := b.get("/v1/connect?state=%3Cscript%3Ealert(1)%3C/script%3E")
	if strings.Contains(rec.Body.String(), "script") {
		t.Errorf("the page reflects the query: %q", rec.Body)
	}
	// A refusal of the method or the query keeps the session, on the last step too.
	install := b.start(rig.pass())
	r := httptest.NewRequest(http.MethodPost, "/v1/connect/authorized", nil)
	r.AddCookie(&http.Cookie{Name: connectCookie, Value: b.cookie.Value})
	rec = httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r)
	refused(t, b.get("/v1/connect/authorized?state=%zz"), refuseQuery)
	if len(rec.Result().Cookies()) != 0 || b.cookie == nil {
		t.Error("a refused method or query drops the cookie")
	}
	if rec := b.get("/v1/connect/return?installation_id=42&setup_action=install&state=" + install); rec.Code != http.StatusSeeOther {
		t.Errorf("the session is gone: %d %s", rec.Code, rec.Body)
	}
	// The receiver beside it is as it was: a webhook delivery is taken, and another
	// method or path there is answered as before.
	body := `{"action":"opened","installation":{"id":42}}`
	if rec := post(rig.h, "issues", guid2, body, sign(body)); rec.Code != http.StatusAccepted {
		t.Errorf("the webhook: %d", rec.Code)
	}
	r = httptest.NewRequest(http.MethodGet, WebhookPath, nil)
	rec = httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Referrer-Policy") != "" {
		t.Errorf("GET of the webhook: %d %v", rec.Code, rec.Header())
	}
}

func TestTheClientSecretFileIsReadAsASecret(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/client-secret"
	writeFile(t, file, clientSecret+"\r\n", 0o600)
	if b, err := ReadClientSecret(file); err != nil || string(b) != clientSecret {
		t.Errorf("%q %v", b, err)
	}
	for _, content := range []string{"", "\n", "two words\n"} {
		writeFile(t, file, content, 0o600)
		if _, err := ReadClientSecret(file); err == nil || strings.Contains(err.Error(), file) {
			t.Errorf("%q: %v", content, err)
		}
	}
	writeFile(t, file, clientSecret, 0o644)
	if _, err := ReadClientSecret(file); err == nil || strings.Contains(err.Error(), file) || strings.Contains(err.Error(), clientSecret) {
		t.Errorf("a file others read: %v", err)
	}
}

func TestTheAppsConnectPathsAreServes(t *testing.T) {
	if github.ConnectReturnPath != connectPath+"/return" || github.ConnectAuthorizedPath != connectPath+"/authorized" {
		t.Errorf("setup's paths %s and %s are not serve's", github.ConnectReturnPath, github.ConnectAuthorizedPath)
	}
}

func TestAnInstallationMadeWithoutConnectIsKeptUnlinkedUntilItIsDeleted(t *testing.T) {
	rig := newConnectRig(t)
	rig.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 43}})
	if _, err := rig.st.Get(nsUnlinked, "43"); err != nil {
		t.Fatalf("not kept: %v", err)
	}
	if ok, _ := Linked(rig.st, 43); ok || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Error("linked or listed")
	}
	rig.deliver(t, "installation", guid2, map[string]any{"action": "deleted", "installation": map[string]any{"id": 43}})
	if _, err := rig.st.Get(nsUnlinked, "43"); err == nil {
		t.Error("kept after its deletion")
	}
}

func TestAConnectThatWaitsPastItsDeadlineForTheLinkIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	state := b.signIn(rig.pass())
	// Another connect holds the link.
	rig.c.linking <- struct{}{}
	r := httptest.NewRequest(http.MethodGet, "/v1/connect/authorized?code="+signInCode+"&state="+url.QueryEscape(state), nil)
	r.AddCookie(&http.Cookie{Name: connectCookie, Value: b.cookie.Value})
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r.WithContext(ctx))
	refused(t, rec, refuseBusy)
	<-rig.c.linking
	if ok, _ := Linked(rig.st, 42); ok || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Error("linked or listed")
	}
	rig.noLeak(t)
}

// TestALinkThatIsFreeIsTakenEvenPastTheDeadline checks a connect whose deadline has
// passed takes the link when no other holds it, each time, so its refusal never says
// another held it; and does not take it when another does.
func TestALinkThatIsFreeIsTakenEvenPastTheDeadline(t *testing.T) {
	rig := newConnectRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		if !rig.c.takeLink(ctx) {
			t.Fatal("a free link was not taken")
		}
		<-rig.c.linking
	}
	rig.c.linking <- struct{}{}
	if rig.c.takeLink(ctx) {
		t.Error("a link another holds was taken")
	}
	<-rig.c.linking
}

func TestNoRefillStartsAfterTheStopAndOneRunsForEachCollection(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42)
	setReach(rig.st, "acme/widgets", 42)
	linkCollection(rig.st, "acme/widgets")
	rig.gh.issues = []map[string]any{ghIssue(1, 0)}
	// A fill under way for the collection holds its turn: a second refill leaves it to
	// the first.
	done, err := rig.adapter.waitTurn(context.Background(), "acme/widgets")
	if err != nil {
		t.Fatal(err)
	}
	rig.c.refill(42)
	rig.c.refill(42)
	rig.c.fillMu.Lock()
	n := len(rig.c.refilling)
	rig.c.fillMu.Unlock()
	done()
	eventually(t, "filled", func() bool { return len(rig.apiary.sent(routeItems)) >= 1 })
	eventually(t, "refilled", func() bool {
		rig.c.fillMu.Lock()
		defer rig.c.fillMu.Unlock()
		return len(rig.c.refilling) == 0
	})
	if n != 1 || len(rig.apiary.sent(routeItems)) != 1 {
		t.Errorf("%d refills under way, %d fills sent", n, len(rig.apiary.sent(routeItems)))
	}
	rig.c.stop()
	rig.c.refill(42)
	rig.c.fillMu.Lock()
	n = len(rig.c.refilling)
	rig.c.fillMu.Unlock()
	if n != 0 || len(rig.apiary.sent(routeItems)) != 1 {
		t.Errorf("a refill started after the stop")
	}
}

func TestTheRecordOfAnInstallationNotLinkedExpiresAndGoesWithItsDeletion(t *testing.T) {
	rig := newConnectRig(t)
	rig.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 42}})
	Link(rig.st, 42)
	// A linked installation's deletion drops the record too.
	rig.deliver(t, "installation", guid2, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	if _, err := rig.st.Get(nsUnlinked, "42"); err == nil {
		t.Error("kept after the deletion of a linked installation")
	}
	// The record expires.
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(dir, store.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	keepUnlinked(st, 7)
	now = now.Add(unlinkedFor)
	if _, err := st.Get(nsUnlinked, "7"); err == nil {
		t.Error("the record does not expire")
	}
}
