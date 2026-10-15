package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// connectRig is the adapter whole, as [wired] makes it, with Connect in front of the
// receiver, its passes signed by the fake Qory Apiary's server key, and its connect
// returns by the adapter's access key.
type connectRig struct {
	*wired
	c       *Connect
	h       http.Handler
	signer  *accesskey.Key
	secrets []string

	mu    sync.Mutex
	waits []time.Duration
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

// connect is a Connect on st, as Run makes it, whose waits between a first listing's
// tries are noted and pass at once.
func (rig *connectRig) connect(st *store.Store) *Connect {
	rig.adapter.Store = st
	return &Connect{
		Store: st, Adapter: rig.adapter, Pin: pinOf(rig.signer), AdapterID: testAdapterID, Key: rig.access, ClientID: testClientID, ClientSecret: []byte(clientSecret),
		PublicURL: "https://qory-github.example.com", ApiaryURL: rig.apiary.srv.URL, Log: rig.adapter.Log,
		sleep: func(_ context.Context, d time.Duration) error {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			rig.waits = append(rig.waits, d)
			return nil
		},
	}
}

// payload is a pass's payload as Qory Apiary writes it, its members in the
// contract's order.
func payload(adapter, connection, nonce string, expires time.Time) string {
	return `{"version":1,"adapter_id":"` + adapter + `","connection_id":"` + connection + `","nonce":"` + nonce + `","expires_at":"` + contracts.FormatTime(expires) + `"}`
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

// pass is a valid pass for testConnection, new each call, that expires in ten minutes.
func (rig *connectRig) pass() string { return rig.passFor(testConnection) }

// passFor is a valid pass for connection, new each call, that expires in ten minutes.
func (rig *connectRig) passFor(connection string) string {
	p := signPass(rig.signer, payload(testAdapterID, connection, newNonce(), time.Now().Add(10*time.Minute)))
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

// start runs the first step with the pass and returns the state GitHub's sign-in was
// handed, which it sends back.
func (b *browser) start(pass string) string {
	b.t.Helper()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	if rec.Code != http.StatusSeeOther {
		b.t.Fatalf("connect: %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("state")
}

// signIn runs the first two steps with the pass and returns the answer to the second,
// which sends the browser to install the App, or shows the page that says to press
// Save.
func (b *browser) signIn(pass string) *httptest.ResponseRecorder {
	b.t.Helper()
	state := b.start(pass)
	return b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + url.QueryEscape(state))
}

// connect runs every step, GitHub's Setup URL naming the installation, and returns the
// last answer.
func (b *browser) connect(pass string, installation string) *httptest.ResponseRecorder {
	b.t.Helper()
	if rec := b.signIn(pass); rec.Code != http.StatusSeeOther && rec.Code != http.StatusOK {
		b.t.Fatalf("authorized: %d %s", rec.Code, rec.Body)
	}
	return b.get("/v1/connect/return?installation_id=" + installation + "&setup_action=install")
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
	if rec.Header().Get("Location") != "" {
		t.Errorf("a refusal sends the browser to %s", rec.Header().Get("Location"))
	}
}

// returnSchema is the contract's schema of a connect return's payload.
var returnSchema = sync.OnceValue(func() *jsonschema.Schema {
	s, err := contracts.Compile("connect-return.schema.json")
	if err != nil {
		panic(err)
	}
	return s
})

// backTo checks that rec sends the browser back to Qory Apiary, to the enrolled origin,
// for connection, with a connect return that verifies under the adapter's access key,
// as the contract writes one, and returns its payload.
func (rig *connectRig) backTo(t *testing.T, rec *httptest.ResponseRecorder, connection string) contracts.ConnectReturn {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Body.Len() != 0 || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	loc := rec.Header().Get("Location")
	prefix := rig.apiary.srv.URL + "/integrations/" + connection + "?return="
	if !strings.HasPrefix(loc, prefix) {
		t.Fatalf("sent to %s", loc)
	}
	u, _ := url.Parse(loc)
	if len(u.Query()) != 1 {
		t.Errorf("the query %v", u.Query())
	}
	ret := u.Query().Get("return")
	if len(ret) > 1024 || !passShape.MatchString(ret) || strings.Count(ret, ".") != 1 || strings.Contains(ret, "=") {
		t.Fatalf("the connect return %q", ret)
	}
	enc, sig, _ := strings.Cut(ret, ".")
	p, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !pinOf(rig.access).Verify(append([]byte(contracts.ConnectReturnDomain+"\n"), p...), sig) {
		t.Error("the connect return does not verify under the adapter's access key")
	}
	if pinOf(rig.access).Verify(append([]byte(contracts.ConnectDomain+"\n"), p...), sig) {
		t.Error("the connect return verifies as a pass")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(p))
	if err == nil {
		err = returnSchema().Validate(doc)
	}
	if err != nil {
		t.Errorf("the connect return breaks the contract: %v", err)
	}
	var r contracts.ConnectReturn
	json.Unmarshal(p, &r)
	expires, _ := time.Parse(contracts.TimeLayout, r.ExpiresAt)
	if d := time.Until(expires); d > 300*time.Second || d < 290*time.Second {
		t.Errorf("the connect return expires in %v", d)
	}
	if r.ConnectionID != connection {
		t.Errorf("the connect return %+v", r)
	}
	return r
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

// linked checks the installation's link: its connection and state, or none.
func (rig *connectRig) linked(t *testing.T, installation int64, connection, state string) {
	t.Helper()
	l, ok, err := linkOf(rig.st, installation)
	if err != nil || ok != (connection != "") || l.Connection != connection || l.State != state {
		t.Errorf("the installation %d's link %+v %v %v, want %s %s", installation, l, ok, err, connection, state)
	}
}

func TestThePassIsCheckedStepByStep(t *testing.T) {
	rig := newConnectRig(t)
	now := time.Now().Truncate(time.Second)
	good := payload(testAdapterID, testConnection, newNonce(), now.Add(10*time.Minute))
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
		"an unknown member":          {signPass(rig.signer, strings.TrimSuffix(good, "}")+`,"apiary_url":"https://elsewhere.example.com"}`), &refusePayload},
		"no connection":              {signPass(rig.signer, `{"version":1,"adapter_id":"`+testAdapterID+`","nonce":"`+newNonce()+`","expires_at":"`+contracts.FormatTime(now.Add(time.Minute))+`"}`), &refusePayload},
		"a connection not one":       {signPass(rig.signer, payload(testAdapterID, "ac_0123456789ABCDEF", newNonce(), now.Add(time.Minute))), &refusePayload},
		"an adapter's id as one":     {signPass(rig.signer, payload(testAdapterID, testAdapterID, newNonce(), now.Add(time.Minute))), &refusePayload},
		"two documents":              {signPass(rig.signer, good+"{}"), &refusePayload},
		"a short nonce":              {signPass(rig.signer, payload(testAdapterID, testConnection, "AAAA", now.Add(time.Minute))), &refusePayload},
		"a local time":               {signPass(rig.signer, strings.Replace(good, "Z\"", "+00:00\"", 1)), &refusePayload},
		"another adapter":            {signPass(rig.signer, payload("na_fedcba9876543210", testConnection, newNonce(), now.Add(time.Minute))), &refuseAdapter},
		"expired":                    {signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), now.Add(-time.Second))), &passExpired},
		"too far ahead":              {signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), now.Add(16*time.Minute))), &passExpired},
		"expiring now":               {signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), now)), nil},
		"good":                       {signPass(rig.signer, good), nil},
	} {
		p, _, rf := rig.c.checkPass(tc.pass, now)
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
		if (rf == nil || rf == &passExpired) && p.ConnectionID != testConnection {
			t.Errorf("%s: the payload %+v", name, p)
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

// TestTheContractsSignedPassVerifies checks the contract's signed pass, under its
// fixture server key, and that its tampered twin is refused.
func TestTheContractsSignedPassVerifies(t *testing.T) {
	var keys struct {
		ServerKey struct {
			PublicKey string `json:"public_key"`
		} `json:"server_key"`
	}
	readFixture(t, "keys.json", &keys)
	var doc struct {
		Pass     string `json:"pass"`
		Tampered string `json:"tampered"`
	}
	readFixture(t, "connect-pass.json", &doc)
	c := &Connect{Pin: accesskey.Pin{{Alg: "ed25519", PublicKey: keys.ServerKey.PublicKey}}, AdapterID: "na_f1xt0re000000000"}
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	p, _, rf := c.checkPass(doc.Pass, at)
	if rf != nil || p.ConnectionID != "ac_f1xt0re000000000" || p.Nonce != "AAECAwQFBgcICQoLDA0ODw" {
		t.Errorf("%+v %v", p, rf)
	}
	if _, _, rf := c.checkPass(doc.Tampered, at); rf != &refuseSignature {
		t.Errorf("the tampered pass: %v", rf)
	}
}

// TestTheConnectReturnIsTheContractsSignedFixture makes the connect return of the
// contract's fixture, under its fixture access key at its time, and checks it is the
// fixture's byte for byte, and that a refused one carries its reason, and a linked or
// cancelled one none.
func TestTheConnectReturnIsTheContractsSignedFixture(t *testing.T) {
	var keys struct {
		AccessKey struct {
			Secret string `json:"secret"`
		} `json:"access_key"`
	}
	readFixture(t, "keys.json", &keys)
	var doc struct {
		Payload string `json:"payload"`
		Token   string `json:"token"`
	}
	readFixture(t, "connect-return.json", &doc)
	access, err := accesskey.ParseSecret(keys.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 15, 12, 0, 0, 900_000_000, time.UTC)
	c := &Connect{Key: access, now: func() time.Time { return at }}
	ret, err := c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeLinked, "")
	if err != nil || ret != doc.Token {
		t.Errorf("the connect return\n%s\nwant\n%s\n%v", ret, doc.Token, err)
	}
	b, _ := fs.ReadFile(contracts.FS, "fixtures/adapter/connect-return/refused-grant-taken.json")
	var want bytes.Buffer
	json.Compact(&want, b)
	ret, _ = c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeRefused, reasonGrantTaken)
	enc, _, _ := strings.Cut(ret, ".")
	if p, _ := base64.RawURLEncoding.DecodeString(enc); string(p) != want.String() {
		t.Errorf("the refused return's payload %s, want %s", p, want.String())
	}
	ret, _ = c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeCancelled, reasonGrantTaken)
	enc, _, _ = strings.Cut(ret, ".")
	if p, _ := base64.RawURLEncoding.DecodeString(enc); strings.Contains(string(p), "reason") || !strings.Contains(string(p), `"outcome":"cancelled"`) {
		t.Errorf("the cancelled return's payload %s", p)
	}
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

// TestAPassThatArrivesLateGoesBackAsPassExpired brings a pass that verifies but has
// expired, as one does past its 15 minutes, or one that expires too far ahead: each
// goes back to Qory Apiary as a connect return, refused, pass_expired, and starts no
// session.
func TestAPassThatArrivesLateGoesBackAsPassExpired(t *testing.T) {
	rig := newConnectRig(t)
	for _, expires := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(-15 * time.Minute), time.Now().Add(16 * time.Minute)} {
		pass := signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), expires))
		b := rig.browser(t)
		rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
		r := rig.backTo(t, rec, testConnection)
		if r.Outcome != outcomeRefused || r.Reason != reasonPassExpired {
			t.Errorf("the connect return %+v", r)
		}
		if b.cookie != nil || len(rec.Result().Cookies()) != 0 {
			t.Error("a session started")
		}
	}
	if n := 0; rig.st.Each(nsConnectSessions, func(string, []byte) error { n++; return nil }) != nil || n != 0 {
		t.Errorf("%d sessions are kept", n)
	}
	if !strings.Contains(rig.log.String(), `"reason":"the pass has expired, or expires too far ahead","outcome":"refused","return_reason":"pass_expired"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
}

func TestTheSessionsCookie(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	pass := rig.pass()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	// GitHub's sign-in is asked for: the App's client id, a random state, which the
	// sign-in brings back, and the callback URL under the public URL.
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	if rec.Code != http.StatusSeeOther || loc.Scheme+"://"+loc.Host+loc.Path != rig.gh.srv.URL+"/login/oauth/authorize" || len(q) != 3 ||
		q.Get("client_id") != testClientID || !idShape.MatchString(q.Get("state")) || strings.Contains(pass, q.Get("state")) ||
		q.Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" || rec.Body.Len() != 0 {
		t.Fatalf("%d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("the headers %v", rec.Header())
	}
	// The session holds 30 minutes, whatever the pass's expiry.
	ck := b.cookie
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/v1/connect" || ck.MaxAge != 1800 || !idShape.MatchString(ck.Value) {
		t.Fatalf("the cookie %+v", ck)
	}
	if strings.Contains(ck.Value, pass) || strings.Contains(pass, ck.Value) || ck.Value == q.Get("state") {
		t.Error("the cookie carries the pass or the state")
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

func TestARequestWithoutASessionIsRefused(t *testing.T) {
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
	if ok, _ := Linked(rig.st, 42); ok || len(rig.gh.exchanges) != 0 {
		t.Error("linked or signed in")
	}
}

// TestTheSignInsAnswerIsChecked brings back a sign-in whose state is not the session's,
// one the person cancelled, one without a code and one whose code GitHub refuses: each
// goes back as a connect return and ends the session, which the right state then finds
// no more.
func TestTheSignInsAnswerIsChecked(t *testing.T) {
	rig := newConnectRig(t)
	for name, tc := range map[string]struct {
		query   string
		outcome string
		reason  string
	}{
		"another state":         {"code=" + signInCode + "&state=" + strings.Repeat("A", 43), outcomeRefused, reasonGrantNotConfirmed},
		"two states":            {"code=" + signInCode + "&state=S&state=S", outcomeRefused, reasonGrantNotConfirmed},
		"cancelled":             {"error=access_denied&state=S", outcomeCancelled, ""},
		"no code":               {"state=S", outcomeRefused, reasonGrantNotConfirmed},
		"another error":         {"error=server_error&code=" + signInCode + "&state=S", outcomeRefused, reasonGrantNotConfirmed},
		"a code GitHub refuses": {"code=another-code&state=S", outcomeRefused, reasonGrantNotConfirmed},
	} {
		b := rig.browser(t)
		state := b.start(rig.pass())
		cookie := b.cookie
		r := rig.backTo(t, b.get("/v1/connect/authorized?"+strings.ReplaceAll(tc.query, "state=S", "state="+state)), testConnection)
		if r.Outcome != tc.outcome || r.Reason != tc.reason {
			t.Errorf("%s: %+v", name, r)
		}
		if b.cookie != nil {
			t.Errorf("%s: the cookie is kept", name)
		}
		b.cookie = cookie
		refused(t, b.get("/v1/connect/authorized?code="+signInCode+"&state="+state), refuseNoSession)
	}
	if !strings.Contains(rig.log.String(), "GitHub answered bad_verification_code") {
		t.Errorf("the log: %s", rig.log.String())
	}
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
	rig.noLeak(t, "another-code")
}

// TestTheSavePageIsShownWhenTheAppIsInstalled signs in a person who reaches an
// installation of the App: the page says to press Save on GitHub's page, and links to
// GitHub's page to install the App; one who reaches none goes there at once.
func TestTheSavePageIsShownWhenTheAppIsInstalled(t *testing.T) {
	rig := newConnectRig(t)
	install := rig.gh.srv.URL + "/apps/" + testSlug + "/installations/new"
	rec := rig.browser(t).signIn(rig.pass())
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || rec.Header().Get("Location") != "" ||
		!strings.Contains(rec.Body.String(), "press Save to finish") || !strings.Contains(rec.Body.String(), `<a href="`+install+`">`) {
		t.Errorf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("the headers %v", rec.Header())
	}
	rig.gh.userInstallations = nil
	rec = rig.browser(t).signIn(rig.pass())
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != install || rec.Body.Len() != 0 {
		t.Errorf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rig.noLeak(t)
}

// TestAConnectLinksTheInstallationPendingAndListsItAtOnce connects the installation
// 42 of acme, which alice administers: it goes back to Qory Apiary linked, the link is
// pending, and the connection's first listing goes at once, sent again while Qory
// Apiary answers 403, until its 204 makes the link live.
func TestAConnectLinksTheInstallationPendingAndListsItAtOnce(t *testing.T) {
	rig := newConnectRig(t)
	// GitHub announces the installation before its link: it is kept as not linked, and
	// nothing of it is listed.
	rig.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 42}})
	if _, err := rig.st.Get(nsUnlinked, "42"); err != nil || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Fatalf("the installation made on GitHub: %v, %d listings", err, len(rig.apiary.sent(routeCollections)))
	}
	listed := make(chan struct{})
	rig.apiary.refuse = func(route string, n int) (int, string) {
		if route != routeCollections {
			return 0, ""
		}
		if n == 1 {
			<-listed
		}
		if n <= 4 {
			// The connection is not made until Qory Apiary takes the return: the first
			// listing and the part that ends it, then the next try's.
			return 403, `{"error":"forbidden"}`
		}
		return 0, ""
	}
	b := rig.browser(t)
	rec := b.connect(rig.pass(), "42")
	r := rig.backTo(t, rec, testConnection)
	if r.Outcome != outcomeLinked || r.Reason != "" {
		t.Errorf("the connect return %+v", r)
	}
	if b.cookie != nil {
		t.Error("the cookie is kept")
	}
	if n := 0; rig.st.Each(nsConnectSessions, func(string, []byte) error { n++; return nil }) != nil || n != 0 {
		t.Errorf("%d sessions are kept", n)
	}
	rig.c.tokenMu.Lock()
	if len(rig.c.tokens) != 0 {
		t.Errorf("%d tokens are held", len(rig.c.tokens))
	}
	rig.c.tokenMu.Unlock()
	rig.linked(t, 42, testConnection, linkPending)
	if _, err := rig.st.Get(nsUnlinked, "42"); err == nil {
		t.Error("the installation is still kept unlinked")
	}
	close(listed)
	eventually(t, "live", func() bool { l, _, _ := linkOf(rig.st, 42); return l.State == linkLive })
	sent := rig.apiary.sent(routeCollections)
	if len(sent) != 5 {
		t.Fatalf("%d listings sent", len(sent))
	}
	for _, s := range sent {
		if s.body["connection_id"] != testConnection {
			t.Errorf("sent %s", s.raw)
		}
	}
	cols, _ := json.Marshal(sent[4].body["collections"])
	if !strings.Contains(string(cols), `"ref":"acme/widgets"`) || !strings.Contains(string(cols), `"ref":"acme/gadgets"`) {
		t.Errorf("sent %s", sent[4].raw)
	}
	rig.mu.Lock()
	if len(rig.waits) != 2 || rig.waits[0] != 8*time.Second || rig.waits[1] != 16*time.Second {
		t.Errorf("waited %v", rig.waits)
	}
	rig.mu.Unlock()
	if inst, ok, _ := reachOf(rig.st, "acme/widgets"); !ok || inst != 42 {
		t.Errorf("the repository's installation is %d", inst)
	}
	if len(rig.gh.exchanges) != 1 || rig.gh.exchanges[0].Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" {
		t.Errorf("exchanged %v", rig.gh.exchanges)
	}
	if !strings.Contains(rig.log.String(), `"msg":"connected","installation":42,"connection":"`+testConnection+`","again":false`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	if !strings.Contains(rig.log.String(), `"msg":"the installation is not linked to Qory Apiary, so nothing of it is listed until a person connects it","installation":42`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t)
}

// TestAUserAccountsInstallationIsLinkedByItsUser connects the installation 7 on alice's
// own account.
func TestAUserAccountsInstallationIsLinkedByItsUser(t *testing.T) {
	rig := newConnectRig(t)
	// The connection is not made yet: Qory Apiary answers its listing 403.
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"forbidden"}` }
	r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "7"), testConnection)
	if r.Outcome != outcomeLinked {
		t.Errorf("the connect return %+v", r)
	}
	rig.linked(t, 7, testConnection, linkPending)
}

// TestOnlyAnAdministratorOfTheAccountLinksItsInstallation tries to link the
// installation 42 of acme as people who may not: an administrator of octo-org who
// does not reach it, or reaches it as a member alone; a membership that is pending,
// of another organisation's id, of another person's, or one the App may not read;
// another user's installation, by login or by id; and an installation the Setup URL
// names alone. Each goes back refused, and nothing is linked or listed.
func TestOnlyAnAdministratorOfTheAccountLinksItsInstallation(t *testing.T) {
	for name, tc := range map[string]struct {
		change       func(f *fakeGitHub)
		installation string
		reason       string
	}{
		"an administrator of another organisation": {func(f *fakeGitHub) {
			f.userInstallations = []ghInstallation{{id: 9, account: octoOrg, permissions: allPermissions()}}
			f.memberships = map[string]ghMembership{"octo-org": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID}}
		}, "42", reasonGrantNotConfirmed},
		"a member": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"acme": {state: "active", role: "member", org: acme.ID, person: alice.ID}, "octo-org": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID}}
		}, "42", reasonPersonNotPermitted},
		"no member": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"octo-org": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID}}
		}, "42", reasonPersonNotPermitted},
		"a pending membership": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"acme": {state: "pending", role: "admin", org: acme.ID, person: alice.ID}}
		}, "42", reasonPersonNotPermitted},
		"another organisation's membership": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"acme": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID}}
		}, "42", reasonPersonNotPermitted},
		"another person's membership": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"acme": {state: "active", role: "admin", org: acme.ID, person: 1002}}
		}, "42", reasonPersonNotPermitted},
		"a membership the App may not read": {func(f *fakeGitHub) {
			f.memberships = map[string]ghMembership{"acme": {refused: true}}
		}, "42", reasonPersonNotPermitted},
		"another user's installation": {func(f *fakeGitHub) {
			f.userInstallations = []ghInstallation{{id: 42, account: github.Account{Login: "bob", ID: 1002, Type: "User"}, permissions: allPermissions()}}
		}, "42", reasonPersonNotPermitted},
		"another user's id under the person's login": {func(f *fakeGitHub) {
			f.userInstallations = []ghInstallation{{id: 42, account: github.Account{Login: "alice", ID: 1002, Type: "User"}, permissions: allPermissions()}}
		}, "42", reasonPersonNotPermitted},
		"another account's type": {func(f *fakeGitHub) {
			f.userInstallations = []ghInstallation{{id: 42, account: github.Account{Login: "acme", ID: 500, Type: "Enterprise"}, permissions: allPermissions()}}
		}, "42", reasonPersonNotPermitted},
		"an installation the URL names alone": {func(*fakeGitHub) {}, "99", reasonGrantNotConfirmed},
	} {
		rig := newConnectRig(t)
		tc.change(rig.gh)
		r := rig.backTo(t, rig.browser(t).connect(rig.pass(), tc.installation), testConnection)
		if r.Outcome != outcomeRefused || r.Reason != tc.reason {
			t.Errorf("%s: %+v", name, r)
		}
		for _, id := range []int64{42, 9, 99} {
			if ok, _ := Linked(rig.st, id); ok {
				t.Errorf("%s: %d is linked", name, id)
			}
		}
		rig.c.stop()
		if n := len(rig.apiary.sent(routeCollections)); n != 0 {
			t.Errorf("%s: %d listings", name, n)
		}
		rig.noLeak(t)
	}
}

// TestAnInstallationSuspendedOrWithoutAPermissionIsRefused connects an installation
// GitHub has suspended, and ones that lack a permission the adapter needs.
func TestAnInstallationSuspendedOrWithoutAPermissionIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		in     ghInstallation
		reason string
	}{
		"suspended":         {ghInstallation{id: 42, account: acme, suspended: true, permissions: allPermissions()}, reasonGrantSuspended},
		"issues read":       {ghInstallation{id: 42, account: acme, permissions: map[string]string{"metadata": "read", "issues": "read", "members": "read"}}, reasonPermissionMissing},
		"no metadata":       {ghInstallation{id: 42, account: acme, permissions: map[string]string{"issues": "write", "members": "read"}}, reasonPermissionMissing},
		"no members":        {ghInstallation{id: 42, account: acme, permissions: map[string]string{"metadata": "read", "issues": "write"}}, reasonPermissionMissing},
		"no permissions":    {ghInstallation{id: 42, account: acme}, reasonPermissionMissing},
		"a user's, members": {ghInstallation{id: 42, account: alice, permissions: map[string]string{"metadata": "read", "issues": "admin"}}, ""},
	} {
		rig := newConnectRig(t)
		rig.gh.userInstallations = []ghInstallation{tc.in}
		r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "42"), testConnection)
		want := outcomeRefused
		if tc.reason == "" {
			want = outcomeLinked
		}
		if r.Outcome != want || r.Reason != tc.reason {
			t.Errorf("%s: %+v", name, r)
		}
		if ok, _ := Linked(rig.st, 42); ok != (tc.reason == "") {
			t.Errorf("%s: linked %v", name, ok)
		}
	}
}

// TestGitHubOutOfReachGoesBackAsSourceUnavailable has GitHub fail the sign-in's
// exchange, and the listing of the person's installations at each step.
func TestGitHubOutOfReachGoesBackAsSourceUnavailable(t *testing.T) {
	rig := newConnectRig(t)
	rig.gh.userDown = true
	r := rig.backTo(t, rig.browser(t).signIn(rig.pass()), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonSourceUnavailable {
		t.Errorf("%+v", r)
	}
	rig.gh.userDown = false
	b := rig.browser(t)
	b.signIn(rig.pass())
	rig.gh.userDown = true
	r = rig.backTo(t, b.get("/v1/connect/return?installation_id=42&setup_action=install"), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonSourceUnavailable {
		t.Errorf("%+v", r)
	}
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
	rig.noLeak(t)
}

// TestTheSetupURLsAnswerIsChecked brings back the Setup URL without an installation,
// with one that is not GitHub's, for an installation that waits for an owner's
// approval, and before the sign-in: each goes back refused, and nothing is linked. A
// state the Setup URL carries, or not, changes nothing.
func TestTheSetupURLsAnswerIsChecked(t *testing.T) {
	for query, want := range map[string]contracts.ConnectReturn{
		"setup_action=request":                                       {Outcome: outcomeRefused, Reason: reasonPersonNotPermitted},
		"installation_id=42":                                         {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=-1&setup_action=install":                    {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=<b>&setup_action=install":                   {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&setup_action=uninstall":                  {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&installation_id=42&setup_action=install": {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"error=access_denied":                                        {Outcome: outcomeCancelled},
		"installation_id=42&setup_action=update&state=x":             {Outcome: outcomeLinked},
	} {
		rig := newConnectRig(t)
		b := rig.browser(t)
		b.signIn(rig.pass())
		rec := b.get("/v1/connect/return?" + query)
		r := rig.backTo(t, rec, testConnection)
		if r.Outcome != want.Outcome || r.Reason != want.Reason {
			t.Errorf("%s: %+v", query, r)
		}
		if b.cookie != nil || strings.Contains(rec.Header().Get("Location"), "<b>") {
			t.Errorf("%s: the cookie %v, sent to %s", query, b.cookie, rec.Header().Get("Location"))
		}
		if ok, _ := Linked(rig.st, 42); ok != (want.Outcome == outcomeLinked) {
			t.Errorf("%s: linked %v", query, ok)
		}
	}
	// The Setup URL before the sign-in: the session holds no token.
	rig := newConnectRig(t)
	b := rig.browser(t)
	b.start(rig.pass())
	r := rig.backTo(t, b.get("/v1/connect/return?installation_id=42&setup_action=install"), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed {
		t.Errorf("before the sign-in: %+v", r)
	}
	// The token is held in memory alone: a restart between the steps finds none.
	b = rig.browser(t)
	b.signIn(rig.pass())
	rig.c.tokenMu.Lock()
	clear(rig.c.tokens)
	rig.c.tokenMu.Unlock()
	r = rig.backTo(t, b.get("/v1/connect/return?installation_id=42&setup_action=install"), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed {
		t.Errorf("without the token: %+v", r)
	}
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
	for _, s := range []string{userToken} {
		rig.st.Each(nsConnectSessions, func(_ string, v []byte) error {
			if strings.Contains(string(v), s) {
				t.Error("the store holds the person's token")
			}
			return nil
		})
	}
}

// TestALiveLinkIsNotTakenByAnotherConnection connects an installation linked to
// another connection that is live: refused, grant_taken, and the link stays.
func TestALiveLinkIsNotTakenByAnotherConnection(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42, otherConnection, linkLive)
	r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "42"), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonGrantTaken {
		t.Errorf("%+v", r)
	}
	rig.linked(t, 42, otherConnection, linkLive)
	if n := len(rig.apiary.sent(routeCollections)); n != 0 {
		t.Errorf("%d listings", n)
	}
}

// TestAPendingLinkIsListedBeforeItIsReplaced connects an installation linked to another
// connection that is pending: a listing for that connection goes first. Answered 204,
// the connection was made meanwhile, the link is live, and the connect is refused,
// grant_taken; 403, the link is replaced by the new connection, pending; 409
// connection_ended, likewise; 409 connection_suspended, refused, grant_taken; any other
// answer, refused, source_unavailable.
func TestAPendingLinkIsListedBeforeItIsReplaced(t *testing.T) {
	for name, tc := range map[string]struct {
		status     int
		body       string
		connection string
		state      string
		reason     string
	}{
		"204":                  {0, "", otherConnection, linkLive, reasonGrantTaken},
		"403":                  {403, `{"error":"forbidden"}`, testConnection, linkPending, ""},
		"connection_ended":     {409, `{"error":"connection_ended"}`, testConnection, linkPending, ""},
		"connection_suspended": {409, `{"error":"connection_suspended"}`, otherConnection, linkPending, reasonGrantTaken},
		"500":                  {500, `oops`, otherConnection, linkPending, reasonSourceUnavailable},
	} {
		rig := newConnectRig(t)
		Link(rig.st, 42, otherConnection, linkPending)
		listing := make(chan struct{})
		rig.apiary.refuse = func(route string, n int) (int, string) {
			if route != routeCollections {
				return 0, ""
			}
			if n == 3 {
				// The new connection's first listing waits until the test has looked.
				<-listing
			}
			if n <= 2 {
				return tc.status, tc.body
			}
			return 403, `{"error":"forbidden"}`
		}
		r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "42"), testConnection)
		want := outcomeRefused
		if tc.reason == "" {
			want = outcomeLinked
		}
		if r.Outcome != want || r.Reason != tc.reason {
			t.Errorf("%s: %+v", name, r)
		}
		rig.linked(t, 42, tc.connection, tc.state)
		sent := rig.apiary.sent(routeCollections)
		if len(sent) == 0 || sent[0].body["connection_id"] != otherConnection {
			t.Errorf("%s: the first listing %v", name, sent)
		}
		close(listing)
		rig.c.stop()
	}
}

// TestTheReturnGoesToTheEnrolledOriginAlone connects with requests that name another
// origin, in the query, in the headers and as the host, and checks every connect
// return goes to the origin the adapter enrolled with.
func TestTheReturnGoesToTheEnrolledOriginAlone(t *testing.T) {
	rig := newConnectRig(t)
	elsewhere := "https://elsewhere.example.com"
	b := rig.browser(t)
	get := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, elsewhere+target+"&apiary_url="+url.QueryEscape(elsewhere)+"&return_to="+url.QueryEscape(elsewhere), nil)
		r.Header.Set("Origin", elsewhere)
		r.Header.Set("Referer", elsewhere+"/integrations/x")
		r.Header.Set("X-Forwarded-Host", "elsewhere.example.com")
		if b.cookie != nil {
			r.AddCookie(&http.Cookie{Name: b.cookie.Name, Value: b.cookie.Value})
		}
		rec := httptest.NewRecorder()
		rig.h.ServeHTTP(rec, r)
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == connectCookie && ck.MaxAge > 0 {
				b.cookie = ck
			}
		}
		return rec
	}
	rec := get("/v1/connect?state=" + url.QueryEscape(rig.pass()))
	u, _ := url.Parse(rec.Header().Get("Location"))
	get("/v1/connect/authorized?code=" + signInCode + "&state=" + u.Query().Get("state"))
	rig.backTo(t, get("/v1/connect/return?installation_id=42&setup_action=install"), testConnection)
	// A pass that verifies late goes back to the enrolled origin too.
	late := signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), time.Now().Add(-time.Hour)))
	rig.backTo(t, get("/v1/connect?state="+url.QueryEscape(late)), testConnection)
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
	state := b.start(rig.pass())
	r := httptest.NewRequest(http.MethodPost, "/v1/connect/return", nil)
	r.AddCookie(&http.Cookie{Name: connectCookie, Value: b.cookie.Value})
	rec = httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r)
	refused(t, b.get("/v1/connect/return?state=%zz"), refuseQuery)
	if len(rec.Result().Cookies()) != 0 || b.cookie == nil {
		t.Error("a refused method or query drops the cookie")
	}
	if rec := b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + state); rec.Code != http.StatusOK {
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

func TestAConnectThatWaitsPastItsDeadlineForTheLinkGoesBack(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	b.signIn(rig.pass())
	// Another connect holds the link.
	rig.c.linking <- struct{}{}
	r := httptest.NewRequest(http.MethodGet, "/v1/connect/return?installation_id=42&setup_action=install", nil)
	r.AddCookie(&http.Cookie{Name: connectCookie, Value: b.cookie.Value})
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r.WithContext(ctx))
	if ret := rig.backTo(t, rec, testConnection); ret.Outcome != outcomeRefused || ret.Reason != reasonSourceUnavailable {
		t.Errorf("%+v", ret)
	}
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

// TestAReconnectOfALiveLinkListsAndFillsAgain connects an installation linked to the
// same connection, live, with a pass issued before it was made: the link stays, and
// the installation is listed and its linked collections filled again.
func TestAReconnectOfALiveLinkListsAndFillsAgain(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42, testConnection, linkLive)
	setReach(rig.st, "acme/widgets", 42)
	linkCollection(rig.st, "acme/widgets")
	rig.gh.issues = []map[string]any{ghIssue(1, 0)}
	if r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "42"), testConnection); r.Outcome != outcomeLinked {
		t.Errorf("%+v", r)
	}
	eventually(t, "listed", func() bool { return len(rig.apiary.sent(routeCollections)) == 1 })
	eventually(t, "filled again", func() bool { return len(rig.apiary.sent(routeItems)) == 1 })
	rig.linked(t, 42, testConnection, linkLive)
	if !strings.Contains(rig.log.String(), `"again":true`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	rig.noLeak(t)
}

func TestNoRefillStartsAfterTheStopAndOneRunsForEachCollection(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42, testConnection, linkLive)
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
	rig.c.listSoon(42, testConnection, true)
	rig.c.fillMu.Lock()
	n = len(rig.c.refilling)
	rig.c.fillMu.Unlock()
	if n != 0 || len(rig.apiary.sent(routeItems)) != 1 || len(rig.apiary.sent(routeCollections)) != 0 {
		t.Errorf("a refill or a listing started after the stop")
	}
}

func TestTheRecordOfAnInstallationNotLinkedExpiresAndGoesWithItsDeletion(t *testing.T) {
	rig := newConnectRig(t)
	rig.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 42}})
	Link(rig.st, 42, testConnection, linkLive)
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
