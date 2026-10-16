package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	c      *Connect
	h      http.Handler
	signer *accesskey.Key
	// secrets are the passes the rig made and the connect returns it read, which no
	// log may hold.
	secrets []string

	mu    sync.Mutex
	waits []time.Duration
	// budget is how much of the waits pass at once; a wait past it holds until its
	// context is done, as time that has not passed yet.
	budget time.Duration
	// clock, when set, is the adapter's and the Connect's clock, which each wait that
	// passes moves on.
	clock *pullClock
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
// tries are noted and pass at once, up to the rig's budget, two minutes unless a test
// sets it: the waits past it hold until the Connect stops.
func (rig *connectRig) connect(st *store.Store) *Connect {
	rig.adapter.Store = st
	return &Connect{
		Store: st, Adapter: rig.adapter, Pin: pinOf(rig.signer), AdapterID: testAdapterID, Key: rig.access, ClientID: testClientID, ClientSecret: []byte(clientSecret),
		PublicURL: "https://qory-github.example.com", ApiaryURL: rig.apiary.srv.URL, Log: rig.adapter.Log,
		sleep: func(ctx context.Context, d time.Duration) error {
			rig.mu.Lock()
			rig.waits = append(rig.waits, d)
			var sum time.Duration
			for _, w := range rig.waits {
				sum += w
			}
			budget, clock := rig.budget, rig.clock
			rig.mu.Unlock()
			if budget == 0 {
				budget = 2 * time.Minute
			}
			if sum > budget {
				<-ctx.Done()
				return ctx.Err()
			}
			if clock != nil {
				return clock.sleep(ctx, d)
			}
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
	return rig.passAt(connection, time.Now().Add(10*time.Minute))
}

// passAt is a valid pass for connection, new each call, that expires at expires.
func (rig *connectRig) passAt(connection string, expires time.Time) string {
	p := signPass(rig.signer, payload(testAdapterID, connection, newNonce(), expires))
	rig.secrets = append(rig.secrets, p)
	return p
}

// browser is one browser: it keeps the connect cookie, and the page's, as the answers
// set and drop them.
type browser struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	page   *http.Cookie
}

func (rig *connectRig) browser(t *testing.T) *browser { return &browser{t: t, h: rig.h} }

// get requests target, a path and its query, with the cookie the browser holds.
func (b *browser) get(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, ck := range []*http.Cookie{b.cookie, b.page} {
		if ck != nil {
			r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, r)
	for _, ck := range rec.Result().Cookies() {
		kept := &b.cookie
		switch ck.Name {
		case connectCookie:
		case pageCookie:
			kept = &b.page
		default:
			continue
		}
		if ck.MaxAge < 0 {
			*kept = nil
		} else {
			*kept = ck
		}
	}
	return rec
}

// passRefused brings target, a request that may carry a pass, which must answer 303
// to the page's address, with no part of the query in it, and the page's cookie, then
// follows it, which must show the page rf.
func (b *browser) passRefused(target string, rf refusal) {
	b.t.Helper()
	rec := b.get(target)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || loc != "/v1/connect/refused" || rec.Body.Len() != 0 || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Cache-Control") != "no-store" {
		b.t.Errorf("%d %v %q, want 303 to the page", rec.Code, rec.Header(), rec.Body)
	}
	if _, query, _ := strings.Cut(target, "?"); query != "" {
		for _, part := range strings.FieldsFunc(query, func(r rune) bool { return r == '=' || r == '&' || r == '.' }) {
			if len(part) >= 8 && strings.Contains(loc, part) {
				b.t.Errorf("the page's address %s holds %q", loc, part)
			}
		}
	}
	if b.page == nil || b.page.Value == "" || !b.page.HttpOnly || !b.page.Secure || b.page.MaxAge <= 0 || b.page.MaxAge > 60 || strings.Contains(target, b.page.Value+".") {
		b.t.Errorf("the page's cookie %+v", b.page)
	}
	refused(b.t, b.get("/v1/connect/refused"), rf)
	if b.page != nil {
		b.t.Error("the page's cookie is kept")
	}
}

// start runs the first step with the pass, which answers 303 to the continue address,
// and that one, and returns the state GitHub's sign-in was handed, which it sends back.
func (b *browser) start(pass string) string {
	b.t.Helper()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/v1/connect/continue" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		b.t.Fatalf("connect: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rec = b.get("/v1/connect/continue")
	if rec.Code != http.StatusSeeOther {
		b.t.Fatalf("continue: %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("state")
}

// authorize follows rec, a 303 to GitHub's sign-in, as GitHub does for a person who
// authorised the App: back to the callback URL, with a code and the state.
func (b *browser) authorize(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	b.t.Helper()
	u, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || u.Path != "/login/oauth/authorize" {
		b.t.Fatalf("not sent to GitHub's sign-in: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	return b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + url.QueryEscape(u.Query().Get("state")))
}

// bindTarget brings GitHub's Setup URL naming the installation, which must send the
// browser to GitHub's sign-in again, and returns the callback GitHub sends it back to.
func (b *browser) bindTarget(installation string) string {
	b.t.Helper()
	rec := b.get("/v1/connect/return?installation_id=" + installation + "&setup_action=install")
	u, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || u.Path != "/login/oauth/authorize" {
		b.t.Fatalf("not sent to GitHub's sign-in: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	return "/v1/connect/authorized?code=" + signInCode + "&state=" + url.QueryEscape(u.Query().Get("state"))
}

// finish brings GitHub's Setup URL with query, and, when it sends the browser to
// GitHub's sign-in again, follows it, and returns the last answer.
func (b *browser) finish(query string) *httptest.ResponseRecorder {
	b.t.Helper()
	rec := b.get("/v1/connect/return?" + query)
	if u, _ := url.Parse(rec.Header().Get("Location")); rec.Code == http.StatusSeeOther && u.Path == "/login/oauth/authorize" {
		return b.authorize(rec)
	}
	return rec
}

// signIn runs the first two steps with the pass and returns the answer to the second,
// which sends the browser to install the App, or shows the page that says to press
// Save.
func (b *browser) signIn(pass string) *httptest.ResponseRecorder {
	b.t.Helper()
	state := b.start(pass)
	return b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + url.QueryEscape(state))
}

// connect runs every step, GitHub's Setup URL naming the installation, then the second
// sign-in, and returns the last answer.
func (b *browser) connect(pass string, installation string) *httptest.ResponseRecorder {
	b.t.Helper()
	if rec := b.signIn(pass); rec.Code != http.StatusSeeOther && rec.Code != http.StatusOK {
		b.t.Fatalf("authorized: %d %s", rec.Code, rec.Body)
	}
	return b.finish("installation_id=" + installation + "&setup_action=install")
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
	rig.secrets = append(rig.secrets, ret)
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

// noLeak checks that the log holds no secret, no pass, no connect return, no code and
// no token.
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
	b.passRefused("/v1/connect?state="+url.QueryEscape(signPass(other, good)), refusePass)
	b.passRefused("/v1/connect", refusePass)
	b.passRefused("/v1/connect?state=a&state=b", refusePass)
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
	ret, err := c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeLinked, "", at.Add(returnFor))
	if err != nil || ret != doc.Token {
		t.Errorf("the connect return\n%s\nwant\n%s\n%v", ret, doc.Token, err)
	}
	b, _ := fs.ReadFile(contracts.FS, "fixtures/adapter/connect-return/refused-grant-taken.json")
	var want bytes.Buffer
	json.Compact(&want, b)
	ret, _ = c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeRefused, reasonGrantTaken, at.Add(returnFor))
	enc, _, _ := strings.Cut(ret, ".")
	if p, _ := base64.RawURLEncoding.DecodeString(enc); string(p) != want.String() {
		t.Errorf("the refused return's payload %s, want %s", p, want.String())
	}
	ret, _ = c.connectReturn("ac_f1xt0re000000000", "AAECAwQFBgcICQoLDA0ODw", outcomeCancelled, reasonGrantTaken, at.Add(returnFor))
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
	rig.browser(t).passRefused("/v1/connect?state="+url.QueryEscape(pass), refuseUsed)
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
	(&browser{t: t, h: c.Route(rig.mux)}).passRefused("/v1/connect?state="+url.QueryEscape(pass), refuseUsed)
	rig.noLeak(t)
}

// TestAPassThatArrivesLateGoesBackAsPassExpired brings a pass that verifies but has
// expired, as one does past its 15 minutes, or one that expires too far ahead: each
// goes back to Qory Apiary as a connect return, refused, pass_expired, and starts no
// session. Its expiry is checked before its nonce, which is never kept, so the same
// pass brought again goes back the same way, never to the page of a pass used.
func TestAPassThatArrivesLateGoesBackAsPassExpired(t *testing.T) {
	rig := newConnectRig(t)
	for _, expires := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(-15 * time.Minute), time.Now().Add(16 * time.Minute)} {
		pass := signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), expires))
		rig.secrets = append(rig.secrets, pass)
		for range 2 {
			b := rig.browser(t)
			rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
			r := rig.backTo(t, rec, testConnection)
			if r.Outcome != outcomeRefused || r.Reason != reasonPassExpired {
				t.Errorf("the connect return %+v", r)
			}
			if b.cookie != nil || len(rec.Result().Cookies()) != 0 {
				t.Error("a session started")
			}
			payload, sig, _ := strings.Cut(pass, ".")
			if loc := rec.Header().Get("Location"); strings.Contains(loc, payload) || strings.Contains(loc, sig) {
				t.Errorf("the return's address holds the pass: %s", loc)
			}
		}
	}
	for ns, what := range map[string]string{nsConnectSessions: "sessions", nsConnectNonces: "nonces"} {
		if n := 0; rig.st.Each(ns, func(string, []byte) error { n++; return nil }) != nil || n != 0 {
			t.Errorf("%d %s are kept", n, what)
		}
	}
	rig.noLeak(t)
	if !strings.Contains(rig.log.String(), `"reason":"the pass has expired, or expires too far ahead","outcome":"refused","return_reason":"pass_expired"`) {
		t.Errorf("the log: %s", rig.log.String())
	}
}

func TestTheSessionsCookie(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	pass := rig.pass()
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	// The pass leaves the address: the browser goes to the continue address.
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/v1/connect/continue" || rec.Body.Len() != 0 || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("%d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	rec = b.get("/v1/connect/continue")
	// GitHub's sign-in is asked for: the App's client id, a random state of 256 bits,
	// which the sign-in brings back, and the callback URL under the public URL.
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
	if p, sig, _ := strings.Cut(pass, "."); strings.Contains(rec.Header().Get("Location"), p) || strings.Contains(rec.Header().Get("Location"), sig) {
		t.Error("GitHub is sent the pass")
	}
	// The session holds 900 seconds, the contract's most, whatever the pass's expiry.
	ck := b.cookie
	if ck == nil || ck.Name != "__Secure-qory_github_connect" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/v1/connect" || ck.MaxAge != 900 || !idShape.MatchString(ck.Value) {
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
	// A sign-in is taken once: the same answer brought again, its state dropped, goes
	// back refused, and its code is not exchanged again.
	b := rig.browser(t)
	state := b.start(rig.pass())
	exchanges := len(rig.gh.exchanges)
	if rec := b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + state); rec.Code != http.StatusOK {
		t.Fatalf("the sign-in: %d %s", rec.Code, rec.Body)
	}
	r := rig.backTo(t, b.get("/v1/connect/authorized?code="+signInCode+"&state="+state), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed || len(rig.gh.exchanges) != exchanges+1 {
		t.Errorf("the sign-in brought again: %+v, %d exchanges", r, len(rig.gh.exchanges)-exchanges)
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
		!strings.Contains(rec.Body.String(), "press Save to finish") || !strings.Contains(rec.Body.String(), `<a href="`+install+`?state=`) {
		t.Errorf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("the headers %v", rec.Header())
	}
	rig.gh.userInstallations = nil
	rec = rig.browser(t).signIn(rig.pass())
	// GitHub's page to install the App carries a state of 256 bits, which is not the
	// pass, and which GitHub sends back to the Setup URL.
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || loc.Scheme+"://"+loc.Host+loc.Path != install || len(loc.Query()) != 1 || !idShape.MatchString(loc.Query().Get("state")) || rec.Body.Len() != 0 {
		t.Errorf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rig.noLeak(t)
}

// TestAConnectLinksTheInstallationPendingAndListsItAtOnce connects the installation
// 42 of acme, which alice administers: it goes back to Qory Apiary linked, the link is
// pending, and the connection's first listing goes at once, sent again while Qory
// Apiary answers 403, after a second and then two, the same listing each time, read
// from GitHub once, until its 204 makes the link live.
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
		if n <= 2 {
			// The connection is not made until Qory Apiary takes the return: the first
			// listing's one part, then the next try's, which sends it again.
			return 403, `{"error":"connection_unknown"}`
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
	rig.linked(t, 42, testConnection, linkPending)
	if _, err := rig.st.Get(nsUnlinked, "42"); err == nil {
		t.Error("the installation is still kept unlinked")
	}
	close(listed)
	eventually(t, "live", func() bool { l, _, _ := linkOf(rig.st, 42); return l.State == linkLive })
	sent := rig.apiary.sent(routeCollections)
	if len(sent) != 3 {
		t.Fatalf("%d listings sent", len(sent))
	}
	for _, s := range sent {
		if s.body["connection_id"] != testConnection || !reflect.DeepEqual(s.body["listing"], sent[0].body["listing"]) || !reflect.DeepEqual(s.body["collections"], sent[0].body["collections"]) {
			t.Errorf("sent %s, then %s", sent[0].raw, s.raw)
		}
	}
	if l := sent[0].body["listing"].(map[string]any); l["part"] != 1.0 || l["complete"] != true {
		t.Errorf("sent %s", sent[0].raw)
	}
	cols, _ := json.Marshal(sent[2].body["collections"])
	if !strings.Contains(string(cols), `"ref":"acme/widgets"`) || !strings.Contains(string(cols), `"ref":"acme/gadgets"`) {
		t.Errorf("sent %s", sent[2].raw)
	}
	if n := rig.gh.listings(); n != 1 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
	eventually(t, "the parts kept forgotten", func() bool { return rig.adapter.keptFirsts() == 0 })
	rig.mu.Lock()
	if len(rig.waits) != 2 || rig.waits[0] != time.Second || rig.waits[1] != 2*time.Second {
		t.Errorf("waited %v", rig.waits)
	}
	rig.mu.Unlock()
	if inst, ok, _ := reachOf(rig.st, "acme/widgets"); !ok || inst != 42 {
		t.Errorf("the repository's installation is %d", inst)
	}
	// Two sign-ins: the first before the installation, the second that binds it.
	if len(rig.gh.exchanges) != 2 || rig.gh.exchanges[0].Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" || rig.gh.exchanges[1].Get("redirect_uri") != "https://qory-github.example.com/v1/connect/authorized" {
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
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
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
// another user's installation, by login, by id, or by the person's id under another
// login; and an installation the Setup URL
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
		"the person's id under another login": {func(f *fakeGitHub) {
			f.userInstallations = []ghInstallation{{id: 42, account: github.Account{Login: "bob", ID: alice.ID, Type: "User"}, permissions: allPermissions()}}
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
	r = rig.backTo(t, b.finish("installation_id=42&setup_action=install"), testConnection)
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
// approval, with a state that is not the session's, and before the sign-in: each goes
// back refused, and nothing is linked. Without a state, or with the session's, the
// candidate is linked after the second sign-in. A restart between the steps changes
// nothing: the session is in the store, and no token is kept.
func TestTheSetupURLsAnswerIsChecked(t *testing.T) {
	for query, want := range map[string]contracts.ConnectReturn{
		"setup_action=request":                                       {Outcome: outcomeRefused, Reason: reasonPersonNotPermitted},
		"installation_id=42":                                         {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=-1&setup_action=install":                    {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=<b>&setup_action=install":                   {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&setup_action=uninstall":                  {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&installation_id=42&setup_action=install": {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"error=access_denied":                                        {Outcome: outcomeCancelled},
		"installation_id=42&setup_action=update":                     {Outcome: outcomeLinked},
		"installation_id=42&setup_action=update&state=x":             {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&setup_action=update&state=S&state=S":     {Outcome: outcomeRefused, Reason: reasonGrantNotConfirmed},
		"installation_id=42&setup_action=install&state=S":            {Outcome: outcomeLinked},
	} {
		rig := newConnectRig(t)
		rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
		b := rig.browser(t)
		// The state GitHub's page to install the App carries, which the Setup URL brings
		// back.
		signed := b.signIn(rig.pass())
		target := signed.Header().Get("Location")
		if signed.Code == http.StatusOK {
			target = html.UnescapeString(strings.Split(strings.Split(signed.Body.String(), `href="`)[1], `"`)[0])
		}
		u, _ := url.Parse(target)
		rec := b.finish(strings.ReplaceAll(query, "state=S", "state="+url.QueryEscape(u.Query().Get("state"))))
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
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
	// A restart between the steps: a new Connect on the store finishes the connect.
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	b = rig.browser(t)
	b.signIn(rig.pass())
	rig.c.stop()
	c := rig.connect(rig.st)
	defer c.stop()
	b.h = c.Route(rig.mux)
	r = rig.backTo(t, b.finish("installation_id=42&setup_action=install"), testConnection)
	if r.Outcome != outcomeLinked {
		t.Errorf("after a restart: %+v", r)
	}
	rig.linked(t, 42, testConnection, linkPending)
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
// grant_taken; 403 connection_unknown, the link is replaced by the new connection,
// pending; 409 connection_ended, likewise; 409 connection_suspended, refused,
// source_unavailable; any other answer, refused, source_unavailable, a 403 not signed
// under the pin and a 403 forbidden among them.
func TestAPendingLinkIsListedBeforeItIsReplaced(t *testing.T) {
	for name, tc := range map[string]struct {
		status     int
		body       string
		connection string
		state      string
		reason     string
		unsigned   bool
	}{
		"204":                  {0, "", otherConnection, linkLive, reasonGrantTaken, false},
		"403":                  {403, `{"error":"connection_unknown"}`, testConnection, linkPending, "", false},
		"connection_ended":     {409, `{"error":"connection_ended"}`, testConnection, linkPending, "", false},
		"connection_suspended": {409, `{"error":"connection_suspended"}`, otherConnection, linkPending, reasonSourceUnavailable, false},
		"500":                  {500, `oops`, otherConnection, linkPending, reasonSourceUnavailable, false},
		"403 not signed":       {403, `{"error":"connection_unknown"}`, otherConnection, linkPending, reasonSourceUnavailable, true},
		"403 forbidden":        {403, `{"error":"forbidden"}`, otherConnection, linkPending, reasonSourceUnavailable, false},
	} {
		rig := newConnectRig(t)
		if tc.unsigned {
			rig.apiary.signer = newKey(t)
		}
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
			return 403, `{"error":"connection_unknown"}`
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
	get("/v1/connect?state=" + url.QueryEscape(rig.pass()))
	rec := get("/v1/connect/continue?x=1")
	u, _ := url.Parse(rec.Header().Get("Location"))
	get("/v1/connect/authorized?code=" + signInCode + "&state=" + u.Query().Get("state"))
	rec = get("/v1/connect/return?installation_id=42&setup_action=install")
	u, _ = url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(rec.Header().Get("Location"), rig.gh.srv.URL+"/login/oauth/authorize?") {
		t.Fatalf("sent to %s", rec.Header().Get("Location"))
	}
	rig.backTo(t, get("/v1/connect/authorized?code="+signInCode+"&state="+u.Query().Get("state")), testConnection)
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
	b.passRefused("/v1/connect?state="+strings.Repeat("A", maxConnectQuery), refuseQuery)
	b.passRefused("/v1/connect?state=%zz", refuseQuery)
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
	r := httptest.NewRequest(http.MethodGet, b.bindTarget("42"), nil)
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

// held checks the installation's link names connection, in state, under the pass that
// expires at pass, in Unix seconds.
func (rig *connectRig) held(t *testing.T, installation int64, connection, state string, pass int64) {
	t.Helper()
	l, ok, err := linkOf(rig.st, installation)
	if err != nil || !ok || l.Connection != connection || l.State != state || l.Pass != pass {
		t.Errorf("the installation %d's link %+v %v %v, want %s %s %d", installation, l, ok, err, connection, state, pass)
	}
}

// TestAConnectionHoldsOneInstallation connects the installation 7 to the connection
// that the installation 42 is linked to already: live, the page refuseHeld refuses, and
// nothing changes; pending, the link gives way at once, unlisted, to a newer pass, and
// to a pass as old or older refuseHeld refuses. Where serve minted a linked return for
// the connection under a pass as new as the one brought, refuseOlder refuses instead,
// whatever the link. Qory Apiary failing, or answering unsigned, changes none of that,
// since the link is not listed: the contract says "A newer pass on the same connection
// (connect-pass.schema.json) drops the old link at once, since the control plane
// accepts a return only for the nonce of the connection's latest pass", and the record
// of the newest pass a linked return was minted under, see [keepPass], keeps an older
// pass from ever replacing a link.
func TestAConnectionHoldsOneInstallation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	older, newer := now.Add(5*time.Minute), now.Add(10*time.Minute)
	for name, tc := range map[string]struct {
		state    string
		pass     time.Time
		replaced bool
		status   int
		unsigned bool
		minted   bool
	}{
		"live, a newer pass":    {linkLive, newer, false, 403, false, false},
		"pending, a newer pass": {linkPending, newer, true, 403, false, false},
		"pending, an older one": {linkPending, older.Add(-time.Minute), false, 403, false, false},
		"pending, one as old":   {linkPending, older, false, 403, false, false},
		// Qory Apiary failing, or answering under a key the pin does not list, changes
		// nothing: the link is not listed, and the passes alone decide.
		"pending, a newer pass, Qory Apiary failing": {linkPending, newer, true, 500, false, false},
		"pending, a newer pass, answers not signed":  {linkPending, newer, true, 403, true, false},
		"pending, one as old, Qory Apiary failing":   {linkPending, older, false, 500, false, false},
		"live, a newer pass, answers not signed":     {linkLive, newer, false, 403, true, false},
		// A linked return minted under the link's pass: refuseOlder answers where both
		// apply.
		"pending, one as old, its return minted":   {linkPending, older, false, 403, false, true},
		"live, an older one, its return minted":    {linkLive, older.Add(-time.Minute), false, 403, false, true},
		"pending, a newer pass, its return minted": {linkPending, newer, true, 403, false, true},
	} {
		rig := newConnectRig(t)
		putLink(rig.st, 42, link{Connection: testConnection, State: tc.state, Pass: older.Unix(), Return: time.Now().Add(returnFor).Unix()})
		if tc.minted {
			keepPass(rig.st, testConnection, older.Unix(), time.Now())
		}
		setReach(rig.st, "acme/widgets", 42)
		rig.apiary.refuse = func(string, int) (int, string) { return tc.status, `{"error":"connection_unknown"}` }
		if tc.unsigned {
			rig.apiary.signer = newKey(t)
		}
		b := rig.browser(t)
		rec := b.connect(rig.passAt(testConnection, tc.pass), "7")
		rig.gh.mu.Lock()
		mints := len(rig.gh.mints)
		rig.gh.mu.Unlock()
		if mints != 0 {
			t.Errorf("%s: the installation 42 is listed", name)
		}
		if tc.replaced {
			if r := rig.backTo(t, rec, testConnection); r.Outcome != outcomeLinked {
				t.Errorf("%s: %+v", name, r)
			}
			rig.held(t, 7, testConnection, linkPending, tc.pass.Unix())
			rig.linked(t, 42, "", "")
			if inst, ok, _ := reachOf(rig.st, "acme/widgets"); ok && inst == 42 {
				t.Errorf("%s: the replaced installation's repositories are kept", name)
			}
			if !strings.Contains(rig.log.String(), `"msg":"a newer pass for the connection replaces its pending link","connection":"`+testConnection+`","installation":42`) {
				t.Errorf("%s: the log: %s", name, rig.log.String())
			}
			if _, ok, _ := replacedOf(rig.st, testConnection); ok {
				t.Errorf("%s: the connection is kept as replaced", name)
			}
		} else {
			want := refuseHeld
			if tc.minted {
				want = refuseOlder
			}
			refused(t, rec, want)
			if b.cookie != nil {
				t.Errorf("%s: the cookie is kept", name)
			}
			rig.held(t, 42, testConnection, tc.state, older.Unix())
			rig.linked(t, 7, "", "")
			if n := len(rig.apiary.sent(routeCollections)); n != 0 {
				t.Errorf("%s: %d listings", name, n)
			}
		}
		rig.c.stop()
		rig.noLeak(t)
	}
}

// TestTwoPassesForOneConnectionLinkOneInstallation has two passes for one connection,
// an older and a newer, used to connect the installation 9 of octo-org and the
// installation 42 of acme, which the person both administers, in each order, while
// Qory Apiary has made no connection: the connection holds one installation at the
// end, never the one of the older pass when the newer linked another.
func TestTwoPassesForOneConnectionLinkOneInstallation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	older, newer := now.Add(5*time.Minute), now.Add(10*time.Minute)
	type step struct {
		installation string
		pass         time.Time
	}
	for name, steps := range map[string][2]step{
		"octo-org older, acme newer": {{"9", older}, {"42", newer}},
		"acme older, octo-org newer": {{"42", older}, {"9", newer}},
		"octo-org newer, acme older": {{"9", newer}, {"42", older}},
		"acme newer, octo-org older": {{"42", newer}, {"9", older}},
	} {
		rig := newConnectRig(t)
		rig.gh.userInstallations = []ghInstallation{{id: 9, account: octoOrg, permissions: allPermissions()}, {id: 42, account: acme, permissions: allPermissions()}}
		rig.gh.memberships = map[string]ghMembership{
			"acme":     {state: "active", role: "admin", org: acme.ID, person: alice.ID},
			"octo-org": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID},
		}
		rig.apiary.refuse = func(route string, _ int) (int, string) {
			if route != routeCollections {
				return 0, ""
			}
			return 403, `{"error":"connection_unknown"}`
		}
		var linked step
		for i, s := range steps {
			rec := rig.browser(t).connect(rig.passAt(testConnection, s.pass), s.installation)
			if i == 0 || s.pass.After(linked.pass) {
				if r := rig.backTo(t, rec, testConnection); r.Outcome != outcomeLinked {
					t.Errorf("%s: step %d: %+v", name, i+1, r)
				}
				linked = s
			} else {
				refused(t, rec, refuseOlder)
			}
			held, err := linkedTo(rig.st, testConnection)
			if err != nil || len(held) != 1 {
				t.Fatalf("%s: step %d: the connection holds %v %v", name, i+1, held, err)
			}
			if id := strconv.FormatInt(held[0], 10); id != linked.installation {
				t.Errorf("%s: step %d: the connection holds %s, want %s", name, i+1, id, linked.installation)
			}
			l, _, _ := linkOf(rig.st, held[0])
			if l.Pass != linked.pass.Unix() {
				t.Errorf("%s: step %d: the link's pass %d, want %d", name, i+1, l.Pass, linked.pass.Unix())
			}
		}
		rig.c.stop()
		rig.noLeak(t)
	}
}

// TestAListingInFlightIsNotOvertakenByAConnect holds a listing of the installation 42
// for the connection it is linked to, pending, at Qory Apiary, while a connect for
// another connection reaches its link: the connect waits for the listing, whose 204
// makes the link live, and goes back refused, grant_taken; the installation is never
// linked to the new connection while Qory Apiary took the other's listing.
func TestAListingInFlightIsNotOvertakenByAConnect(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42, otherConnection, linkPending)
	arrived, release, waiting := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	rig.adapter.lockWaits = func(installation int64) {
		if installation == 42 {
			once.Do(func() { close(waiting) })
		}
	}
	rig.apiary.refuse = func(route string, n int) (int, string) {
		if route != routeCollections {
			return 0, ""
		}
		if n == 1 {
			close(arrived)
			<-release
			// Qory Apiary made the other connection and takes its listing.
			return 0, ""
		}
		return 403, `{"error":"connection_unknown"}`
	}
	listed := make(chan error, 1)
	go func() { listed <- rig.adapter.listConnection(context.Background(), 42, otherConnection) }()
	<-arrived
	b := rig.browser(t)
	b.signIn(rig.pass())
	answered := make(chan *httptest.ResponseRecorder, 1)
	target := b.bindTarget("42")
	go func() { answered <- b.get(target) }()
	select {
	case <-waiting:
	case rec := <-answered:
		// The connect did not wait for the listing.
		answered <- rec
	}
	close(release)
	if err := <-listed; err != nil {
		t.Fatal(err)
	}
	if r := rig.backTo(t, <-answered, testConnection); r.Outcome != outcomeRefused || r.Reason != reasonGrantTaken {
		t.Errorf("%+v", r)
	}
	rig.linked(t, 42, otherConnection, linkLive)
	if n := len(rig.apiary.sent(routeCollections)); n != 1 {
		t.Errorf("%d listings", n)
	}

}

// TestAReplacedConnectionIsListedEmptyUntilItsLastListing replaces the installation 42's
// pending link to another connection with a connect: from then on each listing of the
// replaced connection, the first listing's tries still running for it among them, is
// complete and names no collection, and never the installation's repositories, and a
// 403 connection_unknown keeps it until its last listing, which forgets it; a 204 to one
// ends the connection, POST /v1/connections/disconnect, and forgets it; and the round
// sends the last listing once its moment has come.
func TestAReplacedConnectionIsListedEmptyUntilItsLastListing(t *testing.T) {
	forbid := func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	replace := func(t *testing.T) *connectRig {
		rig := newConnectRig(t)
		putLink(rig.st, 42, link{Connection: otherConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
		rig.apiary.refuse = forbid
		if r := rig.backTo(t, rig.browser(t).connect(rig.pass(), "42"), testConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
		rig.c.stop()
		if r, ok, _ := replacedOf(rig.st, otherConnection); !ok || r.Installation != 42 {
			t.Fatalf("the replaced connection %+v %v", r, ok)
		}
		return rig
	}
	// empty checks every listing of the replaced connection from the one numbered from
	// on is complete, in one part, and names no collection.
	empty := func(t *testing.T, rig *connectRig, from int) int {
		t.Helper()
		n := 0
		for _, s := range rig.apiary.sent(routeCollections)[from:] {
			if s.body["connection_id"] != otherConnection {
				continue
			}
			n++
			var req contracts.SourceCollections
			json.Unmarshal(s.raw, &req)
			if !strings.Contains(string(s.raw), `"collections":[]`) || len(req.Collections) != 0 || !req.Listing.Complete || req.Listing.Part != 1 {
				t.Errorf("a listing of the replaced connection names collections: %s", s.raw)
			}
		}
		return n
	}

	rig := replace(t)
	before := len(rig.apiary.sent(routeCollections))
	// A first listing's tries still running for the replaced connection.
	rig.c = rig.connect(rig.st)
	rig.c.listSoon(42, otherConnection, false)
	eventually(t, "the first listing's tries", func() bool {
		n := 0
		for _, s := range rig.apiary.sent(routeCollections)[before:] {
			if s.body["connection_id"] == otherConnection {
				n++
			}
		}
		return n >= 3
	})
	rig.c.stop()
	if err := rig.adapter.listConnection(context.Background(), 42, otherConnection); !refusedAs(err, 403, codeConnectionUnknown) {
		t.Errorf("err %v", err)
	}
	if n := empty(t, rig, before); n < 4 {
		t.Errorf("%d listings of the replaced connection", n)
	}
	if _, ok, _ := replacedOf(rig.st, otherConnection); !ok {
		t.Error("a 403 before the last listing forgot the replaced connection")
	}
	rig.linked(t, 42, testConnection, linkPending)
	// The last listing, once the adapter's clock is past the replaced link's return
	// and returnSkew more: a 403 forgets it.
	before = len(rig.apiary.sent(routeCollections))
	rig.adapter.now = func() time.Time { return time.Now().Add(returnFor + returnSkew + time.Second) }
	if err := rig.adapter.listFor(context.Background(), 42, otherConnection); err != nil {
		t.Errorf("err %v", err)
	}
	if n := empty(t, rig, before); n != 1 {
		t.Errorf("%d last listings", n)
	}
	if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
		t.Error("the replaced connection is kept past its last listing")
	}
	if !strings.Contains(rig.log.String(), `"msg":"the replaced connection was not made, so it is forgotten","connection":"`+otherConnection+`","installation":42`) {
		t.Errorf("the log: %s", rig.log.String())
	}
	if n := len(rig.apiary.sent(routeConnectionsDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}

	// A 204: the replaced connection was made meanwhile, and is ended.
	rig = replace(t)
	rig.apiary.refuse = nil
	before = len(rig.apiary.sent(routeCollections))
	if err := rig.adapter.listConnection(context.Background(), 42, otherConnection); err != nil {
		t.Fatal(err)
	}
	empty(t, rig, before)
	sent := rig.apiary.sent(routeConnectionsDisconnect)
	if len(sent) != 1 || sent[0].body["connection_id"] != otherConnection {
		t.Errorf("the disconnects %v", sent)
	}
	if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
		t.Error("the ended connection is kept as replaced")
	}
	rig.linked(t, 42, testConnection, linkPending)

	// The round sends the last listing once its moment has come, and not before.
	rig = replace(t)
	clock := &pullClock{t: time.Now()}
	p := &puller{adapter: rig.adapter, store: rig.st, log: rig.adapter.Log, now: clock.now, sleep: clock.sleep, jitter: func(time.Duration) time.Duration { return 0 }}
	before = len(rig.apiary.sent(routeCollections))
	p.listReplaced(context.Background())
	p.rounds.Wait()
	if n := empty(t, rig, before); n != 0 {
		t.Errorf("%d listings before the moment", n)
	}
	clock.sleep(context.Background(), returnFor+returnSkew+time.Second)
	rig.adapter.now = clock.now
	p.listReplaced(context.Background())
	p.rounds.Wait()
	if n := empty(t, rig, before); n != 1 {
		t.Errorf("%d listings at the moment", n)
	}
	if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
		t.Error("the replaced connection is kept past its last listing")
	}
}

// TestABusyLinkIsWaitedForBriefly holds the link while a connect reaches it: freed
// within the wait, the connect links; held past it, the connect goes back refused,
// source_unavailable, though its request's deadline is far.
func TestABusyLinkIsWaitedForBriefly(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	b := rig.browser(t)
	b.signIn(rig.pass())
	target := b.bindTarget("42")
	rig.c.linking <- struct{}{}
	go func() {
		time.Sleep(100 * time.Millisecond)
		<-rig.c.linking
	}()
	if r := rig.backTo(t, b.get(target), testConnection); r.Outcome != outcomeLinked {
		t.Errorf("%+v", r)
	}
	rig.c.linkWait = 50 * time.Millisecond
	b = rig.browser(t)
	b.signIn(rig.pass())
	target = b.bindTarget("7")
	rig.c.linking <- struct{}{}
	began := time.Now()
	r := rig.backTo(t, b.get(target), testConnection)
	if r.Outcome != outcomeRefused || r.Reason != reasonSourceUnavailable || time.Since(began) > 5*time.Second {
		t.Errorf("%+v after %v", r, time.Since(began))
	}
	<-rig.c.linking
	rig.linked(t, 7, "", "")
}

// TestALiveAnswerChangesOnlyTheLinkOfItsConnection checks a listing's 204 for a
// connection leaves a link that names another connection as it is, and keeps the pass
// of the link it makes live.
func TestALiveAnswerChangesOnlyTheLinkOfItsConnection(t *testing.T) {
	rig := newConnectRig(t)
	Link(rig.st, 42, otherConnection, linkPending)
	if err := goLive(rig.st, 42, testConnection); err != nil {
		t.Fatal(err)
	}
	rig.linked(t, 42, otherConnection, linkPending)
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Pass: 1234})
	if err := goLive(rig.st, 42, testConnection); err != nil {
		t.Fatal(err)
	}
	rig.held(t, 42, testConnection, linkLive, 1234)
}

// TestThePagesSayTheUsersWords pins each page's line as the user approved it, and
// checks a page carries its quotes as they are, since a page is plain text, and the
// Save page's line reads the same once its HTML is read.
func TestThePagesSayTheUsersWords(t *testing.T) {
	for rf, want := range map[*refusal]string{
		&refuseQuery:     `This link is not one this server reads. Press "Install" in Qory Apiary again.`,
		&refusePass:      `This link is not valid. Press "Install" in Qory Apiary again.`,
		&refuseSignature: `This link is not valid. Press "Install" in Qory Apiary again.`,
		&refusePayload:   `This link is not valid. Press "Install" in Qory Apiary again.`,
		&refuseUsed:      `This link was used already. Press "Install" in Qory Apiary again.`,
		&refuseFailed:    `Something failed on this server. Press "Install" in Qory Apiary again.`,
		&refuseNoSession: `No installation is under way in this browser, or it took too long. Press "Install" in Qory Apiary again.`,
		&refuseHeld:      "This connection already holds another installation of the App, and it holds only one.",
		&refuseOlder:     `A newer link for this connection was used already. Press "Install" in Qory Apiary again.`,
		&refuseAdapter:   `This connect link is for another integration. Press "Install" on this integration's page in Qory Apiary.`,
		&refuseMethod:    "This address answers GET requests alone.",
	} {
		if rf.page != want {
			t.Errorf("the page %q, want %q", rf.page, want)
		}
	}
	rig := newConnectRig(t)
	rec := rig.browser(t).get("/v1/connect/return?installation_id=42&setup_action=install")
	refused(t, rec, refuseNoSession)
	if !strings.Contains(rec.Body.String(), `Press "Install" in`) {
		t.Errorf("the page %q", rec.Body)
	}
	rec = rig.browser(t).signIn(rig.pass())
	if line := strings.ReplaceAll(rec.Body.String(), "&#39;", "'"); !strings.Contains(line, "<p>The App is already installed. On GitHub's page, choose the account, then press Save to finish.</p>") ||
		!strings.Contains(line, ">Continue on GitHub</a>") {
		t.Errorf("the Save page %s", rec.Body)
	}
}

// spent checks rec, a connect return, clears the session's cookie, Max-Age=0 on its name
// and path, so the binding serves one flow.
func spent(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == connectCookie && ck.MaxAge < 0 && ck.Path == "/v1/connect" && ck.Value == "" {
			return
		}
	}
	t.Errorf("the return keeps the cookie: %v", rec.Header()["Set-Cookie"])
}

// TestEveryReturnSpendsThePass mints a connect return at each step, linked, refused
// and cancelled, and checks each clears the cookie and ends the session, so the same
// browser brings nothing more under the pass: the step brought again, with the cookie
// it had, finds no session.
func TestEveryReturnSpendsThePass(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	for name, prepare := range map[string]func(b *browser) string{
		"linked": func(b *browser) string {
			b.signIn(rig.pass())
			return b.bindTarget("7")
		},
		"refused at the Setup URL": func(b *browser) string {
			b.signIn(rig.pass())
			return "/v1/connect/return?installation_id=42&setup_action=install&state=x"
		},
		"cancelled at the sign-in": func(b *browser) string {
			return "/v1/connect/authorized?error=access_denied&state=" + b.start(rig.pass())
		},
		"refused at the second sign-in": func(b *browser) string {
			b.signIn(rig.pass())
			b.bindTarget("99")
			return "/v1/connect/authorized?code=" + signInCode + "&state=" + strings.Repeat("A", 43)
		},
		"refused at the continue address": func(b *browser) string {
			b.signIn(rig.pass())
			return "/v1/connect/continue"
		},
	} {
		b := rig.browser(t)
		target := prepare(b)
		cookie := b.cookie
		rec := b.get(target)
		rig.backTo(t, rec, testConnection)
		spent(t, rec)
		if b.cookie != nil {
			t.Errorf("%s: the cookie is kept", name)
		}
		b.cookie = cookie
		refused(t, b.get(target), refuseNoSession)
	}
	rig.noLeak(t)
}

// TestTheGrantIsBoundToTheStateAndTheCookie checks the Setup URL links nothing: its
// installation is a candidate, linked only on the second sign-in, which needs the
// session's cookie and its state; a wrong state at either sign-in, or the first
// sign-in brought again, goes back refused; another browser, without the cookie, gets
// the page; and a sign-in brought again after the return finds no session.
func TestTheGrantIsBoundToTheStateAndTheCookie(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	b := rig.browser(t)
	first := b.start(rig.pass())
	b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + first)
	target := b.bindTarget("42")
	if ok, _ := Linked(rig.st, 42); ok || len(rig.gh.exchanges) != 1 {
		t.Errorf("the Setup URL linked, or signed in: %v, %d", ok, len(rig.gh.exchanges))
	}
	// Another browser, without the cookie: the page.
	refused(t, rig.browser(t).get(target), refuseNoSession)
	refused(t, rig.browser(t).get("/v1/connect/return?installation_id=42&setup_action=install"), refuseNoSession)
	// The second sign-in links.
	cookie := b.cookie
	if r := rig.backTo(t, b.get(target), testConnection); r.Outcome != outcomeLinked {
		t.Errorf("%+v", r)
	}
	rig.linked(t, 42, testConnection, linkPending)
	// Brought again, with the cookie it had: no session.
	b.cookie = cookie
	refused(t, b.get(target), refuseNoSession)

	for name, bring := range map[string]func(b *browser, first, target string) *httptest.ResponseRecorder{
		"a wrong state at the second sign-in": func(b *browser, _, target string) *httptest.ResponseRecorder {
			return b.get(strings.Split(target, "&state=")[0] + "&state=" + strings.Repeat("A", 43))
		},
		"the first sign-in brought again": func(b *browser, first, _ string) *httptest.ResponseRecorder {
			return b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + first)
		},
		"the first sign-in's state on the Setup URL": func(b *browser, first, _ string) *httptest.ResponseRecorder {
			return b.get("/v1/connect/return?installation_id=42&setup_action=install&state=" + first)
		},
	} {
		rig := newConnectRig(t)
		b := rig.browser(t)
		first := b.start(rig.pass())
		b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + first)
		var target string
		if !strings.Contains(name, "Setup URL") {
			target = b.bindTarget("42")
		}
		rec := bring(b, first, target)
		if r := rig.backTo(t, rec, testConnection); r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed {
			t.Errorf("%s: %+v", name, r)
		}
		spent(t, rec)
		if ok, _ := Linked(rig.st, 42); ok {
			t.Errorf("%s: linked", name)
		}
	}
	rig.noLeak(t)
}

// TestAWaitForTheInstallationsLockPastTheDeadlineGoesBack holds the installation's
// lock, as a listing of it does, while a connect for it reaches its link: past its
// deadline it goes back refused, source_unavailable, and links nothing.
func TestAWaitForTheInstallationsLockPastTheDeadlineGoesBack(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	b.signIn(rig.pass())
	unlock, err := rig.adapter.lockInstallation(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, b.bindTarget("42"), nil)
	r.AddCookie(&http.Cookie{Name: connectCookie, Value: b.cookie.Value})
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	rig.h.ServeHTTP(rec, r.WithContext(ctx))
	unlock()
	if ret := rig.backTo(t, rec, testConnection); ret.Outcome != outcomeRefused || ret.Reason != reasonSourceUnavailable {
		t.Errorf("%+v", ret)
	}
	if ok, _ := Linked(rig.st, 42); ok {
		t.Error("linked")
	}
}

// TestAFirstListingEndsWithTheLastListing lists, on a clock each wait moves on, a
// pending link whose connect return expired now: the tries wait a second, doubling,
// up to 64, and the last wait ends at the expiry and returnSkew more, where the last
// listing is sent, read from GitHub again. Its 403 connection_unknown drops the link; a
// 500 keeps it, and its tries go on, the waits doubling up to an hour.
func TestAFirstListingEndsWithTheLastListing(t *testing.T) {
	before := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second, 64 * time.Second, 64 * time.Second}
	for _, status := range []int{403, 500} {
		rig := newConnectRig(t)
		rig.budget = 4 * time.Hour
		rig.apiary.refuse = func(string, int) (int, string) {
			if status == 403 {
				return 403, `{"error":"connection_unknown"}`
			}
			return 500, `{"error":"internal"}`
		}
		rig.clock = &pullClock{t: time.Now().Truncate(time.Second)}
		rig.adapter.now, rig.c.now = rig.clock.now, rig.clock.now
		putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: rig.clock.now().Unix()})
		rig.c.listSoon(42, testConnection, false)
		sum := func() (s time.Duration) {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			for _, w := range rig.waits {
				s += w
			}
			return s
		}
		if status == 403 {
			eventually(t, "the link dropped", func() bool { ok, _ := Linked(rig.st, 42); return !ok })
			rig.c.stop()
		} else {
			eventually(t, "the waits past the budget", func() bool { return sum() > rig.budget })
			rig.c.stop()
			rig.linked(t, 42, testConnection, linkPending)
		}
		rig.mu.Lock()
		waits := slices.Clone(rig.waits)
		rig.mu.Unlock()
		if len(waits) < 10 || !slices.Equal(waits[:9], before) {
			t.Fatalf("%d: waited %v", status, waits)
		}
		// The tenth wait ends at the expiry and returnSkew more.
		var upTo time.Duration
		for _, w := range waits[:10] {
			upTo += w
		}
		if upTo != returnSkew {
			t.Errorf("%d: the last listing after %v", status, upTo)
		}
		if status == 403 {
			if len(waits) != 10 {
				t.Errorf("waited past the last listing: %v", waits)
			}
			// The first listing's ten tries read GitHub once, and the last listing again.
			if n := rig.gh.listings(); n != 2 {
				t.Errorf("GitHub's repositories read %d times", n)
			}
			continue
		}
		after := waits[10:]
		want := []time.Duration{64 * time.Second, 128 * time.Second, 256 * time.Second, 512 * time.Second, 1024 * time.Second, 2048 * time.Second, time.Hour}
		if len(after) < len(want)+1 || !slices.Equal(after[:len(want)], want) || after[len(want)] != time.Hour {
			t.Errorf("waited after the last listing %v", after)
		}
	}
}

// TestAPassOneSecondPastFifteenMinutesAheadIsRefused brings, on a clock at a whole
// second, a pass that expires 15 minutes and one second ahead, which Qory Apiary never
// issues, as from a clock behind the adapter's: it goes back refused, pass_expired, and
// its nonce is not kept; one that expires 15 minutes ahead is accepted.
func TestAPassOneSecondPastFifteenMinutesAheadIsRefused(t *testing.T) {
	rig := newConnectRig(t)
	now := time.Now().Truncate(time.Second)
	rig.c.now = func() time.Time { return now }
	pass := rig.passAt(testConnection, now.Add(passAhead+time.Second))
	b := rig.browser(t)
	rec := b.get("/v1/connect?state=" + url.QueryEscape(pass))
	if r := rig.backTo(t, rec, testConnection); r.Outcome != outcomeRefused || r.Reason != reasonPassExpired {
		t.Errorf("the connect return %+v", r)
	}
	if n := 0; rig.st.Each(nsConnectNonces, func(string, []byte) error { n++; return nil }) != nil || n != 0 || b.cookie != nil {
		t.Errorf("%d nonces are kept, or a session started", n)
	}
	rec = rig.browser(t).get("/v1/connect?state=" + url.QueryEscape(rig.passAt(testConnection, now.Add(passAhead))))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/v1/connect/continue" {
		t.Errorf("a pass 15 minutes ahead: %d %v", rec.Code, rec.Header())
	}
	rig.noLeak(t)
}

// twoOrgs has the person administer octo-org's installation 9 and acme's 42, and Qory
// Apiary answer every listing 403 connection_unknown until made is set, then 204, as
// once it has taken a linked return and made the connection.
func twoOrgs(rig *connectRig, made *atomic.Bool) {
	rig.gh.userInstallations = []ghInstallation{{id: 9, account: octoOrg, permissions: allPermissions()}, {id: 42, account: acme, permissions: allPermissions()}}
	rig.gh.memberships = map[string]ghMembership{
		"acme":     {state: "active", role: "admin", org: acme.ID, person: alice.ID},
		"octo-org": {state: "active", role: "admin", org: octoOrg.ID, person: alice.ID},
	}
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route != routeCollections || made.Load() {
			return 0, ""
		}
		return 403, `{"error":"connection_unknown"}`
	}
}

// TestAPassNoNewerThanTheConnectionsNewestIsRefused has the newest pass a linked return
// was minted under for the connection outlive every link that pass made: a pass whose
// expiry is no later than it, as late or earlier, gets the page refuseOlder, links
// nothing, and mints no return, whether the installation that pass linked has since
// been re-linked elsewhere, deleted, or re-connected under it; so a return that newest
// pass minted, delivered later, never makes another installation live.
func TestAPassNoNewerThanTheConnectionsNewestIsRefused(t *testing.T) {
	// (a) octo-org's 9 linked under p1 and re-connected under p2; then acme's 42 under
	// pv, between them, or under p2's expiry, the same.
	for _, pv := range []time.Duration{7 * time.Minute, 10 * time.Minute, 4 * time.Minute} {
		rig := newConnectRig(t)
		var made atomic.Bool
		twoOrgs(rig, &made)
		now := time.Now().Truncate(time.Second)
		p1, p2 := now.Add(5*time.Minute), now.Add(10*time.Minute)
		for _, p := range []time.Time{p1, p2} {
			if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, p), "9"), testConnection); r.Outcome != outcomeLinked {
				t.Fatalf("%+v", r)
			}
		}
		rig.held(t, 9, testConnection, linkPending, p2.Unix())
		b := rig.browser(t)
		refused(t, b.connect(rig.passAt(testConnection, now.Add(pv)), "42"), refuseOlder)
		if b.cookie != nil {
			t.Errorf("%v: the cookie is kept", pv)
		}
		made.Store(true)
		rig.c.stop()
		rig.adapter.listRepositories(context.Background(), 42)
		rig.linked(t, 42, "", "")
		rig.held(t, 9, testConnection, linkPending, p2.Unix())
		rig.noLeak(t)
	}
	// (b) octo-org's 9 linked under the newer pass; then the connection freed, by a
	// connect of 9 to another connection, or GitHub deleting 9; then acme's 42 under
	// the older pass, or one as new.
	for _, free := range []string{"re-linked elsewhere", "deleted"} {
		for _, as := range []string{"older", "as new"} {
			rig := newConnectRig(t)
			var made atomic.Bool
			twoOrgs(rig, &made)
			now := time.Now().Truncate(time.Second)
			newer := now.Add(10 * time.Minute)
			victim := rig.browser(t)
			if as == "older" {
				victim.signIn(rig.passAt(testConnection, now.Add(5*time.Minute)))
			}
			if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, newer), "9"), testConnection); r.Outcome != outcomeLinked {
				t.Fatalf("%+v", r)
			}
			switch free {
			case "re-linked elsewhere":
				if r := rig.backTo(t, rig.browser(t).connect(rig.passFor(otherConnection), "9"), otherConnection); r.Outcome != outcomeLinked {
					t.Fatalf("%+v", r)
				}
			case "deleted":
				rig.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 9}})
			}
			if held, _ := linkedTo(rig.st, testConnection); len(held) != 0 {
				t.Fatalf("%s: the connection holds %v", free, held)
			}
			var rec *httptest.ResponseRecorder
			if as == "older" {
				rec = victim.finish("installation_id=42&setup_action=install")
			} else {
				rec = victim.connect(rig.passAt(testConnection, newer), "42")
			}
			refused(t, rec, refuseOlder)
			if victim.cookie != nil {
				t.Errorf("%s, %s: the cookie is kept", free, as)
			}
			made.Store(true)
			rig.c.stop()
			rig.adapter.listRepositories(context.Background(), 42)
			rig.linked(t, 42, "", "")
			rig.noLeak(t)
		}
	}
}

// TestAReConnectUnderANewerPassRaisesTheLinksPass re-connects acme's 42 under p2 after
// p1: the link holds p2's expiry, and octo-org's 9 under p1.5, between them, gets the
// page refuseOlder, and the connection holds 42 alone.
func TestAReConnectUnderANewerPassRaisesTheLinksPass(t *testing.T) {
	rig := newConnectRig(t)
	var made atomic.Bool
	twoOrgs(rig, &made)
	now := time.Now().Truncate(time.Second)
	p1, p15, p2 := now.Add(5*time.Minute), now.Add(7*time.Minute), now.Add(10*time.Minute)
	for _, p := range []time.Time{p1, p2} {
		if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, p), "42"), testConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
	}
	rig.held(t, 42, testConnection, linkPending, p2.Unix())
	refused(t, rig.browser(t).connect(rig.passAt(testConnection, p15), "9"), refuseOlder)
	if held, _ := linkedTo(rig.st, testConnection); len(held) != 1 || held[0] != 42 {
		t.Errorf("the connection holds %v", held)
	}
	rig.linked(t, 9, "", "")
	// A live link's pass is raised too.
	putLink(rig.st, 42, link{Connection: testConnection, State: linkLive, Pass: p2.Unix()})
	p3 := now.Add(12 * time.Minute)
	if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, p3), "42"), testConnection); r.Outcome != outcomeLinked {
		t.Fatalf("%+v", r)
	}
	rig.held(t, 42, testConnection, linkLive, p3.Unix())
	rig.c.stop()
}

// TestALockHeldPastLinkWaitGoesBackSourceUnavailable holds, as a listing in flight
// does, the lock of the installation a connect links, or of the installation linked to
// the connection pending, which a newer pass would replace: past linkWait, while the
// request's context lives on, the connect goes back refused, source_unavailable, and
// nothing changes.
func TestALockHeldPastLinkWaitGoesBackSourceUnavailable(t *testing.T) {
	for _, held := range []int64{42, 9} {
		rig := newConnectRig(t)
		var made atomic.Bool
		twoOrgs(rig, &made)
		rig.c.linkWait = 50 * time.Millisecond
		now := time.Now().Truncate(time.Second)
		putLink(rig.st, 9, link{Connection: testConnection, State: linkPending, Pass: now.Add(5 * time.Minute).Unix(), Return: now.Add(returnFor).Unix()})
		unlock, err := rig.adapter.lockInstallation(context.Background(), held)
		if err != nil {
			t.Fatal(err)
		}
		began := time.Now()
		rec := rig.browser(t).connect(rig.passAt(testConnection, now.Add(10*time.Minute)), "42")
		unlock()
		if r := rig.backTo(t, rec, testConnection); r.Outcome != outcomeRefused || r.Reason != reasonSourceUnavailable {
			t.Errorf("%d: %+v", held, r)
		}
		if d := time.Since(began); d > 5*time.Second {
			t.Errorf("%d: waited %v", held, d)
		}
		rig.linked(t, 42, "", "")
		rig.held(t, 9, testConnection, linkPending, now.Add(5*time.Minute).Unix())
		rig.c.stop()
	}
}

// TestAnInstallationDeletedDuringAConnectIsNotLinked has GitHub delete acme's 42 while
// a connect for it is under way: deleted before the connect links, the connect goes
// back refused, grant_not_confirmed, and links nothing; deleted while the connect holds
// the installation's lock, the deletion waits for it, then drops the link the connect
// wrote, and ends its connection.
func TestAnInstallationDeletedDuringAConnectIsNotLinked(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	b := rig.browser(t)
	b.signIn(rig.pass())
	target := b.bindTarget("42")
	rig.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	if r := rig.backTo(t, b.get(target), testConnection); r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed {
		t.Errorf("%+v", r)
	}
	rig.linked(t, 42, "", "")

	rig = newConnectRig(t)
	unlock, err := rig.adapter.lockInstallation(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	waits := make(chan int64, 1)
	rig.adapter.lockWaits = func(id int64) { waits <- id }
	done := make(chan struct{})
	go func() {
		defer close(done)
		rig.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	}()
	select {
	case id := <-waits:
		if id != 42 {
			t.Fatalf("waited for %d", id)
		}
	case <-done:
		unlock()
		t.Fatal("the deletion did not wait for the installation's lock")
	}
	// What a connect writes holding the lock.
	installMu.Lock()
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Pass: time.Now().Add(5 * time.Minute).Unix(), Return: time.Now().Add(returnFor).Unix()})
	installMu.Unlock()
	unlock()
	<-done
	rig.linked(t, 42, "", "")
	if sent := rig.apiary.sent(routeConnectionsDisconnect); len(sent) != 1 || sent[0].body["connection_id"] != testConnection {
		t.Errorf("disconnects %v", sent)
	}
	rig.c.stop()
}

// TestAFirstListingAnswered403ForbiddenIsSentAgain has Qory Apiary answer a pending
// link's first listing 403 forbidden: it is logged, and sent again, read from GitHub
// once, with the waits that double, and the link stays.
func TestAFirstListingAnswered403ForbiddenIsSentAgain(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"forbidden"}` }
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	eventually(t, "three waits", func() bool { rig.mu.Lock(); defer rig.mu.Unlock(); return len(rig.waits) >= 3 })
	rig.c.stop()
	rig.mu.Lock()
	waits := slices.Clone(rig.waits[:3])
	rig.mu.Unlock()
	if !slices.Equal(waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Errorf("waited %v", waits)
	}
	rig.linked(t, 42, testConnection, linkPending)
	// Each try sends the listing read from GitHub once.
	if n := rig.gh.listings(); n != 1 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
	if !strings.Contains(rig.log.String(), `"msg":"Qory Apiary answered a listing 403 forbidden, so it is sent again later","connection":"`+testConnection+`","installation":42`) {
		t.Errorf("the log %s", rig.log.String())
	}
}

// TestAConnectionLinkedAgainIsNotListedAsReplaced has a connect replace the installation
// 42's pending link to C, then a newer pass for C link octo-org's 9, and C made: C's
// record as replaced is forgotten as C is linked again, so no listing of C, the first
// listing's tries for 42 or the round's among them, empties it or ends it. And a
// record found stale, naming a connection an installation's link names, is forgotten,
// and nothing is sent.
func TestAConnectionLinkedAgainIsNotListedAsReplaced(t *testing.T) {
	for _, order := range []string{"42 then 9", "9 then 42"} {
		first, again := "42", "9"
		if order == "9 then 42" {
			first, again = "9", "42"
		}
		rig := newConnectRig(t)
		var made atomic.Bool
		twoOrgs(rig, &made)
		now := time.Now().Truncate(time.Second)
		if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(otherConnection, now.Add(5*time.Minute)), first), otherConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
		if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, now.Add(5*time.Minute)), first), testConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
		if _, ok, _ := replacedOf(rig.st, otherConnection); !ok {
			t.Fatalf("%s: C is not kept as replaced", order)
		}
		// No listing runs from here on, so the link itself forgets the record.
		rig.c.stop()
		if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(otherConnection, now.Add(10*time.Minute)), again), otherConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
		if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
			t.Errorf("%s: C linked again is kept as replaced", order)
		}
		made.Store(true)
		id, _ := strconv.ParseInt(first, 10, 64)
		before := len(rig.apiary.sent(routeCollections))
		if err := rig.adapter.listFor(context.Background(), id, otherConnection); err != nil {
			t.Errorf("%s: err %v", order, err)
		}
		if n := len(rig.apiary.sent(routeCollections)); n != before {
			t.Errorf("%s: %d listings of C for %s", order, n-before, first)
		}
		if sent := rig.apiary.sent(routeConnectionsDisconnect); len(sent) != 0 {
			t.Errorf("%s: C, linked again, was disconnected: %v", order, sent)
		}
		rig.linked(t, id, testConnection, linkPending)
	}

	// A stale record, naming the connection the installation is linked to again: the
	// round lists the link, never the replaced connection, forgets the record, and the
	// link stays.
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	now := time.Now()
	putLink(rig.st, 42, link{Connection: otherConnection, State: linkPending, Pass: now.Add(10 * time.Minute).Unix(), Return: now.Add(returnFor).Unix()})
	keepReplaced(rig.st, 42, link{Connection: otherConnection, Return: now.Add(-returnFor - returnSkew - time.Minute).Unix()})
	p := &puller{adapter: rig.adapter, store: rig.st, log: rig.adapter.Log, sleep: func(context.Context, time.Duration) error { return nil }, jitter: func(time.Duration) time.Duration { return 0 }}
	p.listReplaced(context.Background())
	p.rounds.Wait()
	rig.linked(t, 42, otherConnection, linkPending)
	if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
		t.Error("the stale record is kept")
	}
	if sent := rig.apiary.sent(routeConnectionsDisconnect); len(sent) != 0 {
		t.Errorf("disconnects %v", sent)
	}
	// And listed for an installation that is not the link's, a stale record is
	// forgotten, and nothing is sent.
	keepReplaced(rig.st, 9, link{Connection: otherConnection, Return: now.Add(-returnFor - returnSkew - time.Minute).Unix()})
	before := len(rig.apiary.sent(routeCollections))
	if err := rig.adapter.listFor(context.Background(), 9, otherConnection); err != nil {
		t.Errorf("err %v", err)
	}
	if n := len(rig.apiary.sent(routeCollections)); n != before {
		t.Errorf("%d listings", n-before)
	}
	if _, ok, _ := replacedOf(rig.st, otherConnection); ok {
		t.Error("the stale record is kept")
	}
}

// TestTheLastListingsMomentIsTheLinks starts, on a clock each wait moves on, a first
// listing of a pending link whose return expires now, so its last listing is due in
// returnSkew; during the second wait a re-connect moves the return ten minutes on. The
// tries then wait for the new moment: no last listing comes at the old one, the waits
// end exactly at the new one, and the last listing's 403 connection_unknown drops the
// link there.
func TestTheLastListingsMomentIsTheLinks(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	clock := &pullClock{t: time.Now().Truncate(time.Second)}
	rig.adapter.now, rig.c.now = clock.now, clock.now
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: clock.now().Unix()})
	gate, gated := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var waits []time.Duration
	rig.c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		n := len(waits)
		mu.Unlock()
		if n == 2 {
			close(gated)
			<-gate
		}
		return clock.sleep(ctx, d)
	}
	rig.c.listSoon(42, testConnection, false)
	<-gated
	// The re-connect, as link writes it.
	moved := clock.now().Add(10 * time.Minute)
	installMu.Lock()
	l, _, _ := linkOf(rig.st, 42)
	l.Return = moved.Unix()
	putLink(rig.st, 42, l)
	installMu.Unlock()
	close(gate)
	eventually(t, "the link dropped", func() bool { ok, _ := Linked(rig.st, 42); return !ok })
	rig.c.stop()
	if got, want := clock.now(), moved.Add(returnSkew); !got.Equal(want) {
		t.Errorf("the last listing at %v, want %v", got, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(waits) < 8 || waits[len(waits)-1] > firstListingMaxWait || waits[len(waits)-2] != firstListingMaxWait {
		t.Errorf("waited %v", waits)
	}
	if !strings.Contains(rig.log.String(), `"msg":"the connection was not made in time, so its pending link is dropped","connection":"`+testConnection+`","installation":42`) {
		t.Errorf("the log %s", rig.log.String())
	}
}

// TestA409ConnectionEndedToAFirstListingDropsTheLink has Qory Apiary answer a pending
// link's first listing 409 connection_ended: the link is dropped at once, with no wait
// and no other try; the parts sent are the one listing's.
func TestA409ConnectionEndedToAFirstListingDropsTheLink(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"connection_ended"}` }
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	eventually(t, "the link dropped", func() bool { ok, _ := Linked(rig.st, 42); return !ok })
	rig.c.stop()
	rig.mu.Lock()
	defer rig.mu.Unlock()
	ids := map[any]bool{}
	for _, s := range rig.apiary.sent(routeCollections) {
		ids[s.body["listing"].(map[string]any)["id"]] = true
	}
	if len(rig.waits) != 0 || len(ids) != 1 {
		t.Errorf("waited %v, %d listings", rig.waits, len(ids))
	}
}

// TestTheNewestPassOutlivesTheOlderSession runs, on one clock for the store and the
// Connect, a connect of octo-org's 9 under a newer pass while a session under an older
// pass for the same connection waits; then GitHub deletes 9, serve restarts, and the
// clock moves to just before the older session ends: the older pass still gets
// refuseOlder, and acme's 42 never goes live under the connection. A record kept too
// short a time, or not kept in the store, fails it.
func TestTheNewestPassOutlivesTheOlderSession(t *testing.T) {
	for _, later := range []time.Duration{2 * time.Minute, sessionFor - 10*time.Second} {
		rig := newConnectRig(t)
		rig.c.stop()
		clock := &pullClock{t: time.Now().Truncate(time.Second)}
		dir := filepath.Join(t.TempDir(), "s")
		open := func() *store.Store {
			st, err := store.Open(dir, store.Options{Now: clock.now})
			if err != nil {
				t.Fatal(err)
			}
			rig.st = st
			rig.c = rig.connect(st)
			rig.c.now = clock.now
			rig.adapter.now = clock.now
			rig.h = rig.c.Route(rig.mux)
			return st
		}
		st := open()
		var made atomic.Bool
		twoOrgs(rig, &made)
		t0 := clock.now()
		victim := rig.browser(t)
		victim.signIn(rig.passAt(testConnection, t0.Add(time.Second)))
		if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, t0.Add(2*time.Second)), "9"), testConnection); r.Outcome != outcomeLinked {
			t.Fatalf("%+v", r)
		}
		if err := rig.adapter.deleted(context.Background(), Delivery{Event: "installation", Action: "deleted", InstallationID: 9}); err != nil {
			t.Fatal(err)
		}
		rig.c.stop()
		st.Close()
		clock.sleep(context.Background(), later)
		st = open()
		victim.h = rig.h
		refused(t, victim.finish("installation_id=42&setup_action=install"), refuseOlder)
		made.Store(true)
		rig.c.stop()
		rig.adapter.listRepositories(context.Background(), 42)
		rig.linked(t, 42, "", "")
		st.Close()
	}
}

// TestNoValueInTheAddressChoosesThePage brings /v1/connect/refused with no page cookie
// and a query that names another page: the page is the default, never the one the
// query names.
func TestNoValueInTheAddressChoosesThePage(t *testing.T) {
	rig := newConnectRig(t)
	rec := rig.browser(t).get("/v1/connect/refused?" + pageCookie + "=used&page=used&name=used")
	if strings.Contains(rec.Body.String(), refuseUsed.page) || (rec.Body.String() != refusePass.page+"\n" && rec.Body.String() != refuseQuery.page+"\n") {
		t.Errorf("%d %q", rec.Code, rec.Body)
	}
}

// TestTheSetupURLMakesANewState checks each step's state is new: the install's, after
// the first sign-in, is not the first sign-in's, and the second sign-in's, after the
// Setup URL, is neither; the install's state brought to the callback is refused.
func TestTheSetupURLMakesANewState(t *testing.T) {
	rig := newConnectRig(t)
	b := rig.browser(t)
	first := b.start(rig.pass())
	rec := b.get("/v1/connect/authorized?code=" + signInCode + "&state=" + first)
	m := regexp.MustCompile(`state=([A-Za-z0-9_-]{43})`).FindStringSubmatch(rec.Header().Get("Location") + rec.Body.String())
	if m == nil {
		t.Fatalf("no install state: %v %s", rec.Header(), rec.Body)
	}
	install := m[1]
	rec = b.get("/v1/connect/return?installation_id=42&setup_action=install&state=" + install)
	u, _ := url.Parse(rec.Header().Get("Location"))
	second := u.Query().Get("state")
	if second == "" || second == install || second == first || install == first {
		t.Errorf("the states %q %q %q", first, install, second)
	}
	if r := rig.backTo(t, b.get("/v1/connect/authorized?code="+signInCode+"&state="+install), testConnection); r.Outcome != outcomeRefused || r.Reason != reasonGrantNotConfirmed {
		t.Errorf("%+v", r)
	}
	rig.linked(t, 42, "", "")
}

// TestAReConnectForgetsTheConnectionsRecordAsReplaced re-connects acme's 42, pending
// under C, with a newer pass, while the store holds a record of C as replaced on
// octo-org's 9, as one a build before this fix could leave: the re-connect forgets it,
// with no listing run, so no later listing of C for 9 empties it or ends it.
func TestAReConnectForgetsTheConnectionsRecordAsReplaced(t *testing.T) {
	rig := newConnectRig(t)
	var made atomic.Bool
	twoOrgs(rig, &made)
	now := time.Now().Truncate(time.Second)
	if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, now.Add(5*time.Minute)), "42"), testConnection); r.Outcome != outcomeLinked {
		t.Fatalf("%+v", r)
	}
	// No listing runs from here on.
	rig.c.stop()
	keepReplaced(rig.st, 9, link{Connection: testConnection, Return: now.Add(returnFor).Unix()})
	if r := rig.backTo(t, rig.browser(t).connect(rig.passAt(testConnection, now.Add(10*time.Minute)), "42"), testConnection); r.Outcome != outcomeLinked {
		t.Fatalf("%+v", r)
	}
	rig.linked(t, 42, testConnection, linkPending)
	if _, ok, _ := replacedOf(rig.st, testConnection); ok {
		t.Error("the re-connect kept the connection's record as replaced")
	}
}

// manyRepos has the installation reach n repositories, acme/repo0 and on, which GitHub
// lists on one page.
func manyRepos(rig *connectRig, n int) {
	rig.gh.mu.Lock()
	defer rig.gh.mu.Unlock()
	rig.gh.repos = nil
	for i := range n {
		rig.gh.repos = append(rig.gh.repos, "acme/repo"+strconv.Itoa(i))
	}
}

// listingOf is the listing member of a listing's part as Qory Apiary received it.
func listingOf(r apiaryRequest) map[string]any {
	l, _ := r.body["listing"].(map[string]any)
	return l
}

// TestAFirstListingIsReadOnceAndSentAgainFromThePartNotTaken lists a pending link of
// an installation that reaches 101 repositories, two parts, which Qory Apiary answers
// 403 connection_unknown, then takes part 1, fails part 2 once, passing, with a 500,
// then takes it: each try sends again the part not taken, part 1 after the 403
// connection_unknown and part 2 after its failure, the same listing's parts, id and
// started_at, with no part between them that ends the listing; GitHub's repositories
// are read once; the tries wait a second, then two; and once the link is live and every
// part taken, no listing is kept.
func TestAFirstListingIsReadOnceAndSentAgainFromThePartNotTaken(t *testing.T) {
	rig := newConnectRig(t)
	manyRepos(rig, 101)
	rig.apiary.refuse = func(route string, n int) (int, string) {
		switch {
		case route != routeCollections:
		case n == 1:
			return 403, `{"error":"connection_unknown"}`
		case n == 3:
			return 500, `{"error":"internal"}`
		}
		return 0, ""
	}
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	// Each part keeps each of its collections' installations in the store first, which
	// takes a while.
	for deadline := time.Now().Add(time.Minute); rig.adapter.keptFirsts() != 0 || len(rig.apiary.sent(routeCollections)) < 4; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d parts sent, %d listings kept", len(rig.apiary.sent(routeCollections)), rig.adapter.keptFirsts())
		}
	}
	rig.c.stop()
	sent := rig.apiary.sent(routeCollections)
	if len(sent) != 4 {
		t.Fatalf("%d parts sent", len(sent))
	}
	first := listingOf(sent[0])
	parts := []float64{1, 1, 2, 2}
	for i, want := range parts {
		l := listingOf(sent[i])
		if l["part"] != want || l["id"] != first["id"] || l["started_at"] != first["started_at"] || l["complete"] != (want == 2) {
			t.Errorf("sent %d is %v, want part %v of %v", i+1, l, want, first)
		}
		if j := slices.Index(parts, want); !reflect.DeepEqual(sent[i].body["collections"], sent[j].body["collections"]) {
			t.Errorf("part %v sent again changed", want)
		}
	}
	for i, n := range map[int]int{0: 100, 2: 1} {
		if cols, _ := sent[i].body["collections"].([]any); len(cols) != n {
			t.Errorf("sent %d holds %d collections", i+1, len(cols))
		}
	}
	if n := rig.gh.listings(); n != 1 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
	rig.mu.Lock()
	if !slices.Equal(rig.waits, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("waited %v", rig.waits)
	}
	rig.mu.Unlock()
	rig.linked(t, 42, testConnection, linkLive)
	if inst, ok, _ := reachOf(rig.st, "acme/repo100"); !ok || inst != 42 {
		t.Errorf("the last part's repository's installation is %d", inst)
	}
}

// TestAFirstListing403ConnectionUnknownAfterAPartTakenIsSentAgainFromPart1 lists a
// pending link of an installation that reaches 101 repositories, two parts, whose part
// 1 Qory Apiary takes and whose part 2 it answers 403 connection_unknown: the next try
// sends part 1 again, then part 2, the same listing's parts, id and started_at, and
// GitHub's repositories are read once.
func TestAFirstListing403ConnectionUnknownAfterAPartTakenIsSentAgainFromPart1(t *testing.T) {
	rig := newConnectRig(t)
	manyRepos(rig, 101)
	rig.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeCollections && n == 2 {
			return 403, `{"error":"connection_unknown"}`
		}
		return 0, ""
	}
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	for deadline := time.Now().Add(time.Minute); rig.adapter.keptFirsts() != 0 || len(rig.apiary.sent(routeCollections)) < 4; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d parts sent, %d listings kept", len(rig.apiary.sent(routeCollections)), rig.adapter.keptFirsts())
		}
	}
	rig.c.stop()
	sent := rig.apiary.sent(routeCollections)
	if len(sent) != 4 {
		t.Fatalf("%d parts sent", len(sent))
	}
	first := listingOf(sent[0])
	for i, want := range []float64{1, 2, 1, 2} {
		l := listingOf(sent[i])
		if l["part"] != want || l["id"] != first["id"] || l["started_at"] != first["started_at"] || l["complete"] != (want == 2) {
			t.Errorf("sent %d is %v, want part %v of %v", i+1, l, want, first)
		}
	}
	if !reflect.DeepEqual(sent[0].body["collections"], sent[2].body["collections"]) || !reflect.DeepEqual(sent[1].body["collections"], sent[3].body["collections"]) {
		t.Error("a part sent again changed")
	}
	if n := rig.gh.listings(); n != 1 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
	rig.linked(t, 42, testConnection, linkLive)
}

// TestAFirstListingGitHubFailsMidwayKeepsNothingAndReadsAgain lists a pending link of
// an installation whose three repositories GitHub lists one on a page and fails the
// second page once: the try sends nothing and keeps nothing, and the next, a second
// later, reads GitHub again, and sends the listing, one part, not complete, since it
// read more than one page, which Qory Apiary takes.
func TestAFirstListingGitHubFailsMidwayKeepsNothingAndReadsAgain(t *testing.T) {
	rig := newConnectRig(t)
	manyRepos(rig, 3)
	rig.gh.repoPageSize, rig.gh.repoPageDown = 1, 2
	var mu sync.Mutex
	var waits []time.Duration
	var kept, sentThen []int
	rig.c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		kept = append(kept, rig.adapter.keptFirsts())
		sentThen = append(sentThen, len(rig.apiary.sent(routeCollections)))
		mu.Unlock()
		rig.gh.mu.Lock()
		rig.gh.repoPageDown = 0
		rig.gh.mu.Unlock()
		return nil
	}
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	eventually(t, "live", func() bool { l, _, _ := linkOf(rig.st, 42); return l.State == linkLive })
	eventually(t, "the parts kept forgotten", func() bool { return rig.adapter.keptFirsts() == 0 })
	rig.c.stop()
	mu.Lock()
	if !slices.Equal(waits, []time.Duration{time.Second}) || !slices.Equal(kept, []int{0}) || !slices.Equal(sentThen, []int{0}) {
		t.Errorf("waited %v, keeping %v listings, %v parts sent", waits, kept, sentThen)
	}
	mu.Unlock()
	sent := rig.apiary.sent(routeCollections)
	if cols, _ := sent[0].body["collections"].([]any); len(sent) != 1 || len(cols) != 3 || listingOf(sent[0])["part"] != 1.0 || listingOf(sent[0])["complete"] != false {
		t.Errorf("sent %v", sent)
	}
	if n := rig.gh.listings(); n != 2 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
}

// TestAFirstListingKeptIsForgottenWithItsLink has a pending link's first listing kept
// between its tries, which Qory Apiary answers 403 connection_unknown, and forgotten
// when: a try's 409 connection_ended drops the link; another request's 409
// connection_ended does; GitHub deletes the installation; the installation's
// repositories change, and the next try keeps a listing read again; a connect for
// another connection replaces the link, whose listing kept stays; a newer pass for the
// connection links another installation; and Connect stops.
func TestAFirstListingKeptIsForgottenWithItsLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		// during runs while the first try's wait holds, the listing kept.
		during func(t *testing.T, rig *connectRig)
		// stays is the listing kept that stays, if any.
		stays *firstKey
	}{
		{name: "a try's connection_ended"},
		{name: "another request's connection_ended", during: func(t *testing.T, rig *connectRig) {
			rig.apiary.mu.Lock()
			rig.apiary.refuse = func(route string, _ int) (int, string) { return 409, `{"error":"connection_ended"}` }
			rig.apiary.mu.Unlock()
			rig.adapter.listFor(context.Background(), 42, testConnection)
		}},
		{name: "deleted", during: func(t *testing.T, rig *connectRig) {
			rig.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
		}},
		{name: "repositories changed", during: func(t *testing.T, rig *connectRig) {
			rig.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{}, "repositories_removed": []any{}})
		}},
		{name: "replaced", during: func(t *testing.T, rig *connectRig) {
			if r := rig.backTo(t, rig.browser(t).connect(rig.passFor(otherConnection), "42"), otherConnection); r.Outcome != outcomeLinked {
				t.Fatalf("%+v", r)
			}
		}, stays: &firstKey{42, otherConnection}},
		{name: "a newer pass", during: func(t *testing.T, rig *connectRig) {
			if r := rig.backTo(t, rig.browser(t).connect(rig.passFor(testConnection), "9"), testConnection); r.Outcome != outcomeLinked {
				t.Fatalf("%+v", r)
			}
		}},
		{name: "stop", during: func(t *testing.T, rig *connectRig) { rig.c.stop() }},
	} {
		rig := newConnectRig(t)
		var made atomic.Bool
		twoOrgs(rig, &made)
		if tc.name == "a try's connection_ended" {
			rig.apiary.refuse = func(route string, n int) (int, string) {
				if n == 1 {
					return 403, `{"error":"connection_unknown"}`
				}
				return 409, `{"error":"connection_ended"}`
			}
		}
		gate, gated := make(chan struct{}), make(chan struct{})
		var mu sync.Mutex
		var kept []bool
		rig.c.sleep = func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			kept = append(kept, rig.adapter.keptFirst(42, testConnection))
			n := len(kept)
			mu.Unlock()
			if n == 1 {
				close(gated)
				select {
				case <-gate:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			<-ctx.Done()
			return ctx.Err()
		}
		putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Pass: time.Now().Add(5 * time.Minute).Unix(), Return: time.Now().Add(returnFor).Unix()})
		rig.c.listSoon(42, testConnection, false)
		<-gated
		if tc.during != nil {
			tc.during(t, rig)
			if rig.adapter.keptFirst(42, testConnection) {
				t.Errorf("%s: the listing is kept", tc.name)
			}
		}
		close(gate)
		if tc.stays != nil {
			eventually(t, tc.name+": the other link's listing kept", func() bool { return rig.adapter.keptFirst(tc.stays.installation, tc.stays.connection) })
		}
		switch tc.name {
		case "a try's connection_ended", "another request's connection_ended", "deleted":
			eventually(t, tc.name+": the link dropped", func() bool { ok, _ := Linked(rig.st, 42); return !ok })
			eventually(t, tc.name+": the listing forgotten", func() bool { return rig.adapter.keptFirsts() == 0 })
		case "repositories changed":
			// The next try reads GitHub again, and keeps that listing.
			eventually(t, tc.name+": the next try", func() bool { mu.Lock(); defer mu.Unlock(); return len(kept) == 2 })
			mu.Lock()
			if !kept[1] {
				t.Errorf("%s: the next try keeps no listing", tc.name)
			}
			mu.Unlock()
		}
		mu.Lock()
		if len(kept) == 0 || !kept[0] {
			t.Errorf("%s: kept %v at the waits", tc.name, kept)
		}
		mu.Unlock()
		if tc.stays == nil && tc.name != "repositories changed" && rig.adapter.keptFirsts() != 0 {
			t.Errorf("%s: %d listings kept", tc.name, rig.adapter.keptFirsts())
		}
		if rig.adapter.keptFirst(42, testConnection) && tc.name != "repositories changed" {
			t.Errorf("%s: the listing is kept", tc.name)
		}
		rig.c.stop()
		if n := rig.adapter.keptFirsts(); n != 0 {
			t.Errorf("%s: %d listings kept after stop", tc.name, n)
		}
	}
}

// TestAFirstListingKeptIsForgottenAtTheLastListing lists, on a clock each wait moves
// on, a pending link whose connect return expired now, which Qory Apiary answers 500:
// each try before the last listing's moment sends the listing kept, and from the
// moment on no listing is kept, and each try reads GitHub again.
func TestAFirstListingKeptIsForgottenAtTheLastListing(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(string, int) (int, string) { return 500, `{"error":"internal"}` }
	clock := &pullClock{t: time.Now().Truncate(time.Second)}
	rig.adapter.now, rig.c.now = clock.now, clock.now
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: clock.now().Unix()})
	var mu sync.Mutex
	var kept []int
	rig.c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		kept = append(kept, rig.adapter.keptFirsts())
		n := len(kept)
		mu.Unlock()
		if n >= 13 {
			<-ctx.Done()
			return ctx.Err()
		}
		return clock.sleep(ctx, d)
	}
	rig.c.listSoon(42, testConnection, false)
	eventually(t, "thirteen waits", func() bool { mu.Lock(); defer mu.Unlock(); return len(kept) == 13 })
	rig.c.stop()
	mu.Lock()
	defer mu.Unlock()
	// Ten tries before the moment, the waits a second doubling up to 64 and the rest to
	// the moment, then the last listing's three.
	if want := []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0}; !slices.Equal(kept, want) {
		t.Errorf("listings kept at the waits %v, want %v", kept, want)
	}
	if n := rig.gh.listings(); n != 4 {
		t.Errorf("GitHub's repositories read %d times", n)
	}
	if n := rig.adapter.keptFirsts(); n != 0 {
		t.Errorf("%d listings kept", n)
	}
}

// TestARepositoryRemovedWhileAFirstListingIsReadIsNotKept removes a repository while a
// pending link's first listing reads GitHub, once the page that names it, or the page
// after it, is answered, and runs installation_repositories's first steps meanwhile,
// which drop the installation's tokens and first listings without its lock: that try's
// listing, which names the repository, is sent, and Qory Apiary answers it 403
// connection_unknown, but it is not kept, so the next try reads GitHub again, and the
// listing Qory Apiary takes does not name the repository.
func TestARepositoryRemovedWhileAFirstListingIsReadIsNotKept(t *testing.T) {
	for _, tc := range []struct {
		name          string
		repos         []string
		pageSize, at  int
		removed, kept string
	}{
		{"one page", []string{"acme/widgets", "acme/gadgets"}, 0, 1, "acme/gadgets", "acme/widgets"},
		{"the page that names it", []string{"acme/repo0", "acme/repo1", "acme/repo2"}, 1, 1, "acme/repo0", "acme/repo2"},
		{"the page after it", []string{"acme/repo0", "acme/repo1", "acme/repo2"}, 1, 2, "acme/repo0", "acme/repo1"},
	} {
		rig := newConnectRig(t)
		rig.gh.repos, rig.gh.repoPageSize = tc.repos, tc.pageSize
		once := false
		rig.gh.repoAfter = func(f *fakeGitHub, page int) {
			if once || page != tc.at {
				return
			}
			once = true
			// GitHub has answered the page; now the repository is removed, and the
			// installation_repositories handler's first steps run, outside the lock.
			f.repos = slices.DeleteFunc(slices.Clone(f.repos), func(r string) bool { return r == tc.removed })
			rig.adapter.forgetTokens(42)
			rig.adapter.dropFirsts(42, "")
		}
		rig.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeCollections && n == 1 {
				return 403, `{"error":"connection_unknown"}`
			}
			return 0, ""
		}
		putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
		rig.c.listSoon(42, testConnection, false)
		eventually(t, tc.name+": live", func() bool { l, _, _ := linkOf(rig.st, 42); return l.State == linkLive })
		rig.c.stop()
		sent := rig.apiary.sent(routeCollections)
		if len(sent) != 2 {
			t.Fatalf("%s: %d parts sent", tc.name, len(sent))
		}
		first, _ := json.Marshal(sent[0].body["collections"])
		last, _ := json.Marshal(sent[1].body["collections"])
		if !strings.Contains(string(first), `"ref":"`+tc.removed+`"`) {
			t.Errorf("%s: the try under way sent %s", tc.name, first)
		}
		if strings.Contains(string(last), tc.removed) || !strings.Contains(string(last), `"ref":"`+tc.kept+`"`) {
			t.Errorf("%s: the listing Qory Apiary took names %s, which the installation no longer reaches, or not %s: %s", tc.name, tc.removed, tc.kept, last)
		}
		if listingOf(sent[0])["id"] == listingOf(sent[1])["id"] {
			t.Errorf("%s: the next try sent the listing read before the change", tc.name)
		}
		if n := rig.gh.listings(); n != 2 {
			t.Errorf("%s: GitHub's repositories read %d times", tc.name, n)
		}
		if n := rig.adapter.keptFirsts(); n != 0 {
			t.Errorf("%s: %d listings kept", tc.name, n)
		}
	}
}

// TestAPendingLinkDeletedBetweenItsTriesLeavesNothingOfItInMemory lists a pending
// link, which Qory Apiary answers 403 connection_unknown, and GitHub deletes the
// installation while the first try's wait holds: the tries stop, forgetting the
// connection's first listings as they stop, and the adapter's maps hold nothing of the
// installation.
func TestAPendingLinkDeletedBetweenItsTriesLeavesNothingOfItInMemory(t *testing.T) {
	rig := newConnectRig(t)
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeCollections {
			return 403, `{"error":"connection_unknown"}`
		}
		return 0, ""
	}
	gate, gated := make(chan struct{}), make(chan struct{})
	var once sync.Once
	rig.c.sleep = func(ctx context.Context, d time.Duration) error {
		first := false
		once.Do(func() { first = true })
		if first {
			close(gated)
			select {
			case <-gate:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	rig.c.listSoon(42, testConnection, false)
	<-gated
	if !rig.adapter.keptFirst(42, testConnection) {
		t.Fatal("no listing is kept at the wait")
	}
	rig.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	close(gate)
	eventually(t, "the link dropped", func() bool { ok, _ := Linked(rig.st, 42); return !ok })
	rig.c.stop()
	if held := rig.adapter.heldFor(42); len(held) != 0 {
		t.Errorf("the deleted installation's entries are kept in %v", held)
	}
}
