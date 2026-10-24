package serve

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// appSetup is serve's App setup: how an instance admin creates the GitHub App serve
// runs with, when the settings give none and the state directory keeps none. serve
// declares setup_url, <public_url>/setup, to Qory Apiary while no App is kept; an
// instance admin presses Set up on the adapter's page there, and Qory Apiary sends
// the browser to setup_url with a setup pass it signed. Then:
//
//  1. GET <public_url>/setup?state=<pass> checks the pass, see [checkSetupPass]: its
//     form and its signature, its payload, its adapter and its expiry, then its nonce,
//     which it keeps until the pass expires, so a pass is taken once, a restart
//     notwithstanding. A pass that expired keeps no nonce. Under the lock, it starts a
//     setup session, which replaces the flow under way, if any: the flow pointer, in
//     the store, names the session of the one flow that may go on. It answers 303 to
//     <public_url>/setup/continue, so the pass leaves the address bar; a pass refused
//     answers 303 too, to <public_url>/setup/refused, which shows the page a
//     short-lived cookie names.
//  2. GET /setup/continue shows the form that asks for the GitHub account the App is
//     for, an organisation or a user, with the session's form token.
//  3. POST /setup/continue, with the session's cookie and its form token, looks the
//     account up with GitHub, see [github.Client.Account], and answers the page that
//     posts the App's manifest to GitHub, [github.ServeManifest], named qory- and the
//     account's login, with a new state, which GitHub's redirect returns. The page
//     posts itself with its one script, which the page's Content-Security-Policy
//     allows by its SHA-256, and its button does where the script does not run.
//  4. GET /setup/created?code=...&state=..., GitHub's redirect once the admin pressed
//     Create on GitHub, needs the session's cookie and state, and that the session is
//     still the flow pointer's. Under the lock, it checks again that no App is kept and
//     that the session is still the flow's, then exchanges the code for the App with
//     GitHub, [github.Client.ConvertManifest]: the App is GitHub's answer, never what
//     the browser sends but the code. It sets a webhook secret on the App when GitHub
//     made none, keeps the App in the state directory, see [keepApp], and marks it
//     kept, still under the lock, so of two flows one alone is set up.
//
// The session's cookie, __Secure-qory_github_setup, is for <public_url>/setup alone,
// HttpOnly, Secure and SameSite=Lax, for 900 seconds at most; it holds a random id, and
// the store keeps the session under the id's SHA-256. Every end of a flow drops the
// cookie. serve reads no cookie but the two it sets, by name, and logs no header: a cookie it
// did not set is never logged, kept or sent on. Every redirect's target is built from
// the settings and the session, and a page says nothing the request carries.
//
// Once an App is kept, or when the settings give one, every setup pass is refused with
// a page that says the App is set up already.
type appSetup struct {
	// Store keeps the nonces, the sessions and the flow pointer.
	Store *store.Store
	// GitHub reaches GitHub's API, and its website, see [github.Client.Web].
	GitHub github.Client
	// PublicURL is where serve is reached from outside, without a trailing slash, and
	// ApiaryPublicURL Qory Apiary's origin as a person's browser reaches it, which the
	// page that ends a setup links back to.
	PublicURL       string
	ApiaryPublicURL string
	// StateDir is the state directory, where the App is kept.
	StateDir string
	// Active is public_address: whether the App's webhook is created active.
	Active bool
	// Log takes the setup's lines, and its refusals, once a second at most.
	Log *slog.Logger
	// creds are the pin and the adapter's id a setup pass is checked under, read once
	// for each pass, so a re-enrolment applies at once.
	creds *credentials
	// setUp is called once, with the App kept, under the lock, when a setup keeps one.
	setUp func(*app)

	// now is the clock; nil is time.Now. refusalEvery replaces [refusalEvery] in a
	// test, and waits, when set, is called as a step starts to wait for the lock.
	now          func() time.Time
	refusalEvery time.Duration
	waits        func()

	once sync.Once
	// route is the App setup's path as serve's listener receives it, [setupPath], and
	// base the same path as a browser reaches it: public_url's path, then route. A
	// proxy in front of serve strips public_url's path, so serve matches route and
	// writes base into each cookie, redirect and form it sends.
	route, base string
	refusals    *throttle
	// lock holds one token: the step that holds it starts a session and moves the flow
	// pointer, or keeps the App, one step, see [appSetup.take]. kept is whether an App
	// is kept, or the settings give one, set only while the token is held.
	lock chan struct{}
	kept atomic.Bool
}

// setupPath is the App setup's path under the public URL, which serve declares as
// setup_url.
const setupPath = "/setup"

// The App setup's cookies and the store's namespaces and key it keeps its state in.
const (
	// setupCookie is the session's cookie, for the setup's path alone. Its prefix has
	// a browser take it only when it is Secure.
	setupCookie = "__Secure-qory_github_setup"
	// setupPageCookie names the page /setup/refused shows, for a minute at most, so the
	// request that carries a pass answers 303 to an address without it.
	setupPageCookie = "__Secure-qory_github_setup_page"
	nsSetupNonces   = "setup_nonces"
	nsSetupSessions = "setup_sessions"
	nsSetup         = "setup"
	// keyFlow is the key, in nsSetup, of the flow pointer: the store's key of the one
	// session that may go on.
	keyFlow = "flow"
	// maxAccountForm is the most bytes the account form's body may hold.
	maxAccountForm = 4 << 10
)

// setupSession is what the store keeps of a setup session: when it expires, in Unix
// nanoseconds; the nonce of the pass that started it, and when that pass expires, in
// Unix seconds; the form token the account form carries; and, once the account is
// known, its login and kind, and the state GitHub's redirect must return.
type setupSession struct {
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
	Pass    int64  `json:"pass_expires_at"`
	Token   string `json:"form_token"`
	Login   string `json:"login,omitempty"`
	Kind    string `json:"kind,omitempty"`
	State   string `json:"state,omitempty"`
}

// The App setup's pages, each with its status, the one sentence the browser shows,
// and the reason the log names. name, when set, is how [setupPageCookie] names the
// page; endSession ends the session the request carries, and dropCookie has the
// browser drop the cookie.
var (
	setupRefuseMethod    = refusal{status: http.StatusMethodNotAllowed, page: "This address answers only GET requests.", why: "method"}
	setupRefuseQuery     = refusal{status: http.StatusBadRequest, page: "This setup link is not valid. Press Set up in Qory Apiary again.", why: "query", name: "invalid"}
	setupRefusePass      = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "pass", name: "invalid"}
	setupRefuseSignature = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "signature", name: "invalid"}
	setupRefusePayload   = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "payload", name: "invalid"}
	setupRefuseAdapter   = refusal{status: http.StatusForbidden, page: "This setup link is for another adapter. Press Set up on this adapter's page in Qory Apiary.", why: "adapter", name: "adapter"}
	setupRefuseExpired   = refusal{status: http.StatusBadRequest, page: "This setup link has expired. Press Set up in Qory Apiary again.", why: "expired", name: "expired"}
	setupRefuseUsed      = refusal{status: http.StatusBadRequest, page: "This setup link was used already. Press Set up in Qory Apiary again.", why: "used", name: "used"}
	setupRefuseFailed    = refusal{status: http.StatusInternalServerError, page: "Something failed on this server. Press Set up in Qory Apiary again.", why: "failed", name: "failed", endSession: true}
	setupRefuseNoSession = refusal{status: http.StatusBadRequest, page: "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.", why: "no_session", dropCookie: true}
	setupRefuseForm      = refusal{status: http.StatusBadRequest, page: setupRefuseNoSession.page, why: "form"}
	setupRefuseState     = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "state", endSession: true}
	setupRefuseSetUp     = refusal{status: http.StatusConflict, page: "This adapter's GitHub App is set up already.", why: "set_up", name: "set-up", endSession: true}
)

// setupPages are the pages [setupPageCookie] names, by name.
var setupPages = map[string]*refusal{
	"invalid": &setupRefusePass, "adapter": &setupRefuseAdapter, "expired": &setupRefuseExpired,
	"used": &setupRefuseUsed, "failed": &setupRefuseFailed, "set-up": &setupRefuseSetUp,
}

// The pages that end a setup with an App on GitHub that serve does not keep: a newer
// setup replaced the session's, which links to the account's Apps on GitHub; the App
// GitHub created could not be kept, which links to its settings page; or the code's
// exchange failed, and GitHub may have created an App, which links to the account's
// Apps.
const (
	pageReplaced     = "A newer setup replaced this one. If you created an App on GitHub for it, delete it at "
	pageNotKeptStart = "GitHub created the App "
	pageNotKeptMid   = ", and this server could not keep it. Delete it at "
	pageNotKeptEnd   = ", then press Set up in Qory Apiary again."
	pageMayHave      = "GitHub may have created an App; delete it at "
)

func (a *appSetup) init() {
	a.once.Do(func() {
		u, err := url.Parse(a.PublicURL)
		if err == nil {
			a.base = strings.TrimSuffix(u.Path, "/")
		}
		a.route = setupPath
		a.base += setupPath
		a.lock = make(chan struct{}, 1)
		// A count of refusals held back is said by the next refusal logged.
		a.refusals = &throttle{every: cmp.Or(a.refusalEvery, refusalEvery), now: a.now}
	})
}

func (a *appSetup) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *appSetup) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

// owns is whether the path, as serve's listener receives it, is one of the App
// setup's: [setupPath], or one under it.
func (a *appSetup) owns(path string) bool {
	a.init()
	return path == a.route || strings.HasPrefix(path, a.route+"/")
}

// ServeHTTP answers the App setup's paths. Every answer is never kept by a cache,
// sends no referrer, and is not sniffed; its Content-Security-Policy allows nothing
// but what its page needs.
func (a *appSetup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.init()
	var step func(http.ResponseWriter, *http.Request, url.Values)
	switch r.URL.Path {
	case a.route:
		step = a.start
	case a.route + "/continue":
		step = a.proceed
	case a.route + "/created":
		step = a.created
	case a.route + "/refused":
		step = a.showPage
	default:
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.URL.Path == a.route+"/continue" && r.Method == http.MethodPost {
		a.account(w, r)
		return
	}
	if r.Method != http.MethodGet {
		if r.URL.Path == a.route+"/continue" {
			h.Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// The body is never read: Qory Apiary's form, its fields and its token among
		// them, is not serve's.
		h.Set("Allow", http.MethodGet)
		a.refuse(w, r, setupRefuseMethod, "")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if len(r.URL.RawQuery) > maxConnectQuery || err != nil {
		a.refuse(w, r, setupRefuseQuery, "")
		return
	}
	step(w, r, q)
}

// start is the first step, GET /setup?state=<pass>.
func (a *appSetup) start(w http.ResponseWriter, r *http.Request, q url.Values) {
	if a.kept.Load() {
		a.refuse(w, r, setupRefuseSetUp, "")
		return
	}
	pass, ok := one(q, "state")
	if !ok {
		a.refuse(w, r, setupRefusePass, "")
		return
	}
	now := a.clock()
	p, expires, rf := checkSetupPass(pass, now, a.creds.get())
	if rf != nil {
		a.refuse(w, r, *rf, "")
		return
	}
	// The nonce is kept until the pass has expired, past a restart, and a pass whose
	// nonce is kept already is refused: one check and insert, so of two requests with
	// one pass one passes.
	fresh, err := a.Store.PutNew(nsSetupNonces, p.Nonce, []byte{1}, expires.Sub(now)+time.Second)
	if err != nil {
		a.failed(w, r, "", "nonce", err)
		return
	}
	if !fresh {
		a.refuse(w, r, setupRefuseUsed, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	if !a.take(ctx) {
		a.failed(w, r, "", "lock", ctx.Err())
		return
	}
	defer a.release()
	if a.kept.Load() {
		a.refuse(w, r, setupRefuseSetUp, "")
		return
	}
	id := randomID()
	s := setupSession{Expires: now.Add(sessionFor).UnixNano(), Nonce: p.Nonce, Pass: expires.Unix(), Token: randomID()}
	if err := a.save(id, s); err != nil {
		a.failed(w, r, "", "session", err)
		return
	}
	// The pointer names this session alone from now on: the flow it named before, if
	// any, is replaced, and its next step is refused.
	if err := a.Store.Put(nsSetup, keyFlow, []byte(sessionKey(id)), sessionFor); err != nil {
		a.failed(w, r, "", "flow", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: id, Path: a.base, MaxAge: int(sessionFor / time.Second), Expires: now.Add(sessionFor),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	a.log().LogAttrs(r.Context(), slog.LevelInfo, "setup started", slog.String("step", a.step(r)))
	redirect(w, a.base+"/continue")
}

// checkSetupPass checks a setup pass, in this order, and returns its payload and when
// it expires, or the refusal, as [Connect.checkPass] checks a connect pass:
//
//  1. its form and its signature, over [contracts.SetupDomain], under en's pin, see
//     [signedPayload], before the payload is parsed;
//  2. the payload is one JSON object with the contract's four members and no other,
//     each of the contract's shape, and version 1;
//  3. adapter_id is en's;
//  4. expires_at has not passed on serve's clock, and is at most 15 minutes ahead.
//
// The nonce is checked by the caller, which keeps it.
func checkSetupPass(pass string, now time.Time, en enrolment) (contracts.SetupPass, time.Time, *refusal) {
	payload, fault := signedPayload(pass, contracts.SetupDomain, contracts.SetupPassMaxLength, en.pin)
	switch fault {
	case passMalformed:
		return contracts.SetupPass{}, time.Time{}, &setupRefusePass
	case passForged:
		return contracts.SetupPass{}, time.Time{}, &setupRefuseSignature
	}
	var doc struct {
		Version   *int    `json:"version"`
		AdapterID *string `json:"adapter_id"`
		Nonce     *string `json:"nonce"`
		ExpiresAt *string `json:"expires_at"`
	}
	if !strictObject(payload, &doc) || doc.Version == nil || *doc.Version != contracts.Version || doc.AdapterID == nil || !adapterIDShape.MatchString(*doc.AdapterID) ||
		doc.Nonce == nil || !nonceShape.MatchString(*doc.Nonce) || doc.ExpiresAt == nil {
		return contracts.SetupPass{}, time.Time{}, &setupRefusePayload
	}
	expires, ok := passExpiry(*doc.ExpiresAt)
	if !ok {
		return contracts.SetupPass{}, time.Time{}, &setupRefusePayload
	}
	p := contracts.SetupPass{Version: *doc.Version, AdapterID: *doc.AdapterID, Nonce: *doc.Nonce, ExpiresAt: *doc.ExpiresAt}
	if p.AdapterID != en.adapterID {
		return contracts.SetupPass{}, time.Time{}, &setupRefuseAdapter
	}
	if expiredPass(expires, now) {
		return contracts.SetupPass{}, time.Time{}, &setupRefuseExpired
	}
	return p, expires, nil
}

// flowSession is the request's session, when it is the flow pointer's, or the page
// that refuses the request: no session, a session another flow replaced, or an App
// kept already. It ends the session it refuses. ok is false when it answered.
func (a *appSetup) flowSession(w http.ResponseWriter, r *http.Request) (string, setupSession, bool) {
	id, s, ok, err := a.session(r)
	if err != nil {
		a.failed(w, r, id, "session", err)
		return "", setupSession{}, false
	}
	if !ok {
		a.refuse(w, r, setupRefuseNoSession, "")
		return "", setupSession{}, false
	}
	current, err := a.current(id)
	if err != nil {
		a.failed(w, r, id, "flow", err)
		return "", setupSession{}, false
	}
	if !current {
		a.replaced(w, r, id, s)
		return "", setupSession{}, false
	}
	if a.kept.Load() {
		a.refuse(w, r, setupRefuseSetUp, id)
		return "", setupSession{}, false
	}
	return id, s, true
}

// proceed is GET /setup/continue, where a pass accepted sends the browser: it shows
// the account form.
func (a *appSetup) proceed(w http.ResponseWriter, r *http.Request, _ url.Values) {
	if _, s, ok := a.flowSession(w, r); ok {
		a.accountPage(w, s.Token, "")
	}
}

// account is POST /setup/continue, the account form: with the session's form token,
// it looks the account up with GitHub, shows the form again when GitHub has none by
// that name, and otherwise answers the page that posts the App's manifest to GitHub.
func (a *appSetup) account(w http.ResponseWriter, r *http.Request) {
	id, s, ok := a.flowSession(w, r)
	if !ok {
		return
	}
	form, err := readForm(w, r)
	token, _ := one(form, "token")
	handle, _ := one(form, "account")
	if err != nil || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		a.refuse(w, r, setupRefuseForm, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	login, kind, err := a.GitHub.Account(ctx, strings.TrimSpace(handle))
	if errors.Is(err, github.ErrNoAccount) {
		a.accountPage(w, s.Token, "GitHub has no account by that name.")
		return
	}
	if err != nil {
		a.failed(w, r, id, "account", err)
		return
	}
	s.Login, s.Kind, s.State = login, kind, randomID()
	if err := a.save(id, s); err != nil {
		a.failed(w, r, id, "session", err)
		return
	}
	a.manifestPage(w, s)
}

// readForm reads the request's body, a form of application/x-www-form-urlencoded,
// [maxAccountForm] bytes at most.
func readForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != "application/x-www-form-urlencoded" {
		return nil, http.ErrNotSupported
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAccountForm))
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(b))
}

// created is GitHub's redirect once the App is created, GET
// /setup/created?code=...&state=..., which needs the session, its state, and that the
// session is the flow pointer's. Under the lock, it checks that again and that no App
// is kept, then exchanges the code for the App, which GitHub's answer alone says, and
// keeps it, see [keepApp].
func (a *appSetup) created(w http.ResponseWriter, r *http.Request, q url.Values) {
	id, s, ok := a.flowSession(w, r)
	if !ok {
		return
	}
	state, okState := one(q, "state")
	code, okCode := one(q, "code")
	if s.State == "" || !okState || !okCode || subtle.ConstantTimeCompare([]byte(state), []byte(s.State)) != 1 || !codeShape.MatchString(code) {
		a.refuse(w, r, setupRefuseState, id)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	if !a.take(ctx) {
		a.failed(w, r, id, "lock", ctx.Err())
		return
	}
	defer a.release()
	// A flow that replaced this one meanwhile, or set up an App, ends this one before
	// its code is exchanged: of two flows, one alone is set up.
	current, err := a.current(id)
	if err != nil {
		a.failed(w, r, id, "flow", err)
		return
	}
	if !current {
		a.replaced(w, r, id, s)
		return
	}
	if a.kept.Load() || hasApp(a.StateDir) {
		a.refuse(w, r, setupRefuseSetUp, id)
		return
	}
	conv, err := a.GitHub.ConvertManifest(ctx, code)
	if err != nil {
		a.notKept(w, r, id, s, nil, "conversion", err)
		return
	}
	a.log().LogAttrs(r.Context(), slog.LevelInfo, "GitHub created the App", slog.Int64("app_id", conv.ID), slog.String("slug", conv.Slug), slog.String("html_url", conv.HTMLURL))
	kept, err := a.keep(ctx, conv, s)
	if err != nil {
		a.notKept(w, r, id, s, &conv, "keep", err)
		return
	}
	a.kept.Store(true)
	a.endSession(w, id)
	a.log().LogAttrs(r.Context(), slog.LevelInfo, "the GitHub App is set up", slog.Int64("app_id", kept.numericID), slog.String("slug", kept.slug), slog.Bool("webhook_active", kept.webhookActive))
	if a.setUp != nil {
		a.setUp(kept)
	}
	a.donePage(w, kept.slug)
}

// keep checks the App conv, as GitHub answered the code's exchange, and keeps it in
// the state directory, see [keepApp]: its private key must be an RSA key, as
// qory-github setup takes one, and no larger than serve reads back from the state
// directory, the line break keepApp writes at its end counted; its slug, client id and
// client secret must be ones serve takes and reads back from the state directory; a
// webhook secret in the answer must be one serve's receiver takes; and neither its key nor a secret may hold what looks like an access key secret or a
// run key. An error never holds a secret. When GitHub made the App no webhook secret,
// keep makes one and sets it on the App's webhook; when GitHub does not confirm it,
// the App is kept all the same, its webhook secret not confirmed, which serve sets
// again at its next start, see [Run]. The account that owns the App is GitHub's
// answer's, or the session's when the answer names none serve takes, see [ownerOf].
func (a *appSetup) keep(ctx context.Context, conv github.Conversion, s setupSession) (*app, error) {
	pemBytes := bytes.TrimRight([]byte(conv.PEM), "\r\n")
	if len(pemBytes)+1 > github.MaxKeyFile {
		return nil, errors.New(answerLargeKey)
	}
	key, err := github.ParseKey(pemBytes)
	if err != nil {
		return nil, err
	}
	if err := noKeyInAnswer(pemBytes); err != nil {
		return nil, err
	}
	if github.CheckSlug(conv.Slug) != nil {
		return nil, errors.New(answerNoSlug)
	}
	if err := noKeyInAnswer([]byte(conv.ClientSecret)); err != nil {
		return nil, err
	}
	if !appIDShape.MatchString(conv.ClientID) || conv.ClientSecret == "" || len(conv.ClientSecret)+1 > maxClientSecretFile || strings.ContainsFunc(conv.ClientSecret, unkeepable) {
		return nil, errors.New(answerNoClient)
	}
	secret, confirmed := conv.WebhookSecret, true
	if secret == "" {
		secret = github.NewWebhookSecret()
		if err := a.GitHub.SetAppWebhookSecret(ctx, conv.ID, key, secret); err != nil {
			confirmed = false
			a.log().Warn("GitHub did not confirm the App's webhook secret; serve sets it again at its next start", slog.Int64("app_id", conv.ID), slog.String("error", err.Error()))
		}
	} else {
		if err := noKeyInAnswer([]byte(secret)); err != nil {
			return nil, err
		}
		if len(secret) < github.MinWebhookSecret || len(secret)+1 > github.MaxWebhookSecretFile || strings.ContainsFunc(secret, unkeepable) {
			return nil, errors.New(answerBadWebhookSecret)
		}
	}
	owner, kind := ownerOf(conv, s)
	k := keptApp{AppID: conv.ID, AppSlug: conv.Slug, ClientID: conv.ClientID, Owner: owner, OwnerKind: kind, WebhookActive: a.Active, WebhookSecretConfirmed: confirmed}
	webhookSecret, clientSecret := []byte(secret), []byte(conv.ClientSecret)
	if err := keepApp(a.StateDir, k, pemBytes, webhookSecret, clientSecret); err != nil {
		return nil, err
	}
	return &app{
		id: strconv.FormatInt(conv.ID, 10), slug: conv.Slug, clientID: conv.ClientID, key: key, webhookSecret: webhookSecret, clientSecret: clientSecret,
		webhookActive: a.Active, kept: true, numericID: conv.ID, owner: owner, ownerKind: kind, confirmed: confirmed,
	}, nil
}

// The words of the checks of GitHub's answer to the code's exchange: answerNoClient and
// answerBadWebhookSecret say a client id, client secret or webhook secret serve cannot
// keep; answerNoSlug says a slug serve cannot keep, answerLargeKey a private key larger
// than serve reads back from the state directory, and answerAccessKey and answerRunKey
// what looks like an access key secret or a run key in the answer's key or a secret.
const (
	answerAccessKey        = "GitHub's answer holds what looks like an access key secret, qak_, which belongs nowhere in it"
	answerRunKey           = "GitHub's answer holds what looks like a run key, qrk_, which belongs nowhere in it"
	answerLargeKey         = "GitHub's answer holds a private key larger than setup can keep"
	answerNoSlug           = "GitHub's answer holds no App slug setup can keep"
	answerNoClient         = "GitHub's answer holds no client id, or no client secret setup can keep"
	answerBadWebhookSecret = "GitHub's answer holds a webhook secret qory-github-server serve cannot use"
)

// noKeyInAnswer refuses the bytes b of the private key or a secret in GitHub's answer
// when they hold what looks like an access key secret or a run key, as [secretIn] finds
// one. The error quotes nothing.
func noKeyInAnswer(b []byte) error {
	switch err := secretIn(b); {
	case err == nil:
		return nil
	case errors.Is(err, errRunKeyInSettings):
		return errors.New(answerRunKey)
	}
	return errors.New(answerAccessKey)
}

// unkeepable is whether r is white space or a control character, which no secret serve
// keeps holds.
func unkeepable(r rune) bool { return r <= ' ' || r >= 0x7f }

// ownerOf is the account that owns the App conv, as GitHub's answer names it, or the
// session s's account when the answer names none serve takes: a login of 39 characters
// at most and an organisation or a user.
func ownerOf(conv github.Conversion, s setupSession) (string, string) {
	owner, kind := conv.Owner.Login, conv.Owner.Type
	if len(owner) > 39 || !loginShape.MatchString(owner) || (kind != github.AccountOrganization && kind != github.AccountUser) {
		return s.Login, s.Kind
	}
	return owner, kind
}

// notKept ends the flow whose App GitHub created, or may have, and serve does not
// keep: it logs what failed with the error, and the page says to delete the App on
// GitHub, at its settings page when conv names a slug serve takes, or else at the
// account's Apps.
func (a *appSetup) notKept(w http.ResponseWriter, r *http.Request, id string, s setupSession, conv *github.Conversion, what string, err error) {
	a.log().LogAttrs(r.Context(), slog.LevelError, "setup failed", slog.String("step", a.step(r)), slog.String("what", what), slog.String("error", err.Error()))
	web := a.GitHub.Web()
	rf := refusal{status: http.StatusBadGateway, why: "not_kept", endSession: true}
	if conv == nil || github.CheckSlug(conv.Slug) != nil {
		rf.page = pageMayHave + github.AppsURL(web, orgOf(s.Login, s.Kind)) + pageNotKeptEnd
	} else {
		rf.status = http.StatusInternalServerError
		owner := app{slug: conv.Slug}
		owner.owner, owner.ownerKind = ownerOf(*conv, s)
		rf.page = pageNotKeptStart + conv.Slug + pageNotKeptMid + owner.settingsURL(web) + pageNotKeptEnd
	}
	a.refuse(w, r, rf, id)
}

// replaced ends the session id, which a newer flow replaced: its page says to delete
// an App created for it, at the Apps of the account it named, if any.
func (a *appSetup) replaced(w http.ResponseWriter, r *http.Request, id string, s setupSession) {
	rf := refusal{status: http.StatusConflict, why: "replaced", endSession: true}
	rf.page = pageReplaced + github.AppsURL(a.GitHub.Web(), orgOf(s.Login, s.Kind)) + "."
	a.refuse(w, r, rf, id)
}

// showPage is GET /setup/refused, where a pass refused sends the browser: it shows the
// page [setupPageCookie] names, or the one for a pass that is not valid when it names
// none, and drops the cookie. The refusal was logged as it was made.
func (a *appSetup) showPage(w http.ResponseWriter, r *http.Request, _ url.Values) {
	rf := setupRefusePass
	if ck, err := r.Cookie(setupPageCookie); err == nil && setupPages[ck.Value] != nil {
		rf = *setupPages[ck.Value]
	}
	http.SetCookie(w, &http.Cookie{Name: setupPageCookie, Value: "", Path: a.base, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	plainPage(w, rf.status, rf.page)
}

// plainPage answers status with the one line line, as text.
func plainPage(w http.ResponseWriter, status int, line string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, line+"\n")
}

// accountPageHTML is the account form, which posts the account's handle and the
// session's form token to /setup/continue.
var accountPageHTML = template.Must(template.New("account").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github</title>
<h1>{{.Heading}}</h1>
{{if .Line}}<p>{{.Line}}</p>
{{end}}<form method="post" action="{{.Action}}">
<label>{{.Label}} <input name="account" required maxlength="39" autocomplete="off"></label>
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit">{{.Button}}</button>
</form>
`))

// accountPage answers the account form, with line above it when it is set.
func (a *appSetup) accountPage(w http.ResponseWriter, token, line string) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	accountPageHTML.Execute(w, map[string]string{
		"Heading": "Set up the GitHub App", "Line": line, "Action": a.base + "/continue",
		"Label": "GitHub account for the App, an organisation or a user", "Token": token, "Button": "Continue",
	})
}

// manifestPageHTML is the page that posts the App's manifest to GitHub, as setup's
// does: its one script posts the form, and its button does where the script does not
// run.
var manifestPageHTML = template.Must(template.New("manifest").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github</title>
<p>{{.Line}}</p>
{{if .SignIn}}<p>{{.SignIn}}</p>
{{end}}<form id="f" method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<button type="submit">{{.Button}}</button>
</form>
<script>` + github.SubmitScript + `</script>
`))

// submitScriptHash is the source of a Content-Security-Policy that allows the manifest
// page's one script, [github.SubmitScript], by its SHA-256.
var submitScriptHash = func() string {
	sum := sha256.Sum256([]byte(github.SubmitScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// manifestPage answers the page that posts the manifest of the App, named qory- and the
// login of the account s names, to GitHub, with s's state, to be created under the
// account: an organisation's, or, for a user, the person signed in on GitHub, whom the
// page asks to be that user.
func (a *appSetup) manifestPage(w http.ResponseWriter, s setupSession) {
	web := a.GitHub.Web()
	manifest, _ := json.Marshal(github.ServeManifest("qory-"+s.Login, a.PublicURL+setupPath+"/created", a.PublicURL, a.Active))
	signIn := ""
	if s.Kind == github.AccountUser {
		signIn = "Sign in to GitHub as " + s.Login + " to create the App."
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action "+web+"; script-src "+submitScriptHash)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	manifestPageHTML.Execute(w, map[string]string{
		"Line":   "GitHub opens with the App filled in, named qory-" + s.Login + "; you can change the name there.",
		"SignIn": signIn, "Action": github.ManifestAction(web, orgOf(s.Login, s.Kind), s.State), "Manifest": string(manifest),
		"Button": "Create the GitHub App",
	})
}

// donePageHTML is the page that ends a setup that kept the App, which links back to
// Qory Apiary.
var donePageHTML = template.Must(template.New("done").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github</title>
<p>{{.Line}}</p>
{{if .Pulls}}<p>{{.Pulls}}</p>
{{end}}<p><a href="{{.Target}}">{{.Link}}</a></p>
`))

// donePage answers the page that says the App slug is set up, and, when its webhook is
// inactive, that GitHub sends it none.
func (a *appSetup) donePage(w http.ResponseWriter, slug string) {
	pulls := ""
	if !a.Active {
		pulls = "GitHub sends this App no webhooks: changes on GitHub arrive with each pull."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	donePageHTML.Execute(w, map[string]string{
		"Line":   "The GitHub App " + slug + " is set up. Organisations install it with Install in Qory Apiary.",
		"Pulls":  pulls,
		"Target": a.ApiaryPublicURL, "Link": "Back to Qory Apiary",
	})
}

// save keeps the session under its id until it expires.
func (a *appSetup) save(id string, s setupSession) error {
	ttl := time.Unix(0, s.Expires).Sub(a.clock())
	if ttl <= 0 {
		return errors.New("the session has expired")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return a.Store.Put(nsSetupSessions, sessionKey(id), b, ttl)
}

// session is the request's session, by the id its cookie carries, or false when it
// carries none, or one the store does not know or that has expired. It reads no
// cookie but [setupCookie].
func (a *appSetup) session(r *http.Request) (string, setupSession, bool, error) {
	ck, err := r.Cookie(setupCookie)
	if err != nil || !idShape.MatchString(ck.Value) {
		return "", setupSession{}, false, nil
	}
	b, err := a.Store.Get(nsSetupSessions, sessionKey(ck.Value))
	if errors.Is(err, store.ErrNotFound) {
		return "", setupSession{}, false, nil
	}
	if err != nil {
		return ck.Value, setupSession{}, false, err
	}
	var s setupSession
	if json.Unmarshal(b, &s) != nil || !a.clock().Before(time.Unix(0, s.Expires)) || !nonceShape.MatchString(s.Nonce) || !idShape.MatchString(s.Token) {
		return "", setupSession{}, false, nil
	}
	return ck.Value, s, true, nil
}

// current is whether the session id is the flow pointer's.
func (a *appSetup) current(id string) (bool, error) {
	b, err := a.Store.Get(nsSetup, keyFlow)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(b, []byte(sessionKey(id))) == 1, nil
}

// endSession ends the session: it drops it from the store, when id is set, and has the
// browser drop the cookie. The flow pointer is left: it names no session then, and the
// next pass replaces it.
func (a *appSetup) endSession(w http.ResponseWriter, id string) {
	if id != "" {
		if err := a.Store.Delete(nsSetupSessions, sessionKey(id)); err != nil {
			a.log().Error("setup failed", slog.String("step", "end"), slog.String("what", "session"), slog.String("error", err.Error()))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: "", Path: a.base, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// take takes the lock's token, waiting for it until ctx is done, and says whether it
// took it. waits, when set, is called as it starts to wait.
func (a *appSetup) take(ctx context.Context) bool {
	select {
	case a.lock <- struct{}{}:
		return true
	default:
	}
	if a.waits != nil {
		a.waits()
	}
	select {
	case a.lock <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// release gives the lock's token back.
func (a *appSetup) release() { <-a.lock }

// markKept marks an App kept, or given by the settings, from the start: every setup
// pass is refused.
func (a *appSetup) markKept() {
	a.init()
	a.lock <- struct{}{}
	a.kept.Store(true)
	<-a.lock
}

// refuse answers the refusal's page, or, for the request that may carry a pass, a 303
// to /setup/refused, which shows it, see [setupPageCookie]; ends the session id names
// when the refusal ends it, has the browser drop the cookie when the refusal says so,
// and logs the refusal once each [refusalEvery] at most. A line names the request's
// step, the status and the reason, never a pass, a code, a cookie or what the request
// carries.
func (a *appSetup) refuse(w http.ResponseWriter, r *http.Request, rf refusal, id string) {
	if !rf.endSession {
		id = ""
	}
	if _, err := r.Cookie(setupCookie); (err == nil && rf.dropCookie) || rf.endSession {
		a.endSession(w, id)
	}
	status := rf.status
	if r.URL.Path == a.route && r.Method == http.MethodGet && rf.name != "" {
		// The request may carry a pass, so the page shows at an address without it.
		status = http.StatusSeeOther
		http.SetCookie(w, &http.Cookie{
			Name: setupPageCookie, Value: rf.name, Path: a.base, MaxAge: int(pageFor / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		redirect(w, a.base+"/refused")
	} else {
		plainPage(w, rf.status, rf.page)
	}
	ok, dropped := a.refusals.allow()
	if !ok {
		return
	}
	line := []slog.Attr{slog.String("step", a.step(r)), slog.Int("status", status), slog.String("reason", rf.why)}
	if dropped > 0 {
		line = append(line, slog.Int("refusals_dropped", dropped))
	}
	a.log().LogAttrs(r.Context(), slog.LevelInfo, "setup refused", line...)
}

// failed answers that something failed on serve, ends the session id names, and logs
// what failed with the error.
func (a *appSetup) failed(w http.ResponseWriter, r *http.Request, id, what string, err error) {
	if err == nil {
		err = context.DeadlineExceeded
	}
	a.log().LogAttrs(r.Context(), slog.LevelError, "setup failed", slog.String("step", a.step(r)), slog.String("what", what), slog.String("error", err.Error()))
	a.refuse(w, r, setupRefuseFailed, id)
}

// step names the request's step for the log: setup, continue, account, created or
// refused.
func (a *appSetup) step(r *http.Request) string {
	switch r.URL.Path {
	case a.route + "/continue":
		if r.Method == http.MethodPost {
			return "account"
		}
		return "continue"
	case a.route + "/created":
		return "created"
	case a.route + "/refused":
		return "refused"
	}
	return "setup"
}
