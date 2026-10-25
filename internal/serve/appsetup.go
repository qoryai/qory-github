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
// runs with, when Qory Apiary stores none. serve declares setup_url,
// <public_url>/setup, to Qory Apiary while no App is set up; an
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
//     for, an organisation or a user, and who can install the App: only that account,
//     a private App, which the form selects first, or any GitHub account, a public
//     App. The form carries the session's form token.
//  3. POST /setup/continue, with the session's cookie and its form token, takes the
//     choice only as one of its two values, looks the account up with GitHub, see
//     [github.Client.Account], keeps the account and the choice in the session, and
//     answers the page that posts the App's manifest to GitHub,
//     [github.ServeManifest], named qory- and the account's login, private or public
//     as chosen, with a new state, which GitHub's redirect returns. A later POST
//     replaces the account, the choice and the state, so GitHub's redirect for an
//     earlier page is refused. The page posts itself with its one script, which the
//     page's Content-Security-Policy allows by its SHA-256, and its button does where
//     the script does not run.
//  4. GET /setup/created?code=...&state=..., GitHub's redirect once the admin pressed
//     Create on GitHub, needs the session's cookie and state, and that the session is
//     still the flow pointer's. Under the lock, it checks again that no App is set up
//     or being stored, and that the session is still the flow's, then exchanges the
//     code for the App with GitHub, [github.Client.ConvertManifest]: the App is
//     GitHub's answer, never what the browser sends but the code. It sets a webhook
//     secret on the App when GitHub made none, and stores the App in Qory Apiary, see
//     [runner.upload], still under the lock, so of two flows one alone is set up. The
//     App is kept in memory alone: nothing of it is written to disk.
//  5. GitHub issues the App's private key once, at the exchange. When the upload
//     fails, the setup keeps the App in memory and tries again for upload_retry_seconds,
//     see [appSetup.retry], and the browser is sent to GET /setup/status, which shows
//     that it tries again and reloads itself until the upload ends: with the page that
//     says the App is set up, or, once every try failed, the page that says to delete
//     the App on GitHub. While the setup tries again, every setup pass is refused.
//
// The session's cookie, __Secure-qory_github_setup, is for <public_url>/setup alone,
// HttpOnly, Secure and SameSite=Lax, for 900 seconds at most, or, while the setup tries
// again to store the App, for upload_retry_seconds and 900 seconds more at most; it
// contains a random id, and the store keeps the session under the id's SHA-256. Every
// end of a flow drops the cookie. serve reads no cookie but the two it sets, by name,
// and logs no header: a cookie it did not set is never logged, kept or sent on. Every
// redirect's target is built from the settings and the session, and a page says
// nothing the request carries.
//
// Once an App is set up, every setup pass is refused with a page that says the App is
// set up already.
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
	// Upload stores an App in Qory Apiary, see [runner.upload], and UploadFor is how
	// long the setup tries again when an upload fails, upload_retry_seconds.
	Upload    func(context.Context, *app) error
	UploadFor time.Duration
	// Active is public_address: whether the App's webhook is created active.
	Active bool
	// Log takes the setup's lines, and its refusals, once a second at most.
	Log *slog.Logger
	// creds are the pin and the adapter's id a setup pass is checked under, read once
	// for each pass, so a re-enrolment applies at once.
	creds *credentials
	// setUp is called once, with the App stored, under the lock, when a setup stores
	// one in Qory Apiary.
	setUp func(*app)
	// ctx is Run's, done when serve stops, which ends the tries of an upload; wait, when
	// set, replaces the waits between them.
	ctx  context.Context
	wait func(context.Context, time.Duration) error

	// now is the clock; nil is time.Now. refusalEvery replaces [refusalEvery] in a
	// test, and waits, when set, is called as a step starts to wait for the lock.
	now          func() time.Time
	refusalEvery time.Duration
	waits        func()

	once     sync.Once
	refusals *throttle
	// lock holds one token: the step that holds it starts a session and moves the flow
	// pointer, or stores the App, one step, see [appSetup.take]. kept is whether an App
	// is set up, set only while the token is held.
	lock chan struct{}
	kept atomic.Bool
	// mu guards pending, the App whose upload is tried again, or was, nil when none is;
	// tries counts the goroutines of [appSetup.retry], which the stop waits for.
	mu      sync.Mutex
	pending *pendingUpload
	tries   sync.WaitGroup
}

// pendingUpload is an App GitHub created whose first upload to Qory Apiary failed: the
// App, whether it is public, until when the setup tries again, the store's key of the
// session that set it up, and how its tries ended.
type pendingUpload struct {
	app     *app
	public  bool
	until   time.Time
	session string
	state   uploadState
}

// uploadState is where the tries of a [pendingUpload] are: under way, stored, or
// failed, every try failed or serve stopped first.
type uploadState int

const (
	uploadTrying uploadState = iota
	uploadStored
	uploadFailed
)

// The bounds of an upload of the App: the first, made while GitHub's redirect waits,
// is answered within firstUploadBound; then the tries again wait from
// uploadFirstWait, doubling, to uploadMaxWait between them; the status page reloads
// itself every statusEvery seconds while they go on.
const (
	firstUploadBound = 15 * time.Second
	uploadFirstWait  = 2 * time.Second
	uploadMaxWait    = 30 * time.Second
	statusEvery      = 10
)

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
	// installPrivate and installPublic are the two values of the account form's
	// field install: the App is private, or public.
	installPrivate = "private"
	installPublic  = "public"
)

// setupSession is what the store keeps of a setup session: when it expires, in Unix
// nanoseconds; the nonce of the pass that started it, and when that pass expires, in
// Unix seconds; the form token the account form carries; and, once the account is
// known, its login and kind, whether the App is public, and the state GitHub's redirect
// must return.
type setupSession struct {
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
	Pass    int64  `json:"pass_expires_at"`
	Token   string `json:"form_token"`
	Login   string `json:"login,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Public  bool   `json:"public,omitempty"`
	State   string `json:"state,omitempty"`
	// Uploading is whether the setup tries again to store the session's App in Qory
	// Apiary, see [appSetup.retry].
	Uploading bool `json:"uploading,omitempty"`
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
	setupRefusePending   = refusal{status: http.StatusConflict, page: "Wait until the earlier setup ends, then press Set up in Qory Apiary again if this adapter's GitHub App is still not set up. An earlier setup is storing its App in Qory Apiary.", why: "pending", name: "pending"}
)

// setupPages are the pages [setupPageCookie] names, by name.
var setupPages = map[string]*refusal{
	"invalid": &setupRefusePass, "adapter": &setupRefuseAdapter, "expired": &setupRefuseExpired,
	"used": &setupRefuseUsed, "failed": &setupRefuseFailed, "set-up": &setupRefuseSetUp, "pending": &setupRefusePending,
}

// The pages that end a setup with an App on GitHub that serve does not use: a newer
// setup replaced the session's, which links to the account's Apps on GitHub; the App
// GitHub created could not be used, which links to its settings page; or the code's
// exchange failed, and GitHub may have created an App, which links to the account's
// Apps. pageNotStored ends a setup whose every upload of the App failed, see
// [appSetup.status].
const (
	pageReplaced     = "A newer setup replaced this one. If you created an App on GitHub for it, delete it at "
	pageNotKeptStart = "GitHub created the App "
	pageNotKeptMid   = ", and this server could not use it. Delete it at "
	pageNotKeptEnd   = ", then press Set up in Qory Apiary again."
	pageMayHave      = "GitHub may have created an App; delete it at "
	// pageNotStored is followed by the App's slug, pageNotStoredAt, its settings page,
	// pageNotStoredEnd, and when the tries ended.
	pageNotStored    = "Delete the GitHub App "
	pageNotStoredAt  = " at "
	pageNotStoredEnd = ", then press Set up in Qory Apiary again. This server could not store the App in Qory Apiary by "
)

func (a *appSetup) init() {
	a.once.Do(func() {
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

// owns is whether the path is one of the App setup's: [setupPath], or one under it.
func (a *appSetup) owns(path string) bool {
	a.init()
	return path == setupPath || strings.HasPrefix(path, setupPath+"/")
}

// ServeHTTP answers the App setup's paths. Every answer is never kept by a cache,
// sends no referrer, and is not sniffed; its Content-Security-Policy allows nothing
// but what its page needs.
func (a *appSetup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.init()
	var step func(http.ResponseWriter, *http.Request, url.Values)
	switch r.URL.Path {
	case setupPath:
		step = a.start
	case setupPath + "/continue":
		step = a.proceed
	case setupPath + "/created":
		step = a.created
	case setupPath + "/refused":
		step = a.showPage
	case setupPath + "/status":
		step = a.status
	default:
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.URL.Path == setupPath+"/continue" && r.Method == http.MethodPost {
		a.account(w, r)
		return
	}
	if r.Method != http.MethodGet {
		if r.URL.Path == setupPath+"/continue" {
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
	if a.trying() {
		a.refuse(w, r, setupRefusePending, "")
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
	if a.trying() {
		a.refuse(w, r, setupRefusePending, "")
		return
	}
	a.mu.Lock()
	// The tries of an earlier setup have ended, and its status page ends with them.
	a.pending = nil
	a.mu.Unlock()
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
		Name: setupCookie, Value: id, Path: setupPath, MaxAge: int(sessionFor / time.Second), Expires: now.Add(sessionFor),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	a.log().LogAttrs(r.Context(), slog.LevelInfo, "setup started", slog.String("step", a.step(r)))
	redirect(w, setupPath+"/continue")
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
	if a.trying() {
		a.refuse(w, r, setupRefusePending, "")
		return "", setupSession{}, false
	}
	return id, s, true
}

// proceed is GET /setup/continue, where a pass accepted sends the browser: it shows
// the account form.
func (a *appSetup) proceed(w http.ResponseWriter, r *http.Request, _ url.Values) {
	if _, s, ok := a.flowSession(w, r); ok {
		a.accountPage(w, s.Token, "", false)
	}
}

// account is POST /setup/continue, the account form: with the session's form token,
// it shows the form again when install is not exactly one of its two values, before
// any call to GitHub; it looks the account up with GitHub, shows the form again when
// GitHub has none by that name, and otherwise keeps the account and the choice in the
// session and answers the page that posts the App's manifest to GitHub.
func (a *appSetup) account(w http.ResponseWriter, r *http.Request) {
	id, s, ok := a.flowSession(w, r)
	if !ok {
		return
	}
	form, err := readForm(w, r)
	token, _ := one(form, "token")
	handle, _ := one(form, "account")
	install, _ := one(form, "install")
	if err != nil || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		a.refuse(w, r, setupRefuseForm, "")
		return
	}
	if install != installPrivate && install != installPublic {
		a.accountPage(w, s.Token, "Choose who can install the App: only this account, or any GitHub account.", false)
		return
	}
	public := install == installPublic
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	login, kind, err := a.GitHub.Account(ctx, strings.TrimSpace(handle))
	if errors.Is(err, github.ErrNoAccount) {
		a.accountPage(w, s.Token, "GitHub has no account by that name.", public)
		return
	}
	if err != nil {
		a.failed(w, r, id, "account", err)
		return
	}
	s.Login, s.Kind, s.Public, s.State = login, kind, public, randomID()
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
// is set up or being stored, then exchanges the code for the App, which GitHub's
// answer alone says, checks it, see [appSetup.keep], and stores it in Qory Apiary.
// When that first upload fails, it tries again, see [appSetup.retry], and sends the
// browser to the status page.
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
	if a.kept.Load() {
		a.refuse(w, r, setupRefuseSetUp, id)
		return
	}
	if a.trying() {
		a.refuse(w, r, setupRefusePending, "")
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
	first, cancelFirst := context.WithTimeout(ctx, firstUploadBound)
	err = a.Upload(first, kept)
	cancelFirst()
	if err == nil {
		a.stored(r.Context(), kept)
		a.endSession(w, id)
		a.donePage(w, kept, s.Public)
		return
	}
	now := a.clock()
	until := now.Add(a.UploadFor)
	a.log().LogAttrs(r.Context(), slog.LevelWarn, "storing the GitHub App in Qory Apiary failed; the setup tries again", slog.Int64("app_id", kept.numericID),
		slog.String("slug", kept.slug), slog.String("until", contracts.FormatTime(until)), slog.String("error", err.Error()))
	// The session lasts while the setup tries again, and for sessionFor after, so the
	// status page shows how the tries ended.
	s.Uploading = true
	s.Expires = until.Add(sessionFor).UnixNano()
	if err := a.save(id, s); err != nil {
		a.log().Error("setup failed", slog.String("step", a.step(r)), slog.String("what", "session"), slog.String("error", err.Error()))
	}
	p := &pendingUpload{app: kept, public: s.Public, until: until, session: sessionKey(id)}
	a.mu.Lock()
	a.pending = p
	a.mu.Unlock()
	a.tries.Add(1)
	go a.retry(p)
	lasts := time.Unix(0, s.Expires).Sub(now)
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: id, Path: setupPath, MaxAge: int(lasts / time.Second), Expires: now.Add(lasts),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	redirect(w, setupPath+"/status")
}

// stored marks the App k set up, logs it, and hands it to serve, see [appSetup.setUp].
// It runs only after Qory Apiary accepted the upload of k, so serve sends its start-up
// body without setup_url after that upload, and never while the setup tries again or
// after every try failed, as adapter-secrets.schema.json:5 orders it. The upload
// itself follows a start-up body: the setup pass that starts the flow comes from Qory
// Apiary, which has setup_url from the start-up body with it. The lock is held.
func (a *appSetup) stored(ctx context.Context, k *app) {
	a.kept.Store(true)
	a.log().LogAttrs(ctx, slog.LevelInfo, "the GitHub App is set up", slog.Int64("app_id", k.numericID), slog.String("slug", k.slug), slog.Bool("webhook_active", k.webhookActive))
	if a.setUp != nil {
		a.setUp(k)
	}
}

// trying is whether the setup tries again to store an App in Qory Apiary.
func (a *appSetup) trying() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending != nil && a.pending.state == uploadTrying
}

// retry tries again to store the App of p in Qory Apiary, after a wait that doubles
// from [uploadFirstWait] to [uploadMaxWait], until p's until or until serve stops. Once
// an upload succeeds, it marks the App set up under the lock, see [appSetup.stored].
// When none does, the App's secrets are dropped from memory, a line names the App to
// delete on GitHub, and a new setup may start.
func (a *appSetup) retry(p *pendingUpload) {
	defer a.tries.Done()
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithDeadline(parent, p.until)
	defer cancel()
	wait := uploadFirstWait
	for {
		if a.pause(ctx, wait) != nil {
			break
		}
		err := a.Upload(ctx, p.app)
		if err == nil {
			a.lock <- struct{}{}
			a.mu.Lock()
			p.state = uploadStored
			a.mu.Unlock()
			a.stored(context.Background(), p.app)
			<-a.lock
			return
		}
		if ctx.Err() != nil {
			break
		}
		a.log().Warn("storing the GitHub App in Qory Apiary failed again; the setup tries again", slog.Int64("app_id", p.app.numericID), slog.String("error", err.Error()))
		wait = min(2*wait, uploadMaxWait)
	}
	a.mu.Lock()
	p.state = uploadFailed
	settings := p.app.settingsURL(a.GitHub.Web())
	gone := &app{id: p.app.id, numericID: p.app.numericID, slug: p.app.slug, owner: p.app.owner, ownerKind: p.app.ownerKind}
	// GitHub's answer is dropped: no secret of the App stays in memory.
	p.app = gone
	a.mu.Unlock()
	a.log().Error("storing the GitHub App in Qory Apiary failed for good: delete the App on GitHub, then press Set up in Qory Apiary again",
		slog.Int64("app_id", gone.numericID), slog.String("slug", gone.slug), slog.String("settings_url", settings))
}

// pause waits d or until ctx is done, with wait when it is set.
func (a *appSetup) pause(ctx context.Context, d time.Duration) error {
	if a.wait != nil {
		return a.wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stop waits for the tries of an upload under way, which end when serve stops.
func (a *appSetup) stop() {
	if a != nil {
		a.tries.Wait()
	}
}

// status is GET /setup/status, where the browser waits while the setup tries again to
// store the App, which needs the session that set the App up: while the tries go on,
// a page that says so and reloads itself every [statusEvery] seconds; once the App is
// stored, the page that says it is set up; once every try failed, the page that says
// to delete the App on GitHub. Both end the session.
func (a *appSetup) status(w http.ResponseWriter, r *http.Request, _ url.Values) {
	id, s, ok, err := a.session(r)
	if err != nil {
		a.failed(w, r, id, "session", err)
		return
	}
	a.mu.Lock()
	var p pendingUpload
	if a.pending != nil {
		p = *a.pending
	}
	a.mu.Unlock()
	if !ok || !s.Uploading || p.app == nil || subtle.ConstantTimeCompare([]byte(p.session), []byte(sessionKey(id))) != 1 {
		a.refuse(w, r, setupRefuseNoSession, "")
		return
	}
	switch p.state {
	case uploadStored:
		a.endSession(w, id)
		a.donePage(w, p.app, p.public)
	case uploadFailed:
		a.endSession(w, id)
		plainPage(w, http.StatusBadGateway, pageNotStored+p.app.slug+pageNotStoredAt+p.app.settingsURL(a.GitHub.Web())+pageNotStoredEnd+uploadTime(p.until)+".")
	default:
		a.tryingPage(w, p)
	}
}

// uploadTime is t as the status pages write it, in UTC to the minute.
func uploadTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

// tryingPageHTML is the page the browser shows while the setup tries again to store the
// App, which reloads itself.
var tryingPageHTML = template.Must(template.New("trying").Parse(`<!doctype html>
<meta charset="utf-8"><meta http-equiv="refresh" content="{{.Every}}"><title>qory-github</title>
<p>{{.Line}}</p>
<p>{{.Wait}}</p>
`))

// tryingPage answers the page that says the setup tries again to store the App of p.
func (a *appSetup) tryingPage(w http.ResponseWriter, p pendingUpload) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	tryingPageHTML.Execute(w, map[string]any{
		"Every": statusEvery,
		"Line":  "GitHub created the App " + p.app.slug + ". Storing it in Qory Apiary failed, and this server tries again until " + uploadTime(p.until) + ".",
		"Wait":  "Keep this page open: it reloads every " + strconv.Itoa(statusEvery) + " seconds and shows the result.",
	})
}

// keep checks the App conv, as GitHub answered the code's exchange, and returns it, kept
// in memory alone: its private key must be an RSA key, as qory-github setup takes one,
// and no larger than Qory Apiary stores a secret; its slug, client id and client secret
// must be ones serve takes and Qory Apiary stores; a webhook secret in the answer must
// be one serve's receiver takes; and neither its key nor a secret may contain what
// looks like an access key secret or a run key. An error never contains a secret. When
// GitHub made the App no webhook secret, keep makes one and sets it on the App's
// webhook; when GitHub does not confirm it, the App is used all the same, its webhook
// secret not confirmed, which serve sets again at its next start, see [Run]. The
// account that owns the App is GitHub's answer's, or the session's when the answer
// names none serve takes, see [ownerOf].
func (a *appSetup) keep(ctx context.Context, conv github.Conversion, s setupSession) (*app, error) {
	pemBytes := bytes.TrimRight([]byte(conv.PEM), "\r\n")
	if len(pemBytes) > contracts.SecretValueMaxBytes {
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
	if !appIDShape.MatchString(conv.ClientID) || conv.ClientSecret == "" || len(conv.ClientSecret) > maxClientSecret || strings.ContainsFunc(conv.ClientSecret, unkeepable) {
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
	return &app{
		id: strconv.FormatInt(conv.ID, 10), numericID: conv.ID, slug: conv.Slug, clientID: conv.ClientID, pem: pemBytes, key: key,
		webhookSecret: []byte(secret), clientSecret: []byte(conv.ClientSecret), webhookActive: a.Active, owner: owner, ownerKind: kind, confirmed: confirmed,
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
	answerLargeKey         = "GitHub's answer contains a private key larger than setup can store in Qory Apiary"
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

// unkeepable is whether r is white space or a control character, which no secret of
// the App has.
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
	http.SetCookie(w, &http.Cookie{Name: setupPageCookie, Value: "", Path: setupPath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	plainPage(w, rf.status, rf.page)
}

// plainPage answers status with the one line line, as text.
func plainPage(w http.ResponseWriter, status int, line string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, line+"\n")
}

// accountPageHTML is the account form, which posts the account's handle, who can
// install the App, and the session's form token to /setup/continue.
var accountPageHTML = template.Must(template.New("account").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github</title>
<h1>{{.Heading}}</h1>
{{if .Line}}<p>{{.Line}}</p>
{{end}}<form method="post" action="{{.Action}}">
<label>{{.Label}} <input name="account" required maxlength="39" autocomplete="off"></label>
<fieldset>
<legend>{{.Question}}</legend>
<label><input type="radio" name="install" value="` + installPrivate + `" required{{if not .Public}} checked{{end}}> {{.Private}}</label>
<label><input type="radio" name="install" value="` + installPublic + `"{{if .Public}} checked{{end}}> {{.Any}}</label>
</fieldset>
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit">{{.Button}}</button>
</form>
`))

// accountForm is what [accountPageHTML] shows. Public selects the public App's option
// in place of the private App's.
type accountForm struct {
	Heading, Line, Action, Label, Question, Private, Any, Token, Button string
	Public                                                              bool
}

// accountPage answers the account form, with line above it when it is set, and the
// public App's option selected when public is set.
func (a *appSetup) accountPage(w http.ResponseWriter, token, line string, public bool) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	accountPageHTML.Execute(w, accountForm{
		Heading: "Set up the GitHub App", Line: line, Action: setupPath + "/continue",
		Label:    "GitHub account for the App, an organisation or a user",
		Question: "Who can install the App", Private: "Only this account (private)", Any: "Any GitHub account (public)",
		Public: public, Token: token, Button: "Continue",
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
// login of the account s names, public when s says so, to GitHub, with s's state, to be
// created under the account: an organisation's, or, for a user, the person signed in on
// GitHub, whom the page asks to be that user.
func (a *appSetup) manifestPage(w http.ResponseWriter, s setupSession) {
	web := a.GitHub.Web()
	manifest, _ := json.Marshal(github.ServeManifest("qory-"+s.Login, a.PublicURL+setupPath+"/created", a.PublicURL, s.Public, a.Active))
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

// donePage answers the page that says the App k is set up and who can install it, as
// the account form chose: any organisation when public is set, and otherwise only the
// account that owns it, GitHub's rule for a private App; and, when its webhook is
// inactive, that GitHub sends it none.
func (a *appSetup) donePage(w http.ResponseWriter, k *app, public bool) {
	line := "The GitHub App " + k.slug + " is set up. Only " + k.owner + " can install it, with Install in Qory Apiary."
	if public {
		line = "The GitHub App " + k.slug + " is set up. Organisations install it with Install in Qory Apiary."
	}
	pulls := ""
	if !a.Active {
		pulls = "GitHub sends this App no webhooks: changes on GitHub arrive with each pull."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	donePageHTML.Execute(w, map[string]string{
		"Line":   line,
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
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: "", Path: setupPath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
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

// markKept marks an App set up from the start, the one Qory Apiary delivered: every
// setup pass is refused.
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
	if r.URL.Path == setupPath && r.Method == http.MethodGet && rf.name != "" {
		// The request may carry a pass, so the page shows at an address without it.
		status = http.StatusSeeOther
		http.SetCookie(w, &http.Cookie{
			Name: setupPageCookie, Value: rf.name, Path: setupPath, MaxAge: int(pageFor / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		redirect(w, setupPath+"/refused")
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

// step names the request's step for the log: setup, continue, account, created,
// refused or status.
func (a *appSetup) step(r *http.Request) string {
	switch r.URL.Path {
	case setupPath + "/continue":
		if r.Method == http.MethodPost {
			return "account"
		}
		return "continue"
	case setupPath + "/created":
		return "created"
	case setupPath + "/refused":
		return "refused"
	case setupPath + "/status":
		return "status"
	}
	return "setup"
}
