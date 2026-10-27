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
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

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
//  2. GET /setup/continue shows Start, the form that asks for the GitHub organisation
//     the App is for, which may be left empty for the person signed in on GitHub; who
//     can install the App: only its owner, a private App, which the form selects
//     first, or any GitHub account, a public App; and the App's name, which may be
//     left empty. The name field is filled with qory- and the pass's
//     organisation_slug, see [defaultAppName], and is empty when the pass had none.
//     The form carries the session's form token.
//  3. POST /setup/continue, with the session's cookie and its form token, takes the
//     choice only as one of its two values, checks the name, see [checkAppName], looks
//     the organisation up with GitHub, if one is given, and takes it only as an
//     organisation, see [github.Client.Account], keeps the organisation and the choice
//     in the session, and answers the page that posts the App's manifest to GitHub,
//     [github.ServeManifest], with the name, private or public as chosen, with a new
//     state, which GitHub's redirect returns. A later POST replaces the organisation,
//     the choice and the state, so GitHub's redirect for an earlier page is refused.
//     The page posts itself with its one script, which the page's
//     Content-Security-Policy allows by its SHA-256, and its button does where the
//     script does not run.
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
// redirect's target is built from the settings and the session, and a page shows
// nothing the request carries but Start's fields, sent back in their inputs.
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
	// maxAccountForm is the most bytes the body of Start's form may hold.
	maxAccountForm = 4 << 10
	// installPrivate and installPublic are the two values of Start's
	// field install: the App is private, or public.
	installPrivate = "private"
	installPublic  = "public"
)

// setupSession is what the store keeps of a setup session: when it expires, in Unix
// nanoseconds; the nonce of the pass that started it, and when that pass expires, in
// Unix seconds; the pass's organisation_slug, empty when the pass had none; the form
// token Start carries; and, once Start is sent, the organisation's login and kind, both
// empty when Start had none, whether the App is public, and the state GitHub's redirect
// must return.
type setupSession struct {
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
	Pass    int64  `json:"pass_expires_at"`
	Slug    string `json:"organisation_slug,omitempty"`
	Token   string `json:"form_token"`
	Login   string `json:"login,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Public  bool   `json:"public,omitempty"`
	State   string `json:"state,omitempty"`
	// Uploading is whether the setup tries again to store the session's App in Qory
	// Apiary, see [appSetup.retry].
	Uploading bool `json:"uploading,omitempty"`
}

// The App setup's refusal pages, each with its status, its heading, the one sentence
// the browser shows, and the reason the log names. name, when set, is how
// [setupPageCookie] names the page; endSession ends the session the request carries,
// and dropCookie has the browser drop the cookie.
var (
	setupRefuseMethod    = refusal{status: http.StatusMethodNotAllowed, page: "This address answers only GET requests.", why: "method", heading: headingLink}
	setupRefuseQuery     = refusal{status: http.StatusBadRequest, page: "This set-up link is not valid. Press Set up in Qory Apiary again.", why: "query", name: "invalid", heading: headingLink}
	setupRefusePass      = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "pass", name: "invalid", heading: headingLink}
	setupRefuseSignature = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "signature", name: "invalid", heading: headingLink}
	setupRefusePayload   = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "payload", name: "invalid", heading: headingLink}
	setupRefuseAdapter   = refusal{status: http.StatusForbidden, page: "This set-up link is for another adapter. Press Set up on the GitHub adapter's page in Qory Apiary.", why: "adapter", name: "adapter", heading: headingLink}
	setupRefuseExpired   = refusal{status: http.StatusBadRequest, page: "This set-up link has expired. Press Set up in Qory Apiary again.", why: "expired", name: "expired", heading: headingLink}
	setupRefuseUsed      = refusal{status: http.StatusBadRequest, page: "This set-up link was used already. Press Set up in Qory Apiary again.", why: "used", name: "used", heading: headingLink}
	setupRefuseFailed    = refusal{status: http.StatusInternalServerError, page: "Something failed on this server. Press Set up in Qory Apiary again.", why: "failed", name: "failed", endSession: true, heading: headingFailed}
	setupRefuseNoSession = refusal{status: http.StatusBadRequest, page: "No setup is under way in this browser, or it took too long. Press Set up in Qory Apiary again.", why: "no_session", dropCookie: true, heading: headingNoSession}
	setupRefuseForm      = refusal{status: http.StatusBadRequest, page: setupRefuseNoSession.page, why: "form", heading: headingNoSession}
	setupRefuseState     = refusal{status: http.StatusBadRequest, page: setupRefuseQuery.page, why: "state", endSession: true, heading: headingLink}
	setupRefuseSetUp     = refusal{status: http.StatusConflict, page: "Qory Apiary has this App's keys. No action needed.", why: "set_up", name: "set-up", endSession: true, heading: headingSetUp}
	setupRefusePending   = refusal{status: http.StatusConflict, page: "Wait until the earlier setup ends, then press Set up in Qory Apiary again if the GitHub adapter's GitHub App is still not set up. An earlier setup is storing its App in Qory Apiary.", why: "pending", name: "pending", heading: headingPending}
)

// The headings of the setup's refusal pages, by what each refuses: a set-up link that
// cannot be used, an App set up already, an earlier setup that still stores its App, no
// session, a session a newer setup replaced, an App GitHub created that serve does not
// keep, and a failure on serve.
const (
	headingLink      = "This set-up link cannot be used"
	headingSetUp     = "The GitHub App is set up already"
	headingPending   = "An earlier set-up is still running"
	headingNoSession = "No set-up is under way in this browser"
	headingReplaced  = "A newer set-up replaced this one"
	headingNotStored = "The GitHub App could not be stored"
	headingFailed    = "Something failed on the GitHub adapter"
)

// setupPages are the pages [setupPageCookie] names, by name.
var setupPages = map[string]*refusal{
	"invalid": &setupRefusePass, "adapter": &setupRefuseAdapter, "expired": &setupRefuseExpired,
	"used": &setupRefuseUsed, "failed": &setupRefuseFailed, "set-up": &setupRefuseSetUp, "pending": &setupRefusePending,
}

// The lines of the pages that end a setup with an App on GitHub that serve does not
// use: a newer setup replaced the session's, which links to the Apps of the session's
// organisation on GitHub, or of the person signed in on GitHub; the App GitHub created
// could not be used, which links to its settings page; or the code's exchange failed,
// and GitHub may have created an App, which links to the Apps as a replaced session's
// page does. Each link is the address the line shows.
const (
	pageReplaced     = "A newer setup replaced this one. If you created an App on GitHub for it, delete it at "
	pageNotKeptStart = "GitHub created the App "
	pageNotKeptMid   = ", and this server could not use it. Delete it at "
	pageNotKeptEnd   = ", then press Set up in Qory Apiary again."
	pageMayHave      = "GitHub may have created an App; delete it at "
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
// but what its page needs. The pages' stylesheet and font, under [assetsPath], are
// the exception: every cache may keep them, see [serveAsset].
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
		if !serveAsset(w, r) {
			http.NotFound(w, r)
		}
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
	s := setupSession{Expires: now.Add(sessionFor).UnixNano(), Nonce: p.Nonce, Pass: expires.Unix(), Slug: p.OrganisationSlug, Token: randomID()}
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
//  2. the payload is one JSON object with the contract's four required members, and
//     organisation_slug or not, and no other member, each of the contract's shape, see
//     [organisationSlug], and version 1;
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
		Version   *int            `json:"version"`
		AdapterID *string         `json:"adapter_id"`
		Nonce     *string         `json:"nonce"`
		ExpiresAt *string         `json:"expires_at"`
		Slug      json.RawMessage `json:"organisation_slug"`
	}
	if !strictObject(payload, &doc) || doc.Version == nil || *doc.Version != contracts.Version || doc.AdapterID == nil || !adapterIDShape.MatchString(*doc.AdapterID) ||
		doc.Nonce == nil || !nonceShape.MatchString(*doc.Nonce) || doc.ExpiresAt == nil {
		return contracts.SetupPass{}, time.Time{}, &setupRefusePayload
	}
	expires, ok := passExpiry(*doc.ExpiresAt)
	if !ok {
		return contracts.SetupPass{}, time.Time{}, &setupRefusePayload
	}
	slug, ok := organisationSlug(doc.Slug)
	if !ok {
		return contracts.SetupPass{}, time.Time{}, &setupRefusePayload
	}
	p := contracts.SetupPass{Version: *doc.Version, AdapterID: *doc.AdapterID, Nonce: *doc.Nonce, ExpiresAt: *doc.ExpiresAt, OrganisationSlug: slug}
	if p.AdapterID != en.adapterID {
		return contracts.SetupPass{}, time.Time{}, &setupRefuseAdapter
	}
	if expiredPass(expires, now) {
		return contracts.SetupPass{}, time.Time{}, &setupRefuseExpired
	}
	return p, expires, nil
}

// slugShape is a setup pass's organisation_slug, the contract's pattern: lower-case
// letters, digits and hyphens, with no hyphen at either end. maxSlug is the contract's
// maxLength; slugShape matches only ASCII, so len counts the slug's characters.
var slugShape = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const maxSlug = 40

// organisationSlug is a setup pass's organisation_slug from its raw JSON value: empty
// when the pass has no such member, or false when the value is not a string of
// [maxSlug] characters at most that matches [slugShape]. A null leaves the string
// empty, which [slugShape] refuses, as the contract's type string does.
func organisationSlug(raw json.RawMessage) (string, bool) {
	if raw == nil {
		return "", true
	}
	var slug string
	if json.Unmarshal(raw, &slug) != nil || len(slug) > maxSlug || !slugShape.MatchString(slug) {
		return "", false
	}
	return slug, true
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
// Start, the setup's form.
func (a *appSetup) proceed(w http.ResponseWriter, r *http.Request, _ url.Values) {
	if _, s, ok := a.flowSession(w, r); ok {
		def := defaultAppName(s.Slug)
		a.startPage(w, startView{Token: s.Token, Name: def, Default: def != ""})
	}
}

// account is POST /setup/continue, Start's form: with the session's form token, it
// checks the form and shows it again, with a line under each field it refuses, when
// install is not exactly one of its two values, when the App name is not one GitHub
// takes, see [checkAppName], or when the organisation, if one is given, is not a
// GitHub organisation, see [github.Client.Account], which it looks up only when install
// passes. Otherwise it keeps the organisation and the choice in the session and answers
// the page that posts the App's manifest to GitHub.
func (a *appSetup) account(w http.ResponseWriter, r *http.Request) {
	id, s, ok := a.flowSession(w, r)
	if !ok {
		return
	}
	form, err := readForm(w, r)
	token, _ := one(form, "token")
	if err != nil || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		a.refuse(w, r, setupRefuseForm, "")
		return
	}
	org, _ := one(form, "organisation")
	install, _ := one(form, "install")
	typed, _ := one(form, "name")
	def := defaultAppName(s.Slug)
	v := startView{Token: s.Token, Organisation: strings.TrimSpace(org), Name: typed, Default: def != "", Public: install == installPublic}
	if install != installPrivate && install != installPublic {
		v.InstallError = "Choose who can install the App."
	}
	name, nameErr := checkAppName(typed)
	v.NameError = nameErr
	login := ""
	if v.Organisation != "" && v.InstallError == "" {
		ctx, cancel := context.WithTimeout(r.Context(), connectBound)
		defer cancel()
		found, kind, err := a.GitHub.Account(ctx, v.Organisation)
		switch {
		case errors.Is(err, github.ErrNoAccount):
			v.OrgError = "GitHub has no account by that name."
		case err != nil:
			a.failed(w, r, id, "account", err)
			return
		case kind != github.AccountOrganization:
			v.OrgError = found + " is a personal GitHub account. Leave the field empty to create the App under your account."
		default:
			login = found
		}
	}
	if v.InstallError != "" || v.NameError != "" || v.OrgError != "" {
		a.startPage(w, v)
		return
	}
	s.Login, s.Kind, s.Public, s.State = login, "", v.Public, randomID()
	if login != "" {
		s.Kind = github.AccountOrganization
	}
	if err := a.save(id, s); err != nil {
		a.failed(w, r, id, "session", err)
		return
	}
	a.manifestPage(w, s, name)
}

// maxAppName is the most characters GitHub takes in an App's name.
const maxAppName = 34

// checkAppName checks the App name typed on Start, and returns it without white space
// at either end, or the line that refuses it: one with a control character, or one of
// more than [maxAppName] characters. An empty name passes: the manifest then has no
// name, and the person names the App on GitHub's page.
func checkAppName(typed string) (string, string) {
	if strings.ContainsFunc(typed, unicode.IsControl) {
		return "", "Remove the line break or tab from the name."
	}
	name := strings.TrimSpace(typed)
	if utf8.RuneCountInString(name) > maxAppName {
		return "", "Shorten the name to 34 characters or fewer. GitHub refuses longer App names."
	}
	return name, ""
}

// defaultAppName is the App name Start fills in for the Qory Apiary organisation org,
// a setup pass's organisation_slug: qory- and org, in GitHub's shape, which is lower
// case, each run of characters other than a to z and 0 to 9 written as one -, so a run
// of - is one - too, no - at either end, and at most [maxAppName] characters, cut at
// the end, with no - at the end after the cut. It is empty when org is empty, or has
// no letter a to z or digit.
func defaultAppName(org string) string {
	var b strings.Builder
	run := false
	for _, c := range strings.ToLower(org) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			run = false
			continue
		}
		if !run {
			b.WriteByte('-')
			run = true
		}
	}
	shaped := strings.Trim(b.String(), "-")
	if shaped == "" {
		return ""
	}
	name := "qory-" + shaped
	if len(name) > maxAppName {
		name = name[:maxAppName]
	}
	return strings.TrimRight(name, "-")
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
		a.failedPage(w, p)
	default:
		a.tryingPage(w, p)
	}
}

// uploadTime is t as the status pages write it, in UTC to the minute.
func uploadTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

// tryingPage answers the page that says the setup tries again to store the App of p,
// which reloads itself every [statusEvery] seconds.
func (a *appSetup) tryingPage(w http.ResponseWriter, p pendingUpload) {
	v := statusView{
		pageFrame: a.frame(3, true), Trying: true,
		Line: "Storing the App in Qory Apiary failed. The GitHub adapter tries again until " + uploadTime(p.until) + ", and this page reloads every " + strconv.Itoa(statusEvery) + " seconds to show the result.",
	}
	v.Refresh = statusEvery
	writePage(w, http.StatusAccepted, pageCSP(""), statusPageHTML, v)
}

// failedPage answers the page that says to delete the App of p on GitHub, whose every
// upload to Qory Apiary failed, and links to the App's settings page.
func (a *appSetup) failedPage(w http.ResponseWriter, p pendingUpload) {
	writePage(w, http.StatusBadGateway, pageCSP(""), statusPageHTML, statusView{
		pageFrame: a.frame(3, false), Settings: p.app.settingsURL(a.GitHub.Web()),
		Line: "Delete the GitHub App " + p.app.slug + " on GitHub, then press Set up in Qory Apiary again. The GitHub adapter could not store the App in Qory Apiary by " + uploadTime(p.until) + ".",
	})
}

// statusPageHTML is the page /setup/status shows while the setup tries again to store
// the App, Trying, or once every try failed, with Settings, the App's settings page.
var statusPageHTML = pageTemplate(`{{define "main"}}{{if .Trying}}<div class="alert alert-warning" role="note">{{template "ic-warning"}}<div class="alert-body"><p>{{.Line}}</p></div></div>
<div class="q-su-acts"><a class="btn btn-md" href="{{.Apiary}}">Back to Qory Apiary</a></div>
{{- else}}<div class="alert alert-error" role="alert">{{template "ic-error"}}<div class="alert-body"><p>{{.Line}}</p></div></div>
<div class="q-su-acts"><a class="btn btn-md btn-primary" href="{{.Settings}}">Open the App's settings on GitHub</a><a class="btn btn-md" href="{{.Apiary}}">Back to Qory Apiary</a></div>
{{- end}}{{end}}
{{- define "ctx"}}<p>You can close this tab. Your first Qory Apiary tab updates without a reload.</p>{{end}}`)

// statusView is what [statusPageHTML] shows.
type statusView struct {
	pageFrame
	Trying         bool
	Line, Settings string
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
// account that owns the App is GitHub's answer's, or the session's organisation when
// the answer has none serve takes, see [ownerOf]; with neither, the App is not kept.
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
	owner, kind, ok := ownerOf(conv, s)
	if !ok {
		return nil, errors.New(answerNoOwner)
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
	return &app{
		id: strconv.FormatInt(conv.ID, 10), numericID: conv.ID, slug: conv.Slug, clientID: conv.ClientID, pem: pemBytes, key: key,
		webhookSecret: []byte(secret), clientSecret: []byte(conv.ClientSecret), webhookActive: a.Active, owner: owner, ownerKind: kind, confirmed: confirmed,
	}, nil
}

// The words of the checks of GitHub's answer to the code's exchange: answerNoClient and
// answerBadWebhookSecret say a client id, client secret or webhook secret serve cannot
// keep; answerNoSlug says a slug serve cannot keep, answerLargeKey a private key larger
// than serve reads back from the state directory, and answerAccessKey and answerRunKey
// what looks like an access key secret or a run key in the answer's key or a secret;
// answerNoOwner says an owner serve cannot keep when Start had no organisation.
const (
	answerAccessKey        = "GitHub's answer holds what looks like an access key secret, qak_, which belongs nowhere in it"
	answerRunKey           = "GitHub's answer holds what looks like a run key, qrk_, which belongs nowhere in it"
	answerLargeKey         = "GitHub's answer contains a private key larger than setup can store in Qory Apiary"
	answerNoSlug           = "GitHub's answer holds no App slug setup can keep"
	answerNoClient         = "GitHub's answer holds no client id, or no client secret setup can keep"
	answerBadWebhookSecret = "GitHub's answer holds a webhook secret qory-github-server serve cannot use"
	answerNoOwner          = "GitHub's answer contains no owner setup can keep, and the setup has no organisation"
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

// ownerOf is the account that owns the App conv, as GitHub's answer has it: a login of
// 39 characters at most, of an organisation or a user. When the answer has none serve
// takes, it is the organisation the session s has, if any. ok is false when neither
// has one.
func ownerOf(conv github.Conversion, s setupSession) (owner, kind string, ok bool) {
	owner, kind = conv.Owner.Login, conv.Owner.Type
	if len(owner) <= 39 && loginShape.MatchString(owner) && (kind == github.AccountOrganization || kind == github.AccountUser) {
		return owner, kind, true
	}
	if s.Login != "" {
		return s.Login, s.Kind, true
	}
	return "", "", false
}

// notKept ends the flow whose App GitHub created, or may have, and serve does not
// keep: it logs what failed with the error, and the page says to delete the App on
// GitHub, at its settings page when conv has a slug serve takes, or else at the Apps
// of the session's organisation, or of the person signed in on GitHub when the session
// has none.
func (a *appSetup) notKept(w http.ResponseWriter, r *http.Request, id string, s setupSession, conv *github.Conversion, what string, err error) {
	a.log().LogAttrs(r.Context(), slog.LevelError, "setup failed", slog.String("step", a.step(r)), slog.String("what", what), slog.String("error", err.Error()))
	web := a.GitHub.Web()
	rf := refusal{status: http.StatusBadGateway, why: "not_kept", endSession: true, heading: headingNotStored}
	if conv == nil || github.CheckSlug(conv.Slug) != nil {
		rf.link = github.AppsURL(web, orgOf(s.Login, s.Kind))
		rf.page = pageMayHave + rf.link + pageNotKeptEnd
	} else {
		rf.status = http.StatusInternalServerError
		k := app{slug: conv.Slug}
		k.owner, k.ownerKind, _ = ownerOf(*conv, s)
		rf.link = k.settingsURL(web)
		rf.page = pageNotKeptStart + conv.Slug + pageNotKeptMid + rf.link + pageNotKeptEnd
	}
	a.refuse(w, r, rf, id)
}

// replaced ends the session id, which a newer flow replaced: its page says to delete
// an App created for it, at the Apps of the session's organisation, or of the person
// signed in on GitHub when the session has none.
func (a *appSetup) replaced(w http.ResponseWriter, r *http.Request, id string, s setupSession) {
	rf := refusal{status: http.StatusConflict, why: "replaced", endSession: true, heading: headingReplaced}
	rf.link = github.AppsURL(a.GitHub.Web(), orgOf(s.Login, s.Kind))
	rf.page = pageReplaced + rf.link + "."
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
	a.refusalPage(w, rf)
}

// plainPage answers status with the one line line, as text.
func plainPage(w http.ResponseWriter, status int, line string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, line+"\n")
}

// frame is the frame of the setup's page at step, from 1 to 3, with a context column
// when ctx is set.
func (a *appSetup) frame(step int, ctx bool) pageFrame {
	return pageFrame{
		Title: setupSteps[step-1] + " · Set up the GitHub App", Heading: "Set up the GitHub App",
		Where: true, Context: ctx, Step: step, Apiary: a.ApiaryPublicURL,
	}
}

// refusalPage answers the page of the setup's refusal rf.
func (a *appSetup) refusalPage(w http.ResponseWriter, rf refusal) {
	refusalPage(w, pageFrame{Heading: rf.heading, Where: true, Apiary: a.ApiaryPublicURL}, rf)
}

// startPageHTML is Start, the setup's form, which posts the GitHub organisation, who
// can install the App, the App's name, and the session's form token to
// /setup/continue. Who can install the App is a select with no script: a details
// element whose summary shows the option checked, see setup.css.
var startPageHTML = pageTemplate(`{{define "main"}}<p>You create the GitHub App that this Qory Apiary instance's GitHub adapter uses to work with GitHub. GitHub's page opens next, where you create it, and GitHub then sends you back here.</p>
<form class="q-su-form" method="post" action="` + setupPath + `/continue">
<div class="fieldset"><label class="label" for="organisation">GitHub organisation (optional)</label><input class="input{{if .OrgError}} input-error{{end}}" id="organisation" name="organisation" type="text" value="{{.Organisation}}" maxlength="39" autocomplete="off" spellcheck="false" aria-describedby="organisation-{{if .OrgError}}error{{else}}hint{{end}}"{{if .OrgError}} aria-invalid="true"{{end}}>
{{- if .OrgError}}<p id="organisation-error" class="field-error">{{template "ic-error"}}{{.OrgError}}</p>{{else}}<p id="organisation-hint" class="hint">Leave it empty to create the App under your GitHub user.</p>{{end}}</div>
<fieldset class="fieldset"><legend class="label">Who can install the App</legend><details class="q-pick"><summary class="q-pick-btn"><span class="q-pick-text q-pick-none"><span class="q-pick-t">Who can install the App</span></span><span class="q-pick-text q-pick-sum q-pick-sum1"><span class="q-pick-t">Only the owner (private)</span><span class="q-pick-s">The organisation above, or your user if you leave it empty.</span></span><span class="q-pick-text q-pick-sum q-pick-sum2"><span class="q-pick-t">Any GitHub account (public)</span><span class="q-pick-s">Other organisations can install it too.</span></span><svg class="q-pick-chev" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 8 10 4.5 13.5 8M6.5 12l3.5 3.5 3.5-3.5"/></svg></summary><div class="q-pick-panel">
<label class="q-pick-opt q-pick-o1"><input class="q-pick-radio" type="radio" name="install" value="` + installPrivate + `" required{{if not .Public}} checked{{end}}>{{template "ic-check" " q-pick-ck"}}<span class="q-pick-text"><span class="q-pick-t">Only the owner (private)</span><span class="q-pick-s">The organisation above, or your user if you leave it empty.</span></span></label>
<label class="q-pick-opt q-pick-o2"><input class="q-pick-radio" type="radio" name="install" value="` + installPublic + `"{{if .Public}} checked{{end}}>{{template "ic-check" " q-pick-ck"}}<span class="q-pick-text"><span class="q-pick-t">Any GitHub account (public)</span><span class="q-pick-s">Other organisations can install it too.</span></span></label>
</div></details>{{if .InstallError}}<p class="field-error">{{template "ic-error"}}{{.InstallError}}</p>{{end}}</fieldset>
<div class="fieldset"><label class="label" for="name">App name</label><input class="input{{if .NameError}} input-error{{end}}" id="name" name="name" type="text" value="{{.Name}}" autocomplete="off" spellcheck="false" aria-describedby="name-{{if .NameError}}error{{else}}hint{{end}}"{{if .NameError}} aria-invalid="true"{{end}}>
{{- if .NameError}}<p id="name-error" class="field-error">{{template "ic-error"}}{{.NameError}}</p>{{else if .Default}}<p id="name-hint" class="hint">qory- and your Qory Apiary organisation's name, in lower case with hyphens. Up to 34 characters. You can change it here or on GitHub's page.</p>{{else}}<p id="name-hint" class="hint">Up to 34 characters. Leave it empty to name the App on GitHub's page.</p>{{end}}</div>
<section class="q-sec"><h2 class="q-sec-h">What the App may do on an account that installs it</h2><ul class="q-list"><li>Read and write issues and their comments</li><li>Read and write code and pull requests</li><li>Start GitHub Actions workflows, and write checks</li><li>Read an organisation's members</li><li>Read repository settings and metadata</li></ul></section>
<input type="hidden" name="token" value="{{.Token}}">
<div class="q-su-acts"><button class="btn btn-md btn-primary" type="submit">Continue on GitHub</button></div>
</form>{{end}}
{{- define "ctx"}}<p><strong class="q-ctx-b">Owner.</strong> The organisation or user that owns the App holds its settings and keys on GitHub. An organisation keeps the App when a person leaves. An App owned by your user leaves with you. Sign in on github.com in this browser first: as an owner of the organisation, or as the user who will own the App.</p>
<p><strong class="q-ctx-b">Who can install.</strong> A private App can be installed only by its owner. A public App can be installed by any GitHub account. Either way, the GitHub adapter uses only installations made with Install or Connect in Qory Apiary. You can change this later on GitHub, in the App's settings under Advanced.</p>
<p>Nothing is installed yet. The App reaches no repository until an organisation in Qory Apiary installs it.</p>{{end}}`)

// startView is what [startPageHTML] shows: the session's form token, the fields as the
// form was sent, the line under each field the form refused, and Default, whether Name
// is a default App name, which changes the name's hint.
type startView struct {
	pageFrame
	Token, Organisation, Name         string
	OrgError, InstallError, NameError string
	Public, Default                   bool
}

// startPage answers Start with v, under a Content-Security-Policy that lets the form
// post to serve alone.
func (a *appSetup) startPage(w http.ResponseWriter, v startView) {
	v.pageFrame = a.frame(1, true)
	writePage(w, http.StatusOK, pageCSP("form-action 'self'"), startPageHTML, v)
}

// manifestPageHTML is the page that posts the App's manifest to GitHub, as setup's
// does: its one script posts the form, and its button does where the script does not
// run.
var manifestPageHTML = pageTemplate(`{{define "main"}}<p>Opening GitHub…</p>
<form id="f" method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<div class="q-su-acts"><button class="btn btn-md btn-primary" type="submit">Open GitHub</button></div>
</form>
<script>` + github.SubmitScript + `</script>{{end}}
{{- define "ctx"}}<h3>On GitHub</h3>
<ol><li>If GitHub asks you to sign in, sign in as {{if .Org}}an owner of {{.Org}}{{else}}the user who will own the App{{end}}.</li><li>Check the App name. If GitHub says the name is taken, change it.</li><li>Press Create GitHub App{{if .Org}} for {{.Org}}{{end}}. GitHub then brings you back here.</li></ol>
<p>When you press Create GitHub App, GitHub sends you back here with a one-time code. The GitHub adapter exchanges the code with GitHub for the App's ID, private key and secrets, and stores them in Qory Apiary. You copy nothing.</p>{{end}}`)

// manifestView is what [manifestPageHTML] shows: where the form posts, the manifest,
// and the organisation the App is created under, if any.
type manifestView struct {
	pageFrame
	Action, Manifest, Org string
}

// submitScriptHash is the source of a Content-Security-Policy that allows the manifest
// page's one script, [github.SubmitScript], by its SHA-256.
var submitScriptHash = func() string {
	sum := sha256.Sum256([]byte(github.SubmitScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// manifestPage answers the page that posts the manifest of the App, named name, or
// with no name when name is empty, public when s says so, to GitHub, with s's state, to
// be created under the organisation s has, or, without one, under the person signed in
// on GitHub.
func (a *appSetup) manifestPage(w http.ResponseWriter, s setupSession, name string) {
	web := a.GitHub.Web()
	org := orgOf(s.Login, s.Kind)
	manifest, _ := json.Marshal(github.ServeManifest(name, a.PublicURL+setupPath+"/created", a.PublicURL, s.Public, a.Active))
	writePage(w, http.StatusOK, pageCSP("form-action "+web+"; script-src "+submitScriptHash), manifestPageHTML, manifestView{
		pageFrame: a.frame(2, true), Action: github.ManifestAction(web, org, s.State), Manifest: string(manifest), Org: org,
	})
}

// donePageHTML is the page that ends a setup that kept the App, which links back to
// Qory Apiary.
var donePageHTML = pageTemplate(`{{define "main"}}<div class="alert alert-success" role="note">{{template "ic-success"}}<div class="alert-body"><p>The GitHub App <strong>{{.Slug}}</strong> is set up and connected to Qory Apiary: its keys are stored there. {{if .Public}}Any GitHub account can install it.{{else}}Only <strong>{{.Owner}}</strong> can install it.{{end}} The GitHub step in your Qory Apiary tab now shows Set up.</p>
{{- if .Public}}<p><strong>Next</strong><br>In Qory Apiary, each organisation installs the App, with Install in Settings › Integrations or with Connect on the Work source step. GitHub's install page then lists the GitHub accounts you can install it on.</p>
{{- else}}<p><strong>Next</strong><br>In Qory Apiary, the organisation installs the App, with Install in Settings › Integrations or with Connect on the Work source step. GitHub's install page then asks which repositories the App may reach.</p>{{end}}</div></div>
{{if .NoWebhooks}}<div class="alert alert-info" role="note">{{template "ic-info"}}<div class="alert-body"><p>GitHub sends this App no webhooks, because the GitHub adapter has no public address. Changes on GitHub arrive with each pull.</p></div></div>
{{end}}<div class="q-su-acts"><a class="btn btn-md btn-primary" href="{{.Apiary}}">Back to Qory Apiary</a></div>{{end}}
{{- define "ctx"}}<p>GitHub sent the App's ID, private key and secrets to the GitHub adapter, which stored them in Qory Apiary. There is nothing to copy.</p>
<p>You can close this tab. Your first Qory Apiary tab updates without a reload.</p>{{end}}`)

// doneView is what [donePageHTML] shows.
type doneView struct {
	pageFrame
	Slug, Owner        string
	Public, NoWebhooks bool
}

// donePage answers the page that says the App k is set up and who can install it, as
// Start chose: any GitHub account when public is set, and otherwise only the account
// that owns it, GitHub's rule for a private App; and, when its webhook is inactive,
// that GitHub sends it none.
func (a *appSetup) donePage(w http.ResponseWriter, k *app, public bool) {
	writePage(w, http.StatusOK, pageCSP(""), donePageHTML, doneView{
		pageFrame: a.frame(3, true), Slug: k.slug, Owner: k.owner, Public: public, NoWebhooks: !a.Active,
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
		a.refusalPage(w, rf)
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
