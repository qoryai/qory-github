package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// Connect is how a person links the App's installation to Qory Apiary. An owner or
// administrator presses Connect on the integration's page in Qory Apiary, which sends
// the browser to serve's connect page with a connect pass, which Qory Apiary signed.
// Then:
//
//  1. GET <public_url>/v1/connect?state=<pass> checks the pass, see [Connect.checkPass],
//     keeps its nonce until the pass expires, so it is taken once, a restart
//     notwithstanding, starts a connect session, and sends the browser to install the
//     App on GitHub, with a random state the session keeps.
//  2. GET <public_url>/v1/connect/return, the App's Setup URL, where GitHub sends the
//     browser after the installation with that state, notes the installation in the
//     session, once, and starts GitHub's sign-in.
//  3. GET <public_url>/v1/connect/authorized, the App's callback URL, takes the
//     sign-in's code: the person's token, which is used for the checks alone and
//     never kept or logged, must reach the installation and read every repository it
//     reaches. Then the installation is linked, its repositories are sent to Qory
//     Apiary, and the browser goes back to Qory Apiary, to
//     <apiary_url>/integrations/<adapter_id>, a route Qory Apiary keeps, which sends
//     it on to the integration's page.
//
// One installation is linked for each adapter: the same one again is a re-connect,
// which lists its repositories again and fills the linked collections again; another is
// refused. A session lives in the store under the SHA-256 of a random id, which a
// cookie for /v1/connect alone carries, for 15 minutes at most. It ends with each
// answer of the last step that reads it, and with each refusal once it is read; a
// refusal of the method, of the query's size or of its form comes before the session
// is read, so it keeps the session, on /v1/connect/authorized as on the other pages.
// Every redirect's target is built from the settings, never from what the request
// carries, and a page that refuses says one sentence and nothing the request carries.
//
// The pages count no requests by address: behind the operator's TLS proxy every request
// comes from the proxy's address, so such a count would bound every person at once.
// What a request costs is bounded otherwise: a pass's signature is checked before
// anything is written to the store, and the Setup URL and the callback URL read a
// session the store keeps, which only a pass makes, before they reach GitHub.
type Connect struct {
	// Store keeps the nonces, the sessions and the links.
	Store *store.Store
	// Adapter lists the installation's repositories and sends them.
	Adapter *Adapter
	// Pin are Qory Apiary's public keys, one of which signs a connect pass.
	Pin accesskey.Pin
	// AdapterID is the adapter's id, na_ and 16 characters, which a pass must name.
	AdapterID string
	// ClientID and ClientSecret are the App's, which GitHub's sign-in takes.
	ClientID     string
	ClientSecret []byte
	// PublicURL is where serve is reached from outside, without a trailing slash.
	PublicURL string
	// ApiaryURL is Qory Apiary's origin, without a trailing slash. Once connected, the
	// browser goes to ApiaryURL/integrations/AdapterID there.
	ApiaryURL string
	// Log takes a line for each connect, and the refusals, once a second at most.
	Log *slog.Logger

	// now is the clock; nil is time.Now.
	now func() time.Time

	once     sync.Once
	base     string
	refusals *throttle
	// linking holds one token: the connect that holds it makes the check that no other
	// installation is linked and the link one step, so two connects at once link one
	// installation. A connect waits for it until its request's deadline.
	linking chan struct{}
	// fills are the fills a re-connect started, which [Connect.stop] stops and waits
	// for. fillMu guards stopped, after which no fill starts, and refilling, the
	// collections a re-connect's fill is under way for, which another does not fill
	// again meanwhile.
	fillCtx   context.Context
	stopFills context.CancelFunc
	fills     sync.WaitGroup
	fillMu    sync.Mutex
	stopped   bool
	refilling map[string]bool
}

// The store's namespaces Connect keeps its state in, each value with an expiry, and the
// one an installation GitHub announced is kept in while it is not linked, see
// [keepUnlinked].
const (
	nsConnectNonces   = "connect_nonces"
	nsConnectSessions = "connect_sessions"
	nsUnlinked        = "installations_unlinked"
)

// unlinkedFor is how long the record of an installation not linked is kept.
const unlinkedFor = 30 * 24 * time.Hour

// Connect's bounds.
const (
	// connectCookie is the session's cookie, for the connect page's path alone.
	connectCookie = "qory_github_connect"
	// sessionFor is how long a session lives at most; a pass that expires sooner ends
	// it then.
	sessionFor = 15 * time.Minute
	// passAhead is how far ahead of serve's clock a pass's expiry may be: Qory Apiary
	// makes a pass that expires 15 minutes after it is made.
	passAhead = 15 * time.Minute
	// maxConnectQuery is the most bytes a request's query may hold: a pass is 1,024
	// characters at most.
	maxConnectQuery = 2 << 10
	// connectBound is how long the last step may take, within [writeTimeout], its
	// wait for another connect's link among it.
	connectBound = 50 * time.Second
)

var (
	// idShape is a session's id as the cookie carries it, and a state the session
	// keeps: 32 random bytes in base64url.
	idShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// passShape is the characters a pass may hold: base64url's and the dot. Go's
	// base64 decoder skips a line break, so a pass is checked against it before it is
	// decoded.
	passShape = regexp.MustCompile(`^[A-Za-z0-9_.-]*$`)
	// nonceShape is a pass's nonce, the contract's pattern: 128 bits in base64url.
	nonceShape = regexp.MustCompile(`^[A-Za-z0-9_-]{21}[AQgw]$`)
	// codeShape is the code GitHub's sign-in sends back.
	codeShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	// installationShape is an installation's id as GitHub's Setup URL carries it.
	installationShape = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
)

// refusal is a page that refuses a request: its status, the one sentence the browser
// shows, and why, for the log.
type refusal struct {
	status    int
	page, why string
	// endSession ends the session the request carries, and dropCookie has the browser
	// drop the cookie, which endSession does too.
	endSession, dropCookie bool
}

// The pages that refuse, by what went wrong. Each says one sentence, and nothing the
// request carries.
var (
	refuseMethod    = refusal{status: http.StatusMethodNotAllowed, page: "This address answers GET requests alone.", why: "the request is not GET"}
	refuseQuery     = refusal{status: http.StatusBadRequest, page: "This link is not one this server reads. Press Connect in Qory Apiary again.", why: "the query is too long, or not one this server reads"}
	refusePass      = refusal{status: http.StatusBadRequest, page: "This connect link is not valid. Press Connect in Qory Apiary again.", why: "the pass is not one: too long, or not two parts in base64url"}
	refuseSignature = refusal{status: refusePass.status, page: refusePass.page, why: "the pass's signature does not verify under the pin"}
	refusePayload   = refusal{status: refusePass.status, page: refusePass.page, why: "the pass's payload is not the contract's"}
	refuseAdapter   = refusal{status: http.StatusForbidden, page: "This connect link is for another integration. Press Connect on this integration's page in Qory Apiary.", why: "the pass is for another adapter"}
	refuseExpired   = refusal{status: http.StatusBadRequest, page: "This connect link has expired. Press Connect in Qory Apiary again.", why: "the pass has expired, or expires too far ahead"}
	refuseUsed      = refusal{status: http.StatusBadRequest, page: "This connect link was used already. Press Connect in Qory Apiary again.", why: "the pass's nonce was used already"}
	refuseFailed    = refusal{status: http.StatusInternalServerError, page: "Something failed on this server. Press Connect in Qory Apiary again.", why: "the store failed"}
	refuseNoSession = refusal{status: http.StatusBadRequest, page: "No connection is under way in this browser, or it took too long. Press Connect in Qory Apiary again.", why: "no session", dropCookie: true}
	refuseWaits     = refusal{status: http.StatusBadRequest, page: "The installation waits for an owner's approval on GitHub. Once it is approved, press Connect in Qory Apiary again.", why: "the installation waits for an owner's approval", endSession: true}
	refuseInstall   = refusal{status: http.StatusBadRequest, page: "This installation does not belong to the connection under way in this browser. Press Connect in Qory Apiary again.", why: "the Setup URL's state is not the session's", endSession: true}
	refuseOnce      = refusal{status: http.StatusBadRequest, page: "The connection under way in this browser is for another installation already. Press Connect in Qory Apiary again.", why: "the session holds another installation", endSession: true}
	refuseBusy      = refusal{status: http.StatusServiceUnavailable, page: "Another connection is being made on this server. Press Connect in Qory Apiary again.", why: "another connect held the link past the deadline", endSession: true}
	refuseAnswer    = refusal{status: http.StatusBadRequest, page: "GitHub's answer is not one this server reads. Press Connect in Qory Apiary again.", why: "the Setup URL's query is not GitHub's", endSession: true}
	refuseState     = refusal{status: http.StatusBadRequest, page: "This sign-in does not belong to the connection under way in this browser. Press Connect in Qory Apiary again.", why: "the sign-in's state is not the session's", endSession: true}
	refuseDenied    = refusal{status: http.StatusBadRequest, page: "GitHub did not complete the sign-in. Press Connect in Qory Apiary again.", why: "the sign-in sent back no code", endSession: true}
	refuseSignIn    = refusal{status: http.StatusBadGateway, page: "GitHub could not confirm the sign-in. Press Connect in Qory Apiary again.", why: "the sign-in's code could not be exchanged", endSession: true}
	refuseGitHub    = refusal{status: http.StatusBadGateway, page: "GitHub could not be reached, or did not answer as expected. Press Connect in Qory Apiary again.", why: "GitHub failed", endSession: true}
	refuseNoAccess  = refusal{status: http.StatusForbidden, page: "Your GitHub account cannot reach this installation of the App. Sign in to GitHub with an account that can, then press Connect in Qory Apiary again.", why: "the person does not reach the installation", endSession: true}
	refuseCannot    = refusal{status: http.StatusForbidden, page: "Your GitHub account cannot read every repository this installation reaches, so it cannot connect it.", why: "the person cannot read every repository the installation reaches", endSession: true}
	refuseAnother   = refusal{status: http.StatusConflict, page: "Another installation of this GitHub App is connected already, and only one can be.", why: "another installation is linked", endSession: true}
	refuseApiary    = refusal{status: http.StatusBadGateway, page: "The repositories could not be sent to Qory Apiary. Press Connect in Qory Apiary again.", why: "Qory Apiary did not take the repositories", endSession: true}
)

// session is what the store keeps of a connect session: when it expires, in Unix
// nanoseconds; the state GitHub's Setup URL must send back; and, once that URL is
// reached, the installation and the state GitHub's sign-in must send back.
type session struct {
	Expires      int64  `json:"expires"`
	InstallState string `json:"install_state"`
	Installation int64  `json:"installation,omitempty"`
	State        string `json:"state,omitempty"`
}

func (c *Connect) init() {
	c.once.Do(func() {
		u, err := url.Parse(c.PublicURL)
		if err == nil {
			c.base = strings.TrimSuffix(u.Path, "/")
		}
		c.base += connectPath
		c.linking = make(chan struct{}, 1)
		c.refilling = map[string]bool{}
		c.refusals = &throttle{every: refusalEvery, now: c.now, flush: func(dropped int) {
			c.log().LogAttrs(context.Background(), slog.LevelInfo, "connect refusals dropped", slog.Int("refusals_dropped", dropped))
		}}
		c.fillCtx, c.stopFills = context.WithCancel(context.Background())
	})
}

func (c *Connect) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Connect) log() *slog.Logger {
	if c.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Log
}

// stop stops the fills a re-connect started and waits for them, and logs the count of
// refusals held back, if any.
func (c *Connect) stop() {
	c.init()
	c.fillMu.Lock()
	c.stopped = true
	c.fillMu.Unlock()
	c.stopFills()
	c.fills.Wait()
	c.refusals.stop()
}

// Route is next with the connect page's three paths, under the public URL's path,
// answered by Connect: every other path goes to next, the receiver among them, whose
// bounds stay as they are.
func (c *Connect) Route(next http.Handler) http.Handler {
	c.init()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var step func(http.ResponseWriter, *http.Request, url.Values)
		switch r.URL.Path {
		case c.base:
			step = c.start
		case c.base + "/return":
			step = c.returned
		case c.base + "/authorized":
			step = c.authorized
		default:
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if r.Method != http.MethodGet {
			h.Set("Allow", http.MethodGet)
			c.refuse(w, r, refuseMethod, "")
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if len(r.URL.RawQuery) > maxConnectQuery || err != nil {
			c.refuse(w, r, refuseQuery, "")
			return
		}
		step(w, r, q)
	})
}

// one is the query's one value of name, or false when it has none or more than one.
func one(q url.Values, name string) (string, bool) {
	v := q[name]
	if len(v) != 1 {
		return "", false
	}
	return v[0], true
}

// start is the first step, GET /v1/connect?state=<pass>.
func (c *Connect) start(w http.ResponseWriter, r *http.Request, q url.Values) {
	pass, ok := one(q, "state")
	if !ok {
		c.refuse(w, r, refusePass, "")
		return
	}
	now := c.clock()
	p, expires, rf := c.checkPass(pass, now)
	if rf != nil {
		c.refuse(w, r, *rf, "")
		return
	}
	// The nonce is kept until the pass has expired, past a restart, and a pass whose
	// nonce is kept already is refused: one check and insert, so of two requests with
	// one pass one passes.
	kept, err := c.Store.PutNew(nsConnectNonces, p.Nonce, []byte{1}, expires.Sub(now)+time.Second)
	if err != nil {
		c.failed(w, r, "", "keeping the pass's nonce", err)
		return
	}
	if !kept {
		c.refuse(w, r, refuseUsed, "")
		return
	}
	ttl := max(min(sessionFor, expires.Sub(now)), time.Second)
	id, installState := randomID(), randomID()
	if err := c.save(id, session{Expires: now.Add(ttl).UnixNano(), InstallState: installState}); err != nil {
		c.failed(w, r, "", "keeping the session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: connectCookie, Value: id, Path: c.base, MaxAge: int(ttl / time.Second), Expires: now.Add(ttl),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	// GitHub sends the state on to the Setup URL, which requires it. Whether GitHub
	// sends it when the person changes an installation that exists, on its settings
	// page, rather than installing anew, is not known here; the Setup URL requires it
	// all the same, so such a return is refused, and the person connects again.
	redirect(w, github.App{Slug: c.Adapter.Slug}.InstallURL(c.Adapter.GitHub.Web())+"?"+url.Values{"state": {installState}}.Encode())
}

// checkPass checks a connect pass, in this order, and returns its payload and when it
// expires, or the refusal:
//
//  1. at most [contracts.ConnectPassMaxLength] characters, each base64url's or a dot,
//     split on its last dot into the payload and the signature, each base64url
//     without padding, decoded strictly;
//  2. the signature verifies under a key of the pin over [contracts.ConnectDomain], a
//     line feed and the payload's bytes, before the payload is parsed;
//  3. the payload is one JSON object with the contract's four members and no other,
//     each of the contract's shape, and version 1;
//  4. adapter_id is the adapter's;
//  5. expires_at has not passed on serve's clock, and is at most 15 minutes ahead.
//
// The nonce is checked by the caller, which keeps it.
func (c *Connect) checkPass(pass string, now time.Time) (contracts.ConnectPass, time.Time, *refusal) {
	invalid := &refusePass
	if len(pass) > contracts.ConnectPassMaxLength || !passShape.MatchString(pass) {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	i := strings.LastIndexByte(pass, '.')
	if i < 0 {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	enc := base64.RawURLEncoding.Strict()
	payload, err := enc.DecodeString(pass[:i])
	if err != nil {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	if _, err := enc.DecodeString(pass[i+1:]); err != nil {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	if !c.Pin.Verify(append([]byte(contracts.ConnectDomain+"\n"), payload...), pass[i+1:]) {
		return contracts.ConnectPass{}, time.Time{}, &refuseSignature
	}
	invalid = &refusePayload
	var doc struct {
		Version   *int    `json:"version"`
		AdapterID *string `json:"adapter_id"`
		Nonce     *string `json:"nonce"`
		ExpiresAt *string `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if !bytes.HasPrefix(payload, []byte("{")) || dec.Decode(&doc) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	if doc.Version == nil || *doc.Version != contracts.Version || doc.AdapterID == nil || !adapterIDShape.MatchString(*doc.AdapterID) ||
		doc.Nonce == nil || !nonceShape.MatchString(*doc.Nonce) || doc.ExpiresAt == nil {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	expires, err := time.Parse(contracts.TimeLayout, *doc.ExpiresAt)
	if err != nil || contracts.FormatTime(expires) != *doc.ExpiresAt {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	p := contracts.ConnectPass{Version: *doc.Version, AdapterID: *doc.AdapterID, Nonce: *doc.Nonce, ExpiresAt: *doc.ExpiresAt}
	if p.AdapterID != c.AdapterID {
		return contracts.ConnectPass{}, time.Time{}, &refuseAdapter
	}
	if now.After(expires) || expires.Sub(now) > passAhead {
		return contracts.ConnectPass{}, time.Time{}, &refuseExpired
	}
	return p, expires, nil
}

// returned is the second step, GitHub's Setup URL, GET
// /v1/connect/return?installation_id=…&setup_action=…, which needs the session.
func (c *Connect) returned(w http.ResponseWriter, r *http.Request, q url.Values) {
	id, s, ok, err := c.session(r)
	if err != nil {
		c.failed(w, r, id, "reading the session", err)
		return
	}
	if !ok {
		c.refuse(w, r, refuseNoSession, "")
		return
	}
	state, ok := one(q, "state")
	if !ok || s.InstallState == "" || subtle.ConstantTimeCompare([]byte(state), []byte(s.InstallState)) != 1 {
		c.refuse(w, r, refuseInstall, id)
		return
	}
	action, _ := one(q, "setup_action")
	if action == "request" {
		c.refuse(w, r, refuseWaits, id)
		return
	}
	raw, ok := one(q, "installation_id")
	if !ok || !installationShape.MatchString(raw) || (action != "install" && action != "update") {
		c.refuse(w, r, refuseAnswer, id)
		return
	}
	installation, _ := strconv.ParseInt(raw, 10, 64)
	// The session's installation is set once: a second return names the same one, or
	// is refused.
	if s.Installation != 0 && s.Installation != installation {
		c.refuse(w, r, refuseOnce, id)
		return
	}
	s.Installation = installation
	s.State = randomID()
	if err := c.save(id, s); err != nil {
		c.failed(w, r, id, "keeping the session", err)
		return
	}
	redirect(w, c.Adapter.GitHub.Web()+"/login/oauth/authorize?"+url.Values{
		"client_id": {c.ClientID}, "state": {s.State}, "redirect_uri": {c.PublicURL + github.ConnectAuthorizedPath},
	}.Encode())
}

// authorized is the last step, GitHub's sign-in sending the browser back, GET
// /v1/connect/authorized?code=…&state=…, which needs the session and its state. The
// session ends whatever the answer.
func (c *Connect) authorized(w http.ResponseWriter, r *http.Request, q url.Values) {
	id, s, ok, err := c.session(r)
	if err != nil {
		c.failed(w, r, id, "reading the session", err)
		return
	}
	if !ok {
		c.refuse(w, r, refuseNoSession, "")
		return
	}
	state, ok := one(q, "state")
	if s.State == "" || s.Installation <= 0 || !ok || subtle.ConstantTimeCompare([]byte(state), []byte(s.State)) != 1 {
		c.refuse(w, r, refuseState, id)
		return
	}
	code, ok := one(q, "code")
	if q.Has("error") || !ok || !codeShape.MatchString(code) {
		c.refuse(w, r, refuseDenied, id)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	installation := s.Installation
	attrs := []slog.Attr{slog.Int64("installation", installation)}
	gh := c.Adapter.GitHub
	token, err := gh.UserToken(ctx, c.ClientID, c.ClientSecret, code, c.PublicURL+github.ConnectAuthorizedPath)
	if err != nil {
		c.refuse(w, r, refuseSignIn, id, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	reached, err := gh.UserInstallations(ctx, token)
	if err != nil {
		c.refuse(w, r, refuseGitHub, id, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	found := false
	for _, in := range reached {
		found = found || in == installation
	}
	if !found {
		c.refuse(w, r, refuseNoAccess, id, attrs...)
		return
	}
	if !c.takeLink(ctx) {
		c.refuse(w, r, refuseBusy, id, attrs...)
		return
	}
	defer func() { <-c.linking }()
	other, err := linkedOther(c.Store, installation)
	if err != nil {
		c.failed(w, r, id, "reading the links", err)
		return
	}
	if other {
		c.refuse(w, r, refuseAnother, id, attrs...)
		return
	}
	listing, err := c.listInstallation(ctx, installation)
	if err != nil {
		c.refuse(w, r, refuseGitHub, id, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	// This is the person's token's last use: it is never kept or logged.
	readable, err := gh.UserRepositories(ctx, token, installation)
	if err != nil {
		c.refuse(w, r, refuseGitHub, id, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	reads := map[string]bool{}
	for _, name := range readable {
		reads[collectionKey(name)] = true
	}
	unread, total := 0, 0
	for _, req := range listing {
		for _, col := range req.Collections {
			total++
			if !reads[collectionKey(col.Ref)] {
				unread++
			}
		}
	}
	if unread > 0 {
		c.refuse(w, r, refuseCannot, id, append(attrs, slog.Int("unread", unread))...)
		return
	}
	again, err := Linked(c.Store, installation)
	if err == nil {
		err = Link(c.Store, installation)
	}
	if err == nil {
		err = dropUnlinked(c.Store, installation)
	}
	if err != nil {
		c.failed(w, r, id, "linking the installation", err)
		return
	}
	// Should Qory Apiary not take the listing, the installation stays linked, and a
	// re-connect sends it again.
	sink := reachSink{Sink: c.Adapter.Sink, st: c.Store, installation: installation}
	for _, req := range listing {
		if err := sink.Collections(ctx, req); err != nil {
			c.refuse(w, r, refuseApiary, id, append(attrs, slog.String("error", err.Error()))...)
			return
		}
	}
	if again {
		c.refill(installation)
	}
	c.end(w, id)
	c.log().LogAttrs(r.Context(), slog.LevelInfo, "connected", append(attrs, slog.Bool("again", again), slog.Int("repositories", total))...)
	redirect(w, c.ApiaryURL+"/integrations/"+c.AdapterID)
}

// listInstallation lists the repositories the installation reaches, as
// [github.Lister.ListRepositories] lists them with an installation token, and keeps
// the requests it would send, so they are checked before any is sent.
func (c *Connect) listInstallation(ctx context.Context, installation int64) ([]contracts.SourceCollections, error) {
	a := c.Adapter
	kept := &keptCollections{}
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, github.Repository{}, "") },
		Slug:   a.Slug,
		Sink:   kept,
		Logf:   a.logf,
		LogCut: a.logCut,
	}
	if err := a.forgetOn401(installation, l.ListRepositories(ctx)); err != nil {
		return nil, err
	}
	return kept.reqs, nil
}

// keptCollections is a [github.Sink] that keeps the listing's requests and sends
// nothing.
type keptCollections struct{ reqs []contracts.SourceCollections }

// Collections keeps the request.
func (k *keptCollections) Collections(_ context.Context, req contracts.SourceCollections) error {
	k.reqs = append(k.reqs, req)
	return nil
}

// Items refuses: a listing of repositories sends none.
func (k *keptCollections) Items(context.Context, contracts.SourceItems) error {
	return errors.New("a listing of repositories sends no items")
}

// Comments refuses: a listing of repositories sends none.
func (k *keptCollections) Comments(context.Context, contracts.SourceItemComments) error {
	return errors.New("a listing of repositories sends no comments")
}

// Disconnect refuses: a listing of repositories disconnects nothing.
func (k *keptCollections) Disconnect(context.Context, contracts.SourcesDisconnect) error {
	return errors.New("a listing of repositories disconnects nothing")
}

// refill fills again, after the answer, each collection Qory Apiary linked that the
// installation reaches, as the change feed's linked entry fills it, so a re-connect
// brings what changed meanwhile. Each fill goes through [Adapter.fill], so it takes
// the collection's turn. A collection a re-connect's fill is under way for already is
// left to that fill, and once [Connect.stop] has run no fill starts. A fill that fails
// is logged.
func (c *Connect) refill(installation int64) {
	refs, err := reachedBy(c.Store, installation)
	if err != nil {
		c.log().Error("filling the collections again after a re-connect", slog.String("error", err.Error()))
		return
	}
	c.fillMu.Lock()
	defer c.fillMu.Unlock()
	if c.stopped {
		return
	}
	var mine []string
	for _, ref := range refs {
		if key := collectionKey(ref); !c.refilling[key] {
			c.refilling[key] = true
			mine = append(mine, ref)
		}
	}
	if len(mine) == 0 {
		return
	}
	c.fills.Add(1)
	go func() {
		defer c.fills.Done()
		for _, ref := range mine {
			if ok, err := collectionLinked(c.Store, ref); err == nil && ok {
				if err := c.Adapter.fill(c.fillCtx, ref); err != nil && c.fillCtx.Err() == nil {
					c.log().Error("filling a collection again after a re-connect", slog.String("collection", ref), slog.String("error", err.Error()))
				}
			}
			c.fillMu.Lock()
			delete(c.refilling, collectionKey(ref))
			c.fillMu.Unlock()
		}
	}()
}

// linkedOther is whether an installation other than installation is linked.
func linkedOther(st *store.Store, installation int64) (bool, error) {
	other := false
	self := strconv.FormatInt(installation, 10)
	err := st.Each(nsInstallations, func(key string, _ []byte) error {
		other = other || key != self
		return nil
	})
	return other, err
}

// keepUnlinked keeps, for [unlinkedFor], that GitHub announced the installation, by
// its installation created event, while it is not linked: Connect's installations
// bring that event too, before their link. The record says what serve has seen of the
// App's installations; nothing reads it to decide what is handled, which the link
// alone decides, and it expires, so it never grows unread.
func keepUnlinked(st *store.Store, installation int64) error {
	return st.Put(nsUnlinked, strconv.FormatInt(installation, 10), []byte("unlinked"), unlinkedFor)
}

// dropUnlinked forgets the installation's record of [keepUnlinked], once it is linked
// or deleted.
func dropUnlinked(st *store.Store, installation int64) error {
	return st.Delete(nsUnlinked, strconv.FormatInt(installation, 10))
}

// sessionKey is the store's key for the session id: its SHA-256, so the store's
// lookup compares hashes, never the id.
func sessionKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// save keeps the session under its id until it expires.
func (c *Connect) save(id string, s session) error {
	ttl := time.Unix(0, s.Expires).Sub(c.clock())
	if ttl <= 0 {
		return errors.New("the session has expired")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return c.Store.Put(nsConnectSessions, sessionKey(id), b, ttl)
}

// session is the request's session, by the id its cookie carries, or false when it
// carries none, or one the store does not know or that has expired.
func (c *Connect) session(r *http.Request) (string, session, bool, error) {
	ck, err := r.Cookie(connectCookie)
	if err != nil || !idShape.MatchString(ck.Value) {
		return "", session{}, false, nil
	}
	b, err := c.Store.Get(nsConnectSessions, sessionKey(ck.Value))
	if errors.Is(err, store.ErrNotFound) {
		return "", session{}, false, nil
	}
	if err != nil {
		return ck.Value, session{}, false, err
	}
	var s session
	if json.Unmarshal(b, &s) != nil || !c.clock().Before(time.Unix(0, s.Expires)) {
		return "", session{}, false, nil
	}
	return ck.Value, s, true, nil
}

// end ends the session: it drops it from the store, when id is set, and has the
// browser drop the cookie.
func (c *Connect) end(w http.ResponseWriter, id string) {
	if id != "" {
		if err := c.Store.Delete(nsConnectSessions, sessionKey(id)); err != nil {
			c.log().Error("dropping a connect session", slog.String("error", err.Error()))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: connectCookie, Value: "", Path: c.base, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// takeLink takes the linking token, waiting for it while another connect holds it until
// ctx is done, and says whether it took it. A token that is free is taken even when ctx
// is done, so false says another connect held it all the while.
func (c *Connect) takeLink(ctx context.Context) bool {
	select {
	case c.linking <- struct{}{}:
		return true
	default:
	}
	select {
	case c.linking <- struct{}{}:
		return true
	case <-ctx.Done():
	}
	select {
	case c.linking <- struct{}{}:
		return true
	default:
		return false
	}
}

// refuse answers the refusal's page, ends the session id names when the refusal ends
// it, has the browser drop the cookie when the refusal says so, and logs the refusal once each
// [refusalEvery] at most, with attrs, which never hold a pass, a code, a token or a
// cookie.
func (c *Connect) refuse(w http.ResponseWriter, r *http.Request, rf refusal, id string, attrs ...slog.Attr) {
	if !rf.endSession {
		id = ""
	}
	if _, err := r.Cookie(connectCookie); (err == nil && rf.dropCookie) || rf.endSession {
		c.end(w, id)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(rf.status)
	io.WriteString(w, rf.page+"\n")
	ok, dropped := c.refusals.allow()
	if !ok {
		return
	}
	line := append([]slog.Attr{slog.String("step", c.step(r)), slog.Int("status", rf.status), slog.String("reason", rf.why)}, attrs...)
	if dropped > 0 {
		line = append(line, slog.Int("refusals_dropped", dropped))
	}
	c.log().LogAttrs(r.Context(), slog.LevelInfo, "connect refused", line...)
}

// failed answers that something failed on serve, ends the session id names, and logs
// what failed with the error, which is the store's.
func (c *Connect) failed(w http.ResponseWriter, r *http.Request, id, what string, err error) {
	c.log().LogAttrs(r.Context(), slog.LevelError, "connect failed", slog.String("step", c.step(r)), slog.String("what", what), slog.String("error", err.Error()))
	rf := refuseFailed
	rf.endSession = true
	c.refuse(w, r, rf, id)
}

// step names the request's step for the log: connect, return or authorized.
func (c *Connect) step(r *http.Request) string {
	switch r.URL.Path {
	case c.base + "/return":
		return "return"
	case c.base + "/authorized":
		return "authorized"
	}
	return "connect"
}

// redirect sends the browser to target, 303, with no body.
func redirect(w http.ResponseWriter, target string) {
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
}

// randomID is 32 bytes from crypto/rand in base64url without padding, 43 characters.
func randomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
