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
	"html/template"
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

// Connect is how a person links an installation of the App to a connection in Qory
// Apiary. An owner or administrator presses "Install" in Qory Apiary,
// which makes a connection, pending until the person comes back, unless it ends first,
// and sends the browser to serve's connect page with a connect pass, which Qory Apiary
// signed and which names the connection. Then:
//
//  1. GET <public_url>/v1/connect?state=<pass> checks the pass, see
//     [Connect.checkPass]: its expiry first, then its nonce, which it keeps until the
//     pass expires, so a pass is taken once, by the first browser that brings it, a
//     restart notwithstanding.
//     It starts a connect session for the pass, with a random state of 256 bits, and
//     answers 303 to <public_url>/v1/connect/continue, so the pass leaves the address
//     bar. A pass refused answers 303 too: to the pass_expired return, or to
//     <public_url>/v1/connect/refused, which shows the page a short-lived cookie names.
//  2. GET /v1/connect/continue sends the browser to GitHub's sign-in with the session's
//     state; the pass never leaves serve.
//  3. GET /v1/connect/authorized, the App's callback URL, takes the sign-in's code,
//     which needs the session's state, exchanges it for the person's token, and reads
//     the installations the person reaches. Then it sends the browser to install the App
//     on GitHub, with a new state; when the person reaches an installation of the App
//     already, it first shows a page that says to press Save on GitHub's page, since
//     only then does GitHub send the browser back. The token is not kept.
//  4. GET /v1/connect/return, the App's Setup URL, where GitHub sends the browser after
//     the installation, or after its change once Save is pressed. A state it carries
//     must be the session's. The installation it names is only a candidate, which the
//     session keeps, and nothing is linked here: it sends the browser to GitHub's
//     sign-in again, with a new state, which GitHub answers at once for a person who
//     authorised the App.
//  5. GET /v1/connect/authorized again, with that state and the session's cookie, under
//     a new token: the candidate is linked only once GitHub, under that token, lists it
//     among the person's installations, not suspended and with the permissions the
//     adapter needs, and says the person administers the account it is installed on, an
//     organisation's active administrator or the user the account is. So a grant is
//     linked only once it is finished in the browser that brought the pass, under that
//     pass, never on a value the browser sends back alone.
//
// Every step past the pass's checks ends with a connect return, see
// [Connect.connectReturn]: the browser goes back to Qory Apiary, to
// <apiary_url>/integrations/<connection_id>?return=<the connect return>, with the
// outcome, linked, refused with a reason, or cancelled, which Qory Apiary shows. Every
// return spends the pass: its session ends. These get serve's page instead, one
// sentence: a request that is not GET or whose query is not one serve reads; a pass
// that is forged or malformed, one taken already, or one for another adapter; a request
// without a session; a store that fails, or a connect return that fails to be made; and
// a connection that holds another installation already; and a pass no newer than the
// newest a linked return was minted under for the connection, see [Connect.link]. So
// does the request that tells the person to press Save.
//
// An installation is linked to one connection at a time, and a connection holds one
// installation, pending from the linked connect return, live once Qory Apiary takes a
// listing that names the connection, see [Connect.link]. A session lives in the store
// under the SHA-256 of a random id, which a cookie for /v1/connect alone carries, for 15
// minutes at most, see [sessionFor]. It ends with each connect return, and with each
// refusal that ends it once it is read; a refusal of the method, of the query's size or
// of its form comes before the session is read, so it keeps the session. Every
// redirect's target is built from the settings and the session, never from what the
// request carries, and a page says nothing the request carries.
//
// The pages count no requests by address: behind the operator's TLS proxy every request
// comes from the proxy's address, so such a count would bound every person at once.
// What a request costs is bounded otherwise: a pass's signature is checked before
// anything is written to the store, and the callback URL and the Setup URL read a
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
	// Key is the adapter's access key, which signs each connect return.
	Key *accesskey.Key
	// ClientID and ClientSecret are the App's, which GitHub's sign-in takes.
	ClientID     string
	ClientSecret []byte
	// PublicURL is where serve is reached from outside, without a trailing slash.
	PublicURL string
	// ApiaryURL is Qory Apiary's origin the adapter enrolled with, without a trailing
	// slash: every connect return goes to ApiaryURL/integrations/<connection_id> there.
	ApiaryURL string
	// Log takes a line for each connect, and the refusals, once a second at most.
	Log *slog.Logger

	// now is the clock; nil is time.Now. sleep waits d or until ctx is done between
	// the tries of a connection's first listing; nil waits on a timer.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	once     sync.Once
	base     string
	refusals *throttle
	// linking holds one token: the connect that holds it makes the checks of the
	// installation's link and of the connection's, and the link, one step, so two
	// connects at once link an installation to one connection, and a connection to one
	// installation. A connect waits for it [linkWait] at most, and its request's
	// deadline. linkWait is that wait; 0 is [linkWait].
	linking  chan struct{}
	linkWait time.Duration
	// fills are the first listings and the fills a connect started, which
	// [Connect.stop] stops and waits for. fillMu guards stopped, after which none
	// starts, and refilling, the collections a re-connect's fill is under way for,
	// which another does not fill again meanwhile.
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
	// connectCookie is the session's cookie, for the connect page's path alone. Its
	// prefix has a browser take it only when it is Secure.
	connectCookie = "__Secure-qory_github_connect"
	// pageCookie names the page /v1/connect/refused shows, for a minute at most, so
	// the request that carries a pass answers 303 to an address without it.
	pageCookie = "__Secure-qory_github_connect_page"
	pageFor    = time.Minute
	// sessionFor is how long a session, and its cookie, live: the contract's 900 seconds
	// at most, the pass's 15 minutes, counted from the pass's arrival, since its expiry
	// bounds only that. A connect slower than that finds no session, and its page says
	// it took too long.
	sessionFor = 900 * time.Second
	// passAhead is how far ahead of serve's clock a pass's expiry may be: Qory Apiary
	// makes a pass that expires at most 15 minutes after it is made.
	passAhead = 15 * time.Minute
	// returnFor is how long a connect return lives at most.
	returnFor = 300 * time.Second
	// maxConnectReturn is the most characters a connect return has, as a pass.
	maxConnectReturn = contracts.ConnectPassMaxLength
	// maxConnectQuery is the most bytes a request's query may hold: a pass is 1,024
	// characters at most.
	maxConnectQuery = 2 << 10
	// connectBound is how long a step that reaches GitHub may take, within
	// [writeTimeout], its wait for another connect's link among it.
	connectBound = 50 * time.Second
	// linkWait is how long a connect waits for another connect's link, see
	// [Connect.takeLink].
	linkWait = 5 * time.Second
	// firstListingWait and firstListingMaxWait are the first and the longest wait
	// between the tries of a connection's first listing, see [Connect.listSoon].
	firstListingWait    = time.Second
	firstListingMaxWait = 64 * time.Second
	// lastListingMaxWait is the longest wait between the tries of a pending link's last
	// listing that fail passing, see [Connect.lastListing].
	lastListingMaxWait = time.Hour
	// returnSkew is how long past a connect return's expiry a link still pending is
	// listed once more, see [Adapter.listConnection]: the clock difference Qory
	// Apiary's freshness check allows.
	returnSkew = 300 * time.Second
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
// shows, and why, for the log. name, when set, is how [pageCookie] names the page.
type refusal struct {
	status          int
	page, why, name string
	// endSession ends the session the request carries, and dropCookie has the browser
	// drop the cookie, which endSession does too.
	endSession, dropCookie bool
}

// The pages that refuse, by what went wrong: a request that is not one; a pass that is
// forged or malformed, taken already, or another adapter's; a store that fails, or a
// connect return that fails to be made; no session; a connection that holds another
// installation; or a pass no newer than one a linked return was made under,
// refuseOlder. Each says one sentence, and nothing the request carries.
var (
	refuseMethod    = refusal{status: http.StatusMethodNotAllowed, page: "This address answers GET requests alone.", why: "the request is not GET"}
	refuseQuery     = refusal{status: http.StatusBadRequest, page: `This link is not one this server reads. Press "Install" in Qory Apiary again.`, why: "the query is too long, or not one this server reads", name: "query"}
	refusePass      = refusal{status: http.StatusBadRequest, page: `This link is not valid. Press "Install" in Qory Apiary again.`, why: "the pass is not one: too long, or not two parts in base64url", name: "pass"}
	refuseSignature = refusal{status: refusePass.status, page: refusePass.page, why: "the pass's signature does not verify under the pin", name: refusePass.name}
	refusePayload   = refusal{status: refusePass.status, page: refusePass.page, why: "the pass's payload is not the contract's", name: refusePass.name}
	refuseAdapter   = refusal{status: http.StatusForbidden, page: `This connect link is for another integration. Press "Install" on this integration's page in Qory Apiary.`, why: "the pass is for another adapter", name: "adapter"}
	refuseUsed      = refusal{status: http.StatusBadRequest, page: `This link was used already. Press "Install" in Qory Apiary again.`, why: "the pass's nonce was used already", name: "used"}
	refuseFailed    = refusal{status: http.StatusInternalServerError, page: `Something failed on this server. Press "Install" in Qory Apiary again.`, why: "the store, or the making of a connect return, failed", name: "failed"}
	refuseNoSession = refusal{status: http.StatusBadRequest, page: `No installation is under way in this browser, or it took too long. Press "Install" in Qory Apiary again.`, why: "no session", dropCookie: true}
	refuseHeld      = refusal{
		status:     http.StatusConflict,
		page:       "This connection already holds another installation of the App, and it holds only one.",
		why:        "the connection holds another installation, live, or pending under a pass as new as this one",
		endSession: true,
	}
	refuseOlder = refusal{
		status:     http.StatusConflict,
		page:       `A newer link for this connection was used already. Press "Install" in Qory Apiary again.`,
		why:        "the pass is no newer than one a linked return was made under",
		endSession: true,
	}
)

// pages are the pages [pageCookie] names, by name.
var pages = map[string]*refusal{"query": &refuseQuery, "pass": &refusePass, "adapter": &refuseAdapter, "used": &refuseUsed, "failed": &refuseFailed}

// passExpired is a pass that verifies but has expired, or expires too far ahead: no
// page, but a connect return, refused, pass_expired.
var passExpired = refusal{why: "the pass has expired, or expires too far ahead"}

// The outcomes of a connect return, and the reasons of one refused, the contract's.
const (
	outcomeLinked    = "linked"
	outcomeRefused   = "refused"
	outcomeCancelled = "cancelled"

	reasonPersonNotPermitted = "person_not_permitted"
	reasonGrantTaken         = "grant_taken"
	reasonGrantNotConfirmed  = "grant_not_confirmed"
	reasonGrantSuspended     = "grant_suspended"
	reasonPermissionMissing  = "permission_missing"
	reasonPassExpired        = "pass_expired"
	reasonSourceUnavailable  = "source_unavailable"
)

// verdict is how a connect ends that sends the browser back to Qory Apiary without a
// link: the connect return's outcome and reason, and why, for the log.
type verdict struct {
	outcome, reason, why string
}

// The verdicts, by what went wrong.
var (
	verdictExpired   = verdict{outcomeRefused, reasonPassExpired, passExpired.why}
	verdictCancelled = verdict{outcomeCancelled, "", "the person cancelled on GitHub"}
	verdictState     = verdict{outcomeRefused, reasonGrantNotConfirmed, "the sign-in's state is not the session's"}
	verdictReplay    = verdict{outcomeRefused, reasonGrantNotConfirmed, "the session's sign-in is taken already"}
	verdictSetup     = verdict{outcomeRefused, reasonGrantNotConfirmed, "the Setup URL's state is not the session's"}
	verdictDenied    = verdict{outcomeRefused, reasonGrantNotConfirmed, "the sign-in sent back no code"}
	verdictSignIn    = verdict{outcomeRefused, reasonGrantNotConfirmed, "the sign-in's code could not be exchanged"}
	verdictGitHub    = verdict{outcomeRefused, reasonSourceUnavailable, "GitHub failed"}
	verdictNoSignIn  = verdict{outcomeRefused, reasonGrantNotConfirmed, "the session holds no sign-in"}
	verdictAnswer    = verdict{outcomeRefused, reasonGrantNotConfirmed, "the Setup URL's query is not GitHub's"}
	verdictWaits     = verdict{outcomeRefused, reasonPersonNotPermitted, "the installation waits for an owner's approval"}
	verdictNoAccess  = verdict{outcomeRefused, reasonGrantNotConfirmed, "the person does not reach the installation"}
	verdictSuspended = verdict{outcomeRefused, reasonGrantSuspended, "GitHub has suspended the installation"}
	verdictPermitted = verdict{outcomeRefused, reasonPermissionMissing, "the installation does not grant a permission the adapter needs"}
	verdictNotAdmin  = verdict{outcomeRefused, reasonPersonNotPermitted, "the person does not administer the installation's account"}
	verdictTaken     = verdict{outcomeRefused, reasonGrantTaken, "the installation is linked to another connection that is made"}
	verdictBusy      = verdict{outcomeRefused, reasonSourceUnavailable, "another connect, or a listing, held the link past the deadline"}
	verdictApiary    = verdict{outcomeRefused, reasonSourceUnavailable, "the listing of the connection the installation is linked to failed"}
	verdictDeleted   = verdict{outcomeRefused, reasonGrantNotConfirmed, "GitHub deleted the installation meanwhile"}
	verdictPaused    = verdict{outcomeRefused, reasonSourceUnavailable, "Qory Apiary has suspended the connection the installation is linked to"}
)

// needs are the permissions an installation grants the App that the adapter needs,
// each at least at the level named: it lists the repositories, reads and writes their
// issues, and, for an organisation, reads whether the person administers it.
var (
	needs             = map[string]string{"metadata": "read", "issues": "write"}
	organisationNeeds = map[string]string{"members": "read"}
)

// levels orders a permission's levels.
var levels = map[string]int{"read": 1, "write": 2, "admin": 3}

// session is what the store keeps of a connect session: when it expires, in Unix
// nanoseconds; the connection and the nonce of the pass that started it, and when that
// pass expires, in Unix seconds; the state GitHub must send back next, a new one for
// each trip to GitHub, so each is taken once; whether the person signed in once; and
// the installation the Setup URL named, the candidate, which the second sign-in links.
type session struct {
	Expires    int64  `json:"expires"`
	Connection string `json:"connection_id"`
	Nonce      string `json:"nonce"`
	Pass       int64  `json:"pass_expires_at"`
	State      string `json:"state"`
	SignedIn   bool   `json:"signed_in,omitempty"`
	Candidate  int64  `json:"installation_id,omitempty"`
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

func (c *Connect) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
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

func (c *Connect) log() *slog.Logger {
	if c.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Log
}

// stop stops the first listings and the fills a connect started and waits for them,
// each first listing forgetting the parts it kept as it stops, see [Connect.listSoon],
// and logs the count of refusals held back, if any.
func (c *Connect) stop() {
	c.init()
	c.fillMu.Lock()
	c.stopped = true
	c.fillMu.Unlock()
	c.stopFills()
	c.fills.Wait()
	c.refusals.stop()
}

// Route is next with the connect page's five paths, under the public URL's path,
// answered by Connect: every other path goes to next, the receiver among them, whose
// bounds stay as they are.
//
// The first path's query carries the pass. serve keeps no access log, and its lines
// name a request's step, never its address or query; net/http's error log, which serve
// writes, names a panic's remote address and the panic, never the request's URL. A
// reverse proxy in front of serve should keep the query of /v1/connect out of its
// logs too.
func (c *Connect) Route(next http.Handler) http.Handler {
	c.init()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var step func(http.ResponseWriter, *http.Request, url.Values)
		switch r.URL.Path {
		case c.base:
			step = c.start
		case c.base + "/continue":
			step = c.proceed
		case c.base + "/refused":
			step = c.showPage
		case c.base + "/authorized":
			step = c.authorized
		case c.base + "/return":
			step = c.installed
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
	if rf == &passExpired {
		// The pass verifies, so it goes back as a connect return; its nonce, past its
		// expiry, is not kept, and no session starts.
		c.giveBack(w, r, "", p.ConnectionID, p.Nonce, verdictExpired)
		return
	}
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
	id := randomID()
	s := session{Expires: now.Add(sessionFor).UnixNano(), Connection: p.ConnectionID, Nonce: p.Nonce, Pass: expires.Unix(), State: randomID()}
	if err := c.save(id, s); err != nil {
		c.failed(w, r, "", "keeping the session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: connectCookie, Value: id, Path: c.base, MaxAge: int(sessionFor / time.Second), Expires: now.Add(sessionFor),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	redirect(w, c.base+"/continue")
}

// proceed is GET /v1/connect/continue, where a pass accepted sends the browser, with no
// pass in its address: it sends the browser to GitHub's sign-in with the session's
// state. Once the person has signed in, it goes back refused.
func (c *Connect) proceed(w http.ResponseWriter, r *http.Request, _ url.Values) {
	id, s, ok, err := c.session(r)
	if err != nil {
		c.failed(w, r, id, "reading the session", err)
		return
	}
	if !ok {
		c.refuse(w, r, refuseNoSession, "")
		return
	}
	if s.SignedIn {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictReplay)
		return
	}
	c.signIn(w, s.State)
}

// signIn sends the browser to GitHub's sign-in, with state, and the callback URL under
// the public URL.
func (c *Connect) signIn(w http.ResponseWriter, state string) {
	redirect(w, c.Adapter.GitHub.Web()+"/login/oauth/authorize?"+url.Values{
		"client_id": {c.ClientID}, "state": {state}, "redirect_uri": {c.PublicURL + github.ConnectAuthorizedPath},
	}.Encode())
}

// showPage is GET /v1/connect/refused, where a pass refused sends the browser: it shows
// the page [pageCookie] names, or [refusePass] when it names none, and drops the
// cookie. The refusal was logged as it was made.
func (c *Connect) showPage(w http.ResponseWriter, r *http.Request, _ url.Values) {
	rf := refusePass
	if ck, err := r.Cookie(pageCookie); err == nil && pages[ck.Value] != nil {
		rf = *pages[ck.Value]
	}
	http.SetCookie(w, &http.Cookie{Name: pageCookie, Value: "", Path: c.base, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(rf.status)
	io.WriteString(w, rf.page+"\n")
}

// checkPass checks a connect pass, in this order, and returns its payload and when it
// expires, or the refusal:
//
//  1. at most [contracts.ConnectPassMaxLength] characters, each base64url's or a dot,
//     split on its last dot into the payload and the signature, each base64url
//     without padding, decoded strictly;
//  2. the signature verifies under a key of the pin over [contracts.ConnectDomain], a
//     line feed and the payload's bytes, before the payload is parsed;
//  3. the payload is one JSON object with the contract's five members and no other,
//     each of the contract's shape, and version 1;
//  4. adapter_id is the adapter's;
//  5. expires_at has not passed on serve's clock, and is at most 15 minutes ahead,
//     or the refusal is [passExpired], returned with the payload, which verified.
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
		Version      *int    `json:"version"`
		AdapterID    *string `json:"adapter_id"`
		ConnectionID *string `json:"connection_id"`
		Nonce        *string `json:"nonce"`
		ExpiresAt    *string `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if !bytes.HasPrefix(payload, []byte("{")) || dec.Decode(&doc) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	if doc.Version == nil || *doc.Version != contracts.Version || doc.AdapterID == nil || !adapterIDShape.MatchString(*doc.AdapterID) ||
		doc.ConnectionID == nil || !connectionShape.MatchString(*doc.ConnectionID) ||
		doc.Nonce == nil || !nonceShape.MatchString(*doc.Nonce) || doc.ExpiresAt == nil {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	expires, err := time.Parse(contracts.TimeLayout, *doc.ExpiresAt)
	if err != nil || contracts.FormatTime(expires) != *doc.ExpiresAt {
		return contracts.ConnectPass{}, time.Time{}, invalid
	}
	p := contracts.ConnectPass{Version: *doc.Version, AdapterID: *doc.AdapterID, ConnectionID: *doc.ConnectionID, Nonce: *doc.Nonce, ExpiresAt: *doc.ExpiresAt}
	if p.AdapterID != c.AdapterID {
		return contracts.ConnectPass{}, time.Time{}, &refuseAdapter
	}
	if now.After(expires) || expires.Sub(now) > passAhead {
		return p, expires, &passExpired
	}
	return p, expires, nil
}

// authorized is GitHub's sign-in sending the browser back, GET
// /v1/connect/authorized?code=...&state=..., which needs the session and its state. The
// first sign-in reads the installations the person reaches and sends the browser to
// install the App; the second, once the Setup URL named a candidate, links it, see
// [Connect.bind]. A sign-in brought again goes back refused, its state taken.
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
	if !ok || subtle.ConstantTimeCompare([]byte(state), []byte(s.State)) != 1 {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictState)
		return
	}
	if s.SignedIn && s.Candidate == 0 {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictReplay)
		return
	}
	if e, _ := one(q, "error"); e == "access_denied" {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictCancelled)
		return
	}
	code, ok := one(q, "code")
	if q.Has("error") || !ok || !codeShape.MatchString(code) {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictDenied)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectBound)
	defer cancel()
	gh := c.Adapter.GitHub
	token, err := gh.UserToken(ctx, c.ClientID, c.ClientSecret, code, c.PublicURL+github.ConnectAuthorizedPath)
	if err != nil {
		v := verdictGitHub
		if github.CodeRefused(err) {
			v = verdictSignIn
		}
		c.giveBack(w, r, id, s.Connection, s.Nonce, v, slog.String("error", err.Error()))
		return
	}
	if s.Candidate != 0 {
		c.bind(ctx, w, r, id, s, token)
		return
	}
	reached, err := gh.UserInstallations(ctx, token)
	if err != nil {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictGitHub, slog.String("error", err.Error()))
		return
	}
	// The sign-in is taken once: its state gives way to the installation's.
	s.State, s.SignedIn = randomID(), true
	if err := c.save(id, s); err != nil {
		c.failed(w, r, id, "keeping the session", err)
		return
	}
	install := github.App{Slug: c.Adapter.Slug}.InstallURL(gh.Web()) + "?" + url.Values{"state": {s.State}}.Encode()
	if len(reached) > 0 {
		c.savePage(w, install)
		return
	}
	redirect(w, install)
}

// installed is GitHub's Setup URL, GET
// /v1/connect/return?installation_id=...&setup_action=..., which needs the session,
// after its first sign-in, and the session's state when it carries one. The
// installation it names is kept in the session as the candidate, and nothing is linked
// here: the browser goes to GitHub's sign-in again, with a new state, see
// [Connect.bind].
func (c *Connect) installed(w http.ResponseWriter, r *http.Request, q url.Values) {
	id, s, ok, err := c.session(r)
	if err != nil {
		c.failed(w, r, id, "reading the session", err)
		return
	}
	if !ok {
		c.refuse(w, r, refuseNoSession, "")
		return
	}
	if !s.SignedIn {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictNoSignIn)
		return
	}
	// GitHub sends back the state the installation's address carried; whether it does
	// once Save is pressed on an installation's page is not relied on, since the second
	// sign-in's state binds the grant.
	if states, has := q["state"]; has && (len(states) != 1 || subtle.ConstantTimeCompare([]byte(states[0]), []byte(s.State)) != 1) {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictSetup)
		return
	}
	if e, _ := one(q, "error"); e == "access_denied" {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictCancelled)
		return
	}
	action, _ := one(q, "setup_action")
	if action == "request" {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictWaits)
		return
	}
	raw, ok := one(q, "installation_id")
	if !ok || !installationShape.MatchString(raw) || (action != "install" && action != "update") {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictAnswer)
		return
	}
	s.Candidate, _ = strconv.ParseInt(raw, 10, 64)
	s.State = randomID()
	if err := c.save(id, s); err != nil {
		c.failed(w, r, id, "keeping the session", err)
		return
	}
	c.signIn(w, s.State)
}

// bind links the session's candidate, under the person's token from the second
// sign-in: it checks that GitHub lists the installation among the person's, that GitHub
// has not suspended it, that it grants the permissions the adapter needs, and that the
// person administers its account, see [Connect.administers]; then it links the
// installation to the session's connection, see [Connect.link]. The session ends
// whatever the answer.
func (c *Connect) bind(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, s session, token string) {
	installation := s.Candidate
	attrs := []slog.Attr{slog.Int64("installation", installation), slog.String("connection", s.Connection)}
	gh := c.Adapter.GitHub
	reached, err := gh.UserInstallations(ctx, token)
	if err != nil {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictGitHub, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	var in *github.UserInstallation
	for i := range reached {
		if reached[i].ID == installation {
			in = &reached[i]
		}
	}
	if in == nil {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictNoAccess, attrs...)
		return
	}
	if in.Suspended {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictSuspended, attrs...)
		return
	}
	if !permitted(*in) {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictPermitted, attrs...)
		return
	}
	admin, err := c.administers(ctx, token, in.Account)
	if err != nil {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictGitHub, append(attrs, slog.String("error", err.Error()))...)
		return
	}
	if !admin {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictNotAdmin, attrs...)
		return
	}
	if !c.takeLink(ctx) {
		c.giveBack(w, r, id, s.Connection, s.Nonce, verdictBusy, attrs...)
		return
	}
	expires := c.clock().Add(returnFor)
	again, v, rf, err := c.link(ctx, installation, s, expires.Unix())
	<-c.linking
	if err != nil {
		c.failed(w, r, id, "linking the installation", err)
		return
	}
	if rf != nil {
		c.refuse(w, r, *rf, id, attrs...)
		return
	}
	if v != nil {
		c.giveBack(w, r, id, s.Connection, s.Nonce, *v, attrs...)
		return
	}
	ret, err := c.connectReturn(s.Connection, s.Nonce, outcomeLinked, "", expires)
	if err != nil {
		c.failed(w, r, id, "making the connect return", err)
		return
	}
	c.listSoon(installation, s.Connection, again)
	c.end(w, id)
	c.log().LogAttrs(r.Context(), slog.LevelInfo, "connected", append(attrs, slog.Bool("again", again))...)
	c.toApiary(w, s.Connection, ret)
}

// permitted is whether the installation grants the App each permission it needs, see
// [needs], at least at the level named.
func permitted(in github.UserInstallation) bool {
	check := func(want map[string]string) bool {
		for name, level := range want {
			if levels[in.Permissions[name]] < levels[level] {
				return false
			}
		}
		return true
	}
	return check(needs) && (in.Account.Type != "Organization" || check(organisationNeeds))
}

// administers is whether the person whose token token is administers account, as
// GitHub says under that token: for an organisation, the person's membership of it is
// active, its role admin, and it names the organisation's id and the person's; for a
// user, the account is the person's, by id and by login. GitHub's 404 or 403 to the
// membership, a person not a member or a membership the token may not read, is no.
// Any other account is no.
func (c *Connect) administers(ctx context.Context, token string, account github.Account) (bool, error) {
	gh := c.Adapter.GitHub
	person, err := gh.User(ctx, token)
	if err != nil {
		return false, err
	}
	if person.ID <= 0 || account.ID <= 0 {
		return false, nil
	}
	switch account.Type {
	case "Organization":
		m, err := gh.OrgMembership(ctx, token, account.Login)
		if github.Gone(err) || github.Refused(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return m.State == "active" && m.Role == "admin" && m.Organization == account.ID && m.Person == person.ID, nil
	case "User":
		return person.ID == account.ID && strings.EqualFold(person.Login, account.Login), nil
	}
	return false, nil
}

// link links the installation to the session's connection, pending, which the caller
// does holding the linking token, and says whether the installation was linked to the
// connection and live already, a re-connect; or the verdict, or the page, that refuses
// it. An installation is linked to one connection at a time:
//
//   - one linked to the connection already stays, live, or pending with the new
//     return's expiry, which its last listing waits for, see [Adapter.listConnection],
//     and its link takes the session's pass, which is the newer;
//   - one linked to another connection that is live is refused, grant_taken;
//   - one linked to another connection that is pending is first listed for that
//     connection, so the link learns whether the connection was made meanwhile: a
//     signed 204, the link is live, refused, grant_taken; a 403 connection_unknown,
//     the connection is not made yet, and the link is replaced, and kept until its last
//     listing, see [keepReplaced]; a 409 connection_ended, the connection
//     ended, and the link is replaced; a 409 connection_suspended, refused,
//     source_unavailable, since Qory Apiary shows the suspension itself; any other
//     answer, refused, source_unavailable.
//
// And a connection holds one installation: when another installation is linked to the
// connection, see [Connect.heldBy], the page [refuseHeld] answers, and nothing is
// linked, unless that link is pending and gives way to a newer pass. Before all of that,
// a pass that expires no later than the newest pass a linked return was minted under for
// the connection, see [keepPass], gets [refuseOlder], whatever is linked to the
// connection now, so where both apply [refuseOlder] answers: Qory Apiary takes a return
// only for the connection's newest pass, which may be that return, still unspent. Each
// linked return it allows keeps its pass as that newest, with the link.
// A link it writes to the session's connection forgets the connection's record as
// replaced, see [keepReplaced], which is stale from then on, and the installation's
// first listings kept, see [Adapter.sendFirst], as a pending link a newer pass replaces
// forgets the first listing kept for it, so the first listing after a link it writes
// reads GitHub again.
//
// An installation GitHub deleted meanwhile, see [keepDeleted], is refused,
// grant_not_confirmed, and nothing is linked.
//
// It holds the installation's lock, and the lock of each other installation linked to
// the connection, from its first read of a link to its write, so no listing's answer
// lands between them; it waits for those locks [linkWait] at most, the caller holding
// the linking token meanwhile, and past that, or ctx, refuses, source_unavailable. The
// person administers the installation's account, which the caller checked, for each
// connect anew.
func (c *Connect) link(ctx context.Context, installation int64, s session, returnExpires int64) (bool, *verdict, *refusal, error) {
	newest, err := newestPass(c.Store, s.Connection)
	if err != nil {
		return false, nil, nil, err
	}
	if s.Pass <= newest {
		return false, nil, &refuseOlder, nil
	}
	wait := c.linkWait
	if wait <= 0 {
		wait = linkWait
	}
	locks, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	unlock, err := c.Adapter.lockInstallation(locks, installation)
	if err != nil {
		return false, &verdictBusy, nil, nil
	}
	defer unlock()
	gone, err := wasDeleted(c.Store, installation)
	if err != nil {
		return false, nil, nil, err
	}
	if gone {
		return false, &verdictDeleted, nil, nil
	}
	l, ok, err := linkOf(c.Store, installation)
	if err != nil {
		return false, nil, nil, err
	}
	var old *link
	switch {
	case ok && l.Connection == s.Connection:
		// A re-connect: a live link stays live, and a pending one takes the new return's
		// expiry, which its last listing waits for.
		l.Pass = max(l.Pass, s.Pass)
		if l.State == linkPending {
			l.Return = returnExpires
		}
		installMu.Lock()
		defer installMu.Unlock()
		if err := putLink(c.Store, installation, l); err != nil {
			return false, nil, nil, err
		}
		c.Adapter.dropFirsts(installation, s.Connection)
		if err := forgetReplaced(c.Store, s.Connection); err != nil {
			return false, nil, nil, err
		}
		return l.State == linkLive, nil, nil, keepPass(c.Store, s.Connection, s.Pass, c.clock())
	case ok && l.State == linkLive:
		return false, &verdictTaken, nil, nil
	case ok:
		listed := c.Adapter.listLocked(ctx, installation, l.Connection)
		installMu.Lock()
		now, still, err := linkOf(c.Store, installation)
		installMu.Unlock()
		if err != nil {
			return false, nil, nil, err
		}
		pending := still && now.Connection == l.Connection
		switch {
		case pending && now.State == linkLive:
			return false, &verdictTaken, nil, nil
		case !pending || refusedAs(listed, http.StatusConflict, codeConnectionEnded):
		case refusedAs(listed, http.StatusConflict, codeConnectionSuspended):
			return false, &verdictPaused, nil, nil
		case !refusedAs(listed, http.StatusForbidden, codeConnectionUnknown):
			c.listFailed(installation, l.Connection, listed)
			return false, &verdictApiary, nil, nil
		default:
			old = &now
		}
	}
	others, err := linkedTo(c.Store, s.Connection)
	if err != nil {
		return false, nil, nil, err
	}
	var replaced []int64
	for _, other := range others {
		if other == installation {
			continue
		}
		unlock, err := c.Adapter.lockInstallation(locks, other)
		if err != nil {
			return false, &verdictBusy, nil, nil
		}
		defer unlock()
		gives, rf, err := c.heldBy(other, s)
		if err != nil || rf != nil {
			return false, nil, rf, err
		}
		if gives {
			replaced = append(replaced, other)
		}
	}
	installMu.Lock()
	defer installMu.Unlock()
	for _, other := range replaced {
		l, ok, err := linkOf(c.Store, other)
		if err == nil && ok && l.Connection == s.Connection {
			err = dropInstallation(c.Store, other)
			c.Adapter.dropFirsts(other, s.Connection)
			c.log().Info("a newer pass for the connection replaces its pending link", slog.String("connection", s.Connection), slog.Int64("installation", other))
		}
		if err != nil {
			return false, nil, nil, err
		}
	}
	if old != nil {
		if err := keepReplaced(c.Store, installation, *old); err != nil {
			return false, nil, nil, err
		}
		c.log().Info("a connect for another connection replaces the installation's pending link", slog.String("connection", old.Connection), slog.Int64("installation", installation))
	}
	if err := putLink(c.Store, installation, link{Connection: s.Connection, State: linkPending, Pass: s.Pass, Return: returnExpires}); err != nil {
		return false, nil, nil, err
	}
	c.Adapter.dropFirsts(installation, "")
	// A record of the connection replaced before is stale once the connection is
	// linked again: its listings would end or empty it.
	if err := forgetReplaced(c.Store, s.Connection); err != nil {
		return false, nil, nil, err
	}
	if err := keepPass(c.Store, s.Connection, s.Pass, c.clock()); err != nil {
		return false, nil, nil, err
	}
	return false, nil, nil, dropUnlinked(c.Store, installation)
}

// heldBy checks the installation other, linked to the session's connection, which the
// caller holds the lock of, so no listing of it lands meanwhile, and says whether its
// link gives way to the session's:
//
//   - a link that is live holds the connection, and the page [refuseHeld] answers;
//   - a link that is pending gives way at once, unlisted, when the session's pass
//     expires later than the pass the link was made under, which makes it the newer,
//     since Qory Apiary issues a connection's passes in order and takes a connect return
//     only for the newest; to a pass as old, or older, [refuseHeld] answers;
//   - a link that names another connection by then, or none, holds nothing, and gives
//     way.
func (c *Connect) heldBy(other int64, s session) (bool, *refusal, error) {
	l, ok, err := linkOf(c.Store, other)
	switch {
	case err != nil:
		return false, nil, err
	case !ok || l.Connection != s.Connection:
		return true, nil, nil
	case l.State == linkLive, s.Pass <= l.Pass:
		return false, &refuseHeld, nil
	}
	return true, nil, nil
}

// listFailed logs a listing that failed, when it did.
func (c *Connect) listFailed(installation int64, connection string, err error) {
	if err != nil {
		c.log().Error("listing the installation's repositories failed", slog.Int64("installation", installation), slog.String("connection", connection), slog.String("error", err.Error()))
	}
}

// listSoon sends, after the answer, the first listing of connection for the
// installation, while the browser carries the linked connect return to Qory Apiary,
// which answers the listing 403 connection_unknown until it has taken the return. That
// 403, and a failure that passes, no answer, a 429, a 5xx, an answer not signed or a
// 403 forbidden, which is logged, is sent again, the waits doubling from
// [firstListingWait] up to [firstListingMaxWait], until the moment of the last listing:
// the expiry of the return the link keeps, or the replaced record keeps, and
// [returnSkew] more, on the adapter's clock. Until then each try is
// [Adapter.listFirst]'s, which reads GitHub once and sends the parts it keeps again,
// with the same listing's id and started_at, see [Adapter.sendFirst]. Then the parts
// kept are forgotten, and the link's last listing settles it, see [Adapter.listFor],
// which reads GitHub again, sent again past failures that pass, the waits doubling up
// to [lastListingMaxWait]. A signed 204 makes the link live, and a 409 connection_ended
// to any try drops it at once. Once a connect for another connection has replaced the
// link, each listing is the replaced connection's, empty, see [Adapter.listReplaced].
// It stops once the link is live or settled, once Qory Apiary refuses otherwise, a 409
// connection_suspended among them, which keeps the link, which is logged and which the
// round's listing takes up again, and once [Connect.stop] has run; as it stops, for
// any reason, it forgets the parts kept, see [Adapter.dropFirsts]. again, a
// re-connect, fills the linked collections again once the listing is taken, see
// [Connect.refill].
func (c *Connect) listSoon(installation int64, connection string, again bool) {
	c.init()
	c.fillMu.Lock()
	defer c.fillMu.Unlock()
	if c.stopped {
		return
	}
	c.fills.Add(1)
	go func() {
		defer c.fills.Done()
		defer c.Adapter.dropFirsts(installation, connection)
		wait := firstListingWait
		for {
			moment, ok := c.lastListing(installation, connection)
			if !ok {
				return
			}
			last := !c.Adapter.clock().Before(moment)
			var err error
			if last {
				c.Adapter.dropFirsts(installation, connection)
				err = c.Adapter.listFor(c.fillCtx, installation, connection)
			} else {
				err = c.Adapter.listFirst(c.fillCtx, installation, connection)
			}
			if c.fillCtx.Err() != nil {
				return
			}
			if l, ok, _ := linkOf(c.Store, installation); ok && l.Connection == connection && l.State == linkLive && err == nil {
				if again {
					c.refill(installation)
				}
				return
			}
			if moment, ok = c.lastListing(installation, connection); !ok {
				return
			}
			var refused *refusedError
			passing := !errors.As(err, &refused) || refused.status >= 500 || refused.status == http.StatusTooManyRequests
			if refusedAs(err, http.StatusForbidden, codeForbidden) {
				// A 403 forbidden never drops a link: it is sent again, as a failure that passes.
				passing = true
				c.log().Warn("Qory Apiary answered a listing 403 forbidden, so it is sent again later", slog.String("connection", connection), slog.Int64("installation", installation))
			}
			if err != nil && !passing && (last || !refusedAs(err, http.StatusForbidden, codeConnectionUnknown)) {
				c.listFailed(installation, connection, err)
				return
			}
			d := wait
			if now := c.Adapter.clock(); now.Before(moment) {
				d = min(wait, moment.Sub(now))
			}
			if c.wait(c.fillCtx, d) != nil {
				return
			}
			if last {
				wait = min(2*wait, lastListingMaxWait)
			} else {
				wait = min(2*wait, firstListingMaxWait)
			}
		}
	}()
}

// lastListing is the moment of the last listing of connection for the installation,
// and whether it is still to be listed: the installation is linked to it, and the
// moment is the expiry of the return its link keeps and [returnSkew] more; or it is a
// connection a connect replaced on the installation, see [keepReplaced], and the
// moment is that of the replaced link.
func (c *Connect) lastListing(installation int64, connection string) (time.Time, bool) {
	if l, ok, err := linkOf(c.Store, installation); err == nil && ok && l.Connection == connection {
		return time.Unix(l.Return, 0).Add(returnSkew), true
	}
	r, ok, err := replacedOf(c.Store, connection)
	if err != nil || !ok || r.Installation != installation {
		return time.Time{}, false
	}
	return time.Unix(r.Return, 0).Add(returnSkew), true
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

// connectReturn is the connect return for the pass whose connection and nonce are
// connection and nonce: the payload, contracts.ConnectReturn, version 1, with outcome,
// reason when it is refused, and expires, in whole seconds, [returnFor] from now;
// signed with the adapter's access key over [contracts.ConnectReturnDomain], a line feed
// and the payload's bytes; written as the payload in base64url without padding, a dot,
// and the signature in base64url without padding, at most [maxConnectReturn]
// characters. It is made only for a pass that verified.
func (c *Connect) connectReturn(connection, nonce, outcome, reason string, expires time.Time) (string, error) {
	if outcome != outcomeRefused {
		reason = ""
	}
	payload, err := json.Marshal(contracts.ConnectReturn{
		Version: contracts.Version, ConnectionID: connection, Nonce: nonce, Outcome: outcome, Reason: reason,
		ExpiresAt: contracts.FormatTime(expires),
	})
	if err != nil {
		return "", err
	}
	if c.Key == nil {
		return "", errors.New("no access key signs the connect return")
	}
	enc := base64.RawURLEncoding.EncodeToString
	ret := enc(payload) + "." + enc(c.Key.Sign(append([]byte(contracts.ConnectReturnDomain+"\n"), payload...)))
	if len(ret) > maxConnectReturn {
		return "", errors.New("the connect return is longer than 1024 characters")
	}
	return ret, nil
}

// giveBack ends the connect without a link: it makes the connect return of the verdict
// for the pass whose connection and nonce are connection and nonce, ends the session id
// names, when it is set, logs the verdict once each [refusalEvery] at most, with attrs,
// which never hold a pass, a code, a token or a cookie, and sends the browser back to
// Qory Apiary.
func (c *Connect) giveBack(w http.ResponseWriter, r *http.Request, id, connection, nonce string, v verdict, attrs ...slog.Attr) {
	ret, err := c.connectReturn(connection, nonce, v.outcome, v.reason, c.clock().Add(returnFor))
	if err != nil {
		c.failed(w, r, id, "making the connect return", err)
		return
	}
	if id != "" {
		c.end(w, id)
	}
	if ok, dropped := c.refusals.allow(); ok {
		line := append([]slog.Attr{slog.String("step", c.step(r)), slog.Int("status", http.StatusSeeOther), slog.String("reason", v.why), slog.String("outcome", v.outcome)}, attrs...)
		if v.reason != "" {
			line = append(line, slog.String("return_reason", v.reason))
		}
		if dropped > 0 {
			line = append(line, slog.Int("refusals_dropped", dropped))
		}
		c.log().LogAttrs(r.Context(), slog.LevelInfo, "connect refused", line...)
	}
	c.toApiary(w, connection, ret)
}

// toApiary sends the browser to Qory Apiary with the connect return ret, 303, to
// <apiary_url>/integrations/<connection_id>?return=<ret>: the origin is the settings'
// alone, the one the adapter enrolled with, and connection one a pass named that
// verified, of the contract's shape.
func (c *Connect) toApiary(w http.ResponseWriter, connection, ret string) {
	redirect(w, c.ApiaryURL+"/integrations/"+url.PathEscape(connection)+"?"+url.Values{"return": {ret}}.Encode())
}

// savePageHTML is the page that tells the person to press Save on GitHub's page, which
// links to GitHub's page to install the App.
var savePageHTML = template.Must(template.New("save").Parse(`<!doctype html>
<meta charset="utf-8"><title>qory-github</title>
<p>{{.Line}}</p>
<p><a href="{{.Target}}">{{.Link}}</a></p>
`))

// savePage answers the page that tells the person, who reaches an installation of the
// App already, to press Save on GitHub's page: GitHub sends the browser back to the
// Setup URL for an installation that exists only once Save is pressed. target is
// GitHub's page to install the App, built from the settings.
func (c *Connect) savePage(w http.ResponseWriter, target string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	savePageHTML.Execute(w, map[string]string{
		"Line":   "The App is already installed. On GitHub's page, choose the account, then press Save to finish.",
		"Link":   "Continue on GitHub",
		"Target": target,
	})
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
	if json.Unmarshal(b, &s) != nil || !c.clock().Before(time.Unix(0, s.Expires)) || !connectionShape.MatchString(s.Connection) || !nonceShape.MatchString(s.Nonce) {
		return "", session{}, false, nil
	}
	return ck.Value, s, true, nil
}

// end ends the session, which spends its pass: it drops it from the store, when id is
// set, and has the browser drop the cookie.
func (c *Connect) end(w http.ResponseWriter, id string) {
	if id != "" {
		if err := c.Store.Delete(nsConnectSessions, sessionKey(id)); err != nil {
			c.log().Error("dropping a connect session", slog.String("error", err.Error()))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: connectCookie, Value: "", Path: c.base, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// takeLink takes the linking token, waiting for it while another connect holds it,
// [linkWait] at most and until ctx is done, and says whether it took it. A token that
// is free is taken even when ctx is done, so false says another connect held it all
// the while.
func (c *Connect) takeLink(ctx context.Context) bool {
	wait := c.linkWait
	if wait <= 0 {
		wait = linkWait
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
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

// refuse answers the refusal's page, or, for the request that may carry a pass, a 303 to
// /v1/connect/refused, which shows it, see [pageCookie]; ends the session id names when
// the refusal ends it, has the browser drop the cookie when the refusal says so, and
// logs the refusal once each [refusalEvery] at most, with attrs, which never hold a
// pass, a code, a token or a cookie.
func (c *Connect) refuse(w http.ResponseWriter, r *http.Request, rf refusal, id string, attrs ...slog.Attr) {
	if !rf.endSession {
		id = ""
	}
	if _, err := r.Cookie(connectCookie); (err == nil && rf.dropCookie) || rf.endSession {
		c.end(w, id)
	}
	status := rf.status
	if r.URL.Path == c.base && r.Method == http.MethodGet && rf.name != "" {
		// The request may carry a pass, so the page shows at an address without it.
		status = http.StatusSeeOther
		http.SetCookie(w, &http.Cookie{
			Name: pageCookie, Value: rf.name, Path: c.base, MaxAge: int(pageFor / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		redirect(w, c.base+"/refused")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(rf.status)
		io.WriteString(w, rf.page+"\n")
	}
	ok, dropped := c.refusals.allow()
	if !ok {
		return
	}
	line := append([]slog.Attr{slog.String("step", c.step(r)), slog.Int("status", status), slog.String("reason", rf.why)}, attrs...)
	if dropped > 0 {
		line = append(line, slog.Int("refusals_dropped", dropped))
	}
	c.log().LogAttrs(r.Context(), slog.LevelInfo, "connect refused", line...)
}

// failed answers that something failed on serve, ends the session id names, and logs
// what failed with the error: the store's, or the making of a connect return's.
func (c *Connect) failed(w http.ResponseWriter, r *http.Request, id, what string, err error) {
	c.log().LogAttrs(r.Context(), slog.LevelError, "connect failed", slog.String("step", c.step(r)), slog.String("what", what), slog.String("error", err.Error()))
	rf := refuseFailed
	rf.endSession = true
	c.refuse(w, r, rf, id)
}

// step names the request's step for the log: connect, continue, authorized or return.
func (c *Connect) step(r *http.Request) string {
	switch r.URL.Path {
	case c.base + "/return":
		return "return"
	case c.base + "/authorized":
		return "authorized"
	case c.base + "/continue":
		return "continue"
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
