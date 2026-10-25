package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The routes of Qory Apiary's adapter API, the header that names the contract's
// revision, and the query parameter that carries the change feed's cursor: every place
// that names one reads it here, so a later rename costs one line.
const (
	routeAdapter     = "/v1/adapter"
	routeCollections = "/v1/source-collections"
	routeItems       = "/v1/source-items"
	routeComments    = "/v1/source-items/comments"
	routeDisconnect  = "/v1/sources/disconnect"
	routeChanges     = "/v1/work-items/changes"
	changesAfter     = "after"
	// routeConnectionsDisconnect ends a connection the source no longer grants access.
	routeConnectionsDisconnect = "/v1/connections/disconnect"
	// headerContractVersion carries contracts.Revision on every request. It is not
	// part of what the request's signature covers.
	headerContractVersion = "X-Qory-Contract-Version"
	// connectPath is serve's page under its public URL where Qory Apiary sends a
	// person to connect GitHub.
	connectPath = "/v1/connect"
)

// What serve declares to Qory Apiary at start: it pulls from GitHub every hour unless a
// person sets another interval, every 15 minutes at the most often, and sends GitHub's
// changes as its webhooks bring them.
const (
	defaultSyncInterval = 3600
	minimumSyncInterval = 900
)

// maximumSyncInterval is the longest interval the contract allows, a day: a longer one
// in the change feed is taken as a day.
const maximumSyncInterval = 86400

// The bounds of Qory Apiary's answers. A POST is answered within postTimeout, and its
// answer, a refusal at most, is read up to maxPostAnswer. Qory Apiary holds a read of
// the change feed up to 25 seconds while nothing follows its cursor, so changesTimeout
// is longer, and a page of the feed is read up to maxChangesAnswer. A larger answer is
// refused, never read in part.
const (
	postTimeout      = 30 * time.Second
	changesTimeout   = 40 * time.Second
	maxPostAnswer    = 64 << 10
	maxChangesAnswer = 16 << 20
)

// The waits for Qory Apiary's 429: the Retry-After it sends, an hour at most, one
// second at least, since a request built again within the same second as the one it
// retries could be the same bytes, whose signature Qory Apiary has seen; rateLimitedTries
// requests in all, after which the refusal is the answer.
const (
	maxRetryAfter    = time.Hour
	minRetryAfter    = time.Second
	rateLimitedTries = 5
)

// unauthorizedEvery is how often a 401 is logged at most; those in between are counted.
const unauthorizedEvery = time.Minute

// The refusal codes serve reads, contracts' refusal.schema.json.
const (
	codeCollectionNotLinked = "collection_not_linked"
	// codeConnectionEnded is final for the connection: serve drops what it keeps of it.
	// codeConnectionSuspended is not: serve changes nothing, and sends the request again
	// on its periodic check.
	codeConnectionEnded     = "connection_ended"
	codeConnectionSuspended = "connection_suspended"
	// codeConnectionUnknown is a 403 for a connection Qory Apiary does not hold for the
	// adapter, or, in a listing, one still pending. Qory Apiary sends it only to a
	// request that names the connection, a listing of its collections or its
	// disconnect: only one that lasts, for a live connection, ends it, see
	// [noteAnswer]. A 403 forbidden, a request outside the access key's rights, never
	// ends a connection.
	codeConnectionUnknown = "connection_unknown"
	codeForbidden         = "forbidden"
)

// The tries of POST /v1/connections/disconnect that Qory Apiary answers 403, as it
// answers one sent while the connection's linked connect return is being saved:
// disconnectTries in all, the waits between them doubling from disconnectWait, so the
// last is sent about two minutes after the first.
const (
	disconnectTries = 5
	disconnectWait  = 8 * time.Second
)

// refusalShape is a refusal code's form, refusal.schema.json's error.
var refusalShape = regexp.MustCompile(`^[a-z_]{1,64}$`)

// Apiary is Qory Apiary's client: it sends the adapter's requests, each signed with the
// adapter's access key, and checks each answer under the pin before it reads it. It is
// the [github.Sink] the listings and the webhooks' events send to. Every request goes
// to URL, which the settings fix, and no redirect is followed. It is safe for
// concurrent use.
type Apiary struct {
	// URL is Qory Apiary's origin, without a trailing slash.
	URL string
	// KeyID and Key are the adapter's access key: its id and its secret. AdapterID is
	// the id Qory Apiary enrolled the key in, which a seal of secrets binds to.
	KeyID     string
	Key       *accesskey.Key
	AdapterID string
	// Pin are Qory Apiary's public keys. Every answer is signed under them but a 401,
	// which is always unsigned, and a 413, 415 or 400 bad_request, which may be
	// unsigned. No unsigned answer is acted on but a 401, which is [Held]: any other
	// answer not signed under the pin is an [Outage], and its body is never parsed.
	// An answer larger than its bound, maxPostAnswer or maxChangesAnswer, is refused
	// before its status or its signature is checked, so it is neither: it is a plain
	// error.
	Pin accesskey.Pin
	// InstanceID is serve's instance id, made by [accesskey.NewInstanceID] and kept in
	// the store.
	InstanceID string
	// ProgramVersion is the program's version, which the description that
	// [Apiary.Declare] sends carries as its program_version.
	ProgramVersion string
	// HTTP is the client; nil is one with no other setting. Whichever it is, its
	// timeout is the request's, and no redirect is followed.
	HTTP *http.Client
	// Now is the clock a request's time and timestamp are read from; nil is time.Now.
	Now func() time.Time
	// Sleep waits d or until ctx is done; nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Unlinked, when set, is called with a collection's ref when Qory Apiary answers
	// its items 409 collection_not_linked, so serve stops sending its items, and with
	// the [linkMoment] the request began at, so a link the change feed stored since is
	// kept. A 409 collection_not_linked to comments never calls it, see
	// [Apiary.Comments], and Qory Apiary never answers a disconnect so, see
	// [Apiary.Disconnect].
	Unlinked func(collectionRef string, began uint64)
	// Ended, when set, is called with a connection's id when Qory Apiary answers a
	// request of that connection, or of a collection of it, 409 connection_ended, so
	// serve drops what it keeps of the connection. ConnectionOf, when set, is the
	// connection of a collection, read as a request for the collection begins, so the
	// answer speaks of the connection the request was sent for.
	Ended        func(connection string)
	ConnectionOf func(collectionRef string) string
	// Answered, when set, is called with a connection's id, the status and the refusal's
	// code, or "", of each signed answer to a request that names that connection, a
	// listing of its collections or its disconnect, the only requests Qory Apiary
	// answers 403 connection_unknown, and the time it came, so serve times a 403 that
	// lasts, see [noteAnswer]. A collection's disconnect names its connection too, and
	// is not noted, see [Apiary.Disconnect].
	Answered func(connection string, status int, code string, at time.Time)
	// Log takes the throttled line for a 401, and the line for comments Qory Apiary
	// answers 409 collection_not_linked; nil logs nothing.
	Log *slog.Logger
	// PullsAlone is whether serve learns of changes on GitHub by pulling alone, as when
	// GitHub cannot reach serve or the App's webhook is inactive: [Apiary.Declare] then
	// declares that the adapter does not send changes as they happen. It is set before
	// a declaration is sent, never while one is.
	PullsAlone bool
	// CallURL is call_url, where Qory Apiary sends its calls, which [Apiary.Declare]
	// declares when it is set and setupURL is empty: serve answers calls only while it
	// serves with an App. It is set before a declaration is sent, never while one is.
	CallURL string

	once         sync.Once
	unauthorized *throttle
	// creds, when set, are the access key and the pin in place of KeyID, Key and Pin:
	// serve's, which a re-enrolment replaces while requests are sent, see [reenroller].
	// Each request reads them once, so it is signed and its answer checked with one
	// enrolment. refused, when set, is called at each 401, which changes no state here.
	creds   *credentials
	refused func()

	// lastGet, when set, keeps the X-Qory-Timestamp of the latest GET across a
	// restart, see [Apiary.getTime]; nil keeps it in memory alone.
	lastGet lastGetStore

	// mu guards changesSent, when the last request for the change feed was sent, and
	// signer, the pin's key that verified the latest signed answer, see
	// [Apiary.UploadSecrets].
	mu          sync.Mutex
	changesSent time.Time
	signer      accesskey.PublicKey
	signerKnown bool

	// getMu guards getSecond, the X-Qory-Timestamp of the latest GET in Unix seconds,
	// and getLoaded, whether getSecond was read from lastGet yet.
	getMu     sync.Mutex
	getSecond int64
	getLoaded bool
}

// lastGetStore keeps the X-Qory-Timestamp of the latest GET in Unix seconds: load
// returns it, 0 when none is kept, and save replaces it.
type lastGetStore interface {
	load() (int64, error)
	save(second int64) error
}

// storeLastGet is a [lastGetStore] in the store, the adapter namespace's key
// last_get_timestamp. It belongs to the instance, as the instance id does, so a
// re-enrolment keeps it.
type storeLastGet struct{ st *store.Store }

const keyLastGet = "last_get_timestamp"

func (s storeLastGet) load() (int64, error) {
	b, err := s.st.Get(nsAdapter, keyLastGet)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	sec, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil || sec < 0 {
		return 0, errors.New("the store's last GET timestamp is not a number of seconds")
	}
	return sec, nil
}

func (s storeLastGet) save(second int64) error {
	return s.st.Put(nsAdapter, keyLastGet, []byte(strconv.FormatInt(second, 10)), 0)
}

// lastSigner is the pin's key that verified Qory Apiary's latest signed answer, and
// whether one did.
func (a *Apiary) lastSigner() (accesskey.PublicKey, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signer, a.signerKnown
}

// getTime is the time a GET signs in its X-Qory-Timestamp: the clock's second, or a
// second later than the latest GET's when that is later, whatever the GET's target.
// The contract wants each GET of one instance to carry a later timestamp than the GET
// before it, definitions.schema.json: Qory Apiary returns 401 for a signature it has
// seen, and an answer is bound to the GET's signature. The latest second is kept in
// lastGet before the GET is sent, so after a restart no GET carries that second or an
// earlier one. getTime never waits: a timestamp ahead of the clock is used at once.
// When the second that the process's first GET reads from lastGet is ahead of the
// clock, one line says so. GETs take their seconds one at a time, in the order they
// ask.
func (a *Apiary) getTime() (time.Time, error) {
	a.getMu.Lock()
	defer a.getMu.Unlock()
	now := a.now().Unix()
	if !a.getLoaded && a.lastGet != nil {
		sec, err := a.lastGet.load()
		if err != nil {
			return time.Time{}, fmt.Errorf("reading the latest GET's timestamp from the store: %w", err)
		}
		if sec > now && a.Log != nil {
			a.Log.Warn("the last GET's timestamp in the store is later than the clock, so serve continues from it; "+
				"Qory Apiary returns 401 for a GET more than 300 seconds ahead of its clock",
				slog.Int64("last_get_timestamp", sec), slog.Int64("clock", now))
		}
		a.getSecond = max(a.getSecond, sec)
	}
	a.getLoaded = true
	sec := max(now, a.getSecond+1)
	if a.lastGet != nil {
		if err := a.lastGet.save(sec); err != nil {
			return time.Time{}, fmt.Errorf("keeping the GET's timestamp in the store: %w", err)
		}
	}
	a.getSecond = sec
	return time.Unix(sec, 0), nil
}

// lastChanges is when the last request for the change feed was sent, a 429's retry
// among them, or the zero time.
func (a *Apiary) lastChanges() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.changesSent
}

func (a *Apiary) init() {
	a.once.Do(func() {
		a.unauthorized = &throttle{every: unauthorizedEvery, flush: func(dropped int) { a.logUnauthorized(dropped) }}
	})
}

func (a *Apiary) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Apiary) sleep(ctx context.Context, d time.Duration) error {
	if a.Sleep != nil {
		return a.Sleep(ctx, d)
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

// Collections sends POST /v1/source-collections.
func (a *Apiary) Collections(ctx context.Context, req contracts.SourceCollections) error {
	return a.post(ctx, "sending the collections", routeCollections, "", req.ConnectionID, func(t string) any { req.Time = t; return req })
}

// Items sends POST /v1/source-items. When Qory Apiary answers 409
// collection_not_linked, [Apiary.Unlinked] is called with the collection's ref, and the
// error is [Permanent].
func (a *Apiary) Items(ctx context.Context, req contracts.SourceItems) error {
	began := linkMoment()
	err := a.post(ctx, "sending the items of "+req.CollectionRef, routeItems, req.CollectionRef, "", func(t string) any { req.Time = t; return req })
	return a.unlinkOn(err, req.CollectionRef, began)
}

// Comments sends POST /v1/source-items/comments. An item's ref is the repository's id,
// #, and the issue's number, so its collection is the part before #. Qory Apiary
// answers 409 collection_not_linked for an item of a collection that is not linked,
// and for an item_ref it holds no item for, so that answer is final for this request
// only: it is logged, the comments are dropped with no error, and no link is changed.
// The change feed says when a collection is unlinked.
func (a *Apiary) Comments(ctx context.Context, req contracts.SourceItemComments) error {
	collection, _, _ := strings.Cut(req.ItemRef, "#")
	err := a.post(ctx, "sending the comments on "+req.ItemRef, routeComments, collection, "", func(t string) any { req.Time = t; return req })
	if !refusedAs(err, http.StatusConflict, codeCollectionNotLinked) {
		return err
	}
	if a.Log != nil {
		a.Log.Info("Qory Apiary answered collection_not_linked to the comments, so they are dropped", slog.String("item", req.ItemRef), slog.String("collection", collection))
	}
	return nil
}

// Disconnect sends POST /v1/sources/disconnect, which names the collection's ref and the
// connection the collection was listed under. Qory Apiary answers the signed 204 for a
// ref with no live collection under that connection, one live under another connection
// among them, and for a connection it does not hold, pending, ended or unknown: the
// answer says nothing of whether Qory Apiary holds the connection, so
// [Apiary.Answered] is not called with it. Of the 409s only connection_suspended
// applies, so a disconnect never unlinks a collection.
func (a *Apiary) Disconnect(ctx context.Context, req contracts.SourcesDisconnect) error {
	return a.postAs(ctx, "disconnecting "+req.CollectionRef, routeDisconnect, "", req.ConnectionID, func(t string) any { req.Time = t; return req })
}

// unlinkOn calls [Apiary.Unlinked] with collection and began when err is Qory Apiary's
// 409 collection_not_linked to a request for the collection's items that began at
// began, and returns err.
func (a *Apiary) unlinkOn(err error, collection string, began uint64) error {
	if a.Unlinked != nil && refusedAs(err, http.StatusConflict, codeCollectionNotLinked) {
		a.Unlinked(collection, began)
	}
	return err
}

// DisconnectConnection sends POST /v1/connections/disconnect: the source no longer
// grants the connection access. Qory Apiary answers 403 for a connection not made yet,
// and for one whose linked connect return is being saved, so a 403 is sent again, built
// anew, up to [disconnectTries] in all, see [disconnectWait]; a 403 that lasts is the
// error. A 409 connection_ended is the connection ended, as the signed 204 is, so it is
// no error.
func (a *Apiary) DisconnectConnection(ctx context.Context, req contracts.ConnectionsDisconnect) error {
	wait := disconnectWait
	for try := 1; ; try++ {
		err := a.post(ctx, "disconnecting the connection "+req.ConnectionID, routeConnectionsDisconnect, "", req.ConnectionID, func(t string) any { req.Time = t; return req })
		if refusedAs(err, http.StatusConflict, codeConnectionEnded) {
			return nil
		}
		if !refusedAs(err, http.StatusForbidden, "") || try == disconnectTries {
			return err
		}
		if err := a.sleep(ctx, wait); err != nil {
			return err
		}
		wait *= 2
	}
}

// Declare sends POST /v1/adapter, which serve sends each time it starts, and again
// once the App is set up: where a person connects GitHub, under publicURL; where an
// instance admin sets the App up, setupURL, which is left out when it is empty, as it
// is once an App is kept or the settings give one; where Qory Apiary calls serve,
// [Apiary.CallURL], declared only with no setupURL; how often serve pulls from GitHub,
// and whether it sends changes as they happen, which it does unless
// [Apiary.PullsAlone]; and the integration's description. The description is
// [github.Describe] with [Apiary.ProgramVersion], the source role among its roles: the
// document qory-github describe prints where QORY_FEATURES names factory, as
// json.Marshal writes it. Every declaration carries it. A description that cannot be
// marshalled is a [Permanent] error, as a body that cannot be is in every request.
func (a *Apiary) Declare(ctx context.Context, publicURL, setupURL string) error {
	const what = "declaring the adapter"
	description, err := json.Marshal(github.Describe(a.ProgramVersion))
	if err != nil {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	callURL := ""
	if setupURL == "" {
		callURL = a.CallURL
	}
	req := contracts.Adapter{
		Version:     contracts.Version,
		ConnectURL:  publicURL + connectPath,
		SetupURL:    setupURL,
		CallURL:     callURL,
		Sync:        contracts.Sync{DefaultInterval: defaultSyncInterval, MinimumInterval: minimumSyncInterval, SendsChanges: !a.PullsAlone},
		Description: description,
	}
	return a.post(ctx, what, routeAdapter, "", "", func(t string) any { req.Time = t; return req })
}

// Changes reads the change feed after cursor, GET /v1/work-items/changes, from the
// start when cursor is empty. Qory Apiary holds the request while nothing follows the
// cursor, so an answer may take up to 25 seconds. The answer is used only once its
// signature and its revision are checked, see [checkChanges].
func (a *Apiary) Changes(ctx context.Context, cursor string) (contracts.Changes, error) {
	const what = "reading the change feed"
	target := routeChanges
	if cursor != "" {
		target += "?" + url.Values{changesAfter: {cursor}}.Encode()
	}
	for try := 1; ; try++ {
		a.mu.Lock()
		a.changesSent = a.now()
		a.mu.Unlock()
		ans, err := a.send(ctx, what, http.MethodGet, target, nil, maxChangesAnswer, changesTimeout)
		if err == nil {
			err = a.judge(what, ans, "", "")
		}
		if wait, ok := retryWait(err); ok && try < rateLimitedTries {
			if err := a.sleep(ctx, wait); err != nil {
				return contracts.Changes{}, fmt.Errorf("%s: %w", what, err)
			}
			continue
		}
		if err != nil {
			return contracts.Changes{}, err
		}
		return checkChanges(ans.body)
	}
}

// checkChanges reads a page of the change feed, whose signature is checked already,
// and refuses one that is not of the version and the revision serve implements, or
// whose cursor is not one: a cursor is never taken from a page refused. The revision
// is checked here alone.
func checkChanges(body []byte) (contracts.Changes, error) {
	const what = "reading the change feed"
	var doc struct {
		contracts.Changes
		Revision *int `json:"revision"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return contracts.Changes{}, fmt.Errorf("%s: the answer is not the feed's document: %w", what, err)
	}
	ch := doc.Changes
	switch {
	case ch.Version != contracts.Version:
		return contracts.Changes{}, fmt.Errorf("%s: the answer is not of version %d", what, contracts.Version)
	case doc.Revision == nil || *doc.Revision != contracts.Revision:
		return contracts.Changes{}, fmt.Errorf("%s: the answer is not of the contract's revision %d", what, contracts.Revision)
	case ch.Cursor == "" || len(ch.Cursor) > 200:
		return contracts.Changes{}, fmt.Errorf("%s: the answer's cursor is not 1 to 200 characters", what)
	}
	ch.Revision = *doc.Revision
	return ch, nil
}

// post sends one POST, its body body with the time set, and judges the answer. A 429 is
// waited out and the request built again, with a later time and so a new signature.
// collection is the collection the request is for, when it is one collection's, and
// connection the connection the request names, when it names one; a collection's
// connection is read with [Apiary.ConnectionOf] as the request begins.
func (a *Apiary) post(ctx context.Context, what, route, collection, connection string, body func(time string) any) error {
	of := connection
	if of == "" && collection != "" && a.ConnectionOf != nil {
		of = a.ConnectionOf(collection)
	}
	return a.postAs(ctx, what, route, connection, of, body)
}

// postAs is [Apiary.post] for a request whose answers [Apiary.Answered] notes for
// connection, when it is not "", and whose 409 connection_ended speaks of the connection
// of, when it is not "".
func (a *Apiary) postAs(ctx context.Context, what, route, connection, of string, body func(time string) any) error {
	return a.postWith(ctx, nil, what, route, connection, of, body)
}

// postWith is [Apiary.postAs] signed with the enrolment e for every try, when e is set,
// or else with the enrolment in use as each try is sent.
func (a *Apiary) postWith(ctx context.Context, e *enrolment, what, route, connection, of string, body func(time string) any) error {
	for try := 1; ; try++ {
		b, err := json.Marshal(body(contracts.FormatTime(a.now())))
		if err != nil {
			return Permanent(fmt.Errorf("%s: %w", what, err))
		}
		if len(b) > contracts.MaxRequest {
			return Permanent(fmt.Errorf("%s: the request is larger than %d bytes, which Qory Apiary refuses", what, contracts.MaxRequest))
		}
		in := a.current()
		if e != nil {
			in = *e
		}
		ans, err := a.sendWith(ctx, in, what, http.MethodPost, route, b, maxPostAnswer, postTimeout)
		if err == nil {
			err = a.judge(what, ans, connection, of)
		}
		if wait, ok := retryWait(err); ok && try < rateLimitedTries {
			if err := a.sleep(ctx, wait); err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
			continue
		}
		return err
	}
}

// answer is Qory Apiary's answer to one request: its status, its body, whether its
// signature verified under the pin, and its Retry-After.
type answer struct {
	status     int
	body       []byte
	signed     bool
	retryAfter string
}

// send signs one request and sends it, then reads the answer, max bytes at most, and
// checks its signature under the pin, bound to this request's signature. A GET carries
// and signs X-Qory-Timestamp, later than the GET before it, see [Apiary.getTime]; a
// POST's signature covers its body. A 401 is never signed. An error is no answer; it
// begins with what and never says a header, the body or a secret. Qory Apiary out of
// reach, or its answer unread, is an [Outage].
func (a *Apiary) send(ctx context.Context, what, method, target string, body []byte, max int64, timeout time.Duration) (*answer, error) {
	return a.sendWith(ctx, a.current(), what, method, target, body, max, timeout)
}

// sendWith is [Apiary.send] signed with the enrolment e, its answer checked under e's
// pin.
func (a *Apiary) sendWith(ctx context.Context, e enrolment, what, method, target string, body []byte, max int64, timeout time.Duration) (*answer, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.URL+target, r)
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made", what)
	}
	keyID, key, pin := e.keyID, e.key, e.pin
	signed := accesskey.Request{AccessKeyID: keyID, InstanceID: a.InstanceID, Method: method, Target: req.URL.RequestURI()}
	if method == http.MethodPost {
		signed.Body = body
		req.Header.Set("Content-Type", "application/json")
	} else {
		at, err := a.getTime()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		signed.Timestamp = accesskey.Timestamp(at)
		req.Header.Set(accesskey.HeaderTimestamp, signed.Timestamp)
	}
	sig, err := key.SignRequest(signed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	req.Header.Set("User-Agent", "qory-github")
	req.Header.Set(accesskey.HeaderAccessKeyID, keyID)
	req.Header.Set(accesskey.HeaderInstanceID, a.InstanceID)
	req.Header.Set(headerContractVersion, strconv.Itoa(contracts.Revision))
	req.Header.Set(accesskey.HeaderSignature, sig)
	hc := http.Client{}
	if a.HTTP != nil {
		hc = *a.HTTP
	}
	hc.Timeout = timeout
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		var u *url.Error
		if errors.As(err, &u) {
			err = u.Err
		}
		return nil, Outage(fmt.Errorf("%s: Qory Apiary could not be reached: %w", what, err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, Outage(fmt.Errorf("%s: Qory Apiary's answer could not be read: %w", what, err))
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: Qory Apiary's answer is larger than %d bytes", what, max)
	}
	ans := &answer{status: resp.StatusCode, body: b, retryAfter: resp.Header.Get("Retry-After")}
	if resp.StatusCode == http.StatusUnauthorized {
		return ans, nil
	}
	one := func(name string) (string, bool) {
		v := resp.Header.Values(name)
		return strings.Join(v, ""), len(v) <= 1
	}
	signature, ok1 := one(accesskey.HeaderSignature)
	conf, ok2 := one(accesskey.HeaderConfiguration)
	run, ok3 := one(accesskey.HeaderRunConfiguration)
	if ok1 && ok2 && ok3 {
		signedAnswer := accesskey.Answer{Status: resp.StatusCode, RequestSignature: sig, Body: b, Configuration: conf, RunConfiguration: run}
		for _, k := range pin.Keys() {
			if k.VerifyAnswer(signedAnswer, signature) {
				ans.signed = true
				a.mu.Lock()
				a.signer, a.signerKnown = k, true
				a.mu.Unlock()
				break
			}
		}
	}
	return ans, nil
}

// rateLimited is Qory Apiary's 429, with the wait it asks for.
type rateLimited struct {
	what string
	wait time.Duration
}

func (e *rateLimited) Error() string {
	return e.what + ": Qory Apiary answered 429 rate_limited"
}

// retryWait is the wait err asks for when it is Qory Apiary's 429.
func retryWait(err error) (time.Duration, bool) {
	var r *rateLimited
	if errors.As(err, &r) {
		return r.wait, true
	}
	return 0, false
}

// judge is the error an answer is, or nil for a signed 2xx:
//
//   - a 401, unsigned whatever its cause, an access key not yet approved, one revoked,
//     a clock that is off or a replay, is [Held] and logged once a minute at most,
//     never taken as the key's revocation: it changes no state, and only tells
//     [Apiary.refused], with which serve looks for an enrolment code, see [reenroller];
//   - an answer whose signature does not verify under the pin is an [Outage], and its
//     body is never parsed;
//   - a signed answer to a request that names a connection, connection, is told to
//     [Apiary.Answered];
//   - 409 connection_ended calls [Apiary.Ended] with of, the connection the request
//     names or the connection of its collection; 409 connection_suspended changes
//     nothing, and the periodic check sends the request again. Each is [Permanent],
//     and so are 400, 403, 409 and 413, each a [*refusedError]; what a 409
//     collection_not_linked does is for the request's sender to say, see
//     [Apiary.Items] and [Apiary.Comments];
//   - a 429 is [*rateLimited], with its Retry-After, an hour at most;
//   - a 5xx is an [Outage];
//   - any other answer is an error that may pass.
//
// An error names the status and the refusal's code, never the body.
func (a *Apiary) judge(what string, ans *answer, connection, of string) error {
	if ans.status == http.StatusUnauthorized {
		a.init()
		if ok, dropped := a.unauthorized.allow(); ok {
			a.logUnauthorized(dropped)
		}
		if a.refused != nil {
			a.refused()
		}
		return Held(fmt.Errorf("%s: Qory Apiary answered 401 unauthorized", what))
	}
	if !ans.signed {
		return Outage(fmt.Errorf("%s: Qory Apiary's answer, %d, is not signed under a key of apiary_public_key, so it is not used", what, ans.status))
	}
	var refusal contracts.Refusal
	if ans.status < 200 || ans.status >= 300 {
		if json.Unmarshal(ans.body, &refusal) != nil || !refusalShape.MatchString(refusal.Error) {
			refusal.Error = ""
		}
	}
	if connection != "" && a.Answered != nil {
		a.Answered(connection, ans.status, refusal.Error, a.now())
	}
	if ans.status >= 200 && ans.status < 300 {
		return nil
	}
	var err error = &refusedError{what: what, status: ans.status, code: refusal.Error}
	switch ans.status {
	case http.StatusConflict:
		if refusal.Error == codeConnectionEnded && of != "" && a.Ended != nil {
			a.Ended(of)
		}
		return Permanent(err)
	case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge:
		return Permanent(err)
	case http.StatusTooManyRequests:
		return &rateLimited{what: what, wait: retryAfter(ans.retryAfter, a.now())}
	}
	if ans.status >= 500 {
		return Outage(err)
	}
	return err
}

// refusedError is Qory Apiary's signed answer that is not a 2xx: the request it answers,
// as post names it, the status, and the refusal's code, or "" when the answer names
// none.
type refusedError struct {
	what   string
	status int
	code   string
}

func (e *refusedError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("%s: Qory Apiary answered %d", e.what, e.status)
	}
	return fmt.Sprintf("%s: Qory Apiary answered %d %s", e.what, e.status, e.code)
}

// refusedAs is whether err, or an error it wraps or joins, is Qory Apiary's signed
// answer status, with the refusal code code unless code is "".
func refusedAs(err error, status int, code string) bool {
	var e *refusedError
	return errors.As(err, &e) && e.status == status && (code == "" || e.code == code)
}

// retryAfter reads Retry-After, seconds or an HTTP date, from one second to an hour; a
// value it cannot read is a second.
func retryAfter(v string, now time.Time) time.Duration {
	d := minRetryAfter
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		d = time.Duration(min(n, int64(maxRetryAfter/time.Second))) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, minRetryAfter), maxRetryAfter)
}

// logUnauthorized logs a 401, and how many were held back since the last line.
func (a *Apiary) logUnauthorized(dropped int) {
	if a.Log == nil {
		return
	}
	attrs := []any{slog.String("hint", "check in Qory Apiary that the access key access_key_id names is approved, and that this machine's clock is right")}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("dropped", dropped))
	}
	a.Log.Warn("Qory Apiary answered 401 unauthorized", attrs...)
}
