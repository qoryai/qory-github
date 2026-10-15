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
	// KeyID and Key are the adapter's access key: its id and its secret.
	KeyID string
	Key   *accesskey.Key
	// Pin are Qory Apiary's public keys. Every answer is signed under them but a 401,
	// which is always unsigned, and a 413, 415 or 400 bad_request, which may be
	// unsigned. No unsigned answer is acted on but a 401, which is [Held]: any other
	// answer not signed under the pin is an [Outage], and its body is never parsed.
	Pin accesskey.Pin
	// InstanceID is serve's instance id, i_ and 22 characters, kept in the store.
	InstanceID string
	// HTTP is the client; nil is one with no other setting. Whichever it is, its
	// timeout is the request's, and no redirect is followed.
	HTTP *http.Client
	// Now is the clock a request's time and timestamp are read from; nil is time.Now.
	Now func() time.Time
	// Sleep waits d or until ctx is done; nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Unlinked, when set, is called with a collection's ref when Qory Apiary answers
	// that the collection is not linked, so serve stops sending its items, and with the
	// [linkMoment] the request began at, so a link the change feed stored since is kept.
	Unlinked func(collectionRef string, began uint64)
	// Log takes the throttled line for a 401; nil logs nothing.
	Log *slog.Logger

	once         sync.Once
	unauthorized *throttle

	// mu guards changesSent, when the last request for the change feed was sent.
	mu          sync.Mutex
	changesSent time.Time
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
	return a.post(ctx, "sending the collections", routeCollections, "", func(t string) any { req.Time = t; return req })
}

// Items sends POST /v1/source-items. When Qory Apiary answers that the collection is not
// linked, [Apiary.Unlinked] is called with its ref, and the error is [Permanent].
func (a *Apiary) Items(ctx context.Context, req contracts.SourceItems) error {
	return a.post(ctx, "sending the items of "+req.CollectionRef, routeItems, req.CollectionRef, func(t string) any { req.Time = t; return req })
}

// Comments sends POST /v1/source-items/comments. An item's ref is owner/name#number, so
// its collection is the part before #, which [Apiary.Unlinked] is called with as
// [Apiary.Items] calls it.
func (a *Apiary) Comments(ctx context.Context, req contracts.SourceItemComments) error {
	collection, _, _ := strings.Cut(req.ItemRef, "#")
	return a.post(ctx, "sending the comments on "+req.ItemRef, routeComments, collection, func(t string) any { req.Time = t; return req })
}

// Disconnect sends POST /v1/sources/disconnect.
func (a *Apiary) Disconnect(ctx context.Context, req contracts.SourcesDisconnect) error {
	return a.post(ctx, "disconnecting "+req.CollectionRef, routeDisconnect, "", func(t string) any { req.Time = t; return req })
}

// Declare sends POST /v1/adapter, which serve sends each time it starts: where a person
// connects GitHub, under publicURL, and how often serve pulls from GitHub.
func (a *Apiary) Declare(ctx context.Context, publicURL string) error {
	req := contracts.Adapter{
		Version:    contracts.Version,
		ConnectURL: publicURL + connectPath,
		Sync:       contracts.Sync{DefaultInterval: defaultSyncInterval, MinimumInterval: minimumSyncInterval, SendsChanges: true},
	}
	return a.post(ctx, "declaring the adapter", routeAdapter, "", func(t string) any { req.Time = t; return req })
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
			err = a.judge(what, ans, "", 0)
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
// collection is the collection the request is for, when it is one collection's.
func (a *Apiary) post(ctx context.Context, what, route, collection string, body func(time string) any) error {
	began := linkMoment()
	for try := 1; ; try++ {
		b, err := json.Marshal(body(contracts.FormatTime(a.now())))
		if err != nil {
			return Permanent(fmt.Errorf("%s: %w", what, err))
		}
		if len(b) > contracts.MaxRequest {
			return Permanent(fmt.Errorf("%s: the request is larger than %d bytes, which Qory Apiary refuses", what, contracts.MaxRequest))
		}
		ans, err := a.send(ctx, what, http.MethodPost, route, b, maxPostAnswer, postTimeout)
		if err == nil {
			err = a.judge(what, ans, collection, began)
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
// and signs X-Qory-Timestamp; a POST's signature covers its body. A 401 is never
// signed. An error is no answer; it begins with what and never says a header, the
// body or a secret. Qory Apiary out of reach, or its answer unread, is an [Outage].
func (a *Apiary) send(ctx context.Context, what, method, target string, body []byte, max int64, timeout time.Duration) (*answer, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.URL+target, r)
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made", what)
	}
	signed := accesskey.Request{AccessKeyID: a.KeyID, InstanceID: a.InstanceID, Method: method, Target: req.URL.RequestURI()}
	if method == http.MethodPost {
		signed.Body = body
		req.Header.Set("Content-Type", "application/json")
	} else {
		signed.Timestamp = accesskey.Timestamp(a.now())
		req.Header.Set(accesskey.HeaderTimestamp, signed.Timestamp)
	}
	sig, err := a.Key.SignRequest(signed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	req.Header.Set("User-Agent", "qory-github")
	req.Header.Set(accesskey.HeaderAccessKeyID, a.KeyID)
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
	ans.signed = ok1 && ok2 && ok3 && a.Pin.VerifyAnswer(accesskey.Answer{Status: resp.StatusCode, RequestSignature: sig, Body: b, Configuration: conf, RunConfiguration: run}, signature)
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
//     never taken as the key's revocation;
//   - an answer whose signature does not verify under the pin is an [Outage], and its
//     body is never read;
//   - 409 collection_not_linked calls [Apiary.Unlinked] with collection and began,
//     and is [Permanent], and so are 400, 403, 409 and 413;
//   - a 429 is [*rateLimited], with its Retry-After, an hour at most;
//   - a 5xx is an [Outage];
//   - any other answer is an error that may pass.
//
// An error names the status and the refusal's code, never the body.
func (a *Apiary) judge(what string, ans *answer, collection string, began uint64) error {
	if ans.status == http.StatusUnauthorized {
		a.init()
		if ok, dropped := a.unauthorized.allow(); ok {
			a.logUnauthorized(dropped)
		}
		return Held(fmt.Errorf("%s: Qory Apiary answered 401 unauthorized", what))
	}
	if !ans.signed {
		return Outage(fmt.Errorf("%s: Qory Apiary's answer, %d, is not signed under a key of apiary_public_key, so it is not used", what, ans.status))
	}
	if ans.status >= 200 && ans.status < 300 {
		return nil
	}
	var refusal contracts.Refusal
	if json.Unmarshal(ans.body, &refusal) != nil || !refusalShape.MatchString(refusal.Error) {
		refusal.Error = ""
	}
	err := fmt.Errorf("%s: Qory Apiary answered %d", what, ans.status)
	if refusal.Error != "" {
		err = fmt.Errorf("%s: Qory Apiary answered %d %s", what, ans.status, refusal.Error)
	}
	switch ans.status {
	case http.StatusConflict:
		if refusal.Error == codeCollectionNotLinked && collection != "" && a.Unlinked != nil {
			a.Unlinked(collection, began)
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
