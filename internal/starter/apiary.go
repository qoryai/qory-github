package starter

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	foragercontracts "github.com/qoryai/forager/contracts"
	"github.com/qoryai/integrations/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The routes of the provisioner contract, and the header that names the revision a
// request was built for. Every place that names one reads it here.
const (
	routeClaim      = "/v1/pools/claim"
	routeDispatches = "/v1/dispatches/"
	// headerContractVersion carries the revision of the contract a request implements:
	// contracts.ProvisionerRevision on the provisioner contract's requests, Forager's
	// revision on a run's outcome. The signature does not cover it; the answers whose
	// content the revision bounds name it in their signed body.
	headerContractVersion = "X-Qory-Contract-Version"
	userAgent             = "qory-github-starter"
)

// The bounds of Qory Apiary's answers. A claim is held up to 25 seconds while no run
// can be claimed, so claimTimeout is longer than requestTimeout. A claim's 200 is read
// up to maxClaimAnswer, far more than its members' limits add up to; a handover's 200
// up to contracts.MaxHandoverAnswer, the contract's bound; every other answer, a
// refusal, a 204 or an outcome's 200, up to maxAnswer. A larger answer, whatever its
// status, is refused before its signature is read, nothing in it is used, and the
// request is sent again, built anew, as for an answer not signed.
const (
	requestTimeout = 30 * time.Second
	claimTimeout   = 40 * time.Second
	maxClaimAnswer = 64 << 10
	maxAnswer      = 64 << 10
)

// The tries of one request: tries in all, the waits between them doubling from
// firstWait. A try that fails, an answer not signed under the pin, a server error or no
// answer, is built anew and sent again after the wait. A signed 429's Retry-After is
// read from one second to an hour.
const (
	tries         = 5
	firstWait     = time.Second
	minRetryAfter = time.Second
	maxRetryAfter = time.Hour
)

var (
	// dispatchIDShape and runIDShape are the provisioner contract's dispatch_id and
	// run_id. An id is checked before it is put in a path.
	dispatchIDShape = regexp.MustCompile(`^dp_[0-9a-hjkmnp-tv-z]{16}$`)
	runIDShape      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// The refusals of Qory Apiary a later step acts on, each matched with errors.Is against
// the [*Refusal] a request returns. A signed refusal matches only for the request whose
// schema gives it, with its status and its code: provisioner/v1 claim.schema.json,
// dispatched.schema.json, handover.schema.json and release.schema.json, and Forager's
// run-outcome.schema.json.
var (
	// ErrForbidden is the signed 403 forbidden: a request outside the key's rights, a
	// claim's pool_id that is not the key's node pool, or a dispatch that is unknown or
	// of another node pool.
	ErrForbidden = errors.New("403 forbidden")
	// ErrGone is the signed 410 gone: the dispatch ended.
	ErrGone = errors.New("410 gone")
	// ErrHandedOver is a handover's signed 409 handed_over: the run was handed over
	// before, through this or another dispatch.
	ErrHandedOver = errors.New("409 handed_over")
	// ErrLeaseExpired is the signed 409 lease_expired: the dispatch is stale. The
	// contract asks the starter to stop the job it started for that dispatch.
	ErrLeaseExpired = errors.New("409 lease_expired")
	// ErrNotDispatched is a handover's signed 409 not_dispatched: the handover came
	// before dispatched.
	ErrNotDispatched = errors.New("409 not_dispatched")
	// ErrNoGateway is the signed 409 no_gateway of a claim or a handover. After a
	// handover's, the dispatch stays claimed until its lease lapses, and the handover
	// may be sent again, built anew, while the lease lasts.
	ErrNoGateway = errors.New("409 no_gateway")
	// ErrRateLimited is the signed 429 rate_limited; [Refusal.RetryAfter] is the wait it
	// asks for, after which the request is sent again, built anew. An unsigned 429 is not
	// one: it is [ErrUnsigned].
	ErrRateLimited = errors.New("429 rate_limited")
	// ErrOutcomeGiven is an outcome's signed 409 outcome_given: the run has another
	// outcome already.
	ErrOutcomeGiven = errors.New("409 outcome_given")
	// ErrRunNotFound is an outcome's signed 404 not_found: a run the key's node pool did
	// not register, or whose record is gone.
	ErrRunNotFound = errors.New("404 not_found")
	// ErrUnsigned is an answer within its bound that is not signed under the pin, still
	// so after every try: a 401, always unsigned, a 413, 415 or 400 bad_request decided
	// before the signature, or any other answer that does not verify. It changes no
	// state. A 401 never means the access key is revoked. An answer over its bound is
	// [ErrTooLarge] instead, a 401 among them.
	ErrUnsigned = errors.New("an answer not signed under a key of apiary_public_key")
	// ErrTooLarge is an answer larger than its bound, whatever its status, still so after
	// every try: it is refused for its size before its signature is read, so nothing
	// says whether Qory Apiary sent it, and it changes no state.
	ErrTooLarge = errors.New("an answer refused for its size before its signature was read")
	// ErrUnreachable is Qory Apiary out of reach after every try: no answer.
	ErrUnreachable = errors.New("Qory Apiary could not be reached")
	// ErrAnswerUnusable is a signed answer within its bound that breaks the contract: a
	// success status the request's schema does not give, a body that is not one JSON document,
	// that breaks its schema, that names another revision, that is for another node pool
	// or run than the one asked, or whose inputs are over their bound. Nothing in it is
	// used, and the request is not sent again, since Qory Apiary acted on it.
	ErrAnswerUnusable = errors.New("Qory Apiary's answer breaks the contract, so nothing in it is used")
)

// codeOf is the status and the code of each signed refusal above.
var codeOf = map[error]struct {
	status int
	code   string
}{
	ErrForbidden:     {http.StatusForbidden, "forbidden"},
	ErrGone:          {http.StatusGone, "gone"},
	ErrHandedOver:    {http.StatusConflict, "handed_over"},
	ErrLeaseExpired:  {http.StatusConflict, "lease_expired"},
	ErrNotDispatched: {http.StatusConflict, "not_dispatched"},
	ErrNoGateway:     {http.StatusConflict, "no_gateway"},
	ErrRateLimited:   {http.StatusTooManyRequests, "rate_limited"},
	ErrOutcomeGiven:  {http.StatusConflict, "outcome_given"},
	ErrRunNotFound:   {http.StatusNotFound, "not_found"},
}

// kind is which request a refusal answers.
type kind int

const (
	kindClaim kind = iota
	kindDispatched
	kindHandover
	kindRelease
	kindOutcome
)

// refusalsOf are the signed refusals each request's schema gives, in the order the
// control plane decides them: handover.schema.json's for a handover, and its order for
// a release; dispatched's 403 before its 410 and its 410 before its 409. Each request
// may also be answered 429, refusal.schema.json.
var refusalsOf = map[kind][]error{
	kindClaim:      {ErrForbidden, ErrNoGateway, ErrRateLimited},
	kindDispatched: {ErrForbidden, ErrGone, ErrLeaseExpired, ErrRateLimited},
	kindHandover:   {ErrForbidden, ErrGone, ErrHandedOver, ErrLeaseExpired, ErrNotDispatched, ErrNoGateway, ErrRateLimited},
	kindRelease:    {ErrForbidden, ErrGone, ErrLeaseExpired, ErrRateLimited},
	kindOutcome:    {ErrRunNotFound, ErrOutcomeGiven, ErrRateLimited},
}

// Refusal is an answer to a request that is not the one wanted: its status, whether it
// was signed under the pin or refused for its size first, and the code of a signed
// one's body. errors.Is matches it against [ErrForbidden] and the other refusals by its
// request, its status and its code, against [ErrUnsigned] when it is within its bound
// and not signed, and against [ErrTooLarge] when it is over its bound. Its text names
// the request, the status and the code, never a body, a header or a secret.
type Refusal struct {
	// What is the request, as an error names it: "the claim", "the handover of dp_…".
	What string
	// Status is the answer's HTTP status.
	Status int
	// Signed is whether the answer's signature verified under the pin. A code is read
	// from a signed answer alone.
	Signed bool
	// Code is a signed answer's refusal code, refusal.schema.json's error, or "" when
	// the body holds none.
	Code string
	// RetryAfter is the wait a signed 429 asks for, from a second to an hour; 0
	// otherwise.
	RetryAfter time.Duration
	// TooLarge is whether the answer was over its bound, Limit bytes, and so refused
	// before its signature was read.
	TooLarge bool
	Limit    int64

	kind kind
}

func (r *Refusal) Error() string {
	switch {
	case r.TooLarge:
		return fmt.Sprintf("%s: the answer, %d, is larger than %d bytes, so it was refused before its signature was read", r.What, r.Status, r.Limit)
	case !r.Signed && r.Status == http.StatusUnauthorized:
		return r.What + ": Qory Apiary answered 401 unauthorized, which is never taken as the access key revoked"
	case !r.Signed:
		return fmt.Sprintf("%s: Qory Apiary answered %d, not signed under a key of apiary_public_key, so it is not used", r.What, r.Status)
	case r.Code == "":
		return fmt.Sprintf("%s: Qory Apiary answered %d", r.What, r.Status)
	case r.RetryAfter > 0:
		return fmt.Sprintf("%s: Qory Apiary answered %d %s, and asks to wait %s", r.What, r.Status, r.Code, r.RetryAfter)
	}
	return fmt.Sprintf("%s: Qory Apiary answered %d %s", r.What, r.Status, r.Code)
}

// Is reports whether the refusal is target: [ErrTooLarge] for an answer over its bound,
// [ErrUnsigned] for one within it that is not signed, or a signed refusal the request's
// schema gives, with its status and its code.
func (r *Refusal) Is(target error) bool {
	switch target {
	case ErrTooLarge:
		return r.TooLarge
	case ErrUnsigned:
		return !r.Signed && !r.TooLarge
	}
	c, ok := codeOf[target]
	return ok && r.Signed && r.Status == c.status && r.Code == c.code && slices.Contains(refusalsOf[r.kind], target)
}

// Apiary is the starter's client of Qory Apiary's provisioner contract, provisioner/v1,
// and of Forager's run outcome. Each request is signed with the node pool's access key
// as forager/accesskey signs one, and each answer is checked under the pin, then
// against its schema and its revision, before anything in it is used. A request's time
// is the clock's, in whole seconds, and never ahead of it. A request with the same
// method, URL and body but its time as one sent within the clock's current second, a
// try sent again or an identical call, waits for the clock's next second first, so the
// same bytes are never sent twice; a distinct request does not wait. No redirect is
// followed. No error it returns and no line it logs holds the access
// key's secret, a run key, a handover's inputs or a work item's title; a [Claimed] or a
// [Handed] prints, logs and marshals without them. It is safe for concurrent use, and is
// used by its pointer.
type Apiary struct {
	// URL is Qory Apiary's origin, without a trailing slash, as [Settings.ApiaryURL].
	URL string
	// KeyID and Key are the node pool's access key: its id and its secret.
	KeyID string
	Key   *accesskey.Key
	// Pin are Qory Apiary's public keys, as [Settings.ApiaryPublicKey].
	Pin accesskey.Pin
	// InstanceID is the starter's instance id, i_ and 22 characters, signed into every
	// request.
	InstanceID string
	// PoolID is the node pool the settings name. When it is set, a claim names it, and a
	// claim's answer for another node pool is refused. When it is "", a claim names no
	// node pool, and the answer's node pool is compared with nothing.
	PoolID string
	// HTTP is the client; nil is one with no other setting. Its timeout is set per
	// request, and no redirect is followed.
	HTTP *http.Client
	// Now is the clock a request's time is read from; nil is time.Now.
	Now func() time.Time
	// Sleep waits d or until ctx is done; nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Log takes a line for each try sent again; nil logs nothing.
	Log *slog.Logger

	// mu guards last, the second each request identity was last sent at, see
	// [Apiary.nextTime].
	mu   sync.Mutex
	last map[string]time.Time
}

// nextTime is the time of a request whose identity, its method, its URL and its body
// built without the time, is id: the clock's second, once it is later than the second
// that identity was last sent at. Until it is, it waits for the clock's next second
// with [Apiary.Sleep], so it never runs ahead of the clock. An identity the clock is
// past is forgotten. Once ctx is done, its error is the error.
func (a *Apiary) nextTime(ctx context.Context, id string) (time.Time, error) {
	for {
		now := a.now().UTC()
		t := now.Truncate(time.Second)
		a.mu.Lock()
		for k, last := range a.last {
			if t.After(last) {
				delete(a.last, k)
			}
		}
		last, held := a.last[id]
		if !held {
			if a.last == nil {
				a.last = map[string]time.Time{}
			}
			a.last[id] = t
			a.mu.Unlock()
			return t, nil
		}
		a.mu.Unlock()
		if err := a.sleep(ctx, max(last.Add(time.Second).Sub(now), time.Millisecond)); err != nil {
			return time.Time{}, err
		}
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
	}
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

// hiddenText is how a [Hidden] value prints, logs and marshals.
const hiddenText = "[hidden]"

// Hidden is a value that stays out of logs and errors: a run key, a handover's inputs or
// a work item's title. It prints, logs and marshals as [hidden], whatever the verb and
// however deep it sits in another value, even in a field fmt cannot call its methods
// on: it holds the value behind a pointer, which fmt prints as an address below the top
// level. A printer that follows pointers by reflection, such as go-spew, would show the
// value. Value is the value itself; the zero Hidden is "".
type Hidden struct{ p *string }

// hide is s, hidden.
func hide(s string) Hidden { return Hidden{&s} }

// Value is the hidden value.
func (h Hidden) Value() string {
	if h.p == nil {
		return ""
	}
	return *h.p
}

// String is [hidden].
func (h Hidden) String() string { return hiddenText }

// GoString is [hidden].
func (h Hidden) GoString() string { return hiddenText }

// Format writes [hidden] for every verb.
func (h Hidden) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, hiddenText) }

// LogValue is [hidden].
func (h Hidden) LogValue() slog.Value { return slog.StringValue(hiddenText) }

// MarshalJSON is [hidden], as a JSON string.
func (h Hidden) MarshalJSON() ([]byte, error) { return json.Marshal(hiddenText) }

// WorkItem is the work item a run is for, definitions.schema.json's work_item: its
// public id, its page in Qory Apiary, and its title, hidden.
type WorkItem struct {
	ID    string
	URL   string
	Title Hidden
}

// Claimed is a claim's answer, claim-answer.schema.json, checked: signed under the pin,
// of the schema and of the revision sent, and, when the settings name a node pool, of
// that node pool. The work item's title is [Hidden].
type Claimed struct {
	DispatchID string
	RunID      string
	PoolID     string
	LeaseUntil string
	Step       string
	Access     string
	Target     contracts.Target
	WorkItem   WorkItem
}

// Handed is a handover's answer, handover-answer.schema.json, checked: signed under the
// pin, of the schema and its bounds, of the revision sent, and for the claimed run. The
// run key, the inputs, as the answer's bytes, and the work item's title are [Hidden];
// [Handed.Document] is the answer whole, for the job it is passed to.
type Handed struct {
	RunID    string
	RunKey   Hidden
	Step     string
	Access   string
	Target   contracts.Target
	WorkItem WorkItem
	Inputs   Hidden
}

// Document is the handover's answer as the contract's document. It holds the raw run
// key, inputs and title, so it must never be logged or printed.
func (h Handed) Document() contracts.HandoverAnswer {
	return contracts.HandoverAnswer{
		Version: 1, Revision: contracts.ProvisionerRevision, RunID: h.RunID, RunKey: h.RunKey.Value(),
		Step: h.Step, Access: h.Access, Target: h.Target,
		WorkItem: contracts.WorkItem{ID: h.WorkItem.ID, URL: h.WorkItem.URL, Title: h.WorkItem.Title.Value()},
		Inputs:   json.RawMessage(h.Inputs.Value()),
	}
}

// workItemOf is the contract's work item, its title hidden.
func workItemOf(w contracts.WorkItem) WorkItem {
	return WorkItem{ID: w.ID, URL: w.URL, Title: hide(w.Title)}
}

// Claim sends POST /v1/pools/claim, claim.schema.json, with waitSeconds, 0 to 25, and
// the settings' node pool when they name one. Qory Apiary holds it up to waitSeconds
// while no run can be claimed. A signed 204 is no run: ok is false. A signed 200 is the
// run claimed, once it is checked, see [Claimed]. A refusal is a [*Refusal]:
// [ErrForbidden], [ErrNoGateway] or [ErrRateLimited].
func (a *Apiary) Claim(ctx context.Context, waitSeconds int) (claimed Claimed, ok bool, err error) {
	const what = "the claim"
	ans, err := a.do(ctx, request{
		what: what, kind: kindClaim, url: a.URL + routeClaim, revision: contracts.ProvisionerRevision,
		schema: "claim.schema.json", max: maxClaimAnswer, timeout: claimTimeout,
		body: func(t string) any {
			return contracts.Claim{Version: 1, Time: t, PoolID: a.PoolID, WaitSeconds: waitSeconds}
		},
	})
	if err != nil {
		return Claimed{}, false, err
	}
	switch ans.status {
	case http.StatusNoContent:
		return Claimed{}, false, nil
	case http.StatusOK:
	default:
		return Claimed{}, false, a.refused(what, kindClaim, ans)
	}
	var doc contracts.ClaimAnswer
	if err := readAnswer(provisionerSchema, "claim-answer.schema.json", ans.body, &doc); err != nil {
		return Claimed{}, false, unusable(what, err.Error())
	}
	switch {
	case doc.Revision != contracts.ProvisionerRevision:
		return Claimed{}, false, unusable(what, fmt.Sprintf("it names the contract's revision %d, not %d", doc.Revision, contracts.ProvisionerRevision))
	case a.PoolID != "" && doc.PoolID != a.PoolID:
		return Claimed{}, false, unusable(what, fmt.Sprintf("it is for the node pool %s, not %s", doc.PoolID, a.PoolID))
	}
	return Claimed{
		DispatchID: doc.DispatchID, RunID: doc.RunID, PoolID: doc.PoolID, LeaseUntil: doc.LeaseUntil,
		Step: doc.Step, Access: doc.Access, Target: doc.Target, WorkItem: workItemOf(doc.WorkItem),
	}, true, nil
}

// Dispatched sends POST /v1/dispatches/<dispatchID>/dispatched, dispatched.schema.json:
// the starter started the job, which external names when it is not nil. A signed 204 is
// the answer. A refusal is a [*Refusal]: [ErrForbidden], [ErrGone], [ErrLeaseExpired],
// on which the contract asks the starter to stop the job, or [ErrRateLimited].
func (a *Apiary) Dispatched(ctx context.Context, dispatchID string, external *contracts.External) error {
	return a.toDispatch(ctx, "dispatched of "+dispatchID, kindDispatched, dispatchID, "dispatched", "dispatched.schema.json", func(t string) any {
		return contracts.Dispatched{Version: 1, Time: t, External: external}
	})
}

// Release sends POST /v1/dispatches/<dispatchID>/release, release.schema.json: the
// starter gives the run back, for reason, display text of 1 to 200 characters, and
// whether it should wait for another claim. A signed 204 is the answer, after the
// handover too. A refusal is a [*Refusal]: [ErrForbidden], [ErrGone], [ErrLeaseExpired]
// or [ErrRateLimited].
func (a *Apiary) Release(ctx context.Context, dispatchID, reason string, retry bool) error {
	return a.toDispatch(ctx, "the release of "+dispatchID, kindRelease, dispatchID, "release", "release.schema.json", func(t string) any {
		return contracts.Release{Version: 1, Time: t, Reason: reason, Retry: retry}
	})
}

// toDispatch sends a request about one dispatch whose answer is a signed 204.
func (a *Apiary) toDispatch(ctx context.Context, what string, k kind, dispatchID, action, schema string, body func(string) any) error {
	if !dispatchIDShape.MatchString(dispatchID) {
		return fmt.Errorf("%s: the dispatch id is not dp_ and 16 lower-case Crockford base32 characters", what)
	}
	ans, err := a.do(ctx, request{
		what: what, kind: k, url: a.URL + routeDispatches + dispatchID + "/" + action, revision: contracts.ProvisionerRevision,
		schema: schema, max: maxAnswer, timeout: requestTimeout, body: body,
	})
	if err != nil {
		return err
	}
	if ans.status != http.StatusNoContent {
		return a.refused(what, k, ans)
	}
	return nil
}

// Handover sends POST /v1/dispatches/<dispatchID>/handover, handover.schema.json, for
// the job started for the dispatch of the claimed run runID. A signed 200 is the run key
// and the job's input, once checked, see [Handed]: its run_id must be runID, and its
// inputs at most contracts.MaxInputs bytes, compacted. A refusal is a [*Refusal], in
// handover.schema.json's order: [ErrForbidden], [ErrGone], [ErrHandedOver],
// [ErrLeaseExpired], [ErrNotDispatched], [ErrNoGateway], or [ErrRateLimited].
func (a *Apiary) Handover(ctx context.Context, dispatchID, runID string) (Handed, error) {
	what := "the handover of " + dispatchID
	if !dispatchIDShape.MatchString(dispatchID) {
		return Handed{}, fmt.Errorf("%s: the dispatch id is not dp_ and 16 lower-case Crockford base32 characters", what)
	}
	if !runIDShape.MatchString(runID) {
		return Handed{}, fmt.Errorf("%s: the run id is not a UUID in the canonical lower-case form", what)
	}
	ans, err := a.do(ctx, request{
		what: what, kind: kindHandover, url: a.URL + routeDispatches + dispatchID + "/handover", revision: contracts.ProvisionerRevision,
		schema: "handover.schema.json", max: contracts.MaxHandoverAnswer, timeout: requestTimeout,
		body: func(t string) any { return contracts.Handover{Version: 1, Time: t} },
	})
	if err != nil {
		return Handed{}, err
	}
	if ans.status != http.StatusOK {
		return Handed{}, a.refused(what, kindHandover, ans)
	}
	var doc contracts.HandoverAnswer
	if err := readAnswer(provisionerSchema, "handover-answer.schema.json", ans.body, &doc); err != nil {
		return Handed{}, unusable(what, err.Error())
	}
	var inputs bytes.Buffer
	switch {
	case doc.Revision != contracts.ProvisionerRevision:
		return Handed{}, unusable(what, fmt.Sprintf("it names the contract's revision %d, not %d", doc.Revision, contracts.ProvisionerRevision))
	case doc.RunID != runID:
		return Handed{}, unusable(what, fmt.Sprintf("it is for the run %s, not the claimed run %s", doc.RunID, runID))
	case json.Compact(&inputs, doc.Inputs) != nil || inputs.Len() > contracts.MaxInputs:
		return Handed{}, unusable(what, fmt.Sprintf("its inputs are larger than %d bytes", contracts.MaxInputs))
	}
	return Handed{
		RunID: doc.RunID, RunKey: hide(doc.RunKey), Step: doc.Step, Access: doc.Access, Target: doc.Target,
		WorkItem: workItemOf(doc.WorkItem), Inputs: hide(string(doc.Inputs)),
	}, nil
}

// request is one request of the starter's: what it is, as an error names it, which
// refusals apply, where it goes, the revision it implements, the schema its body is
// checked against before it is sent, the bound of its answer's 200, its timeout, and
// its body with the time set.
type request struct {
	what     string
	kind     kind
	url      string
	revision int
	schema   string
	foreign  bool
	max      int64
	timeout  time.Duration
	body     func(time string) any
}

// answer is an answer to one request: its status, its body, whether its signature
// verified under the pin, its Retry-After, and whether it was over its bound, limit
// bytes, in which case neither its body nor its signature is read.
type answer struct {
	status     int
	body       []byte
	signed     bool
	retryAfter string
	tooLarge   bool
	limit      int64
}

// do sends req until Qory Apiary answers a signed status below 500, up to [tries]
// tries. Each try is built anew, its time from [Apiary.nextTime], so its bytes and its
// signature are new. A try that fails is no answer, an answer over its bound, whatever
// its status, an answer not signed under the pin, whatever its status, a 429 among
// them, or a signed server error: it changes nothing, and it is sent again after a wait
// that doubles from [firstWait]. After the last try, the failure is the error. Once ctx
// is done, its error is the error, and nothing more is logged or sent.
func (a *Apiary) do(ctx context.Context, req request) (*answer, error) {
	id, err := json.Marshal(req.body(""))
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made", req.what)
	}
	wait := firstWait
	for try := 1; ; try++ {
		t, err := a.nextTime(ctx, http.MethodPost+" "+req.url+"\n"+string(id))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", req.what, err)
		}
		b, err := a.build(req, t)
		if err != nil {
			return nil, err
		}
		ans, err := a.send(ctx, req, b)
		var failure error
		var line string
		var attrs []any
		switch {
		case err != nil:
			failure, line = err, "Qory Apiary could not be reached, so the request is sent again, built anew"
			attrs = []any{slog.String("error", err.Error())}
		case ans.tooLarge:
			failure = &Refusal{What: req.what, Status: ans.status, TooLarge: true, Limit: ans.limit, kind: req.kind}
			line = "the answer is larger than its bound, so it is refused before its signature is read and the request is sent again, built anew"
			attrs = []any{slog.Int("status", ans.status), slog.Int64("limit", ans.limit)}
		case !ans.signed:
			failure = &Refusal{What: req.what, Status: ans.status, kind: req.kind}
			line = "Qory Apiary's answer is not signed under a key of apiary_public_key, so the request is sent again, built anew"
			attrs = []any{slog.Int("status", ans.status)}
			if ans.status == http.StatusUnauthorized {
				attrs = append(attrs, slog.String("hint", "a 401 is never taken as the access key revoked: check in Qory Apiary that the access key access_key_id names is approved, and that this machine's clock is right"))
			}
		case ans.status >= 500:
			failure = a.refused(req.what, req.kind, ans)
			line = "Qory Apiary answered a server error, so the request is sent again, built anew"
			attrs = []any{slog.Int("status", ans.status)}
		default:
			return ans, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", req.what, err)
		}
		if try == tries {
			return nil, failure
		}
		if a.Log != nil {
			a.Log.Warn(line, append([]any{slog.String("request", req.what), slog.Duration("wait", wait)}, attrs...)...)
		}
		if err := a.sleep(ctx, wait); err != nil {
			return nil, fmt.Errorf("%s: %w", req.what, err)
		}
		wait *= 2
	}
}

// build is req's body with the time t, checked against its schema and for what looks
// like a secret before it is sent. Its error names the request and the schema, never a
// value.
func (a *Apiary) build(req request, t time.Time) ([]byte, error) {
	b, err := json.Marshal(req.body(contracts.FormatTime(t)))
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made", req.what)
	}
	if accesskey.ContainsSecret(string(b)) {
		return nil, fmt.Errorf("%s: the request holds what looks like a secret, qak_ or qrk_, so it is not sent", req.what)
	}
	compile := provisionerSchema
	if req.foreign {
		compile = foragerSchema
	}
	s, err := compile(req.schema)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", req.what, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || s.Validate(doc) != nil {
		return nil, fmt.Errorf("%s: the request breaks %s, so it is not sent", req.what, req.schema)
	}
	return b, nil
}

// send signs one POST of body to req.url and sends it, then reads the answer: a 200's
// body up to req.max, any other up to [maxAnswer]. A larger answer, whatever its status,
// is marked too large, and neither its body nor its signature is read. A 401 is never
// signed; any other answer is checked under the pin, bound to this request's signature.
// An error is no answer; it names the request and never a header, a body or a secret.
func (a *Apiary) send(ctx context.Context, req request, body []byte) (*answer, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, req.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made", req.what)
	}
	sig, err := a.Key.SignRequest(accesskey.Request{AccessKeyID: a.KeyID, InstanceID: a.InstanceID, Method: http.MethodPost, Target: hr.URL.RequestURI(), Body: body})
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be signed", req.what)
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", userAgent)
	hr.Header.Set(accesskey.HeaderAccessKeyID, a.KeyID)
	hr.Header.Set(accesskey.HeaderInstanceID, a.InstanceID)
	hr.Header.Set(headerContractVersion, strconv.Itoa(req.revision))
	hr.Header.Set(accesskey.HeaderSignature, sig)
	hc := http.Client{}
	if a.HTTP != nil {
		hc = *a.HTTP
	}
	hc.Timeout = req.timeout
	hc.Jar = nil
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(hr)
	if err != nil {
		var u *url.Error
		if errors.As(err, &u) {
			err = u.Err
		}
		return nil, fmt.Errorf("%s: %w: %w", req.what, ErrUnreachable, err)
	}
	defer resp.Body.Close()
	limit := int64(maxAnswer)
	if resp.StatusCode == http.StatusOK {
		limit = req.max
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w: its answer could not be read", req.what, ErrUnreachable)
	}
	if int64(len(b)) > limit {
		return &answer{status: resp.StatusCode, tooLarge: true, limit: limit}, nil
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

// refused is the [*Refusal] of a signed answer that is not the one wanted. Its code is
// read only from a body that is one JSON document refusal.schema.json accepts, or, for
// an outcome, a coded refusal of Forager's, {"error": "<code>", "names": [...]}; any
// other body, and a code that holds qak_ or qrk_, names no code. A 429's Retry-After is
// read from a second to an hour.
func (a *Apiary) refused(what string, k kind, ans *answer) error {
	r := &Refusal{What: what, Status: ans.status, Signed: ans.signed, kind: k}
	if ans.status >= 200 && ans.status < 300 {
		return unusable(what, fmt.Sprintf("it is a %d, which the contract does not give for this request", ans.status))
	}
	var doc struct {
		Error string `json:"error"`
	}
	if k == kindOutcome {
		if rr := accesskey.ReadRefusal(ans.status, ans.body); rr != nil {
			r.Code = rr.Code
		}
	} else if readAnswer(provisionerSchema, "refusal.schema.json", ans.body, &doc) == nil {
		r.Code = doc.Error
	}
	if accesskey.ContainsSecret(r.Code) {
		r.Code = ""
	}
	if ans.status == http.StatusTooManyRequests {
		r.RetryAfter = retryAfter(ans.retryAfter, a.now())
	}
	return r
}

// unusable is [ErrAnswerUnusable] for the request what, and why: a fixed text that may
// name ids, statuses and revisions, never a value of the answer's body otherwise.
func unusable(what, why string) error {
	return fmt.Errorf("%s: %w: %s", what, ErrAnswerUnusable, why)
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

// readAnswer reads body, a signed answer's, into out: one JSON document with valid
// UTF-8 and no member twice in any object, which the schema name accepts. Its error
// names the schema, never a value of body.
func readAnswer(compile func(string) (*jsonschema.Schema, error), name string, body []byte, out any) error {
	if !jsontext.Value(body).IsValid() {
		return errors.New("it is not one JSON document with valid UTF-8 and no member twice")
	}
	s, err := compile(name)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil || s.Validate(doc) != nil {
		return fmt.Errorf("it breaks %s", name)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("it breaks %s", name)
	}
	return nil
}

// schemaCache holds each compiled schema by its contract and name.
var schemaCache sync.Map

// cached compiles the schema name with compile once, and keeps it under key.
func cached(key, name string, compile func(string) (*jsonschema.Schema, error)) (*jsonschema.Schema, error) {
	if s, ok := schemaCache.Load(key); ok {
		return s.(*jsonschema.Schema), nil
	}
	s, err := compile(name)
	if err != nil {
		return nil, fmt.Errorf("the contract's schema %s does not compile", name)
	}
	schemaCache.Store(key, s)
	return s, nil
}

// provisionerSchema is a schema of provisioner/v1, compiled once.
func provisionerSchema(name string) (*jsonschema.Schema, error) {
	return cached("provisioner/"+name, name, contracts.CompileProvisioner)
}

// foragerSchema is a schema of Forager's contract, forager/v1, compiled once.
func foragerSchema(name string) (*jsonschema.Schema, error) {
	return cached("forager/"+name, name, foragercontracts.Compile)
}
