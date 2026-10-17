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
// refusal, a 204 or an outcome's 200, up to maxAnswer. A larger answer is refused
// before its status or its signature is read, and nothing in it is used.
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
	// ErrLeaseExpired is the signed 409 lease_expired: the dispatch is stale, and the
	// starter stops the job it started for it.
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
	// ErrUnsigned is an answer not signed under the pin, still so after every try: a 401,
	// always unsigned, a 413, 415 or 400 bad_request decided before the signature, or
	// any other answer that does not verify. It changes no state. A 401 never means the
	// access key is revoked.
	ErrUnsigned = errors.New("an answer not signed under a key of apiary_public_key")
	// ErrUnreachable is Qory Apiary out of reach after every try: no answer.
	ErrUnreachable = errors.New("Qory Apiary could not be reached")
	// ErrAnswerUnusable is a signed answer that breaks the contract: larger than its
	// bound, not one JSON document, against its schema, of another revision, or for
	// another node pool or run than the one asked. Nothing in it is used, and the request
	// is not sent again, since Qory Apiary acted on it.
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

// Refusal is Qory Apiary's answer to a request that is not the one wanted: its status,
// whether it was signed under the pin, and the code of a signed one's body. errors.Is
// matches it against [ErrForbidden] and the other refusals by its request, its status
// and its code, and against [ErrUnsigned] when it is not signed. Its text names the
// request, the status and the code, never a body, a header or a secret.
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

	kind kind
}

func (r *Refusal) Error() string {
	switch {
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

// Is reports whether the refusal is target: [ErrUnsigned] for an answer not signed, or a
// signed refusal the request's schema gives, with its status and its code.
func (r *Refusal) Is(target error) bool {
	if target == ErrUnsigned {
		return !r.Signed
	}
	c, ok := codeOf[target]
	return ok && r.Signed && r.Status == c.status && r.Code == c.code && slices.Contains(refusalsOf[r.kind], target)
}

// Apiary is the starter's client of Qory Apiary's provisioner contract, provisioner/v1,
// and of Forager's run outcome. Each request is signed with the node pool's access key
// as forager/accesskey signs one, and each answer is checked under the pin, then
// against its schema and its revision, before anything in it is used. A request that
// fails is built anew for each try, with a later time and so a new signature: the same
// bytes are never sent twice. No redirect is followed. Nothing it logs or returns holds
// the access key's secret, a run key, a handover's inputs or a work item's title. It is
// safe for concurrent use.
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
	// PoolID is the node pool the settings name, or "": a claim then names none, and an
	// answer for another node pool is refused.
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

// Claimed is a claim's answer, claim-answer.schema.json, checked: signed under the pin,
// of the schema, of the revision sent and, when the settings name one, of their node
// pool. It prints, logs and marshals as its ids alone, never the work item's title; the
// document is its ClaimAnswer.
type Claimed struct{ contracts.ClaimAnswer }

// shownClaim is what a [Claimed] shows of itself.
type shownClaim struct {
	DispatchID string `json:"dispatch_id"`
	RunID      string `json:"run_id"`
	PoolID     string `json:"pool_id"`
	LeaseUntil string `json:"lease_until"`
	Step       string `json:"step"`
	WorkItemID string `json:"work_item_id"`
}

func (c Claimed) shown() shownClaim {
	return shownClaim{c.DispatchID, c.RunID, c.PoolID, c.LeaseUntil, c.Step, c.WorkItem.ID}
}

// String is the claim's ids.
func (c Claimed) String() string {
	return fmt.Sprintf("dispatch %s of run %s, node pool %s, step %s, work item %s, lease until %s", c.DispatchID, c.RunID, c.PoolID, c.Step, c.WorkItem.ID, c.LeaseUntil)
}

// GoString is [Claimed.String].
func (c Claimed) GoString() string { return c.String() }

// Format writes [Claimed.String] for every verb.
func (c Claimed) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue is the claim's ids.
func (c Claimed) LogValue() slog.Value {
	s := c.shown()
	return slog.GroupValue(slog.String("dispatch_id", s.DispatchID), slog.String("run_id", s.RunID), slog.String("pool_id", s.PoolID),
		slog.String("lease_until", s.LeaseUntil), slog.String("step", s.Step), slog.String("work_item_id", s.WorkItemID))
}

// MarshalJSON is the claim's ids.
func (c Claimed) MarshalJSON() ([]byte, error) { return json.Marshal(c.shown()) }

// Handed is a handover's answer, handover-answer.schema.json, checked: signed under the
// pin, of the schema and its bounds, of the revision sent, and for the claimed run. It
// holds the run key: it prints, logs and marshals as its run's id and step alone,
// never the run key, the inputs or the work item's title. The document, which the job
// alone is given, is its HandoverAnswer.
type Handed struct{ contracts.HandoverAnswer }

// String is the run's id and step.
func (h Handed) String() string {
	return fmt.Sprintf("handover of run %s, step %s, work item %s", h.RunID, h.Step, h.WorkItem.ID)
}

// GoString is [Handed.String].
func (h Handed) GoString() string { return h.String() }

// Format writes [Handed.String] for every verb.
func (h Handed) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, h.String()) }

// LogValue is the run's id and step.
func (h Handed) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run_id", h.RunID), slog.String("step", h.Step), slog.String("work_item_id", h.WorkItem.ID))
}

// MarshalJSON is the run's id and step.
func (h Handed) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RunID      string `json:"run_id"`
		Step       string `json:"step"`
		WorkItemID string `json:"work_item_id"`
	}{h.RunID, h.Step, h.WorkItem.ID})
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
	return Claimed{doc}, true, nil
}

// Dispatched sends POST /v1/dispatches/<dispatchID>/dispatched, dispatched.schema.json:
// the starter started the job, which external names when it is not nil. A signed 204 is
// the answer. A refusal is a [*Refusal]: [ErrForbidden], [ErrGone], [ErrLeaseExpired],
// on which the starter stops the job, or [ErrRateLimited].
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
	return Handed{doc}, nil
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
// verified under the pin, and its Retry-After.
type answer struct {
	status     int
	body       []byte
	signed     bool
	retryAfter string
}

// do sends req until Qory Apiary answers a signed status below 500, up to [tries]
// tries. Each try is built anew: its time is later than the last try's, by a second at
// least, so its bytes and its signature are new. A try that fails is no answer, an
// answer not signed under the pin, whatever its status, a 429 among them, or a signed
// server error: it changes nothing, and it is sent again after a wait that doubles
// from [firstWait]. After the last try, the failure is the error. An answer larger than
// its bound is [ErrAnswerUnusable], at once.
func (a *Apiary) do(ctx context.Context, req request) (*answer, error) {
	var last time.Time
	wait := firstWait
	for try := 1; ; try++ {
		t := a.now().UTC().Truncate(time.Second)
		if !t.After(last) && !last.IsZero() {
			t = last.Add(time.Second)
		}
		last = t
		b, err := a.build(req, t)
		if err != nil {
			return nil, err
		}
		ans, err := a.send(ctx, req, b)
		var failure error
		var line string
		var attrs []any
		switch {
		case errors.Is(err, ErrAnswerUnusable):
			return nil, err
		case err != nil:
			failure, line = err, "Qory Apiary could not be reached, so the request is sent again, built anew"
			attrs = []any{slog.String("error", err.Error())}
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
// body up to req.max, any other up to [maxAnswer], and a larger one is
// [ErrAnswerUnusable]. A 401 is never signed; any other answer is checked under the pin,
// bound to this request's signature. An error is no answer; it names the request and
// never a header, a body or a secret.
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
		return nil, unusable(req.what, fmt.Sprintf("its %d is larger than %d bytes", resp.StatusCode, limit))
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
