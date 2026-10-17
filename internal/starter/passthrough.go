package starter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// maxJobBody is the most a job's request body may hold; the pass-through reads
	// nothing from it.
	maxJobBody = 1 << 10
	// maxJobHeader is the most a job's request header may hold, room for a token of
	// [maxToken] bytes.
	maxJobHeader = 32 << 10
)

// handoverRoute is the one route the pass-through serves below the public URL's path:
// the handover of a dispatch, named by the provisioner contract's dispatch_id.
var handoverRoute = regexp.MustCompile(`^/v1/dispatches/(dp_[0-9a-hjkmnp-tv-z]{16})/handover$`)

// The pass-through's answers but the run key's. A request that names a dispatch the
// starter does not hold, whose token fails any check, or that comes after the
// dispatch's one request, gets the same answer, refused, so nobody learns which.
const (
	answerNotFound  = `{"error":"not_found"}`
	answerMethod    = `{"error":"method_not_allowed"}`
	answerTooLarge  = `{"error":"too_large"}`
	answerRefused   = `{"error":"forbidden"}`
	answerNoRunKey  = `{"error":"no_run_key"}`
	statusNoRunKey  = http.StatusBadGateway
	statusRefused   = http.StatusForbidden
	authorization   = "Authorization"
	bearer          = "Bearer "
	headerNoStore   = "no-store"
	contentTypeJSON = "application/json"
)

// ServeHTTP is the pass-through: POST <path>/v1/dispatches/<dispatch_id>/handover,
// where <path> is public_url's path without its trailing slash, as [publicPath] gives
// it, with the job's GitHub Actions OIDC token as a bearer, and nothing else. The
// request's target is taken exactly as sent, with no other escape, no query and no
// other form; any other target is 404, the route outside that path among them. On the
// handover's target, any other method is 405, and a body over [maxJobBody] is 413.
//
// The token is checked against the dispatch's workflow run, see [starter.expect]. A
// request for a dispatch the starter does not hold, whose token fails a check, or that
// is not the first request whose token passed for its dispatch, gets the same 403 and
// body, and so does the first when its request ends while it waits for the dispatched
// answer, as when the starter stops. The first that passes sends the handover, again
// while it fails for a while, see [starter.handover], and on the signed 200 answers
// {"run_key", "inputs"} with Cache-Control: no-store, after which the starter keeps no
// reference to the run key; copies of it stay in memory at least until they are
// collected as garbage, in the [Handed] value, the body of the signed answer and
// net/http's buffers among them. Any other end of the handover answers 502, and the
// dispatch ends as the handover's end says. No answer is a 200 without the run key.
func (st *starter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, under := strings.CutPrefix(r.RequestURI, st.prefix)
	m := handoverRoute.FindStringSubmatch(route)
	if !under || m == nil {
		writeJob(w, http.StatusNotFound, answerNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJob(w, http.StatusMethodNotAllowed, answerMethod)
		return
	}
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxJobBody)); err != nil {
		writeJob(w, http.StatusRequestEntityTooLarge, answerTooLarge)
		return
	}
	token, ok := bearerOf(r)
	if !ok {
		writeJob(w, statusRefused, answerRefused)
		return
	}
	st.mu.Lock()
	d := st.dispatches[m[1]]
	st.mu.Unlock()
	if d == nil {
		// The token is checked all the same, in full, against a run no token is for,
		// so an unknown dispatch is refused after the signature check, as a known
		// one is.
		_, _ = st.verifier.Verify(r.Context(), token, st.decoy())
		writeJob(w, statusRefused, answerRefused)
		return
	}
	var err error
	if st.now().Before(d.lease) {
		_, err = st.verifier.Verify(r.Context(), token, st.expect(d))
	} else {
		// Verify refuses a token at or after the lease before its signature is
		// checked; the token is checked in full against the decoy instead, so this
		// refusal comes after the signature check, as an unknown dispatch's does.
		_, _ = st.verifier.Verify(r.Context(), token, st.decoy())
		err = refuse("lease_until")
	}
	if err != nil {
		reason := Reason(err)
		if reason == "" {
			reason = "expect"
		}
		st.log.Warn("the job's token failed its check", slog.String("dispatch_id", d.id), slog.Int64("workflow_run_id", d.workflowRun), slog.String("reason", reason))
		writeJob(w, statusRefused, answerRefused)
		return
	}
	if !d.take() {
		writeJob(w, statusRefused, answerRefused)
		return
	}
	select {
	case <-d.ready:
	case <-r.Context().Done():
		writeJob(w, statusRefused, answerRefused)
		return
	}
	if !d.begin() {
		writeJob(w, statusRefused, answerRefused)
		return
	}
	handed, end, err := st.handover(r.Context(), d)
	if err != nil {
		st.log.Warn("the run key could not be handed over", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.String("error", err.Error()))
		d.finish(end)
		writeJob(w, statusNoRunKey, answerNoRunKey)
		return
	}
	d.mu.Lock()
	d.state = stateHanded
	d.mu.Unlock()
	body := jobAnswer(handed)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", headerNoStore)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(body)
	clear(body)
	if err != nil {
		st.log.Warn("the answer to the job could not be written", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.String("error", err.Error()))
		return
	}
	st.log.Info("handed the run to its job", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.Int64("workflow_run_id", d.workflowRun))
}

// bearerOf is the token of the request's one Authorization, Bearer and a token that is
// not empty; ok is false for any other.
func bearerOf(r *http.Request) (token string, ok bool) {
	values := r.Header.Values(authorization)
	if len(values) != 1 || !strings.HasPrefix(values[0], bearer) || len(values[0]) == len(bearer) {
		return "", false
	}
	return values[0][len(bearer):], true
}

// publicPath is the path of publicURL, escaped as it is sent, without its trailing
// slash: the pass-through's route is served below it, as a proxy that passes the path
// on sends it. A URL without a path, or one that does not parse, gives "".
func publicPath(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.EscapedPath(), "/")
}

// take takes the dispatch's one request, and reports whether it was still there: a
// dispatch that ended, or whose request was taken, has none.
func (d *dispatch) take() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.asked || d.state == stateEnded {
		return false
	}
	d.asked = true
	return true
}

// begin moves a dispatch whose dispatched was answered to stateAsking, and reports
// whether it was waiting.
func (d *dispatch) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state != stateWaiting {
		return false
	}
	d.state = stateAsking
	return true
}

// expect is the run d's job must prove it is: the settings' public_url as the
// audience; the repository as GitHub names it, its case included, and its id; the
// settings' workflow, ref and workflow_sha; d's workflow run; and d's lease, so a
// token is refused at or after lease_until.
func (st *starter) expect(d *dispatch) Expect {
	return Expect{
		Audience: st.settings.PublicURL, Repository: st.repo.FullName, RepositoryID: st.repo.ID,
		Workflow: st.settings.Workflow, Ref: st.settings.Ref, SHA: st.settings.WorkflowSHA,
		RunID: d.workflowRun, LeaseUntil: d.lease,
	}
}

// decoy is a run no token is for, a workflow run whose id GitHub never gives, which a
// token for an unknown dispatch is checked against.
func (st *starter) decoy() Expect {
	return st.expect(&dispatch{workflowRun: math.MaxInt64, lease: st.now().Add(time.Hour)})
}

// handover sends d's handover until it is answered with the signed 200, which it
// returns, while d's lease lasts: it stops at lease_until, and so do the tries of
// Qory Apiary's client, see [starter.sleepWithinLease]. A 409 no_gateway, a signed
// 503 unavailable, and a transient failure, no answer, an answer not signed under the
// pin, one over its bound or any other 5xx, send it again, built anew, after a wait
// that doubles from [firstBackoff] up to [maxHandoverWait]; a signed 429 after its
// Retry-After. Any other end is the error, with how the dispatch ends: on 409
// handed_over, a 200 lost on the way or the run handed over through a later dispatch,
// the job is stopped and the run released with retry true, and the run key is never
// recovered; on 409 lease_expired, 410 gone or 403 forbidden the job is stopped; on the
// lease ending, the job going away, or anything else, the job is stopped and the run
// released with retry true.
func (st *starter) handover(ctx context.Context, d *dispatch) (Handed, ending, error) {
	wait := firstBackoff
	for {
		if !st.now().Before(d.lease) {
			return Handed{}, ending{cancel: true, release: true, reason: reasonLeaseHanding}, errors.New("the lease ended before the handover was answered")
		}
		h, err := st.apiary.Handover(context.WithValue(ctx, leaseKey{}, d.lease), d.id, d.runID)
		var r *Refusal
		var pause time.Duration
		switch {
		case err == nil:
			return h, ending{}, nil
		case errors.Is(err, errLeaseEnded):
			return Handed{}, ending{cancel: true, release: true, reason: reasonLeaseHanding}, err
		case ctx.Err() != nil:
			return Handed{}, ending{cancel: true, release: true, reason: reasonJobLeft}, err
		case errors.Is(err, ErrHandedOver):
			return Handed{}, ending{cancel: true, release: true, reason: reasonHandedOver}, err
		case errors.Is(err, ErrLeaseExpired), errors.Is(err, ErrGone), errors.Is(err, ErrForbidden):
			return Handed{}, ending{cancel: true}, err
		case errors.Is(err, ErrRateLimited) && errors.As(err, &r):
			pause = r.RetryAfter
		case transient(err):
			pause, wait = wait, min(wait*2, maxHandoverWait)
		default:
			return Handed{}, ending{cancel: true, release: true, reason: reasonNotHanded}, err
		}
		pause = min(pause, d.lease.Sub(st.now()))
		st.log.Warn("the handover is sent again after a wait", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.Duration("wait", max(pause, 0)), slog.String("error", err.Error()))
		if pause > 0 {
			if err := st.sleep(ctx, pause); err != nil {
				return Handed{}, ending{cancel: true, release: true, reason: reasonJobLeft}, err
			}
		}
	}
}

// transient is whether a handover's err leaves the dispatch as it was, so the handover
// may be sent again, built anew, while the lease lasts: a 409 no_gateway, a signed 503
// unavailable, no answer, an answer not signed under the pin or over its bound, or any
// other 5xx.
func transient(err error) bool {
	var r *Refusal
	switch {
	case errors.Is(err, ErrNoGateway), errors.Is(err, ErrUnavailable), errors.Is(err, ErrUnsigned),
		errors.Is(err, ErrUnreachable), errors.Is(err, ErrTooLarge):
		return true
	case errors.As(err, &r):
		return r.Status >= 500
	}
	return false
}

// jobAnswer is the job's answer, {"run_key": ..., "inputs": ...}, the inputs as the
// handover's answer gave their bytes. It holds the raw run key, so it is written to the
// job alone, and cleared once written.
func jobAnswer(h Handed) []byte {
	key, _ := json.Marshal(h.RunKey.Value())
	inputs := h.Inputs.Value()
	b := make([]byte, 0, len(key)+len(inputs)+len(`{"run_key":,"inputs":}`))
	b = append(b, `{"run_key":`...)
	b = append(b, key...)
	b = append(b, `,"inputs":`...)
	b = append(b, inputs...)
	b = append(b, '}')
	clear(key)
	return b
}

// writeJob writes status and the JSON body, with Cache-Control: no-store.
func writeJob(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", headerNoStore)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
