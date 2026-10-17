package starter

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/qoryai/forager/accesskey"
	foragercontracts "github.com/qoryai/forager/contracts"
)

var (
	// runURLShape is the run endpoint, Forager's configuration.schema.json run.url:
	// https, or http to a loopback address only, with no query, no fragment and no
	// trailing slash.
	runURLShape = regexp.MustCompile(`^(https://[^/?#@\s]+|http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?)(/[^\s?#]*[^\s?#/])?$`)
	// reasonShape is an outcome's reason, a code, run-outcome.schema.json's reason.
	reasonShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// The states an outcome may carry, dev.qory.run.exited's, run-outcome.schema.json.
const (
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// Outcome is how a handed-over run ended, the body of Forager's run-outcome.schema.json
// but its version and time, which [Apiary.PostOutcome] sets.
type Outcome struct {
	// State is [StateSucceeded], [StateFailed] or [StateCancelled]. Empty sends neither
	// state nor reason, which Forager reads as cancelled with the reason stopped.
	State string `json:"state,omitempty"`
	// Reason is a code: a lower-case letter, then lower-case letters, digits and
	// underscores, up to 64. It needs a State. Empty sends none.
	Reason string `json:"reason,omitempty"`
}

// outcomeBody is an outcome's body: the version, then the outcome's members and the
// time, in the order Forager's client writes them.
type outcomeBody struct {
	Version int `json:"version"`
	Outcome
	Time string `json:"time"`
}

// OutcomeOf is the outcome of a GitHub Actions workflow run that ended with conclusion:
// success is succeeded; failure, timed_out and startup_failure are failed; cancelled is
// cancelled. Any other conclusion, neutral, skipped, stale or action_required say, gives
// no state, which Forager reads as cancelled with the reason stopped. No reason is
// given.
func OutcomeOf(conclusion string) Outcome {
	switch conclusion {
	case "success":
		return Outcome{State: StateSucceeded}
	case "failure", "timed_out", "startup_failure":
		return Outcome{State: StateFailed}
	case "cancelled":
		return Outcome{State: StateCancelled}
	}
	return Outcome{}
}

// PostOutcome posts how the handed-over run runID ended, o, to <runURL>/<runID>/outcome,
// Forager's run-outcome.schema.json, signed with the node pool's access key, a key of
// the node pool that registered the run at its handover. runURL is the run endpoint,
// run.url of the configuration document Qory Apiary answers the key's signed GET of
// /.well-known/qory-configuration with; the handover's answer does not carry it.
// X-Qory-Contract-Version is Forager's revision. A State other than the three, a Reason
// without a State or that is no code, a runURL or a runID outside its form, and a runURL
// that holds qak_ or qrk_ are refused before anything is sent. Each try is built anew, with a later time. The
// answer is a signed 200 whose body run-outcome-answer.schema.json accepts, a member it
// does not define ignored. A refusal is a [*Refusal]: [ErrOutcomeGiven],
// [ErrRunNotFound] or [ErrRateLimited]; the same outcome again is answered the signed
// 200.
func (a *Apiary) PostOutcome(ctx context.Context, runURL, runID string, o Outcome) error {
	what := "the outcome of run " + runID
	switch {
	case !runIDShape.MatchString(runID):
		return errors.New("the outcome: the run id is not a UUID in the canonical lower-case form")
	case accesskey.ContainsSecret(runURL):
		return errors.New(what + ": the run endpoint holds what looks like a secret, qak_ or qrk_, so nothing is sent")
	case !runURLShape.MatchString(runURL):
		return errors.New(what + ": the run endpoint is not https, or http to a loopback address, with no query, no fragment and no trailing slash")
	case o.State != "" && o.State != StateSucceeded && o.State != StateFailed && o.State != StateCancelled:
		return errors.New(what + ": the state is not succeeded, failed or cancelled")
	case o.State == "" && o.Reason != "":
		return errors.New(what + ": a reason needs a state; with no state the outcome is cancelled with the reason stopped")
	case o.Reason != "" && !reasonShape.MatchString(o.Reason):
		return errors.New(what + ": the reason is not a code, a lower-case letter, then lower-case letters, digits and underscores, up to 64")
	}
	ans, err := a.do(ctx, request{
		what: what, kind: kindOutcome, url: runURL + "/" + runID + "/outcome", revision: foragercontracts.Revision,
		schema: "run-outcome.schema.json", foreign: true, max: maxAnswer, timeout: requestTimeout,
		body: func(t string) any { return outcomeBody{Version: 1, Outcome: o, Time: t} },
	})
	if err != nil {
		return err
	}
	if ans.status != http.StatusOK {
		return a.refused(what, kindOutcome, ans)
	}
	var doc struct {
		Version int `json:"version"`
	}
	if err := readAnswer(foragerSchema, "run-outcome-answer.schema.json", ans.body, &doc); err != nil {
		return unusable(what, err.Error())
	}
	return nil
}
