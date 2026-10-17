package starter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	foragercontracts "github.com/qoryai/forager/contracts"
)

// foragerFixture reads one file of Forager's contract.
func foragerFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(foragercontracts.FS, "fixtures/"+name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOutcomeKnownAnswer posts the outcome of Forager's known answers under its fixture
// access key and instance id, and checks the request's target, body and signature are
// the known ones, and the known answer, signed under the fixture signing key, is taken.
func TestOutcomeKnownAnswer(t *testing.T) {
	var keys struct {
		AccessKey struct {
			Secret      string `json:"secret"`
			AccessKeyID string `json:"access_key_id"`
			InstanceID  string `json:"instance_id"`
		} `json:"access_key"`
		SigningKey struct {
			PublicKey string `json:"public_key"`
		} `json:"signing_key"`
	}
	var known struct {
		Requests []struct {
			Body      string   `json:"body"`
			Lines     []string `json:"lines"`
			Signature string   `json:"signature"`
		} `json:"requests"`
		Answers []struct {
			Body      string   `json:"body"`
			Lines     []string `json:"lines"`
			Signature string   `json:"signature"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(foragerFixture(t, "known-answers/keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(foragerFixture(t, "known-answers/through-gateway.json"), &known); err != nil {
		t.Fatal(err)
	}
	const outcomeFile = "fixtures/known-answers/outcome.json"
	var req, ans int = -1, -1
	for i, r := range known.Requests {
		if r.Body == outcomeFile {
			req = i
		}
	}
	for i, a := range known.Answers {
		if a.Body == "fixtures/known-answers/outcome-answer.json" {
			ans = i
		}
	}
	if req < 0 || ans < 0 {
		t.Fatal("the known answers hold no outcome")
	}
	wantReq, wantAns := known.Requests[req], known.Answers[ans]
	answerBody := foragerFixture(t, "known-answers/outcome-answer.json")
	key, err := accesskey.ParseSecret(keys.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		target, signature, version string
		body                       []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.target, got.signature, got.version = r.URL.RequestURI(), r.Header.Get(accesskey.HeaderSignature), r.Header.Get(headerContractVersion)
		got.body, _ = io.ReadAll(r.Body)
		w.Header().Set(accesskey.HeaderConfiguration, wantAns.Lines[4])
		w.Header().Set(accesskey.HeaderSignature, wantAns.Signature)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(answerBody)
	}))
	defer srv.Close()
	tm, _ := time.Parse(time.RFC3339, "2026-10-11T12:30:00Z")
	a := &Apiary{
		URL: srv.URL, KeyID: keys.AccessKey.AccessKeyID, Key: key, InstanceID: keys.AccessKey.InstanceID,
		Pin: accesskey.Pin{{Alg: "ed25519", PublicKey: keys.SigningKey.PublicKey}},
		Now: func() time.Time { return tm },
		Sleep: func(context.Context, time.Duration) error {
			t.Error("the known answer was not taken")
			return errors.New("stop")
		},
	}
	runID := "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	if err := a.PostOutcome(context.Background(), srv.URL+"/v1/runs", runID, Outcome{State: StateSucceeded, Reason: "all_checks_passed"}); err != nil {
		t.Fatalf("the outcome failed: %v", err)
	}
	switch {
	case got.target != wantReq.Lines[4]:
		t.Errorf("the target is %s, not %s", got.target, wantReq.Lines[4])
	case !bytes.Equal(got.body, foragerFixture(t, "known-answers/outcome.json")) || string(got.body) != wantReq.Lines[5]:
		t.Errorf("the body is not the known one: %s", got.body)
	case got.signature != wantReq.Signature:
		t.Error("the signature is not the known one")
	case got.version != strconv.Itoa(foragercontracts.Revision):
		t.Errorf("X-Qory-Contract-Version is %q, not Forager's revision", got.version)
	}
}

// TestOutcomeBodies checks the outcome of each GitHub conclusion, and that each body
// is one Forager's run-outcome.schema.json accepts, with no state and no reason when the
// outcome has none.
func TestOutcomeBodies(t *testing.T) {
	for conclusion, want := range map[string]string{
		"success": StateSucceeded, "failure": StateFailed, "timed_out": StateFailed, "startup_failure": StateFailed,
		"cancelled": StateCancelled, "neutral": "", "skipped": "", "stale": "", "action_required": "", "": "",
	} {
		o := OutcomeOf(conclusion)
		if o.State != want || o.Reason != "" {
			t.Errorf("%q: the outcome is %+v, not %q", conclusion, o, want)
		}
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: `{"version":1,"later":true}`} })
		a := f.client(&sleeps{}, nil)
		if err := a.PostOutcome(context.Background(), f.srv.URL+"/v1/runs", testRun, o); err != nil {
			t.Fatalf("%q: the outcome failed: %v", conclusion, err)
		}
		r := f.requests()[0]
		var doc map[string]any
		if err := json.Unmarshal(r.body, &doc); err != nil {
			t.Fatal(err)
		}
		_, hasState := doc["state"]
		_, hasReason := doc["reason"]
		var v any
		switch {
		case r.target != "/v1/runs/"+testRun+"/outcome":
			t.Errorf("the target is %s", r.target)
		case !r.verified:
			t.Error("the outcome does not verify under the pool's key")
		case hasState != (want != "") || hasReason:
			t.Errorf("%q: the body is %s", conclusion, r.body)
		case readAnswer(foragerSchema, "run-outcome.schema.json", r.body, &v) != nil:
			t.Errorf("%q: run-outcome.schema.json refuses %s", conclusion, r.body)
		}
	}
}

// TestOutcomeRefused checks what the client refuses before sending, and how it reads
// Forager's coded refusals and an answer the schema refuses.
func TestOutcomeRefused(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: `{"version":1}`} })
	a := f.client(&sleeps{}, nil)
	run := f.srv.URL + "/v1/runs"
	for name, err := range map[string]error{
		"a state it does not know":    a.PostOutcome(ctx, run, testRun, Outcome{State: "stopped"}),
		"a reason with no state":      a.PostOutcome(ctx, run, testRun, Outcome{Reason: "why"}),
		"a reason that is no code":    a.PostOutcome(ctx, run, testRun, Outcome{State: StateFailed, Reason: "Not A Code"}),
		"a run id":                    a.PostOutcome(ctx, run, "../x", Outcome{}),
		"a run endpoint with a query": a.PostOutcome(ctx, run+"?x=1", testRun, Outcome{}),
		"a plain http run endpoint":   a.PostOutcome(ctx, "http://example.com/v1/runs", testRun, Outcome{}),
	} {
		if err == nil {
			t.Errorf("%s: the outcome is sent", name)
		}
	}
	for _, u := range []string{run + "/qrk_x", run + "/QAK_x", "https://qrk_x.example.com/v1/runs"} {
		err := a.PostOutcome(ctx, u, testRun, Outcome{})
		if err == nil || !strings.Contains(err.Error(), "holds what looks like a secret, qak_ or qrk_, so nothing is sent") || strings.Contains(err.Error(), "not https") {
			t.Errorf("a run endpoint that holds a secret is not refused as one: %v", err)
		}
	}
	if len(f.requests()) != 0 {
		t.Error("a refused outcome was sent")
	}
	for body, want := range map[string]error{
		`{"error":"outcome_given","names":["state"]}`: ErrOutcomeGiven,
		`{"error":"not_found"}`:                       ErrRunNotFound,
	} {
		status := http.StatusConflict
		if want == ErrRunNotFound {
			status = http.StatusNotFound
		}
		f := newFake(t, func(int, seen) reply { return reply{status: status, body: body} })
		a := f.client(&sleeps{}, nil)
		if err := a.PostOutcome(ctx, f.srv.URL+"/v1/runs", testRun, Outcome{}); !errors.Is(err, want) {
			t.Errorf("%s: %v is not %v", body, err, want)
		}
	}
	for _, body := range []string{`{"version":2}`, `{}`, `{"version":1,"version":1}`, `not json`} {
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
		a := f.client(&sleeps{}, nil)
		if err := a.PostOutcome(ctx, f.srv.URL+"/v1/runs", testRun, Outcome{}); !errors.Is(err, ErrAnswerUnusable) {
			t.Errorf("%s: %v is not ErrAnswerUnusable", body, err)
		}
	}
	t.Run("an unsigned 401 is sent again, built anew", func(t *testing.T) {
		f := newFake(t, func(n int, _ seen) reply {
			if n == 1 {
				return reply{status: http.StatusUnauthorized, unsigned: true}
			}
			return reply{status: http.StatusOK, body: `{"version":1}`}
		})
		if err := f.client(&sleeps{}, nil).PostOutcome(ctx, f.srv.URL+"/v1/runs", testRun, Outcome{State: StateSucceeded}); err != nil {
			t.Fatalf("the outcome failed: %v", err)
		}
		checkBuiltAnew(t, f.requests(), 2)
	})
}
