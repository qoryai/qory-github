package starter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
)

const (
	testKeyID    = "ak_0123456789abcdef"
	testInstance = "i_AAAAAAAAAAAAAAAAAAAAAA"
	testPool     = "np_f1xt0re000000000"
	testDispatch = "dp_8w3k0q9t2v7m4r6x"
	testRun      = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	otherRun     = "0192f0c1-7d4e-7a2b-8c3d-000000000000"
)

// testClock is the time the tests' clock reads.
var testClock = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// seen is one request the fake Qory Apiary received.
type seen struct {
	target    string
	header    http.Header
	body      []byte
	signature string
	verified  bool
	replayed  bool
	// sent is the body's time, and lead how far it is ahead of the client's clock as
	// the request arrives.
	sent time.Time
	lead time.Duration
}

// reply is what the fake answers one request with: its status and body, whether it
// is left unsigned or signed under a key other than the pinned one, whether its
// signature header is sent twice, and where it redirects to.
type reply struct {
	status       int
	body         string
	unsigned     bool
	wrongKey     bool
	retryAfter   string
	dupSignature bool
	location     string
}

// fake is Qory Apiary as the starter reaches it. It verifies each request's signature
// under the pool's key, answers a signature it has seen with the unsigned 401, as the
// replay rule says, and otherwise answers with answer, signed under its server key
// unless the reply says otherwise.
type fake struct {
	t      *testing.T
	srv    *httptest.Server
	server *accesskey.Key
	pool   *accesskey.Key
	answer func(n int, s seen) reply

	mu    sync.Mutex
	seen  []seen
	sigs  map[string]bool
	other *accesskey.Key
	// clock is the client's clock, which a request's time is checked against.
	clock func() time.Time
}

func newKey(t *testing.T) *accesskey.Key {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pinOf(k *accesskey.Key) accesskey.Pin {
	return accesskey.Pin{{Alg: "ed25519", PublicKey: k.PublicKey().String()}}
}

func newFake(t *testing.T, answer func(n int, s seen) reply) *fake {
	t.Helper()
	f := &fake{t: t, server: newKey(t), pool: newKey(t), other: newKey(t), answer: answer, sigs: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	sig := r.Header.Get(accesskey.HeaderSignature)
	s := seen{target: r.URL.RequestURI(), header: r.Header.Clone(), body: b, signature: sig}
	s.verified = r.Method == http.MethodPost && f.pool.PublicKey().VerifyRequest(accesskey.Request{
		AccessKeyID: r.Header.Get(accesskey.HeaderAccessKeyID), InstanceID: r.Header.Get(accesskey.HeaderInstanceID),
		Method: r.Method, Target: r.URL.RequestURI(), Body: b,
	}, sig)
	var doc struct {
		Time string `json:"time"`
	}
	if json.Unmarshal(b, &doc) == nil {
		s.sent, _ = time.Parse(time.RFC3339, doc.Time)
	}
	f.mu.Lock()
	if f.clock != nil && !s.sent.IsZero() {
		s.lead = s.sent.Sub(f.clock())
	}
	s.replayed = f.sigs[sig]
	f.sigs[sig] = true
	f.seen = append(f.seen, s)
	n := len(f.seen)
	f.mu.Unlock()
	if !s.verified || s.replayed {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rep := f.answer(n, s)
	if rep.retryAfter != "" {
		w.Header().Set("Retry-After", rep.retryAfter)
	}
	if !rep.unsigned {
		k := f.server
		if rep.wrongKey {
			k = f.other
		}
		signature := k.SignAnswer(accesskey.Answer{Status: rep.status, RequestSignature: sig, Body: []byte(rep.body)})
		w.Header().Set(accesskey.HeaderSignature, signature)
		if rep.dupSignature {
			w.Header().Add(accesskey.HeaderSignature, signature)
		}
	}
	if rep.location != "" {
		w.Header().Set("Location", rep.location)
	}
	if rep.body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, rep.body)
}

// requests are the requests the fake received so far.
func (f *fake) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

// sleeps is a client's clock, which reads testClock until a wait moves it on, and
// records the waits.
type sleeps struct {
	mu  sync.Mutex
	d   []time.Duration
	now time.Time
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	s.now = s.clockLocked().Add(d)
	return nil
}

// clock is the time the clock reads.
func (s *sleeps) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clockLocked()
}

func (s *sleeps) clockLocked() time.Time {
	if s.now.IsZero() {
		s.now = testClock
	}
	return s.now
}

func (s *sleeps) waits() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.d)
}

// client is the starter's client of f, whose clock reads testClock, whose waits are
// recorded in sl, and whose log goes to logBuf when it is not nil.
func (f *fake) client(sl *sleeps, logBuf *bytes.Buffer) *Apiary {
	a := &Apiary{
		URL: f.srv.URL, KeyID: testKeyID, Key: f.pool, Pin: pinOf(f.server), InstanceID: testInstance,
		Now: sl.clock, Sleep: sl.sleep,
	}
	f.mu.Lock()
	f.clock = sl.clock
	f.mu.Unlock()
	if logBuf != nil {
		a.Log = slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return a
}

// fixture reads one provisioner fixture.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(contracts.ProvisionerFS, "fixtures/"+name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sameJSON reports whether a and b are the same JSON value.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

// at is a clock that reads the fixture's time.
func at(t *testing.T, s string) func() time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return func() time.Time { return tm }
}

func ok204(int, seen) reply { return reply{status: http.StatusNoContent} }

// TestRequestFixtures builds each request the provisioner contract's fixtures hold,
// claim, dispatched, handover and release, and checks the body sent is the fixture,
// signed with the pool's key, with the headers the contract names.
func TestRequestFixtures(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		fixture, target, time string
		send                  func(a *Apiary) error
	}{
		{"claim/one-pool.json", routeClaim, "2026-10-15T12:00:00Z", func(a *Apiary) error {
			a.PoolID = testPool
			_, _, err := a.Claim(ctx, 0)
			return err
		}},
		{"claim/without-pool-id.json", routeClaim, "2026-10-15T12:00:00Z", func(a *Apiary) error {
			_, _, err := a.Claim(ctx, 25)
			return err
		}},
		{"dispatched/with-external.json", "/v1/dispatches/" + testDispatch + "/dispatched", "2026-10-15T12:00:20Z", func(a *Apiary) error {
			return a.Dispatched(ctx, testDispatch, &contracts.External{Type: "example-ci", Ref: "run-8812", URL: "https://ci.example.com/acme/shop/runs/8812"})
		}},
		{"dispatched/without-external.json", "/v1/dispatches/" + testDispatch + "/dispatched", "2026-10-15T12:00:20Z", func(a *Apiary) error {
			return a.Dispatched(ctx, testDispatch, nil)
		}},
		{"release/retry.json", "/v1/dispatches/" + testDispatch + "/release", "2026-10-15T12:02:00Z", func(a *Apiary) error {
			return a.Release(ctx, testDispatch, "The job could not start: no runner was free.", true)
		}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			f := newFake(t, ok204)
			a := f.client(&sleeps{}, nil)
			a.Now = at(t, c.time)
			if err := c.send(a); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
			checkSent(t, f, c.target, fixture(t, c.fixture))
		})
	}
	t.Run("handover/handover.json", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply {
			return reply{status: http.StatusOK, body: fixture(t, "handover-answer/explore.json")}
		})
		a := f.client(&sleeps{}, nil)
		a.Now = at(t, "2026-10-15T12:01:00Z")
		if _, err := a.Handover(ctx, testDispatch, testRun); err != nil {
			t.Fatalf("the handover failed: %v", err)
		}
		checkSent(t, f, "/v1/dispatches/"+testDispatch+"/handover", fixture(t, "handover/handover.json"))
	})
}

// checkSent checks the one request f received: its target, its headers, its signature
// and that its body is want.
func checkSent(t *testing.T, f *fake, target, want string) {
	t.Helper()
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("the fake received %d requests, not 1", len(reqs))
	}
	r := reqs[0]
	switch {
	case r.target != target:
		t.Errorf("the target is %s, not %s", r.target, target)
	case !r.verified:
		t.Error("the signature does not verify under the pool's key")
	case r.header.Get("Content-Type") != "application/json":
		t.Errorf("the Content-Type is %q", r.header.Get("Content-Type"))
	case r.header.Get(headerContractVersion) != strconv.Itoa(contracts.ProvisionerRevision):
		t.Errorf("X-Qory-Contract-Version is %q", r.header.Get(headerContractVersion))
	case r.header.Get(accesskey.HeaderAccessKeyID) != testKeyID || r.header.Get(accesskey.HeaderInstanceID) != testInstance:
		t.Error("the access key id or the instance id is not the client's")
	case r.header.Get(accesskey.HeaderTimestamp) != "":
		t.Error("a POST carries X-Qory-Timestamp")
	case !sameJSON(t, r.body, []byte(want)):
		t.Errorf("the body is not the fixture:\n%s\n%s", r.body, want)
	}
}

// TestAnswerFixtures answers each answer fixture, signed, and checks the client returns
// it, the handover's inputs as the answer's bytes.
func TestAnswerFixtures(t *testing.T) {
	ctx := context.Background()
	t.Run("claim-answer/explore.json", func(t *testing.T) {
		body := fixture(t, "claim-answer/explore.json")
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
		a := f.client(&sleeps{}, nil)
		a.PoolID = testPool
		got, ok, err := a.Claim(ctx, 0)
		if err != nil || !ok {
			t.Fatalf("the claim failed: %v, %v", ok, err)
		}
		var want contracts.ClaimAnswer
		if err := json.Unmarshal([]byte(body), &want); err != nil {
			t.Fatal(err)
		}
		w := got.WorkItem
		if got.DispatchID != want.DispatchID || got.RunID != want.RunID || got.PoolID != want.PoolID || got.LeaseUntil != want.LeaseUntil ||
			got.Step != want.Step || got.Access != want.Access || got.Target != want.Target ||
			w.ID != want.WorkItem.ID || w.URL != want.WorkItem.URL || w.Title.Value() != want.WorkItem.Title {
			t.Errorf("the claim is not the fixture's")
		}
	})
	t.Run("handover-answer/explore.json", func(t *testing.T) {
		body := fixture(t, "handover-answer/explore.json")
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
		got, err := f.client(&sleeps{}, nil).Handover(ctx, testDispatch, testRun)
		if err != nil {
			t.Fatalf("the handover failed: %v", err)
		}
		var want struct {
			contracts.HandoverAnswer
			Inputs json.RawMessage `json:"inputs"`
		}
		if err := json.Unmarshal([]byte(body), &want); err != nil {
			t.Fatal(err)
		}
		if got.Inputs.Value() != string(want.Inputs) {
			t.Error("the inputs are not the answer's bytes")
		}
		doc := got.Document()
		if !bytes.Equal(doc.Inputs, want.Inputs) {
			t.Error("the document's inputs are not the answer's bytes")
		}
		w := want.HandoverAnswer
		if doc.Version != w.Version || doc.Revision != w.Revision || doc.RunID != w.RunID || doc.RunKey != w.RunKey || doc.Step != w.Step ||
			doc.Access != w.Access || doc.Target != w.Target || doc.WorkItem != w.WorkItem ||
			got.RunKey.Value() != w.RunKey || got.WorkItem.Title.Value() != w.WorkItem.Title {
			t.Error("the handover is not the fixture's")
		}
	})
	t.Run("204", func(t *testing.T) {
		f := newFake(t, ok204)
		got, ok, err := f.client(&sleeps{}, nil).Claim(ctx, 25)
		if err != nil || ok || got.DispatchID != "" {
			t.Fatalf("a 204 is not no run: %v, %v", ok, err)
		}
	})
}

// TestInvalidFixtures checks each invalid fixture is refused: a request one is never
// sent, and an answer one is never used. Every file under fixtures/invalid is named
// here, so a new one fails the test until it is.
func TestInvalidFixtures(t *testing.T) {
	ctx := context.Background()
	entries, err := fs.ReadDir(contracts.ProvisionerFS, "fixtures/invalid")
	if err != nil {
		t.Fatal(err)
	}
	// requests are the invalid requests the client can be asked to build.
	requests := map[string]func(a *Apiary) error{
		"claim-pool-id-node.json": func(a *Apiary) error {
			a.PoolID = "nd_f1xt0re000000000"
			_, _, err := a.Claim(ctx, 10)
			return err
		},
		"claim-wait-seconds-26.json": func(a *Apiary) error { _, _, err := a.Claim(ctx, 26); return err },
		"dispatched-external-type-upper-case.json": func(a *Apiary) error {
			return a.Dispatched(ctx, testDispatch, &contracts.External{Type: "Example-CI", Ref: "run-8812", URL: "https://ci.example.com/acme/shop/runs/8812"})
		},
	}
	// schemaOnly are invalid requests the client's types cannot express; the schema the
	// client checks each request against refuses them.
	schemaOnly := map[string]string{"claim-undefined-member.json": "claim.schema.json"}
	for _, e := range entries {
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			body := fixture(t, "invalid/"+name)
			switch {
			case requests[name] != nil:
				f := newFake(t, ok204)
				err := requests[name](f.client(&sleeps{}, nil))
				if err == nil || !strings.Contains(err.Error(), "breaks") {
					t.Errorf("the request is not refused as one its schema breaks: %v", err)
				}
				if len(f.requests()) != 0 {
					t.Error("the request was sent")
				}
			case schemaOnly[name] != "":
				var doc any
				if readAnswer(provisionerSchema, schemaOnly[name], []byte(body), &doc) == nil {
					t.Error("the schema accepts it")
				}
			case strings.HasPrefix(name, "claim-answer-"):
				f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
				got, ok, err := f.client(&sleeps{}, nil).Claim(ctx, 0)
				if !errors.Is(err, ErrAnswerUnusable) || ok || got.DispatchID != "" {
					t.Errorf("the answer is used: %v", err)
				}
			case strings.HasPrefix(name, "handover-answer-"):
				f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
				got, err := f.client(&sleeps{}, nil).Handover(ctx, testDispatch, testRun)
				if !errors.Is(err, ErrAnswerUnusable) || got.RunKey.Value() != "" {
					t.Errorf("the answer is used: %v", err)
				}
			default:
				t.Fatalf("the invalid fixture %s is not tested", name)
			}
		})
	}
}

// sentinels are every refusal a later step may act on.
var sentinels = []error{ErrForbidden, ErrGone, ErrHandedOver, ErrLeaseExpired, ErrNotDispatched, ErrNoGateway, ErrRateLimited, ErrOutcomeGiven, ErrRunNotFound}

// refusalCodes are every signed refusal code the tests answer with, each with its
// status and the error that names it, written out from refusal.schema.json and Forager's
// README rather than read from the client.
var refusalCodes = []struct {
	status int
	code   string
	err    error
}{
	{403, "forbidden", ErrForbidden},
	{410, "gone", ErrGone},
	{409, "handed_over", ErrHandedOver},
	{409, "lease_expired", ErrLeaseExpired},
	{409, "not_dispatched", ErrNotDispatched},
	{409, "no_gateway", ErrNoGateway},
	{429, "rate_limited", ErrRateLimited},
	{409, "outcome_given", ErrOutcomeGiven},
	{404, "not_found", ErrRunNotFound},
}

// givenCodes are the codes each request's schema gives, in the order the control plane
// decides them, written out from claim.schema.json, dispatched.schema.json,
// handover.schema.json, release.schema.json and Forager's run-outcome.schema.json, with
// refusal.schema.json's 429 last.
var givenCodes = map[string][]string{
	"claim":      {"forbidden", "no_gateway", "rate_limited"},
	"dispatched": {"forbidden", "gone", "lease_expired", "rate_limited"},
	"handover":   {"forbidden", "gone", "handed_over", "lease_expired", "not_dispatched", "no_gateway", "rate_limited"},
	"release":    {"forbidden", "gone", "lease_expired", "rate_limited"},
	"outcome":    {"not_found", "outcome_given", "rate_limited"},
}

// TestRefusals answers each request with each signed refusal code in [refusalCodes],
// and checks the error matches that code's refusal exactly when [givenCodes] lists the
// code for the request, matches no other refusal, and comes after one try. It checks
// the client's table holds the lists in their order, and that a code with another
// status, or a refusal body refusal.schema.json refuses, matches none.
func TestRefusals(t *testing.T) {
	ctx := context.Background()
	send := map[string]func(a *Apiary) error{
		"claim":      func(a *Apiary) error { _, _, err := a.Claim(ctx, 0); return err },
		"dispatched": func(a *Apiary) error { return a.Dispatched(ctx, testDispatch, nil) },
		"handover":   func(a *Apiary) error { _, err := a.Handover(ctx, testDispatch, testRun); return err },
		"release":    func(a *Apiary) error { return a.Release(ctx, testDispatch, "gone", false) },
		"outcome": func(a *Apiary) error {
			return a.PostOutcome(ctx, a.URL+"/v1/runs", testRun, Outcome{State: StateFailed})
		},
	}
	kinds := map[string]kind{"claim": kindClaim, "dispatched": kindDispatched, "handover": kindHandover, "release": kindRelease, "outcome": kindOutcome}
	for name, want := range givenCodes {
		var got []string
		for _, e := range refusalsOf[kinds[name]] {
			got = append(got, codeOf[e].code)
		}
		if !slices.Equal(got, want) {
			t.Errorf("the client gives the %s %v, not %v", name, got, want)
		}
	}
	for name, fn := range send {
		for _, c := range refusalCodes {
			t.Run(fmt.Sprintf("%s %d %s", name, c.status, c.code), func(t *testing.T) {
				f := newFake(t, func(int, seen) reply {
					return reply{status: c.status, body: `{"error":"` + c.code + `"}`, retryAfter: "7"}
				})
				err := fn(f.client(&sleeps{}, nil))
				given := slices.Contains(givenCodes[name], c.code)
				if errors.Is(err, c.err) != given {
					t.Errorf("errors.Is(%v, %v) is %v", err, c.err, !given)
				}
				for _, other := range sentinels {
					if other != c.err && errors.Is(err, other) {
						t.Errorf("%v matches %v too", err, other)
					}
				}
				var r *Refusal
				if !errors.As(err, &r) || r.Status != c.status || r.Code != c.code || !r.Signed {
					t.Errorf("the error is not the signed refusal: %v", err)
				}
				if errors.Is(err, ErrUnsigned) || errors.Is(err, ErrTooLarge) {
					t.Error("a signed refusal is ErrUnsigned or ErrTooLarge")
				}
				if c.code == "rate_limited" && r.RetryAfter != 7*time.Second {
					t.Errorf("Retry-After is %s, not 7s", r.RetryAfter)
				}
				if n := len(f.requests()); n != 1 {
					t.Errorf("a signed refusal was sent %d times", n)
				}
			})
		}
	}
	t.Run("a code with another status", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusConflict, body: `{"error":"gone"}`} })
		err := send["handover"](f.client(&sleeps{}, nil))
		for _, s := range sentinels {
			if errors.Is(err, s) {
				t.Errorf("409 gone matches %v", s)
			}
		}
	})
	t.Run("a refusal body the schema refuses names no code", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply {
			return reply{status: http.StatusConflict, body: `{"error":"handed_over","extra":1}`}
		})
		err := send["handover"](f.client(&sleeps{}, nil))
		var r *Refusal
		if errors.Is(err, ErrHandedOver) || !errors.As(err, &r) || r.Code != "" {
			t.Errorf("a refusal with a member refusal.schema.json does not define is read: %v", err)
		}
	})
	t.Run("the refusal fixtures", func(t *testing.T) {
		for name, want := range map[string]error{"handed-over.json": ErrHandedOver, "no-gateway.json": ErrNoGateway} {
			body := fixture(t, "refusal/"+name)
			f := newFake(t, func(int, seen) reply { return reply{status: http.StatusConflict, body: body} })
			if err := send["handover"](f.client(&sleeps{}, nil)); !errors.Is(err, want) {
				t.Errorf("%s: %v is not %v", name, err, want)
			}
		}
	})
}

// TestUnusable answers a claim and a handover with answers that break the contract and
// checks nothing in them is returned: a wrong revision, an unknown member, a member
// twice, a revision with a fraction, a run or a node pool other than the one asked, and
// inputs over their bound. Each is refused at once, after one try.
func TestUnusable(t *testing.T) {
	ctx := context.Background()
	claim := fixture(t, "claim-answer/explore.json")
	handover := fixture(t, "handover-answer/explore.json")
	edit := func(doc string, fn func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	bigInputs := edit(handover, func(m map[string]any) {
		m["inputs"].(map[string]any)["filler"] = strings.Repeat("x", contracts.MaxInputs)
	})
	cases := []struct {
		name, claim, handover string
	}{
		{"wrong revision", edit(claim, func(m map[string]any) { m["revision"] = 2 }), edit(handover, func(m map[string]any) { m["revision"] = 2 })},
		{"unknown member", edit(claim, func(m map[string]any) { m["extra"] = true }), edit(handover, func(m map[string]any) { m["extra"] = true })},
		{"member twice", strings.Replace(claim, `"version": 1,`, `"version": 1, "version": 1,`, 1), strings.Replace(handover, `"version": 1,`, `"version": 1, "version": 1,`, 1)},
		{"revision with a fraction", strings.Replace(claim, `"revision": 1`, `"revision": 1.5`, 1), strings.Replace(handover, `"revision": 1`, `"revision": 1.5`, 1)},
		{"another run or pool", edit(claim, func(m map[string]any) { m["pool_id"] = "np_0000000000000000" }), edit(handover, func(m map[string]any) { m["run_id"] = otherRun })},
		{"inputs over their bound", "", bigInputs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.claim != "" {
				f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: c.claim} })
				a := f.client(&sleeps{}, nil)
				a.PoolID = testPool
				got, ok, err := a.Claim(ctx, 0)
				if !errors.Is(err, ErrAnswerUnusable) || ok || got.DispatchID != "" || got.WorkItem.Title.Value() != "" {
					t.Errorf("the claim's answer is used: %v", err)
				}
				if len(f.requests()) != 1 {
					t.Error("an unusable answer was sent again")
				}
			}
			f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: c.handover} })
			got, err := f.client(&sleeps{}, nil).Handover(ctx, testDispatch, testRun)
			if !errors.Is(err, ErrAnswerUnusable) || got.RunKey.Value() != "" || got.Inputs.Value() != "" {
				t.Errorf("the handover's answer is used: %v", err)
			}
		})
	}
}

// TestBadSignature answers with a signature under a key that is not pinned, and with
// none, and checks the answer is never used: it is sent again, built anew, and after
// every try the error is ErrUnsigned.
func TestBadSignature(t *testing.T) {
	ctx := context.Background()
	handover := fixture(t, "handover-answer/explore.json")
	for _, rep := range []reply{
		{status: http.StatusOK, body: handover, wrongKey: true},
		{status: http.StatusOK, body: handover, unsigned: true},
	} {
		f := newFake(t, func(int, seen) reply { return rep })
		sl := &sleeps{}
		got, err := f.client(sl, nil).Handover(ctx, testDispatch, testRun)
		if !errors.Is(err, ErrUnsigned) || got.RunKey.Value() != "" {
			t.Fatalf("an answer not signed under the pin is used: %v", err)
		}
		checkBuiltAnew(t, f.requests(), tries)
		if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}; !slices.Equal(sl.waits(), want) {
			t.Errorf("the waits are %v, not %v", sl.waits(), want)
		}
	}
	t.Run("a refusal not signed under the pin names no code", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply {
			return reply{status: http.StatusConflict, body: `{"error":"handed_over"}`, wrongKey: true}
		})
		_, err := f.client(&sleeps{}, nil).Handover(ctx, testDispatch, testRun)
		if errors.Is(err, ErrHandedOver) || !errors.Is(err, ErrUnsigned) {
			t.Errorf("an unsigned refusal is read: %v", err)
		}
	})
}

// checkBuiltAnew checks reqs are n tries, each signed under the pool's key, none a
// replay, each with a new signature, and each body's time later than the last's.
func checkBuiltAnew(t *testing.T, reqs []seen, n int) {
	t.Helper()
	if len(reqs) != n {
		t.Fatalf("%d tries, not %d", len(reqs), n)
	}
	var last string
	sigs := map[string]bool{}
	for i, r := range reqs {
		var doc struct {
			Time string `json:"time"`
		}
		if err := json.Unmarshal(r.body, &doc); err != nil {
			t.Fatal(err)
		}
		switch {
		case !r.verified:
			t.Errorf("try %d does not verify", i+1)
		case r.replayed || sigs[r.signature]:
			t.Errorf("try %d reuses a signature", i+1)
		case doc.Time <= last:
			t.Errorf("try %d's time %s is not later than %s", i+1, doc.Time, last)
		case r.lead > 0:
			t.Errorf("try %d's time is %s ahead of the clock", i+1, r.lead)
		}
		sigs[r.signature], last = true, doc.Time
	}
}

// TestUnsignedRetried answers the unsigned 401, 413, 415 and 400, and an unsigned 429
// whose Retry-After is an hour, then a signed 204, and checks the request is sent again,
// built anew, after the backoff's first wait, and succeeds; and that a 401 that lasts is
// ErrUnsigned, never a revocation.
func TestUnsignedRetried(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusUnauthorized, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusBadRequest, http.StatusTooManyRequests} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFake(t, func(n int, _ seen) reply {
				if n == 1 {
					return reply{status: status, body: `{"error":"bad_request"}`, unsigned: true, retryAfter: "3600"}
				}
				return reply{status: http.StatusNoContent}
			})
			sl := &sleeps{}
			if err := f.client(sl, nil).Dispatched(ctx, testDispatch, nil); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
			checkBuiltAnew(t, f.requests(), 2)
			if !slices.Equal(sl.waits(), []time.Duration{firstWait}) {
				t.Errorf("the waits are %v, not the backoff's first", sl.waits())
			}
		})
	}
	t.Run("a 401 that lasts", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusUnauthorized, unsigned: true} })
		var logs bytes.Buffer
		err := f.client(&sleeps{}, &logs).Release(ctx, testDispatch, "gone", true)
		var r *Refusal
		if !errors.Is(err, ErrUnsigned) || !errors.As(err, &r) || r.Status != http.StatusUnauthorized {
			t.Fatalf("a 401 that lasts is not ErrUnsigned: %v", err)
		}
		if !strings.Contains(err.Error(), "never taken as the access key revoked") {
			t.Errorf("the error does not say a 401 is no revocation: %v", err)
		}
		checkBuiltAnew(t, f.requests(), tries)
		if strings.Count(logs.String(), "\n") != tries-1 {
			t.Errorf("not one line per try sent again:\n%s", logs.String())
		}
	})
	t.Run("a server error is sent again", func(t *testing.T) {
		f := newFake(t, func(n int, _ seen) reply {
			if n == 1 {
				return reply{status: http.StatusServiceUnavailable, body: `{"error":"unavailable"}`}
			}
			return reply{status: http.StatusNoContent}
		})
		if err := f.client(&sleeps{}, nil).Dispatched(ctx, testDispatch, nil); err != nil {
			t.Fatalf("the request failed: %v", err)
		}
		checkBuiltAnew(t, f.requests(), 2)
	})
	t.Run("no answer is sent again, then ErrUnreachable", func(t *testing.T) {
		f := newFake(t, ok204)
		a := f.client(&sleeps{}, nil)
		f.srv.Close()
		if err := a.Dispatched(ctx, testDispatch, nil); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("not ErrUnreachable: %v", err)
		}
	})
}

// TestRateLimited checks a signed 429 is ErrRateLimited with its Retry-After, from a
// second to an hour, after one try.
func TestRateLimited(t *testing.T) {
	for v, want := range map[string]time.Duration{"7": 7 * time.Second, "0": time.Second, "86400": time.Hour, "soon": time.Second} {
		f := newFake(t, func(int, seen) reply {
			return reply{status: http.StatusTooManyRequests, body: `{"error":"rate_limited"}`, retryAfter: v}
		})
		_, _, err := f.client(&sleeps{}, nil).Claim(context.Background(), 0)
		var r *Refusal
		if !errors.Is(err, ErrRateLimited) || !errors.As(err, &r) || r.RetryAfter != want {
			t.Errorf("Retry-After %q: %v", v, err)
		}
		if len(f.requests()) != 1 {
			t.Errorf("a signed 429 was sent again by the client")
		}
	}
}

// TestRefusedBeforeSending checks requests the client refuses to build: an id outside
// its form, a reason over its bound, and a body that holds what looks like a secret.
func TestRefusedBeforeSending(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, ok204)
	a := f.client(&sleeps{}, nil)
	for name, err := range map[string]error{
		"dispatch id":   a.Dispatched(ctx, "dp_../../v1/pools/claim", nil),
		"handover id":   func() error { _, err := a.Handover(ctx, "DP_8w3k0q9t2v7m4r6x", testRun); return err }(),
		"run id":        func() error { _, err := a.Handover(ctx, testDispatch, "not-a-run"); return err }(),
		"long reason":   a.Release(ctx, testDispatch, strings.Repeat("x", 201), false),
		"empty reason":  a.Release(ctx, testDispatch, "", false),
		"secret reason": a.Release(ctx, testDispatch, "see QRK_abc.def", false),
	} {
		if err == nil {
			t.Errorf("%s: the request is built", name)
		}
	}
	if len(f.requests()) != 0 {
		t.Error("a refused request was sent")
	}
}

// TestShown checks a Claimed and a Handed print, log and marshal without the run key,
// the inputs or the title, at the top level, behind a pointer and in an unexported
// field fmt cannot call methods on, and that Value and Document give them back.
func TestShown(t *testing.T) {
	ctx := context.Background()
	claimBody, handoverBody := fixture(t, "claim-answer/explore.json"), fixture(t, "handover-answer/explore.json")
	f := newFake(t, func(n int, _ seen) reply {
		if n == 1 {
			return reply{status: http.StatusOK, body: claimBody}
		}
		return reply{status: http.StatusOK, body: handoverBody}
	})
	a := f.client(&sleeps{}, nil)
	c, ok, err := a.Claim(ctx, 0)
	if err != nil || !ok {
		t.Fatalf("the claim failed: %v", err)
	}
	h, err := a.Handover(ctx, testDispatch, testRun)
	if err != nil {
		t.Fatalf("the handover failed: %v", err)
	}
	if !strings.HasPrefix(h.RunKey.Value(), "qrk_") || !strings.Contains(h.Inputs.Value(), "cart page") ||
		c.WorkItem.Title.Value() != "Checkout fails on an empty cart" || h.Document().RunKey != h.RunKey.Value() {
		t.Fatal("Value or Document does not give the value back")
	}
	var logs bytes.Buffer
	jsonLog := slog.New(slog.NewJSONHandler(&logs, nil))
	textLog := slog.New(slog.NewTextHandler(&logs, nil))
	for _, v := range []any{c, h, &c, &h, struct{ h Handed }{h}, struct{ c Claimed }{c}, []Handed{h}, map[string]Handed{"h": h}, h.RunKey, h.Inputs, c.WorkItem} {
		jsonLog.Info("shown", "v", v)
		textLog.Info("shown", "v", v)
		js, _ := json.Marshal(v)
		for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v), fmt.Sprintf("%q", v), fmt.Sprintf("%x", v), string(js), logs.String()} {
			if strings.Contains(strings.ToLower(s), "qrk_") || strings.Contains(s, "Checkout fails") || strings.Contains(s, "cart page") {
				t.Errorf("%T shows a run key, a title or the inputs", v)
			}
		}
	}
}

// padTo is the JSON object doc with white space after its opening brace, so that it is
// size bytes in all.
func padTo(t *testing.T, doc string, size int) string {
	t.Helper()
	if len(doc) > size || doc[0] != '{' {
		t.Fatal("the document cannot be padded to that size")
	}
	return "{" + strings.Repeat(" ", size-len(doc)) + doc[1:]
}

// TestTooLarge answers with answers one byte over their bound, an unsigned 200, 502 and
// 401 and a signed 200, and checks each is a try that failed: sent again, built anew,
// up to every try, then ErrTooLarge, whose text says the answer was refused for its size
// before its signature was read.
func TestTooLarge(t *testing.T) {
	ctx := context.Background()
	claim := fixture(t, "claim-answer/explore.json")
	big := padTo(t, `{"error":"bad_gateway"}`, maxAnswer+1)
	cases := []struct {
		name string
		rep  reply
		send func(a *Apiary) error
	}{
		{"unsigned 200", reply{status: http.StatusOK, body: padTo(t, claim, maxClaimAnswer+1), unsigned: true}, func(a *Apiary) error { _, _, err := a.Claim(ctx, 0); return err }},
		{"signed 200", reply{status: http.StatusOK, body: padTo(t, claim, maxClaimAnswer+1)}, func(a *Apiary) error { _, _, err := a.Claim(ctx, 0); return err }},
		{"unsigned 502", reply{status: http.StatusBadGateway, body: big, unsigned: true}, func(a *Apiary) error { return a.Dispatched(ctx, testDispatch, nil) }},
		{"unsigned 401", reply{status: http.StatusUnauthorized, body: big, unsigned: true}, func(a *Apiary) error { return a.Release(ctx, testDispatch, "gone", false) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t, func(int, seen) reply { return c.rep })
			var logs bytes.Buffer
			err := c.send(f.client(&sleeps{}, &logs))
			var r *Refusal
			if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnsigned) || errors.Is(err, ErrAnswerUnusable) || !errors.As(err, &r) || r.Status != c.rep.status {
				t.Fatalf("not ErrTooLarge alone: %v", err)
			}
			if msg := err.Error(); !strings.Contains(msg, "refused before its signature was read") || strings.Contains(msg, "not signed") || strings.Contains(msg, "Qory Apiary answered") {
				t.Errorf("the error's text is not true: %v", err)
			}
			checkBuiltAnew(t, f.requests(), tries)
			if strings.Count(logs.String(), "larger than its bound") != tries-1 {
				t.Errorf("not one line per try sent again:\n%s", logs.String())
			}
		})
	}
}

// TestBounds checks each bound at its edge: an answer of exactly its bound is used and
// one byte more is not, for a claim's 200, a handover's 200 and a refusal; a handover's
// answer between 64 KiB and 1 MiB is used; and inputs of exactly contracts.MaxInputs
// bytes, compacted, are used and one byte more are not.
func TestBounds(t *testing.T) {
	ctx := context.Background()
	claim, handover := fixture(t, "claim-answer/explore.json"), fixture(t, "handover-answer/explore.json")
	answer := func(rep reply) *Apiary {
		return newFake(t, func(int, seen) reply { return rep }).client(&sleeps{}, nil)
	}
	claimOf := func(a *Apiary) error { _, _, err := a.Claim(ctx, 0); return err }
	handoverOf := func(a *Apiary) error { _, err := a.Handover(ctx, testDispatch, testRun); return err }
	for _, c := range []struct {
		name string
		body string
		edge bool
		send func(a *Apiary) error
	}{
		{"a claim of its bound", padTo(t, claim, maxClaimAnswer), true, claimOf},
		{"a handover of 100 KiB", padTo(t, handover, 100<<10), false, handoverOf},
		{"a handover of its bound", padTo(t, handover, contracts.MaxHandoverAnswer), true, handoverOf},
	} {
		if err := c.send(answer(reply{status: http.StatusOK, body: c.body})); err != nil {
			t.Errorf("%s is not used: %v", c.name, err)
		}
		if err := c.send(answer(reply{status: http.StatusOK, body: " " + c.body})); c.edge && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s and a byte is used: %v", c.name, err)
		}
	}
	refusal := padTo(t, `{"error":"handed_over"}`, maxAnswer)
	if err := handoverOf(answer(reply{status: http.StatusConflict, body: refusal})); !errors.Is(err, ErrHandedOver) {
		t.Errorf("a refusal of its bound is not read: %v", err)
	}
	if err := handoverOf(answer(reply{status: http.StatusConflict, body: " " + refusal})); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a refusal of its bound and a byte is read: %v", err)
	}
	inputs := func(n int) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(handover), &m); err != nil {
			t.Fatal(err)
		}
		// {"f":"…","version":1} is 20 bytes and the filler, compacted.
		m["inputs"] = map[string]any{"version": 1, "f": strings.Repeat("x", n-20)}
		b, _ := json.Marshal(m)
		return string(b)
	}
	if err := handoverOf(answer(reply{status: http.StatusOK, body: inputs(contracts.MaxInputs)})); err != nil {
		t.Errorf("inputs of their bound are not used: %v", err)
	}
	if err := handoverOf(answer(reply{status: http.StatusOK, body: inputs(contracts.MaxInputs + 1)})); !errors.Is(err, ErrAnswerUnusable) {
		t.Errorf("inputs of their bound and a byte are used: %v", err)
	}
}

// TestTimes checks a request's time against the clock, which moves on only when the
// client waits: distinct requests in one second all carry the clock's time with no
// wait; identical requests, one after another or at once, wait for the clock's next
// second and so carry strictly later times; no time sent is ahead of the clock, after
// 400 requests too; and a context cancelled during that wait ends the request with its
// error, nothing more sent and no line logged.
func TestTimes(t *testing.T) {
	ctx := context.Background()
	noLead := func(t *testing.T, reqs []seen) {
		t.Helper()
		for i, r := range reqs {
			if r.sent.IsZero() || r.lead > 0 {
				t.Fatalf("request %d's time is %s ahead of the clock", i+1, r.lead)
			}
		}
	}
	t.Run("distinct requests in one second", func(t *testing.T) {
		f := newFake(t, ok204)
		sl := &sleeps{}
		a := f.client(sl, nil)
		for i := range 50 {
			if err := a.Dispatched(ctx, fmt.Sprintf("dp_8w3k0q9t2v7m%04d", i), nil); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
		}
		for _, r := range f.requests() {
			if !r.sent.Equal(testClock) || r.replayed {
				t.Fatalf("a distinct request's time is %s, not the clock's", r.sent)
			}
		}
		if len(sl.waits()) != 0 {
			t.Errorf("distinct requests waited %v", sl.waits())
		}
	})
	t.Run("identical requests", func(t *testing.T) {
		f := newFake(t, ok204)
		a := f.client(&sleeps{}, nil)
		for range 3 {
			if err := a.Dispatched(ctx, testDispatch, nil); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
		}
		reqs := f.requests()
		checkBuiltAnew(t, reqs, 3)
		noLead(t, reqs)
	})
	t.Run("400 requests leave no lead", func(t *testing.T) {
		f := newFake(t, ok204)
		sl := &sleeps{}
		a := f.client(sl, nil)
		for i := range 400 {
			id := testDispatch
			if i%2 == 1 {
				id = "dp_8w3k0q9t2v7m4r6y"
			}
			if err := a.Dispatched(ctx, id, nil); err != nil {
				t.Fatalf("the request failed: %v", err)
			}
		}
		reqs := f.requests()
		noLead(t, reqs)
		if last := reqs[len(reqs)-1]; last.lead != 0 {
			t.Errorf("after 400 requests the lead is %s, not 0", last.lead)
		}
	})
	t.Run("a cancel during the wait", func(t *testing.T) {
		f := newFake(t, ok204)
		var logs bytes.Buffer
		sl := &sleeps{}
		a := f.client(sl, &logs)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := a.Dispatched(cctx, testDispatch, nil); err != nil {
			t.Fatalf("the request failed: %v", err)
		}
		a.Sleep = func(ctx context.Context, d time.Duration) error {
			cancel()
			return sl.sleep(ctx, d)
		}
		d := &deadlines{}
		a.HTTP = &http.Client{Transport: d}
		if err := a.Dispatched(cctx, testDispatch, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("not the context's error: %v", err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.left) != 0 || len(f.requests()) != 1 || logs.Len() != 0 {
			t.Errorf("a request cancelled during its wait is sent or logged:\n%s", logs.String())
		}
	})
	t.Run("identical requests at once", func(t *testing.T) {
		f := newFake(t, ok204)
		a := f.client(&sleeps{}, nil)
		const n = 8
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				if err := a.Dispatched(ctx, testDispatch, nil); err != nil {
					t.Errorf("the request failed: %v", err)
				}
			})
		}
		wg.Wait()
		reqs := f.requests()
		noLead(t, reqs)
		times, sigs := map[time.Time]bool{}, map[string]bool{}
		for _, r := range reqs {
			if r.replayed || times[r.sent] || sigs[r.signature] {
				t.Error("two requests at once share a time or a signature")
			}
			times[r.sent], sigs[r.signature] = true, true
		}
		if len(reqs) != n {
			t.Errorf("%d requests, not %d", len(reqs), n)
		}
	})
}

// TestCancel cancels the context while a claim waits for its answer, and checks the
// error is the context's, after one try, with no line logged and no wait.
func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFake(t, ok204)
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.ReadAll(r.Body)
		cancel()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	var logs bytes.Buffer
	sl := &sleeps{}
	a := f.client(sl, &logs)
	a.URL = srv.URL
	_, _, err := a.Claim(ctx, 25)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("not the context's error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logs.Len() != 0 || len(sl.waits()) != 0 || hits != 1 {
		t.Errorf("a cancelled claim logs, waits or sends again: %d requests\n%s", hits, logs.String())
	}
}

// TestNoRedirect answers with a redirect and checks it is not followed: the place it
// points to gets no request, and the unsigned 302 is a try that failed.
func TestNoRedirect(t *testing.T) {
	var hits int
	var mu sync.Mutex
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer elsewhere.Close()
	f := newFake(t, func(int, seen) reply {
		return reply{status: http.StatusFound, location: elsewhere.URL + "/v1/pools/claim", unsigned: true}
	})
	_, _, err := f.client(&sleeps{}, nil).Claim(context.Background(), 0)
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 || !errors.Is(err, ErrUnsigned) {
		t.Errorf("the redirect is followed: %d requests elsewhere, %v", hits, err)
	}
}

// TestSignatureHeaderTwice answers with its valid signature sent twice, and checks the
// answer is never used.
func TestSignatureHeaderTwice(t *testing.T) {
	f := newFake(t, func(int, seen) reply { return reply{status: http.StatusNoContent, dupSignature: true} })
	if err := f.client(&sleeps{}, nil).Dispatched(context.Background(), testDispatch, nil); !errors.Is(err, ErrUnsigned) {
		t.Errorf("an answer with its signature header twice is used: %v", err)
	}
}

// TestUnexpected2xx answers each request with a signed 2xx its schema does not give,
// and checks it is ErrAnswerUnusable, after one try.
func TestUnexpected2xx(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		status int
		body   string
		send   func(a *Apiary) error
	}{
		{"claim 202", http.StatusAccepted, "", func(a *Apiary) error { _, _, err := a.Claim(ctx, 0); return err }},
		{"dispatched 200", http.StatusOK, "{}", func(a *Apiary) error { return a.Dispatched(ctx, testDispatch, nil) }},
		{"release 202", http.StatusAccepted, "", func(a *Apiary) error { return a.Release(ctx, testDispatch, "gone", true) }},
		{"handover 204", http.StatusNoContent, "", func(a *Apiary) error { _, err := a.Handover(ctx, testDispatch, testRun); return err }},
		{"outcome 204", http.StatusNoContent, "", func(a *Apiary) error {
			return a.PostOutcome(ctx, a.URL+"/v1/runs", testRun, Outcome{})
		}},
	} {
		f := newFake(t, func(int, seen) reply { return reply{status: c.status, body: c.body} })
		if err := c.send(f.client(&sleeps{}, nil)); !errors.Is(err, ErrAnswerUnusable) || len(f.requests()) != 1 {
			t.Errorf("%s: not refused at once: %v", c.name, err)
		}
	}
}

// deadlines is a transport that records how long each request has before its
// deadline.
type deadlines struct {
	mu   sync.Mutex
	left []time.Duration
}

func (d *deadlines) RoundTrip(r *http.Request) (*http.Response, error) {
	left := time.Duration(-1)
	if dl, ok := r.Context().Deadline(); ok {
		left = time.Until(dl)
	}
	d.mu.Lock()
	d.left = append(d.left, left)
	d.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// TestTimeouts checks a claim has longer than the 25 seconds Qory Apiary may hold it,
// and longer than any other request, and that another request has requestTimeout.
func TestTimeouts(t *testing.T) {
	ctx := context.Background()
	f := newFake(t, ok204)
	d := &deadlines{}
	a := f.client(&sleeps{}, nil)
	a.HTTP = &http.Client{Transport: d}
	if _, _, err := a.Claim(ctx, 25); err != nil {
		t.Fatal(err)
	}
	if err := a.Dispatched(ctx, testDispatch, nil); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.left) != 2 || d.left[0] <= requestTimeout || d.left[0] <= 25*time.Second || d.left[1] > requestTimeout || d.left[1] < requestTimeout-5*time.Second {
		t.Errorf("the time left to the claim and to dispatched are %v", d.left)
	}
}
