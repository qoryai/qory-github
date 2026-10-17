package github

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// actionsToken is the token the fake mints for every request: a marker no error, no
// line logged and no printed Actions may contain.
const actionsToken = "ghs_actionsmarkerthatmustnotleak"

// actionsRequest is one request the fake received outside the mint.
type actionsRequest struct {
	method, path, body string
	header             http.Header
}

// fakeActions is GitHub's API as far as Actions uses it: the installation's check and
// the mint under /app/installations/, and every other request, which answer answers.
type fakeActions struct {
	mu         sync.Mutex
	all        int      // every request received, the mint's among them
	mints      []string // the mints' bodies
	mintStatus int      // the mint's status; zero is 201
	mintHeader http.Header
	requests   []actionsRequest
	agents     []string // every request's User-Agent, the mint's among them
	answer     func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeActions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.all++
	f.agents = append(f.agents, r.Header.Get("User-Agent"))
	b, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/app/installations/"):
		io.WriteString(w, `{"id":7,"account":{"login":"example-org","type":"Organization"}}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/7/access_tokens":
		f.mints = append(f.mints, string(b))
		for k, v := range f.mintHeader {
			w.Header()[k] = v
		}
		if f.mintStatus != 0 {
			w.WriteHeader(f.mintStatus)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"`+actionsToken+`","expires_at":"2026-09-21T15:00:00Z"}`)
	default:
		f.requests = append(f.requests, actionsRequest{method: r.Method, path: r.URL.RequestURI(), body: string(b), header: r.Header.Clone()})
		f.answer(w, r)
	}
}

// actionsAt is the fake's clock, an hour before the token it mints expires.
var actionsAt = time.Date(2026, 9, 21, 14, 0, 0, 0, time.UTC)

// serveActions serves f and returns an Actions that reaches it, with a Pacer that never
// sleeps.
func serveActions(t *testing.T, f *fakeActions) *Actions {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Actions{
		Client: Client{API: srv.URL, Now: func() time.Time { return actionsAt }},
		AppID:  appID,
		Key:    key(t),
		Pacer:  &Pacer{Now: func() time.Time { return actionsAt }, Sleep: func(context.Context, time.Duration) error { return nil }},
	}
}

// answering answers every request with status, body and header.
func answering(status int, body string, header ...string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

const (
	dispatchID = "dp_0123456789abcdef"
	runAnswer  = `{"id":99,"status":"completed","conclusion":"success","run_attempt":2,"html_url":"https://github.com/example-org/runner/actions/runs/99","head_sha":"0123456789abcdef0123456789abcdef01234567","path":".github/workflows/runner.yml"}`
)

// checkHeaders checks a request carries the token and GitHub's headers, and a JSON
// Content-Type when it has a body.
func checkHeaders(t *testing.T, r actionsRequest, withBody bool) {
	t.Helper()
	want := map[string]string{
		"Authorization":        "Bearer " + actionsToken,
		"Accept":               "application/vnd.github+json",
		"X-Github-Api-Version": "2022-11-28",
		"User-Agent":           "qory-github",
	}
	if withBody {
		want["Content-Type"] = "application/json"
	}
	for k, v := range want {
		if got := r.header.Get(k); got != v {
			t.Errorf("%s is %q, not %q", k, got, v)
		}
	}
	if !withBody && r.header.Get("Content-Type") != "" {
		t.Errorf("a request without a body has a Content-Type, %q", r.header.Get("Content-Type"))
	}
}

// TestDispatchWorkflowSendsTheDispatchAndReturnsTheRun dispatches and checks the mint,
// narrowed to the repository's id with actions: write, the request's method, path, body
// and headers, and the run GitHub's 200 names.
func TestDispatchWorkflowSendsTheDispatchAndReturnsTheRun(t *testing.T) {
	f := &fakeActions{answer: answering(200, `{"workflow_run_id":99,"run_url":"https://api.github.com/repos/example-org/runner/actions/runs/99","html_url":"https://github.com/example-org/runner/actions/runs/99"}`)}
	a := serveActions(t, f)
	got, err := a.DispatchWorkflow(context.Background(), 7, 42, "runner.yml", "main", dispatchID)
	if err != nil {
		t.Fatal(err)
	}
	want := DispatchedRun{ID: 99, URL: "https://api.github.com/repos/example-org/runner/actions/runs/99", HTMLURL: "https://github.com/example-org/runner/actions/runs/99"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(f.mints) != 1 || strings.TrimSpace(f.mints[0]) != `{"permissions":{"actions":"write"},"repository_ids":[42]}` {
		t.Errorf("the mints asked for %q", f.mints)
	}
	if len(f.requests) != 1 {
		t.Fatalf("%d requests", len(f.requests))
	}
	r := f.requests[0]
	if r.method != "POST" || r.path != "/repositories/42/actions/workflows/runner.yml/dispatches" {
		t.Errorf("%s %s", r.method, r.path)
	}
	if r.body != `{"ref":"refs/heads/main","inputs":{"dispatch_id":"dp_0123456789abcdef"},"return_run_details":true}` {
		t.Errorf("the body is %s", r.body)
	}
	checkHeaders(t, r, true)
}

// actionsClasses are the errors [Actions] wraps, each error exactly one of them.
var actionsClasses = []error{ErrActionsGone, ErrActionsRefused, ErrActionsTransient, ErrActionsInvalid, ErrActionsNoRun}

// wrapsOnly reports whether err wraps want and no other of [actionsClasses].
func wrapsOnly(err, want error) bool {
	for _, class := range actionsClasses {
		if errors.Is(err, class) != (class == want) {
			return false
		}
	}
	return true
}

// TestADispatchGitHubAnswers204NamesNoRun takes GitHub's 204, a dispatch taken with no
// run named, as an error that wraps ErrActionsNoRun alone, never a run whose ID is 0
// with nil.
func TestADispatchGitHubAnswers204NamesNoRun(t *testing.T) {
	f := &fakeActions{answer: answering(204, "")}
	got, err := serveActions(t, f).DispatchWorkflow(context.Background(), 7, 42, "runner.yaml", "refs/heads/main", dispatchID)
	if !wrapsOnly(err, ErrActionsNoRun) || got != (DispatchedRun{}) {
		t.Errorf("got %+v, %v", got, err)
	}
	if want := "GitHub took the dispatch and named no workflow run: dispatching the workflow runner.yaml: GitHub answered 204, with no run's details"; err == nil || err.Error() != want {
		t.Errorf("the error is %v, not %s", err, want)
	}
	if len(f.requests) != 1 {
		t.Errorf("%d requests", len(f.requests))
	}
}

// TestADispatch200WithoutARunIDFails refuses a 200 that names no run, a run's id
// missing, 0 or below, or an answer that does not decode, as ErrActionsNoRun alone: GitHub
// took the dispatch.
func TestADispatch200WithoutARunIDFails(t *testing.T) {
	for body, want := range map[string]string{
		`{}`:                        "GitHub answered 200 without a run's id above 0",
		`{"workflow_run_id":null}`:  "GitHub answered 200 without a run's id above 0",
		`{"workflow_run_id":0}`:     "GitHub answered 200 without a run's id above 0",
		`{"workflow_run_id":-1}`:    "GitHub answered 200 without a run's id above 0",
		`{"run_url":"x"}`:           "GitHub answered 200 without a run's id above 0",
		`not json`:                  "GitHub's answer: invalid character",
		`{"workflow_run_id":"99"}`:  "GitHub's answer: json: cannot unmarshal",
		`{"workflow_run_id":99.5}`:  "GitHub's answer: json: cannot unmarshal",
		`{"workflow_run_id":[99]}`:  "GitHub's answer: json: cannot unmarshal",
		`{"workflow_run_id":true}`:  "GitHub's answer: json: cannot unmarshal",
		`{"workflow_run_id":{}}`:    "GitHub's answer: json: cannot unmarshal",
		`{"workflow_run_id":1e400}`: "GitHub's answer: json: cannot unmarshal",
	} {
		f := &fakeActions{answer: answering(200, body)}
		got, err := serveActions(t, f).DispatchWorkflow(context.Background(), 7, 42, "runner.yml", "main", dispatchID)
		if !wrapsOnly(err, ErrActionsNoRun) || got != (DispatchedRun{}) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %+v, %v; want %q", body, got, err, want)
		}
	}
}

// truncated answers status with a Content-Length longer than the body it writes, so
// reading the answer fails.
func truncated(status int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(status)
		io.WriteString(w, `{"workflow_run_id":`)
	}
}

// TestADispatch200ThatCannotBeReadNamesNoRun refuses a dispatch's 200 larger than 1 MiB,
// or whose answer cannot be read, as ErrActionsNoRun alone, and the same answers with
// another status, and to a read, as ones that may pass.
func TestADispatch200ThatCannotBeReadNamesNoRun(t *testing.T) {
	large := `{"workflow_run_id":99,"padding":"` + strings.Repeat("x", 1<<20) + `"}`
	dispatch := actionsCalls["dispatch"]
	cases := []struct {
		name   string
		call   func(*Actions) error
		answer func(http.ResponseWriter, *http.Request)
		want   error
		says   string
	}{
		{"a dispatch's large 200", dispatch, answering(200, large), ErrActionsNoRun, "GitHub took the dispatch and named no workflow run: dispatching the workflow runner.yml: GitHub's answer is larger than 1048576 bytes"},
		{"a dispatch's cut 200", dispatch, truncated(200), ErrActionsNoRun, "GitHub took the dispatch and named no workflow run: dispatching the workflow runner.yml: GitHub's answer could not be read"},
		{"a dispatch's large 500", dispatch, answering(500, large), ErrActionsTransient, "GitHub's answer is larger than 1048576 bytes"},
		{"a dispatch's cut 500", dispatch, truncated(500), ErrActionsTransient, "GitHub's answer could not be read"},
		{"a read's cut 200", actionsCalls["read"], truncated(200), ErrActionsTransient, "GitHub's answer could not be read"},
	}
	for _, c := range cases {
		f := &fakeActions{answer: c.answer}
		err := c.call(serveActions(t, f))
		if !wrapsOnly(err, c.want) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestADispatchSendsTheFullRef sends a short name as refs/heads/NAME, and a ref under
// refs/heads/ or refs/tags/ as it is.
func TestADispatchSendsTheFullRef(t *testing.T) {
	for ref, want := range map[string]string{
		"main":                 "refs/heads/main",
		"release/1.2":          "refs/heads/release/1.2",
		"refs":                 "refs/heads/refs",
		"tags/v1":              "refs/heads/tags/v1",
		"refs/heads/main":      "refs/heads/main",
		"refs/tags/runner-1.2": "refs/tags/runner-1.2",
	} {
		if got := FullRef(ref); got != want {
			t.Errorf("FullRef(%q) is %q, not %q", ref, got, want)
		}
		f := &fakeActions{answer: answering(200, `{"workflow_run_id":99}`)}
		if _, err := serveActions(t, f).DispatchWorkflow(context.Background(), 7, 42, "runner.yml", ref, dispatchID); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if body := `{"ref":"` + want + `","inputs":{"dispatch_id":"dp_0123456789abcdef"},"return_run_details":true}`; len(f.requests) != 1 || f.requests[0].body != body {
			t.Errorf("%s: the requests are %+v", ref, f.requests)
		}
	}
}

// TestCheckRefTakesABranchOrATag takes a short name, refs/heads/NAME and
// refs/tags/NAME, and refuses a name under another refs/ prefix, HEAD, a name that
// begins with a hyphen, as git does, and a later part that begins with one, with the
// rule each fails.
func TestCheckRefTakesABranchOrATag(t *testing.T) {
	for _, ref := range []string{"main", "release/1.2", "a-b", "a/b-", "refs", "heads/main", "HEADS", "a/HEAD", "refs/heads/main", "refs/heads/release/1.2", "refs/tags/v1.2.3", "refs/tags/runner-1.2", "refs/heads/refs/tags/x"} {
		if err := CheckRef(ref); err != nil {
			t.Errorf("%q: %v", ref, err)
		}
	}
	const bad, prefix, hyphen = "is not a branch or tag name git takes", "is neither a branch, NAME or refs/heads/NAME, nor a tag, refs/tags/NAME", "has a part that begins with a hyphen"
	for ref, want := range map[string]string{
		"-main":                    bad,
		"-":                        bad,
		"a/-b":                     hyphen,
		"a/b/-":                    hyphen,
		"refs/tags/v1/-rc":         hyphen,
		"HEAD":                     bad,
		"refs/heads/HEAD":          bad,
		"refs/tags/HEAD":           bad,
		"refs/heads/-main":         bad,
		"refs/tags/-v1":            bad,
		"refs/heads/a/-b":          hyphen,
		"refs/heads/a/-b/.c":       bad,
		"refs/heads/":              bad,
		"refs/tags/":               bad,
		"refs/heads/.x":            bad,
		"refs/pull/1/head":         prefix,
		"refs/remotes/origin/main": prefix,
		"refs/heads":               prefix,
		"refs/tags":                prefix,
		"refs/x":                   prefix,
		"refs/":                    prefix,
	} {
		if err := CheckRef(ref); err == nil || err.Error() != want {
			t.Errorf("%q: %v, not %s", ref, err, want)
		}
	}
}

// TestAClientSendsItsUserAgent sends a mint and a dispatch with a client's User-Agent,
// and qory-github with none.
func TestAClientSendsItsUserAgent(t *testing.T) {
	for agent, want := range map[string]string{"example-program/1.2.3": "example-program/1.2.3", "": "qory-github"} {
		f := &fakeActions{answer: answering(200, `{"workflow_run_id":99}`)}
		a := serveActions(t, f)
		a.Client.UserAgent = agent
		if _, err := a.DispatchWorkflow(context.Background(), 7, 42, "runner.yml", "main", dispatchID); err != nil {
			t.Fatal(err)
		}
		if len(f.mints) != 1 || len(f.agents) < 2 {
			t.Fatalf("%d mints, %d requests", len(f.mints), len(f.agents))
		}
		for _, got := range f.agents {
			if got != want {
				t.Errorf("a request's User-Agent is %q, not %q", got, want)
			}
		}
	}
}

// TestReadWorkflowRunReadsTheRunWithATokenThatReadsActions reads a run and checks the
// mint, actions: read on the repository's id alone, the request, and what it returns,
// a null conclusion as "".
func TestReadWorkflowRunReadsTheRunWithATokenThatReadsActions(t *testing.T) {
	f := &fakeActions{answer: answering(200, runAnswer)}
	a := serveActions(t, f)
	got, err := a.ReadWorkflowRun(context.Background(), 7, 42, 99)
	if err != nil {
		t.Fatal(err)
	}
	want := WorkflowRun{ID: 99, Status: "completed", Conclusion: "success", RunAttempt: 2, HTMLURL: "https://github.com/example-org/runner/actions/runs/99", HeadSHA: "0123456789abcdef0123456789abcdef01234567", Path: ".github/workflows/runner.yml"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(f.mints) != 1 || strings.TrimSpace(f.mints[0]) != `{"permissions":{"actions":"read"},"repository_ids":[42]}` {
		t.Errorf("the mints asked for %q", f.mints)
	}
	r := f.requests[0]
	if r.method != "GET" || r.path != "/repositories/42/actions/runs/99" || r.body != "" {
		t.Errorf("%s %s %q", r.method, r.path, r.body)
	}
	checkHeaders(t, r, false)

	f.answer = answering(200, `{"id":99,"status":"queued","conclusion":null,"html_url":"https://github.com/example-org/runner/actions/runs/99","head_sha":"0123456789abcdef0123456789abcdef01234567","path":".github/workflows/runner.yml"}`)
	got, err = a.ReadWorkflowRun(context.Background(), 7, 42, 99)
	if err != nil || got.Status != "queued" || got.Conclusion != "" || got.RunAttempt != 0 {
		t.Errorf("got %+v, %v", got, err)
	}
}

// TestCancelWorkflowRunCancelsAndTakesA409AsDone cancels a run, GitHub's 202, and again
// once it has completed, GitHub's 409, which is done too, with one request each.
func TestCancelWorkflowRunCancelsAndTakesA409AsDone(t *testing.T) {
	f := &fakeActions{answer: answering(202, `{}`)}
	a := serveActions(t, f)
	if err := a.CancelWorkflowRun(context.Background(), 7, 42, 99); err != nil {
		t.Fatal(err)
	}
	f.answer = answering(409, `{"message":"Cannot cancel a workflow run that is completed."}`)
	if err := a.CancelWorkflowRun(context.Background(), 7, 42, 99); err != nil {
		t.Errorf("a 409: %v", err)
	}
	if len(f.mints) != 1 || strings.TrimSpace(f.mints[0]) != `{"permissions":{"actions":"write"},"repository_ids":[42]}` {
		t.Errorf("the mints asked for %q", f.mints)
	}
	if len(f.requests) != 2 {
		t.Fatalf("%d requests", len(f.requests))
	}
	for _, r := range f.requests {
		if r.method != "POST" || r.path != "/repositories/42/actions/runs/99/cancel" || r.body != "" {
			t.Errorf("%s %s %q", r.method, r.path, r.body)
		}
		checkHeaders(t, r, false)
	}
}

// TestATokenIsKeptUntilShortlyBeforeItExpiresOrA401 sends three requests with one mint,
// mints again once five minutes or fewer are left, and again after a 401.
func TestATokenIsKeptUntilShortlyBeforeItExpiresOrA401(t *testing.T) {
	f := &fakeActions{answer: answering(202, `{}`)}
	a := serveActions(t, f)
	ctx := context.Background()
	for range 3 {
		if err := a.CancelWorkflowRun(ctx, 7, 42, 99); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.mints) != 1 {
		t.Errorf("%d mints for three requests", len(f.mints))
	}
	// Another repository, or another level, is another token.
	a.CancelWorkflowRun(ctx, 7, 43, 99)
	f.answer = answering(200, runAnswer)
	a.ReadWorkflowRun(ctx, 7, 42, 99)
	if len(f.mints) != 3 {
		t.Errorf("%d mints, not 3", len(f.mints))
	}
	at := actionsAt.Add(55 * time.Minute)
	a.Client.Now = func() time.Time { return at }
	a.ReadWorkflowRun(ctx, 7, 42, 99)
	if len(f.mints) != 4 {
		t.Errorf("%d mints, not 4, with five minutes left", len(f.mints))
	}
	a.Client.Now = func() time.Time { return actionsAt }
	f.answer = answering(401, `{"message":"Bad credentials"}`)
	if _, err := a.ReadWorkflowRun(ctx, 7, 42, 99); !errors.Is(err, ErrActionsTransient) || !Unauthorized(err) {
		t.Errorf("a 401: %v", err)
	}
	f.answer = answering(200, runAnswer)
	a.ReadWorkflowRun(ctx, 7, 42, 99)
	if len(f.mints) != 5 {
		t.Errorf("%d mints, not 5, after a 401", len(f.mints))
	}
}

// actionsCalls are the three calls, each sent once.
var actionsCalls = map[string]func(*Actions) error{
	"dispatch": func(a *Actions) error {
		_, err := a.DispatchWorkflow(context.Background(), 7, 42, "runner.yml", "main", dispatchID)
		return err
	},
	"read": func(a *Actions) error {
		_, err := a.ReadWorkflowRun(context.Background(), 7, 42, 99)
		return err
	},
	"cancel": func(a *Actions) error { return a.CancelWorkflowRun(context.Background(), 7, 42, 99) },
}

// TestEachRefusalIsClassed answers each call with each status and checks which of
// gone, refused and transient its error wraps, and that it wraps no other.
func TestEachRefusalIsClassed(t *testing.T) {
	cases := []struct {
		status int
		header []string
		want   error
	}{
		{301, []string{"Location", "/elsewhere"}, ErrActionsGone},
		{302, []string{"Location", "/elsewhere"}, ErrActionsGone},
		{307, []string{"Location", "/elsewhere"}, ErrActionsGone},
		{308, []string{"Location", "/elsewhere"}, ErrActionsGone},
		{404, nil, ErrActionsGone},
		{410, nil, ErrActionsGone},
		{400, nil, ErrActionsRefused},
		{403, nil, ErrActionsRefused},
		{422, nil, ErrActionsRefused},
		{403, []string{"Retry-After", "1"}, ErrActionsTransient},
		{429, []string{"Retry-After", "1"}, ErrActionsTransient},
		{401, nil, ErrActionsTransient},
		{408, nil, ErrActionsTransient},
		{500, nil, ErrActionsTransient},
		{502, nil, ErrActionsTransient},
		{503, nil, ErrActionsTransient},
	}
	for name, call := range actionsCalls {
		for _, c := range cases {
			f := &fakeActions{answer: answering(c.status, `{"message":"an example refusal"}`, c.header...)}
			if err := call(serveActions(t, f)); !wrapsOnly(err, c.want) {
				t.Errorf("%s, %d %v: %v", name, c.status, c.header, err)
			}
		}
	}
}

// TestAMintThatFailsIsClassedAndSendsNothingMore classes a mint GitHub refuses for good,
// one it redirects, and one that may pass, and checks no Actions request follows.
func TestAMintThatFailsIsClassedAndSendsNothingMore(t *testing.T) {
	cases := []struct {
		status int
		header http.Header
		want   error
	}{
		{404, nil, ErrActionsRefused},
		{422, nil, ErrActionsRefused},
		{401, nil, ErrActionsRefused},
		{302, http.Header{"Location": {"/elsewhere"}}, ErrActionsGone},
		{500, nil, ErrActionsTransient},
	}
	for name, call := range actionsCalls {
		for _, c := range cases {
			f := &fakeActions{mintStatus: c.status, mintHeader: c.header, answer: answering(200, runAnswer)}
			err := call(serveActions(t, f))
			if !errors.Is(err, c.want) || len(f.requests) != 0 {
				t.Errorf("%s, a mint's %d: %v, %d requests", name, c.status, err, len(f.requests))
			}
		}
	}
}

// TestAnAPIThatCannotBeReachedIsTransient sends to an API that is closed.
func TestAnAPIThatCannotBeReachedIsTransient(t *testing.T) {
	f := &fakeActions{answer: answering(200, runAnswer)}
	a := serveActions(t, f)
	a.Client.Now = func() time.Time { return actionsAt }
	if _, err := a.ReadWorkflowRun(context.Background(), 7, 42, 99); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	a.Client.API = srv.URL
	srv.Close()
	for name, call := range actionsCalls {
		if err := call(a); !errors.Is(err, ErrActionsTransient) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestARedirectIsNotFollowed answers each call with a redirect to another server and to
// another path of the same one, and checks neither is asked.
func TestARedirectIsNotFollowed(t *testing.T) {
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	defer other.Close()
	for name, call := range actionsCalls {
		for _, to := range []string{other.URL + "/repositories/42/actions/runs/99", "/repositories/43/actions/runs/99"} {
			for _, status := range []int{301, 302, 303, 307, 308} {
				f := &fakeActions{answer: answering(status, "", "Location", to)}
				err := call(serveActions(t, f))
				if !errors.Is(err, ErrActionsGone) || !strings.Contains(err.Error(), "GitHub answered "+strconv.Itoa(status)) {
					t.Errorf("%s, %d to %s: %v", name, status, to, err)
				}
				if len(f.requests) != 1 {
					t.Errorf("%s, %d to %s: %d requests", name, status, to, len(f.requests))
				}
			}
		}
	}
	if elsewhere != 0 {
		t.Errorf("the other server was asked %d times", elsewhere)
	}
}

// TestAnAnswerLargerThan1MiBIsRefused answers each call with more than 1 MiB.
func TestAnAnswerLargerThan1MiBIsRefused(t *testing.T) {
	large := `{"padding":"` + strings.Repeat("x", 1<<20) + `"}`
	for name, call := range actionsCalls {
		status, want := 200, ErrActionsTransient
		switch name {
		case "cancel":
			status = 202
		case "dispatch":
			want = ErrActionsNoRun
		}
		f := &fakeActions{answer: answering(status, large)}
		err := call(serveActions(t, f))
		if !wrapsOnly(err, want) || !strings.Contains(err.Error(), "larger than 1048576 bytes") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestARequestThatIsNotOneIsRefusedWithNoRequest refuses a dispatch_id outside the
// contract's pattern, a workflow's file name or a ref that is not one, an id that is not
// one, and an App that is not one, before anything is sent, the mint among it.
func TestARequestThatIsNotOneIsRefusedWithNoRequest(t *testing.T) {
	f := &fakeActions{answer: answering(200, runAnswer)}
	a := serveActions(t, f)
	ctx := context.Background()
	dispatch := func(installation, repository int64, workflow, ref, id string) func() error {
		return func() error {
			_, err := a.DispatchWorkflow(ctx, installation, repository, workflow, ref, id)
			return err
		}
	}
	cases := map[string]func() error{}
	for _, id := range []string{"", "dp_", "dp_0123456789abcde", "dp_0123456789abcdef0", "dp_0123456789ABCDEF", "dp_0123456789abcdei", "dp_0123456789abcdel", "dp_0123456789abcdeo", "dp_0123456789abcdeu", "np_0123456789abcdef", "dp_0123456789abcdef\n", " dp_0123456789abcdef"} {
		cases["dispatch_id "+strconv.Quote(id)] = dispatch(7, 42, "runner.yml", "main", id)
	}
	for _, w := range []string{"", "runner", ".yml", "runner.json", "../runner.yml", "a/runner.yml", "runner.yml/../x.yml", "runner.yml?x=1", "runner.yml#x", "run ner.yml", "runner.yml%2F", strings.Repeat("a", 251) + ".yml"} {
		cases["workflow "+strconv.Quote(w)] = dispatch(7, 42, w, "main", dispatchID)
	}
	for _, ref := range []string{"", "-main", "HEAD", "refs/heads/HEAD", "refs/heads/-main", "refs/pull/1/head", "refs/remotes/origin/main", "@", "a..b", "a b", "main.", "main/", "/main", "a@{1}", "a~1", "a^", "a:b", "a?", "a*", "a[", `a\b`, ".hidden", "x.lock", "a\x00b", strings.Repeat("a", 256)} {
		cases["ref "+strconv.Quote(ref)] = dispatch(7, 42, "runner.yml", ref, dispatchID)
	}
	cases["dispatch, installation 0"] = dispatch(0, 42, "runner.yml", "main", dispatchID)
	cases["dispatch, repository 0"] = dispatch(7, 0, "runner.yml", "main", dispatchID)
	cases["dispatch, repository -1"] = dispatch(7, -1, "runner.yml", "main", dispatchID)
	cases["read, repository 0"] = func() error { _, err := a.ReadWorkflowRun(ctx, 7, 0, 99); return err }
	cases["read, run 0"] = func() error { _, err := a.ReadWorkflowRun(ctx, 7, 42, 0); return err }
	cases["read, installation -1"] = func() error { _, err := a.ReadWorkflowRun(ctx, -1, 42, 99); return err }
	cases["cancel, run -1"] = func() error { return a.CancelWorkflowRun(ctx, 7, 42, -1) }
	cases["cancel, repository 0"] = func() error { return a.CancelWorkflowRun(ctx, 7, 0, 99) }
	for name, call := range cases {
		if err := call(); !errors.Is(err, ErrActionsInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noApp := &Actions{Client: a.Client, AppID: "not an id", Key: key(t)}
	noKey := &Actions{Client: a.Client, AppID: appID}
	elsewhere := &Actions{Client: Client{API: "https://api.example.com"}, AppID: appID, Key: key(t)}
	for _, b := range []*Actions{noApp, noKey, elsewhere} {
		for name, call := range actionsCalls {
			if err := call(b); !errors.Is(err, ErrActionsInvalid) {
				t.Errorf("%s with %v: %v", name, b, err)
			}
		}
	}
	if f.all != 0 {
		t.Errorf("%d requests", f.all)
	}
	// The pattern's ends hold: the first and the last characters of its alphabet.
	for _, id := range []string{"dp_0000000000000000", "dp_zzzzzzzzzzzzzzzz", "dp_hjkmnpqrstvwxyz0"} {
		if !dispatchIDShape().MatchString(id) {
			t.Errorf("%s is refused", id)
		}
	}
}

// TestTheTokenNeverAppearsInAnErrorALogOrAPrintedActions gathers an error of every
// class and every call, with the log captured, and looks for the token in each, and in
// the Actions printed with every verb.
func TestTheTokenNeverAppearsInAnErrorALogOrAPrintedActions(t *testing.T) {
	var logged bytes.Buffer
	before := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(before)
	var errs []error
	for _, status := range []int{301, 400, 401, 403, 404, 409, 410, 422, 429, 500} {
		for _, call := range actionsCalls {
			f := &fakeActions{answer: answering(status, `{"message":"an example refusal"}`)}
			if err := call(serveActions(t, f)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, body := range []string{`not json`, `{"padding":"` + strings.Repeat("x", 1<<20) + `"}`} {
		for _, call := range actionsCalls {
			if err := call(serveActions(t, &fakeActions{answer: answering(200, body)})); err != nil {
				errs = append(errs, err)
			}
		}
	}
	a := serveActions(t, &fakeActions{answer: answering(200, runAnswer)})
	if _, err := a.ReadWorkflowRun(context.Background(), 7, 42, 99); err != nil {
		t.Fatal(err)
	}
	if len(errs) < 30 {
		t.Fatalf("only %d errors", len(errs))
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), actionsToken) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), actionsToken) {
			t.Errorf("an error says the token: %v", err)
		}
	}
	printed := fmt.Sprintf("%v %+v %#v %s", a, a, a, a)
	if strings.Contains(printed, actionsToken) || strings.Contains(printed, a.Key.D.String()[:20]) || !strings.Contains(printed, "tokens: 1 kept") {
		t.Errorf("printed: %s", printed)
	}
	if strings.Contains(logged.String(), actionsToken) {
		t.Errorf("the log says the token: %s", logged.String())
	}
}

// TestAnActionsIsSafeForConcurrentUse sends from many goroutines at once, for the race
// detector.
func TestAnActionsIsSafeForConcurrentUse(t *testing.T) {
	f := &fakeActions{answer: answering(202, `{}`)}
	a := serveActions(t, f)
	a.Pacer = nil
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			if err := a.CancelWorkflowRun(context.Background(), 7, int64(40+i%3), 99); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if s := a.String(); !strings.Contains(s, "tokens: 3 kept") {
		t.Errorf("%s", s)
	}
}

// findAnswer answers FindRepository's requests: the installation's lookup with
// installation, and the repository's read with status and body.
func findAnswer(installation string, status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/installation") {
			io.WriteString(w, installation)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

// TestFindRepositoryNamesTheRepositoryAsGitHubDoes finds a repository whose full_name
// GitHub writes in another case, and checks the installation's lookup with the App's
// token, the mint for that repository alone with metadata read, and the read.
func TestFindRepositoryNamesTheRepositoryAsGitHubDoes(t *testing.T) {
	f := &fakeActions{answer: findAnswer(`{"id":7}`, 200, `{"id":42,"full_name":"Example-Org/Runner"}`)}
	a := serveActions(t, f)
	got, err := a.FindRepository(context.Background(), Repository{Owner: "example-org", Name: "runner"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (ActionsRepository{Installation: 7, ID: 42, FullName: "Example-Org/Runner"}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(f.mints) != 1 || strings.TrimSpace(f.mints[0]) != `{"permissions":{"metadata":"read"},"repositories":["runner"]}` {
		t.Errorf("the mints asked for %q", f.mints)
	}
	if len(f.requests) != 2 || f.requests[0].path != "/repos/example-org/runner/installation" || f.requests[1].path != "/repos/example-org/runner" {
		t.Fatalf("the requests were %+v", f.requests)
	}
	if auth := f.requests[0].header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") || auth == "Bearer "+actionsToken {
		t.Errorf("the installation's lookup is not made with the App's token")
	}
	checkHeaders(t, f.requests[1], false)
}

// TestFindRepositoryRefusesWhatIsNotTheRepository refuses another repository's
// full_name, an id that is not one, a redirect, a 404 and an installation without an id,
// each classed, and never says the token.
func TestFindRepositoryRefusesWhatIsNotTheRepository(t *testing.T) {
	for _, c := range []struct {
		name         string
		installation string
		status       int
		body         string
		want         error
	}{
		{"another repository", `{"id":7}`, 200, `{"id":42,"full_name":"example-org/runner2"}`, ErrActionsRefused},
		{"no id", `{"id":7}`, 200, `{"full_name":"example-org/runner"}`, ErrActionsRefused},
		{"not a name", `{"id":7}`, 200, `{"id":42,"full_name":"example-org/runner/x"}`, ErrActionsRefused},
		{"moved", `{"id":7}`, 301, `{"message":"Moved Permanently"}`, ErrActionsGone},
		{"not found", `{"id":7}`, 404, `{"message":"Not Found"}`, ErrActionsGone},
		{"no installation", `{}`, 200, `{"id":42,"full_name":"example-org/runner"}`, ErrActionsTransient},
		{"server error", `{"id":7}`, 502, `{"message":"Bad Gateway"}`, ErrActionsTransient},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeActions{answer: findAnswer(c.installation, c.status, c.body)}
			a := serveActions(t, f)
			_, err := a.FindRepository(context.Background(), Repository{Owner: "example-org", Name: "runner"})
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if strings.Contains(err.Error(), actionsToken) {
				t.Errorf("the error says the token")
			}
		})
	}
	t.Run("installation not found", func(t *testing.T) {
		f := &fakeActions{answer: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
		}}
		a := serveActions(t, f)
		if _, err := a.FindRepository(context.Background(), Repository{Owner: "example-org", Name: "runner"}); !errors.Is(err, ErrActionsGone) {
			t.Fatalf("got %v", err)
		}
		if len(f.mints) != 0 {
			t.Errorf("a token was minted")
		}
	})
	t.Run("not owner/name", func(t *testing.T) {
		f := &fakeActions{}
		a := serveActions(t, f)
		if _, err := a.FindRepository(context.Background(), Repository{Owner: "-x", Name: "runner"}); !errors.Is(err, ErrActionsInvalid) {
			t.Fatalf("got %v", err)
		}
		if f.all != 0 {
			t.Errorf("%d requests were sent", f.all)
		}
	})
}
