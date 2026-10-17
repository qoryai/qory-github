package starter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/server"
	"github.com/qoryai/qory-github"
)

const (
	ghInstallation = 77
	ghFullName     = "Example-Org/Runners"
	ghHTML         = "https://github.com/Example-Org/Runners/actions/runs/987654321"
	ghToken        = "ghs_starterfaketoken"
	// runsPath is the run endpoint's path the configuration document gives, which no
	// other setting holds.
	runsPath = "/v1/runs-from-configuration"
)

// leaseUntil is the claim answer's lease_until, provisioner fixture explore.json's.
var leaseUntil = time.Date(2026, 10, 15, 12, 5, 0, 0, time.UTC)

// fakeTime is the starter's clock in a test: it reads testClock until a wait moves it
// on, records each wait, and lets the watch read a workflow run only on a tick.
type fakeTime struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
	ticks chan struct{}
}

func newFakeTime() *fakeTime { return &fakeTime{now: testClock, ticks: make(chan struct{})} }

func (c *fakeTime) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeTime) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	c.mu.Unlock()
	runtime.Gosched()
	return nil
}

func (c *fakeTime) set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

func (c *fakeTime) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.slept)
}

func (c *fakeTime) Poll(ctx context.Context, _ time.Duration, wake <-chan struct{}) error {
	select {
	case <-c.ticks:
		return nil
	case <-wake:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// apiaryFake is Qory Apiary for the starter: [fake], with claims answered in order and
// then held, as a claim is while no run can be claimed, and handovers answered by
// handover, the first drops of them answered and then cut off, so the answer is lost.
type apiaryFake struct {
	*fake
	t *testing.T

	mu         sync.Mutex
	claims     []reply
	claimsSeen int
	answered   int
	dispatched reply
	handover   func(n int) reply
	handovers  int
	drops      int
	release    reply
	stop       chan struct{}
}

func newApiaryFake(t *testing.T) *apiaryFake {
	t.Helper()
	a := &apiaryFake{t: t, stop: make(chan struct{})}
	a.fake = &fake{t: t, server: newKey(t), pool: newKey(t), other: newKey(t), answer: a.answer, sigs: map[string]bool{}}
	a.claims = []reply{{status: http.StatusOK, body: claimAnswer(t, "explore")}}
	a.handover = func(int) reply { return reply{status: http.StatusOK, body: handoverAnswer(t)} }
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	t.Cleanup(func() { close(a.stop) })
	return a
}

func (a *apiaryFake) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	var hold, drop bool
	switch {
	case r.URL.Path == routeClaim:
		a.claimsSeen++
		hold = a.claimsSeen > len(a.claims)
	case strings.HasSuffix(r.URL.Path, "/handover") && a.drops > 0:
		a.drops--
		drop = true
	}
	a.mu.Unlock()
	switch {
	case hold:
		select {
		case <-r.Context().Done():
		case <-a.stop:
		}
	case drop:
		a.fake.serve(httptest.NewRecorder(), r)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	default:
		a.fake.serve(w, r)
	}
}

func (a *apiaryFake) answer(_ int, s seen) reply {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case s.target == routeClaim:
		a.answered++
		return a.claims[a.answered-1]
	case strings.HasSuffix(s.target, "/dispatched"):
		if a.dispatched.status == 0 {
			return reply{status: http.StatusNoContent}
		}
		return a.dispatched
	case strings.HasSuffix(s.target, "/handover"):
		a.handovers++
		return a.handover(a.handovers)
	case strings.HasSuffix(s.target, "/release"):
		if a.release.status == 0 {
			return reply{status: http.StatusNoContent}
		}
		return a.release
	case s.target == server.WellKnown:
		return confAnswer(withRunURL(a.t, a.srv.URL+runsPath))
	case strings.HasPrefix(s.target, runsPath+"/"):
		return reply{status: http.StatusOK, body: `{"version":1}`}
	}
	return reply{status: http.StatusNotFound, body: `{"error":"not_found"}`}
}

// sent are the requests whose path ends in suffix, in order.
func (a *apiaryFake) sent(suffix string) []seen {
	var out []seen
	for _, s := range a.requests() {
		if strings.HasSuffix(s.target, suffix) {
			out = append(out, s)
		}
	}
	return out
}

// targets are the paths of the requests after the claims, in order.
func (a *apiaryFake) targets() []string {
	var out []string
	for _, s := range a.requests() {
		if s.target != routeClaim {
			out = append(out, s.target)
		}
	}
	return out
}

// claimAnswer is the provisioner fixture's claim answer for step, its title the marker.
func claimAnswer(t *testing.T, step string) string {
	t.Helper()
	doc := strings.Replace(fixture(t, "claim-answer/explore.json"), "Checkout fails on an empty cart", titleMarker, 1)
	return strings.Replace(doc, `"step": "explore"`, `"step": "`+step+`"`, 1)
}

// handoverAnswer is the provisioner fixture's handover answer with the run key, the
// inputs and the title markers.
func handoverAnswer(t *testing.T) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(fixture(t, "handover-answer/explore.json")), &m); err != nil {
		t.Fatal(err)
	}
	m["run_key"] = runKeyMarker
	m["work_item"].(map[string]any)["title"] = titleMarker
	m["inputs"].(map[string]any)["ticket"].(map[string]any)["body"] = inputsMarker
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// refusalOf is a signed refusal with code.
func refusalOf(status int, code string) reply {
	return reply{status: status, body: `{"error":"` + code + `"}`}
}

// gitHubFake is GitHub's API for the starter: the installation, the mint, the
// repository, the dispatch, the workflow run and its cancel.
type gitHubFake struct {
	srv *httptest.Server

	mu             sync.Mutex
	dispatchStatus int
	dispatches     []string
	status         string
	conclusion     string
	cancels        int
	cancelRefused  bool
	reads          int
}

func newGitHubFake(t *testing.T) *gitHubFake {
	t.Helper()
	g := &gitHubFake{dispatchStatus: http.StatusOK, status: "queued"}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gitHubFake) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	run := "/repositories/" + strconv.Itoa(testRepoID) + "/actions/runs/" + strconv.Itoa(testRunID)
	switch p := r.URL.Path; {
	case r.Method == http.MethodGet && p == "/repos/example-org/runners/installation":
		io.WriteString(w, `{"id":`+strconv.Itoa(ghInstallation)+`}`)
	case r.Method == http.MethodGet && p == "/app/installations/"+strconv.Itoa(ghInstallation):
		io.WriteString(w, `{"account":{"login":"Example-Org"}}`)
	case r.Method == http.MethodPost && p == "/app/installations/"+strconv.Itoa(ghInstallation)+"/access_tokens":
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"token":"`+ghToken+`","expires_at":"2099-01-01T00:00:00Z"}`)
	case r.Method == http.MethodGet && p == "/repos/example-org/runners":
		io.WriteString(w, `{"id":`+strconv.Itoa(testRepoID)+`,"full_name":"`+ghFullName+`"}`)
	case r.Method == http.MethodPost && p == "/repositories/"+strconv.Itoa(testRepoID)+"/actions/workflows/"+testWorkflow+"/dispatches":
		g.dispatches = append(g.dispatches, string(b))
		w.WriteHeader(g.dispatchStatus)
		if g.dispatchStatus == http.StatusOK {
			io.WriteString(w, `{"workflow_run_id":`+strconv.Itoa(testRunID)+`,"run_url":"https://api.github.com`+run+`","html_url":"`+ghHTML+`"}`)
		}
	case r.Method == http.MethodGet && p == run:
		g.reads++
		conclusion := "null"
		if g.conclusion != "" {
			conclusion = `"` + g.conclusion + `"`
		}
		io.WriteString(w, `{"id":`+strconv.Itoa(testRunID)+`,"status":"`+g.status+`","conclusion":`+conclusion+`}`)
	case r.Method == http.MethodPost && p == run+"/cancel":
		g.cancels++
		if g.cancelRefused {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"message":"Cannot cancel"}`)
			return
		}
		g.status, g.conclusion = "completed", "cancelled"
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func (g *gitHubFake) set(status, conclusion string) {
	g.mu.Lock()
	g.status, g.conclusion = status, conclusion
	g.mu.Unlock()
}

func (g *gitHubFake) counts() (dispatches, cancels, reads int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.dispatches), g.cancels, g.reads
}

// lockedBuffer is a log the starter writes to while a test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// harness runs the starter against the three fakes: Qory Apiary, GitHub and the
// issuer of the job's token.
type harness struct {
	t        *testing.T
	clock    *fakeTime
	apiary   *apiaryFake
	gh       *gitHubFake
	issuer   *fakeIssuer
	settings Settings
	dir      string
	tmp      string
	logs     *lockedBuffer
	addr     string
	cancel   context.CancelFunc
	done     chan error
	stopped  bool
}

var (
	appKeyOnce sync.Once
	appKeyPEM  []byte
)

func newHarness(t *testing.T) *harness {
	t.Helper()
	k, _, _ := testKeys(t)
	h := &harness{
		t: t, clock: newFakeTime(), apiary: newApiaryFake(t), gh: newGitHubFake(t),
		issuer: newFakeIssuer(t, jwk(&k.PublicKey, "k1", nil)), dir: t.TempDir(), tmp: t.TempDir(), logs: &lockedBuffer{},
	}
	appKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		appKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	})
	if err := os.WriteFile(filepath.Join(h.dir, "access-key"), []byte(h.apiary.pool.Secret()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "app.pem"), appKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	h.settings = Settings{
		ApiaryURL: h.apiary.srv.URL, AccessKeyID: testKeyID, AccessKeySecretFile: filepath.Join(h.dir, "access-key"),
		ApiaryPublicKey: pinOf(h.apiary.server), PoolID: testPool, Listen: "127.0.0.1:0", PublicURL: testAudience,
		StateDir: filepath.Join(h.dir, "state"), AppID: "12345", PrivateKeyFile: filepath.Join(h.dir, "app.pem"),
		APIURL: h.gh.srv.URL, Repository: "example-org/runners", Workflow: testWorkflow, Ref: "main", WorkflowSHA: testSHA,
	}
	t.Setenv("TMPDIR", h.tmp)
	return h
}

// start runs the starter.
func (h *harness) start() {
	h.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	deps := Deps{
		Now: h.clock.Now, Sleep: h.clock.Sleep, Poll: h.clock.Poll,
		Log:      slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		GitHub:   github.Client{UserAgent: "qory-github-starter/test"},
		Verifier: newVerifier(h.issuer.srv.URL, h.issuer.srv.Client().Transport, h.clock.Now),
		Listener: ln,
	}
	go func() { h.done <- Run(ctx, h.settings, deps) }()
	h.t.Cleanup(h.stop)
}

// stop stops the starter and checks it returned nil.
func (h *harness) stop() {
	if h.stopped || h.cancel == nil {
		return
	}
	h.stopped = true
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("Run returned %v", err)
		}
	case <-time.After(20 * time.Second):
		h.t.Fatal("Run did not return")
	}
}

// eventually waits until cond holds.
func (h *harness) eventually(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("never: %s; Qory Apiary saw %v; the log:\n%s", what, h.apiary.targets(), h.logs.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// tick lets the watch read the workflow run once.
func (h *harness) tick() {
	h.t.Helper()
	select {
	case h.clock.ticks <- struct{}{}:
	case <-time.After(15 * time.Second):
		h.t.Fatalf("the watch never waited for a tick; the log:\n%s", h.logs.String())
	}
}

// dispatchedSeen waits until dispatched reached Qory Apiary.
func (h *harness) dispatchedSeen() {
	h.t.Helper()
	h.eventually("dispatched", func() bool { return len(h.apiary.sent("/dispatched")) == 1 })
}

// claims are the job's token's claims for the dispatched run, as GitHub writes them.
func (h *harness) claims() map[string]any {
	now := h.clock.Now().Unix()
	template := ghFullName + "/.github/workflows/" + testWorkflow + "@refs/heads/main"
	return map[string]any{
		"jti": marker + "-jti", "sub": "repo:" + ghFullName + ":ref:refs/heads/main", "iss": h.issuer.srv.URL,
		"aud": testAudience, "ref": "refs/heads/main", "ref_type": "branch", "sha": testSHA,
		"repository": ghFullName, "repository_owner": "Example-Org", "repository_id": strconv.Itoa(testRepoID),
		"run_id": strconv.Itoa(testRunID), "run_number": "7", "run_attempt": "1", "runner_environment": "github-hosted",
		"event_name": "workflow_dispatch", "workflow_ref": template, "workflow_sha": testSHA,
		"job_workflow_ref": template, "job_workflow_sha": testSHA, "nbf": now - 60, "iat": now, "exp": now + 300,
	}
}

// token is the job's token, with edit applied to its claims.
func (h *harness) token(edit func(map[string]any)) string {
	h.t.Helper()
	k, _, _ := testKeys(h.t)
	c := h.claims()
	if edit != nil {
		edit(c)
	}
	return token(h.t, k, "k1", c)
}

// jobAnswer is what the pass-through answered the job.
type jobReply struct {
	status int
	body   []byte
	header http.Header
}

// job sends the job's request for dispatch with auth as its Authorization, none when
// empty.
func (h *harness) job(dispatch, auth string) jobReply {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+h.addr+"/v1/dispatches/"+dispatch+"/handover", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		h.t.Fatalf("the job's request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return jobReply{status: resp.StatusCode, body: b, header: resp.Header}
}

// bearer is the Authorization of token.
func bearerOf(token string) string { return "Bearer " + token }

// checkReleased checks the one release Qory Apiary saw: its reason and its retry.
func (h *harness) checkReleased(reason string, retry bool) {
	h.t.Helper()
	rel := h.apiary.sent("/release")
	if len(rel) != 1 {
		h.t.Fatalf("%d releases, not 1; Qory Apiary saw %v", len(rel), h.apiary.targets())
	}
	var doc struct {
		Reason string `json:"reason"`
		Retry  bool   `json:"retry"`
	}
	if err := json.Unmarshal(rel[0].body, &doc); err != nil {
		h.t.Fatal(err)
	}
	if doc.Reason != reason || doc.Retry != retry {
		h.t.Errorf("released for %q, retry %v; want %q, retry %v", doc.Reason, doc.Retry, reason, retry)
	}
}

// checkNoLeak checks that no line of the log, no request to GitHub and no file in the
// test's directories or its TMPDIR holds the run key, the inputs or the title.
func (h *harness) checkNoLeak() {
	h.t.Helper()
	if l := leaks(h.logs.String(), h.apiary.pool.Secret()); l != "" {
		h.t.Errorf("the log holds %s", l)
	}
	h.gh.mu.Lock()
	for _, d := range h.gh.dispatches {
		if d != `{"ref":"refs/heads/main","inputs":{"dispatch_id":"`+testDispatch+`"},"return_run_details":true}` {
			h.t.Errorf("a dispatch sent %s", d)
		}
	}
	h.gh.mu.Unlock()
	for _, dir := range []string{h.dir, h.tmp} {
		err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range []string{runKeyMarker, "RunKeyMarker", inputsMarker, titleMarker, "qrk_"} {
				if bytes.Contains(b, []byte(m)) {
					h.t.Errorf("the file %s holds a secret's marker", filepath.Base(path))
				}
			}
			return nil
		})
		if err != nil {
			h.t.Fatal(err)
		}
	}
}

// logLines are the messages of the log's lines.
func (h *harness) logLines() []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var m struct {
			Msg string `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m.Msg)
		}
	}
	return out
}

// handOver runs the happy path to the handover: the job asks, and gets the run key.
func (h *harness) handOver() jobReply {
	h.t.Helper()
	h.start()
	h.dispatchedSeen()
	got := h.job(testDispatch, bearerOf(h.token(nil)))
	if got.status != http.StatusOK {
		h.t.Fatalf("the job got %d %s; the log:\n%s", got.status, got.body, h.logs.String())
	}
	return got
}

// TestHappyPath claims, dispatches, says dispatched with the workflow run, hands the run
// key to the job whose token passes, and on the run's success posts the outcome
// succeeded to the run endpoint of the configuration document, and nothing else.
func TestHappyPath(t *testing.T) {
	h := newHarness(t)
	got := h.handOver()
	var answer struct {
		RunKey string          `json:"run_key"`
		Inputs json.RawMessage `json:"inputs"`
	}
	if err := json.Unmarshal(got.body, &answer); err != nil {
		t.Fatal(err)
	}
	var full struct {
		Inputs json.RawMessage `json:"inputs"`
	}
	_ = json.Unmarshal([]byte(handoverAnswer(t)), &full)
	if answer.RunKey != runKeyMarker || !sameJSON(t, answer.Inputs, full.Inputs) {
		t.Errorf("the job did not get the run key and the inputs")
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(got.body, &members)
	if len(members) != 2 {
		t.Errorf("the job's answer has %d members", len(members))
	}
	if cc := got.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control is %q", cc)
	}

	h.gh.set("completed", "success")
	h.tick()
	h.eventually("the outcome", func() bool { return len(h.apiary.sent("/outcome")) == 1 })
	h.stop()

	want := []string{
		"/v1/dispatches/" + testDispatch + "/dispatched",
		"/v1/dispatches/" + testDispatch + "/handover",
		server.WellKnown,
		runsPath + "/" + testRun + "/outcome",
	}
	if got := h.apiary.targets(); !slices.Equal(got, want) {
		t.Errorf("Qory Apiary saw %v, not %v", got, want)
	}
	var dispatched struct {
		External struct {
			Type, Ref, URL string
		} `json:"external"`
	}
	_ = json.Unmarshal(h.apiary.sent("/dispatched")[0].body, &dispatched)
	if dispatched.External.Type != "github-actions" || dispatched.External.Ref != strconv.Itoa(testRunID) || dispatched.External.URL != ghHTML {
		t.Errorf("dispatched named %+v", dispatched.External)
	}
	var outcome struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(h.apiary.sent("/outcome")[0].body, &outcome)
	if outcome.State != StateSucceeded {
		t.Errorf("the outcome is %q", outcome.State)
	}
	for _, s := range h.apiary.requests() {
		if !s.verified {
			t.Errorf("%s was not signed with the pool's key", s.target)
		}
	}
	instance, err := os.ReadFile(filepath.Join(h.settings.StateDir, instanceFile))
	if err != nil {
		t.Fatal(err)
	}
	if id := h.apiary.requests()[0].header.Get("X-Qory-Instance-Id"); id+"\n" != string(instance) {
		t.Errorf("the instance id sent is not the one kept")
	}
	lines := h.logLines()
	for _, l := range []string{"claimed a run", "started the job", "handed the run to its job", "posted the run's outcome"} {
		if !slices.Contains(lines, l) {
			t.Errorf("no line %q in %q", l, lines)
		}
	}
	h.checkNoLeak()
}

// TestOutcomeOrder posts, after the handover, the outcome succeeded alone on success,
// and on any other conclusion releases the run with retry true first, then posts the
// outcome the conclusion gives.
func TestOutcomeOrder(t *testing.T) {
	for _, c := range []struct {
		conclusion, state string
		release           bool
	}{
		{"success", StateSucceeded, false},
		{"failure", StateFailed, true},
		{"timed_out", StateFailed, true},
		{"cancelled", StateCancelled, true},
		{"neutral", "", true},
	} {
		t.Run(c.conclusion, func(t *testing.T) {
			h := newHarness(t)
			h.handOver()
			h.gh.set("completed", c.conclusion)
			h.tick()
			h.eventually("the outcome", func() bool { return len(h.apiary.sent("/outcome")) == 1 })
			h.stop()
			targets := h.apiary.targets()
			out := slices.Index(targets, runsPath+"/"+testRun+"/outcome")
			rel := slices.Index(targets, "/v1/dispatches/"+testDispatch+"/release")
			switch {
			case !c.release && rel >= 0:
				t.Errorf("the run was released on success: %v", targets)
			case c.release && (rel < 0 || rel > out):
				t.Errorf("the release did not come before the outcome: %v", targets)
			}
			if c.release {
				h.checkReleased(reasonNoSuccess, true)
			}
			var outcome map[string]any
			_ = json.Unmarshal(h.apiary.sent("/outcome")[0].body, &outcome)
			if state, _ := outcome["state"].(string); state != c.state {
				t.Errorf("the outcome's state is %q, not %q", state, c.state)
			}
			h.checkNoLeak()
		})
	}
}

// TestHandedOver stops the job and releases the run with retry true when a handover is
// refused 409 handed_over: at once, after an answer cut off on the way, and after an
// answer over its bound, both of which are sent again first. The run key of the lost
// answer goes nowhere.
func TestHandedOver(t *testing.T) {
	for _, c := range []struct {
		name  string
		drops int
		first reply
	}{
		{"at once", 0, refusalOf(http.StatusConflict, "handed_over")},
		{"after a lost answer", 1, reply{}},
		{"after an answer over its bound", 0, reply{status: http.StatusOK, body: strings.Repeat(" ", 1<<20+1)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.apiary.drops = c.drops
			lost := handoverAnswer(t)
			h.apiary.handover = func(n int) reply {
				switch {
				case n == 1 && c.first.status != 0:
					return c.first
				case n == 1:
					return reply{status: http.StatusOK, body: lost}
				}
				return refusalOf(http.StatusConflict, "handed_over")
			}
			h.gh.set("in_progress", "")
			h.start()
			h.dispatchedSeen()
			got := h.job(testDispatch, bearerOf(h.token(nil)))
			if got.status != http.StatusBadGateway || bytes.Contains(got.body, []byte("qrk_")) {
				t.Fatalf("the job got %d %s", got.status, got.body)
			}
			h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
			h.eventually("the watch's end", func() bool { return !h.watching() })
			h.stop()
			h.checkReleased(reasonHandedOver, true)
			if _, cancels, _ := h.gh.counts(); cancels != 1 {
				t.Errorf("%d cancels", cancels)
			}
			want := 2
			if c.first.status == http.StatusConflict {
				want = 1
			}
			if n := len(h.apiary.sent("/handover")); n != want {
				t.Errorf("%d handovers, not %d", n, want)
			}
			if len(h.apiary.sent("/outcome")) != 0 {
				t.Errorf("an outcome was posted")
			}
			h.checkNoLeak()
		})
	}
}

// watching is whether a watch still waits for a tick: once the watch ends, nothing
// takes one. A tick it takes is one more read of the workflow run.
func (h *harness) watching() bool {
	select {
	case h.clock.ticks <- struct{}{}:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

// TestHandedOverStale takes the stale case's release refusal, 409 lease_expired or 410
// gone, as the expected end: the release is not sent again.
func TestHandedOverStale(t *testing.T) {
	for _, code := range []string{"lease_expired", "gone"} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t)
			h.apiary.drops = 1
			h.apiary.handover = func(n int) reply {
				if n == 1 {
					return reply{status: http.StatusOK, body: handoverAnswer(t)}
				}
				return refusalOf(http.StatusConflict, "handed_over")
			}
			status := http.StatusConflict
			if code == "gone" {
				status = http.StatusGone
			}
			h.apiary.release = refusalOf(status, code)
			h.start()
			h.dispatchedSeen()
			if got := h.job(testDispatch, bearerOf(h.token(nil))); got.status != http.StatusBadGateway {
				t.Fatalf("the job got %d", got.status)
			}
			h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
			h.eventually("the line", func() bool {
				return slices.Contains(h.logLines(), "the dispatch was over already, so nothing was released")
			})
			h.stop()
			if n := len(h.apiary.sent("/release")); n != 1 {
				t.Errorf("%d releases", n)
			}
			if slices.Contains(h.logLines(), "the release failed") {
				t.Errorf("the expected end was logged as a failure")
			}
			h.checkNoLeak()
		})
	}
}

// TestSecondRequestRefused takes one job request per dispatch: a second, with the same
// token, is refused as an unknown dispatch is, and of two at once one gets the run key.
func TestSecondRequestRefused(t *testing.T) {
	h := newHarness(t)
	h.handOver()
	again := h.job(testDispatch, bearerOf(h.token(nil)))
	if again.status != http.StatusForbidden || string(again.body) != answerRefused {
		t.Errorf("a second request got %d %s", again.status, again.body)
	}
	h.stop()
	if n := len(h.apiary.sent("/handover")); n != 1 {
		t.Errorf("%d handovers", n)
	}

	h = newHarness(t)
	h.start()
	h.dispatchedSeen()
	tok := bearerOf(h.token(nil))
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = h.job(testDispatch, tok).status
		}()
	}
	wg.Wait()
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{http.StatusOK, http.StatusForbidden}) {
		t.Errorf("two requests at once got %v", statuses)
	}
	h.stop()
	if n := len(h.apiary.sent("/handover")); n != 1 {
		t.Errorf("%d handovers", n)
	}
	h.checkNoLeak()
}

// TestSameRefusal refuses a request without a bearer, for an unknown dispatch, and with
// a token that fails a check, the repository named in the settings' case among them,
// with the same status and body, and sends no handover for any of them.
func TestSameRefusal(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.dispatchedSeen()
	_, keyB, _ := testKeys(t)
	other := h.claims()
	cases := []struct {
		name, dispatch, auth, reason string
	}{
		{"no bearer", testDispatch, "", ""},
		{"basic", testDispatch, "Basic " + h.token(nil), ""},
		{"empty bearer", testDispatch, "Bearer ", ""},
		{"unknown dispatch", "dp_0000000000000000", bearerOf(h.token(nil)), ""},
		{"another key", testDispatch, bearerOf(token(t, keyB, "k1", other)), "signature"},
		{"another run", testDispatch, bearerOf(h.token(func(c map[string]any) { c["run_id"] = "1" })), "run_id"},
		{"the settings' case", testDispatch, bearerOf(h.token(func(c map[string]any) {
			c["repository"] = "example-org/runners"
		})), "repository"},
		{"another audience", testDispatch, bearerOf(h.token(func(c map[string]any) { c["aud"] = "https://other.example.com" })), "aud"},
		{"another attempt", testDispatch, bearerOf(h.token(func(c map[string]any) { c["run_attempt"] = "2" })), "run_attempt"},
		{"not a token", testDispatch, "Bearer " + marker, "format"},
	}
	for _, c := range cases {
		got := h.job(c.dispatch, c.auth)
		if got.status != http.StatusForbidden || string(got.body) != answerRefused || got.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: got %d %s", c.name, got.status, got.body)
		}
		if c.reason != "" && !strings.Contains(h.logs.String(), `"reason":"`+c.reason+`"`) {
			t.Errorf("%s: no line names the check %s", c.name, c.reason)
		}
	}
	if n := len(h.apiary.sent("/handover")); n != 0 {
		t.Errorf("%d handovers", n)
	}
	if strings.Contains(h.logs.String(), marker) {
		t.Errorf("the log quotes a token")
	}
	// The dispatch's one request is still there for its job.
	if got := h.job(testDispatch, bearerOf(h.token(nil))); got.status != http.StatusOK {
		t.Errorf("the job got %d after the refusals", got.status)
	}
	h.stop()
	h.checkNoLeak()
}

// TestHandoverSentAgainWhileTheLeaseLasts sends a handover answered 409 no_gateway, a
// signed 503 unavailable, an unsigned answer, a signed 500 or no answer again, built
// anew, until lease_until and never after it, then stops the job and releases the run
// with retry true.
func TestHandoverSentAgainWhileTheLeaseLasts(t *testing.T) {
	for _, c := range []struct {
		name  string
		rep   reply
		drops int
	}{
		{"no_gateway", refusalOf(http.StatusConflict, "no_gateway"), 0},
		{"unavailable", refusalOf(http.StatusServiceUnavailable, "unavailable"), 0},
		{"unsigned", reply{status: http.StatusBadGateway, unsigned: true}, 0},
		{"server error", reply{status: http.StatusInternalServerError, body: `{"error":"internal"}`}, 0},
		{"no answer", refusalOf(http.StatusConflict, "no_gateway"), 1 << 30},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.apiary.handover = func(int) reply { return c.rep }
			h.apiary.drops = c.drops
			h.gh.set("in_progress", "")
			h.start()
			h.dispatchedSeen()
			got := h.job(testDispatch, bearerOf(h.token(nil)))
			if got.status != http.StatusBadGateway || string(got.body) != answerNoRunKey {
				t.Fatalf("the job got %d %s", got.status, got.body)
			}
			h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
			h.stop()
			sent := h.apiary.sent("/handover")
			if len(sent) < 3 {
				t.Errorf("the handover was sent %d times", len(sent))
			}
			sigs := map[string]bool{}
			for _, s := range sent {
				if !s.sent.Before(leaseUntil) {
					t.Errorf("a handover was sent at %s, at or after lease_until", s.sent)
				}
				if sigs[s.signature] {
					t.Errorf("a handover was sent again unchanged")
				}
				sigs[s.signature] = true
			}
			// The handover stops once its next try would be sent at or after
			// lease_until, so its last try is no more than the longest wait before it.
			if last := sent[len(sent)-1].sent; last.Before(leaseUntil.Add(-maxHandoverWait)) {
				t.Errorf("the last handover was sent at %s, long before lease_until", last)
			}
			h.checkReleased(reasonLeaseHanding, true)
			if _, cancels, _ := h.gh.counts(); cancels != 1 {
				t.Errorf("%d cancels", cancels)
			}
			h.checkNoLeak()
		})
	}
}

// TestHandoverStaleOrGone stops the job, and releases nothing, when the handover is
// refused 409 lease_expired or 410 gone.
func TestHandoverStaleOrGone(t *testing.T) {
	for _, rep := range []reply{refusalOf(http.StatusConflict, "lease_expired"), refusalOf(http.StatusGone, "gone")} {
		h := newHarness(t)
		h.apiary.handover = func(int) reply { return rep }
		h.gh.set("in_progress", "")
		h.start()
		h.dispatchedSeen()
		if got := h.job(testDispatch, bearerOf(h.token(nil))); got.status != http.StatusBadGateway {
			t.Fatalf("the job got %d", got.status)
		}
		h.eventually("the cancel", func() bool { _, c, _ := h.gh.counts(); return c == 1 })
		h.stop()
		if n := len(h.apiary.sent("/release")); n != 0 {
			t.Errorf("%s: %d releases", rep.body, n)
		}
	}
}

// TestLeaseLapse stops the job and releases the run with retry true when no job asks
// before lease_until, and refuses a job that asks after.
func TestLeaseLapse(t *testing.T) {
	h := newHarness(t)
	h.gh.set("in_progress", "")
	h.start()
	h.dispatchedSeen()
	h.tick()
	h.clock.set(leaseUntil)
	h.tick()
	h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
	h.checkReleased(reasonNoAsk, true)
	if _, cancels, _ := h.gh.counts(); cancels != 1 {
		t.Errorf("%d cancels", cancels)
	}
	if got := h.job(testDispatch, bearerOf(h.token(nil))); got.status != http.StatusForbidden {
		t.Errorf("a job after the lease got %d", got.status)
	}
	h.stop()
	if n := len(h.apiary.sent("/handover")); n != 0 {
		t.Errorf("%d handovers", n)
	}
}

// TestCancelReadAgain reads the run again after a cancel GitHub answers 409, and sends
// the cancel again while the run goes on.
func TestCancelReadAgain(t *testing.T) {
	h := newHarness(t)
	h.gh.set("in_progress", "")
	h.gh.cancelRefused = true
	h.start()
	h.dispatchedSeen()
	h.clock.set(leaseUntil)
	h.tick()
	h.eventually("the first cancel", func() bool { _, c, _ := h.gh.counts(); return c == 1 })
	h.tick()
	h.eventually("the second cancel", func() bool { _, c, _ := h.gh.counts(); return c == 2 })
	h.gh.mu.Lock()
	h.gh.cancelRefused = false
	h.gh.mu.Unlock()
	h.tick()
	h.eventually("the third cancel", func() bool { _, c, _ := h.gh.counts(); return c == 3 })
	h.tick()
	h.eventually("the watch's end", func() bool { return !h.watching() })
	h.stop()
	if _, cancels, _ := h.gh.counts(); cancels != 3 {
		t.Errorf("%d cancels", cancels)
	}
	if n := len(h.apiary.sent("/release")); n != 1 {
		t.Errorf("%d releases", n)
	}
}

// TestFailureBeforeHandover releases the run with retry true, and stops nothing, when
// the job's run ends before any job asks.
func TestFailureBeforeHandover(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.dispatchedSeen()
	h.gh.set("completed", "failure")
	h.tick()
	h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
	h.stop()
	h.checkReleased(reasonEndedBeforeAsk, true)
	if _, cancels, _ := h.gh.counts(); cancels != 0 {
		t.Errorf("%d cancels", cancels)
	}
	if len(h.apiary.sent("/outcome")) != 0 {
		t.Errorf("an outcome was posted before the handover")
	}
}

// TestUnknownStep releases a run for another step with retry false, and starts nothing.
func TestUnknownStep(t *testing.T) {
	h := newHarness(t)
	h.apiary.claims = []reply{{status: http.StatusOK, body: claimAnswer(t, "review")}}
	h.start()
	h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
	h.stop()
	h.checkReleased(reasonStep, false)
	if d, _, _ := h.gh.counts(); d != 0 {
		t.Errorf("%d dispatches", d)
	}
}

// TestDispatchFailure releases the run with retry true when the dispatch fails, GitHub
// naming no run among the failures, and never sends the dispatch again.
func TestDispatchFailure(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusNoContent, http.StatusUnprocessableEntity} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			h := newHarness(t)
			h.gh.dispatchStatus = status
			h.start()
			h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
			h.eventually("the next claim", func() bool { return len(h.apiary.sent(routeClaim)) >= 1 && h.claimsSeen() >= 2 })
			h.stop()
			h.checkReleased(reasonNotStarted, true)
			if d, _, _ := h.gh.counts(); d != 1 {
				t.Errorf("the dispatch was sent %d times", d)
			}
			if n := len(h.apiary.sent("/dispatched")); n != 0 {
				t.Errorf("dispatched was sent without a run")
			}
			h.checkNoLeak()
		})
	}
}

func (h *harness) claimsSeen() int {
	h.apiary.mu.Lock()
	defer h.apiary.mu.Unlock()
	return h.apiary.claimsSeen
}

// TestDispatchedRefused stops the job, and releases nothing, when dispatched is refused
// 410 gone or 409 lease_expired; any other failure releases the run with retry true
// too. A job that asks then is refused.
func TestDispatchedRefused(t *testing.T) {
	for _, c := range []struct {
		rep     reply
		release bool
	}{
		{refusalOf(http.StatusGone, "gone"), false},
		{refusalOf(http.StatusConflict, "lease_expired"), false},
		{refusalOf(http.StatusForbidden, "forbidden"), true},
	} {
		t.Run(c.rep.body, func(t *testing.T) {
			h := newHarness(t)
			h.apiary.dispatched = c.rep
			h.gh.set("in_progress", "")
			h.start()
			h.eventually("the cancel", func() bool { _, n, _ := h.gh.counts(); return n == 1 })
			if c.release {
				h.eventually("the release", func() bool { return len(h.apiary.sent("/release")) == 1 })
				h.checkReleased(reasonNotRecorded, true)
			}
			if got := h.job(testDispatch, bearerOf(h.token(nil))); got.status != http.StatusForbidden {
				t.Errorf("the job got %d", got.status)
			}
			h.stop()
			if !c.release && len(h.apiary.sent("/release")) != 0 {
				t.Errorf("the run was released")
			}
			if n := len(h.apiary.sent("/handover")); n != 0 {
				t.Errorf("%d handovers", n)
			}
		})
	}
}

// TestClaimBacksOff waits after a claim refused 409 no_gateway or not signed, a wait
// that doubles, and after a signed 429 its Retry-After.
func TestClaimBacksOff(t *testing.T) {
	h := newHarness(t)
	unsigned := reply{status: http.StatusUnauthorized, unsigned: true}
	h.apiary.claims = []reply{
		refusalOf(http.StatusConflict, "no_gateway"),
		unsigned, unsigned, unsigned, unsigned, unsigned,
		{status: http.StatusTooManyRequests, body: `{"error":"rate_limited"}`, retryAfter: "7"},
	}
	h.start()
	h.eventually("the held claim", func() bool { return h.claimsSeen() == len(h.apiary.claims)+1 })
	h.stop()
	waits := h.clock.waits()
	// After the 409: the first wait. The client sends an unsigned answer's claim again
	// itself, waiting 1, 2, 4 and 8 seconds, then the starter waits twice the first.
	// After the 429: its Retry-After.
	want := []time.Duration{time.Second, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 2 * time.Second, 7 * time.Second}
	var long []time.Duration
	for _, w := range waits {
		if w >= time.Second {
			long = append(long, w)
		}
	}
	if !slices.Equal(long, want) {
		t.Errorf("the waits of a second or more were %v, not %v", long, want)
	}
	if d, _, _ := h.gh.counts(); d != 0 {
		t.Errorf("%d dispatches", d)
	}
}

// TestPassThroughTakesOnlyTheHandover answers 404 to any other path, the handover's
// path with an escape, a query or a trailing slash among them, 405 to another method,
// and 413 to a body over its bound, before any dispatch is looked up.
func TestPassThroughTakesOnlyTheHandover(t *testing.T) {
	st := &starter{dispatches: map[string]*dispatch{}, log: slog.New(slog.DiscardHandler), now: time.Now}
	for _, c := range []struct {
		method, target string
		body           string
		status         int
	}{
		{http.MethodGet, "/v1/dispatches/" + testDispatch + "/handover", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/dispatches/" + testDispatch + "/handover/", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/" + testDispatch + "/handover?x=1", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/" + testDispatch + "/handover?", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/dp_8w3k0q9t2v7m4r6%78/handover", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/DP_8W3K0Q9T2V7M4R6X/handover", "", http.StatusNotFound},
		{http.MethodPost, "//v1/dispatches/" + testDispatch + "/handover", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/" + testDispatch + "/dispatched", "", http.StatusNotFound},
		{http.MethodPost, "/", "", http.StatusNotFound},
		{http.MethodPost, "/v1/dispatches/" + testDispatch + "/handover", strings.Repeat("x", maxJobBody+1), http.StatusRequestEntityTooLarge},
	} {
		req := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
		w := httptest.NewRecorder()
		st.ServeHTTP(w, req)
		if w.Code != c.status {
			t.Errorf("%s %s: %d, not %d", c.method, c.target, w.Code, c.status)
		}
	}
}

// TestInstanceID makes the instance id once, keeps it 0600 in the state directory and
// reads it back; a file holding no id is written anew, and one others may read is
// refused.
func TestInstanceID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	id, err := instanceID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "i_") || len(id) != 24 {
		t.Errorf("the instance id %q is not i_ and 22 characters", id)
	}
	path := filepath.Join(dir, instanceFile)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v %v", info, err)
	}
	if again, err := instanceID(dir); err != nil || again != id {
		t.Errorf("read back %q, %v", again, err)
	}
	if err := os.WriteFile(path, []byte("not an id!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh, err := instanceID(dir); err != nil || fresh == id || !strings.HasPrefix(fresh, "i_") {
		t.Errorf("a file holding no id gave %q, %v", fresh, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := instanceID(dir); err == nil {
		t.Errorf("a file others may read was taken")
	}
}

// TestRunRefusesARepositoryGitHubDoesNotName stops before claiming when the settings'
// repository cannot be found.
func TestRunRefusesARepositoryGitHubDoesNotName(t *testing.T) {
	h := newHarness(t)
	h.settings.Repository = "example-org/elsewhere"
	err := Run(context.Background(), h.settings, Deps{Now: h.clock.Now, Sleep: h.clock.Sleep})
	if !errors.Is(err, github.ErrActionsGone) {
		t.Fatalf("got %v", err)
	}
	if n := len(h.apiary.requests()); n != 0 {
		t.Errorf("%d requests reached Qory Apiary", n)
	}
}
