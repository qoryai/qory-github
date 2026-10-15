package serve

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// pullGitHub is the fake GitHub a pull reads: acme/widgets's comments as GitHub lists a
// repository's, and acme/gadgets, with the issues gadgets, in front of a [fakeGitHub],
// which answers the rest. It records what it is asked for. hold, when set, holds each
// request for acme/widgets's issues until it is closed, and says on held that one
// waits; onComments is called as acme/widgets's comments are read.
type pullGitHub struct {
	gh  *fakeGitHub
	srv *httptest.Server

	mu         sync.Mutex
	comments   []map[string]any
	gadgets    []map[string]any
	requests   []string
	hold, held chan struct{}
	onComments func()
}

func (f *pullGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	hold, held, onComments := f.hold, f.held, f.onComments
	comments, gadgets := f.comments, f.gadgets
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/repos/acme/widgets/issues":
		if hold != nil {
			held <- struct{}{}
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		f.gh.ServeHTTP(w, r)
	case "/repos/acme/widgets/issues/comments":
		if onComments != nil {
			onComments()
		}
		json.NewEncoder(w).Encode(append([]map[string]any{}, comments...))
	case "/repos/acme/gadgets":
		io.WriteString(w, `{"full_name":"acme/gadgets","html_url":"https://github.com/acme/gadgets"}`)
	case "/repos/acme/gadgets/issues":
		json.NewEncoder(w).Encode(append([]map[string]any{}, gadgets...))
	case "/repos/acme/gadgets/issues/comments":
		io.WriteString(w, `[]`)
	default:
		f.gh.ServeHTTP(w, r)
	}
}

// asked are the requests made whose path is path, with their queries.
func (f *pullGitHub) asked(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if p, _, _ := strings.Cut(strings.TrimPrefix(r, "GET "), "?"); p == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *pullGitHub) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// pullClock is a clock a sleep moves on, so nothing waits.
type pullClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pullClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *pullClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return nil
}

// pullStart is the fake clock's time when a test begins.
var pullStart = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// pulling is the adapter whole, as [newWired] makes it, with installation 42 linked and
// reaching acme/widgets, linked too, a GitHub that a pull reads, and a puller on a fake
// clock that never waits, whose rounds spread nothing.
func pulling(t *testing.T) (*wired, *pullGitHub, *puller, *pullClock) {
	t.Helper()
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	f := &pullGitHub{gh: w.gh}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	w.adapter.GitHub = github.Client{API: f.srv.URL}
	clock := &pullClock{t: pullStart}
	w.adapter.now = clock.now
	Link(w.st, 42)
	setReach(w.st, "acme/widgets", 42)
	linkCollection(w.st, "acme/widgets")
	p := &puller{adapter: w.adapter, store: w.st, log: w.adapter.Log, now: clock.now, sleep: clock.sleep, jitter: func(time.Duration) time.Duration { return 0 }}
	return w, f, p, clock
}

// repoComment is a comment on acme/widgets's issue n, as GitHub lists a repository's.
func repoComment(id, n int) map[string]any {
	return map[string]any{
		"id": id, "html_url": "https://github.com/acme/widgets/issues/" + strconv.Itoa(n) + "#issuecomment-" + strconv.Itoa(id),
		"issue_url": "https://api.github.com/repos/acme/widgets/issues/" + strconv.Itoa(n), "body": "Same here.",
		"user": map[string]any{"login": "bob", "type": "User"}, "created_at": "2026-02-01T00:00:00Z", "updated_at": "2026-02-01T00:00:00Z",
	}
}

// closedIssue is acme/widgets's issue n, closed as completed.
func closedIssue(n int) map[string]any {
	is := ghIssue(n, 0)
	is["state"], is["state_reason"] = "closed", "completed"
	return is
}

// sinceOf is the time a request for what changed asks from.
func sinceOf(t *testing.T, request string) time.Time {
	t.Helper()
	_, q, _ := strings.Cut(request, "?")
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, v.Get("since"))
	if err != nil {
		t.Fatalf("%s: %v", request, err)
	}
	return at
}

func markOf(t *testing.T, w *wired) pullMark {
	t.Helper()
	m, err := pulledOf(w.st, "acme/widgets")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestAPullSendsWhatChangedSinceTheLastGoodPull pulls a collection last pulled an hour
// ago and listed today, and checks GitHub is asked for what changed from five minutes
// before that pull, every state's, and Qory Apiary is sent the issues, a closed one
// with its reason, and the comments, as events: no listing, nothing complete. The open
// issues are not listed again, and the pull's start is kept.
func TestAPullSendsWhatChangedSinceTheLastGoodPull(t *testing.T) {
	w, f, p, clock := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, "acme/widgets", pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 1), closedIssue(2)}
	f.comments = []map[string]any{repoComment(11, 1)}
	clock.t = pullStart
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	asked := f.asked("/repos/acme/widgets/issues")
	if len(asked) != 1 || !strings.Contains(asked[0], "state=all") || !strings.Contains(asked[0], "sort=updated") || !sinceOf(t, asked[0]).Equal(last.Add(-5*time.Minute)) {
		t.Errorf("asked for issues %v", asked)
	}
	if c := f.asked("/repos/acme/widgets/issues/comments"); len(c) != 1 || !sinceOf(t, c[0]).Equal(last.Add(-5*time.Minute)) {
		t.Errorf("asked for comments %v", c)
	}
	items := w.apiary.sent(routeItems)
	if len(items) != 1 {
		t.Fatalf("%d items requests", len(items))
	}
	var req contracts.SourceItems
	json.Unmarshal(items[0].raw, &req)
	if req.Listing != nil || len(req.Items) != 2 || req.Items[1].State != github.StateClosed || req.Items[1].StateReason == nil || *req.Items[1].StateReason != "Completed" {
		t.Errorf("sent %s", items[0].raw)
	}
	comments := w.apiary.sent(routeComments)
	if len(comments) != 1 || comments[0].body["item_ref"] != "acme/widgets#1" || comments[0].body["complete"] != nil {
		t.Errorf("sent comments %v", comments)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(last) {
		t.Errorf("kept %+v", m)
	}
}

// TestTheLastGoodTimeMovesOnlyOnSuccess has Qory Apiary answer 502, then GitHub answer
// 502, and checks neither pull moves the time kept and the next asks from the same
// time; then a pull that passes moves it to its start.
func TestTheLastGoodTimeMovesOnlyOnSuccess(t *testing.T) {
	w, f, p, clock := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, "acme/widgets", pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.refuse = func(string, int) (int, string) { return 502, `{"error":"bad_gateway"}` }
	if err := p.pull(context.Background(), "acme/widgets", 42); !IsOutage(err) {
		t.Errorf("err %v", err)
	}
	if m := markOf(t, w); !m.Since.Equal(last) {
		t.Errorf("an outage of Qory Apiary moved the time to %v", m.Since)
	}
	w.apiary.refuse = nil
	w.gh.mu.Lock()
	w.gh.issuesDown = true
	w.gh.mu.Unlock()
	clock.t = pullStart.Add(time.Hour)
	if err := p.pull(context.Background(), "acme/widgets", 42); err == nil {
		t.Error("a pull GitHub answered 502 passed")
	}
	if m := markOf(t, w); !m.Since.Equal(last) {
		t.Errorf("GitHub's 502 moved the time to %v", m.Since)
	}
	w.gh.mu.Lock()
	w.gh.issuesDown = false
	w.gh.mu.Unlock()
	clock.t = pullStart.Add(2 * time.Hour)
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.asked("/repos/acme/widgets/issues") {
		if !sinceOf(t, r).Equal(last.Add(-5 * time.Minute)) {
			t.Errorf("asked %s", r)
		}
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart.Add(2 * time.Hour)) {
		t.Errorf("kept %+v", m)
	}
}

// TestTheDailyListingIsSentAndIsNotComplete pulls a collection listed more than a day
// ago, and checks its open issues are listed as the fill lists them, not complete, and
// the listing's start kept; and that a collection with no pull kept is listed alone.
func TestTheDailyListingIsSentAndIsNotComplete(t *testing.T) {
	w, f, p, _ := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, "acme/widgets", pullMark{Since: last, Listed: pullStart.Add(-25 * time.Hour)})
	w.gh.issues = []map[string]any{ghIssue(1, 0), closedIssue(2), ghIssue(3, 0)}
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	var listings []contracts.SourceItems
	for _, r := range w.apiary.sent(routeItems) {
		var req contracts.SourceItems
		json.Unmarshal(r.raw, &req)
		if req.Listing != nil {
			listings = append(listings, req)
		}
	}
	if len(listings) != 1 || listings[0].Listing.Complete || len(listings[0].Items) != 2 {
		t.Errorf("listed %+v", listings)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("kept %+v", m)
	}

	w.st.Delete(nsPulls, "acme/widgets")
	before := len(f.asked("/repos/acme/widgets/issues"))
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	asked := f.asked("/repos/acme/widgets/issues")[before:]
	if len(asked) != 1 || strings.Contains(asked[0], "since=") || len(f.asked("/repos/acme/widgets/issues/comments")) != 1 {
		t.Errorf("a collection with no pull kept asked %v", asked)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("kept %+v", m)
	}
}

// TestTheFirstPullAfterAFillStartsFromTheFill links a collection through the feed, which
// fills it, and checks the next pull asks for what changed from five minutes before the
// fill began, and does not list again.
func TestTheFirstPullAfterAFillStartsFromTheFill(t *testing.T) {
	w, f, p, clock := pulling(t)
	unlinkCollection(w.st, "acme/widgets")
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("the fill kept %+v", m)
	}
	clock.t = pullStart.Add(time.Hour)
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	asked := f.asked("/repos/acme/widgets/issues")
	if len(asked) != 2 || !sinceOf(t, asked[1]).Equal(pullStart.Add(-5*time.Minute)) {
		t.Errorf("asked %v", asked)
	}
}

// TestAPullAndAFillNeverOverlap holds a fill on GitHub and checks a pull of the same
// collection passes its round without a request; then holds a pull and checks a fill
// waits for it before it reaches GitHub.
func TestAPullAndAFillNeverOverlap(t *testing.T) {
	w, f, p, _ := pulling(t)
	keepPulled(w.st, "acme/widgets", pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	hold := func() chan struct{} {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hold, f.held = make(chan struct{}), make(chan struct{}, 10)
		return f.hold
	}
	release := func(c chan struct{}) {
		f.mu.Lock()
		f.hold = nil
		f.mu.Unlock()
		close(c)
	}

	c := hold()
	filled := make(chan error, 1)
	go func() { filled <- w.adapter.fill(context.Background(), "acme/widgets") }()
	<-f.held
	n := f.count()
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	if f.count() != n || !strings.Contains(w.log.String(), "a fill of the collection runs, so it is not pulled this round") {
		t.Errorf("a pull ran during a fill: %d requests after %d; the log %s", f.count(), n, w.log.String())
	}
	release(c)
	if err := <-filled; err != nil {
		t.Fatal(err)
	}

	c = hold()
	pulled := make(chan error, 1)
	go func() { pulled <- p.pull(context.Background(), "acme/widgets", 42) }()
	<-f.held
	n = f.count()
	go func() { filled <- w.adapter.fill(context.Background(), "acme/widgets") }()
	time.Sleep(100 * time.Millisecond)
	if f.count() != n {
		t.Errorf("a fill reached GitHub during a pull: %d requests after %d", f.count(), n)
	}
	release(c)
	if err := <-pulled; err != nil {
		t.Fatal(err)
	}
	if err := <-filled; err != nil {
		t.Fatal(err)
	}
	if f.count() == n {
		t.Error("the fill never ran")
	}
}

// TestAnUnlinkedCollectionSendsNothing pulls a collection that is not linked, which
// sends nothing and reads nothing; one the feed unlinks while its comments are read,
// which sends none of them; and one Qory Apiary answers 409 collection_not_linked,
// which stops there. None keeps a time.
func TestAnUnlinkedCollectionSendsNothing(t *testing.T) {
	w, f, p, _ := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, "acme/widgets", pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 1)}
	f.comments = []map[string]any{repoComment(11, 1)}
	unlinkCollection(w.st, "acme/widgets")
	if err := p.pull(context.Background(), "acme/widgets", 42); err != nil {
		t.Fatal(err)
	}
	if f.count() != 0 || len(w.apiary.sent(routeItems)) != 0 {
		t.Errorf("a collection not linked was pulled: %d requests", f.count())
	}

	linkCollection(w.st, "acme/widgets")
	f.onComments = func() { unlinkCollection(w.st, "acme/widgets") }
	err := p.pull(context.Background(), "acme/widgets", 42)
	if len(w.apiary.sent(routeItems)) != 1 || len(w.apiary.sent(routeComments)) != 0 {
		t.Errorf("sent %d items and %d comments requests", len(w.apiary.sent(routeItems)), len(w.apiary.sent(routeComments)))
	}
	p.report(context.Background(), slog.String("collection", "acme/widgets"), "pulling the collection failed", err)
	if !strings.Contains(w.log.String(), "the collection is not linked, so its pull stops") {
		t.Errorf("err %v; the log %s", err, w.log.String())
	}

	f.onComments = nil
	linkCollection(w.st, "acme/widgets")
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	if err := p.pull(context.Background(), "acme/widgets", 42); err == nil {
		t.Error("a pull refused 409 passed")
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); ok {
		t.Error("the collection is still linked")
	}
	if len(w.apiary.sent(routeComments)) != 0 {
		t.Error("comments were sent after the 409")
	}
	if m := markOf(t, w); !m.Since.Equal(last) {
		t.Errorf("kept %+v", m)
	}
}

// TestAFailingCollectionDoesNotHoldAnother runs a round of an installation that reaches
// three linked collections: one whose issues GitHub answers 502, one gone, and one that
// passes. It checks the round lists the installation's repositories, pulls the third,
// logs the first's failure and the second's absence, and keeps the third's time alone.
func TestAFailingCollectionDoesNotHoldAnother(t *testing.T) {
	w, _, p, _ := pulling(t)
	for _, ref := range []string{"acme/gone", "acme/gadgets"} {
		setReach(w.st, ref, 42)
		linkCollection(w.st, ref)
	}
	for _, ref := range []string{"acme/widgets", "acme/gone", "acme/gadgets"} {
		keepPulled(w.st, ref, pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	}
	w.gh.issuesDown = true
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	if len(w.apiary.sent(routeCollections)) != 1 {
		t.Errorf("%d collections requests", len(w.apiary.sent(routeCollections)))
	}
	if m, _ := pulledOf(w.st, "acme/gadgets"); !m.Since.Equal(pullStart) {
		t.Errorf("acme/gadgets kept %+v", m)
	}
	if m, _ := pulledOf(w.st, "acme/widgets"); !m.Since.Equal(pullStart.Add(-time.Hour)) {
		t.Errorf("acme/widgets kept %+v", m)
	}
	log := w.log.String()
	if !strings.Contains(log, `"msg":"pulling the collection failed","collection":"acme/widgets"`) ||
		!strings.Contains(log, `"msg":"pulling the collection failed: GitHub answers it is gone, moved or out of the App's reach, and the next round tries again","collection":"acme/gone"`) {
		t.Errorf("the log %s", log)
	}
	if strings.Contains(log, ghToken) {
		t.Error("a token is logged")
	}
}

// TestARoundSpreadsItsCollections runs a round whose collections and installation are
// given moments in the first half of the interval, and checks each waits for the moment
// it was given.
func TestARoundSpreadsItsCollections(t *testing.T) {
	w, _, p, clock := pulling(t)
	setReach(w.st, "acme/gadgets", 42)
	linkCollection(w.st, "acme/gadgets")
	// The collections are read in their keys' order, gadgets first, then the
	// installation.
	moments := []time.Duration{20 * time.Minute, 10 * time.Minute, 5 * time.Minute}
	var spreads []time.Duration
	p.jitter = func(d time.Duration) time.Duration {
		spreads = append(spreads, d)
		m := moments[0]
		moments = moments[1:]
		return m
	}
	var mu sync.Mutex
	var waits []time.Duration
	p.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return clock.sleep(ctx, d)
	}
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	if len(spreads) != 3 || spreads[0] != 30*time.Minute {
		t.Errorf("spread over %v", spreads)
	}
	// The installation at 5 minutes, widgets at 10 and gadgets at 20.
	if len(waits) != 3 || waits[0] != 5*time.Minute || waits[1] != 5*time.Minute || waits[2] != 10*time.Minute {
		t.Errorf("waited %v", waits)
	}
}

// TestTheIntervalComesFromTheStoredSync runs the puller on a fake clock with no
// installation, and checks the rounds: an hour apart with no sync entry, then as the
// feed's sync entries set, 15 minutes at least, a new interval counted from the round
// that began last.
func TestTheIntervalComesFromTheStoredSync(t *testing.T) {
	w, _, p, _ := pulling(t)
	Unlink(w.st, 42)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setSync := func(seconds *int) {
		if err := w.feed.apply(ctx, contracts.Change{Kind: contracts.ChangeSync, Interval: seconds}); err != nil {
			t.Fatal(err)
		}
	}
	var starts []time.Time
	var intervals []time.Duration
	p.began = func(start time.Time, interval time.Duration) {
		starts = append(starts, start)
		intervals = append(intervals, interval)
		switch len(starts) {
		case 1:
			setSync(new(1200))
		case 2:
			setSync(new(60))
		case 3:
			setSync(nil)
		case 4:
			cancel()
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
	var gaps []time.Duration
	for i := 1; i < len(starts); i++ {
		gaps = append(gaps, starts[i].Sub(starts[i-1]))
	}
	if want := []time.Duration{20 * time.Minute, 15 * time.Minute, time.Hour}; len(gaps) != 3 || gaps[0] != want[0] || gaps[1] != want[1] || gaps[2] != want[2] {
		t.Errorf("rounds %v apart, want %v", gaps, want)
	}
	if intervals[0] != time.Hour || intervals[1] != 20*time.Minute {
		t.Errorf("intervals %v", intervals)
	}
}

// TestAStopStopsThePuller runs the puller on a timer, its installation's listing held
// by GitHub, and checks a stop returns at once.
func TestAStopStopsThePuller(t *testing.T) {
	_, f, p, _ := pulling(t)
	p.now, p.sleep = nil, nil
	held := make(chan struct{})
	listing := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/installation/repositories" {
			listing <- struct{}{}
			select {
			case <-held:
			case <-r.Context().Done():
			}
			return
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	defer close(held)
	p.adapter.GitHub = github.Client{API: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()
	<-listing
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
}
