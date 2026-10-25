package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// pullGitHub is the fake GitHub a pull reads: acme/widgets's comments as GitHub lists a
// repository's, and acme/gadgets, with the issues gadgets, in front of a [fakeGitHub],
// which answers the rest. It records what it is asked for. hold, when set, holds each
// request for acme/widgets's issues, by REST or by GraphQL, until it is closed, and says
// on held that one waits; onComments is called as acme/widgets's comments are read.
// unchanged answers that none of acme/widgets's issues changed.
type pullGitHub struct {
	gh  *fakeGitHub
	srv *httptest.Server

	mu         sync.Mutex
	comments   []map[string]any
	gadgets    []map[string]any
	requests   []string
	hold, held chan struct{}
	onComments func()
	unchanged  bool
}

func (f *pullGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	hold, held, onComments := f.hold, f.held, f.onComments
	comments, gadgets := f.comments, f.gadgets
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/repositories/" + widgetsRef + "/issues", "/graphql":
		if hold != nil {
			held <- struct{}{}
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if f.unchanged && r.URL.Path == "/repositories/"+widgetsRef+"/issues" {
			io.WriteString(w, `[]`)
			return
		}
		f.gh.ServeHTTP(w, r)
	case "/repositories/" + widgetsRef + "/issues/comments":
		if onComments != nil {
			onComments()
		}
		json.NewEncoder(w).Encode(append([]map[string]any{}, comments...))
	case "/repositories/" + gadgetsRef:
		io.WriteString(w, `{"id":`+gadgetsRef+`,"full_name":"acme/gadgets","html_url":"https://github.com/acme/gadgets"}`)
	case "/repositories/" + gadgetsRef + "/issues":
		json.NewEncoder(w).Encode(append([]map[string]any{}, gadgets...))
	case "/repositories/" + gadgetsRef + "/issues/comments":
		io.WriteString(w, `[]`)
	default:
		f.gh.ServeHTTP(w, r)
	}
}

// asked are the requests made whose path is path, with their queries, and without
// their method.
func (f *pullGitHub) asked(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		_, r, _ = strings.Cut(r, " ")
		if p, _, _ := strings.Cut(r, "?"); p == path {
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
	grantedLink(w.st, 42, testConnection, linkLive)
	setReach(w.st, refOf("acme/widgets"), 42)
	linkCollection(w.st, refOf("acme/widgets"))
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
	m, err := pulledOf(w.st, refOf("acme/widgets"))
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
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 1), closedIssue(2)}
	f.comments = []map[string]any{repoComment(11, 1)}
	clock.t = pullStart
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	asked := f.asked("/repositories/" + widgetsRef + "/issues")
	if len(asked) != 1 || !strings.Contains(asked[0], "state=all") || !strings.Contains(asked[0], "sort=updated") || !sinceOf(t, asked[0]).Equal(last.Add(-5*time.Minute)) {
		t.Errorf("asked for issues %v", asked)
	}
	if c := f.asked("/repositories/" + widgetsRef + "/issues/comments"); len(c) != 1 || !sinceOf(t, c[0]).Equal(last.Add(-5*time.Minute)) {
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
	if len(comments) != 1 || comments[0].body["item_ref"] != itemOf("acme/widgets", 1) || comments[0].body["complete"] != nil {
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
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.refuse = func(string, int) (int, string) { return 502, `{"error":"bad_gateway"}` }
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); !IsOutage(err) {
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
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err == nil {
		t.Error("a pull GitHub answered 502 passed")
	}
	if m := markOf(t, w); !m.Since.Equal(last) {
		t.Errorf("GitHub's 502 moved the time to %v", m.Since)
	}
	w.gh.mu.Lock()
	w.gh.issuesDown = false
	w.gh.mu.Unlock()
	clock.t = pullStart.Add(2 * time.Hour)
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.asked("/repositories/" + widgetsRef + "/issues") {
		if !sinceOf(t, r).Equal(last.Add(-5 * time.Minute)) {
			t.Errorf("asked %s", r)
		}
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart.Add(2 * time.Hour)) {
		t.Errorf("kept %+v", m)
	}
}

// pathsOf are the requests' methods and paths, without their queries, but for the
// App's and its token's, under /app/, in order.
func (f *pullGitHub) pathsOf() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if p, _, _ := strings.Cut(r, "?"); !strings.Contains(p, " /app/") {
			out = append(out, p)
		}
	}
	return out
}

// TestAPullListsByTheNameItReadOnce pulls a collection whose daily listing is due: the
// read of what changed reads the repository by its id once, and the listing asks
// GraphQL for the name that read gave, with no second read; and a pull of a collection
// with no pull kept, which reads no change, reads the repository by its id once and then
// lists. No request names the repository by owner/name.
func TestAPullListsByTheNameItReadOnce(t *testing.T) {
	w, f, p, _ := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, widgetsRef, pullMark{Since: last, Listed: pullStart.Add(-25 * time.Hour)})
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	if err := p.pull(context.Background(), widgetsRef, 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	repo := "/repositories/" + widgetsRef
	want := []string{"GET " + repo, "GET " + repo + "/issues", "GET " + repo + "/issues/comments", "POST /graphql"}
	if got := f.pathsOf(); !slices.Equal(got, want) {
		t.Errorf("GitHub was asked %v, want %v", got, want)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("kept %+v", m)
	}

	w.st.Delete(nsPulls, widgetsRef)
	f.mu.Lock()
	f.requests = nil
	f.mu.Unlock()
	if err := p.pull(context.Background(), widgetsRef, 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	if got, want := f.pathsOf(), []string{"GET " + repo, "POST /graphql"}; !slices.Equal(got, want) {
		t.Errorf("a first pull asked %v, want %v", got, want)
	}
	w.gh.mu.Lock()
	asked := slices.Clone(w.gh.gqlAsked)
	w.gh.mu.Unlock()
	if !slices.Equal(asked, []string{"acme/widgets", "acme/widgets"}) {
		t.Errorf("GraphQL was asked for %v", asked)
	}
}

// TestAPullWhoseNameNamesAnotherRepositoryListsAgainLater pulls a collection whose
// daily listing is due while GraphQL answers, for the name read by the id, a repository
// whose id is another, one with no id, or NOT_FOUND, no repository by that name: what
// changed is sent, as events, the listing sends no part, and the pull fails with an
// error that is no repository gone and keeps no time, so the next round reads the name
// and lists again.
func TestAPullWhoseNameNamesAnotherRepositoryListsAgainLater(t *testing.T) {
	for _, id := range []any{gadgetsRef, nil, "not found"} {
		w, _, p, _ := pulling(t)
		mark := pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart.Add(-25 * time.Hour)}
		keepPulled(w.st, widgetsRef, mark)
		w.gh.issues = []map[string]any{ghIssue(1, 0)}
		if id == "not found" {
			w.gh.gqlNotFound = true
		} else {
			w.gh.gqlIDSet, w.gh.gqlID = true, id
		}
		err := p.pull(context.Background(), widgetsRef, 42, &listedRepositories{})
		if err == nil || errors.Is(err, github.ErrRepositoryGone) {
			t.Errorf("%v: err %v", id, err)
		}
		if parts := listingParts(w); len(parts) != 0 {
			t.Errorf("%v: listed %+v", id, parts)
		}
		if sent := w.apiary.sent(routeItems); len(sent) != 1 {
			t.Errorf("%v: %d items requests, want what changed alone", id, len(sent))
		} else {
			var req contracts.SourceItems
			json.Unmarshal(sent[0].raw, &req)
			if req.Listing != nil || req.CollectionRef != widgetsRef || len(req.Items) != 1 || req.Items[0].Ref != itemOf("acme/widgets", 1) {
				t.Errorf("%v: sent %s", id, sent[0].raw)
			}
		}
		if m := markOf(t, w); m != mark {
			t.Errorf("%v: kept %+v", id, m)
		}
	}
}

// TestTheDailyListingIsSentAndIsComplete pulls a collection listed more than a day
// ago, and checks its open issues are listed as the fill lists them, by GraphQL's
// cursor, in one part that says the listing is complete, and the listing's start kept;
// and that a collection with no pull kept is listed alone.
func TestTheDailyListingIsSentAndIsComplete(t *testing.T) {
	w, f, p, _ := pulling(t)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: last, Listed: pullStart.Add(-25 * time.Hour)})
	w.gh.issues = []map[string]any{ghIssue(1, 0), closedIssue(2), ghIssue(3, 0)}
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	listings := listingParts(w)
	if len(listings) != 1 || !listings[0].Listing.Complete || listings[0].Listing.Part != 1 || len(listings[0].Items) != 2 {
		t.Errorf("listed %+v", listings)
	}
	if len(f.asked("/graphql")) != 1 {
		t.Errorf("asked GraphQL %d times", len(f.asked("/graphql")))
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("kept %+v", m)
	}

	w.st.Delete(nsPulls, widgetsRef)
	before, rest := len(f.asked("/graphql")), len(f.asked("/repositories/"+widgetsRef+"/issues"))
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	if len(f.asked("/graphql")) != before+1 || len(f.asked("/repositories/"+widgetsRef+"/issues")) != rest || len(f.asked("/repositories/"+widgetsRef+"/issues/comments")) != 1 {
		t.Errorf("a collection with no pull kept asked %v", f.requests)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("kept %+v", m)
	}
}

// listingParts are the items requests sent to Qory Apiary that are a listing's parts.
func listingParts(w *wired) []contracts.SourceItems {
	var out []contracts.SourceItems
	for _, r := range w.apiary.sent(routeItems) {
		var req contracts.SourceItems
		json.Unmarshal(r.raw, &req)
		if req.Listing != nil {
			out = append(out, req)
		}
	}
	return out
}

// TestATokenServesTheOneRepositoryItWasMintedFor pulls acme/widgets and then
// acme/gadgets, two repositories the installation 42 reaches, while GitHub answers each
// mint with a new token, and then pulls acme/widgets again. Each repository is minted a
// token, with repository_ids its id alone, every request by a repository's id carries
// the token minted for it and never the other's, and the second pull of acme/widgets
// takes the token kept for it and mints none. The key serve keeps a token under names
// the repository's id, so a token minted for one repository never serves another.
func TestATokenServesTheOneRepositoryItWasMintedFor(t *testing.T) {
	w, f, p, _ := pulling(t)
	setReach(w.st, gadgetsRef, 42)
	linkCollection(w.st, gadgetsRef)
	last := pullStart.Add(-time.Hour)
	keepPulled(w.st, widgetsRef, pullMark{Since: last, Listed: last})
	keepPulled(w.st, gadgetsRef, pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	var mu sync.Mutex
	var mints []string
	// minted is the repository each token was minted for, by the token, and carried the
	// tokens each repository's requests carried, by the repository's id.
	minted := map[string]string{}
	carried := map[string][]string{}
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens" {
			b, _ := io.ReadAll(r.Body)
			var body struct {
				RepositoryIDs []int64 `json:"repository_ids"`
			}
			json.Unmarshal(b, &body)
			mu.Lock()
			mints = append(mints, string(b))
			tok := "ghs_minted-" + strconv.Itoa(len(mints))
			if len(body.RepositoryIDs) == 1 {
				minted[tok] = strconv.FormatInt(body.RepositoryIDs[0], 10)
			}
			mu.Unlock()
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusCreated)
			io.WriteString(rw, `{"token":"`+tok+`","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/repositories/"); ok {
			id, _, _ := strings.Cut(rest, "/")
			mu.Lock()
			carried[id] = append(carried[id], strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			mu.Unlock()
		}
		f.ServeHTTP(rw, r)
	}))
	t.Cleanup(front.Close)
	w.adapter.GitHub = github.Client{API: front.URL}
	for _, ref := range []string{widgetsRef, gadgetsRef, widgetsRef} {
		if err := p.pull(context.Background(), ref, 42, &listedRepositories{}); err != nil {
			t.Fatalf("pulling %s: %v", ref, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		`{"permissions":{"issues":"read"},"repository_ids":[` + widgetsRef + `]}`,
		`{"permissions":{"issues":"read"},"repository_ids":[` + gadgetsRef + `]}`,
	}
	if !slices.Equal(mints, want) {
		t.Errorf("mints\n%s\nwant\n%s", strings.Join(mints, "\n"), strings.Join(want, "\n"))
	}
	for _, ref := range []string{widgetsRef, gadgetsRef} {
		if len(carried[ref]) == 0 {
			t.Errorf("no request by %s's id", ref)
		}
		for _, tok := range carried[ref] {
			if minted[tok] != ref {
				t.Errorf("a request by %s's id carried %q, minted for %q", ref, tok, minted[tok])
			}
		}
	}
}

// TestTheFirstPullAfterAFillStartsFromTheFill links a collection through the feed, which
// fills it, and checks the next pull asks for what changed from five minutes before the
// fill began, and does not list again.
func TestTheFirstPullAfterAFillStartsFromTheFill(t *testing.T) {
	w, f, p, clock := pulling(t)
	unlinkCollection(w.st, refOf("acme/widgets"))
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("the fill kept %+v", m)
	}
	clock.t = pullStart.Add(time.Hour)
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	asked := f.asked("/repositories/" + widgetsRef + "/issues")
	if len(asked) != 1 || !sinceOf(t, asked[0]).Equal(pullStart.Add(-5*time.Minute)) || len(f.asked("/graphql")) != 1 {
		t.Errorf("asked %v", f.requests)
	}
}

// TestAPullAndAFillNeverOverlap holds a fill on GitHub and checks a pull of the same
// collection passes its round without a request; then holds a pull and checks a fill
// waits for it before it reaches GitHub.
func TestAPullAndAFillNeverOverlap(t *testing.T) {
	w, f, p, _ := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
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
	go func() { filled <- w.adapter.fill(context.Background(), refOf("acme/widgets")) }()
	<-f.held
	n := f.count()
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	if f.count() != n || !strings.Contains(w.log.String(), "a fill or another pull of the collection runs, so it is not pulled this round") {
		t.Errorf("a pull ran during a fill: %d requests after %d; the log %s", f.count(), n, w.log.String())
	}
	release(c)
	if err := <-filled; err != nil {
		t.Fatal(err)
	}

	c = hold()
	pulled := make(chan error, 1)
	go func() { pulled <- p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}) }()
	<-f.held
	n = f.count()
	go func() { filled <- w.adapter.fill(context.Background(), refOf("acme/widgets")) }()
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
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: last, Listed: last})
	w.gh.issues = []map[string]any{ghIssue(1, 1)}
	f.comments = []map[string]any{repoComment(11, 1)}
	unlinkCollection(w.st, refOf("acme/widgets"))
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err != nil {
		t.Fatal(err)
	}
	if f.count() != 0 || len(w.apiary.sent(routeItems)) != 0 {
		t.Errorf("a collection not linked was pulled: %d requests", f.count())
	}

	linkCollection(w.st, refOf("acme/widgets"))
	f.onComments = func() { unlinkCollection(w.st, refOf("acme/widgets")) }
	err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{})
	if len(w.apiary.sent(routeItems)) != 1 || len(w.apiary.sent(routeComments)) != 0 {
		t.Errorf("sent %d items and %d comments requests", len(w.apiary.sent(routeItems)), len(w.apiary.sent(routeComments)))
	}
	p.report(context.Background(), slog.String("collection", widgetsRef), "pulling the collection", err)
	if !strings.Contains(w.log.String(), "the collection is not linked, so its pull stops") {
		t.Errorf("err %v; the log %s", err, w.log.String())
	}

	f.onComments = nil
	linkCollection(w.st, refOf("acme/widgets"))
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	if err := p.pull(context.Background(), refOf("acme/widgets"), 42, &listedRepositories{}); err == nil {
		t.Error("a pull refused 409 passed")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
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
	for _, ref := range refsOf("acme/gone", "acme/gadgets") {
		setReach(w.st, ref, 42)
		linkCollection(w.st, ref)
	}
	for _, ref := range refsOf("acme/widgets", "acme/gone", "acme/gadgets") {
		keepPulled(w.st, ref, pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	}
	w.gh.issuesDown = true
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	if len(w.apiary.sent(routeCollections)) != 1 {
		t.Errorf("%d collections requests", len(w.apiary.sent(routeCollections)))
	}
	if m, _ := pulledOf(w.st, refOf("acme/gadgets")); !m.Since.Equal(pullStart) {
		t.Errorf("acme/gadgets kept %+v", m)
	}
	if m, _ := pulledOf(w.st, refOf("acme/widgets")); !m.Since.Equal(pullStart.Add(-time.Hour)) {
		t.Errorf("acme/widgets kept %+v", m)
	}
	log := w.log.String()
	if !strings.Contains(log, `"msg":"pulling the collection failed","collection":"`+widgetsRef+`"`) ||
		!strings.Contains(log, `"msg":"pulling the collection failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again","collection":"`+refOf("acme/gone")+`"`) {
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
	setReach(w.st, refOf("acme/gadgets"), 42)
	linkCollection(w.st, refOf("acme/gadgets"))
	// The collections are read in their keys' order, their ids', widgets first, then
	// gadgets, then the installation.
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
	// The installation at 5 minutes, gadgets at 10 and widgets at 20.
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

// TestAPullThatKeepsFailingIsLoggedOnceAndOnceMoreAfterADay has GitHub answer 502 to a
// collection's pulls round after round, and checks the failure is logged at the first
// round and not at the rounds after it, once more when it has failed for a day, and not
// after that; then that a pull that passes forgets it, so the next failure is logged
// again.
func TestAPullThatKeepsFailingIsLoggedOnceAndOnceMoreAfterADay(t *testing.T) {
	w, _, p, clock := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	down := func(on bool) {
		w.gh.mu.Lock()
		w.gh.issuesDown = on
		w.gh.mu.Unlock()
	}
	round := func(at time.Duration) {
		clock.mu.Lock()
		clock.t = pullStart.Add(at)
		clock.mu.Unlock()
		p.installationRound(context.Background(), 42, []pullTarget{{ref: widgetsRef}}, clock.now(), 0)
	}
	lines := func(want string) int { return strings.Count(w.log.String(), want) }
	const failed = `"msg":"pulling the collection failed","collection":"` + widgetsRef + `"`
	const day = `"msg":"pulling the collection has failed for a day, and the next round tries again","collection":"` + widgetsRef + `"`
	down(true)
	for _, at := range []time.Duration{0, time.Hour, 23 * time.Hour} {
		round(at)
	}
	if lines(failed) != 1 || lines(day) != 0 {
		t.Fatalf("the first day: the log %s", w.log.String())
	}
	for _, at := range []time.Duration{24 * time.Hour, 25 * time.Hour, 49 * time.Hour} {
		round(at)
	}
	if lines(failed) != 1 || lines(day) != 1 {
		t.Fatalf("after a day: the log %s", w.log.String())
	}
	down(false)
	round(50 * time.Hour)
	if m := markOf(t, w); !m.Since.Equal(pullStart.Add(50 * time.Hour)) {
		t.Fatalf("kept %+v", m)
	}
	down(true)
	round(51 * time.Hour)
	if lines(failed) != 2 || lines(day) != 1 {
		t.Errorf("after a pull that passed: the log %s", w.log.String())
	}
}

// TestTheDroppedLinesAreCountedAsThePullRoundsFailures logs a failed read of the store
// and a failed pull within pullFailEvery, and checks the second is held back and
// counted as a failure of the pull rounds.
func TestTheDroppedLinesAreCountedAsThePullRoundsFailures(t *testing.T) {
	w, _, p, _ := pulling(t)
	p.failed("reading the linked collections", errors.New("the store failed"))
	p.failed("pulling the collection failed", errors.New("GitHub answered 502"), slog.String("collection", widgetsRef))
	p.failLog().stop()
	log := w.log.String()
	if strings.Contains(log, "GitHub answered 502") || !strings.Contains(log, `"msg":"failures of the pull rounds dropped","failed_dropped":1`) {
		t.Errorf("the log %s", log)
	}
}

// TestTheSyncIntervalIsADayAtMost has the feed set an interval longer than a day, and
// the store hold one, and checks each is taken as a day, the contract's maximum.
func TestTheSyncIntervalIsADayAtMost(t *testing.T) {
	w, _, p, _ := pulling(t)
	if err := w.feed.apply(context.Background(), contracts.Change{Kind: contracts.ChangeSync, Interval: new(200000)}); err != nil {
		t.Fatal(err)
	}
	if b, _ := w.st.Get(nsAdapter, keySyncInterval); string(b) != "86400" {
		t.Errorf("kept %q", b)
	}
	if d := p.interval(); d != 24*time.Hour {
		t.Errorf("the interval %v", d)
	}
	if err := w.st.Put(nsAdapter, keySyncInterval, []byte("999999"), 0); err != nil {
		t.Fatal(err)
	}
	if d := p.interval(); d != 24*time.Hour {
		t.Errorf("the interval kept as 999999 seconds is %v", d)
	}
}

// listingCallers are the two callers of the listing of open issues: the fill, for a
// collection with no pull kept, and the daily listing, for one last listed more than a
// day ago, each on the rig [pulling] makes. GitHub's pacer for the installation runs on
// the rig's clock, so a rate limit waits for nothing.
var listingCallers = []struct {
	name string
	run  func(ctx context.Context, w *wired, p *puller) error
}{
	{"the fill", func(ctx context.Context, w *wired, _ *puller) error {
		return w.adapter.fill(ctx, refOf("acme/widgets"))
	}},
	{"the daily listing", func(ctx context.Context, w *wired, p *puller) error {
		keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart.Add(-25 * time.Hour)})
		return p.pull(ctx, refOf("acme/widgets"), 42, &listedRepositories{})
	}},
}

// listingRig is the rig [pulling] makes, with GitHub's pacer on its clock and n open
// issues of acme/widgets, none of which changed since the last pull.
func listingRig(t *testing.T, n int) (*wired, *puller) {
	t.Helper()
	w, f, p, clock := pulling(t)
	f.unchanged = true
	w.adapter.pacers = map[int64]*github.Pacer{42: {Now: clock.now, Sleep: clock.sleep}}
	for i := 1; i <= n; i++ {
		w.gh.issues = append(w.gh.issues, ghIssue(i, 0))
	}
	return w, p
}

// partsOf are the listing's parts as their sizes and whether each says complete.
func partsOf(w *wired) string {
	var out []string
	for _, req := range listingParts(w) {
		out = append(out, strconv.Itoa(len(req.Items))+" "+strconv.FormatBool(req.Listing.Complete))
	}
	return strings.Join(out, ", ")
}

// TestTheFillAndTheDailyListingPassTheListingThrough lists 250 and 200 open issues by
// the fill and by the daily listing, and checks each sends the listing's parts as it
// makes them, the last alone complete, a full one for 200; and that with an issue
// Qory Apiary would refuse, skipped, no part says complete.
func TestTheFillAndTheDailyListingPassTheListingThrough(t *testing.T) {
	for _, c := range listingCallers {
		for _, tc := range []struct {
			n    int
			skip bool
			want string
		}{
			{250, false, "100 false, 100 false, 50 true"},
			{200, false, "100 false, 100 true"},
			{250, true, "100 false, 100 false, 49 false"},
		} {
			w, p := listingRig(t, tc.n)
			if tc.skip {
				w.gh.issues[0]["title"] = ""
			}
			if err := c.run(context.Background(), w, p); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got := partsOf(w); got != tc.want {
				t.Errorf("%s, %d, skipped %v: parts %s, want %s", c.name, tc.n, tc.skip, got, tc.want)
			}
			if m := markOf(t, w); !m.Listed.Equal(pullStart) {
				t.Errorf("%s: kept %+v", c.name, m)
			}
		}
	}
}

// TestAListingThatFailsOrStopsNeverSaysComplete lists 150 open issues, 100 to a page,
// by the fill and by the daily listing, and stops each on the second page: GitHub
// answers 502, GraphQL answers errors in a 200, GraphQL's rate limit holds through every
// try, the context is cancelled, or its deadline passes. It checks each returns its
// error, sends the first page's items as a part that does not say complete, sends no
// part that does, and keeps no listing's start, so the next pull lists again.
func TestAListingThatFailsOrStopsNeverSaysComplete(t *testing.T) {
	hold := func(r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}
	for _, tc := range []struct {
		name string
		fail string
		ctx  func(w *wired) (context.Context, context.CancelFunc)
		err  string
		is   error
	}{
		{name: "GitHub answers 502", fail: "502", err: "GitHub answered 502"},
		{name: "GraphQL's errors in a 200", fail: "errors", err: "GitHub answered an error, SERVICE_UNAVAILABLE"},
		{name: "a rate limit that holds", fail: "limited", err: "GitHub answered an error, RATE_LIMITED"},
		{name: "a context cancelled", ctx: func(w *wired) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			w.gh.onPage = func(page int, r *http.Request) {
				if page == 2 {
					// The page is answered once the listing gave up on it.
					cancel()
					hold(r)
				}
			}
			return ctx, cancel
		}, is: context.Canceled},
		{name: "a deadline passed", ctx: func(w *wired) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			w.gh.onPage = func(page int, r *http.Request) {
				if page == 2 {
					hold(r)
				}
			}
			return ctx, cancel
		}, is: context.DeadlineExceeded},
	} {
		for _, c := range listingCallers {
			w, p := listingRig(t, 150)
			if tc.fail != "" {
				w.gh.gqlFailOn, w.gh.gqlFail = 2, tc.fail
			}
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx(w)
			}
			err := c.run(ctx, w, p)
			cancel()
			if err == nil || tc.err != "" && !strings.Contains(err.Error(), tc.err) || tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("%s, %s: err %v", tc.name, c.name, err)
			}
			if got := partsOf(w); got != "100 false" {
				t.Errorf("%s, %s: parts %s", tc.name, c.name, got)
			}
			if m := markOf(t, w); !m.Listed.Before(pullStart) {
				t.Errorf("%s, %s: kept %+v", tc.name, c.name, m)
			}
		}
	}
}

// TestARepositoryWithNoOpenIssueSendsOneEmptyCompletePart lists a repository whose one
// issue is closed, by the fill and by the daily listing, and checks exactly one part is
// sent, without items, that says the listing is complete, and the listing's start is
// kept; and that when GitHub's answer to the first page fails, 502, GraphQL's errors or
// a rate limit that holds, nothing is sent, no line says a listing was sent, and the
// listing's start is not kept.
func TestARepositoryWithNoOpenIssueSendsOneEmptyCompletePart(t *testing.T) {
	for _, c := range listingCallers {
		for _, fail := range []string{"", "502", "errors", "limited"} {
			w, p := listingRig(t, 0)
			w.gh.issues = []map[string]any{closedIssue(1)}
			if fail != "" {
				w.gh.gqlFailOn, w.gh.gqlFail = 1, fail
			}
			err := c.run(context.Background(), w, p)
			want, listed := "0 true", pullStart
			if fail != "" {
				want, listed = "", pullStart.Add(-25*time.Hour)
				if err == nil {
					t.Errorf("%s, %s: no error", c.name, fail)
				}
				if log := w.log.String(); strings.Contains(log, "listing") || strings.Contains(log, "listed") {
					t.Errorf("%s, %s: the log %s", c.name, fail, log)
				}
			} else if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got := partsOf(w); got != want {
				t.Errorf("%s, %q: parts %s, want %s", c.name, fail, got, want)
			}
			if c.name == "the fill" && fail != "" {
				listed = time.Time{}
			}
			if m := markOf(t, w); !m.Listed.Equal(listed) {
				t.Errorf("%s, %q: kept %+v", c.name, fail, m)
			}
		}
	}
}

// TestAPullOfARepositoryWithIssuesOffMovesItsMark pulls acme/widgets with Issues turned
// off: read so by its id, has_issues false; turned off after that read, so GitHub
// answers its issues 410; and with no pull kept, so the pull reads the name alone. It
// checks each pull passes without asking for what it need not, sends Qory Apiary
// nothing, no listing's part among it, logs the lines that say why, and keeps its start
// as both the pull's and the listing's.
func TestAPullOfARepositoryWithIssuesOffMovesItsMark(t *testing.T) {
	repo := "/repositories/" + widgetsRef
	changed := "skipped the issues and comments of " + widgetsRef + ": Issues are turned off for the repository on GitHub"
	gone := "skipped the issues and comments of " + widgetsRef + ": GitHub answers 410, as it does once Issues are turned off for the repository"
	open := "skipped the open issues of " + widgetsRef + ": Issues are turned off for the repository on GitHub"
	for _, tc := range []struct {
		name                  string
		issuesOff, issuesGone bool
		kept                  bool
		asked, lines          []string
	}{
		{"has_issues false", true, true, true, []string{"GET " + repo, "POST /graphql"}, []string{changed, open}},
		{"Issues turned off after the read", false, true, true, []string{"GET " + repo, "GET " + repo + "/issues", "POST /graphql"}, []string{gone, open}},
		{"no pull kept", true, true, false, []string{"GET " + repo}, []string{open}},
	} {
		w, f, p, _ := pulling(t)
		if tc.kept {
			keepPulled(w.st, widgetsRef, pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart.Add(-25 * time.Hour)})
		}
		w.gh.issues = []map[string]any{ghIssue(1, 1)}
		w.gh.issuesOff, w.gh.issuesGone = tc.issuesOff, tc.issuesGone
		if err := p.pull(context.Background(), widgetsRef, 42, &listedRepositories{}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := f.pathsOf(); !slices.Equal(got, tc.asked) {
			t.Errorf("%s: GitHub was asked %v, want %v", tc.name, got, tc.asked)
		}
		if items, comments := w.apiary.sent(routeItems), w.apiary.sent(routeComments); len(items) != 0 || len(comments) != 0 {
			t.Errorf("%s: sent %d items requests and %d comments requests", tc.name, len(items), len(comments))
		}
		log := w.log.String()
		for _, line := range tc.lines {
			if strings.Count(log, `"msg":"`+line+`"`) != 1 {
				t.Errorf("%s: the log %s", tc.name, log)
			}
		}
		if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
			t.Errorf("%s: kept %+v", tc.name, m)
		}
	}
}

// TestAFillOfARepositoryWithIssuesOffKeepsItsMark fills acme/widgets with Issues turned
// off, read so by its id, and turned off after that read, so GraphQL answers
// hasIssuesEnabled false. It checks each fill passes, sends Qory Apiary nothing, no
// listing's part among it, logs the line that says why, and keeps its start.
func TestAFillOfARepositoryWithIssuesOffKeepsItsMark(t *testing.T) {
	repo := "/repositories/" + widgetsRef
	open := "skipped the open issues of " + widgetsRef + ": Issues are turned off for the repository on GitHub"
	for _, tc := range []struct {
		name      string
		issuesOff bool
		asked     []string
	}{
		{"has_issues false", true, []string{"GET " + repo}},
		{"Issues turned off after the read", false, []string{"GET " + repo, "POST /graphql"}},
	} {
		w, f, _, _ := pulling(t)
		w.gh.issues = []map[string]any{ghIssue(1, 1)}
		w.gh.issuesOff, w.gh.issuesGone = tc.issuesOff, true
		if err := w.adapter.fill(context.Background(), widgetsRef); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := f.pathsOf(); !slices.Equal(got, tc.asked) {
			t.Errorf("%s: GitHub was asked %v, want %v", tc.name, got, tc.asked)
		}
		if items, comments := w.apiary.sent(routeItems), w.apiary.sent(routeComments); len(items) != 0 || len(comments) != 0 {
			t.Errorf("%s: sent %d items requests and %d comments requests", tc.name, len(items), len(comments))
		}
		if log := w.log.String(); strings.Count(log, `"msg":"`+open+`"`) != 1 {
			t.Errorf("%s: the log %s", tc.name, log)
		}
		if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
			t.Errorf("%s: kept %+v", tc.name, m)
		}
	}
}

// listingMints are the mints of a listing token the fake answered: those that ask for
// metadata read and name no repository.
func (f *fakeGitHub) listingMints() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.mints {
		if strings.Contains(m, `"metadata":"read"`) && !strings.Contains(m, "repository_ids") {
			n++
		}
	}
	return n
}

// TestEachRoundMintsANewListingToken keeps a listing token for 42 that expires in two
// hours, and runs two rounds an hour apart, each well within its life: each round's
// listing mints a new listing token, so the installation is checked with GitHub each
// round, and the token kept before is never sent.
func TestEachRoundMintsANewListingToken(t *testing.T) {
	w, _, p, clock := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	w.adapter.mu.Lock()
	w.adapter.tokens = map[string]github.InstallationToken{"42 0 ": {Token: "minted-before", ExpiresAt: time.Now().Add(2 * time.Hour)}}
	w.adapter.mu.Unlock()
	for _, at := range []time.Duration{0, time.Hour} {
		clock.mu.Lock()
		clock.t = pullStart.Add(at)
		clock.mu.Unlock()
		p.round(context.Background(), clock.now(), time.Hour)
		p.rounds.Wait()
	}
	if n := w.gh.listingMints(); n != 2 {
		t.Errorf("%d listing tokens minted, want 2", n)
	}
	w.gh.mu.Lock()
	auth := append([]string(nil), w.gh.listAuth...)
	w.gh.mu.Unlock()
	if len(auth) != 2 {
		t.Fatalf("%d listings", len(auth))
	}
	for _, a := range auth {
		if strings.Contains(a, "minted-before") || !strings.Contains(a, ghToken) {
			t.Errorf("a listing sent %q", a)
		}
	}
	if w.gh.listings() != 2 {
		t.Errorf("%d listings", w.gh.listings())
	}
}

// TestAListingTokenMintedAcrossTheDropIsNotKept holds a mint of the installation's
// listing token in flight while the round's drop of it lands: the token is handed to
// the request that minted it, and not kept, so the next request mints again; a token
// minted after the drop is kept, and a repository's token kept before the drop stays.
func TestAListingTokenMintedAcrossTheDropIsNotKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	h := holdMint{once: &sync.Once{}, minting: make(chan struct{}), release: make(chan struct{})}
	w.adapter.GitHub.HTTP = &http.Client{Transport: h}
	w.adapter.mu.Lock()
	w.adapter.tokens = map[string]github.InstallationToken{"42 " + widgetsRef + " read": {Token: "kept", ExpiresAt: time.Now().Add(time.Hour)}}
	w.adapter.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		tok, err := w.adapter.token(context.Background(), 42, 0, "")
		if err == nil && tok != ghToken {
			err = errors.New("the token minted in flight is " + tok)
		}
		done <- err
	}()
	<-h.minting
	w.adapter.forgetListingToken(42)
	close(h.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	kept := func() []string {
		w.adapter.mu.Lock()
		defer w.adapter.mu.Unlock()
		var keys []string
		for k := range w.adapter.tokens {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return keys
	}
	if got := kept(); !slices.Equal(got, []string{"42 " + widgetsRef + " read"}) {
		t.Errorf("kept %v, the listing token minted across the drop among them", got)
	}
	for range 2 {
		if _, err := w.adapter.token(context.Background(), 42, 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.gh.listingMints(); n != 2 {
		t.Errorf("%d listing tokens minted, want 2", n)
	}
	if got := kept(); !slices.Equal(got, []string{"42 0 ", "42 " + widgetsRef + " read"}) {
		t.Errorf("kept %v", got)
	}
}

// setGitHub sets fields of the fake GitHub under its lock.
func setGitHub(f *fakeGitHub, set func(f *fakeGitHub)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	set(f)
}

// repositoryReads are the requests the fake GitHub answered under /repositories/.
func (f *fakeGitHub) repositoryReads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if _, path, _ := strings.Cut(r, " "); strings.HasPrefix(path, "/repositories/") {
			out = append(out, r)
		}
	}
	return out
}

// endedLine is the line of a round that ended the installation 42, linked to
// testConnection.
const endedLine = `"msg":"GitHub returns 404 for the installation under the App's token in two rounds in a row, as for an installation deleted, so serve handles it as deleted","installation":42,"connection":"` + testConnection + `"`

// goneOnceLine is the line of a round that met GitHub's first 404 in a row to the
// installation 42's check.
const goneOnceLine = `"level":"WARN","msg":"GitHub returns 404 for the installation under the App's token, as for an installation deleted, so nothing more of it is pulled this round, and a 404 in the next round handles it as deleted unless GitHub shows the installation in between","installation":42,"error":"`

// goneOnceError is goneOnceLine with the error of a listing whose check GitHub
// answered 404.
const goneOnceError = goneOnceLine + `listing the installation's repositories: the installation token: GitHub refuses to mint the installation token: GitHub answers 404 for the installation under the App's token, as for an installation deleted"`

// keptLinked checks the round changed nothing of the installation 42: no grant end and
// no disconnect was sent, and its link and acme/widgets's records stay.
func keptLinked(t *testing.T, w *wired) {
	t.Helper()
	if n := len(w.apiary.sent(routeGrantsEnd)) + len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d grant ends and disconnects", n)
	}
	if l, ok, _ := linkOf(w.st, 42); !ok || l.State != linkLive {
		t.Error("the link changed")
	}
	if inst, ok, _ := reachOf(w.st, refOf("acme/widgets")); !ok || inst != 42 {
		t.Error("the repository's installation is dropped")
	}
	if ok, _ := wasDeleted(w.st, 42); ok {
		t.Error("the installation is kept as deleted")
	}
}

// TestTwoRoundsGitHubAnswers404ForTheInstallationEndItsGrant has the check of the
// installation 42 return 404 under the App's token, and runs rounds. The first
// changes nothing, pulls nothing of 42 and logs that it met a first 404. The second:
// one POST /v1/grants/end names 42's connection and grant, the link, the repository's
// records, the collection's link and its pull mark are dropped, GitHub's deletion is
// kept, the adapter's memory holds nothing of 42, no collection is pulled, a line says
// so, and the puller forgets the 404s it counted. A third round sends nothing more.
func TestTwoRoundsGitHubAnswers404ForTheInstallationEndItsGrant(t *testing.T) {
	w, _, p, _ := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	keptLinked(t, w)
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
		t.Error("the collection is unlinked after one 404")
	}
	if n := w.gh.repositoryMints(); n != 0 || len(w.gh.repositoryReads()) != 0 {
		t.Errorf("%d checks after the listing's, and the reads %v", n, w.gh.repositoryReads())
	}
	if log := w.log.String(); strings.Count(log, goneOnceError) != 1 || strings.Contains(log, endedLine) || strings.Contains(log, "listing the installation's repositories failed") {
		t.Errorf("after one 404, the log %s", log)
	}
	p.round(context.Background(), pullStart.Add(time.Hour), time.Hour)
	p.rounds.Wait()
	if gone, _ := w.adapter.presence.counts(); gone != 0 {
		t.Errorf("the adapter keeps %d installations' 404s after the end", gone)
	}
	sent := w.apiary.sent(routeGrantsEnd)
	if len(sent) != 1 || sent[0].body["connection_id"] != testConnection {
		t.Fatalf("sent %v", sent)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the link is kept")
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/widgets")); ok {
		t.Error("the repository's installation is kept")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
		t.Error("the collection is still linked")
	}
	if m, _ := pulledOf(w.st, refOf("acme/widgets")); !m.Since.IsZero() {
		t.Error("the pull mark is kept")
	}
	if ok, _ := wasDeleted(w.st, 42); !ok {
		t.Error("GitHub's deletion is not kept")
	}
	if held := w.adapter.heldFor(42); len(held) != 0 {
		t.Errorf("the adapter keeps %v of the installation", held)
	}
	if reads := w.gh.repositoryReads(); len(reads) != 0 {
		t.Errorf("GitHub was read: %v", reads)
	}
	if w.gh.listings() != 0 {
		t.Errorf("%d listings", w.gh.listings())
	}
	if n := len(w.apiary.sent(routeCollections)); n != 0 {
		t.Errorf("%d parts of a listing sent", n)
	}
	if n := strings.Count(w.log.String(), endedLine); n != 1 || strings.Count(w.log.String(), goneOnceLine) != 1 {
		t.Errorf("%d lines; the log %s", n, w.log.String())
	}
	if strings.Contains(w.log.String(), "listing the installation's repositories failed") {
		t.Errorf("a listing's failure is logged: %s", w.log.String())
	}
	p.round(context.Background(), pullStart.Add(2*time.Hour), time.Hour)
	p.rounds.Wait()
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends after a third round", n)
	}
}

// TestA404BetweenOtherAnswersNeverEndsTheInstallation has GitHub answer the check of the
// installation 42 404, then otherwise in the next round, then 404 again: a 200, a
// suspension, a 503 to the check, or a 503 to a page of the listing after the check's
// 200. Each answer between forgets the first 404, so nothing is disconnected, and the
// line of a first 404 is logged twice.
func TestA404BetweenOtherAnswersNeverEndsTheInstallation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(f *fakeGitHub)
	}{
		{"a 200", func(*fakeGitHub) {}},
		{"a suspension", func(f *fakeGitHub) { f.installSuspended = true }},
		{"a 503 to the check", func(f *fakeGitHub) { f.installStatus = 503 }},
		{"a 503 to a page", func(f *fakeGitHub) { f.repos, f.repoPageDown = []string{"acme/widgets"}, 1 }},
	} {
		w, _, p, clock := pulling(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 0)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.installGone = false
			tc.between(f)
		})
		roundAt(p, clock, time.Hour)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 2*time.Hour)
		keptLinked(t, w)
		if log := w.log.String(); strings.Count(log, goneOnceLine) != 2 || strings.Contains(log, endedLine) {
			t.Errorf("%s: the log %s", tc.name, log)
		}
	}
}

// TestA404AfterARoundThatPassesStillEndsTheInstallation has the installation 42's last
// round still run when the next round begins, which passes 42: GitHub's 404 to the check
// in the round before it and in the round after it end the installation.
func TestA404AfterARoundThatPassesStillEndsTheInstallation(t *testing.T) {
	w, _, p, clock := pulling(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	roundAt(p, clock, 0)
	p.mu.Lock()
	p.busy = map[int64]bool{42: true}
	p.mu.Unlock()
	roundAt(p, clock, time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 0 {
		t.Fatalf("%d grant ends in a round that passed", n)
	}
	p.mu.Lock()
	p.busy = nil
	p.mu.Unlock()
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
	if strings.Count(w.log.String(), endedLine) != 1 {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestA404AtAPullStopsTheInstallationsRound has GitHub answer the installation 42's
// check 200 at the round's listing, and 404 from the first pull's mint on: the
// collection's failure is logged as GitHub refusing the token, no other collection of
// 42 is pulled that round, and the 404 counts toward nothing: no line of a first 404 is
// logged, so the next round's 404 at its listing is the first, and the round after it
// ends the installation.
func TestA404AtAPullStopsTheInstallationsRound(t *testing.T) {
	w, _, p, clock := pulling(t)
	setReach(w.st, refOf("acme/gadgets"), 42)
	linkCollection(w.st, refOf("acme/gadgets"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.repos = []string{"acme/widgets", "acme/gadgets"}
		f.goneAfterChecks = 1
	})
	roundAt(p, clock, 0)
	if n := w.gh.repositoryMints(); n != 1 {
		t.Errorf("%d checks after the listing's, want the first pull's alone", n)
	}
	keptLinked(t, w)
	log := w.log.String()
	const refused = `"msg":"pulling the collection failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again","collection":"`
	if strings.Count(log, refused) != 1 || strings.Contains(log, goneOnceLine) || strings.Contains(log, endedLine) {
		t.Errorf("the log %s", log)
	}
	if gone, _ := w.adapter.presence.counts(); gone != 0 {
		t.Errorf("a 404 at a pull counts toward the end of %d installations", gone)
	}
	roundAt(p, clock, time.Hour)
	keptLinked(t, w)
	if log := w.log.String(); strings.Count(log, goneOnceLine) != 1 || strings.Contains(log, endedLine) {
		t.Errorf("after the second round, the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 || strings.Count(w.log.String(), endedLine) != 1 {
		t.Errorf("%d grant ends; the log %s", n, w.log.String())
	}
}

// TestASignOfTheInstallationBetweenRoundsStartsItsCountOver has GitHub answer the
// installation 42's check 404 at a round's listing, then 200 to a check another path
// asks between that round and the next: the listing a webhook sends, or a fill. The
// next round's 404 is a first again, so nothing is disconnected; the round after it
// ends the installation.
func TestASignOfTheInstallationBetweenRoundsStartsItsCountOver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(w *wired)
	}{
		{"a webhook's listing", func(w *wired) {
			w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{}, "repositories_removed": []any{}})
		}},
		{"a fill", func(w *wired) {
			if err := w.adapter.fill(context.Background(), refOf("acme/widgets")); err != nil {
				t.Error(err)
			}
		}},
	} {
		w, _, p, clock := pulling(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 0)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = false })
		before := w.gh.repositoryMints()
		tc.between(w)
		if w.gh.repositoryMints() == before {
			t.Errorf("%s: GitHub was not asked to check the installation", tc.name)
		}
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, time.Hour)
		keptLinked(t, w)
		if log := w.log.String(); strings.Count(log, goneOnceLine) != 2 || strings.Contains(log, endedLine) {
			t.Errorf("%s: the log %s", tc.name, log)
		}
		roundAt(p, clock, 2*time.Hour)
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
			t.Errorf("%s: %d grant ends", tc.name, n)
		}
	}
}

// TestASignOfTheInstallationDuringARoundStartsItsCountOver has GitHub answer the
// installation 42's check 404 at a round's listing; in the next round, which has begun
// and waits for its moment, a fill gets GitHub's 200 to the check, and then the round's
// listing gets 404: that 404 is a first again, so nothing is disconnected; the round
// after it ends the installation.
func TestASignOfTheInstallationDuringARoundStartsItsCountOver(t *testing.T) {
	w, _, p, clock := pulling(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	roundAt(p, clock, 0)
	filled := false
	p.jitter = func(time.Duration) time.Duration { return time.Minute }
	p.sleep = func(ctx context.Context, d time.Duration) error {
		if !filled {
			filled = true
			setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = false })
			if err := w.adapter.fill(ctx, refOf("acme/widgets")); err != nil {
				t.Error(err)
			}
			setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		}
		return clock.sleep(ctx, d)
	}
	roundAt(p, clock, time.Hour)
	if !filled {
		t.Fatal("the round did not wait for its moment")
	}
	keptLinked(t, w)
	if log := w.log.String(); strings.Count(log, goneOnceLine) != 2 || strings.Contains(log, endedLine) {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
}

// TestA401ToTheInstallationsCheckNeverDisconnects has GitHub answer the check of the
// installation 42 401, as for an App's token it does not take: nothing is disconnected,
// the link and the records stay, and the listing's failure is logged.
func TestA401ToTheInstallationsCheckNeverDisconnects(t *testing.T) {
	w, _, p, _ := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(f *fakeGitHub) { f.installUnauthorized = true })
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	if n := len(w.apiary.sent(routeGrantsEnd)) + len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d grant ends and disconnects", n)
	}
	if l, ok, _ := linkOf(w.st, 42); !ok || l.State != linkLive {
		t.Error("the link changed")
	}
	if inst, ok, _ := reachOf(w.st, refOf("acme/widgets")); !ok || inst != 42 {
		t.Error("the repository's installation is dropped")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
		t.Error("the collection is unlinked")
	}
	if ok, _ := wasDeleted(w.st, 42); ok {
		t.Error("the installation is kept as deleted")
	}
	log := w.log.String()
	if !strings.Contains(log, `"msg":"listing the installation's repositories failed","installation":42,"error":"listing the installation's repositories: the installation token: checking installation_id: GitHub answered 401: Bad credentials"`) || strings.Contains(log, "GitHub answers 404 for the installation") {
		t.Errorf("the log %s", log)
	}
}

// TestAnInstallationDeletedByTheWebhookAndTheRoundIsEndedOnce has GitHub's
// deletion of the installation 42 seen by its webhook and by the rounds, whose first
// 404 ends nothing, in either order: one POST /v1/grants/end in all, and the
// one that comes second changes nothing; the webhook that comes second logs that the
// installation is not linked, and the round that comes second never runs, since 42 is
// no longer linked, and the puller forgets the round's first 404.
func TestAnInstallationDeletedByTheWebhookAndTheRoundIsEndedOnce(t *testing.T) {
	deleted := map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}}
	t.Run("the webhook first", func(t *testing.T) {
		w, _, p, clock := pulling(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 0)
		w.deliver(t, "installation", guid1, deleted)
		roundAt(p, clock, time.Hour)
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
			t.Errorf("%d grant ends", n)
		}
		if strings.Contains(w.log.String(), endedLine) {
			t.Errorf("the round says it ended the installation: %s", w.log.String())
		}
		if gone, _ := w.adapter.presence.counts(); gone != 0 {
			t.Errorf("the adapter keeps %d installations' 404s", gone)
		}
	})
	t.Run("the round first", func(t *testing.T) {
		w, _, p, clock := pulling(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 0)
		roundAt(p, clock, time.Hour)
		w.deliver(t, "installation", guid1, deleted)
		if s := state(w.st, guid1); s != store.Done {
			t.Errorf("the delivery is %s", s)
		}
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
			t.Errorf("%d grant ends", n)
		}
		log := w.log.String()
		if strings.Count(log, endedLine) != 1 || !strings.Contains(log, `"msg":"the installation is not linked to Qory Apiary, so the delivery is not handled","event":"installation","action":"deleted"`) {
			t.Errorf("the log %s", log)
		}
	})
	t.Run("both at once", func(t *testing.T) {
		w, _, p, clock := pulling(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
		roundAt(p, clock, 0)
		var wg sync.WaitGroup
		wg.Go(func() {
			p.round(context.Background(), pullStart.Add(time.Hour), time.Hour)
			p.rounds.Wait()
		})
		wg.Go(func() {
			if _, err := w.adapter.endInstallation(context.Background(), 42); err != nil {
				t.Error(err)
			}
		})
		wg.Wait()
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
			t.Errorf("%d grant ends", n)
		}
	})
}

// TestAGrantEndAfterA503IsSentAgainUntilConnectionEnded has the POST /v1/grants/end of
// the round that met GitHub's second 404 return 503: the link stays and a line says
// the grant end is sent again; the next try, 2 seconds later, returns 409
// connection_ended, as for a connection that ended meanwhile, which is taken as the
// 204 is: the link is dropped with no error line, and the next round sends nothing.
func TestAGrantEndAfterA503IsSentAgainUntilConnectionEnded(t *testing.T) {
	w, _, p, clock := pulling(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	w.apiary.refuse = func(route string, n int) (int, string) {
		switch {
		case route != routeGrantsEnd:
			return 0, ""
		case n == 1:
			return 503, `{"error":"unavailable"}`
		}
		return 409, `{"error":"connection_ended"}`
	}
	retry := make(chan struct{})
	w.adapter.endSleep = func(ctx context.Context, d time.Duration) error {
		if d != grantFirstWait {
			t.Errorf("waited %v", d)
		}
		select {
		case <-retry:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	roundAt(p, clock, 0)
	roundAt(p, clock, time.Hour)
	if _, ok, _ := linkOf(w.st, 42); !ok {
		t.Fatal("the link is dropped after a 503")
	}
	if !strings.Contains(w.log.String(), `"level":"WARN","msg":"reporting the end of the installation's grant to Qory Apiary failed, so serve sends it again later","installation":42,"connection":"`+testConnection+`"`) {
		t.Errorf("the log %s", w.log.String())
	}
	close(retry)
	w.endsDone(t, 42)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 2 {
		t.Errorf("%d grant ends", n)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the link is kept after a 409 connection_ended")
	}
	if strings.Contains(w.log.String(), `"level":"ERROR"`) {
		t.Errorf("an error is logged: %s", w.log.String())
	}
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 2 {
		t.Errorf("%d grant ends after the next round", n)
	}
}

// TestASignDuringTheListingBeforeIts404StartsTheCountOver has GitHub answer the
// installation 42's check 404 at the round's listing, round after round. In the first
// round, while the listing waits for that 404, another path gets GitHub's 200 to the
// check, as [Adapter.token] notes it. The sign came after the round began, so the
// second round's 404 is a first again, and nothing is disconnected; the third round ends
// the installation.
func TestASignDuringTheListingBeforeIts404StartsTheCountOver(t *testing.T) {
	w, _, p, clock := pulling(t)
	signed := false
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.installGone = true
		f.answered = func(f *fakeGitHub, request string, _ []byte) {
			if request == "GET /app/installations/42" && !signed {
				signed = true
				w.adapter.presence.installationSeen(42)
			}
		}
	})
	roundAt(p, clock, 0)
	if !signed {
		t.Fatal("GitHub was not asked to check the installation")
	}
	roundAt(p, clock, time.Hour)
	keptLinked(t, w)
	if log := w.log.String(); strings.Count(log, goneOnceLine) != 2 || strings.Contains(log, endedLine) {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 || strings.Count(w.log.String(), endedLine) != 1 {
		t.Errorf("%d grant ends; the log %s", n, w.log.String())
	}
}

// TestAPendingLinkOfAnInstallationGitHubAnswers404ForIsEnded has GitHub answer the check
// of the installation 42 404 while its link is pending and Qory Apiary's copy has its
// grant: the second round sends the grant end, which returns the signed 204, and drops
// the link.
func TestAPendingLinkOfAnInstallationGitHubAnswers404ForIsEnded(t *testing.T) {
	w, _, p, clock := pulling(t)
	grantedLink(w.st, 42, testConnection, linkPending)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	roundAt(p, clock, 0)
	roundAt(p, clock, time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the pending link is kept")
	}
}

// suspendedLine is the line of a round that finds the installation 42 suspended at what.
func suspendedLine(what string) string {
	return `"msg":"` + what + ` failed: GitHub answers that the installation is suspended, so its link stays, nothing more of it is pulled this round, and the next round tries again"`
}

// TestARoundOfASuspendedInstallationIsLoggedOnceAndPullsNothing has GitHub answer the
// installation 42 as suspended, and runs rounds at 0, an hour and 25 hours: the
// suspension is logged once, never as a failure of a day, nothing is disconnected, the
// link and the records stay, and no collection is read. Once GitHub lifts it, the round
// pulls acme/widgets and keeps its mark; a suspension after that is logged again.
func TestARoundOfASuspendedInstallationIsLoggedOnceAndPullsNothing(t *testing.T) {
	w, _, p, clock := pulling(t)
	mark := pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart}
	keepPulled(w.st, refOf("acme/widgets"), mark)
	round := func(at time.Duration) {
		clock.mu.Lock()
		clock.t = pullStart.Add(at)
		clock.mu.Unlock()
		p.round(context.Background(), clock.now(), time.Hour)
		p.rounds.Wait()
	}
	line := suspendedLine("listing the installation's repositories") + `,"installation":42,"error":"listing the installation's repositories: the installation token: GitHub answers that the installation is suspended, so no installation token is minted for it"`
	setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = true })
	for _, at := range []time.Duration{0, time.Hour, 25 * time.Hour} {
		round(at)
	}
	log := w.log.String()
	if strings.Count(log, line) != 1 || strings.Contains(log, "has failed for a day") {
		t.Errorf("the log %s", log)
	}
	if n := len(w.apiary.sent(routeGrantsEnd)) + len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d grant ends and disconnects", n)
	}
	if l, ok, _ := linkOf(w.st, 42); !ok || l.State != linkLive {
		t.Error("the link changed")
	}
	if inst, ok, _ := reachOf(w.st, refOf("acme/widgets")); !ok || inst != 42 {
		t.Error("the repository's installation is dropped")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
		t.Error("the collection is unlinked")
	}
	if m := markOf(t, w); !m.Since.Equal(mark.Since) {
		t.Errorf("the mark %+v", m)
	}
	if reads := w.gh.repositoryReads(); len(reads) != 0 {
		t.Errorf("GitHub was read: %v", reads)
	}
	if n := len(w.apiary.sent(routeCollections)); n != 0 {
		t.Errorf("%d parts of a listing sent", n)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = false })
	round(26 * time.Hour)
	if m := markOf(t, w); !m.Since.Equal(pullStart.Add(26 * time.Hour)) {
		t.Errorf("after the suspension is lifted, the mark %+v", m)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = true })
	round(27 * time.Hour)
	if n := strings.Count(w.log.String(), suspendedLine("listing the installation's repositories")); n != 2 {
		t.Errorf("%d lines after a second suspension: %s", n, w.log.String())
	}
}

// TestASuspensionAfterTheListingStopsTheRound has GitHub suspend the installation 42
// once its listing is answered: the round's first pull meets the suspension, which is
// logged once with the collection, and no other collection of the installation is
// pulled that round.
func TestASuspensionAfterTheListingStopsTheRound(t *testing.T) {
	w, _, p, _ := pulling(t)
	setReach(w.st, refOf("acme/gadgets"), 42)
	linkCollection(w.st, refOf("acme/gadgets"))
	for _, ref := range refsOf("acme/widgets", "acme/gadgets") {
		keepPulled(w.st, ref, pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	}
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.repoAfter = func(f *fakeGitHub, _ int) { f.installSuspended = true }
	})
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	log := w.log.String()
	if n := strings.Count(log, suspendedLine("pulling the collection")+`,"collection":"`); n != 1 {
		t.Errorf("%d lines; the log %s", n, log)
	}
	if reads := w.gh.repositoryReads(); len(reads) != 0 {
		t.Errorf("GitHub was read: %v", reads)
	}
	if n := w.gh.repositoryMints(); n != 1 {
		t.Errorf("%d repositories' tokens asked for, want the first pull's alone", n)
	}
	for _, ref := range refsOf("acme/widgets", "acme/gadgets") {
		if m, _ := pulledOf(w.st, ref); !m.Since.Equal(pullStart.Add(-time.Hour)) {
			t.Errorf("%s kept %+v", ref, m)
		}
	}
}

// repositoryMints are the checks of the installation 42 the fake answered after its
// first, each the check of a mint: the round's listing token's is the first.
func (f *fakeGitHub) repositoryMints() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == "GET /app/installations/42" {
			n++
		}
	}
	return n - 1
}

// TestARoundWhoseListingFailsAtItsFirstPageSendsNoPart has GitHub answer the first page
// of the installation's repositories 502: the round sends Qory Apiary no part of the
// listing, logs the failure, and still pulls the collection.
func TestARoundWhoseListingFailsAtItsFirstPageSendsNoPart(t *testing.T) {
	w, _, p, _ := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 1 })
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	if n := len(w.apiary.sent(routeCollections)); n != 0 {
		t.Errorf("%d parts of a listing sent", n)
	}
	if !strings.Contains(w.log.String(), `"msg":"listing the installation's repositories failed","installation":42`) {
		t.Errorf("the log %s", w.log.String())
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) {
		t.Errorf("the collection is not pulled: %+v", m)
	}
}

// TestAFillPassedWhileSuspendedIsListedByTheRoundAfter has the feed link acme/widgets
// while GitHub answers the installation 42 as suspended: the fill is passed for good.
// Once GitHub lifts the suspension, the round's pull lists the collection's open issues,
// complete, as the fill would have, and keeps its mark.
func TestAFillPassedWhileSuspendedIsListedByTheRoundAfter(t *testing.T) {
	w, _, p, _ := pulling(t)
	unlinkCollection(w.st, refOf("acme/widgets"))
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = true })
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.apiary.sent(routeItems)) != 0 {
		t.Fatal("items were sent while suspended")
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = false })
	p.round(context.Background(), pullStart, time.Hour)
	p.rounds.Wait()
	parts := listingParts(w)
	if len(parts) != 1 || !parts[0].Listing.Complete || len(parts[0].Items) != 1 {
		t.Errorf("parts %+v", parts)
	}
	if m := markOf(t, w); !m.Since.Equal(pullStart) || !m.Listed.Equal(pullStart) {
		t.Errorf("the mark %+v", m)
	}
}

// refusing is [pulling] with acme/old reached by 42 and linked, pulled an hour ago, in
// place of acme/widgets, which is not linked, so acme/old is the round's one pull:
// GitHub answers a token for acme/old alone 422, as for a repository the installation no
// longer reaches. The installation's list of repositories holds repos, a page of size
// each when size is set.
func refusing(t *testing.T, size int, repos ...string) (*wired, *puller, *pullClock) {
	t.Helper()
	w, f, p, clock := pulling(t)
	unlinkCollection(w.st, refOf("acme/widgets"))
	setReach(w.st, refOf("acme/old"), 42)
	linkCollection(w.st, refOf("acme/old"))
	keepPulled(w.st, refOf("acme/old"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(gh *fakeGitHub) { gh.repos, gh.repoPageSize, gh.linkBase = repos, size, f.srv.URL })
	return w, p, clock
}

// roundAt runs a round at at from pullStart, and waits for it.
func roundAt(p *puller, clock *pullClock, at time.Duration) {
	clock.mu.Lock()
	clock.t = pullStart.Add(at)
	clock.mu.Unlock()
	p.round(context.Background(), clock.now(), time.Hour)
	p.rounds.Wait()
}

// listPagesAfterRefusal are the pages of the installation's repositories GitHub was
// asked for after its last answer to a mint, in order.
func (f *fakeGitHub) listPagesAfterRefusal() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	last := -1
	for i, r := range f.requests {
		if strings.HasSuffix(r, "/access_tokens") {
			last = i
		}
	}
	var pages []string
	for _, r := range f.requests[last+1:] {
		if strings.HasPrefix(r, "GET /installation/repositories") {
			pages = append(pages, r)
		}
	}
	return pages
}

// disconnectedLine is the line of a round that disconnected acme/old.
var disconnectedLine = `"msg":"GitHub refuses a token for the repository alone, and the installation's list of repositories, read in full, no longer holds it, so its collection is disconnected","collection":"` + refOf("acme/old") + `","installation":42`

// counts is how many installations' 404s and collections' absences s keeps.
func (s *presence) counts() (gone, absent int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gone), len(s.absent)
}

// absentLine is the line of a round that found the repository name absent from the
// installation's list of repositories, in the first round in a row that does.
func absentLine(name string) string {
	return `"level":"WARN","msg":"pulling the collection failed: GitHub refuses a token for the repository alone, and the installation's list of repositories, read in full, no longer holds it, so its collection is disconnected if the next round finds the same and GitHub shows the repository nowhere in between","collection":"` + refOf(name) + `","error":"`
}

// stillListedLine is the line of a round that kept acme/old, whose token GitHub refuses
// alone, as the installation's list of repositories still holds it.
var stillListedLine = `"msg":"pulling the collection failed: GitHub refuses a token for the repository alone, yet the installation's list of repositories still holds it, so its collection is not disconnected, and the next round tries again","collection":"` + refOf("acme/old") + `"`

// keptOld checks acme/old's records stay: 42 reaches it, its collection is linked and
// its pull mark is the one before the rounds.
func keptOld(t *testing.T, w *wired) {
	t.Helper()
	if inst, ok, _ := reachOf(w.st, refOf("acme/old")); !ok || inst != 42 {
		t.Error("acme/old's installation is dropped")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/old")); !ok {
		t.Error("acme/old is unlinked")
	}
	if m, _ := pulledOf(w.st, refOf("acme/old")); !m.Since.Equal(pullStart.Add(-time.Hour)) {
		t.Errorf("acme/old's mark %+v", m)
	}
}

// droppedOld checks acme/old's records are dropped, and one disconnect named it.
func droppedOld(t *testing.T, w *wired) {
	t.Helper()
	sent := w.apiary.sent(routeDisconnect)
	if len(sent) != 1 || sent[0].body["collection_ref"] != refOf("acme/old") {
		t.Errorf("sent %v", sent)
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
		t.Error("acme/old's installation is kept")
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/old")); ok {
		t.Error("acme/old is still linked")
	}
	if m, _ := pulledOf(w.st, refOf("acme/old")); !m.Since.IsZero() {
		t.Errorf("acme/old's mark %+v", m)
	}
}

// TestARefusedRepositoryTheListNoLongerHoldsIsDisconnected has GitHub answer a token for
// acme/old alone 422, and the installation's list of repositories, two pages, not hold
// it, in two rounds: each round reads every page of the list with the listing token it
// minted for its listing, after the refusal. The first keeps acme/old, with a line that
// says it found it absent; the second disconnects acme/old's collection, with a line,
// and drops its records. A public repository, which GitHub answers by its id under any
// token, goes the same way, and the confirmation never reads the repository by its id.
func TestARefusedRepositoryTheListNoLongerHoldsIsDisconnected(t *testing.T) {
	for _, public := range []bool{false, true} {
		w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
		setGitHub(w.gh, func(f *fakeGitHub) { f.oldPublic = public })
		roundAt(p, clock, 0)
		keptOld(t, w)
		if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
			t.Errorf("public %v: %d disconnects in the first round", public, n)
		}
		if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 1 || strings.Contains(log, disconnectedLine) || !strings.Contains(log, `GitHub answered 422: There is at least one repository that does not exist or is not accessible to the parent installation.; the installation's list of repositories no longer holds the repository, so its collection is disconnected if the next round finds the same and GitHub shows the repository nowhere in between"`) {
			t.Errorf("public %v: after the first round, the log %s", public, log)
		}
		roundAt(p, clock, time.Hour)
		droppedOld(t, w)
		log := w.log.String()
		if strings.Count(log, disconnectedLine) != 1 || strings.Count(log, `"msg":"pulling the collection failed`) != 1 {
			t.Errorf("public %v: the log %s", public, log)
		}
		if pages := w.gh.listPagesAfterRefusal(); len(pages) != 2 {
			t.Errorf("public %v: the list read after the refusal: %v", public, pages)
		}
		if n := w.gh.listingMints(); n != 2 {
			t.Errorf("public %v: %d listing tokens minted, want the rounds' alone", public, n)
		}
		for _, r := range w.gh.repositoryReads() {
			if strings.HasPrefix(r, "GET /repositories/"+strconv.Itoa(oldID)) {
				t.Errorf("public %v: acme/old is read: %s", public, r)
			}
		}
	}
}

// TestARefusedRepositoryTheListStillHoldsIsNotDisconnected has GitHub answer a token
// for acme/old alone 422 while the installation's list of repositories holds it, on
// page 1 of one, or on page 3 of five, every page of which is read: nothing is
// disconnected, the records stay, and the line says so once over rounds at 0 and an
// hour, then once more at 25 hours as a failure of a day. A public repository goes the
// same way.
func TestARefusedRepositoryTheListStillHoldsIsNotDisconnected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		repos  []string
		pages  int
		public bool
	}{
		{"on page 1", 0, []string{"acme/widgets", "acme/old", "acme/gadgets"}, 1, false},
		{"on page 3", 1, []string{"acme/widgets", "acme/gadgets", "acme/old", "acme/a1", "acme/a2"}, 5, false},
		{"public, on page 3", 1, []string{"acme/widgets", "acme/gadgets", "acme/old", "acme/a1", "acme/a2"}, 5, true},
	} {
		w, p, clock := refusing(t, tc.size, tc.repos...)
		setGitHub(w.gh, func(f *fakeGitHub) { f.oldPublic = tc.public })
		roundAt(p, clock, 0)
		if pages := w.gh.listPagesAfterRefusal(); len(pages) != tc.pages {
			t.Errorf("%s: the list read after the refusal: %v", tc.name, pages)
		}
		roundAt(p, clock, time.Hour)
		if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
			t.Errorf("%s: %d disconnects", tc.name, n)
		}
		keptOld(t, w)
		const day = `"msg":"pulling the collection has failed for a day, and the next round tries again","collection":"`
		log := w.log.String()
		if strings.Count(log, stillListedLine) != 1 || strings.Contains(log, day) {
			t.Errorf("%s: the log %s", tc.name, log)
		}
		if !strings.Contains(log, `GitHub answered 422: There is at least one repository that does not exist or is not accessible to the parent installation.; the installation's list of repositories still holds the repository, so its collection is not disconnected"`) {
			t.Errorf("%s: the error: %s", tc.name, log)
		}
		roundAt(p, clock, 25*time.Hour)
		log = w.log.String()
		if strings.Count(log, stillListedLine) != 1 || strings.Count(log, day+refOf("acme/old")+`"`) != 1 {
			t.Errorf("%s: after a day, the log %s", tc.name, log)
		}
	}
}

// TestARefusedRepositoryWhoseListFailsIsTriedAgain has GitHub answer a token for
// acme/old alone 422, and page 2 of the installation's list of repositories 502:
// nothing is decided, nothing is disconnected, and the line says the list failed; of
// the next two rounds, whose lists answer in full without acme/old, the second
// disconnects it.
func TestARefusedRepositoryWhoseListFailsIsTriedAgain(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 2 })
	roundAt(p, clock, 0)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	keptOld(t, w)
	if !strings.Contains(w.log.String(), `"msg":"pulling the collection failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again","collection":"`+refOf("acme/old")+`","error":"`) ||
		!strings.Contains(w.log.String(), `; reading the installation's list of repositories to confirm it no longer holds the repository: listing the installation's repositories: GitHub answered 502: Bad Gateway"`) {
		t.Errorf("the log %s", w.log.String())
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 0 })
	roundAt(p, clock, time.Hour)
	keptOld(t, w)
	roundAt(p, clock, 2*time.Hour)
	droppedOld(t, w)
}

// TestARefusedRepositoryWhoseListDoesNotAddUpIsNotDisconnected has GitHub answer a
// token for acme/old alone 422, and the installation's list of repositories, two pages
// without acme/old, count one repository more than its pages name: nothing is decided,
// nothing is disconnected, and the line says why; of the next two rounds, whose lists
// add up, the second disconnects it.
func TestARefusedRepositoryWhoseListDoesNotAddUpIsNotDisconnected(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoTotalOff = 1 })
	roundAt(p, clock, 0)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	keptOld(t, w)
	if !strings.Contains(w.log.String(), `; reading the installation's list of repositories to confirm it no longer holds the repository: listing the installation's repositories: GitHub counts 3 repositories, and its pages name 2"`) {
		t.Errorf("the log %s", w.log.String())
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoTotalOff = 0 })
	roundAt(p, clock, time.Hour)
	keptOld(t, w)
	roundAt(p, clock, 2*time.Hour)
	droppedOld(t, w)
}

// repositoryPagesRead is how many pages of the installation's repositories GitHub was
// asked for.
func (f *fakeGitHub) repositoryPagesRead() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, "GET /installation/repositories") {
			n++
		}
	}
	return n
}

// refusingThree is refusing with acme/gadgets and acme/gone linked as well, both
// reached by 42 and pulled before, and GitHub answering a token for either alone 422,
// as for acme/old.
func refusingThree(t *testing.T, repos ...string) (*wired, *puller, *pullClock) {
	t.Helper()
	w, p, clock := refusing(t, 1, repos...)
	for _, name := range []string{"acme/gadgets", "acme/gone"} {
		setReach(w.st, refOf(name), 42)
		linkCollection(w.st, refOf(name))
		keepPulled(w.st, refOf(name), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.refused = []int64{gadgetsID, repoID("acme/gone")} })
	return w, p, clock
}

// TestARoundReadsTheListOnceForItsRefusedCollections has GitHub answer a token 422 for
// each of acme/old, acme/gadgets and acme/gone alone, and the installation's list of
// repositories, two pages, hold acme/widgets and acme/gadgets, in two rounds: each round
// reads the list once after its listing, for all three. The first finds acme/old and
// acme/gone absent, and the second disconnects them, while acme/gadgets, which the
// list holds, stays.
func TestARoundReadsTheListOnceForItsRefusedCollections(t *testing.T) {
	w, p, clock := refusingThree(t, "acme/widgets", "acme/gadgets")
	roundAt(p, clock, 0)
	if n := w.gh.repositoryPagesRead(); n != 4 {
		t.Errorf("%d pages read, want the listing's two and one read of two", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 1 || strings.Count(log, absentLine("acme/gone")) != 1 {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, time.Hour)
	if n := w.gh.repositoryPagesRead(); n != 8 {
		t.Errorf("%d pages read after a second round, want 8", n)
	}
	var dropped []string
	for _, s := range w.apiary.sent(routeDisconnect) {
		dropped = append(dropped, s.body["collection_ref"].(string))
	}
	slices.Sort(dropped)
	if want := []string{refOf("acme/old"), refOf("acme/gone")}; !slices.Equal(dropped, slices.Sorted(slices.Values(want))) {
		t.Errorf("disconnected %v", dropped)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/gadgets")); !ok {
		t.Error("acme/gadgets is unlinked")
	}
	if !strings.Contains(w.log.String(), `"msg":"pulling the collection failed: GitHub refuses a token for the repository alone, yet the installation's list of repositories still holds it, so its collection is not disconnected, and the next round tries again","collection":"`+refOf("acme/gadgets")+`"`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestARoundKeepsTheListsFailureForItsRefusedCollections has GitHub answer a token 422
// for each of acme/old, acme/gadgets and acme/gone alone, and page 2 of the
// installation's list of repositories 502: the round reads the list once after its
// listing, and each of the three decides nothing, with the list's error.
func TestARoundKeepsTheListsFailureForItsRefusedCollections(t *testing.T) {
	w, p, clock := refusingThree(t, "acme/widgets", "acme/gadgets")
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 2 })
	roundAt(p, clock, 0)
	if n := w.gh.repositoryPagesRead(); n != 4 {
		t.Errorf("%d pages read, want the listing's two and one read of two", n)
	}
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	for _, name := range []string{"acme/old", "acme/gadgets", "acme/gone"} {
		if !strings.Contains(w.log.String(), `"collection":"`+refOf(name)+`","error":"`) || !strings.Contains(w.log.String(), `; reading the installation's list of repositories to confirm it no longer holds the repository: listing the installation's repositories: GitHub answered 502: Bad Gateway"`) {
			t.Errorf("%s: the log %s", name, w.log.String())
		}
	}
	if n := strings.Count(w.log.String(), `; reading the installation's list of repositories to confirm it no longer holds the repository: listing the installation's repositories: GitHub answered 502: Bad Gateway"`); n != 3 {
		t.Errorf("%d lines with the list's error; the log %s", n, w.log.String())
	}
}

// TestARepositoryFoundAbsentOnceThenOtherwiseIsNotDisconnected has GitHub answer a token
// for acme/widgets alone 422 while the installation's list of repositories does not
// hold it, then otherwise in the next round, then the same again: the list holds it,
// the list fails, or GitHub mints the token and the pull passes, or fails at the read.
// Each answer between forgets the first absence, so nothing is disconnected, and the
// line of a first absence is logged twice.
func TestARepositoryFoundAbsentOnceThenOtherwiseIsNotDisconnected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(f *fakeGitHub)
	}{
		{"the list holds it", func(f *fakeGitHub) { f.repos = []string{"acme/widgets"} }},
		{"the list fails", func(f *fakeGitHub) { f.repoPageDown = 1 }},
		{"the token is minted", func(f *fakeGitHub) { f.refused = nil }},
		{"the token is minted and the read fails", func(f *fakeGitHub) { f.refused, f.reposDown = nil, true }},
	} {
		w, _, p, clock := pulling(t)
		keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
		absent := func(f *fakeGitHub) {
			f.repos, f.repoPageDown, f.refused, f.reposDown = nil, 0, []int64{widgetsID}, false
		}
		setGitHub(w.gh, absent)
		roundAt(p, clock, 0)
		setGitHub(w.gh, tc.between)
		roundAt(p, clock, time.Hour)
		// A token minted between is kept, and would serve the next round.
		w.adapter.forgetTokens(42)
		setGitHub(w.gh, absent)
		roundAt(p, clock, 2*time.Hour)
		if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
			t.Errorf("%s: %d disconnects", tc.name, n)
		}
		if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
			t.Errorf("%s: acme/widgets is unlinked", tc.name)
		}
		if log := w.log.String(); strings.Count(log, absentLine("acme/widgets")) != 2 {
			t.Errorf("%s: the log %s", tc.name, log)
		}
	}
}

// TestADisconnectAnsweredConnectionSuspendedKeepsTheRecords has Qory Apiary answer the
// disconnect of acme/old, sent by the second round that finds it absent from the list,
// 409 connection_suspended, which changes no state: the records stay and the failure is
// logged; the next round, whose absence is still the second in a row, sends the
// disconnect again, which Qory Apiary answers with the signed 204, and the records are
// dropped.
func TestADisconnectAnsweredConnectionSuspendedKeepsTheRecords(t *testing.T) {
	w, p, clock := refusing(t, 0, "acme/widgets")
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeDisconnect && n == 1 {
			return 409, `{"error":"connection_suspended"}`
		}
		return 0, ""
	}
	roundAt(p, clock, 0)
	roundAt(p, clock, time.Hour)
	keptOld(t, w)
	log := w.log.String()
	if !strings.Contains(log, `"msg":"pulling the collection failed","collection":"`+refOf("acme/old")+`","error":"disconnecting `+refOf("acme/old")+`: Qory Apiary answered 409 connection_suspended"`) || strings.Contains(log, disconnectedLine) {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeDisconnect)); n != 2 {
		t.Errorf("%d disconnects", n)
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
		t.Error("acme/old's installation is kept")
	}
	if strings.Count(w.log.String(), disconnectedLine) != 1 {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAPullWhoseReadsPassForgetsTheAbsence has GitHub answer a token for acme/widgets
// alone 422 while the installation's list does not hold it; then, in the next round,
// answer the reads made with a token for acme/widgets kept from before, after which the
// collection is unlinked, so the pull stops before it keeps its start; then, once the collection is linked again, the
// same as the first round. The reads that passed forget the first absence, so the third
// round's absence is a first one, and nothing is disconnected.
func TestAPullWhoseReadsPassForgetsTheAbsence(t *testing.T) {
	w, _, p, clock := pulling(t)
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	absent := func(f *fakeGitHub) { f.repos, f.refused, f.issuesRead = nil, []int64{widgetsID}, nil }
	setGitHub(w.gh, absent)
	roundAt(p, clock, 0)
	// A token for acme/widgets alone kept from before, so the next pull mints none,
	// which would be a sign by itself.
	w.adapter.mu.Lock()
	w.adapter.tokens["42 "+widgetsRef+" read"] = github.InstallationToken{Token: ghToken, ExpiresAt: time.Now().Add(time.Hour)}
	w.adapter.mu.Unlock()
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.issuesRead = func() { unlinkCollection(w.st, refOf("acme/widgets")) }
	})
	mints := w.gh.repositoryMints()
	roundAt(p, clock, time.Hour)
	if n := w.gh.repositoryMints(); n != mints+1 {
		t.Errorf("%d checks in the second round, want the listing's alone", n-mints)
	}
	if m, _ := pulledOf(w.st, refOf("acme/widgets")); !m.Since.Equal(pullStart.Add(-time.Hour)) {
		t.Fatalf("the pull kept its start: %+v", m)
	}
	linkCollection(w.st, refOf("acme/widgets"))
	w.adapter.forgetTokens(42)
	setGitHub(w.gh, absent)
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/widgets")) != 2 {
		t.Errorf("the log %s", log)
	}
}

// TestASignOfTheRepositoryBetweenRoundsStartsItsCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it; then, between that
// round and the next, a sign that GitHub holds acme/old: a fill whose token for acme/old
// alone GitHub mints, a connect's first listing that names acme/old, or a listing a
// webhook sends that names acme/old. The next
// round's absence is a first again, so nothing is disconnected; the round after it
// disconnects acme/old.
func TestASignOfTheRepositoryBetweenRoundsStartsItsCountOver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(w *wired)
	}{
		{"a token minted", func(w *wired) {
			setGitHub(w.gh, func(f *fakeGitHub) { f.oldGrant = 1 })
			w.adapter.fill(context.Background(), refOf("acme/old"))
			left := -1
			setGitHub(w.gh, func(f *fakeGitHub) { left = f.oldGrant })
			if left != 0 {
				t.Error("GitHub minted the fill no token for acme/old alone")
			}
			w.adapter.forgetTokens(42)
		}},
		{"a connect's first listing that names it", func(w *wired) {
			setGitHub(w.gh, func(f *fakeGitHub) { f.repos = []string{"acme/widgets", "acme/gadgets", "acme/old"} })
			if err := w.adapter.sendFirst(context.Background(), 42, link{Connection: testConnection, State: linkPending}); err != nil {
				t.Error(err)
			}
			w.adapter.dropFirsts(42, "")
			setGitHub(w.gh, func(f *fakeGitHub) { f.repos = []string{"acme/widgets", "acme/gadgets"} })
		}},
		{"a listing that names it", func(w *wired) {
			setGitHub(w.gh, func(f *fakeGitHub) { f.repos = []string{"acme/widgets", "acme/gadgets", "acme/old"} })
			if err := w.adapter.listRepositories(context.Background(), 42); err != nil {
				t.Error(err)
			}
			setGitHub(w.gh, func(f *fakeGitHub) { f.repos = []string{"acme/widgets", "acme/gadgets"} })
		}},
	} {
		w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
		roundAt(p, clock, 0)
		tc.between(w)
		roundAt(p, clock, time.Hour)
		keptOld(t, w)
		if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
			t.Errorf("%s: %d disconnects", tc.name, n)
		}
		if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
			t.Errorf("%s: the log %s", tc.name, log)
		}
		roundAt(p, clock, 2*time.Hour)
		droppedOld(t, w)
	}
}

// TestARepositoryAddedBackBetweenRoundsStartsItsCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it; then GitHub's
// webhook says acme/old was added to the installation again, while the listing the
// webhook sends does not name it yet; then the next round finds acme/old absent again.
// The webhook's addition starts the count over, so that absence is a first, and nothing
// is disconnected.
func TestARepositoryAddedBackBetweenRoundsStartsItsCountOver(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	roundAt(p, clock, 0)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{map[string]any{"id": oldID, "full_name": "acme/old"}}, "repositories_removed": []any{}})
	roundAt(p, clock, time.Hour)
	keptOld(t, w)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
		t.Errorf("the log %s", log)
	}
}

// TestADeliveryThatNamesARepositoryStartsItsCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it; then GitHub's
// webhook delivers an event that names acme/old: an issues event, which serve keeps
// and handles, an event no handler takes, or an issues event of an installation not
// linked, neither of which serve keeps; then the next round finds acme/old absent
// again. The delivery is a sign that GitHub holds acme/old, so that absence is a first,
// and nothing is disconnected; the round after that disconnects acme/old.
func TestADeliveryThatNamesARepositoryStartsItsCountOver(t *testing.T) {
	star, _ := json.Marshal(map[string]any{"action": "created", "installation": map[string]any{"id": 42}, "repository": map[string]any{"id": oldID, "full_name": "acme/old"}})
	unlinked, _ := json.Marshal(issueEvent(99, "acme/old", "edited"))
	for _, tc := range []struct {
		name    string
		deliver func(w *wired)
	}{
		{"an issues event", func(w *wired) { w.deliver(t, "issues", guid1, issueEvent(42, "acme/old", "edited")) }},
		{"an event no handler takes", func(w *wired) {
			if rec := post(w.mux, "star", guid1, string(star), sign(string(star))); rec.Code != http.StatusAccepted {
				t.Fatalf("answered %d", rec.Code)
			}
		}},
		{"an installation not linked", func(w *wired) {
			if rec := post(w.mux, "issues", guid1, string(unlinked), sign(string(unlinked))); rec.Code != http.StatusAccepted {
				t.Fatalf("answered %d", rec.Code)
			}
		}},
	} {
		w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
		roundAt(p, clock, 0)
		tc.deliver(w)
		roundAt(p, clock, time.Hour)
		keptOld(t, w)
		if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
			t.Errorf("%s: %d disconnects", tc.name, n)
		}
		if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
			t.Errorf("%s: the log %s", tc.name, log)
		}
		roundAt(p, clock, 2*time.Hour)
		droppedOld(t, w)
	}
}

// TestADeliveryThatIsNoSignKeepsTheCount has GitHub answer a token for acme/old alone
// 422 while the installation's list does not hold it; then comes a delivery that names
// acme/old and is no sign that GitHub holds it: the repository event's deleted, of an
// installation not linked, which serve does not keep, or an issues event whose
// signature is not the body's, which serve refuses. The next round finds acme/old
// absent again, the second in a row, and disconnects it.
func TestADeliveryThatIsNoSignKeepsTheCount(t *testing.T) {
	deleted, _ := json.Marshal(map[string]any{"action": "deleted", "installation": map[string]any{"id": 99}, "repository": map[string]any{"id": oldID, "full_name": "acme/old"}})
	issue, _ := json.Marshal(issueEvent(42, "acme/old", "edited"))
	for _, tc := range []struct {
		name, event, body, sig string
		status                 int
	}{
		{"the repository event's deleted", "repository", string(deleted), sign(string(deleted)), http.StatusAccepted},
		{"a delivery whose signature is not the body's", "issues", string(issue), sign("another body"), http.StatusUnauthorized},
	} {
		w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
		roundAt(p, clock, 0)
		if rec := post(w.mux, tc.event, guid1, tc.body, tc.sig); rec.Code != tc.status {
			t.Fatalf("%s: answered %d", tc.name, rec.Code)
		}
		roundAt(p, clock, time.Hour)
		droppedOld(t, w)
	}
}

// TestEachDeliveryThatNamesARepositoryIsASignButThree pins [Adapter.delivered]: a
// delivery that names a repository is a sign that GitHub holds it, whatever its event,
// but for the repository event's deleted and transferred and
// installation_repositories' removed.
func TestEachDeliveryThatNamesARepositoryIsASignButThree(t *testing.T) {
	for _, tc := range []struct {
		event, action string
		sign          bool
	}{
		{"issues", "opened", true}, {"issues", "deleted", true}, {"issues", "transferred", true}, {"issue_comment", "deleted", true},
		{"label", "deleted", true}, {"push", "", true},
		{"repository", "renamed", true}, {"repository", "archived", true}, {"installation_repositories", "added", true},
		{"repository", "deleted", false}, {"repository", "transferred", false}, {"installation_repositories", "removed", false},
	} {
		a := &Adapter{}
		hs := &Handlers{}
		a.Register(hs)
		hs.seenBy()(tc.event, tc.action, oldID)
		if _, got := a.presence.repositories[refOf("acme/old")]; got != tc.sign {
			t.Errorf("%s %s: a sign %v, want %v", tc.event, tc.action, got, tc.sign)
		}
	}
}

// TestAConfirmationReadThatNamesARepositoryStartsItsCountOver has GitHub answer a
// token for acme/old alone 422 while the installation's list does not hold it. In the
// next round, a fill holds acme/old's turn, so it is not pulled, and the list read to
// confirm acme/gadgets, refused too, names acme/old. In the round after that, acme/old
// is absent again: that absence is a first, so nothing is disconnected.
func TestAConfirmationReadThatNamesARepositoryStartsItsCountOver(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	setReach(w.st, refOf("acme/gadgets"), 42)
	linkCollection(w.st, refOf("acme/gadgets"))
	keepPulled(w.st, refOf("acme/gadgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(f *fakeGitHub) { f.refused = []int64{gadgetsID} })
	roundAt(p, clock, 0)
	done, ok := w.adapter.takeTurn(refOf("acme/old"))
	if !ok {
		t.Fatal("acme/old's turn is held")
	}
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.repoAfter = func(f *fakeGitHub, page int) {
			if page == 2 {
				f.repos, f.repoAfter = []string{"acme/widgets", "acme/gadgets", "acme/old"}, nil
			}
		}
	})
	roundAt(p, clock, time.Hour)
	done()
	setGitHub(w.gh, func(f *fakeGitHub) { f.repos = []string{"acme/widgets", "acme/gadgets"} })
	roundAt(p, clock, 2*time.Hour)
	keptOld(t, w)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
		t.Errorf("the log %s", log)
	}
}

// TestASignAfterTheRoundsReadStartsTheCountOver has GitHub answer a token 422 for
// acme/old and acme/gadgets alone while the installation's list does not hold acme/old.
// In the next round, the list read to confirm acme/gadgets, pulled first, does not name
// acme/old; then, before acme/old's pull, GitHub's webhook says acme/old was added. The
// absence acme/old's pull finds from that read came before the sign, so the round after
// it finds a first absence again, and nothing is disconnected; the round after that
// disconnects acme/old.
func TestASignAfterTheRoundsReadStartsTheCountOver(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	setReach(w.st, refOf("acme/gadgets"), 42)
	linkCollection(w.st, refOf("acme/gadgets"))
	keepPulled(w.st, refOf("acme/gadgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
	setGitHub(w.gh, func(f *fakeGitHub) { f.refused = []int64{gadgetsID} })
	roundAt(p, clock, 0)
	// acme/gadgets's key comes before acme/old's, so it takes the first offset.
	offsets := []time.Duration{time.Minute, 2 * time.Minute}
	p.jitter = func(time.Duration) time.Duration {
		if len(offsets) == 0 {
			return 0
		}
		d := offsets[0]
		offsets = offsets[1:]
		return d
	}
	sleeps := 0
	p.sleep = func(ctx context.Context, d time.Duration) error {
		if sleeps++; sleeps == 2 {
			w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{map[string]any{"id": oldID, "full_name": "acme/old"}}, "repositories_removed": []any{}})
		}
		return clock.sleep(ctx, d)
	}
	roundAt(p, clock, time.Hour)
	if sleeps != 2 {
		t.Fatalf("%d waits in the second round", sleeps)
	}
	p.jitter, p.sleep = func(time.Duration) time.Duration { return 0 }, clock.sleep
	roundAt(p, clock, 2*time.Hour)
	keptOld(t, w)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 3 {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 3*time.Hour)
	droppedOld(t, w)
}

// seenOf is the number of the last sign s keeps of the repository whose collection's ref
// is ref, or 0 when it keeps none.
func (s *presence) seenOf(ref string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repositories[ref]
}

// addBack has GitHub's webhook say acme/old was added to the installation 42 again,
// delivered in another goroutine as a delivery arrives while a round runs, and waits
// until the webhook noted its sign, see [presence], which it does before it asks GitHub
// anything. The delivery, whose GitHub delivery id is guid, is handled after.
func addBack(t *testing.T, w *wired, guid string) {
	seen := w.adapter.presence.seenOf(refOf("acme/old"))
	b, _ := json.Marshal(map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{map[string]any{"id": oldID, "full_name": "acme/old"}}, "repositories_removed": []any{}})
	go func() {
		if rec := post(w.mux, "installation_repositories", guid, string(b), sign(string(b))); rec.Code != http.StatusAccepted {
			t.Errorf("installation_repositories: status %d", rec.Code)
		}
	}()
	for deadline := time.Now().Add(10 * time.Second); w.adapter.presence.seenOf(refOf("acme/old")) == seen; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Error("the webhook noted no sign of acme/old")
			return
		}
	}
}

// TestASignDuringTheConfirmationReadStartsTheCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it, round after round.
// In one round, the first or the second, while the list read to confirm acme/old's
// absence runs, after its first page, comes a sign that GitHub holds acme/old: its
// webhook says acme/old was added to the installation again, or a listing names it, as
// [reachSink] notes it. Whether acme/old is disconnected is decided once the read ends,
// so the sign counts: that round's absence is a first, nothing is disconnected, and
// since the sign came after the read began, so is the next round's; the round after
// that disconnects acme/old.
func TestASignDuringTheConfirmationReadStartsTheCountOver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		round   int
		webhook bool
	}{
		{"the webhook adds it back in the first round", 1, true},
		{"the webhook adds it back in the second round", 2, true},
		{"a listing names it in the second round", 2, false},
	} {
		w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
		signed := false
		for round := 1; round <= tc.round+2; round++ {
			if round == tc.round {
				// The round's listing reads page 1 first; the read that confirms
				// acme/old's absence reads it next.
				ones := 0
				setGitHub(w.gh, func(f *fakeGitHub) {
					f.repoAfter = func(f *fakeGitHub, page int) {
						if page == 1 && !signed {
							if ones++; ones == 2 {
								signed = true
								if tc.webhook {
									addBack(t, w, guid1)
								} else {
									w.adapter.presence.repositorySeen(refOf("acme/old"))
								}
							}
						}
					}
				})
			}
			roundAt(p, clock, time.Duration(round-1)*time.Hour)
			if round == tc.round {
				if !signed {
					t.Fatalf("%s: no sign in round %d", tc.name, round)
				}
				if tc.webhook {
					eventually(t, "the webhook handled", func() bool { s := state(w.st, guid1); return s == store.Done || s == store.Failed })
				}
			}
			if round <= tc.round+1 {
				if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
					t.Fatalf("%s: %d disconnects after round %d; the log %s", tc.name, n, round, w.log.String())
				}
				if c := strings.Count(w.log.String(), absentLine("acme/old")); c != round {
					t.Errorf("%s: %d first absences after round %d", tc.name, c, round)
				}
			}
		}
		if n := len(w.apiary.sent(routeDisconnect)); n != 1 {
			t.Errorf("%s: %d disconnects after round %d", tc.name, n, tc.round+2)
		}
	}
}

// TestASignBeforeTheConfirmationReadStartsTheCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it. In the next round,
// a sign that GitHub holds acme/old, a listing that names it as [reachSink] notes it,
// comes as GitHub answers 422 to acme/old's token, before the list read to confirm
// acme/old's absence begins: that round's absence is a first, so nothing is
// disconnected; the sign came before that read began, so the round after it disconnects
// acme/old.
func TestASignBeforeTheConfirmationReadStartsTheCountOver(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	roundAt(p, clock, 0)
	signed := false
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.answered = func(f *fakeGitHub, request string, body []byte) {
			if request == "POST /app/installations/42/access_tokens" && strings.Contains(string(body), strconv.Itoa(oldID)) && !signed {
				signed = true
				w.adapter.presence.repositorySeen(refOf("acme/old"))
			}
		}
	})
	roundAt(p, clock, time.Hour)
	if !signed {
		t.Fatal("GitHub was asked for no token for acme/old alone")
	}
	keptOld(t, w)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	droppedOld(t, w)
}

// TestASignOfTheRepositoryDuringARoundStartsItsCountOver has GitHub answer a token for
// acme/old alone 422 while the installation's list does not hold it; in the next round,
// the round's listing names acme/old, and the list read after the refusal does not: the
// absence that round finds is a first again, so nothing is disconnected; the round after
// it disconnects acme/old.
func TestASignOfTheRepositoryDuringARoundStartsItsCountOver(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	roundAt(p, clock, 0)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.repos = []string{"acme/widgets", "acme/gadgets", "acme/old"}
		f.repoAfter = func(f *fakeGitHub, page int) {
			if page == 3 {
				f.repos, f.repoAfter = []string{"acme/widgets", "acme/gadgets"}, nil
			}
		}
	})
	roundAt(p, clock, time.Hour)
	keptOld(t, w)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if log := w.log.String(); strings.Count(log, absentLine("acme/old")) != 2 {
		t.Errorf("the log %s", log)
	}
	roundAt(p, clock, 2*time.Hour)
	droppedOld(t, w)
}

// TestAFirstAbsenceForgetsTheFailuresBefore has GitHub answer a token for acme/old alone
// 422 in three rounds: the first round's list fails at page 2, the second's finds
// acme/old absent, and Qory Apiary answers the third's disconnect 409
// connection_suspended. The first absence forgets the failure before it, so the failed
// disconnect is logged as a first failure.
func TestAFirstAbsenceForgetsTheFailuresBefore(t *testing.T) {
	w, p, clock := refusing(t, 1, "acme/widgets", "acme/gadgets")
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeDisconnect {
			return 409, `{"error":"connection_suspended"}`
		}
		return 0, ""
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 2 })
	roundAt(p, clock, 0)
	setGitHub(w.gh, func(f *fakeGitHub) { f.repoPageDown = 0 })
	roundAt(p, clock, time.Hour)
	roundAt(p, clock, 2*time.Hour)
	if n := len(w.apiary.sent(routeDisconnect)); n != 1 {
		t.Errorf("%d disconnects", n)
	}
	keptOld(t, w)
	if !strings.Contains(w.log.String(), `"msg":"pulling the collection failed","collection":"`+refOf("acme/old")+`","error":"disconnecting `+refOf("acme/old")+`: Qory Apiary answered 409 connection_suspended"`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAnAbsenceUnderAnotherInstallationCountsAsNone has GitHub refuse a token for
// acme/old alone 422 while the installation 42's list does not hold it, and then, once
// the store holds acme/old as the installation 9's, refuse it again while 9's list does
// not hold it: 9's absence is its first, so nothing is disconnected; a second under 9
// disconnects it.
func TestAnAbsenceUnderAnotherInstallationCountsAsNone(t *testing.T) {
	w, p, _ := refusing(t, 0, "acme/widgets")
	refused := fmt.Errorf("%w: %w", github.ErrMintRefused, github.ErrRepositoryRefused)
	ref := refOf("acme/old")
	none := func() *listedRepositories { return &listedRepositories{read: true, ids: map[int64]bool{}} }
	if err := p.refused(context.Background(), ref, oldID, 42, none(), refused); !errors.Is(err, errAbsentOnce) {
		t.Fatalf("under 42: %v", err)
	}
	setReach(w.st, ref, 9)
	grantedLink(w.st, 9, testConnection, linkLive)
	if err := p.refused(context.Background(), ref, oldID, 9, none(), refused); !errors.Is(err, errAbsentOnce) {
		t.Errorf("under 9: %v", err)
	}
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects after one absence under 9", n)
	}
	if err := p.refused(context.Background(), ref, oldID, 9, none(), refused); err != nil {
		t.Errorf("under 9 again: %v", err)
	}
	if n := len(w.apiary.sent(routeDisconnect)); n != 1 {
		t.Errorf("%d disconnects after two absences under 9", n)
	}
}

// TestAMintAnswered404IsNotConfirmed has GitHub answer a token for acme/old alone 404,
// which is not the 422: the installation's list is not read for it, nothing is
// disconnected, and the line says GitHub refuses the token.
func TestAMintAnswered404IsNotConfirmed(t *testing.T) {
	w, p, clock := refusing(t, 0, "acme/widgets")
	setGitHub(w.gh, func(f *fakeGitHub) { f.oldMintStatus = 404 })
	roundAt(p, clock, 0)
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if w.gh.listings() != 1 {
		t.Errorf("%d listings, want the round's alone", w.gh.listings())
	}
	keptOld(t, w)
	if !strings.Contains(w.log.String(), `"msg":"pulling the collection failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again","collection":"`+refOf("acme/old")+`"`) || strings.Contains(w.log.String(), "list of repositories") {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestARepositoryRemovedByTheWebhookAndRefusedByTheRoundIsDisconnectedOnce has the
// removal of acme/old from the installation seen by its webhook and by a round, in
// either order: one disconnect in all, and the next round forgets what the round found
// of acme/old.
func TestARepositoryRemovedByTheWebhookAndRefusedByTheRoundIsDisconnectedOnce(t *testing.T) {
	removed := map[string]any{"action": "removed", "installation": map[string]any{"id": 42}, "repositories_removed": []any{map[string]any{"id": oldID, "full_name": "acme/old"}}}
	for _, webhookFirst := range []bool{true, false} {
		w, p, clock := refusing(t, 0, "acme/widgets")
		if webhookFirst {
			w.deliver(t, "installation_repositories", guid1, removed)
		}
		roundAt(p, clock, 0)
		if !webhookFirst {
			w.deliver(t, "installation_repositories", guid1, removed)
		}
		if n := len(w.apiary.sent(routeDisconnect)); n != 1 {
			t.Errorf("the webhook first %v: %d disconnects", webhookFirst, n)
		}
		if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
			t.Errorf("the webhook first %v: acme/old's installation is kept", webhookFirst)
		}
		roundAt(p, clock, time.Hour)
		if _, absent := w.adapter.presence.counts(); absent != 0 {
			t.Errorf("the webhook first %v: the adapter keeps %d absences", webhookFirst, absent)
		}
	}
}

// TestARefusedRepositoryReachedByAnotherInstallationIsNotDisconnected has the store hold
// acme/old as the installation 9's by the time the installation 42's list confirms it
// no longer holds it: nothing is disconnected, and a line says so.
func TestARefusedRepositoryReachedByAnotherInstallationIsNotDisconnected(t *testing.T) {
	w, _, _ := refusing(t, 0, "acme/widgets")
	setReach(w.st, refOf("acme/old"), 9)
	refused := fmt.Errorf("%w: %w", github.ErrMintRefused, github.ErrRepositoryRefused)
	if _, err := w.adapter.dropRefused(context.Background(), refOf("acme/old"), oldID, 42, &listedRepositories{}, refused); err != nil {
		t.Fatal(err)
	}
	if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
		t.Errorf("%d disconnects", n)
	}
	if !strings.Contains(w.log.String(), `"msg":"the repository is not one serve listed for the installation, so nothing is disconnected","collection":"`+refOf("acme/old")+`","installation":42`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAMintRefusedWithoutTheChecks404NeverEndsTheInstallation has GitHub refuse the
// round's listing token for good without answering 404 to the installation's check: the
// check answers 200 and the mint 404, or the check answers a login that is no login.
// Neither ends the installation: no POST /v1/grants/end is sent, the link
// and the records stay, and the listing's failure is logged as GitHub refusing the
// token.
func TestAMintRefusedWithoutTheChecks404NeverEndsTheInstallation(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(f *fakeGitHub)
	}{
		{"the mint answers 404", func(f *fakeGitHub) { f.listingMintStatus = 404 }},
		{"the check answers no login", func(f *fakeGitHub) { f.installLogin = "not a login" }},
	} {
		w, _, p, _ := pulling(t)
		keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart})
		setGitHub(w.gh, tc.set)
		p.round(context.Background(), pullStart, time.Hour)
		p.rounds.Wait()
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 0 {
			t.Errorf("%s: %d grant ends", tc.name, n)
		}
		if l, ok, _ := linkOf(w.st, 42); !ok || l.State != linkLive {
			t.Errorf("%s: the link changed", tc.name)
		}
		if inst, ok, _ := reachOf(w.st, refOf("acme/widgets")); !ok || inst != 42 {
			t.Errorf("%s: the repository's installation is dropped", tc.name)
		}
		if ok, _ := wasDeleted(w.st, 42); ok {
			t.Errorf("%s: the installation is kept as deleted", tc.name)
		}
		log := w.log.String()
		if !strings.Contains(log, `"msg":"listing the installation's repositories failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again","installation":42,"error":"listing the installation's repositories: the installation token: GitHub refuses to mint the installation token: `) || strings.Contains(log, endedLine) {
			t.Errorf("%s: the log %s", tc.name, log)
		}
	}
}

// TestARefusedRepositoryWithNoMarkIsConfirmedAtEachRead runs a round of acme/old with
// no pull mark, so the pull reads the repository by its id, then lists its open issues.
// GitHub refuses a token for acme/old alone 422 at the read, or grants the read's token
// and refuses the next at the listing of open issues, the read's token being dropped
// meanwhile: either way, the round finds acme/old absent when the installation's list
// of repositories no longer holds it, and the next round, which GitHub mints no token
// for acme/old alone, as a token minted would say GitHub holds it, disconnects it; the
// rounds keep it when the list still does.
func TestARefusedRepositoryWithNoMarkIsConfirmedAtEachRead(t *testing.T) {
	for _, at := range []string{"the read", "the listing of open issues"} {
		for _, listed := range []bool{false, true} {
			repos := []string{"acme/widgets"}
			if listed {
				repos = append(repos, "acme/old")
			}
			w, p, clock := refusing(t, 0, repos...)
			if err := w.st.Delete(nsPulls, collectionKey(refOf("acme/old"))); err != nil {
				t.Fatal(err)
			}
			if at == "the listing of open issues" {
				setGitHub(w.gh, func(f *fakeGitHub) {
					f.oldGrant, f.oldPublic = 1, true
					f.oldRead = func() { w.adapter.forgetTokens(42) }
				})
			}
			roundAt(p, clock, 0)
			if !listed && strings.Count(w.log.String(), absentLine("acme/old")) != 1 {
				t.Errorf("%s: after the first round, the log %s", at, w.log.String())
			}
			roundAt(p, clock, time.Hour)
			log := w.log.String()
			// The read of acme/old by its id is answered only when its token was granted.
			if read := slices.Contains(w.gh.repositoryReads(), "GET /repositories/"+strconv.Itoa(oldID)); read != (at == "the listing of open issues") {
				t.Errorf("%s, listed %v: acme/old read %v", at, listed, read)
			}
			if listed {
				if n := len(w.apiary.sent(routeDisconnect)); n != 0 {
					t.Errorf("%s, listed: %d disconnects", at, n)
				}
				if inst, ok, _ := reachOf(w.st, refOf("acme/old")); !ok || inst != 42 {
					t.Errorf("%s, listed: acme/old's installation is dropped", at)
				}
				if strings.Count(log, stillListedLine) != 1 {
					t.Errorf("%s, listed: the log %s", at, log)
				}
				continue
			}
			sent := w.apiary.sent(routeDisconnect)
			if len(sent) != 1 || sent[0].body["collection_ref"] != refOf("acme/old") {
				t.Errorf("%s: sent %v", at, sent)
			}
			if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
				t.Errorf("%s: acme/old's installation is kept", at)
			}
			if strings.Count(log, disconnectedLine) != 1 {
				t.Errorf("%s: the log %s", at, log)
			}
		}
	}
}

// TestAnEndThatFailsStopsTheRound has the installation 42's check return 404 in two
// rounds, and the second's POST /v1/grants/end return 503: a line says the grant end
// is sent again, the link stays, and none of 42's collections is
// pulled in either round.
func TestAnEndThatFailsStopsTheRound(t *testing.T) {
	w, _, p, clock := pulling(t)
	mark := pullMark{Since: pullStart.Add(-time.Hour), Listed: pullStart}
	keepPulled(w.st, refOf("acme/widgets"), mark)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrantsEnd {
			return 503, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	roundAt(p, clock, 0)
	roundAt(p, clock, time.Hour)
	log := w.log.String()
	if strings.Count(log, endedLine) != 1 || !strings.Contains(log, `"msg":"reporting the end of the installation's grant to Qory Apiary failed, so serve sends it again later","installation":42`) {
		t.Errorf("the log %s", log)
	}
	if _, ok, _ := linkOf(w.st, 42); !ok {
		t.Error("the link is dropped")
	}
	if reads := w.gh.repositoryReads(); len(reads) != 0 {
		t.Errorf("GitHub was read: %v", reads)
	}
	// A pull would ask for a token for acme/widgets, whose mint checks 42 again: the
	// checks are the two listings' alone.
	if n := w.gh.repositoryMints(); n != 1 || strings.Contains(log, `"msg":"pulling the collection`) {
		t.Errorf("%d checks after the first listing's; the log %s", n, log)
	}
	if m := markOf(t, w); !m.Since.Equal(mark.Since) {
		t.Errorf("the collection is pulled: %+v", m)
	}
}

// TestAGrantEndRefusedForGoodIsNotSentByLaterRounds has the installation 42's check
// return 404 in four rounds, and the grant end return 403 forbidden: the second round
// sends it once, with a line, and the link stays; the
// third and fourth rounds send no grant end and log no other line that the
// installation is handled as deleted.
func TestAGrantEndRefusedForGoodIsNotSentByLaterRounds(t *testing.T) {
	w, _, p, clock := pulling(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.installGone = true })
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrantsEnd {
			return 403, `{"error":"forbidden"}`
		}
		return 0, ""
	}
	roundAt(p, clock, 0)
	roundAt(p, clock, time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Fatalf("%d grant ends after two rounds", n)
	}
	roundAt(p, clock, 2*time.Hour)
	roundAt(p, clock, 3*time.Hour)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends after four rounds", n)
	}
	if log := w.log.String(); strings.Count(log, endedLine) != 1 || strings.Count(log, `"msg":"Qory Apiary returned an error for the end of the installation's grant that a retry does not change`) != 1 {
		t.Errorf("the log %s", log)
	}
	if _, ok, _ := linkOf(w.st, 42); !ok {
		t.Error("the link is dropped")
	}
	if held, _ := grantOf(w.st, 42); held != testConnection {
		t.Errorf("the grant is %q", held)
	}
}
