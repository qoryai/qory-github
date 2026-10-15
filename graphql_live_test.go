//go:build githublive

package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLiveCursorListingSkipsNoIssue shows against GitHub itself that a listing of a
// repository's open issues by GraphQL's cursor, [Lister.ListOpenIssuesComplete]'s
// paging, holds every issue open for the whole listing exactly once while issues are
// closed, created, edited, reopened and deleted between its pages; that is what lets
// that listing say it is complete. The same scenarios run against REST's listing of
// issues as [Lister.ListIssues] reads it, every state, and of the open issues alone,
// each following the next page GitHub's Link header names, for contrast: those results
// are logged, never failed on. GitHub's Link header names the next page by a cursor,
// after, as well as by number, so these too read by cursor; neither is the listing by
// page number alone, which this test does not run.
//
// It runs only with the build tag githublive, and only when QORY_GITHUB_LIVE_REPO names
// a repository, owner/name, that the token in QORY_GITHUB_LIVE_TOKEN may write issues
// in and delete them from, which deleting takes a repository's admin for. Use a private
// repository kept for tests. It creates about 30 issues there, titled with a prefix of
// this run, one a second, and touches no issue it did not create: it counts the others
// a listing sees, never edits them. When it ends, failed or not, it deletes every issue
// it created, closes one it cannot delete, and checks no issue of the run is left open.
// Each issue it creates is kept, as it goes, in a file named for the run in
// QORY_GITHUB_LIVE_LEDGER, a directory, or else the system's temporary directory, so a
// run that dies can be cleaned up by hand. The token is read from the environment and
// is never written or said.
//
//	QORY_GITHUB_LIVE_REPO=owner/name QORY_GITHUB_LIVE_TOKEN=... \
//	  go test -tags githublive -run TestLiveCursorListingSkipsNoIssue -v -timeout 30m .
func TestLiveCursorListingSkipsNoIssue(t *testing.T) {
	repos, err := ParseRepositories(os.Getenv("QORY_GITHUB_LIVE_REPO"))
	token := os.Getenv("QORY_GITHUB_LIVE_TOKEN")
	if err != nil || len(repos) != 1 || token == "" {
		t.Skip("QORY_GITHUB_LIVE_REPO, one owner/name, and QORY_GITHUB_LIVE_TOKEN are not set")
	}
	ctx := context.Background()
	lv := &live{
		t:     t,
		repo:  repos[0],
		token: token,
		p:     &Pacer{},
		run:   time.Now().UTC().Format("20060102T150405Z"),
	}
	lv.prefix = "qory-github cursor test " + lv.run + " #"
	dir := os.Getenv("QORY_GITHUB_LIVE_LEDGER")
	if dir == "" {
		dir = os.TempDir()
	}
	lv.ledger = filepath.Join(dir, "graphql-live-"+lv.run+".json")
	t.Logf("run %s in %s; the issues it creates are kept in %s", lv.run, lv.repo, lv.ledger)
	t.Cleanup(lv.cleanup)
	lv.save()

	const initial = 24
	for range initial {
		lv.create(ctx, t)
	}

	t.Run("a close an issue on a page already read", func(t *testing.T) {
		lv.scenario(ctx, t, "a", func(s *scene) {
			read := s.readByAll()
			lv.close(ctx, s, s.cursor())
			lv.close(ctx, s, pick(t, read, s.cursor(), 1))
		})
	})
	t.Run("b close an issue on a page not yet read", func(t *testing.T) {
		lv.scenario(ctx, t, "b", func(s *scene) {
			unread := s.unreadByAll()
			lv.close(ctx, s, unread[len(unread)/2])
		})
	})
	t.Run("c create issues", func(t *testing.T) {
		lv.scenario(ctx, t, "c", func(s *scene) {
			s.touch(lv.create(ctx, s.t))
			s.touch(lv.create(ctx, s.t))
		})
	})
	t.Run("d edit an issue on a page read and one not", func(t *testing.T) {
		lv.scenario(ctx, t, "d", func(s *scene) {
			read, unread := s.readByAll(), s.unreadByAll()
			lv.edit(ctx, s, pick(t, read, s.cursor(), 1))
			lv.edit(ctx, s, unread[len(unread)/2])
		})
	})
	t.Run("e reopen closed issues", func(t *testing.T) {
		lv.scenario(ctx, t, "e", func(s *scene) {
			var behind, ahead *liveIssue
			for _, is := range lv.issues() {
				switch {
				case is.State != "closed":
				case is.Number < s.cursor() && behind == nil:
					behind = is
				case is.Number > s.cursor() && ahead == nil:
					ahead = is
				}
			}
			for _, is := range []*liveIssue{behind, ahead} {
				if is != nil {
					lv.reopen(ctx, s, is.Number)
				}
			}
		})
	})
	t.Run("f delete issues", func(t *testing.T) {
		lv.scenario(ctx, t, "f", func(s *scene) {
			read, unread := s.readByAll(), s.unreadByAll()
			cur := s.cursor()
			lv.remove(ctx, s, pick(t, read, cur, 1))
			lv.remove(ctx, s, cur)
			lv.remove(ctx, s, unread[len(unread)/2])
		})
	})
	t.Run("g transfer an issue", func(t *testing.T) {
		t.Skip("a transfer needs a second repository, which this test does not create")
	})

	t.Run("the complete listing", func(t *testing.T) {
		s := &sink{}
		l := lv.lister()
		l.Sink = s
		if err := l.ListOpenIssuesComplete(ctx, lv.repo); err != nil {
			t.Fatal(err)
		}
		refs, parts := sentParts(s)
		for _, is := range lv.issues() {
			ref := lv.repo.String() + "#" + strconv.FormatInt(is.Number, 10)
			if got := slices.Contains(refs, ref); got != (is.State == "open") {
				t.Errorf("%s, %s: sent %v", ref, is.State, got)
			}
		}
		if len(parts) == 0 || !parts[len(parts)-1].Complete {
			t.Errorf("parts %+v", parts)
		}
		for _, why := range s.broken {
			t.Errorf("a request breaks the contract: %s", why)
		}
		t.Logf("sent %d items in %d parts, the last complete", len(refs), len(parts))
	})
}

// live is one run of the test against GitHub.
type live struct {
	t      *testing.T
	repo   Repository
	token  string
	p      *Pacer
	run    string
	prefix string
	ledger string

	mu      sync.Mutex
	created []*liveIssue
	results []liveResult
}

// liveIssue is an issue the test created: its number, node id and title, its state as
// the test left it, open, closed or deleted, and how the cleanup removed it.
type liveIssue struct {
	Number  int64  `json:"number"`
	NodeID  string `json:"node_id"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Removed string `json:"removed,omitempty"`
}

// liveResult is how one listing held up in one scenario.
type liveResult struct {
	Scenario string  `json:"scenario"`
	Listing  string  `json:"listing"`
	Pass     bool    `json:"pass"`
	Expected int     `json:"expected"`
	Missing  []int64 `json:"missing"`
	Twice    []int64 `json:"twice"`
	Pages    int     `json:"pages"`
}

func (lv *live) issues() []*liveIssue {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	return slices.Clone(lv.created)
}

// mine is the issue number of the test's, or nil: the test never touches another.
func (lv *live) mine(n int64) *liveIssue {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	for _, is := range lv.created {
		if is.Number == n {
			return is
		}
	}
	return nil
}

// save writes the ledger: the run, its issues and the results so far.
func (lv *live) save() {
	lv.mu.Lock()
	b, _ := json.MarshalIndent(map[string]any{"run": lv.run, "repository": lv.repo.String(), "prefix": lv.prefix, "issues": lv.created, "results": lv.results}, "", "  ")
	lv.mu.Unlock()
	if err := os.WriteFile(lv.ledger, b, 0o600); err != nil {
		lv.t.Errorf("writing the ledger: %v", err)
	}
}

// call sends one REST request and decodes a 2xx answer into out.
func (lv *live) call(ctx context.Context, what, method, path string, body, out any) error {
	a, err := lv.client().send(ctx, lv.p, false, what, method, path, lv.token, body)
	if err != nil {
		return err
	}
	if a.status/100 != 2 {
		return a.err(what)
	}
	if out != nil {
		return json.Unmarshal(a.body, out)
	}
	return nil
}

// graphql sends one GraphQL request and fails on any error it answers.
func (lv *live) graphql(ctx context.Context, what, query string, vars map[string]any) error {
	var got struct {
		Errors []gqlError `json:"errors"`
	}
	if err := lv.call(ctx, what, http.MethodPost, "/graphql", map[string]any{"query": query, "variables": vars}, &got); err != nil {
		return err
	}
	if len(got.Errors) > 0 {
		return fmt.Errorf("%s: GraphQL answered %s: %s", what, got.Errors[0].Type, got.Errors[0].Message)
	}
	return nil
}

func (lv *live) client() Client { return Client{HTTP: &http.Client{Timeout: 60 * time.Second}} }

func (lv *live) lister() Lister {
	return Lister{
		Client: lv.client(),
		Pacer:  lv.p,
		Token:  func(context.Context) (string, error) { return lv.token, nil },
		Slug:   "qory-github-live-test",
		Logf:   lv.t.Logf,
	}
}

// create creates the next issue of the run, a second after the one before it, and
// records it before anything else.
func (lv *live) create(ctx context.Context, t *testing.T) int64 {
	t.Helper()
	time.Sleep(time.Second)
	k := len(lv.issues()) + 1
	title := lv.prefix + strconv.Itoa(k)
	var got struct {
		Number int64  `json:"number"`
		NodeID string `json:"node_id"`
	}
	if err := lv.call(ctx, "creating an issue", http.MethodPost, "/repos/"+lv.repo.String()+"/issues", map[string]any{"title": title, "body": "Made by qory-github's live test of cursor listing; it deletes this issue when it ends."}, &got); err != nil {
		t.Fatal(err)
	}
	lv.mu.Lock()
	lv.created = append(lv.created, &liveIssue{Number: got.Number, NodeID: got.NodeID, Title: title, State: "open"})
	lv.mu.Unlock()
	lv.save()
	return got.Number
}

// patch changes the test's issue n.
func (lv *live) patch(ctx context.Context, t *testing.T, what string, n int64, body map[string]any) {
	t.Helper()
	if lv.mine(n) == nil {
		t.Fatalf("%s: #%d is not an issue this test created", what, n)
	}
	if err := lv.call(ctx, what, http.MethodPatch, "/repos/"+lv.repo.String()+"/issues/"+strconv.FormatInt(n, 10), body, nil); err != nil {
		t.Fatal(err)
	}
}

func (lv *live) close(ctx context.Context, s *scene, n int64) {
	lv.patch(ctx, s.t, "closing an issue", n, map[string]any{"state": "closed"})
	lv.setState(n, "closed")
	s.touch(n)
	s.did("closed #%d", n)
}

func (lv *live) reopen(ctx context.Context, s *scene, n int64) {
	lv.patch(ctx, s.t, "reopening an issue", n, map[string]any{"state": "open"})
	lv.setState(n, "open")
	s.touch(n)
	s.did("reopened #%d", n)
}

// edit changes the title and body of the test's issue n, keeping its prefix, which an
// edit must not move in the order of creation.
func (lv *live) edit(ctx context.Context, s *scene, n int64) {
	is := lv.mine(n)
	if is == nil {
		s.t.Fatalf("editing: #%d is not an issue this test created", n)
	}
	lv.patch(ctx, s.t, "editing an issue", n, map[string]any{"title": is.Title + " (edited)", "body": "Edited by qory-github's live test of cursor listing."})
	lv.mu.Lock()
	is.Title += " (edited)"
	lv.mu.Unlock()
	lv.save()
	s.did("edited #%d", n)
}

// remove deletes the test's issue n, which GraphQL's deleteIssue does.
func (lv *live) remove(ctx context.Context, s *scene, n int64) {
	s.t.Helper()
	is := lv.mine(n)
	if is == nil {
		s.t.Fatalf("deleting: #%d is not an issue this test created", n)
	}
	if err := lv.deleteIssue(ctx, is); err != nil {
		s.t.Fatal(err)
	}
	s.touch(n)
	s.did("deleted #%d", n)
}

func (lv *live) deleteIssue(ctx context.Context, is *liveIssue) error {
	err := lv.graphql(ctx, "deleting an issue", `mutation($id: ID!) { deleteIssue(input: {issueId: $id}) { clientMutationId } }`, map[string]any{"id": is.NodeID})
	if err == nil {
		lv.mu.Lock()
		is.State, is.Removed = "deleted", "deleted"
		lv.mu.Unlock()
		lv.save()
	}
	return err
}

func (lv *live) setState(n int64, state string) {
	lv.mu.Lock()
	for _, is := range lv.created {
		if is.Number == n {
			is.State = state
		}
	}
	lv.mu.Unlock()
	lv.save()
}

// openNow is the repository's open issues now, pull requests left out, by number, and
// their titles.
func (lv *live) openNow(ctx context.Context, t *testing.T) map[int64]string {
	t.Helper()
	l := lv.lister()
	out := map[int64]string{}
	path := "/repos/" + lv.repo.String() + "/issues?state=open&per_page=100"
	for path != "" {
		var page []ghIssue
		next, err := l.get(ctx, lv.p, "listing the open issues", path, &page)
		if err != nil {
			t.Fatal(err)
		}
		for _, is := range page {
			if is.PullRequest == nil {
				out[is.Number] = is.Title
			}
		}
		path = next
	}
	return out
}

// pager reads one page of open issue numbers at a time, or false once it has read the
// last.
type pager interface {
	next(ctx context.Context) ([]int64, bool, error)
}

// cursorPager is the complete listing's paging, [Lister.issuePager].
type cursorPager struct{ g *issuePager }

func (c cursorPager) next(ctx context.Context) ([]int64, bool, error) {
	_, page, more, err := c.g.next(ctx)
	var ns []int64
	for _, is := range page {
		if is.State == StateOpen {
			ns = append(ns, is.Number)
		}
	}
	return ns, more, err
}

// restPager is REST's paging by number, oldest first, of the issues in state, all or
// open, the open ones kept and pull requests left out.
type restPager struct {
	l    Lister
	p    *Pacer
	path string
}

func (r *restPager) next(ctx context.Context) ([]int64, bool, error) {
	if r.path == "" {
		return nil, false, nil
	}
	var page []ghIssue
	next, err := r.l.get(ctx, r.p, "listing the issues by page", r.path, &page)
	if err != nil {
		return nil, false, err
	}
	r.path = next
	var ns []int64
	for _, is := range page {
		if is.PullRequest == nil && is.State == StateOpen {
			ns = append(ns, is.Number)
		}
	}
	return ns, true, nil
}

// livePageSize is how many issues a page of each listing holds: few, so a listing of
// the run's issues has many pages.
const livePageSize = 3

// reading is one listing in a scenario: what it has read, how often each, and its last
// page.
type reading struct {
	name  string
	pg    pager
	seen  map[int64]int
	last  []int64
	pages int
	done  bool
}

func (r *reading) step(ctx context.Context, t *testing.T) {
	t.Helper()
	ns, more, err := r.pg.next(ctx)
	if err != nil {
		t.Fatalf("%s: %v", r.name, err)
	}
	if !more {
		r.done = true
		return
	}
	r.pages++
	r.last = ns
	for _, n := range ns {
		r.seen[n]++
	}
}

// until reads pages until it has read n or its last page.
func (r *reading) until(ctx context.Context, t *testing.T, n int64) {
	for !r.done && r.seen[n] == 0 {
		r.step(ctx, t)
	}
}

// scene is one scenario's listings and what it changed while they ran.
type scene struct {
	t        *testing.T
	lv       *live
	readings []*reading
	touched  map[int64]bool
	cur      int64
}

// touch marks issue n changed in a way that leaves it not open for the whole listing.
func (s *scene) touch(n int64) { s.touched[n] = true }

func (s *scene) did(format string, args ...any) { s.t.Logf(format, args...) }

// cursor is the last issue the cursor listing read, the one its next page starts after.
func (s *scene) cursor() int64 { return s.cur }

// readByAll are the test's open issues every listing has read, oldest first.
func (s *scene) readByAll() []int64 {
	var out []int64
	for _, is := range s.lv.issues() {
		if is.State != "open" {
			continue
		}
		all := true
		for _, r := range s.readings {
			all = all && r.seen[is.Number] > 0
		}
		if all {
			out = append(out, is.Number)
		}
	}
	return out
}

// unreadByAll are the test's open issues no listing has read, oldest first.
func (s *scene) unreadByAll() []int64 {
	var out []int64
	for _, is := range s.lv.issues() {
		if is.State != "open" {
			continue
		}
		none := true
		for _, r := range s.readings {
			none = none && r.seen[is.Number] == 0
		}
		if none {
			out = append(out, is.Number)
		}
	}
	if len(out) == 0 {
		s.t.Fatal("no issue of the test is unread by every listing")
	}
	return out
}

// pick is the issue of ns that is k before not, or the last before it.
func pick(t *testing.T, ns []int64, not int64, k int) int64 {
	t.Helper()
	var before []int64
	for _, n := range ns {
		if n < not {
			before = append(before, n)
		}
	}
	if len(before) == 0 {
		t.Fatal("no issue read before the cursor's")
	}
	return before[max(len(before)-k-1, 0)]
}

// scenario lists the repository's open issues by the three listings side by side,
// changes issues with change once each has read past the same place, reads them to the
// end, and checks that every issue open for the whole listing, open before and after
// it and not changed by it, was read by each exactly once.
func (lv *live) scenario(ctx context.Context, t *testing.T, name string, change func(*scene)) {
	before := lv.openNow(ctx, t)
	l := lv.lister()
	base := "/repos/" + lv.repo.String() + "/issues?sort=created&direction=asc&per_page=" + strconv.Itoa(livePageSize)
	g := l.issuePager(lv.p, lv.repo, livePageSize)
	s := &scene{t: t, lv: lv, touched: map[int64]bool{}, readings: []*reading{
		{name: "graphql-cursor", pg: cursorPager{g}, seen: map[int64]int{}},
		{name: "rest-all-states", pg: &restPager{l: l, p: lv.p, path: base + "&state=all"}, seen: map[int64]int{}},
		{name: "rest-open", pg: &restPager{l: l, p: lv.p, path: base + "&state=open"}, seen: map[int64]int{}},
	}}
	var open []int64
	for _, is := range lv.issues() {
		if is.State == "open" {
			open = append(open, is.Number)
		}
	}
	anchor := open[len(open)/3]
	cursorListing := s.readings[0]
	cursorListing.until(ctx, t, anchor)
	s.cur = cursorListing.last[len(cursorListing.last)-1]
	if lv.mine(s.cur) == nil {
		t.Fatalf("the cursor's issue #%d is not the test's", s.cur)
	}
	for _, r := range s.readings[1:] {
		r.until(ctx, t, s.cur)
	}
	t.Logf("each listing has read #%d, the cursor listing's last; its cursor %s", s.cur, decodeCursor(g.after))
	change(s)
	// A change GitHub took is read by the next request; the wait lets it reach every
	// replica first.
	time.Sleep(3 * time.Second)
	for _, r := range s.readings {
		for !r.done {
			r.step(ctx, t)
		}
	}
	after := lv.openNow(ctx, t)
	var expected []int64
	for n := range before {
		if _, ok := after[n]; ok && !s.touched[n] {
			expected = append(expected, n)
		}
	}
	slices.Sort(expected)
	others := 0
	for _, n := range expected {
		if lv.mine(n) == nil {
			others++
		}
	}
	for _, r := range s.readings {
		res := liveResult{Scenario: name, Listing: r.name, Expected: len(expected), Pages: r.pages, Missing: []int64{}, Twice: []int64{}}
		for _, n := range expected {
			switch c := r.seen[n]; {
			case c == 0:
				res.Missing = append(res.Missing, n)
			case c > 1:
				res.Twice = append(res.Twice, n)
			}
		}
		res.Pass = len(res.Missing) == 0 && len(res.Twice) == 0
		lv.mu.Lock()
		lv.results = append(lv.results, res)
		lv.mu.Unlock()
		verdict := "pass"
		if !res.Pass {
			verdict = "FAIL"
		}
		line := fmt.Sprintf("RESULT %s %s: %s; %d open for the whole listing, %d of them not the test's; %d pages; missing %v; read twice %v", name, r.name, verdict, len(expected), others, r.pages, res.Missing, res.Twice)
		if r.name == "graphql-cursor" && !res.Pass {
			t.Error(line)
		} else {
			t.Log(line)
		}
	}
	lv.save()
}

// decodeCursor is a GraphQL cursor as it is encoded, for the log: GitHub's cursors are
// base64, and say no secret.
func decodeCursor(c string) string {
	b, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return strconv.Quote(c)
	}
	return fmt.Sprintf("%q, decoded %q", c, b)
}

// cleanup deletes every issue the test created and has not deleted, closes one it
// cannot delete, and checks no issue of the run is left open.
func (lv *live) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, is := range lv.issues() {
		if is.State == "deleted" {
			continue
		}
		time.Sleep(500 * time.Millisecond)
		if err := lv.deleteIssue(ctx, is); err == nil {
			continue
		} else {
			lv.t.Errorf("cleanup: deleting #%d: %v", is.Number, err)
		}
		err := lv.call(ctx, "closing an issue", http.MethodPatch, "/repos/"+lv.repo.String()+"/issues/"+strconv.FormatInt(is.Number, 10), map[string]any{"state": "closed"}, nil)
		lv.mu.Lock()
		if err == nil {
			is.State, is.Removed = "closed", "closed, as it could not be deleted"
		} else {
			is.Removed = "left: " + err.Error()
		}
		lv.mu.Unlock()
		lv.save()
	}
	var left []string
	for n, title := range lv.openNow(ctx, lv.t) {
		if strings.HasPrefix(title, lv.prefix) {
			left = append(left, "#"+strconv.FormatInt(n, 10))
		}
	}
	gone := 0
	for _, is := range lv.issues() {
		a, err := lv.client().send(ctx, lv.p, false, "reading an issue", http.MethodGet, "/repos/"+lv.repo.String()+"/issues/"+strconv.FormatInt(is.Number, 10), lv.token, nil)
		if err == nil && (a.status == http.StatusGone || a.status == http.StatusNotFound) {
			gone++
		}
	}
	if len(left) > 0 {
		lv.t.Errorf("cleanup: issues of the run left open: %v", left)
	}
	lv.t.Logf("cleanup: %d issues created, %d answer gone, %d of the run left open", len(lv.issues()), gone, len(left))
}
