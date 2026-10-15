package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// fakeChanged is GitHub's API as a pull reads it: acme/widgets, and its issues and its
// comments as GitHub lists what changed: those updated at or after since, oldest first,
// in the order they were added within one second, per_page to a page, paged by number.
// after, when set, is called with f.mu held after each page of issues or comments is
// answered, with the path, as GitHub changes between two pages. gone answers the
// repository 404. It records the requests it is asked for.
type fakeChanged struct {
	srv      *httptest.Server
	mu       sync.Mutex
	issues   []map[string]any
	comments []map[string]any
	after    func(path string)
	gone     bool
	paths    []string
}

func (f *fakeChanged) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	serve := func(all []map[string]any) {
		q := r.URL.Query()
		since, err := time.Parse(time.RFC3339, q.Get("since"))
		if err != nil || q.Get("sort") != "updated" || q.Get("direction") != "asc" {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"Validation Failed"}`)
			return
		}
		per, _ := strconv.Atoi(q.Get("per_page"))
		page, _ := strconv.Atoi(q.Get("page"))
		page = max(page, 1)
		var in []map[string]any
		for _, x := range all {
			if t, _ := time.Parse(time.RFC3339, x["updated_at"].(string)); !t.Before(since) {
				in = append(in, x)
			}
		}
		slices.SortStableFunc(in, func(a, b map[string]any) int {
			return strings.Compare(a["updated_at"].(string), b["updated_at"].(string))
		})
		lo, hi := min((page-1)*per, len(in)), min(page*per, len(in))
		json.NewEncoder(w).Encode(append([]map[string]any{}, in[lo:hi]...))
		if f.after != nil {
			f.after(r.URL.Path)
		}
	}
	switch r.URL.Path {
	case "/repos/acme/widgets":
		if f.gone {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		io.WriteString(w, `{"full_name":"acme/widgets","html_url":"https://github.com/acme/widgets"}`)
	case "/repos/acme/widgets/issues":
		serve(f.issues)
	case "/repos/acme/widgets/issues/comments":
		serve(f.comments)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// asked are the queries of the requests for path, in order.
func (f *fakeChanged) asked(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, p := range f.paths {
		if q, ok := strings.CutPrefix(p, path+"?"); ok {
			out = append(out, q)
		}
	}
	return out
}

// lister lists f into s, with a clock that never sleeps, and records what it logs.
func (f *fakeChanged) lister(t *testing.T, s *sink, logs *[]string) Lister {
	t.Helper()
	l := (&fakeIssues{}).lister(t, s, logs)
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	l.Client = Client{API: f.srv.URL}
	return l
}

// pullSince is the time the tests' pulls ask from.
var pullSince = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// changedAt is the time n seconds after pullSince, as GitHub writes it, and escaped is
// it as a query carries it.
func changedAt(n int) string {
	return pullSince.Add(time.Duration(n) * time.Second).Format(time.RFC3339)
}

func escaped(n int) string { return strings.ReplaceAll(changedAt(n), ":", "%3A") }

// changedIssue is issue n, last changed at changedAt(at).
func changedIssue(n, at int) map[string]any {
	is := issue(n, 0)
	is["updated_at"] = changedAt(at)
	return is
}

// repoComment is a comment with id id on the issue or pull request n, its page under
// kind, issues or pull, as GitHub lists a repository's comments, last changed at
// changedAt(at).
func repoComment(id int, kind string, n, at int, login, typ, body string) map[string]any {
	c := comment(id, login, typ, body)
	c["html_url"] = "https://github.com/acme/widgets/" + kind + "/" + strconv.Itoa(n) + "#issuecomment-" + strconv.Itoa(id)
	c["issue_url"] = "https://api.github.com/repos/acme/widgets/issues/" + strconv.Itoa(n)
	c["updated_at"] = changedAt(at)
	return c
}

// sentItems are the items s was sent, in order, each its ref and its updated_at.
func sentItems(t *testing.T, s *sink) []string {
	t.Helper()
	var out []string
	for _, req := range s.items() {
		if req.Listing != nil {
			t.Errorf("a pull sent a listing's part: %+v", req.Listing)
		}
		for _, it := range req.Items {
			out = append(out, it.Ref+" "+it.UpdatedAt)
		}
	}
	return out
}

// TestAPullSendsWhatChangedInEveryStateAndTheCommentsByItem lists what changed, an
// issue closed and a pull request among it, and checks the requests ask from the time
// given, every state's, oldest change first; the items are sent as an event, closed ones
// with their reason, and the comments grouped by item, none complete; a pull request's
// comment and the App's work item comment are left out, and a comment that names no
// issue is skipped by its ref.
func TestAPullSendsWhatChangedInEveryStateAndTheCommentsByItem(t *testing.T) {
	closed := changedIssue(2, 2)
	closed["state"], closed["state_reason"] = "closed", "not_planned"
	pr := changedIssue(3, 3)
	pr["pull_request"] = map[string]any{"url": "https://api.github.com/repos/acme/widgets/pulls/3"}
	noIssue := repoComment(51, "issues", 1, 6, "bob", "User", "Lost.")
	noIssue["issue_url"] = "https://api.github.com/repos/acme/widgets"
	f := &fakeChanged{
		issues: []map[string]any{changedIssue(1, 1), closed, pr, changedIssue(4, 4), changedIssue(5, -10)},
		comments: []map[string]any{
			repoComment(11, "issues", 1, 1, "bob", "User", "First."),
			repoComment(21, "issues", 2, 2, "carol", "User", "Closed it."),
			repoComment(12, "issues", 1, 3, "bob", "User", "Again."),
			repoComment(31, "pull", 3, 4, "bob", "User", "On a pull request."),
			repoComment(13, "issues", 1, 5, "qory-test[bot]", "Bot", "<!-- qory:work-item 7 -->"),
			noIssue,
		},
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, pullSince.In(time.FixedZone("CET", 3600)).Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if got := f.asked("/repos/acme/widgets/issues"); !slices.Equal(got, []string{"state=all&sort=updated&direction=asc&since=" + escaped(0) + "&per_page=100"}) {
		t.Errorf("asked for issues %v", got)
	}
	if got := f.asked("/repos/acme/widgets/issues/comments"); !slices.Equal(got, []string{"sort=updated&direction=asc&since=" + escaped(0) + "&per_page=100"}) {
		t.Errorf("asked for comments %v", got)
	}
	items := s.items()
	if len(items) != 1 || items[0].CollectionRef != "acme/widgets" || items[0].Listing != nil {
		t.Fatalf("items requests %+v", items)
	}
	var got []string
	for _, it := range items[0].Items {
		reason := ""
		if it.StateReason != nil {
			reason = " " + *it.StateReason
		}
		got = append(got, it.Ref+" "+it.State+reason)
	}
	if strings.Join(got, ", ") != "acme/widgets#1 open, acme/widgets#2 closed Not planned, acme/widgets#4 open" {
		t.Errorf("items %v", got)
	}
	got = nil
	for _, c := range s.comments() {
		if c.Complete != nil {
			t.Errorf("comments on %s say they are complete", c.ItemRef)
		}
		var refs []string
		for _, x := range c.Comments {
			refs = append(refs, x.Ref)
		}
		got = append(got, c.ItemRef+": "+strings.Join(refs, " "))
	}
	if strings.Join(got, ", ") != "acme/widgets#1: 11 12, acme/widgets#2: 21" {
		t.Errorf("comments %v", got)
	}
	if _, ok := s.reqs[0].(contracts.SourceItems); !ok {
		t.Errorf("first request %T, want the items", s.reqs[0])
	}
	if strings.Join(logs, "\n") != "skipped the comment 51: it names no issue" {
		t.Errorf("logged %q", logs)
	}
}

// TestAnIssueEditedWhileAPullPagesIsNotSkipped lists 250 issues that changed, each at a
// different second, and edits issue 50, on the first page, once that page is answered,
// which moves it to the end and every issue after it one place earlier. It checks the
// pull asks each page from the latest change the page before showed, and sends every
// issue once, and issue 50 again, as the edit left it, last.
func TestAnIssueEditedWhileAPullPagesIsNotSkipped(t *testing.T) {
	f := &fakeChanged{}
	for n := 1; n <= 250; n++ {
		f.issues = append(f.issues, changedIssue(n, n))
	}
	edited := false
	f.after = func(path string) {
		if path == "/repos/acme/widgets/issues" && !edited {
			edited = true
			f.issues[49]["updated_at"] = changedAt(1000)
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, pullSince); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 1; n <= 250; n++ {
		want = append(want, "acme/widgets#"+strconv.Itoa(n)+" "+changedAt(n))
	}
	want = append(want, "acme/widgets#50 "+changedAt(1000))
	if got := sentItems(t, s); !slices.Equal(got, want) {
		t.Errorf("sent %d items\n%v", len(got), strings.Join(got, "\n"))
	}
	const q = "state=all&sort=updated&direction=asc&since="
	if got := f.asked("/repos/acme/widgets/issues"); !slices.Equal(got, []string{q + escaped(0) + "&per_page=100", q + escaped(100) + "&per_page=100", q + escaped(199) + "&per_page=100"}) {
		t.Errorf("asked\n%v", strings.Join(got, "\n"))
	}
}

// TestATieLargerThanAPageIsReadByPageNumber lists 150 issues that changed in one second
// and 100 after it, and checks the pull reads that second's second page by number, then
// by time again, and sends every issue once.
func TestATieLargerThanAPageIsReadByPageNumber(t *testing.T) {
	f := &fakeChanged{}
	for n := 1; n <= 150; n++ {
		f.issues = append(f.issues, changedIssue(n, 10))
	}
	for n := 151; n <= 250; n++ {
		f.issues = append(f.issues, changedIssue(n, n))
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, pullSince); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 1; n <= 250; n++ {
		at := n
		if n <= 150 {
			at = 10
		}
		want = append(want, "acme/widgets#"+strconv.Itoa(n)+" "+changedAt(at))
	}
	if got := sentItems(t, s); !slices.Equal(got, want) {
		t.Errorf("sent %d items\n%v", len(got), strings.Join(got, "\n"))
	}
	const q = "state=all&sort=updated&direction=asc&since="
	if got := f.asked("/repos/acme/widgets/issues"); !slices.Equal(got, []string{
		q + escaped(0) + "&per_page=100",
		q + escaped(10) + "&per_page=100",
		q + escaped(10) + "&per_page=100&page=2",
		q + escaped(200) + "&per_page=100",
	}) {
		t.Errorf("asked\n%v", strings.Join(got, "\n"))
	}
}

// TestACommentEditedWhileAPullPagesIsNotSkipped lists 150 comments that changed, each at
// a different second, and edits comment 10, on the first page, once that page is
// answered, and checks every comment is sent once, on its item, and comment 10 again, as
// the edit left it.
func TestACommentEditedWhileAPullPagesIsNotSkipped(t *testing.T) {
	f := &fakeChanged{}
	for i := 1; i <= 150; i++ {
		f.comments = append(f.comments, repoComment(i, "issues", 1+i%3, i, "bob", "User", "Same here."))
	}
	edited := false
	f.after = func(path string) {
		if path == "/repos/acme/widgets/issues/comments" && !edited {
			edited = true
			f.comments[9]["updated_at"] = changedAt(1000)
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, pullSince); err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, req := range s.comments() {
		for _, c := range req.Comments {
			count[c.Ref+" "+c.UpdatedAt]++
			id, _ := strconv.Atoi(c.Ref)
			if want := "acme/widgets#" + strconv.Itoa(1+id%3); req.ItemRef != want {
				t.Errorf("comment %s on %s, want %s", c.Ref, req.ItemRef, want)
			}
		}
	}
	for i := 1; i <= 150; i++ {
		if k := strconv.Itoa(i) + " " + changedAt(i); count[k] != 1 {
			t.Errorf("comment %d as it was sent %d times", i, count[k])
		}
	}
	if count["10 "+changedAt(1000)] != 1 || len(count) != 151 {
		t.Errorf("sent %v", count)
	}
}

// TestAPullThatWouldReadMoreThanItsPagesFails lowers the pages a pull reads to two, and
// checks a pull of a tie of 300 issues fails, its error naming the bound.
func TestAPullThatWouldReadMoreThanItsPagesFails(t *testing.T) {
	defer func(n int) { maxChangedPages = n }(maxChangedPages)
	maxChangedPages = 2
	f := &fakeChanged{}
	for n := 1; n <= 300; n++ {
		f.issues = append(f.issues, changedIssue(n, 10))
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	err := l.ListChanged(context.Background(), widgets, pullSince)
	if err == nil || err.Error() != "listing the issues of acme/widgets that changed: GitHub has more than 2 pages, which a pull never reads" {
		t.Errorf("err %v", err)
	}
}

// TestAPullOfARepositoryGoneWrapsErrRepositoryGone has GitHub answer the repository 404
// and checks the pull's error, and that nothing is sent.
func TestAPullOfARepositoryGoneWrapsErrRepositoryGone(t *testing.T) {
	f := &fakeChanged{gone: true}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, pullSince); !errors.Is(err, ErrRepositoryGone) {
		t.Errorf("err %v", err)
	}
	if len(s.reqs) != 0 {
		t.Errorf("sent %+v", s.reqs)
	}
}

// TestACommentsPageIsAPullRequestsOnlyByItsPath checks which pages are a pull
// request's, and which issue an issue_url names.
func TestACommentsPageIsAPullRequestsOnlyByItsPath(t *testing.T) {
	for u, want := range map[string]bool{
		"https://github.com/acme/widgets/pull/3#issuecomment-1":   true,
		"https://github.com/acme/widgets/issues/3#issuecomment-1": false,
		"https://github.com/acme/pull/issues/3#issuecomment-1":    false,
		"https://github.com/pull/widgets/issues/3":                false,
		"::": false,
	} {
		if got := onPullRequest(u); got != want {
			t.Errorf("%s: %v", u, got)
		}
	}
	for u, want := range map[string]int64{
		"https://api.github.com/repos/acme/widgets/issues/12": 12,
		"https://api.github.com/repos/acme/widgets/issues/0":  0,
		"https://api.github.com/repos/acme/widgets/issues/x":  0,
		"https://api.github.com/repos/acme/widgets":           0,
	} {
		if got, _ := issueNumber(u); got != want {
			t.Errorf("%s: %d", u, got)
		}
	}
}
