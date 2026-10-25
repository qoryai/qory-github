package github

import (
	"cmp"
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

// fakeChanged is GitHub's API as a pull reads it, through the repository's id,
// /repositories/1296269: acme/widgets, and its issues and its comments as GitHub lists
// what changed: those updated at or after since, oldest first,
// in the order they were added within one second, per_page to a page, paged by number.
// after, when set, is called with f.mu held after each page of issues or comments is
// answered, with the path, as GitHub changes between two pages. gone answers the
// repository 404, status answers it with that status, and fullName is its full_name,
// "" acme/widgets. hasIssues, when set, is answered as its has_issues, which the answer
// leaves out otherwise. issuesStatus and commentsStatus, when set, answer the issues and
// the comments with that status, as GitHub answers 410 for a repository with Issues
// turned off. It records the requests it is asked for, and their authorization.
type fakeChanged struct {
	srv      *httptest.Server
	mu       sync.Mutex
	issues   []map[string]any
	comments []map[string]any
	after    func(path string)
	gone     bool
	status   int
	fullName string
	// hasIssues is answered as has_issues when it is not nil.
	hasIssues                    any
	issuesStatus, commentsStatus int
	paths                        []string
	auth                         []string
}

func (f *fakeChanged) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.RequestURI())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
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
	case "/repositories/1296269":
		if f.gone {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			io.WriteString(w, `{"message":"Server Error"}`)
			return
		}
		name := cmp.Or(f.fullName, "acme/widgets")
		repo := map[string]any{"id": 1296269, "full_name": name, "html_url": "https://github.com/acme/widgets"}
		if f.hasIssues != nil {
			repo["has_issues"] = f.hasIssues
		}
		json.NewEncoder(w).Encode(repo)
	case "/repositories/1296269/issues":
		if f.issuesStatus != 0 {
			w.WriteHeader(f.issuesStatus)
			io.WriteString(w, `{"message":"`+http.StatusText(f.issuesStatus)+`"}`)
			return
		}
		serve(f.issues)
	case "/repositories/1296269/issues/comments":
		if f.commentsStatus != 0 {
			w.WriteHeader(f.commentsStatus)
			io.WriteString(w, `{"message":"`+http.StatusText(f.commentsStatus)+`"}`)
			return
		}
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
// given, every state's, oldest change first; the items are sent as an event, each with
// its key, # and the issue's number, closed ones with their reason, and the comments grouped by item, none complete; a pull request's
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
	repo, err := l.ListChanged(context.Background(), widgetsID, pullSince.In(time.FixedZone("CET", 3600)).Add(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if repo != widgets {
		t.Errorf("the repository read %v", repo)
	}
	if got := f.asked("/repositories/1296269/issues"); !slices.Equal(got, []string{"state=all&sort=updated&direction=asc&since=" + escaped(0) + "&per_page=100"}) {
		t.Errorf("asked for issues %v", got)
	}
	if got := f.asked("/repositories/1296269/issues/comments"); !slices.Equal(got, []string{"sort=updated&direction=asc&since=" + escaped(0) + "&per_page=100"}) {
		t.Errorf("asked for comments %v", got)
	}
	items := s.items()
	if len(items) != 1 || items[0].CollectionRef != widgetsRef || items[0].Listing != nil {
		t.Fatalf("items requests %+v", items)
	}
	var got []string
	for _, it := range items[0].Items {
		reason := ""
		if it.StateReason != nil {
			reason = " " + *it.StateReason
		}
		got = append(got, it.Ref+" "+it.Key+" "+it.State+reason)
		if it.Target == nil || it.Target.Path != "acme/widgets" || !strings.HasPrefix(it.URL, "https://github.com/acme/widgets/issues/") {
			t.Errorf("item %s: target %+v, url %s", it.Ref, it.Target, it.URL)
		}
	}
	if strings.Join(got, ", ") != "1296269#1 #1 open, 1296269#2 #2 closed Not planned, 1296269#4 #4 open" {
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
	if strings.Join(got, ", ") != "1296269#1: 11 12, 1296269#2: 21" {
		t.Errorf("comments %v", got)
	}
	if _, ok := s.reqs[0].(contracts.SourceItems); !ok {
		t.Errorf("first request %T, want the items", s.reqs[0])
	}
	if strings.Join(logs, "\n") != "skipped the comment 51: it names no issue" {
		t.Errorf("logged %q", logs)
	}
	for _, p := range f.paths {
		if p != "/repositories/1296269" && !strings.HasPrefix(p, "/repositories/1296269/") {
			t.Errorf("requested %s, not through the repository's id", p)
		}
	}
	if len(f.paths) == 0 || f.paths[0] != "/repositories/1296269" {
		t.Errorf("requested %v", f.paths)
	}
}

// TestAPullOfAnIDThatIsNotOneAsksNothing checks a pull of a repository whose id is not
// positive fails before any request, and sends nothing.
func TestAPullOfAnIDThatIsNotOneAsksNothing(t *testing.T) {
	for _, id := range []int64{0, -1} {
		f := &fakeChanged{}
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		_, err := l.ListChanged(context.Background(), id, pullSince)
		if err == nil || err.Error() != "the repository's id is not one" || len(f.paths) != 0 || len(s.reqs) != 0 {
			t.Errorf("%d: %v, requested %v, sent %+v", id, err, f.paths, s.reqs)
		}
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
		if path == "/repositories/1296269/issues" && !edited {
			edited = true
			f.issues[49]["updated_at"] = changedAt(1000)
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 1; n <= 250; n++ {
		want = append(want, "1296269#"+strconv.Itoa(n)+" "+changedAt(n))
	}
	want = append(want, "1296269#50 "+changedAt(1000))
	if got := sentItems(t, s); !slices.Equal(got, want) {
		t.Errorf("sent %d items\n%v", len(got), strings.Join(got, "\n"))
	}
	const q = "state=all&sort=updated&direction=asc&since="
	if got := f.asked("/repositories/1296269/issues"); !slices.Equal(got, []string{q + escaped(0) + "&per_page=100", q + escaped(100) + "&per_page=100", q + escaped(199) + "&per_page=100"}) {
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
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 1; n <= 250; n++ {
		at := n
		if n <= 150 {
			at = 10
		}
		want = append(want, "1296269#"+strconv.Itoa(n)+" "+changedAt(at))
	}
	if got := sentItems(t, s); !slices.Equal(got, want) {
		t.Errorf("sent %d items\n%v", len(got), strings.Join(got, "\n"))
	}
	const q = "state=all&sort=updated&direction=asc&since="
	if got := f.asked("/repositories/1296269/issues"); !slices.Equal(got, []string{
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
		if path == "/repositories/1296269/issues/comments" && !edited {
			edited = true
			f.comments[9]["updated_at"] = changedAt(1000)
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, req := range s.comments() {
		for _, c := range req.Comments {
			count[c.Ref+" "+c.UpdatedAt]++
			id, _ := strconv.Atoi(c.Ref)
			if want := "1296269#" + strconv.Itoa(1+id%3); req.ItemRef != want {
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
	_, err := l.ListChanged(context.Background(), widgetsID, pullSince)
	if err == nil || err.Error() != "listing the issues of 1296269 that changed: GitHub has more than 2 pages, which a pull never reads" {
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
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); !errors.Is(err, ErrRepositoryGone) {
		t.Errorf("err %v", err)
	}
	if len(s.reqs) != 0 {
		t.Errorf("sent %+v", s.reqs)
	}
}

// The lines a pull of acme/widgets logs: issuesOffLine for has_issues false, gone410Line
// for a 410 to the first page of the issues, before any page was read, and noMoreLine
// for a 410 once a page was read.
const (
	issuesOffLine = "skipped the issues and comments of 1296269: Issues are turned off for the repository on GitHub"
	gone410Line   = "skipped the issues and comments of 1296269: GitHub answers 410, as it does once Issues are turned off for the repository"
	noMoreLine    = "read no more issues or comments of 1296269: GitHub answers 410, as it does once Issues are turned off for the repository"
)

// TestAPullOfARepositoryWithIssuesOffReadsNothingOfIt has GitHub answer the repository
// with has_issues false, and checks the pull asks for neither its issues nor its
// comments, sends nothing, logs one line, and returns the name without error; and that
// has_issues true reads them as a repository without has_issues does.
func TestAPullOfARepositoryWithIssuesOffReadsNothingOfIt(t *testing.T) {
	f := &fakeChanged{hasIssues: false, issues: []map[string]any{changedIssue(1, 1)}, comments: []map[string]any{repoComment(11, "issues", 1, 1, "bob", "User", "First.")}}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	repo, err := l.ListChanged(context.Background(), widgetsID, pullSince)
	if err != nil || repo != widgets {
		t.Fatalf("%v, %v", repo, err)
	}
	if !slices.Equal(f.paths, []string{"/repositories/1296269"}) {
		t.Errorf("asked %v", f.paths)
	}
	if len(s.reqs) != 0 {
		t.Errorf("sent %+v", s.reqs)
	}
	if !slices.Equal(logs, []string{issuesOffLine}) {
		t.Errorf("logged %v", logs)
	}

	f = &fakeChanged{hasIssues: true, issues: []map[string]any{changedIssue(1, 1)}, comments: []map[string]any{repoComment(11, "issues", 1, 1, "bob", "User", "First.")}}
	s = &sink{}
	logs = nil
	l = f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil {
		t.Fatal(err)
	}
	if len(s.items()) != 1 || len(s.comments()) != 1 || len(logs) != 0 {
		t.Errorf("items %+v, comments %+v, logged %v", s.items(), s.comments(), logs)
	}
}

// TestAPullWhoseIssuesGitHubAnswers410KeepsWhatItSent has GitHub answer the second page
// of the issues 410, as it answers once Issues are turned off after the repository was
// read, and checks the pull returns the name without error, logs that it read no more,
// sends the issues of the first page, and asks for no comment; and that GitHub's 410 to
// the first page sends nothing, passes too, and logs that it skipped them.
func TestAPullWhoseIssuesGitHubAnswers410KeepsWhatItSent(t *testing.T) {
	f := &fakeChanged{}
	for n := 1; n <= 150; n++ {
		f.issues = append(f.issues, changedIssue(n, n))
	}
	f.after = func(path string) {
		if path == "/repositories/1296269/issues" {
			f.issuesStatus = http.StatusGone
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	repo, err := l.ListChanged(context.Background(), widgetsID, pullSince)
	if err != nil || repo != widgets {
		t.Fatalf("%v, %v", repo, err)
	}
	if sent := sentItems(t, s); len(sent) != 100 || sent[0] != "1296269#1 "+changedAt(1) || sent[99] != "1296269#100 "+changedAt(100) {
		t.Errorf("sent %v", sent)
	}
	if len(f.asked("/repositories/1296269/issues")) != 2 || len(f.asked("/repositories/1296269/issues/comments")) != 0 {
		t.Errorf("asked %v", f.paths)
	}
	if !slices.Equal(logs, []string{noMoreLine}) {
		t.Errorf("logged %v", logs)
	}

	f = &fakeChanged{issuesStatus: http.StatusGone, issues: []map[string]any{changedIssue(1, 1)}}
	s = &sink{}
	logs = nil
	l = f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil || len(s.reqs) != 0 || !slices.Equal(logs, []string{gone410Line}) {
		t.Errorf("a 410 to the first page: err %v, sent %+v, logged %v", err, s.reqs, logs)
	}
}

// TestAPullWhoseCommentsGitHubAnswers410KeepsWhatItSent has GitHub answer the second
// page of the comments 410, and checks the pull returns the name without error, logs
// that it read no more, and sends the issues and the comments of the first page; and
// that a 410 to the first page of the comments, once the issues were read and sent,
// logs that it read no more too, never that it skipped them.
func TestAPullWhoseCommentsGitHubAnswers410KeepsWhatItSent(t *testing.T) {
	f := &fakeChanged{issues: []map[string]any{changedIssue(1, 1)}}
	for id := 1; id <= 150; id++ {
		f.comments = append(f.comments, repoComment(id, "issues", 1, id, "bob", "User", "Same here."))
	}
	f.after = func(path string) {
		if path == "/repositories/1296269/issues/comments" {
			f.commentsStatus = http.StatusGone
		}
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	repo, err := l.ListChanged(context.Background(), widgetsID, pullSince)
	if err != nil || repo != widgets {
		t.Fatalf("%v, %v", repo, err)
	}
	if sent := sentItems(t, s); !slices.Equal(sent, []string{"1296269#1 " + changedAt(1)}) {
		t.Errorf("sent %v", sent)
	}
	if cs := s.comments(); len(cs) != 1 || len(cs[0].Comments) != 100 || cs[0].ItemRef != "1296269#1" {
		t.Errorf("sent comments %+v", cs)
	}
	if len(f.asked("/repositories/1296269/issues/comments")) != 2 {
		t.Errorf("asked %v", f.paths)
	}
	if !slices.Equal(logs, []string{noMoreLine}) {
		t.Errorf("logged %v", logs)
	}

	f = &fakeChanged{commentsStatus: http.StatusGone, issues: []map[string]any{changedIssue(1, 1)}}
	s = &sink{}
	logs = nil
	l = f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil || len(s.items()) != 1 || len(s.comments()) != 0 || !slices.Equal(logs, []string{noMoreLine}) {
		t.Errorf("a 410 to the first page of the comments: err %v, sent %+v, logged %v", err, s.reqs, logs)
	}
}

// TestAPullWhoseIssuesGitHubAnswers404IsGone has GitHub answer the issues 404, on the
// first page and on the second, and the comments 404, and checks the pull fails with
// an error that wraps ErrRepositoryGone and not ErrIssuesOff, and logs nothing.
func TestAPullWhoseIssuesGitHubAnswers404IsGone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fakeChanged)
	}{
		{"the first page of the issues", func(f *fakeChanged) { f.issuesStatus = http.StatusNotFound }},
		{"the second page of the issues", func(f *fakeChanged) {
			f.after = func(path string) {
				if path == "/repositories/1296269/issues" {
					f.issuesStatus = http.StatusNotFound
				}
			}
		}},
		{"the comments", func(f *fakeChanged) { f.commentsStatus = http.StatusNotFound }},
	} {
		f := &fakeChanged{}
		for n := 1; n <= 150; n++ {
			f.issues = append(f.issues, changedIssue(n, n))
		}
		tc.setup(f)
		var logs []string
		l := f.lister(t, &sink{}, &logs)
		_, err := l.ListChanged(context.Background(), widgetsID, pullSince)
		if !errors.Is(err, ErrRepositoryGone) || errors.Is(err, ErrIssuesOff) {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if len(logs) != 0 {
			t.Errorf("%s: logged %v", tc.name, logs)
		}
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

// TestAPullWhereNothingChangedSendsNothing checks a pull where no issue and no comment
// changed sends no request: an event without items is refused by the contract.
func TestAPullWhereNothingChangedSendsNothing(t *testing.T) {
	f := &fakeChanged{issues: []map[string]any{changedIssue(1, -60)}}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if _, err := l.ListChanged(context.Background(), widgetsID, pullSince); err != nil {
		t.Fatal(err)
	}
	if len(s.reqs) != 0 {
		t.Errorf("sent %+v", s.reqs)
	}
}

// TestReadRepositoryReadsTheNameByID reads a repository's owner/name by its id and
// checks it asks GitHub once, GET /repositories/{id} with the listing's token, and
// returns owner/name, and Issues on when the answer has no has_issues, off when it is
// false, and on when it is true; a 404 wraps ErrRepositoryGone, as GitHub answers for a repository
// deleted or out of the App's reach, never for one renamed; a 500 does not; a full_name
// that is not owner/name is refused; and an id that is not one, or a lister with no
// token, asks nothing.
func TestReadRepositoryReadsTheNameByID(t *testing.T) {
	var logs []string
	f := &fakeChanged{}
	l := f.lister(t, &sink{}, &logs)
	repo, issuesOn, err := l.ReadRepository(context.Background(), widgetsID)
	if err != nil || repo != widgets || !issuesOn {
		t.Fatalf("%v, %v", repo, err)
	}
	if !slices.Equal(f.paths, []string{"/repositories/1296269"}) || !slices.Equal(f.auth, []string{"Bearer " + fakeToken}) {
		t.Errorf("asked %v with %v", f.paths, f.auth)
	}

	for _, tc := range []struct {
		has  any
		want bool
	}{{false, false}, {true, true}} {
		f = &fakeChanged{hasIssues: tc.has}
		l = f.lister(t, &sink{}, &logs)
		if repo, issuesOn, err := l.ReadRepository(context.Background(), widgetsID); err != nil || repo != widgets || issuesOn != tc.want {
			t.Errorf("has_issues %v: %v, %v, %v", tc.has, repo, issuesOn, err)
		}
	}

	f = &fakeChanged{gone: true}
	l = f.lister(t, &sink{}, &logs)
	if _, _, err := l.ReadRepository(context.Background(), widgetsID); !errors.Is(err, ErrRepositoryGone) {
		t.Errorf("a 404: %v", err)
	}
	f = &fakeChanged{status: 500}
	l = f.lister(t, &sink{}, &logs)
	if _, _, err := l.ReadRepository(context.Background(), widgetsID); err == nil || errors.Is(err, ErrRepositoryGone) {
		t.Errorf("a 500: %v", err)
	}
	for _, name := range []string{"acme", "acme/", "/widgets", "acme/widgets/more", "acme/..", "-acme/widgets"} {
		f = &fakeChanged{fullName: name}
		l = f.lister(t, &sink{}, &logs)
		if _, _, err := l.ReadRepository(context.Background(), widgetsID); err == nil || err.Error() != "reading the repository 1296269: GitHub's name for it is not owner/name" {
			t.Errorf("%q: %v", name, err)
		}
	}

	f = &fakeChanged{}
	l = f.lister(t, &sink{}, &logs)
	for _, id := range []int64{0, -1} {
		if _, _, err := l.ReadRepository(context.Background(), id); err == nil || err.Error() != "the repository's id is not one" {
			t.Errorf("%d: %v", id, err)
		}
	}
	l.Token = nil
	if _, _, err := l.ReadRepository(context.Background(), widgetsID); err == nil || err.Error() != "the lister has no token" {
		t.Errorf("no token: %v", err)
	}
	if len(f.paths) != 0 {
		t.Errorf("asked %v", f.paths)
	}
}

// TestAPullOfANameThatIsNotOwnerNameReturnsNone has GitHub answer a full_name that is
// not owner/name and checks the pull still sends what changed and returns a zero
// Repository, so a listing of open issues reads the name again.
func TestAPullOfANameThatIsNotOwnerNameReturnsNone(t *testing.T) {
	f := &fakeChanged{fullName: "acme", issues: []map[string]any{changedIssue(1, 1)}}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	repo, err := l.ListChanged(context.Background(), widgetsID, pullSince)
	if err != nil || repo != (Repository{}) {
		t.Fatalf("%v, %v", repo, err)
	}
	if items := s.items(); len(items) != 1 || len(items[0].Items) != 1 || items[0].Items[0].Ref != "1296269#1" {
		t.Errorf("items %+v", items)
	}
}
