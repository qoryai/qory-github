package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// fakeIssues is GitHub's API as a listing reads it: one repository, acme/widgets, its
// issues and their comments, and the installation's repositories, each pageSize to a
// page with a Link header to the next. It records the paths it is asked for.
type fakeIssues struct {
	srv      *httptest.Server
	issues   []map[string]any
	comments map[int][]map[string]any
	repos    []map[string]any
	pageSize int
	// failIssues and failComments answer that page of issues, or of any issue's
	// comments, with a 500; zero never does.
	failIssues, failComments int
	// elsewhere is set to make the first page of issues link its next on another host,
	// and again to make every page link its next to the first.
	elsewhere, again bool
	// afterIssues, when set, is called after a page of issues is answered, with its
	// number, as GitHub changes between two pages.
	afterIssues func(page int)
	mu          sync.Mutex
	paths       []string
	auth        []string
}

var commentsPath = regexp.MustCompile(`^/repos/acme/widgets/issues/(\d+)/comments$`)

func (f *fakeIssues) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.RequestURI())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(page, 1)
	serve := func(all []map[string]any, fail int, wrap func([]map[string]any) any) {
		if page == fail {
			w.WriteHeader(500)
			io.WriteString(w, `{"message":"Server Error"}`)
			return
		}
		lo, hi := min((page-1)*f.pageSize, len(all)), min(page*f.pageSize, len(all))
		if hi < len(all) || f.again {
			q := r.URL.Query()
			q.Set("page", strconv.Itoa(page+1))
			if f.again {
				q.Del("page")
			}
			host := f.srv.URL
			if f.elsewhere {
				host = "https://elsewhere.example"
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?%s>; rel="next", <%s%s?page=99>; rel="last"`, host, r.URL.Path, q.Encode(), host, r.URL.Path))
		}
		json.NewEncoder(w).Encode(wrap(all[lo:hi]))
	}
	list := func(s []map[string]any) any { return s }
	switch m := commentsPath.FindStringSubmatch(r.URL.Path); {
	case r.URL.Path == "/repos/acme/widgets":
		io.WriteString(w, `{"full_name":"acme/widgets","html_url":"https://github.com/acme/widgets","private":true}`)
	case r.URL.Path == "/repos/acme/widgets/issues":
		// GitHub lists issues in the state asked for, all of them for all; the
		// fixtures are in the order they were created.
		f.mu.Lock()
		var in []map[string]any
		for _, is := range f.issues {
			if st := r.URL.Query().Get("state"); st == "all" || st == is["state"] {
				in = append(in, is)
			}
		}
		f.mu.Unlock()
		serve(in, f.failIssues, list)
		if f.afterIssues != nil {
			f.mu.Lock()
			f.afterIssues(page)
			f.mu.Unlock()
		}
	case m != nil:
		n, _ := strconv.Atoi(m[1])
		serve(f.comments[n], f.failComments, list)
	case r.URL.Path == "/installation/repositories":
		serve(f.repos, 0, func(s []map[string]any) any { return map[string]any{"total_count": len(f.repos), "repositories": s} })
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func (f *fakeIssues) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slicesClone(f.paths)
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// issue is an open issue of acme/widgets, filed by a person, with comments comments.
func issue(n, comments int) map[string]any {
	return map[string]any{
		"number":     n,
		"title":      "Widget " + strconv.Itoa(n) + " is broken",
		"body":       "It does not turn.",
		"state":      "open",
		"html_url":   "https://github.com/acme/widgets/issues/" + strconv.Itoa(n),
		"labels":     []any{map[string]any{"name": "bug"}},
		"user":       map[string]any{"login": "alice", "type": "User"},
		"comments":   comments,
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-01-03T03:04:05Z",
	}
}

// comment is a comment with id id by login, a User or a Bot.
func comment(id int, login, typ, body string) map[string]any {
	return map[string]any{
		"id":         id,
		"html_url":   "https://github.com/acme/widgets/issues/1#issuecomment-" + strconv.Itoa(id),
		"body":       body,
		"user":       map[string]any{"login": login, "type": typ},
		"created_at": "2026-01-04T00:00:00Z",
		"updated_at": "2026-01-05T00:00:00Z",
	}
}

// sink records the requests it is sent, and fails the call failAt, counted from 1.
type sink struct {
	mu     sync.Mutex
	reqs   []any
	failAt int
}

func (s *sink) add(req any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	if len(s.reqs) == s.failAt {
		return errors.New("Qory Apiary is not reachable")
	}
	return nil
}

func (s *sink) Collections(_ context.Context, r contracts.SourceCollections) error { return s.add(r) }
func (s *sink) Items(_ context.Context, r contracts.SourceItems) error             { return s.add(r) }
func (s *sink) Comments(_ context.Context, r contracts.SourceItemComments) error   { return s.add(r) }
func (s *sink) Disconnect(_ context.Context, r contracts.SourcesDisconnect) error  { return s.add(r) }

func (s *sink) items() []contracts.SourceItems {
	var out []contracts.SourceItems
	for _, r := range s.reqs {
		if it, ok := r.(contracts.SourceItems); ok {
			out = append(out, it)
		}
	}
	return out
}

func (s *sink) comments() []contracts.SourceItemComments {
	var out []contracts.SourceItemComments
	for _, r := range s.reqs {
		if c, ok := r.(contracts.SourceItemComments); ok {
			out = append(out, c)
		}
	}
	return out
}

// lister lists f into s, with a clock that never sleeps, and records what it logs.
func (f *fakeIssues) lister(t *testing.T, s Sink, logs *[]string) Lister {
	t.Helper()
	if f.pageSize == 0 {
		f.pageSize = 100
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	clock := &fakeClock{}
	return Lister{
		Client: Client{API: f.srv.URL},
		Pacer:  clock.pacer(),
		Token:  func(context.Context) (string, error) { return fakeToken, nil },
		Slug:   "qory-test",
		Sink:   s,
		Logf:   func(format string, args ...any) { *logs = append(*logs, fmt.Sprintf(format, args...)) },
	}
}

var widgets = Repository{Owner: "acme", Name: "widgets"}

// TestAListingPagesDropsPullRequestsAndReadsCommentsWhereThereAreAny lists three pages
// of issues, one a pull request, and checks that every page is read with the token,
// the pull request is left out, comments are read, paged, only for an issue that has
// any, the App's work item comment is left out while a person's comment with the same
// words is kept, and the listing and each item's comments say they are complete.
func TestAListingPagesDropsPullRequestsAndReadsCommentsWhereThereAreAny(t *testing.T) {
	pr := issue(4, 3)
	pr["pull_request"] = map[string]any{"url": "https://api.github.com/repos/acme/widgets/pulls/4"}
	nullPR := issue(5, 0)
	nullPR["pull_request"] = nil
	f := &fakeIssues{
		pageSize: 2,
		issues:   []map[string]any{issue(1, 3), issue(2, 0), pr, nullPR, issue(6, 1)},
		comments: map[int][]map[string]any{
			1: {
				comment(11, "qory-test[bot]", "Bot", "<!-- qory:work-item 7 -->\nThis issue is work in Qory Apiary."),
				comment(12, "bob", "User", "<!-- qory:work-item 7 --> copied by a person"),
				comment(13, "dependabot[bot]", "Bot", "An automation's comment."),
			},
			6: {comment(61, "QORY-TEST[bot]", "Bot", "<!-- qory:work-item 8 -->")},
		},
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListIssues(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/repos/acme/widgets",
		"/repos/acme/widgets/issues?state=all&sort=created&direction=asc&per_page=100",
		"/repos/acme/widgets/issues?direction=asc&page=2&per_page=100&sort=created&state=all",
		"/repos/acme/widgets/issues?direction=asc&page=3&per_page=100&sort=created&state=all",
		"/repos/acme/widgets/issues/1/comments?per_page=100",
		"/repos/acme/widgets/issues/1/comments?page=2&per_page=100",
		"/repos/acme/widgets/issues/6/comments?per_page=100",
	}
	if got := f.requested(); !reflect.DeepEqual(got, want) {
		t.Errorf("requested\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, a := range f.auth {
		if a != "Bearer "+fakeToken {
			t.Errorf("authorization %q", a)
		}
	}
	items := s.items()
	if len(items) != 1 || items[0].Listing == nil || items[0].Listing.Part != 1 || items[0].Listing.Complete || items[0].Listing.StartedAt != "2026-09-21T14:13:20Z" {
		t.Fatalf("items requests %+v", items)
	}
	var refs []string
	for _, it := range items[0].Items {
		refs = append(refs, it.Ref)
	}
	if strings.Join(refs, " ") != "acme/widgets#1 acme/widgets#2 acme/widgets#6" {
		t.Errorf("items %v", refs)
	}
	if items[0].CollectionRef != "acme/widgets" {
		t.Errorf("collection %s", items[0].CollectionRef)
	}
	// #6 has only the work item comment, so nothing is sent for it.
	cs := s.comments()
	if len(cs) != 1 {
		t.Fatalf("comments requests %+v", cs)
	}
	var got []string
	for _, c := range cs[0].Comments {
		got = append(got, c.Ref+" "+c.Author.Name+" "+c.Author.Kind)
	}
	if cs[0].ItemRef != "acme/widgets#1" || strings.Join(got, ", ") != "12 bob person, 13 dependabot[bot] automation" || cs[0].Complete != nil {
		t.Errorf("comments on #1: %+v, %v", cs[0], got)
	}
	// The items come before their comments.
	if _, ok := s.reqs[0].(contracts.SourceItems); !ok {
		t.Errorf("first request %T", s.reqs[0])
	}
	if len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// TestAListingIsSentInPartsOfAHundredItemsAndAMebibyte lists 250 small issues and then
// 40 with long bodies, and checks the parts: at most 100 items and 1 MiB of JSON each,
// numbered from 1, only the last complete, and every item sent once.
func TestAListingIsSentInPartsOfAHundredItemsAndAMebibyte(t *testing.T) {
	long := strings.Repeat("ü", 60_000)
	for _, tc := range []struct {
		name  string
		n     int
		body  string
		parts []int
	}{
		{"small", 250, "", []int{100, 100, 50}},
		{"exactly a hundred", 100, "", []int{100}},
		{"none", 0, "", []int{0}},
		{"long bodies", 40, long, nil},
	} {
		f := &fakeIssues{}
		for i := 1; i <= tc.n; i++ {
			is := issue(i, 0)
			if tc.body != "" {
				is["body"] = tc.body
			}
			f.issues = append(f.issues, is)
		}
		s := &sink{}
		var logs []string
		if err := f.lister(t, s, &logs).ListIssues(context.Background(), widgets); err != nil {
			t.Fatal(err)
		}
		items := s.items()
		var sizes []int
		total := 0
		for i, req := range items {
			// The sink sets the time as it sends.
			req.Time = "2026-01-02T03:04:05Z"
			b, _ := json.Marshal(req)
			if len(b) > contracts.MaxRequest {
				t.Errorf("%s: part %d is %d bytes", tc.name, i+1, len(b))
			}
			if req.Listing.Part != i+1 || req.Listing.Complete {
				t.Errorf("%s: part %d says %+v", tc.name, i+1, req.Listing)
			}
			sizes = append(sizes, len(req.Items))
			total += len(req.Items)
		}
		if tc.parts != nil && !reflect.DeepEqual(sizes, tc.parts) {
			t.Errorf("%s: parts of %v, want %v", tc.name, sizes, tc.parts)
		}
		if tc.parts == nil && (len(items) < 2 || total != tc.n) {
			t.Errorf("%s: parts of %v", tc.name, sizes)
		}
	}
}

// TestAnItemsCommentsGoInRequestsOfAMebibyte lists an issue with many long comments
// and checks they go in several requests of at most 1 MiB, only the last complete.
func TestAnItemsCommentsGoInRequestsOfAMebibyte(t *testing.T) {
	long := strings.Repeat("x", 60_000)
	f := &fakeIssues{issues: []map[string]any{issue(1, 40)}, comments: map[int][]map[string]any{}}
	for i := range 40 {
		f.comments[1] = append(f.comments[1], comment(100+i, "bob", "User", long))
	}
	s := &sink{}
	var logs []string
	if err := f.lister(t, s, &logs).ListIssues(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	cs := s.comments()
	total := 0
	for i, c := range cs {
		c.Time = "2026-01-02T03:04:05Z"
		b, _ := json.Marshal(c)
		if len(b) > contracts.MaxRequest || c.Complete != nil {
			t.Errorf("request %d: %d bytes, complete %v", i, len(b), c.Complete)
		}
		total += len(c.Comments)
	}
	if len(cs) < 2 || total != 40 {
		t.Errorf("%d requests, %d comments", len(cs), total)
	}
}

// TestWhatQoryApiaryWouldRefuseIsSkippedAndLoggedByRef lists issues and a comment that
// each break a limit, and checks they are left out and logged by their ref alone.
func TestWhatQoryApiaryWouldRefuseIsSkippedAndLoggedByRef(t *testing.T) {
	secret := "SECRETTEXT"
	longBody, longTitle, manyLabels, httpURL := issue(2, 0), issue(3, 0), issue(4, 0), issue(5, 0)
	longBody["body"] = secret + strings.Repeat("a", 65_536)
	longTitle["title"] = secret + strings.Repeat("a", 1024)
	var labels []any
	for i := range 101 {
		labels = append(labels, map[string]any{"name": "l" + strconv.Itoa(i)})
	}
	manyLabels["labels"] = labels
	httpURL["html_url"] = "http://github.com/acme/widgets/issues/5"
	atLimit := issue(6, 0)
	atLimit["body"] = strings.Repeat("ü", 65_536)
	f := &fakeIssues{
		issues:   []map[string]any{issue(1, 2), longBody, longTitle, manyLabels, httpURL, atLimit},
		comments: map[int][]map[string]any{1: {comment(10, "bob", "User", secret+strings.Repeat("b", 65_536)), comment(11, "bob", "User", "fine")}},
	}
	s := &sink{}
	var logs []string
	if err := f.lister(t, s, &logs).ListIssues(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	items := s.items()
	if len(items) != 1 || len(items[0].Items) != 2 || items[0].Items[0].Ref != "acme/widgets#1" || items[0].Items[1].Ref != "acme/widgets#6" || items[0].Listing.Complete {
		t.Errorf("items %+v", items)
	}
	cs := s.comments()
	if len(cs) != 1 || len(cs[0].Comments) != 1 || cs[0].Comments[0].Ref != "11" {
		t.Errorf("comments %+v", cs)
	}
	want := []string{
		"skipped the item acme/widgets#2: its body is longer than 65,536 characters",
		"skipped the item acme/widgets#3: its title is empty or longer than 1,024 characters",
		"skipped the item acme/widgets#4: it has more than 100 labels",
		"skipped the item acme/widgets#5: its URL is not https or is longer than 2,048 characters",
		"skipped the comment 10 on acme/widgets#1: its body is longer than 65,536 characters",
	}
	if !reflect.DeepEqual(logs, want) {
		t.Errorf("logged\n%s", strings.Join(logs, "\n"))
	}
}

// TestAListingStoppedEarlyEndsWithAPart stops listings in several places and checks
// that each returns its error and ends with a part, none of which says it is complete.
func TestAListingStoppedEarlyEndsWithAPart(t *testing.T) {
	many := func(n, comments int) []map[string]any {
		var out []map[string]any
		for i := 1; i <= n; i++ {
			out = append(out, issue(i, comments))
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		f     *fakeIssues
		sink  *sink
		err   string
		parts int // items requests, the last of which is incomplete
	}{
		{"a page of issues fails", &fakeIssues{pageSize: 2, issues: many(5, 0), failIssues: 2}, &sink{}, "listing the issues of acme/widgets: GitHub answered 500: Server Error", 1},
		{"a page of issues fails after a part", &fakeIssues{pageSize: 100, issues: many(250, 0), failIssues: 3}, &sink{}, "listing the issues of acme/widgets: GitHub answered 500: Server Error", 2},
		{"the next page is elsewhere", &fakeIssues{pageSize: 2, issues: many(5, 0), elsewhere: true}, &sink{}, "listing the issues of acme/widgets: the next page GitHub names is not on the API, so it is not read", 1},
		{"Qory Apiary fails a part", &fakeIssues{pageSize: 100, issues: many(150, 0)}, &sink{failAt: 1}, "Qory Apiary is not reachable", 2},
		{"comments fail before the last part", &fakeIssues{pageSize: 1, issues: many(150, 1), comments: map[int][]map[string]any{1: {comment(1, "bob", "User", "a"), comment(2, "bob", "User", "b")}}, failComments: 2}, &sink{}, "listing the comments on acme/widgets#1: GitHub answered 500: Server Error", 2},
	} {
		var logs []string
		err := tc.f.lister(t, tc.sink, &logs).ListIssues(context.Background(), widgets)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: err %v, want %s", tc.name, err, tc.err)
		}
		items := tc.sink.items()
		if len(items) != tc.parts {
			t.Errorf("%s: %d parts, want %d", tc.name, len(items), tc.parts)
			continue
		}
		for i, it := range items {
			if it.Listing.Complete || it.Listing.Part != i+1 {
				t.Errorf("%s: part %d says %+v", tc.name, i+1, it.Listing)
			}
		}
		for _, c := range tc.sink.comments() {
			if c.Complete != nil {
				t.Errorf("%s: comments on %s said complete", tc.name, c.ItemRef)
			}
		}
	}
	// A listing whose context is done ends with a part all the same.
	f := &fakeIssues{pageSize: 2, issues: many(5, 0)}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	l.Token = func(context.Context) (string, error) {
		if len(f.requested()) == 2 {
			cancel()
		}
		return fakeToken, ctx.Err()
	}
	err := l.ListIssues(ctx, widgets)
	items := s.items()
	if !errors.Is(err, context.Canceled) || len(items) != 1 || items[0].Listing.Complete || len(items[0].Items) != 2 {
		t.Errorf("err %v, items %+v", err, items)
	}
	// Comments that fail after the last part send no part after it.
	f = &fakeIssues{issues: many(1, 2), comments: map[int][]map[string]any{1: {comment(1, "bob", "User", "a"), comment(2, "bob", "User", "b")}}, pageSize: 1, failComments: 2}
	s = &sink{}
	err = f.lister(t, s, &logs).ListIssues(context.Background(), widgets)
	if items := s.items(); err == nil || len(items) != 1 || items[0].Listing.Complete || len(s.comments()) != 0 {
		t.Errorf("err %v, items %+v, comments %+v", err, items, s.comments())
	}
}

func TestListRepositoriesSendsTheCollectionsWithTheirTarget(t *testing.T) {
	f := &fakeIssues{pageSize: 1}
	for _, n := range []string{"widgets", "gadgets"} {
		f.repos = append(f.repos, map[string]any{"full_name": "acme/" + n, "html_url": "https://github.com/acme/" + n})
	}
	f.repos = append(f.repos, map[string]any{"full_name": "acme/broken", "html_url": "ftp://github.com/acme/broken"})
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(f.srv.URL, "http://")
	if len(s.reqs) != 1 {
		t.Fatalf("requests %+v", s.reqs)
	}
	got := s.reqs[0].(contracts.SourceCollections)
	want := []contracts.Collection{
		{Ref: "acme/widgets", URL: "https://github.com/acme/widgets", Title: "acme/widgets", Target: &contracts.Target{System: host, Path: "acme/widgets"}},
		{Ref: "acme/gadgets", URL: "https://github.com/acme/gadgets", Title: "acme/gadgets", Target: &contracts.Target{System: host, Path: "acme/gadgets"}},
	}
	if !reflect.DeepEqual(got.Collections, want) || got.Listing.Part != 1 || got.Listing.Complete || got.Version != 1 {
		t.Errorf("collections %+v", got)
	}
	if !reflect.DeepEqual(logs, []string{"skipped the collection acme/broken: its URL is not https or is longer than 2,048 characters"}) {
		t.Errorf("logged %v", logs)
	}
	if strings.Join(f.requested(), " ") != "/installation/repositories?per_page=100 /installation/repositories?page=2&per_page=100 /installation/repositories?page=3&per_page=100" {
		t.Errorf("requested %v", f.requested())
	}
}

func TestTheTargetsSystemIsGitHubsWebsite(t *testing.T) {
	for api, want := range map[string]string{"": "github.com", "https://api.github.com": "github.com", "https://api.github.com/": "github.com", "http://127.0.0.1:8080": "127.0.0.1:8080"} {
		if got := (Client{API: api}).WebHost(); got != want {
			t.Errorf("%q: %s, want %s", api, got, want)
		}
	}
}

func str(s string) *string { return &s }

// TestAnIssueMapsToAnItem checks every row of the mapping.
func TestAnIssueMapsToAnItem(t *testing.T) {
	r := ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
	base := ghIssue{
		Number: 42, Title: "Widgets spin backwards", Body: str("They should not."), State: "open",
		HTMLURL: "https://github.com/acme/widgets/issues/42", Labels: []ghLabel{{"bug"}, {"good first issue"}},
		User: &ghUser{Login: "alice", Type: "User"}, Comments: 3,
		CreatedAt: "2026-01-02T05:04:05+02:00", UpdatedAt: "2026-01-03T03:04:05Z",
	}
	it, why := itemOf("github.com", r, base)
	want := contracts.Item{
		Ref: "acme/widgets#42", URL: "https://github.com/acme/widgets/issues/42", Title: "Widgets spin backwards", Body: "They should not.",
		BodyFormat: "markdown", Type: "issue", State: "open", Labels: []string{"bug", "good first issue"},
		FiledBy: contracts.Person{Name: "alice", Kind: "person"}, CommentCount: 3, CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-03T03:04:05Z",
		Target: &contracts.Target{System: "github.com", Path: "acme/widgets"},
	}
	if why != "" || !reflect.DeepEqual(it, want) {
		t.Errorf("item %+v, %s\nwant %+v", it, why, want)
	}
	if c := collectionOf(r); c != (contracts.Collection{Ref: "acme/widgets", URL: "https://github.com/acme/widgets", Title: "acme/widgets"}) {
		t.Errorf("collection %+v", c)
	}
	for _, tc := range []struct {
		state  string
		reason *string
		want   *string
	}{
		{"open", nil, nil},
		{"open", str("reopened"), nil},
		{"closed", str("completed"), str("Completed")},
		{"closed", str("not_planned"), str("Not planned")},
		{"closed", str("duplicate"), str("Duplicate")},
		{"closed", str("reopened"), nil},
		{"closed", str("something_new"), nil},
		{"closed", nil, nil},
	} {
		is := base
		is.State, is.StateReason = tc.state, tc.reason
		it, _ := itemOf("github.com", r, is)
		if it.State != tc.state || !reflect.DeepEqual(it.StateReason, tc.want) {
			t.Errorf("%s %v: state %s, reason %v", tc.state, tc.reason, it.State, it.StateReason)
		}
	}
	is := base
	is.Body, is.Labels, is.User = nil, nil, &ghUser{Login: "renovate[bot]", Type: "Bot"}
	it, _ = itemOf("github.com", r, is)
	if it.Body != "" || it.Labels == nil || len(it.Labels) != 0 || it.FiledBy != (contracts.Person{Name: "renovate[bot]", Kind: "automation"}) {
		t.Errorf("item %+v", it)
	}
	c, why := commentOf(ghComment{ID: 1234567890123, HTMLURL: "https://github.com/acme/widgets/issues/42#issuecomment-1234567890123", Body: str("Same here."), User: &ghUser{Login: "ci", Type: "Bot"}, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"})
	if why != "" || c != (contracts.Comment{Ref: "1234567890123", URL: "https://github.com/acme/widgets/issues/42#issuecomment-1234567890123", Author: contracts.Person{Name: "ci", Kind: "automation"}, Body: "Same here.", BodyFormat: "markdown", CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"}) {
		t.Errorf("comment %+v, %s", c, why)
	}
}

// TestTheWireIsTheContractsJSON checks the JSON an item and a comment of the adapter's
// become: the names, the nulls the contract wants and the fields it leaves out.
func TestTheWireIsTheContractsJSON(t *testing.T) {
	it, _ := itemOf("github.com", ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}, ghIssue{Number: 1, Title: "t", State: "open", HTMLURL: "https://github.com/acme/widgets/issues/1", CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-02T03:04:05Z"})
	b, _ := json.Marshal(contracts.SourceItems{Version: contracts.Version, Time: "2026-01-02T03:04:05Z", CollectionRef: "acme/widgets", Items: []contracts.Item{it}})
	want := `{"version":1,"time":"2026-01-02T03:04:05Z","collection_ref":"acme/widgets","items":[{"ref":"acme/widgets#1","url":"https://github.com/acme/widgets/issues/1","type":"issue","title":"t","body":"","body_format":"markdown","filed_by":{"name":"ghost","kind":"person"},"labels":[],"state":"open","state_reason":null,"comment_count":0,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z","target":{"system":"github.com","path":"acme/widgets"}}]}`
	if string(b) != want {
		t.Errorf("items\n%s\nwant\n%s", b, want)
	}
	got, _ := IssueCommentWebhook(event("deleted", issue(1, 1), map[string]any{"comment": comment(9, "bob", "User", "b")}), "qory-test")
	req := got.Comments[0]
	req.Time = "2026-01-02T03:04:05Z"
	b, _ = json.Marshal(req)
	if string(b) != `{"version":1,"time":"2026-01-02T03:04:05Z","item_ref":"acme/widgets#1","comments":[{"ref":"9","url":"https://github.com/acme/widgets/issues/1#issuecomment-9","author":{"name":"bob","kind":"person"},"body":"","body_format":"markdown","created_at":"2026-01-04T00:00:00Z","updated_at":"2026-01-05T00:00:00Z","deleted":true}]}` {
		t.Errorf("comments %s", b)
	}
}

// event is a webhook payload: action on issue in acme/widgets, with extra fields.
func event(action string, issue map[string]any, extra map[string]any) []byte {
	ev := map[string]any{
		"action":       action,
		"issue":        issue,
		"repository":   map[string]any{"full_name": "acme/widgets", "html_url": "https://github.com/acme/widgets", "id": 1},
		"sender":       map[string]any{"login": "alice"},
		"installation": map[string]any{"id": 7},
	}
	for k, v := range extra {
		ev[k] = v
	}
	b, _ := json.Marshal(ev)
	return b
}

func TestAnIssuesEventIsTheItem(t *testing.T) {
	closed := issue(1, 0)
	closed["state"], closed["state_reason"] = "closed", "not_planned"
	pr := issue(1, 0)
	pr["pull_request"] = map[string]any{}
	gadgets := map[string]any{"full_name": "acme/gadgets", "html_url": "https://github.com/acme/gadgets"}
	transfer := map[string]any{"changes": map[string]any{"new_issue": issue(9, 0), "new_repository": gadgets}}
	active := func(r Repository) bool { return r == Repository{Owner: "acme", Name: "gadgets"} }
	inactive := func(Repository) bool { return false }
	for _, tc := range []struct {
		action string
		issue  map[string]any
		extra  map[string]any
		active func(Repository) bool
		want   []string // collection item state reason, one per items request
	}{
		{"opened", issue(1, 0), nil, nil, []string{"acme/widgets acme/widgets#1 open <nil>"}},
		{"reopened", issue(1, 0), nil, nil, []string{"acme/widgets acme/widgets#1 open <nil>"}},
		{"edited", issue(1, 0), map[string]any{"changes": map[string]any{"title": map[string]any{"from": "old"}}}, nil, []string{"acme/widgets acme/widgets#1 open <nil>"}},
		{"closed", closed, nil, nil, []string{"acme/widgets acme/widgets#1 closed Not planned"}},
		{"labeled", issue(1, 0), map[string]any{"label": map[string]any{"name": "bug"}}, nil, []string{"acme/widgets acme/widgets#1 open <nil>"}},
		{"unlabeled", issue(1, 0), nil, nil, []string{"acme/widgets acme/widgets#1 open <nil>"}},
		{"deleted", issue(1, 0), nil, nil, []string{"acme/widgets acme/widgets#1 closed <nil>"}},
		{"deleted", closed, nil, nil, []string{"acme/widgets acme/widgets#1 closed <nil>"}},
		{"transferred", issue(1, 0), transfer, active, []string{"acme/widgets acme/widgets#1 closed <nil>", "acme/gadgets acme/gadgets#9 open <nil>"}},
		{"transferred", issue(1, 0), transfer, inactive, []string{"acme/widgets acme/widgets#1 closed <nil>"}},
		{"transferred", issue(1, 0), transfer, nil, []string{"acme/widgets acme/widgets#1 closed <nil>"}},
		{"assigned", issue(1, 0), nil, nil, nil},
		{"pinned", issue(1, 0), nil, nil, nil},
		{"milestoned", issue(1, 0), nil, nil, nil},
		{"opened", pr, nil, nil, nil},
	} {
		got, err := IssuesWebhook(event(tc.action, tc.issue, tc.extra), "github.com", tc.active)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, req := range got.Items {
			if len(req.Items) != 1 || req.Listing != nil || req.Version != 1 {
				t.Errorf("%s: request %+v", tc.action, req)
				continue
			}
			it := req.Items[0]
			reason := "<nil>"
			if it.StateReason != nil {
				reason = *it.StateReason
			}
			lines = append(lines, req.CollectionRef+" "+it.Ref+" "+it.State+" "+reason)
			if it.Target.Path != req.CollectionRef || it.Target.System != "github.com" {
				t.Errorf("%s: target %+v", tc.action, it.Target)
			}
		}
		if !reflect.DeepEqual(lines, tc.want) || len(got.Comments) != 0 || len(got.Skipped) != 0 {
			t.Errorf("%s: %v, want %v", tc.action, lines, tc.want)
		}
	}
	long := issue(1, 0)
	long["body"] = strings.Repeat("a", 70_000)
	got, _ := IssuesWebhook(event("edited", long, nil), "github.com", nil)
	if len(got.Items) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "acme/widgets#1", Why: "its body is longer than 65,536 characters"}}) {
		t.Errorf("long body: %+v", got.Skipped)
	}
	if _, err := IssuesWebhook([]byte("{"), "github.com", nil); err == nil {
		t.Error("a payload that is not JSON is taken")
	}
}

func TestAnIssueCommentEventIsTheComment(t *testing.T) {
	pr := issue(1, 0)
	pr["pull_request"] = map[string]any{"url": "https://api.github.com/repos/acme/widgets/pulls/1"}
	byPerson := comment(5, "bob", "User", "Me too.")
	marker := comment(6, "qory-test[bot]", "Bot", "<!-- qory:work-item 3 -->\nWork in Qory Apiary.")
	personsMarker := comment(7, "bob", "User", "<!-- qory:work-item 3 --> quoted")
	otherBot := comment(8, "other-app[bot]", "Bot", "<!-- qory:work-item 3 -->")
	// A login GitHub would give a bot alone, but not of type Bot, is not the App.
	notABot := comment(9, "qory-test[bot]", "User", "<!-- qory:work-item 3 -->")
	for _, tc := range []struct {
		action  string
		issue   map[string]any
		comment map[string]any
		want    string // ref author kind deleted, or "" for nothing
	}{
		{"created", issue(1, 1), byPerson, "5 bob person false"},
		{"edited", issue(1, 1), byPerson, "5 bob person false"},
		{"deleted", issue(1, 1), byPerson, "5 bob person true"},
		{"created", pr, byPerson, ""},
		{"deleted", pr, byPerson, ""},
		{"created", issue(1, 1), marker, ""},
		{"edited", issue(1, 1), marker, ""},
		{"deleted", issue(1, 1), marker, ""},
		{"created", issue(1, 1), personsMarker, "7 bob person false"},
		{"created", issue(1, 1), otherBot, "8 other-app[bot] automation false"},
		{"created", issue(1, 1), notABot, "9 qory-test[bot] person false"},
		{"pinned", issue(1, 1), byPerson, ""},
	} {
		got, err := IssueCommentWebhook(event(tc.action, tc.issue, map[string]any{"comment": tc.comment}), "qory-test")
		if err != nil {
			t.Fatal(err)
		}
		line := ""
		if len(got.Comments) == 1 && len(got.Comments[0].Comments) == 1 {
			req := got.Comments[0]
			c := req.Comments[0]
			line = fmt.Sprintf("%s %s %s %v", c.Ref, c.Author.Name, c.Author.Kind, c.Deleted)
			if req.ItemRef != "acme/widgets#1" || req.Complete != nil || req.Version != 1 || c.BodyFormat != "markdown" {
				t.Errorf("%s: request %+v", tc.action, req)
			}
		}
		if line != tc.want || len(got.Items) != 0 || len(got.Comments) > 1 {
			t.Errorf("%s %v: %q, want %q", tc.action, tc.comment["id"], line, tc.want)
		}
	}
}

// TestTheStartTimeIsTheClocks pins the fake clock's start the listing tests expect.
func TestTheStartTimeIsTheClocks(t *testing.T) {
	if got := t0.UTC().Format(time.RFC3339); got != "2026-09-21T14:13:20Z" {
		t.Errorf("t0 is %s", got)
	}
}

// TestAnIssueClosedDuringAListingSkipsNoOpenIssue closes the first issue once the first
// page is read, which in a list of open issues would move the third onto the first
// page, already read, and checks every open issue is sent all the same, and a closed
// issue is neither sent nor has its comments read.
func TestAnIssueClosedDuringAListingSkipsNoOpenIssue(t *testing.T) {
	closed := issue(6, 2)
	closed["state"], closed["state_reason"] = "closed", "completed"
	f := &fakeIssues{pageSize: 2, issues: []map[string]any{issue(1, 0), issue(2, 0), issue(3, 0), issue(4, 0), issue(5, 0), closed}}
	f.afterIssues = func(page int) {
		if page == 1 {
			f.issues[0]["state"] = "closed"
		}
	}
	s := &sink{}
	var logs []string
	if err := f.lister(t, s, &logs).ListIssues(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, req := range s.items() {
		for _, it := range req.Items {
			refs = append(refs, it.Ref+" "+it.State)
		}
	}
	if strings.Join(refs, ", ") != "acme/widgets#1 open, acme/widgets#2 open, acme/widgets#3 open, acme/widgets#4 open, acme/widgets#5 open" {
		t.Errorf("sent %v", refs)
	}
	for _, p := range f.requested() {
		if strings.Contains(p, "/comments") {
			t.Errorf("read %s", p)
		}
	}
}

// TestAListingReadsABoundedNumberOfPages checks a listing stops, with its error and a
// last part, at 2,000 pages of issues, at 100 pages of an issue's comments, and when a
// next page repeats one it read.
func TestAListingReadsABoundedNumberOfPages(t *testing.T) {
	var manyIssues []map[string]any
	for i := 1; i <= 2001; i++ {
		manyIssues = append(manyIssues, issue(i, 0))
	}
	manyComments := map[int][]map[string]any{1: {}}
	for i := range 101 {
		manyComments[1] = append(manyComments[1], comment(i+1, "bob", "User", "c"))
	}
	for _, tc := range []struct {
		name     string
		f        *fakeIssues
		err      string
		requests int
	}{
		{"issues", &fakeIssues{pageSize: 1, issues: manyIssues}, "listing the issues of acme/widgets: GitHub has more than 2000 pages, which a listing never reads", 1 + 2000},
		{"comments", &fakeIssues{pageSize: 1, issues: []map[string]any{issue(1, 101)}, comments: manyComments}, "listing the comments on acme/widgets#1: GitHub has more than 100 pages, which a listing never reads", 1 + 1 + 100},
		{"a repeated page", &fakeIssues{pageSize: 1, issues: []map[string]any{issue(1, 0), issue(2, 0)}, again: true}, "listing the issues of acme/widgets: GitHub's next page repeats one already read", 1 + 2},
	} {
		s := &sink{}
		var logs []string
		err := tc.f.lister(t, s, &logs).ListIssues(context.Background(), widgets)
		if err == nil || err.Error() != tc.err || len(tc.f.requested()) != tc.requests {
			t.Errorf("%s: err %v, %d requests", tc.name, err, len(tc.f.requested()))
		}
		items := s.items()
		if len(items) == 0 || items[len(items)-1].Listing.Complete {
			t.Errorf("%s: parts %d", tc.name, len(items))
		}
	}
}

func TestCommentsGoInRequestsOfAHundred(t *testing.T) {
	f := &fakeIssues{issues: []map[string]any{issue(1, 250)}, comments: map[int][]map[string]any{}}
	for i := range 250 {
		f.comments[1] = append(f.comments[1], comment(i+1, "bob", "User", "c"))
	}
	s := &sink{}
	var logs []string
	if err := f.lister(t, s, &logs).ListIssues(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, c := range s.comments() {
		sizes = append(sizes, len(c.Comments))
	}
	if !reflect.DeepEqual(sizes, []int{100, 100, 50}) {
		t.Errorf("requests of %v", sizes)
	}
}

// TestAWebhooksEventHasTheListingsChecks sends events from a repository Qory Apiary
// would refuse as a collection, and a deleted comment whose body was too long.
func TestAWebhooksEventHasTheListingsChecks(t *testing.T) {
	bad := map[string]any{"repository": map[string]any{"full_name": "acme/widgets", "html_url": "http://github.com/acme/widgets"}}
	got, _ := IssuesWebhook(event("opened", issue(1, 0), bad), "github.com", nil)
	if len(got.Items) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "acme/widgets#1", Why: "its collection: its URL is not https or is longer than 2,048 characters"}}) {
		t.Errorf("issues: %+v", got)
	}
	bad["comment"] = comment(5, "bob", "User", "c")
	got, _ = IssueCommentWebhook(event("created", issue(1, 1), bad), "qory-test")
	if len(got.Comments) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "5", Why: "its collection: its URL is not https or is longer than 2,048 characters"}}) {
		t.Errorf("issue_comment: %+v", got)
	}
	long := comment(5, "bob", "User", strings.Repeat("a", 70_000))
	got, _ = IssueCommentWebhook(event("edited", issue(1, 1), map[string]any{"comment": long}), "qory-test")
	if len(got.Comments) != 0 || len(got.Skipped) != 1 {
		t.Errorf("edited: %+v", got.Skipped)
	}
	got, _ = IssueCommentWebhook(event("deleted", issue(1, 1), map[string]any{"comment": long}), "qory-test")
	if len(got.Comments) != 1 || len(got.Skipped) != 0 || got.Comments[0].Comments[0].Body != "" || !got.Comments[0].Comments[0].Deleted {
		t.Errorf("deleted: %+v", got)
	}
}

// TestARepositoriesListingOfOnePageIsComplete lists the installation's repositories
// from one page, which says the listing is complete, from one page GitHub fails, and
// from two pages, neither of which does.
func TestARepositoriesListingOfOnePageIsComplete(t *testing.T) {
	for _, tc := range []struct {
		name     string
		n        int
		pageSize int
		fail     bool
		complete bool
		parts    int
	}{
		{"one page", 100, 100, false, true, 1},
		{"none", 0, 100, false, true, 1},
		{"two pages", 101, 100, false, false, 2},
		{"one page GitHub fails", 3, 100, true, false, 1},
		{"one page with a skip", 3, 100, false, false, 1},
	} {
		f := &fakeIssues{pageSize: tc.pageSize}
		for i := range tc.n {
			n := "repo" + strconv.Itoa(i)
			f.repos = append(f.repos, map[string]any{"full_name": "acme/" + n, "html_url": "https://github.com/acme/" + n})
		}
		total := 0
		if tc.name == "one page with a skip" {
			f.repos[1]["html_url"] = "http://github.com/acme/repo1"
			total = 1
		}
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		if tc.fail {
			l.Token = func(context.Context) (string, error) { return "", errors.New("no token") }
		}
		err := l.ListRepositories(context.Background())
		if (err != nil) != tc.fail || len(s.reqs) != tc.parts {
			t.Errorf("%s: err %v, %d parts", tc.name, err, len(s.reqs))
			continue
		}
		for i, req := range s.reqs {
			c := req.(contracts.SourceCollections)
			total += len(c.Collections)
			if c.Listing.Part != i+1 || c.Listing.Complete != (tc.complete && i == len(s.reqs)-1) {
				t.Errorf("%s: part %d says %+v", tc.name, i+1, c.Listing)
			}
		}
		if !tc.fail && total != tc.n {
			t.Errorf("%s: %d collections", tc.name, total)
		}
	}
}
