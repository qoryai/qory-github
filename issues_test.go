package github

import (
	"bytes"
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
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// fakeIssues is GitHub's API as a listing reads it by REST: the comments of
// acme/widgets's issues, and the installation's repositories, each pageSize to a page
// with a Link header to the next. It records the paths it is asked for.
type fakeIssues struct {
	srv      *httptest.Server
	comments map[int][]map[string]any
	repos    []map[string]any
	pageSize int
	// failComments answers that page of any issue's comments with a 500; zero never
	// does.
	failComments int
	// again makes every page link its next to the first.
	again bool
	// goneComments answers the comments of that issue 404, as GitHub answers for an
	// issue deleted while it is listed.
	goneComments int
	mu           sync.Mutex
	paths        []string
	auth         []string
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
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?%s>; rel="next", <%s%s?page=99>; rel="last"`, f.srv.URL, r.URL.Path, q.Encode(), f.srv.URL, r.URL.Path))
		}
		json.NewEncoder(w).Encode(wrap(all[lo:hi]))
	}
	switch m := commentsPath.FindStringSubmatch(r.URL.Path); {
	case m != nil && m[1] == strconv.Itoa(f.goneComments):
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	case m != nil:
		n, _ := strconv.Atoi(m[1])
		serve(f.comments[n], f.failComments, func(s []map[string]any) any { return s })
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

// sink records the requests it is sent, and fails the call failAt, counted from 1. It
// checks each against the contract's schema, with the time the sink would set, and
// keeps what breaks it in broken, which a lister's test reports when it ends.
type sink struct {
	mu     sync.Mutex
	reqs   []any
	failAt int
	broken []string
}

// requestSchemas are the contract's schemas of the requests a sink is sent, compiled once.
var requestSchemas = sync.OnceValue(func() map[string]*jsonschema.Schema {
	out := map[string]*jsonschema.Schema{}
	for _, name := range []string{"source-collections.schema.json", "source-items.schema.json", "source-item-comments.schema.json", "sources-disconnect.schema.json"} {
		s, err := contracts.Compile(name)
		if err != nil {
			panic(err)
		}
		out[name] = s
	}
	return out
})

// check is why req breaks the contract's schema, or "".
func check(req any) string {
	const tm = "2026-01-02T03:04:05Z"
	var name string
	switch r := req.(type) {
	case contracts.SourceCollections:
		r.Time = tm
		name, req = "source-collections.schema.json", r
	case contracts.SourceItems:
		r.Time = tm
		name, req = "source-items.schema.json", r
	case contracts.SourceItemComments:
		r.Time = tm
		name, req = "source-item-comments.schema.json", r
	case contracts.SourcesDisconnect:
		r.Time = tm
		name, req = "sources-disconnect.schema.json", r
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err.Error()
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err == nil {
		err = requestSchemas()[name].Validate(doc)
	}
	if err != nil {
		return fmt.Sprintf("%s: %#v", name, err)
	}
	return ""
}

func (s *sink) add(req any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if why := check(req); why != "" {
		s.broken = append(s.broken, why)
	}
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
	if sk, ok := s.(*sink); ok {
		t.Cleanup(func() {
			sk.mu.Lock()
			defer sk.mu.Unlock()
			for _, why := range sk.broken {
				t.Errorf("a request breaks the contract: %s", why)
			}
		})
	}
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
	host := "127.0.0.1"
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
	if !reflect.DeepEqual(logs, []string{"skipped the collection acme/broken: its URL is not https or is longer than 2048 characters"}) {
		t.Errorf("logged %v", logs)
	}
	if strings.Join(f.requested(), " ") != "/installation/repositories?per_page=100 /installation/repositories?page=2&per_page=100 /installation/repositories?page=3&per_page=100" {
		t.Errorf("requested %v", f.requested())
	}
}

func TestTheTargetsSystemIsGitHubsWebsite(t *testing.T) {
	for api, want := range map[string]string{"": "github.com", "https://api.github.com": "github.com", "https://api.github.com/": "github.com", "http://127.0.0.1:8080": "127.0.0.1", "http://LocalHost:8080": "localhost", "http://[::1]:8080": "localhost"} {
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
	it, why, _ := itemOf("github.com", r, base)
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
		it, _, _ := itemOf("github.com", r, is)
		if it.State != tc.state || !reflect.DeepEqual(it.StateReason, tc.want) {
			t.Errorf("%s %v: state %s, reason %v", tc.state, tc.reason, it.State, it.StateReason)
		}
	}
	is := base
	is.Body, is.Labels, is.User = nil, nil, &ghUser{Login: "renovate[bot]", Type: "Bot"}
	it, _, _ = itemOf("github.com", r, is)
	if it.Body != "" || it.Labels == nil || len(it.Labels) != 0 || it.FiledBy != (contracts.Person{Name: "renovate[bot]", Kind: "automation"}) {
		t.Errorf("item %+v", it)
	}
	c, why, _ := commentOf(ghComment{ID: 1234567890123, HTMLURL: "https://github.com/acme/widgets/issues/42#issuecomment-1234567890123", Body: str("Same here."), User: &ghUser{Login: "ci", Type: "Bot"}, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"})
	if why != "" || !reflect.DeepEqual(c, contracts.Comment{Ref: "1234567890123", URL: "https://github.com/acme/widgets/issues/42#issuecomment-1234567890123", Author: contracts.Person{Name: "ci", Kind: "automation"}, Body: "Same here.", BodyFormat: "markdown", CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"}) {
		t.Errorf("comment %+v, %s", c, why)
	}
}

// TestTheWireIsTheContractsJSON checks the JSON an item and a comment of the adapter's
// become: the names, the nulls the contract wants and the fields it leaves out.
func TestTheWireIsTheContractsJSON(t *testing.T) {
	it, _, _ := itemOf("github.com", ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}, ghIssue{Number: 1, Title: "t", State: "open", HTMLURL: "https://github.com/acme/widgets/issues/1", CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-02T03:04:05Z"})
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
	if len(got.Items) != 1 || len(got.Skipped) != 0 || got.Items[0].Items[0].Body != strings.Repeat("a", 65_536) || !reflect.DeepEqual(got.Cut, []Cut{{Ref: "acme/widgets#1", Field: "body", Length: 70_000}}) {
		t.Errorf("long body: %d requests, skipped %+v", len(got.Items), got.Skipped)
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

// TestAWebhooksEventHasTheListingsChecks sends events from a repository Qory Apiary
// would refuse as a collection, and a comment whose body is too long, which is cut, and
// deleted, which is sent without it.
func TestAWebhooksEventHasTheListingsChecks(t *testing.T) {
	bad := map[string]any{"repository": map[string]any{"full_name": "acme/widgets", "html_url": "http://github.com/acme/widgets"}}
	got, _ := IssuesWebhook(event("opened", issue(1, 0), bad), "github.com", nil)
	if len(got.Items) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "acme/widgets#1", Why: "its collection: its URL is not https or is longer than 2048 characters"}}) {
		t.Errorf("issues: %+v", got)
	}
	bad["comment"] = comment(5, "bob", "User", "c")
	got, _ = IssueCommentWebhook(event("created", issue(1, 1), bad), "qory-test")
	if len(got.Comments) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "5", Why: "its collection: its URL is not https or is longer than 2048 characters"}}) {
		t.Errorf("issue_comment: %+v", got)
	}
	long := comment(5, "bob", "User", strings.Repeat("a", 70_000))
	got, _ = IssueCommentWebhook(event("edited", issue(1, 1), map[string]any{"comment": long}), "qory-test")
	if len(got.Comments) != 1 || len(got.Skipped) != 0 || got.Comments[0].Comments[0].Body != strings.Repeat("a", 65_536) || !reflect.DeepEqual(got.Cut, []Cut{{Ref: "5", Field: "body", Length: 70_000}}) {
		t.Errorf("edited: %d requests, skipped %+v", len(got.Comments), got.Skipped)
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

// TestGone checks which of GitHub's answers say what was asked for is gone or moved.
func TestGone(t *testing.T) {
	for status, want := range map[int]bool{404: true, 410: true, 301: true, 308: true, 302: false, 307: false, 401: false, 403: false, 422: false, 500: false, 502: false} {
		err := fmt.Errorf("listing: %w", &answerError{what: "reading", status: status, message: "m"})
		if Gone(err) != want {
			t.Errorf("%d: gone %v", status, !want)
		}
	}
	if Gone(nil) || Gone(errors.New("GitHub answered 404")) {
		t.Error("an error that is not GitHub's answer is gone")
	}
}

// truncatedMember is the truncated member of v's JSON, and whether it has one.
func truncatedMember(t *testing.T, v any) ([]string, bool) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	got, ok := m["truncated"]
	if !ok {
		return nil, false
	}
	var names []string
	for _, n := range got.([]any) {
		names = append(names, n.(string))
	}
	return names, true
}

// TestACutFieldIsNamedInTruncated cuts each field of an item and of a comment that the
// contract's truncated names, and several at once, and checks truncated names exactly
// the fields cut, in the order of the schema's enum, in the request the contract's
// schema takes: labels once, for a label cut, the labels past 100 left out, or both,
// and two labels equal once cut are sent once. An uncut item or comment has no
// truncated member.
func TestACutFieldIsNamedInTruncated(t *testing.T) {
	r := ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
	long := func(n int) string { return strings.Repeat("ü", n) }
	past := func(is *ghIssue) {
		for i := range 101 {
			is.Labels = append(is.Labels, ghLabel{"l" + strconv.Itoa(i)})
		}
	}
	for _, tc := range []struct {
		name   string
		edit   func(is *ghIssue)
		want   []string
		labels int
	}{
		{"nothing cut", func(*ghIssue) {}, nil, 0},
		{"the title", func(is *ghIssue) { is.Title = long(1025) }, []string{"title"}, 0},
		{"the body", func(is *ghIssue) { is.Body = str(long(65_537)) }, []string{"body"}, 0},
		{"the filer's name", func(is *ghIssue) { is.User = &ghUser{Login: long(101), Type: "User"} }, []string{"filed_by.name"}, 0},
		{"a label alone", func(is *ghIssue) { is.Labels = []ghLabel{{long(101)}} }, []string{"labels"}, 1},
		{"the labels past the most alone", past, []string{"labels"}, 100},
		{"a label and the labels past the most", func(is *ghIssue) {
			is.Labels = []ghLabel{{long(101)}}
			past(is)
		}, []string{"labels"}, 100},
		{"two labels equal once cut", func(is *ghIssue) {
			is.Labels = []ghLabel{{long(100) + "1"}, {"bug"}, {long(100) + "2"}}
		}, []string{"labels"}, 2},
		{"all four", func(is *ghIssue) {
			is.Title, is.Body, is.User, is.Labels = long(1025), str(long(65_537)), &ghUser{Login: long(101), Type: "Bot"}, []ghLabel{{long(101)}}
		}, []string{"title", "body", "filed_by.name", "labels"}, 1},
	} {
		is := ghIssue{
			Number: 42, Title: "Widgets spin backwards", Body: str("They should not."), State: "open",
			HTMLURL: "https://github.com/acme/widgets/issues/42", User: &ghUser{Login: "alice", Type: "User"},
			CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-03T03:04:05Z",
		}
		tc.edit(&is)
		it, why, cuts := itemOf("github.com", r, is)
		got, ok := truncatedMember(t, it)
		if why != "" || !reflect.DeepEqual(it.Truncated, tc.want) || ok != (tc.want != nil) || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("item, %s: truncated %q, member %v %q, %s", tc.name, it.Truncated, ok, got, why)
		}
		if tc.name != "nothing cut" && len(cuts) == 0 {
			t.Errorf("item, %s: no cut logged", tc.name)
		}
		if len(it.Labels) != tc.labels {
			t.Errorf("item, %s: %d labels %q", tc.name, len(it.Labels), it.Labels)
		}
		if bad := check(contracts.SourceItems{Version: contracts.Version, CollectionRef: "acme/widgets", Items: []contracts.Item{it}}); bad != "" {
			t.Errorf("item, %s: %s", tc.name, bad)
		}
	}
	for _, tc := range []struct {
		name string
		edit func(c *ghComment)
		want []string
	}{
		{"nothing cut", func(*ghComment) {}, nil},
		{"the body", func(c *ghComment) { c.Body = str(long(65_537)) }, []string{"body"}},
		{"the author's name", func(c *ghComment) { c.User = &ghUser{Login: long(101), Type: "User"} }, []string{"author.name"}},
		{"both", func(c *ghComment) { c.Body, c.User = str(long(65_537)), &ghUser{Login: long(101), Type: "Bot"} }, []string{"body", "author.name"}},
	} {
		c := ghComment{ID: 5, HTMLURL: "https://github.com/acme/widgets/issues/1#issuecomment-5", Body: str("Same here."), User: &ghUser{Login: "bob", Type: "User"}, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"}
		tc.edit(&c)
		sc, why, _ := commentOf(c)
		got, ok := truncatedMember(t, sc)
		if why != "" || !reflect.DeepEqual(sc.Truncated, tc.want) || ok != (tc.want != nil) || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("comment, %s: truncated %q, member %v %q, %s", tc.name, sc.Truncated, ok, got, why)
		}
		if bad := check(contracts.SourceItemComments{Version: contracts.Version, ItemRef: "acme/widgets#1", Comments: []contracts.Comment{sc}}); bad != "" {
			t.Errorf("comment, %s: %s", tc.name, bad)
		}
	}
}

// TestAWebhooksCutIsNamedInTruncated sends an issues event whose title, filer's name
// and two labels, equal once cut, are past their limits, one whose labels alone are, and
// an issue_comment event whose body is, and checks each request names the fields cut,
// the labels once, sent once, while an event with nothing cut names none.
func TestAWebhooksCutIsNamedInTruncated(t *testing.T) {
	is := issue(1, 1)
	is["title"] = strings.Repeat("t", 1025)
	is["user"] = map[string]any{"login": strings.Repeat("n", 101), "type": "User"}
	is["labels"] = []any{map[string]any{"name": strings.Repeat("a", 101)}, map[string]any{"name": strings.Repeat("a", 102)}}
	got, err := IssuesWebhook(event("edited", is, nil), "github.com", nil)
	if err != nil || len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].Items[0].Truncated, []string{"title", "filed_by.name", "labels"}) || !reflect.DeepEqual(got.Items[0].Items[0].Labels, []string{strings.Repeat("a", 100)}) {
		t.Fatalf("issues: %+v, %v", got, err)
	}
	if bad := check(got.Items[0]); bad != "" {
		t.Error(bad)
	}
	labelled := issue(1, 1)
	var labels []any
	for i := range 101 {
		labels = append(labels, map[string]any{"name": "l" + strconv.Itoa(i)})
	}
	labelled["labels"] = labels
	got, _ = IssuesWebhook(event("labeled", labelled, nil), "github.com", nil)
	if len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].Items[0].Truncated, []string{"labels"}) || len(got.Items[0].Items[0].Labels) != 100 {
		t.Fatalf("labeled: %+v", got)
	}
	if bad := check(got.Items[0]); bad != "" {
		t.Error(bad)
	}
	got, _ = IssuesWebhook(event("edited", issue(1, 1), nil), "github.com", nil)
	if _, ok := truncatedMember(t, got.Items[0].Items[0]); ok {
		t.Error("an uncut item has truncated")
	}
	got, err = IssueCommentWebhook(event("created", issue(1, 1), map[string]any{"comment": comment(5, "bob", "User", strings.Repeat("c", 65_537))}), "qory-test")
	if err != nil || len(got.Comments) != 1 || !reflect.DeepEqual(got.Comments[0].Comments[0].Truncated, []string{"body"}) {
		t.Fatalf("issue_comment: %+v, %v", got, err)
	}
	if bad := check(got.Comments[0]); bad != "" {
		t.Error(bad)
	}
	got, _ = IssueCommentWebhook(event("created", issue(1, 1), map[string]any{"comment": comment(5, "bob", "User", "c")}), "qory-test")
	if _, ok := truncatedMember(t, got.Comments[0].Comments[0]); ok {
		t.Error("an uncut comment has truncated")
	}
}

// TestAStateReasonPastItsLimitIsDropped words a reason, for this test alone, longer
// than the contract's limit of state_reason, and checks a closed issue with it has a
// null state_reason, records no cut, and is an item the contract's schema takes; a
// reason within the limit is sent as it is worded.
func TestAStateReasonPastItsLimitIsDropped(t *testing.T) {
	r := ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
	was := stateReasons["duplicate"]
	t.Cleanup(func() { stateReasons["duplicate"] = was })
	is := ghIssue{
		Number: 42, Title: "Widgets spin backwards", State: "closed", StateReason: str("duplicate"),
		HTMLURL: "https://github.com/acme/widgets/issues/42", CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-03T03:04:05Z",
	}
	n := contractLimits().stateReason
	for _, tc := range []struct {
		words string
		want  *string
	}{
		{strings.Repeat("d", n), str(strings.Repeat("d", n))},
		{strings.Repeat("d", n+1), nil},
	} {
		stateReasons["duplicate"] = tc.words
		it, why, cuts := itemOf("github.com", r, is)
		if why != "" || len(cuts) != 0 || it.Truncated != nil || !reflect.DeepEqual(it.StateReason, tc.want) {
			t.Errorf("%d characters: reason %v, cuts %+v, truncated %q, %s", len(tc.words), it.StateReason, cuts, it.Truncated, why)
		}
		if bad := check(contracts.SourceItems{Version: contracts.Version, CollectionRef: "acme/widgets", Items: []contracts.Item{it}}); bad != "" {
			t.Errorf("%d characters: %s", len(tc.words), bad)
		}
	}
}
