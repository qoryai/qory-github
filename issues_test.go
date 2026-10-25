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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// fakeIssues is GitHub's API as a listing reads it by REST: the comments of
// acme/widgets's issues, through its id, /repositories/1296269, and the installation's repositories, each pageSize to a page
// with a Link header to the next. It records the paths it is asked for.
type fakeIssues struct {
	srv      *httptest.Server
	comments map[int][]map[string]any
	repos    []map[string]any
	pageSize int
	// failComments answers that page of any issue's comments with a 500, and
	// failRepos that page of the installation's repositories; zero never does.
	failComments, failRepos int
	// again makes every page link its next to the first.
	again bool
	// goneComments answers the comments of that issue 404, as GitHub answers for an
	// issue deleted while it is listed.
	goneComments int
	// repoPage, when set, is the body of each page of the installation's repositories,
	// made from the page's number, counted from 1, and its repositories, in place of
	// one that holds them and total_count.
	repoPage func(page int, repos []map[string]any) any
	// env is each repository's environment definition, by its id, as GraphQL answers it;
	// a repository it does not name has none. gqlFail answers those GraphQL requests,
	// counted from 1, as it says: "502", "401", or "errors", a 200 whose error names no
	// node;
	// gqlLimited answers that many requests first with GraphQL's rate limit. gqlReverse
	// answers the nodes in the reverse order, and gqlDrop leaves the last out.
	env        map[int]fakeEnv
	gqlFail    map[int]string
	gqlLimited int
	gqlReverse bool
	gqlDrop    bool
	mu         sync.Mutex
	paths      []string
	auth       []string
	// gql are the node ids each GraphQL request named, and gqlBodies the requests.
	gql       [][]string
	gqlBodies []string
}

// fakeEnv is a repository's environment definition as GraphQL answers it: the object at
// .devcontainer, dir, and at .devcontainer.json, file, each its id, a tree for dir and a
// blob for file unless dirType or fileType says otherwise, "-" for no __typename, ""
// for none. nodeError answers the node null with an error of that type, null answers it
// null alone.
type fakeEnv struct {
	dir, file         string
	dirType, fileType string
	nodeError         string
	null              bool
}

// The Git object ids the tests' environment definitions have.
const (
	treeOID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	blobOID = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
)

// graphql answers a read of environment definitions, environmentQuery, by f.env.
func (f *fakeIssues) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string `json:"query"`
		Variables struct {
			IDs []string `json:"ids"`
		} `json:"variables"`
	}
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &req)
	f.mu.Lock()
	f.gql = append(f.gql, req.Variables.IDs)
	f.gqlBodies = append(f.gqlBodies, string(b))
	n := len(f.gql)
	f.mu.Unlock()
	if req.Query != environmentQuery {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"not the query"}`)
		return
	}
	switch {
	case n <= f.gqlLimited:
		io.WriteString(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
		return
	case f.gqlFail[n] == "502":
		w.WriteHeader(502)
		io.WriteString(w, `{"message":"Bad Gateway"}`)
		return
	case f.gqlFail[n] == "401":
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
		return
	case f.gqlFail[n] == "errors":
		io.WriteString(w, `{"data":null,"errors":[{"type":"SERVICE_UNAVAILABLE","message":"Something went wrong while executing your query."}]}`)
		return
	}
	nodes := []any{}
	errs := []any{}
	for i, node := range req.Variables.IDs {
		id, _ := strconv.Atoi(strings.TrimPrefix(node, "R_"))
		e := f.env[id]
		switch {
		case e.nodeError != "":
			nodes = append(nodes, nil)
			errs = append(errs, map[string]any{"type": e.nodeError, "path": []any{"nodes", i}, "message": "Resource not accessible by integration"})
			continue
		case e.null:
			nodes = append(nodes, nil)
			continue
		}
		object := func(oid, typ, dflt string) any {
			if oid == "" {
				return nil
			}
			if typ == "-" {
				return map[string]any{"oid": oid}
			}
			return map[string]any{"__typename": cmpOr(typ, dflt), "oid": oid}
		}
		nodes = append(nodes, map[string]any{"fullDatabaseId": strconv.Itoa(id), "dir": object(e.dir, e.dirType, "Tree"), "file": object(e.file, e.fileType, "Blob")})
	}
	if f.gqlReverse {
		slices.Reverse(nodes)
	}
	if f.gqlDrop && len(nodes) > 0 {
		nodes = nodes[:len(nodes)-1]
	}
	answer := map[string]any{"data": map[string]any{"nodes": nodes}}
	if len(errs) > 0 {
		answer["errors"] = errs
	}
	json.NewEncoder(w).Encode(answer)
}

// cmpOr is s, or else dflt when s is empty.
func cmpOr(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

var commentsPath = regexp.MustCompile(`^/repositories/1296269/issues/(\d+)/comments$`)

func (f *fakeIssues) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
		f.graphql(w, r)
		return
	}
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
		serve(f.repos, f.failRepos, func(s []map[string]any) any {
			if f.repoPage != nil {
				return f.repoPage(page, s)
			}
			return map[string]any{"total_count": len(f.repos), "repositories": s}
		})
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
		Client:       Client{API: f.srv.URL},
		Pacer:        clock.pacer(),
		Token:        func(context.Context) (string, error) { return fakeToken, nil },
		Slug:         "qory-test",
		ConnectionID: testConnection,
		GrantRef:     testGrant,
		Sink:         s,
		Logf:         func(format string, args ...any) { *logs = append(*logs, fmt.Sprintf(format, args...)) },
	}
}

// testConnection is the connection a test's listings name, and testGrant the grant
// their collections name.
const (
	testConnection = "ac_0123456789abcdef"
	testGrant      = "42"
)

// widgets is the repository the listings' tests read, and widgetsID and widgetsRef its id
// on GitHub and the ref of its collection, which that id is. gadgetsID is another's.
var widgets = Repository{Owner: "acme", Name: "widgets"}

const (
	widgetsID  = 1296269
	widgetsRef = "1296269"
	gadgetsID  = 1296270
)

// repoJSON is a repository as GitHub's REST answers it, with its id and its node id,
// R_ and the id.
func repoJSON(id int, fullName, htmlURL string) map[string]any {
	return map[string]any{"id": id, "node_id": "R_" + strconv.Itoa(id), "full_name": fullName, "html_url": htmlURL}
}

// TestListRepositoriesSendsTheCollectionsWithTheirTarget lists three repositories, one
// with a URL the contract refuses, and checks the two others are sent, each with its
// target and the grant_ref of the lister's grant.
func TestListRepositoriesSendsTheCollectionsWithTheirTarget(t *testing.T) {
	f := &fakeIssues{pageSize: 1}
	f.repos = append(f.repos, repoJSON(widgetsID, "acme/widgets", "https://github.com/acme/widgets"))
	f.repos = append(f.repos, repoJSON(gadgetsID, "acme/gadgets", "https://github.com/acme/gadgets"))
	f.repos = append(f.repos, repoJSON(1296271, "acme/broken", "ftp://github.com/acme/broken"))
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
		{Ref: "1296269", URL: "https://github.com/acme/widgets", Title: "acme/widgets", GrantRef: testGrant, Target: &contracts.Target{System: host, Path: "acme/widgets"}},
		{Ref: "1296270", URL: "https://github.com/acme/gadgets", Title: "acme/gadgets", GrantRef: testGrant, Target: &contracts.Target{System: host, Path: "acme/gadgets"}},
	}
	if !reflect.DeepEqual(got.Collections, want) || got.Listing.Part != 1 || got.Listing.Complete || got.Version != 1 || got.ConnectionID != testConnection {
		t.Errorf("collections %+v", got)
	}
	if !reflect.DeepEqual(logs, []string{"skipped the collection 1296271: its URL is not https or is longer than 2048 characters"}) {
		t.Errorf("logged %v", logs)
	}
	if strings.Join(f.requested(), " ") != "/installation/repositories?per_page=100 /installation/repositories?page=2&per_page=100 /installation/repositories?page=3&per_page=100" {
		t.Errorf("requested %v", f.requested())
	}
}

// TestARepositoryWithIssuesOffIsListedWithNoItems lists an installation's
// repositories, one GitHub answers with has_issues false, one with has_issues true and
// one with no has_issues, and checks, in the JSON sent, that the first collection says
// items false and the others have no items member.
func TestARepositoryWithIssuesOffIsListedWithNoItems(t *testing.T) {
	f := &fakeIssues{}
	off := repoJSON(widgetsID, "acme/widgets", "https://github.com/acme/widgets")
	off["has_issues"] = false
	on := repoJSON(gadgetsID, "acme/gadgets", "https://github.com/acme/gadgets")
	on["has_issues"] = true
	f.repos = append(f.repos, off, on, repoJSON(1296271, "acme/gizmos", "https://github.com/acme/gizmos"))
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.reqs) != 1 {
		t.Fatalf("requests %+v", s.reqs)
	}
	b, err := json.Marshal(s.reqs[0])
	if err != nil {
		t.Fatal(err)
	}
	var sent struct {
		Collections []map[string]json.RawMessage `json:"collections"`
		Listing     contracts.Listing            `json:"listing"`
	}
	if err := json.Unmarshal(b, &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent.Collections) != 3 || !sent.Listing.Complete {
		t.Fatalf("sent %s", b)
	}
	for i, want := range []string{"false", "", ""} {
		c := sent.Collections[i]
		items, ok := c["items"]
		if want == "" && ok || want != "" && string(items) != want {
			t.Errorf("collection %s: items %s, present %v, want %q", c["ref"], items, ok, want)
		}
	}
	if len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// TestARepositoryWithoutAnIDIsSkippedByItsName lists an installation's repositories,
// one GitHub answers without an id and one with an id that is not positive, and checks
// each is skipped and logged by its full_name, since no ref names it, the other sent,
// and the listing not complete.
func TestARepositoryWithoutAnIDIsSkippedByItsName(t *testing.T) {
	f := &fakeIssues{}
	f.repos = append(f.repos, repoJSON(widgetsID, "acme/widgets", "https://github.com/acme/widgets"))
	f.repos = append(f.repos, map[string]any{"full_name": "acme/no-id", "html_url": "https://github.com/acme/no-id"})
	f.repos = append(f.repos, repoJSON(-5, "acme/negative", "https://github.com/acme/negative"))
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.reqs) != 1 {
		t.Fatalf("requests %+v", s.reqs)
	}
	got := s.reqs[0].(contracts.SourceCollections)
	if len(got.Collections) != 1 || got.Collections[0].Ref != widgetsRef || got.Listing.Complete {
		t.Errorf("collections %+v", got)
	}
	want := []string{
		`skipped the collection of the repository "acme/no-id": GitHub answers it without an id, or with one that is not positive`,
		`skipped the collection of the repository "acme/negative": GitHub answers it without an id, or with one that is not positive`,
	}
	if !reflect.DeepEqual(logs, want) {
		t.Errorf("logged %q", logs)
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
	r := ghRepo{ID: widgetsID, FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
	base := ghIssue{
		Number: 42, Title: "Widgets spin backwards", Body: str("They should not."), State: "open",
		HTMLURL: "https://github.com/acme/widgets/issues/42", Labels: []ghLabel{{"bug"}, {"good first issue"}},
		User: &ghUser{Login: "alice", Type: "User"}, Comments: 3,
		CreatedAt: "2026-01-02T05:04:05+02:00", UpdatedAt: "2026-01-03T03:04:05Z",
	}
	it, why, _ := itemOf("github.com", r, base)
	want := contracts.Item{
		Ref: "1296269#42", URL: "https://github.com/acme/widgets/issues/42", Key: "#42", Title: "Widgets spin backwards", Body: "They should not.",
		BodyFormat: "markdown", Type: "issue", State: "open", Labels: []string{"bug", "good first issue"},
		FiledBy: contracts.Person{Name: "alice", Kind: "person"}, CommentCount: 3, CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-03T03:04:05Z",
		Target: &contracts.Target{System: "github.com", Path: "acme/widgets"},
	}
	if why != "" || !reflect.DeepEqual(it, want) {
		t.Errorf("item %+v, %s\nwant %+v", it, why, want)
	}
	if c := collectionOf(r); c != (contracts.Collection{Ref: "1296269", URL: "https://github.com/acme/widgets", Title: "acme/widgets"}) {
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
	it, _, _ := itemOf("github.com", ghRepo{ID: widgetsID, FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}, ghIssue{Number: 1, Title: "t", State: "open", HTMLURL: "https://github.com/acme/widgets/issues/1", CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-02T03:04:05Z"})
	b, _ := json.Marshal(contracts.SourceItems{Version: contracts.Version, Time: "2026-01-02T03:04:05Z", CollectionRef: widgetsRef, Items: []contracts.Item{it}})
	want := `{"version":1,"time":"2026-01-02T03:04:05Z","collection_ref":"1296269","items":[{"ref":"1296269#1","url":"https://github.com/acme/widgets/issues/1","key":"#1","type":"issue","title":"t","body":"","body_format":"markdown","filed_by":{"name":"ghost","kind":"person"},"labels":[],"state":"open","state_reason":null,"comment_count":0,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z","target":{"system":"github.com","path":"acme/widgets"}}]}`
	if string(b) != want {
		t.Errorf("items\n%s\nwant\n%s", b, want)
	}
	if bad := check(contracts.SourceItems{Version: contracts.Version, CollectionRef: widgetsRef, Items: []contracts.Item{it}}); bad != "" {
		t.Errorf("items: %s", bad)
	}
	got, _ := IssueCommentWebhook(event("deleted", issue(1, 1), map[string]any{"comment": comment(9, "bob", "User", "b")}), "qory-test")
	req := got.Comments[0]
	req.Time = "2026-01-02T03:04:05Z"
	b, _ = json.Marshal(req)
	if string(b) != `{"version":1,"time":"2026-01-02T03:04:05Z","item_ref":"1296269#1","comments":[{"ref":"9","url":"https://github.com/acme/widgets/issues/1#issuecomment-9","author":{"name":"bob","kind":"person"},"body":"","body_format":"markdown","created_at":"2026-01-04T00:00:00Z","updated_at":"2026-01-05T00:00:00Z","deleted":true}]}` {
		t.Errorf("comments %s", b)
	}
}

// event is a webhook payload: action on issue in acme/widgets, whose id is widgetsID,
// with extra fields.
func event(action string, issue map[string]any, extra map[string]any) []byte {
	ev := map[string]any{
		"action":       action,
		"issue":        issue,
		"repository":   repoJSON(widgetsID, "acme/widgets", "https://github.com/acme/widgets"),
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
	gadgets := repoJSON(gadgetsID, "acme/gadgets", "https://github.com/acme/gadgets")
	transfer := map[string]any{"changes": map[string]any{"new_issue": issue(9, 0), "new_repository": gadgets}}
	// A repository a transfer names without an id has no collection, so active is not
	// asked about it, and only the issue it left is sent.
	noID := map[string]any{"changes": map[string]any{"new_issue": issue(9, 0), "new_repository": map[string]any{"full_name": "acme/gadgets", "html_url": "https://github.com/acme/gadgets"}}}
	var asked []string
	active := func(ref string) bool { asked = append(asked, ref); return ref == "1296270" }
	inactive := func(string) bool { return false }
	for _, tc := range []struct {
		action string
		issue  map[string]any
		extra  map[string]any
		active func(string) bool
		want   []string // collection item key path state reason, one per items request
	}{
		{"opened", issue(1, 0), nil, nil, []string{"1296269 1296269#1 #1 acme/widgets open <nil>"}},
		{"reopened", issue(1, 0), nil, nil, []string{"1296269 1296269#1 #1 acme/widgets open <nil>"}},
		{"edited", issue(1, 0), map[string]any{"changes": map[string]any{"title": map[string]any{"from": "old"}}}, nil, []string{"1296269 1296269#1 #1 acme/widgets open <nil>"}},
		{"closed", closed, nil, nil, []string{"1296269 1296269#1 #1 acme/widgets closed Not planned"}},
		{"labeled", issue(1, 0), map[string]any{"label": map[string]any{"name": "bug"}}, nil, []string{"1296269 1296269#1 #1 acme/widgets open <nil>"}},
		{"unlabeled", issue(1, 0), nil, nil, []string{"1296269 1296269#1 #1 acme/widgets open <nil>"}},
		{"deleted", issue(1, 0), nil, nil, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>"}},
		{"deleted", closed, nil, nil, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>"}},
		{"transferred", issue(1, 0), transfer, active, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>", "1296270 1296270#9 #9 acme/gadgets open <nil>"}},
		{"transferred", issue(1, 0), transfer, inactive, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>"}},
		{"transferred", issue(1, 0), transfer, nil, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>"}},
		{"transferred", issue(1, 0), noID, active, []string{"1296269 1296269#1 #1 acme/widgets closed <nil>"}},
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
			lines = append(lines, req.CollectionRef+" "+it.Ref+" "+it.Key+" "+it.Target.Path+" "+it.State+" "+reason)
			if it.Target.System != "github.com" {
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
	if len(got.Items) != 1 || len(got.Skipped) != 0 || got.Items[0].Items[0].Body != strings.Repeat("a", 65_536) || !reflect.DeepEqual(got.Cut, []Cut{{Ref: "1296269#1", Field: "body", Length: 70_000}}) {
		t.Errorf("long body: %d requests, skipped %+v", len(got.Items), got.Skipped)
	}
	if _, err := IssuesWebhook([]byte("{"), "github.com", nil); err == nil {
		t.Error("a payload that is not JSON is taken")
	}
	if !reflect.DeepEqual(asked, []string{"1296270"}) {
		t.Errorf("active was asked about %q, want the collection ref of the repository a transfer names", asked)
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
			if req.ItemRef != "1296269#1" || req.Complete != nil || req.Version != 1 || c.BodyFormat != "markdown" {
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
	bad := map[string]any{"repository": repoJSON(widgetsID, "acme/widgets", "http://github.com/acme/widgets")}
	got, _ := IssuesWebhook(event("opened", issue(1, 0), bad), "github.com", nil)
	if len(got.Items) != 0 || !reflect.DeepEqual(got.Skipped, []Skipped{{Ref: "1296269#1", Why: "its collection: its URL is not https or is longer than 2048 characters"}}) {
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
// from one page, which says the listing is complete, and from two pages, which does not.
// A listing whose token fails sends no part; one whose second page of three GitHub
// fails sends the first page's collections in one part, not complete; and one whose
// first part Qory Apiary does not take sends no empty part after it.
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
		{"one page GitHub fails", 3, 100, true, false, 0},
		{"one page with a skip", 3, 100, false, false, 1},
		{"page 2 of 3 GitHub fails", 9, 3, true, false, 1},
		{"a part refused", 150, 100, true, false, 1},
	} {
		f := &fakeIssues{pageSize: tc.pageSize}
		for i := range tc.n {
			n := "repo" + strconv.Itoa(i)
			f.repos = append(f.repos, repoJSON(1000+i, "acme/"+n, "https://github.com/acme/"+n))
		}
		total := 0
		if tc.name == "one page with a skip" {
			f.repos[1]["html_url"] = "http://github.com/acme/repo1"
			total = 1
		}
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		switch tc.name {
		case "one page GitHub fails":
			l.Token = func(context.Context) (string, error) { return "", errors.New("no token") }
		case "page 2 of 3 GitHub fails":
			f.failRepos = 2
			total = -3
		case "a part refused":
			s.failAt = 1
			total = -100
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
		if !tc.fail && total != tc.n || tc.fail && tc.parts > 0 && total != 0 {
			t.Errorf("%s: %d collections", tc.name, total)
		}
	}
}

// TestReadRepositoriesReturnsThePartsAListingSendsAndSendsNone reads the installation's
// repositories, from one page, from two, and from one page with a skip: the parts are
// those ListRepositories sends, one listing's, its id and started_at on each, the same
// collections, part numbers and complete, and none is sent. A read GitHub fails on its
// second page returns no part, and sends none, not even the part that ends the listing.
func TestReadRepositoriesReturnsThePartsAListingSendsAndSendsNone(t *testing.T) {
	for _, tc := range []struct {
		name          string
		n, pageSize   int
		skip, failure bool
	}{
		{"one page", 100, 100, false, false},
		{"two pages", 250, 125, false, false},
		{"one page with a skip", 3, 100, true, false},
		{"two pages GitHub fails on the second", 150, 100, false, true},
	} {
		f := &fakeIssues{pageSize: tc.pageSize}
		for i := range tc.n {
			n := "repo" + strconv.Itoa(i)
			f.repos = append(f.repos, repoJSON(1000+i, "acme/"+n, "https://github.com/acme/"+n))
		}
		if tc.skip {
			f.repos[1]["html_url"] = "http://github.com/acme/repo1"
		}
		if tc.failure {
			f.failRepos = 2
		}
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		parts, err := l.ReadRepositories(context.Background())
		if len(s.reqs) != 0 {
			t.Errorf("%s: %d parts sent", tc.name, len(s.reqs))
		}
		if tc.failure {
			if err == nil || parts != nil {
				t.Errorf("%s: err %v, %d parts", tc.name, err, len(parts))
			}
			if n := len(f.requested()); n != 2 {
				t.Errorf("%s: %d pages requested", tc.name, n)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		read := logs
		logs = nil
		if err := l.ListRepositories(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(parts) != len(s.reqs) || !reflect.DeepEqual(read, logs) {
			t.Errorf("%s: %d parts read, %d sent; logged %v, then %v", tc.name, len(parts), len(s.reqs), read, logs)
			continue
		}
		if parts[0].Listing.ID == "" || parts[0].Listing.StartedAt == "" {
			t.Errorf("%s: the listing %+v", tc.name, parts[0].Listing)
		}
		for i, p := range parts {
			sent := s.reqs[i].(contracts.SourceCollections)
			if p.Listing.ID != parts[0].Listing.ID || p.Listing.StartedAt != parts[0].Listing.StartedAt || p.Listing.ID == sent.Listing.ID {
				t.Errorf("%s: part %d's listing %+v, the first's %+v, a listing's %+v", tc.name, i+1, p.Listing, parts[0].Listing, sent.Listing)
			}
			if p.Listing.Part != sent.Listing.Part || p.Listing.Complete != sent.Listing.Complete || !reflect.DeepEqual(p.Collections, sent.Collections) || p.ConnectionID != testConnection || p.Version != sent.Version {
				t.Errorf("%s: part %d read %+v, sent %+v", tc.name, i+1, p, sent)
			}
			if problem := check(p); problem != "" {
				t.Errorf("%s: part %d breaks the contract: %s", tc.name, i+1, problem)
			}
		}
	}
}

// envRepos are repositories of acme, 1001 to 1000+n, as GitHub's REST lists them.
func envRepos(f *fakeIssues, n int) {
	for i := 1; i <= n; i++ {
		name := "acme/repo" + strconv.Itoa(i)
		f.repos = append(f.repos, repoJSON(1000+i, name, "https://github.com/"+name))
	}
}

// envOf are the environment_refs a listing's parts sent, by the collection's ref, and
// the parts.
func envOf(t *testing.T, s *sink) (map[string]string, []contracts.SourceCollections) {
	t.Helper()
	got := map[string]string{}
	var parts []contracts.SourceCollections
	for _, r := range s.reqs {
		p := r.(contracts.SourceCollections)
		parts = append(parts, p)
		for _, c := range p.Collections {
			got[c.Ref] = c.EnvironmentRef
		}
	}
	return got, parts
}

// TestEachCollectionCarriesItsEnvironmentRef lists repositories with a .devcontainer
// folder, a .devcontainer.json file alone, both, neither, an empty repository, a
// .devcontainer that is a file beside a .devcontainer.json, and a .devcontainer.json
// that is a folder: each collection carries the folder's tree id, else the file's blob
// id, else none, which the JSON leaves out. One GraphQL request names every node id of
// the page, in order, and the listing is complete.
func TestEachCollectionCarriesItsEnvironmentRef(t *testing.T) {
	const otherBlob = "1111111111111111111111111111111111111111"
	f := &fakeIssues{env: map[int]fakeEnv{
		1001: {dir: treeOID},
		1002: {file: blobOID},
		1003: {dir: treeOID, file: blobOID},
		1006: {dir: otherBlob, dirType: "Blob", file: blobOID},
		1007: {file: treeOID, fileType: "Tree"},
	}}
	// 1004 has neither, and 1005 is empty: GraphQL answers both objects null for each.
	envRepos(f, 7)
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, parts := envOf(t, s)
	want := map[string]string{"1001": treeOID, "1002": blobOID, "1003": treeOID, "1004": "", "1005": "", "1006": blobOID, "1007": ""}
	if !reflect.DeepEqual(got, want) || len(parts) != 1 || !parts[0].Listing.Complete {
		t.Errorf("sent %v in %d parts, %+v", got, len(parts), parts)
	}
	b, _ := json.Marshal(parts[0])
	if n := strings.Count(string(b), `"environment_ref":`); n != 4 || strings.Contains(string(b), `"environment_ref":""`) {
		t.Errorf("%d environment_refs in %s", n, b)
	}
	if !reflect.DeepEqual(f.gql, [][]string{{"R_1001", "R_1002", "R_1003", "R_1004", "R_1005", "R_1006", "R_1007"}}) {
		t.Errorf("GraphQL was asked %v", f.gql)
	}
	if len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// TestACollectionWhoseEnvironmentCannotBeReadIsLeftOut lists repositories one of which
// GraphQL answers with an error, one as null, one with an object id that is not one, and
// one REST lists without a node id: each is left out of the listing, the others carry
// their refs, the one part says the listing is not complete, and one line says how many
// were left out, by LogLeftOut when it is set and else by Logf.
func TestACollectionWhoseEnvironmentCannotBeReadIsLeftOut(t *testing.T) {
	for _, custom := range []bool{false, true} {
		f := &fakeIssues{env: map[int]fakeEnv{
			1001: {dir: treeOID},
			1002: {nodeError: "FORBIDDEN"},
			1003: {null: true},
			1004: {dir: "not-an-object-id"},
			1006: {file: blobOID},
		}}
		envRepos(f, 6)
		delete(f.repos[4], "node_id")
		s := &sink{}
		var logs []string
		var counts []int
		l := f.lister(t, s, &logs)
		if custom {
			l.LogLeftOut = func(n int) { counts = append(counts, n) }
		}
		if err := l.ListRepositories(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, parts := envOf(t, s)
		if want := map[string]string{"1001": treeOID, "1006": blobOID}; !reflect.DeepEqual(got, want) || len(parts) != 1 || parts[0].Listing.Complete {
			t.Errorf("sent %v in %+v", got, parts)
		}
		if !reflect.DeepEqual(f.gql, [][]string{{"R_1001", "R_1002", "R_1003", "R_1004", "R_1006"}}) {
			t.Errorf("GraphQL was asked %v", f.gql)
		}
		switch {
		case custom && (!reflect.DeepEqual(counts, []int{4}) || len(logs) != 0):
			t.Errorf("LogLeftOut %v, logged %v", counts, logs)
		case !custom && !reflect.DeepEqual(logs, []string{"left out 4 collections whose environment definition (.devcontainer or .devcontainer.json) could not be read; the listing is not complete, and the next listing reads them again"}):
			t.Errorf("logged %q", logs)
		}
	}
}

// TestAnEnvironmentObjectOfAnUnknownKindIsLeftOut lists repositories whose .devcontainer
// or .devcontainer.json GraphQL answers without a __typename: each collection is left
// out, and the listing is not complete. A .devcontainer that is a commit, as a submodule
// is, or a blob, beside a .devcontainer.json blob, and a .devcontainer.json that is a
// tag or a tree, are read as the rule says: the blob's id, or none.
func TestAnEnvironmentObjectOfAnUnknownKindIsLeftOut(t *testing.T) {
	const otherBlob = "1111111111111111111111111111111111111111"
	f := &fakeIssues{env: map[int]fakeEnv{
		1001: {dir: treeOID, dirType: "-"},
		1002: {dir: treeOID, dirType: "Commit", file: blobOID},
		1003: {file: blobOID, fileType: "-"},
		1004: {file: blobOID, fileType: "Tag"},
		1005: {dir: otherBlob, dirType: "Blob", file: blobOID},
		1006: {file: treeOID, fileType: "Tree"},
		1007: {dir: otherBlob, dirType: "Blob", file: treeOID, fileType: "-"},
	}}
	envRepos(f, 7)
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, parts := envOf(t, s)
	if want := map[string]string{"1002": blobOID, "1004": "", "1005": blobOID, "1006": ""}; !reflect.DeepEqual(got, want) || len(parts) != 1 || parts[0].Listing.Complete {
		t.Errorf("sent %v in %+v", got, parts)
	}
	if !reflect.DeepEqual(logs, []string{"left out 3 collections whose environment definition (.devcontainer or .devcontainer.json) could not be read; the listing is not complete, and the next listing reads them again"}) {
		t.Errorf("logged %q", logs)
	}
}

// TestAnEnvironmentAnswerIsMatchedByTheRepositorysID lists repositories GraphQL answers
// in the reverse order, and then with the last node missing: each collection carries the
// ref of its repository, matched by fullDatabaseId, and the one missing is left out.
func TestAnEnvironmentAnswerIsMatchedByTheRepositorysID(t *testing.T) {
	for _, drop := range []bool{false, true} {
		f := &fakeIssues{env: map[int]fakeEnv{1001: {dir: treeOID}, 1003: {file: blobOID}}, gqlReverse: true, gqlDrop: drop}
		envRepos(f, 3)
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		if err := l.ListRepositories(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, parts := envOf(t, s)
		// Reversed, the last node is 1001's.
		want := map[string]string{"1001": treeOID, "1002": "", "1003": blobOID}
		if drop {
			delete(want, "1001")
		}
		if !reflect.DeepEqual(got, want) || parts[len(parts)-1].Listing.Complete != !drop {
			t.Errorf("drop %v: sent %v in %+v", drop, got, parts)
		}
	}
}

// TestAWholeEnvironmentReadThatFailsLeavesItsPageOut lists two pages of two
// repositories, the first page's GraphQL request failing, as a 502 and as an error that
// names no node: the first page's collections are left out, the second's sent, and the
// listing is not complete. A listing of one page whose request fails sends one part with
// no collection, not complete.
func TestAWholeEnvironmentReadThatFailsLeavesItsPageOut(t *testing.T) {
	for _, fail := range []string{"502", "errors"} {
		f := &fakeIssues{pageSize: 2, gqlFail: map[int]string{1: fail}, env: map[int]fakeEnv{1003: {dir: treeOID}}}
		envRepos(f, 4)
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		if err := l.ListRepositories(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, parts := envOf(t, s)
		if want := map[string]string{"1003": treeOID, "1004": ""}; !reflect.DeepEqual(got, want) || parts[len(parts)-1].Listing.Complete {
			t.Errorf("%s: sent %v in %+v", fail, got, parts)
		}
		if len(f.gql) != 2 || !reflect.DeepEqual(logs, []string{"left out 2 collections whose environment definition (.devcontainer or .devcontainer.json) could not be read; the listing is not complete, and the next listing reads them again"}) {
			t.Errorf("%s: GraphQL asked %v, logged %q", fail, f.gql, logs)
		}

		f = &fakeIssues{gqlFail: map[int]string{1: fail}}
		envRepos(f, 3)
		s = &sink{}
		l = f.lister(t, s, &logs)
		if err := l.ListRepositories(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got, parts := envOf(t, s); len(got) != 0 || len(parts) != 1 || parts[0].Listing.Complete {
			t.Errorf("%s: one page: sent %v in %+v", fail, got, parts)
		}
	}
}

// TestARateLimitedEnvironmentReadIsSentAgain answers GraphQL's rate limit twice, which
// is waited out and the request sent again, so nothing is left out and the listing is
// complete; and on every try, which stops the listing with an error and sends no part,
// since the listing read no collection that a part could carry.
func TestARateLimitedEnvironmentReadIsSentAgain(t *testing.T) {
	f := &fakeIssues{gqlLimited: 2, env: map[int]fakeEnv{1001: {dir: treeOID}}}
	envRepos(f, 2)
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, parts := envOf(t, s)
	if want := map[string]string{"1001": treeOID, "1002": ""}; !reflect.DeepEqual(got, want) || len(parts) != 1 || !parts[0].Listing.Complete || len(f.gql) != 3 || len(logs) != 0 {
		t.Errorf("sent %v in %+v after %d requests, logged %v", got, parts, len(f.gql), logs)
	}

	f = &fakeIssues{gqlLimited: limitedTries}
	envRepos(f, 2)
	s = &sink{}
	logs = nil
	l = f.lister(t, s, &logs)
	err := l.ListRepositories(context.Background())
	if !errors.Is(err, errStillLimited) || !strings.HasPrefix(err.Error(), "reading the environment definitions (.devcontainer or .devcontainer.json) of the installation's repositories: GitHub returned a rate-limit error on all 5 tries") {
		t.Errorf("err %v", err)
	}
	if got, parts := envOf(t, s); len(got) != 0 || len(parts) != 0 || len(f.gql) != limitedTries || len(logs) != 0 {
		t.Errorf("sent %v in %+v after %d requests, logged %v", got, parts, len(f.gql), logs)
	}
}

// TestAnEnvironmentReadGitHubAnswers401StopsTheListing answers GraphQL 401, as GitHub
// answers a token it no longer takes: the listing stops with that error, so the token is
// dropped, and no part is sent, since the listing read no collection that a part could
// carry.
func TestAnEnvironmentReadGitHubAnswers401StopsTheListing(t *testing.T) {
	f := &fakeIssues{gqlFail: map[int]string{1: "401"}}
	envRepos(f, 2)
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	err := l.ListRepositories(context.Background())
	if !Unauthorized(err) {
		t.Errorf("err %v", err)
	}
	if got, parts := envOf(t, s); len(got) != 0 || len(parts) != 0 || len(logs) != 0 {
		t.Errorf("sent %v in %+v, logged %v", got, parts, logs)
	}
}

// TestEnvironmentsAreReadAHundredRepositoriesAtATime lists a page GitHub answers with
// 250 repositories: GraphQL is asked in requests of 100, 100 and 50 node ids.
func TestEnvironmentsAreReadAHundredRepositoriesAtATime(t *testing.T) {
	f := &fakeIssues{pageSize: 250}
	envRepos(f, 250)
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListRepositories(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, ids := range f.gql {
		sizes = append(sizes, len(ids))
	}
	got, _ := envOf(t, s)
	if !reflect.DeepEqual(sizes, []int{100, 100, 50}) || len(got) != 250 {
		t.Errorf("requests of %v, %d collections", sizes, len(got))
	}
	if _, _, err := l.environments(context.Background(), l.Pacer, "reading", make([]envRepo, 101)); err == nil || len(f.gql) != 3 {
		t.Errorf("101 repositories: %v", err)
	}
}

// TestReadEnvironmentRef reads one repository's environment_ref by its node id: a
// folder's tree id, none, and an error for a node GraphQL answers with an error, as
// null, or a whole request that fails, which says GitHub's type and message.
func TestReadEnvironmentRef(t *testing.T) {
	f := &fakeIssues{env: map[int]fakeEnv{1001: {dir: treeOID}, 1003: {nodeError: "FORBIDDEN"}, 1004: {null: true}}}
	var logs []string
	l := f.lister(t, &sink{}, &logs)
	ctx := context.Background()
	if ref, err := l.ReadEnvironmentRef(ctx, 1001, "R_1001"); ref != treeOID || err != nil {
		t.Errorf("1001: %q %v", ref, err)
	}
	if ref, err := l.ReadEnvironmentRef(ctx, 1002, "R_1002"); ref != "" || err != nil {
		t.Errorf("1002: %q %v", ref, err)
	}
	if _, err := l.ReadEnvironmentRef(ctx, 1003, "R_1003"); err == nil || err.Error() != "reading the environment definition (.devcontainer or .devcontainer.json) of the repository 1003: GitHub returned an error, FORBIDDEN: Resource not accessible by integration" {
		t.Errorf("1003: %v", err)
	}
	if _, err := l.ReadEnvironmentRef(ctx, 1004, "R_1004"); err == nil || err.Error() != "reading the environment definition (.devcontainer or .devcontainer.json) of the repository 1004: GitHub's GraphQL response has no usable entry for the repository: it is null, missing, repeated, or has an invalid object id or type" {
		t.Errorf("1004: %v", err)
	}
	f.gqlFail = map[int]string{len(f.gql) + 1: "errors"}
	if _, err := l.ReadEnvironmentRef(ctx, 1001, "R_1001"); err == nil || err.Error() != "reading the environment definition (.devcontainer or .devcontainer.json) of the repository 1001: GitHub returned an error, SERVICE_UNAVAILABLE: Something went wrong while executing your query." {
		t.Errorf("a failed request: %v", err)
	}
	if _, err := l.ReadEnvironmentRef(ctx, 1001, ""); err == nil || len(f.gql) != 5 {
		t.Errorf("no node id: %v, %d requests", err, len(f.gql))
	}
	for _, body := range f.gqlBodies {
		if strings.Contains(body, fakeToken) {
			t.Errorf("a request carries the token: %s", body)
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
	r := ghRepo{ID: widgetsID, FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
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
		if bad := check(contracts.SourceItems{Version: contracts.Version, CollectionRef: widgetsRef, Items: []contracts.Item{it}}); bad != "" {
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
		if bad := check(contracts.SourceItemComments{Version: contracts.Version, ItemRef: "1296269#1", Comments: []contracts.Comment{sc}}); bad != "" {
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
	r := ghRepo{ID: widgetsID, FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
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
		if bad := check(contracts.SourceItems{Version: contracts.Version, CollectionRef: widgetsRef, Items: []contracts.Item{it}}); bad != "" {
			t.Errorf("%d characters: %s", len(tc.words), bad)
		}
	}
}

// TestU0000IsDroppedBeforeTheLimit checks cut and fit drop every U+0000, which the
// integration contract refuses in a text, before they count the limit: a text that only
// loses U+0000 is not a cut, a text at the limit once U+0000 is dropped is kept whole,
// and one past it is cut to the limit, as valid UTF-8, its cut logged with its length
// without U+0000.
func TestU0000IsDroppedBeforeTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		n, length      int
	}{
		{"U+0000 inside and at the end", "a\x00b\x00", "ab", 10, 0},
		{"U+0000 alone", "\x00\x00", "", 10, 0},
		{"at the limit with U+0000 inside", "üü\x00üü", "üüüü", 4, 0},
		{"past the limit with U+0000 inside", "üü\x00üüü", "üüüü", 4, 5},
		{"U+0000 at the cut", "üüüü\x00ü", "üüüü", 4, 5},
	} {
		if got := cut(tc.in, tc.n); got != tc.want || !utf8.ValidString(got) {
			t.Errorf("cut, %s: %q", tc.name, got)
		}
		var cuts []Cut
		got := fit(&cuts, "1296269#1", "title", tc.in, tc.n)
		var want []Cut
		if tc.length != 0 {
			want = []Cut{{Ref: "1296269#1", Field: "title", Length: tc.length}}
		}
		if got != tc.want || !utf8.ValidString(got) || !reflect.DeepEqual(cuts, want) {
			t.Errorf("fit, %s: %q, cuts %+v", tc.name, got, cuts)
		}
	}
}

// TestListedRepositoriesReadsEveryPage has the installation's list of repositories hold
// five, one on each page: every page is read, and the five ids are the list; a page
// GitHub fails, or a token that fails, is the error, and the list is none.
func TestListedRepositoriesReadsEveryPage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fail  int
		pages int
	}{
		{"every page", 0, 5},
		{"page 2 fails", 2, 2},
		{"page 5 fails", 5, 5},
	} {
		f := &fakeIssues{pageSize: 1, failRepos: tc.fail}
		for i := range 5 {
			n := "repo" + strconv.Itoa(i)
			f.repos = append(f.repos, repoJSON(1000+i, "acme/"+n, "https://github.com/acme/"+n))
		}
		s := &sink{}
		var logs []string
		l := f.lister(t, s, &logs)
		ids, err := l.ListedRepositories(context.Background())
		want := map[int64]bool{1000: true, 1001: true, 1002: true, 1003: true, 1004: true}
		if tc.fail != 0 {
			want = nil
		}
		if !reflect.DeepEqual(ids, want) || (err != nil) != (tc.fail != 0) {
			t.Errorf("%s: ids %v, err %v", tc.name, ids, err)
		}
		if n := len(f.requested()); n != tc.pages {
			t.Errorf("%s: %d pages read, want %d", tc.name, n, tc.pages)
		}
		if len(s.reqs) != 0 {
			t.Errorf("%s: %d requests sent", tc.name, len(s.reqs))
		}
	}
	f := &fakeIssues{pageSize: 1}
	l := f.lister(t, &sink{}, nil)
	l.Token = func(context.Context) (string, error) { return "", errors.New("no token") }
	if ids, err := l.ListedRepositories(context.Background()); ids != nil || err == nil {
		t.Errorf("a token that fails: ids %v, err %v", ids, err)
	}
}

// TestListedRepositoriesDecidesNothingOnAListThatDoesNotAddUp has the installation's
// list of repositories, five on five pages, answer pages that do not add up: a page
// with no repositories, or with them null, or with no total_count; a total_count that changes from page 2 on; a total_count above or below
// the repositories the pages name; and a repository named on two pages, which leaves
// one unread. Each is the error, and the list is none, with a text that says why.
func TestListedRepositoriesDecidesNothingOnAListThatDoesNotAddUp(t *testing.T) {
	const what = "listing the installation's repositories: "
	for _, tc := range []struct {
		name string
		page func(page int, repos []map[string]any) any
		dup  bool
		want string
	}{
		{"no repositories", func(page int, repos []map[string]any) any {
			if page == 2 {
				return map[string]any{"total_count": 5}
			}
			return map[string]any{"total_count": 5, "repositories": repos}
		}, false, "GitHub's page holds no list or no count of repositories"},
		{"repositories null", func(int, []map[string]any) any {
			return map[string]any{"total_count": 5, "repositories": nil}
		}, false, "GitHub's page holds no list or no count of repositories"},
		{"no total_count", func(page int, repos []map[string]any) any {
			if page == 3 {
				return map[string]any{"repositories": repos}
			}
			return map[string]any{"total_count": 5, "repositories": repos}
		}, false, "GitHub's page holds no list or no count of repositories"},
		{"total_count changes", func(page int, repos []map[string]any) any {
			return map[string]any{"total_count": 5 + min(page-1, 1), "repositories": repos}
		}, false, "GitHub's count of the installation's repositories changed while its pages were read"},
		{"more than the pages name", func(_ int, repos []map[string]any) any {
			return map[string]any{"total_count": 6, "repositories": repos}
		}, false, "GitHub counts 6 repositories, and its pages name 5"},
		{"fewer than the pages name", func(_ int, repos []map[string]any) any {
			return map[string]any{"total_count": 4, "repositories": repos}
		}, false, "GitHub counts 4 repositories, and its pages name 5"},
		{"one named twice", nil, true, "GitHub counts 5 repositories, and its pages name 4"},
	} {
		f := &fakeIssues{pageSize: 1, repoPage: tc.page}
		for i := range 5 {
			n := "repo" + strconv.Itoa(i)
			if tc.dup && i == 3 {
				n = "repo2"
			}
			id := 1000 + i
			if tc.dup && i == 3 {
				id = 1002
			}
			f.repos = append(f.repos, repoJSON(id, "acme/"+n, "https://github.com/acme/"+n))
		}
		l := f.lister(t, &sink{}, nil)
		ids, err := l.ListedRepositories(context.Background())
		if ids != nil || err == nil || err.Error() != what+tc.want {
			t.Errorf("%s: ids %v, err %v", tc.name, ids, err)
		}
	}
}
