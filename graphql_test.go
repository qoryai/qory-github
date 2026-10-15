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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
)

// fakeGraphQL is GitHub's GraphQL API as [Lister.ListOpenIssuesComplete] reads it: the
// open issues of acme/widgets, pageSize to a page, oldest first, each page after the
// cursor of the last issue the page before it held. Every other request, the comments
// an issue has, goes to fakeIssues.
type fakeGraphQL struct {
	*fakeIssues
	// nodes are the issues, open and closed, in the order they were created, as
	// GraphQL says them.
	nodes []map[string]any
	// name is the repository as GitHub names it; "" is acme/widgets.
	name string
	// limited answers that many requests with GraphQL's rate limit, from the page
	// limitFrom on, counted from 1, and limitHeaders says with them that no request
	// remains until a minute after t0.
	limited, limitFrom int
	limitHeaders       bool
	// errorOn answers that page, counted from 1, with a GraphQL error, statusOn with
	// status; notFound answers that the repository cannot be resolved.
	errorOn, statusOn, status int
	notFound                  bool
	// sameCursor names the first page's cursor again on every page, noCursor names
	// none, and nullNode answers the first page's first issue as null.
	sameCursor, noCursor, nullNode bool
	// renameOn names the repository otherwise from that page on.
	renameOn int
	// closedToo answers the closed issues among the open ones, as GraphQL never
	// should, so a page can hold no open issue.
	closedToo bool
	// onPage, when set, is called with each page's number and request before the page
	// is answered, without g.mu held.
	onPage   func(page int, r *http.Request)
	mu       sync.Mutex
	vars     []map[string]any
	answered int
	// pages counts the answers that were not a rate limit.
	pages int
}

// node is an open issue of acme/widgets as GraphQL says it, filed by a person, with
// comments comments.
func node(n, comments int) map[string]any {
	return map[string]any{
		"number":      n,
		"url":         "https://github.com/acme/widgets/issues/" + strconv.Itoa(n),
		"title":       "Widget " + strconv.Itoa(n) + " is broken",
		"body":        "It does not turn.",
		"state":       "OPEN",
		"stateReason": nil,
		"labels":      map[string]any{"nodes": []any{map[string]any{"name": "bug"}}},
		"author":      map[string]any{"login": "alice", "__typename": "User"},
		"createdAt":   "2026-01-02T03:04:05Z",
		"updatedAt":   "2026-01-03T03:04:05Z",
		"comments":    map[string]any{"totalCount": comments},
	}
}

func (g *fakeGraphQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/graphql" {
		g.fakeIssues.ServeHTTP(w, r)
		return
	}
	g.fakeIssues.mu.Lock()
	g.fakeIssues.paths = append(g.fakeIssues.paths, r.Method+" "+r.URL.RequestURI())
	g.fakeIssues.auth = append(g.fakeIssues.auth, r.Header.Get("Authorization"))
	g.fakeIssues.mu.Unlock()
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Query != openIssuesQuery {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"Problems parsing JSON"}`)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.answered++
	if g.limited > 0 && g.pages+1 >= g.limitFrom {
		g.limited--
		if g.limitHeaders {
			w.Header().Set("X-Ratelimit-Limit", "5000")
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", strconv.FormatInt(t0.Add(time.Minute*2).Unix(), 10))
		}
		io.WriteString(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
		return
	}
	g.vars = append(g.vars, req.Variables)
	g.pages++
	page := g.pages
	if on := g.onPage; on != nil {
		g.mu.Unlock()
		on(page, r)
		g.mu.Lock()
	}
	if page == g.statusOn {
		w.WriteHeader(g.status)
		io.WriteString(w, `{"message":"Bad credentials"}`)
		return
	}
	if g.notFound {
		io.WriteString(w, `{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve to a Repository with the name 'acme/widgets'."}]}`)
		return
	}
	if page == g.errorOn {
		io.WriteString(w, `{"data":null,"errors":[{"type":"SERVICE_UNAVAILABLE","message":"Something went wrong while executing your query."},{"message":"and another"}]}`)
		return
	}
	after := 0
	if c, ok := req.Variables["after"].(string); ok {
		after, _ = strconv.Atoi(strings.TrimPrefix(c, "cursor:"))
	}
	first := int(req.Variables["first"].(float64))
	var nodes []any
	more := false
	for _, n := range g.nodes {
		if n["state"] != "OPEN" && !g.closedToo || n["number"].(int) <= after {
			continue
		}
		if len(nodes) == first {
			more = true
			break
		}
		nodes = append(nodes, n)
	}
	if nodes == nil {
		nodes = []any{}
	}
	var end any
	if len(nodes) > 0 {
		end = "cursor:" + strconv.Itoa(nodes[len(nodes)-1].(map[string]any)["number"].(int))
	}
	switch {
	case g.sameCursor:
		end = "cursor:" + strconv.Itoa(g.nodes[first-1]["number"].(int))
	case g.noCursor:
		end = nil
	}
	if g.nullNode && page == 1 {
		nodes[0] = nil
	}
	name := g.name
	if name == "" {
		name = "acme/widgets"
	}
	if g.renameOn != 0 && page >= g.renameOn {
		name = "acme/gadgets"
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": map[string]any{
		"nameWithOwner": name,
		"url":           "https://github.com/" + name,
		"issues": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": more, "endCursor": end},
			"nodes":    nodes,
		},
	}}})
}

// lister lists g into s, with a clock that never sleeps, and records what it logs.
func (g *fakeGraphQL) lister(t *testing.T, s Sink, logs *[]string) (Lister, *fakeClock) {
	t.Helper()
	if g.fakeIssues == nil {
		g.fakeIssues = &fakeIssues{}
	}
	if g.pageSize == 0 {
		g.pageSize = 100
	}
	g.srv = httptest.NewServer(g)
	t.Cleanup(g.srv.Close)
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
		Client: Client{API: g.srv.URL},
		Pacer:  clock.pacer(),
		Token:  func(context.Context) (string, error) { return fakeToken, nil },
		Slug:   "qory-test",
		Sink:   s,
		Logf:   func(format string, args ...any) { *logs = append(*logs, fmt.Sprintf(format, args...)) },
	}, clock
}

// afters are the cursors the pages were asked after, "-" for none.
func (g *fakeGraphQL) afters() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, v := range g.vars {
		a, _ := v["after"].(string)
		if v["after"] == nil {
			a = "-"
		}
		out = append(out, a)
	}
	return out
}

// sentParts are the refs of every item sent, in order, and the parts' listings.
func sentParts(s *sink) ([]string, []contracts.Listing) {
	var refs []string
	var parts []contracts.Listing
	for _, req := range s.items() {
		for _, it := range req.Items {
			refs = append(refs, it.Ref)
		}
		if req.Listing != nil {
			parts = append(parts, *req.Listing)
		}
	}
	return refs, parts
}

// TestTheCompleteListingPagesByCursor lists five open issues, two to a page, and a
// closed one GraphQL leaves out, and checks each page is asked for by POST to /graphql
// with the token, after the cursor of the page before it; the items are sent once, in
// one part that says the listing is complete; and the comments are read by REST, the
// App's work item comment left out, in a request that says nothing of complete.
func TestTheCompleteListingPagesByCursor(t *testing.T) {
	closed := node(3, 0)
	closed["state"], closed["stateReason"] = "CLOSED", "COMPLETED"
	g := &fakeGraphQL{
		fakeIssues: &fakeIssues{comments: map[int][]map[string]any{
			1: {
				comment(11, "qory-test[bot]", "Bot", "<!-- qory:work-item 7 -->\nThis issue is work in Qory Apiary."),
				comment(12, "bob", "User", "Same here."),
			},
		}},
		nodes: []map[string]any{node(1, 2), node(2, 0), closed, node(4, 0), node(5, 0), node(6, 0)},
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	p := l.pacerOr()
	pager := l.issuePager(p, widgets, 2)
	var pages [][]int64
	for {
		_, page, more, err := pager.next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
		var ns []int64
		for _, is := range page {
			ns = append(ns, is.Number)
		}
		pages = append(pages, ns)
	}
	if fmt.Sprint(pages) != "[[1 2] [4 5] [6]]" || strings.Join(g.afters(), " ") != "- cursor:2 cursor:5" {
		t.Errorf("pages %v after %v", pages, g.afters())
	}
	g.vars = nil
	g.fakeIssues.paths = nil
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /graphql", "/repos/acme/widgets/issues/1/comments?per_page=100"}
	if got := g.requested(); !reflect.DeepEqual(got, want) {
		t.Errorf("requested %v", got)
	}
	if v := g.vars[0]; v["owner"] != "acme" || v["name"] != "widgets" || v["first"] != float64(100) || v["after"] != nil {
		t.Errorf("variables %v", v)
	}
	for _, a := range g.auth {
		if a != "Bearer "+fakeToken {
			t.Errorf("authorization %q", a)
		}
	}
	refs, parts := sentParts(s)
	if strings.Join(refs, " ") != "acme/widgets#1 acme/widgets#2 acme/widgets#4 acme/widgets#5 acme/widgets#6" {
		t.Errorf("items %v", refs)
	}
	if len(parts) != 1 || parts[0].Part != 1 || !parts[0].Complete || parts[0].StartedAt != "2026-09-21T14:13:20Z" || s.items()[0].CollectionRef != "acme/widgets" {
		t.Errorf("parts %+v", parts)
	}
	cs := s.comments()
	if len(cs) != 1 || cs[0].ItemRef != "acme/widgets#1" || len(cs[0].Comments) != 1 || cs[0].Comments[0].Ref != "12" || cs[0].Complete != nil {
		t.Errorf("comments %+v", cs)
	}
	if len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// TestAGraphQLIssueMapsAsRESTsDoes maps issues GraphQL says to items and checks each is
// the item the same issue makes as REST says it: a person, a bot, whose GraphQL login
// lacks REST's [bot], an author GitHub no longer has, a closed issue's reason, and a
// time with an offset.
func TestAGraphQLIssueMapsAsRESTsDoes(t *testing.T) {
	r := ghRepo{FullName: "acme/widgets", HTMLURL: "https://github.com/acme/widgets"}
	rest := ghIssue{
		Number: 42, Title: "Widgets spin backwards", Body: str("They should not."), State: "open",
		HTMLURL: "https://github.com/acme/widgets/issues/42", Labels: []ghLabel{{"bug"}, {"good first issue"}},
		User: &ghUser{Login: "alice", Type: "User"}, Comments: 3,
		CreatedAt: "2026-01-02T05:04:05+02:00", UpdatedAt: "2026-01-03T03:04:05Z",
	}
	gql := `{"number":42,"url":"https://github.com/acme/widgets/issues/42","title":"Widgets spin backwards","body":"They should not.","state":"OPEN","stateReason":null,
		"labels":{"nodes":[{"name":"bug"},{"name":"good first issue"}]},"author":{"login":"alice","__typename":"User"},
		"createdAt":"2026-01-02T05:04:05+02:00","updatedAt":"2026-01-03T03:04:05Z","comments":{"totalCount":3}}`
	for _, tc := range []struct {
		name string
		edit func(rest *ghIssue, gql map[string]any)
	}{
		{"a person", func(*ghIssue, map[string]any) {}},
		{"a bot", func(rest *ghIssue, gql map[string]any) {
			rest.User = &ghUser{Login: "renovate[bot]", Type: "Bot"}
			gql["author"] = map[string]any{"login": "renovate", "__typename": "Bot"}
		}},
		{"an organization", func(rest *ghIssue, gql map[string]any) {
			rest.User = &ghUser{Login: "acme", Type: "Organization"}
			gql["author"] = map[string]any{"login": "acme", "__typename": "Organization"}
		}},
		{"a ghost", func(rest *ghIssue, gql map[string]any) {
			rest.User = nil
			gql["author"] = nil
		}},
		{"an empty body", func(rest *ghIssue, gql map[string]any) {
			rest.Body = nil
			gql["body"] = ""
		}},
		{"closed as not planned", func(rest *ghIssue, gql map[string]any) {
			rest.State, rest.StateReason = "closed", str("not_planned")
			gql["state"], gql["stateReason"] = "CLOSED", "NOT_PLANNED"
		}},
		{"closed as a duplicate", func(rest *ghIssue, gql map[string]any) {
			rest.State, rest.StateReason = "closed", str("duplicate")
			gql["state"], gql["stateReason"] = "CLOSED", "DUPLICATE"
		}},
		{"reopened", func(rest *ghIssue, gql map[string]any) {
			rest.StateReason = str("reopened")
			gql["stateReason"] = "REOPENED"
		}},
	} {
		is := rest
		var m map[string]any
		json.Unmarshal([]byte(gql), &m)
		tc.edit(&is, m)
		b, _ := json.Marshal(m)
		var n gqlIssue
		if err := json.Unmarshal(b, &n); err != nil {
			t.Fatal(err)
		}
		want, wantWhy, _ := itemOf("github.com", r, is)
		got, why, _ := itemOf("github.com", r, n.issue())
		if why != wantWhy || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: item %+v, %q\nwant %+v, %q", tc.name, got, why, want, wantWhy)
		}
	}
}

// TestTheCompleteListingIsSentInPartsOfAHundredItemsAndAMebibyte lists 250 small
// issues, 100 to a page, a hundred, two hundred, none, and 40 with long bodies, and
// checks the parts: at most 100 items and 1 MiB of JSON each, numbered from 1, one
// listing, the last alone complete, and every item sent once. A count that is a
// multiple of 100 ends with a full part that says complete; a repository with no open
// issue sends one part without items that says complete.
func TestTheCompleteListingIsSentInPartsOfAHundredItemsAndAMebibyte(t *testing.T) {
	long := strings.Repeat("ü", 60_000)
	for _, tc := range []struct {
		name   string
		n      int
		body   string
		parts  []int
		afters string
	}{
		{"small", 250, "", []int{100, 100, 50}, "- cursor:100 cursor:200"},
		{"exactly a hundred", 100, "", []int{100}, "-"},
		{"two hundred", 200, "", []int{100, 100}, "- cursor:100"},
		{"none", 0, "", []int{0}, "-"},
		{"long bodies", 40, long, nil, "-"},
	} {
		g := &fakeGraphQL{}
		for i := 1; i <= tc.n; i++ {
			n := node(i, 0)
			if tc.body != "" {
				n["body"] = tc.body
			}
			g.nodes = append(g.nodes, n)
		}
		s := &sink{}
		var logs []string
		l, _ := g.lister(t, s, &logs)
		if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
			t.Fatal(err)
		}
		items := s.items()
		sizes := []int{}
		total := 0
		for i, req := range items {
			// The sink sets the time as it sends.
			req.Time = "2026-01-02T03:04:05Z"
			b, _ := json.Marshal(req)
			if len(b) > contracts.MaxRequest {
				t.Errorf("%s: part %d is %d bytes", tc.name, i+1, len(b))
			}
			if req.Listing.Part != i+1 || req.Listing.Complete != (i == len(items)-1) || req.Listing.ID != items[0].Listing.ID {
				t.Errorf("%s: part %d says %+v", tc.name, i+1, req.Listing)
			}
			sizes = append(sizes, len(req.Items))
			total += len(req.Items)
		}
		if tc.parts != nil && !slices.Equal(sizes, tc.parts) {
			t.Errorf("%s: parts of %v, want %v", tc.name, sizes, tc.parts)
		}
		if tc.parts == nil && (len(items) < 2 || total != tc.n) {
			t.Errorf("%s: parts of %v", tc.name, sizes)
		}
		if got := strings.Join(g.afters(), " "); got != tc.afters {
			t.Errorf("%s: after %v", tc.name, got)
		}
	}
}

// TestASkippedItemLeavesTheListingNotComplete lists an issue Qory Apiary would refuse,
// with an empty title, and checks it is skipped and logged by its ref, the rest are
// sent, and the listing does not say it is complete, so Qory Apiary closes nothing for
// the item it did not get; a listing whose one item is skipped sends no part. A
// repository without an open issue, read without error, sends exactly one part, without
// items, that says the listing is complete, as does one whose pages GitHub answers
// with no open issue.
func TestASkippedItemLeavesTheListingNotComplete(t *testing.T) {
	empty := node(2, 0)
	empty["title"] = ""
	g := &fakeGraphQL{nodes: []map[string]any{node(1, 0), empty, node(3, 0)}}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	refs, parts := sentParts(s)
	if strings.Join(refs, " ") != "acme/widgets#1 acme/widgets#3" || len(parts) != 1 || parts[0].Complete {
		t.Errorf("items %v, parts %+v", refs, parts)
	}
	if strings.Join(logs, "\n") != "skipped the item acme/widgets#2: its title is empty" {
		t.Errorf("logged %v", logs)
	}

	g = &fakeGraphQL{nodes: []map[string]any{empty}}
	s = &sink{}
	l, _ = g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil || len(s.reqs) != 0 {
		t.Errorf("one item skipped: err %v, requests %+v", err, s.reqs)
	}

	closed := node(1, 0)
	closed["state"] = "CLOSED"
	for name, g := range map[string]*fakeGraphQL{
		"no issue":                    {},
		"a closed issue":              {nodes: []map[string]any{closed}},
		"pages without an open issue": {nodes: closedNodes(3), closedToo: true},
	} {
		s := &sink{}
		var logs []string
		l, _ := g.lister(t, s, &logs)
		err := l.listOpenComplete(context.Background(), widgets, 1)
		refs, parts := sentParts(s)
		if err != nil || len(s.reqs) != 1 || len(refs) != 0 || len(parts) != 1 || parts[0].Part != 1 || !parts[0].Complete || s.items()[0].Items == nil {
			t.Errorf("%s: err %v, requests %+v", name, err, s.reqs)
		}
	}
}

// TestAnEmptyListingThatFailsSendsNothing reads a repository with no open issue, or
// pages GitHub answers without one, and fails or stops the read on its first or second
// page, and checks the listing returns its error and sends no part, so none says
// complete.
func TestAnEmptyListingThatFailsSendsNothing(t *testing.T) {
	pages := func() []map[string]any { return closedNodes(3) }
	cancelOn := func(page int) func(g *fakeGraphQL) context.Context {
		return func(g *fakeGraphQL) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			g.onPage = func(p int, r *http.Request) {
				if p == page {
					cancel()
					select {
					case <-r.Context().Done():
					case <-time.After(10 * time.Second):
					}
				}
			}
			return ctx
		}
	}
	for _, tc := range []struct {
		name string
		g    *fakeGraphQL
		ctx  func(g *fakeGraphQL) context.Context
	}{
		{name: "a status on the first page", g: &fakeGraphQL{statusOn: 1, status: 502}},
		{name: "GraphQL's errors on the first page", g: &fakeGraphQL{errorOn: 1}},
		{name: "a rate limit that holds on the first page", g: &fakeGraphQL{limited: 5}},
		{name: "the repository not found", g: &fakeGraphQL{notFound: true}},
		{name: "the repository renamed", g: &fakeGraphQL{name: "acme/gadgets"}},
		{name: "the context cancelled on the first page", g: &fakeGraphQL{}, ctx: cancelOn(1)},
		{name: "a status on the second page", g: &fakeGraphQL{nodes: pages(), closedToo: true, statusOn: 2, status: 502}},
		{name: "GraphQL's errors on the second page", g: &fakeGraphQL{nodes: pages(), closedToo: true, errorOn: 2}},
		{name: "a rate limit that holds on the second page", g: &fakeGraphQL{nodes: pages(), closedToo: true, limited: 5, limitFrom: 2}},
		{name: "no cursor for the next page", g: &fakeGraphQL{nodes: pages(), closedToo: true, noCursor: true}},
		{name: "the next cursor repeated", g: &fakeGraphQL{nodes: pages(), closedToo: true, sameCursor: true}},
		{name: "the context cancelled on the second page", g: &fakeGraphQL{nodes: pages(), closedToo: true}, ctx: cancelOn(2)},
	} {
		s := &sink{}
		var logs []string
		l, _ := tc.g.lister(t, s, &logs)
		ctx := context.Background()
		if tc.ctx != nil {
			ctx = tc.ctx(tc.g)
		}
		if err := l.listOpenComplete(ctx, widgets, 1); err == nil || len(s.reqs) != 0 {
			t.Errorf("%s: err %v, requests %+v", tc.name, err, s.reqs)
		}
	}
}

// TestTheCompleteListingFailsOnWhatItCannotTrust checks a listing stops with its error
// on each answer it cannot list completely from, and the items it read and had not
// sent go as a last part that is not complete; a listing that fails on its first page
// sends nothing.
func TestTheCompleteListingFailsOnWhatItCannotTrust(t *testing.T) {
	five := func() []map[string]any {
		return []map[string]any{node(1, 0), node(2, 0), node(3, 0), node(4, 0), node(5, 0)}
	}
	const what = "listing the open issues of acme/widgets: "
	for _, tc := range []struct {
		name  string
		g     *fakeGraphQL
		err   string
		gone  bool
		sent  string
		pages int
	}{
		{"a GraphQL error", &fakeGraphQL{nodes: five(), errorOn: 2}, what + "GitHub answered 2 errors, the first SERVICE_UNAVAILABLE: Something went wrong while executing your query.", false, "1 2", 2},
		{"a GraphQL error on the first page", &fakeGraphQL{nodes: five(), errorOn: 1}, what + "GitHub answered 2 errors, the first SERVICE_UNAVAILABLE: Something went wrong while executing your query.", false, "", 1},
		{"a status", &fakeGraphQL{nodes: five(), statusOn: 3, status: 502}, what + "GitHub answered 502: Bad credentials", false, "1 2 3 4", 3},
		{"the repository not found", &fakeGraphQL{nodes: five(), notFound: true}, "the repository is deleted, moved or out of the App's reach: " + what + "GitHub answered: Could not resolve to a Repository with the name 'acme/widgets'.", true, "", 1},
		{"the repository renamed", &fakeGraphQL{nodes: five(), name: "acme/gadgets"}, "the repository is deleted, moved or out of the App's reach: " + what + "GitHub names the repository acme/gadgets", true, "", 1},
		{"the repository renamed while it is listed", &fakeGraphQL{nodes: five(), renameOn: 2}, "the repository is deleted, moved or out of the App's reach: " + what + "GitHub names the repository acme/gadgets", true, "1 2", 2},
		{"a cursor repeated", &fakeGraphQL{nodes: five(), sameCursor: true}, what + "GitHub's next cursor repeats one already read", false, "1 2", 2},
		{"no cursor", &fakeGraphQL{nodes: five(), noCursor: true}, what + "GitHub says there is a next page and names no cursor for it", false, "", 1},
		{"an issue as null", &fakeGraphQL{nodes: five(), nullNode: true}, what + "GitHub answered an issue as null", false, "", 1},
	} {
		s := &sink{}
		var logs []string
		l, _ := tc.g.lister(t, s, &logs)
		err := l.listOpenComplete(context.Background(), widgets, 2)
		if err == nil || err.Error() != tc.err || errors.Is(err, ErrRepositoryGone) != tc.gone {
			t.Errorf("%s: err %v", tc.name, err)
		}
		refs, parts := sentParts(s)
		got := strings.ReplaceAll(strings.Join(refs, " "), "acme/widgets#", "")
		if got != tc.sent || len(tc.g.vars) != tc.pages {
			t.Errorf("%s: sent %q, %d pages", tc.name, got, len(tc.g.vars))
		}
		for _, p := range parts {
			if p.Complete {
				t.Errorf("%s: a part says it is complete", tc.name)
			}
		}
	}
	// 401 is a token GitHub no longer takes, which the caller drops.
	g := &fakeGraphQL{nodes: five(), statusOn: 1, status: 401}
	var logs []string
	l, _ := g.lister(t, &sink{}, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); !Unauthorized(err) {
		t.Errorf("err %v", err)
	}
}

// TestARateLimitInGraphQLsAnswerIsWaitedOut answers GraphQL's rate limit, which comes
// as a 200 with an error of type RATE_LIMITED, and checks the page is asked for again
// after a minute, or after the reset when GitHub says no request remains, and that a
// limit that holds for five tries fails the listing.
func TestARateLimitInGraphQLsAnswerIsWaitedOut(t *testing.T) {
	for _, tc := range []struct {
		name    string
		g       *fakeGraphQL
		err     string
		slept   string
		answers int
	}{
		{"a secondary limit", &fakeGraphQL{nodes: []map[string]any{node(1, 0)}, limited: 2}, "", "[1m0s 1m0s]", 3},
		{"none remaining", &fakeGraphQL{nodes: []map[string]any{node(1, 0)}, limited: 1, limitHeaders: true}, "", "[2m0s]", 2},
		{"a limit that holds", &fakeGraphQL{nodes: []map[string]any{node(1, 0)}, limited: 5}, "listing the open issues of acme/widgets: GitHub answered an error, RATE_LIMITED: API rate limit exceeded", "[1m0s 1m0s 1m0s 1m0s]", 5},
	} {
		s := &sink{}
		var logs []string
		l, clock := tc.g.lister(t, s, &logs)
		err := l.ListOpenIssuesComplete(context.Background(), widgets)
		if (err == nil) != (tc.err == "") || (err != nil && err.Error() != tc.err) {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if got := fmt.Sprint(clock.slept); got != tc.slept || tc.g.answered != tc.answers {
			t.Errorf("%s: slept %s, %d answers", tc.name, got, tc.g.answered)
		}
		if refs, parts := sentParts(s); tc.err == "" && (len(refs) != 1 || !parts[0].Complete) {
			t.Errorf("%s: items %v", tc.name, refs)
		}
	}
}

// TestTheCompleteListingReadsABoundedNumberOfPages checks a listing of more than 2,000
// pages stops with its error, and no part says it is complete.
func TestTheCompleteListingReadsABoundedNumberOfPages(t *testing.T) {
	g := &fakeGraphQL{}
	for i := 1; i <= 2001; i++ {
		g.nodes = append(g.nodes, node(i, 0))
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	err := l.listOpenComplete(context.Background(), widgets, 1)
	if err == nil || err.Error() != "listing the open issues of acme/widgets: GitHub has more than 2000 pages, which a listing never reads" || len(g.vars) != 2000 {
		t.Errorf("err %v, %d pages", err, len(g.vars))
	}
	refs, parts := sentParts(s)
	if len(refs) != 2000 || len(parts) == 0 {
		t.Errorf("%d items, %d parts", len(refs), len(parts))
	}
	for _, p := range parts {
		if p.Complete {
			t.Errorf("part %d says it is complete", p.Part)
		}
	}
}

// many is n open issues of acme/widgets as GraphQL says them, each with comments
// comments.
func many(n, comments int) []map[string]any {
	var out []map[string]any
	for i := 1; i <= n; i++ {
		out = append(out, node(i, comments))
	}
	return out
}

// closedNodes are n closed issues of acme/widgets as GraphQL says them.
func closedNodes(n int) []map[string]any {
	out := many(n, 0)
	for _, c := range out {
		c["state"], c["stateReason"] = "CLOSED", "COMPLETED"
	}
	return out
}

// TestTheCompleteListingReadsCommentsWhereThereAreAny lists three issues and checks
// their comments are read, paged, only for an issue that has any; the App's work item
// comment is left out, whatever the case of its bot's login, while a person's comment
// with the same words is kept; the items come before their comments; and no request of
// comments says it is complete.
func TestTheCompleteListingReadsCommentsWhereThereAreAny(t *testing.T) {
	g := &fakeGraphQL{
		fakeIssues: &fakeIssues{pageSize: 2, comments: map[int][]map[string]any{
			1: {
				comment(11, "qory-test[bot]", "Bot", "<!-- qory:work-item 7 -->\nThis issue is work in Qory Apiary."),
				comment(12, "bob", "User", "<!-- qory:work-item 7 --> copied by a person"),
				comment(13, "dependabot[bot]", "Bot", "An automation's comment."),
			},
			6: {comment(61, "QORY-TEST[bot]", "Bot", "<!-- qory:work-item 8 -->")},
		}},
		nodes: []map[string]any{node(1, 3), node(2, 0), node(6, 1)},
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /graphql",
		"/repos/acme/widgets/issues/1/comments?per_page=100",
		"/repos/acme/widgets/issues/1/comments?page=2&per_page=100",
		"/repos/acme/widgets/issues/6/comments?per_page=100",
	}
	if got := g.requested(); !reflect.DeepEqual(got, want) {
		t.Errorf("requested\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, a := range g.auth {
		if a != "Bearer "+fakeToken {
			t.Errorf("authorization %q", a)
		}
	}
	refs, parts := sentParts(s)
	if strings.Join(refs, " ") != "acme/widgets#1 acme/widgets#2 acme/widgets#6" || len(parts) != 1 || !parts[0].Complete {
		t.Errorf("items %v, parts %+v", refs, parts)
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
	if _, ok := s.reqs[0].(contracts.SourceItems); !ok {
		t.Errorf("first request %T", s.reqs[0])
	}
	if len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// TestAnItemsCommentsGoInRequestsOfAMebibyte lists an issue with many long comments
// and checks they go in several requests of at most 1 MiB, none complete.
func TestAnItemsCommentsGoInRequestsOfAMebibyte(t *testing.T) {
	long := strings.Repeat("x", 60_000)
	g := &fakeGraphQL{fakeIssues: &fakeIssues{comments: map[int][]map[string]any{}}, nodes: many(1, 40)}
	for i := range 40 {
		g.comments[1] = append(g.comments[1], comment(100+i, "bob", "User", long))
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
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

func TestCommentsGoInRequestsOfAHundred(t *testing.T) {
	g := &fakeGraphQL{fakeIssues: &fakeIssues{comments: map[int][]map[string]any{}}, nodes: many(1, 250)}
	for i := range 250 {
		g.comments[1] = append(g.comments[1], comment(i+1, "bob", "User", "c"))
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
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

// TestWhatQoryApiaryWouldRefuseIsSkippedAndLoggedByRef lists issues and a comment with
// a field that cannot be cut into the contract, and checks they are left out, logged by
// their ref alone, the rest are sent, and the listing does not say it is complete.
func TestWhatQoryApiaryWouldRefuseIsSkippedAndLoggedByRef(t *testing.T) {
	secret := "SECRETTEXT"
	noTitle, httpURL := node(3, 0), node(5, 0)
	noTitle["title"] = ""
	noTitle["body"] = secret
	httpURL["url"] = "http://github.com/acme/widgets/issues/5"
	httpURL["body"] = secret
	httpComment := comment(10, "bob", "User", secret)
	httpComment["html_url"] = "http://github.com/acme/widgets/issues/1#issuecomment-10"
	g := &fakeGraphQL{
		fakeIssues: &fakeIssues{comments: map[int][]map[string]any{1: {httpComment, comment(11, "bob", "User", "fine")}}},
		nodes:      []map[string]any{node(1, 2), noTitle, httpURL, node(6, 0)},
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	refs, parts := sentParts(s)
	if strings.Join(refs, " ") != "acme/widgets#1 acme/widgets#6" || len(parts) != 1 || parts[0].Complete {
		t.Errorf("items %v, parts %+v", refs, parts)
	}
	cs := s.comments()
	if len(cs) != 1 || len(cs[0].Comments) != 1 || cs[0].Comments[0].Ref != "11" {
		t.Errorf("comments %+v", cs)
	}
	want := []string{
		"skipped the item acme/widgets#3: its title is empty",
		"skipped the item acme/widgets#5: its URL is not https or is longer than 2048 characters",
		"skipped the comment 10 on acme/widgets#1: its URL is not https or is longer than 2048 characters",
	}
	if !reflect.DeepEqual(logs, want) {
		t.Errorf("logged\n%s", strings.Join(logs, "\n"))
	}
}

// TestATextPastItsLimitIsCutToIt lists issues and a comment whose texts are longer than
// the contract takes, and checks each is cut to its limit on a character's boundary,
// labels left empty or the same as one before are dropped, the labels past 100 are
// dropped, nothing is skipped, so the listing is complete, and each cut is logged by
// ref, field and length, never by its text. Each item and comment names in truncated
// the fields of it cut but its labels, and one with none of those cut has no truncated.
func TestATextPastItsLimitIsCutToIt(t *testing.T) {
	secret := "SECRETTEXT"
	longBody, longTitle, manyLabels, longName, atLimit := node(2, 1), node(3, 0), node(4, 0), node(5, 0), node(6, 0)
	longBody["body"] = secret + strings.Repeat("ü", 70_000-len(secret))
	longTitle["title"] = strings.Repeat("ü", 1030)
	labels := []any{
		map[string]any{"name": strings.Repeat("a", 100) + "1"},
		map[string]any{"name": ""},
		map[string]any{"name": strings.Repeat("a", 100) + "2"},
		map[string]any{"name": "b"},
		map[string]any{"name": "b"},
	}
	for i := range 120 {
		labels = append(labels, map[string]any{"name": "l" + strconv.Itoa(i)})
	}
	manyLabels["labels"] = map[string]any{"nodes": labels}
	longName["author"] = map[string]any{"login": strings.Repeat("n", 300), "__typename": "User"}
	atLimit["body"] = strings.Repeat("ü", 65_536)
	g := &fakeGraphQL{
		fakeIssues: &fakeIssues{comments: map[int][]map[string]any{2: {comment(20, strings.Repeat("m", 300), "Bot", strings.Repeat("c", 70_000))}}},
		nodes:      []map[string]any{longBody, longTitle, manyLabels, longName, atLimit},
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	wantLogs := []string{
		"cut the body of acme/widgets#2, 70000 long, to the contract's limit",
		"cut the title of acme/widgets#3, 1030 long, to the contract's limit",
		"cut the label of acme/widgets#4, 101 long, to the contract's limit",
		"cut the label of acme/widgets#4, 101 long, to the contract's limit",
		"cut the labels of acme/widgets#4, 125 long, to the contract's limit",
		"cut the filed_by.name of acme/widgets#5, 300 long, to the contract's limit",
		"cut the author.name of 20, 300 long, to the contract's limit",
		"cut the body of 20, 70000 long, to the contract's limit",
	}
	if !reflect.DeepEqual(logs, wantLogs) {
		t.Errorf("logged\n%s", strings.Join(logs, "\n"))
	}
	items := s.items()
	if len(items) != 1 || len(items[0].Items) != 5 || !items[0].Listing.Complete {
		t.Fatalf("items %+v", items)
	}
	got := items[0].Items
	if got[0].Body != secret+strings.Repeat("ü", 65_536-len(secret)) {
		t.Errorf("body of %d characters", utf8.RuneCountInString(got[0].Body))
	}
	if got[1].Title != strings.Repeat("ü", 1024) {
		t.Errorf("title of %d characters", utf8.RuneCountInString(got[1].Title))
	}
	want := []string{strings.Repeat("a", 100), "b"}
	for i := range 98 {
		want = append(want, "l"+strconv.Itoa(i))
	}
	if !reflect.DeepEqual(got[2].Labels, want) {
		t.Errorf("labels %q", got[2].Labels)
	}
	if got[3].FiledBy != (contracts.Person{Name: strings.Repeat("n", 100), Kind: KindPerson}) {
		t.Errorf("filed by %+v", got[3].FiledBy)
	}
	if got[4].Body != strings.Repeat("ü", 65_536) {
		t.Errorf("a body at the limit is changed")
	}
	for i, want := range [][]string{{"body"}, {"title"}, nil, {"filed_by.name"}, nil} {
		names, ok := truncatedMember(t, got[i])
		if !reflect.DeepEqual(names, want) || ok != (want != nil) {
			t.Errorf("%s: truncated %q", got[i].Ref, names)
		}
	}
	cs := s.comments()
	if len(cs) != 1 || len(cs[0].Comments) != 1 {
		t.Fatalf("comments %+v", cs)
	}
	if c := cs[0].Comments[0]; c.Body != strings.Repeat("c", 65_536) || c.Author != (contracts.Person{Name: strings.Repeat("m", 100), Kind: KindAutomation}) || !reflect.DeepEqual(c.Truncated, []string{"body", "author.name"}) {
		t.Errorf("comment of %d characters by %+v", utf8.RuneCountInString(c.Body), c.Author)
	}
}

// TestACompleteListingStoppedEarlyNeverSaysComplete stops listings part-way, after
// GitHub's answers have filled a part or more, and checks each returns its error and
// sends the items it read and had not sent as a last part, and that no part says it is
// complete: a status, GraphQL's errors in a 200, a rate limit that holds through every
// try, Qory Apiary failing a part, comments failing before the last part, a context
// cancelled, and a context whose deadline passes while GitHub answers.
func TestACompleteListingStoppedEarlyNeverSaysComplete(t *testing.T) {
	const what = "listing the open issues of acme/widgets: "
	twoComments := map[int][]map[string]any{1: {comment(1, "bob", "User", "a"), comment(2, "bob", "User", "b")}}
	for _, tc := range []struct {
		name  string
		g     *fakeGraphQL
		sink  *sink
		ctx   func(g *fakeGraphQL) (context.Context, context.CancelFunc)
		err   string
		is    error
		parts []int
	}{
		{name: "a status after two parts", g: &fakeGraphQL{nodes: many(250, 0), statusOn: 3, status: 502}, err: what + "GitHub answered 502: Bad credentials", parts: []int{100, 100}},
		{name: "GraphQL's errors in a 200 after two parts", g: &fakeGraphQL{nodes: many(250, 0), errorOn: 3}, err: what + "GitHub answered 2 errors, the first SERVICE_UNAVAILABLE: Something went wrong while executing your query.", parts: []int{100, 100}},
		{name: "GraphQL's errors in a 200 on the second page", g: &fakeGraphQL{nodes: many(150, 0), errorOn: 2}, err: what + "GitHub answered 2 errors, the first SERVICE_UNAVAILABLE: Something went wrong while executing your query.", parts: []int{100}},
		{name: "a rate limit that holds after two parts", g: &fakeGraphQL{nodes: many(250, 0), limited: 5, limitFrom: 3}, err: what + "GitHub answered an error, RATE_LIMITED: API rate limit exceeded", parts: []int{100, 100}},
		{name: "a rate limit that holds on the second page", g: &fakeGraphQL{nodes: many(150, 0), limited: 5, limitFrom: 2}, err: what + "GitHub answered an error, RATE_LIMITED: API rate limit exceeded", parts: []int{100}},
		{name: "Qory Apiary fails a part", g: &fakeGraphQL{nodes: many(150, 0)}, sink: &sink{failAt: 1}, err: "Qory Apiary is not reachable", parts: []int{100}},
		{name: "comments fail before the last part", g: &fakeGraphQL{fakeIssues: &fakeIssues{pageSize: 1, comments: twoComments, failComments: 2}, nodes: many(150, 1)}, err: "listing the comments on acme/widgets#1: GitHub answered 500: Server Error", parts: []int{100}},
		{name: "a context cancelled", g: &fakeGraphQL{nodes: many(150, 0)}, ctx: func(g *fakeGraphQL) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			g.onPage = func(page int, r *http.Request) {
				if page == 2 {
					// The page is answered once the listing gave up on it.
					cancel()
					select {
					case <-r.Context().Done():
					case <-time.After(10 * time.Second):
					}
				}
			}
			return ctx, cancel
		}, is: context.Canceled, parts: []int{100}},
		{name: "a deadline passed", g: &fakeGraphQL{nodes: many(150, 0)}, ctx: func(g *fakeGraphQL) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			g.onPage = func(page int, r *http.Request) {
				if page == 2 {
					select {
					case <-r.Context().Done():
					case <-time.After(10 * time.Second):
					}
				}
			}
			return ctx, cancel
		}, is: context.DeadlineExceeded, parts: []int{100}},
	} {
		s := tc.sink
		if s == nil {
			s = &sink{}
		}
		var logs []string
		l, _ := tc.g.lister(t, s, &logs)
		ctx, cancel := context.Background(), context.CancelFunc(func() {})
		if tc.ctx != nil {
			ctx, cancel = tc.ctx(tc.g)
		}
		err := l.ListOpenIssuesComplete(ctx, widgets)
		cancel()
		if err == nil || tc.err != "" && err.Error() != tc.err || tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: err %v", tc.name, err)
		}
		sizes := []int{}
		for i, req := range s.items() {
			if req.Listing.Complete || req.Listing.Part != i+1 {
				t.Errorf("%s: part %d says %+v", tc.name, i+1, req.Listing)
			}
			sizes = append(sizes, len(req.Items))
		}
		if !slices.Equal(sizes, tc.parts) {
			t.Errorf("%s: parts of %v, want %v", tc.name, sizes, tc.parts)
		}
		for _, c := range s.comments() {
			if c.Complete != nil {
				t.Errorf("%s: comments on %s said complete", tc.name, c.ItemRef)
			}
		}
	}
}

// TestCommentsThatFailAfterTheLastPartLeaveItAsSent lists an issue whose comments
// GitHub answers 500 once its part is sent, and checks the listing returns the error,
// sends nothing after it, and its one part says it is complete all the same: every open
// issue was read, and comments are no part of complete.
func TestCommentsThatFailAfterTheLastPartLeaveItAsSent(t *testing.T) {
	g := &fakeGraphQL{fakeIssues: &fakeIssues{pageSize: 1, failComments: 2, comments: map[int][]map[string]any{1: {comment(1, "bob", "User", "a"), comment(2, "bob", "User", "b")}}}, nodes: many(1, 2)}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	err := l.ListOpenIssuesComplete(context.Background(), widgets)
	if err == nil || err.Error() != "listing the comments on acme/widgets#1: GitHub answered 500: Server Error" {
		t.Errorf("err %v", err)
	}
	if _, parts := sentParts(s); len(s.reqs) != 1 || len(parts) != 1 || !parts[0].Complete {
		t.Errorf("requests %+v", s.reqs)
	}
}

// TestAnItemsCommentsAreReadInABoundedNumberOfPages checks a listing stops with its
// error at 100 pages of an issue's comments, and when a next page of comments repeats
// one it read.
func TestAnItemsCommentsAreReadInABoundedNumberOfPages(t *testing.T) {
	manyComments := map[int][]map[string]any{1: {}}
	for i := range 101 {
		manyComments[1] = append(manyComments[1], comment(i+1, "bob", "User", "c"))
	}
	for _, tc := range []struct {
		name     string
		g        *fakeGraphQL
		err      string
		requests int
	}{
		{"a hundred pages", &fakeGraphQL{fakeIssues: &fakeIssues{pageSize: 1, comments: manyComments}, nodes: many(1, 101)}, "listing the comments on acme/widgets#1: GitHub has more than 100 pages, which a listing never reads", 1 + 100},
		{"a repeated page", &fakeGraphQL{fakeIssues: &fakeIssues{pageSize: 1, comments: manyComments, again: true}, nodes: many(1, 101)}, "listing the comments on acme/widgets#1: GitHub's next page repeats one already read", 1 + 1},
	} {
		s := &sink{}
		var logs []string
		l, _ := tc.g.lister(t, s, &logs)
		err := l.ListOpenIssuesComplete(context.Background(), widgets)
		if err == nil || err.Error() != tc.err || len(tc.g.requested()) != tc.requests {
			t.Errorf("%s: err %v, %d requests", tc.name, err, len(tc.g.requested()))
		}
	}
}

// TestAnIssueGoneWhileListedLosesOnlyItsComments lists 150 open issues, the first of
// which GitHub answers 404 for its comments, as for an issue deleted while it is listed,
// and checks every issue is sent, the others' comments too, the skip is logged by its
// ref, and the listing is complete: comments are no part of complete.
func TestAnIssueGoneWhileListedLosesOnlyItsComments(t *testing.T) {
	g := &fakeGraphQL{fakeIssues: &fakeIssues{comments: map[int][]map[string]any{}, goneComments: 1}, nodes: many(150, 1)}
	for i := 1; i <= 150; i++ {
		g.comments[i] = []map[string]any{comment(1000+i, "bob", "User", "c")}
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	refs, parts := sentParts(s)
	comments := 0
	for _, req := range s.comments() {
		comments += len(req.Comments)
		if req.ItemRef == "acme/widgets#1" {
			t.Errorf("comments sent on the issue gone")
		}
	}
	if len(refs) != 150 || comments != 149 || len(parts) != 2 || !parts[1].Complete {
		t.Errorf("%d items, %d comments, parts %+v", len(refs), comments, parts)
	}
	if !reflect.DeepEqual(logs, []string{"skipped the comments on acme/widgets#1: GitHub answers that the issue is gone or moved"}) {
		t.Errorf("logged %v", logs)
	}
}

// TestAMintsNotFoundIsNotARepositoryGone has GitHub answer the token's mint 404, and
// checks the listing's error does not wrap ErrRepositoryGone, nor does a 404 GraphQL
// answers as a status.
func TestAMintsNotFoundIsNotARepositoryGone(t *testing.T) {
	g := &fakeGraphQL{nodes: many(1, 0)}
	var logs []string
	l, _ := g.lister(t, &sink{}, &logs)
	l.Token = func(context.Context) (string, error) {
		return "", &answerError{what: "minting the installation token", status: 404, message: "Not Found"}
	}
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err == nil || errors.Is(err, ErrRepositoryGone) {
		t.Errorf("a mint's 404: err %v", err)
	}
	g = &fakeGraphQL{nodes: many(1, 0), statusOn: 1, status: 404}
	l, _ = g.lister(t, &sink{}, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err == nil || errors.Is(err, ErrRepositoryGone) {
		t.Errorf("a 404: err %v", err)
	}
}
