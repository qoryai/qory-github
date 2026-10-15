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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
	// limited answers that many requests with GraphQL's rate limit, and limitHeaders
	// says with them that no request remains until a minute after t0.
	limited      int
	limitHeaders bool
	// errorOn answers that page, counted from 1, with a GraphQL error, statusOn with
	// status; notFound answers that the repository cannot be resolved.
	errorOn, statusOn, status int
	notFound                  bool
	// sameCursor names the first page's cursor again on every page, noCursor names
	// none, and nullNode answers the first page's first issue as null.
	sameCursor, noCursor, nullNode bool
	// renameOn names the repository otherwise from that page on.
	renameOn int
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
	if g.limited > 0 {
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
		if n["state"] != "OPEN" || n["number"].(int) <= after {
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

// TestTheCompleteListingIsSentInPartsOfAHundred lists 250 issues, 100 to a page, and
// checks they go in three parts, numbered from 1, of which the last alone says the
// listing is complete, and every request fits the contract.
func TestTheCompleteListingIsSentInPartsOfAHundred(t *testing.T) {
	g := &fakeGraphQL{}
	for i := 1; i <= 250; i++ {
		g.nodes = append(g.nodes, node(i, 0))
	}
	s := &sink{}
	var logs []string
	l, _ := g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil {
		t.Fatal(err)
	}
	refs, parts := sentParts(s)
	if len(refs) != 250 || len(parts) != 3 || parts[0].Complete || parts[1].Complete || !parts[2].Complete || parts[2].Part != 3 || parts[0].ID != parts[2].ID {
		t.Errorf("%d items, parts %+v", len(refs), parts)
	}
	if strings.Join(g.afters(), " ") != "- cursor:100 cursor:200" {
		t.Errorf("after %v", g.afters())
	}
}

// TestASkippedItemLeavesTheListingNotComplete lists an issue Qory Apiary would refuse,
// with an empty title, and checks it is skipped and logged by its ref, the rest are
// sent, and the listing does not say it is complete, so Qory Apiary closes nothing for
// the item it did not get. A repository without an open issue sends nothing.
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

	g = &fakeGraphQL{}
	s = &sink{}
	l, _ = g.lister(t, s, &logs)
	if err := l.ListOpenIssuesComplete(context.Background(), widgets); err != nil || len(s.reqs) != 0 {
		t.Errorf("err %v, requests %+v", err, s.reqs)
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
		{"a limit that holds", &fakeGraphQL{nodes: []map[string]any{node(1, 0)}, limited: 5}, "listing the open issues of acme/widgets: GitHub answered 1 errors, the first RATE_LIMITED: API rate limit exceeded", "[1m0s 1m0s 1m0s 1m0s]", 5},
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
// pages stops with its error, and its last part is not complete.
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
	if len(refs) != 2000 || len(parts) == 0 || parts[len(parts)-1].Complete {
		t.Errorf("%d items, %d parts", len(refs), len(parts))
	}
}
