package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/qoryai/integrations/contracts"
)

// A listing that says it is complete makes Qory Apiary close every item of the
// collection it left out, so it may say so only when its paging cannot skip an item.
// Paging by page number can: an issue deleted from a page already read moves the first
// issue of the next page onto it. GraphQL's cursors do not: a cursor names a place in
// the order, the creation time and the id of the last issue a page held, and the next
// page starts after that place, whatever came or went before it. graphql_live_test.go
// shows it against GitHub itself, with issues closed, created, edited, reopened and
// deleted between the pages. [Lister.ListOpenIssuesComplete] lists the open issues by
// cursor, oldest first, so an issue open for the whole listing is in it once. GitHub's
// REST listing of issues, as GitHub answers it today, names its next page by a cursor
// as well as by number, but GitHub documents that listing by page number, so the
// adapter does not rely on it.

// openIssuesPerPage is how many issues a page of [Lister.ListOpenIssuesComplete] holds,
// the most GraphQL gives. A page of issues each with 100 labels is about 10,000 nodes,
// well within GraphQL's limit of 500,000 for one query.
const openIssuesPerPage = 100

// openIssuesQuery reads one page of a repository's open issues, oldest first, the page
// after the cursor $after, or the first page when it is null. It names the repository
// too, as GitHub has it, and its id, which must be the id the listing is for, and which
// the refs of its collection and its items are. The id is fullDatabaseId, GraphQL's
// BigInt, which GitHub writes as a JSON string, not databaseId, an Int, which GraphQL
// holds to 32 bits and cannot answer once an id passes 2,147,483,647. It reads
// hasIssuesEnabled as well, false when Issues are turned off for the repository, see
// [issuePager.next].
const openIssuesQuery = `query($owner: String!, $name: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    fullDatabaseId
    nameWithOwner
    url
    hasIssuesEnabled
    issues(states: OPEN, first: $first, after: $after, orderBy: {field: CREATED_AT, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number url title body state stateReason
        labels(first: 100) { nodes { name } }
        author { login __typename }
        createdAt updatedAt
        comments { totalCount }
      }
    }
  }
}`

// The fields of GraphQL's answer the listing reads.
type (
	gqlIssue struct {
		Number      int64   `json:"number"`
		URL         string  `json:"url"`
		Title       string  `json:"title"`
		Body        string  `json:"body"`
		State       string  `json:"state"`
		StateReason *string `json:"stateReason"`
		Labels      struct {
			Nodes []ghLabel `json:"nodes"`
		} `json:"labels"`
		Author *struct {
			Login    string `json:"login"`
			Typename string `json:"__typename"`
		} `json:"author"`
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
		Comments  struct {
			TotalCount int `json:"totalCount"`
		} `json:"comments"`
	}
	gqlError struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Path    []any  `json:"path"`
	}
	gqlOpenIssues struct {
		Data struct {
			Repository *struct {
				FullDatabaseID   json.RawMessage `json:"fullDatabaseId"`
				NameWithOwner    string          `json:"nameWithOwner"`
				URL              string          `json:"url"`
				HasIssuesEnabled *bool           `json:"hasIssuesEnabled"`
				Issues           struct {
					PageInfo struct {
						HasNextPage bool    `json:"hasNextPage"`
						EndCursor   *string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []*gqlIssue `json:"nodes"`
				} `json:"issues"`
			} `json:"repository"`
		} `json:"data"`
		Errors []gqlError `json:"errors"`
	}
)

// issue is the GraphQL issue as REST says it, so it maps to an item the same way: the
// state and its reason in lower case, and the author as REST's user. A bot's login is
// REST's, which ends in [bot] where GraphQL's does not; an author GitHub no longer has
// is nil, which maps to its ghost, as REST's ghost user does.
func (g gqlIssue) issue() ghIssue {
	is := ghIssue{
		Number:    g.Number,
		Title:     g.Title,
		Body:      &g.Body,
		State:     strings.ToLower(g.State),
		HTMLURL:   g.URL,
		Labels:    g.Labels.Nodes,
		Comments:  g.Comments.TotalCount,
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	}
	if g.StateReason != nil {
		r := strings.ToLower(*g.StateReason)
		is.StateReason = &r
	}
	if g.Author != nil {
		u := ghUser{Login: g.Author.Login, Type: "User"}
		if g.Author.Typename == "Bot" {
			u.Type = "Bot"
			if !strings.HasSuffix(u.Login, "[bot]") {
				u.Login += "[bot]"
			}
		}
		is.User = &u
	}
	return is
}

// issuePager reads a repository's open issues by GraphQL's cursor, oldest first, one
// page at a time: the repository whose id is id, by its owner/name, repo.
type issuePager struct {
	l     Lister
	p     *Pacer
	id    int64
	repo  Repository
	first int
	what  string
	// after is the cursor the next page starts after, "" for the first page, and
	// cursors every cursor read, so one GitHub names again is refused.
	after   string
	cursors map[string]bool
	read    int
	done    bool
	// r is the repository as the last page named it.
	r ghRepo
}

// issuePager starts reading the open issues of the repository whose id is id, by its
// owner/name, repo, first to a page.
func (l Lister) issuePager(p *Pacer, id int64, repo Repository, first int) *issuePager {
	return &issuePager{l: l, p: p, id: id, repo: repo, first: first, what: "listing the open issues of " + repo.String(), cursors: map[string]bool{}}
}

// next reads the next page: the repository as GitHub names it and the page's issues, or
// false once the last page is read. A rate limit GitHub answers in the body is waited
// out and the page asked for again, at most limitedTries times. It fails, and the
// listing with it, for any error GraphQL answers, a repository it cannot resolve by
// owner/name, a repository whose id is not the pager's or that has none that is an id,
// see [fullDatabaseID], an issue it answers as null, a next cursor that is missing or
// repeats one already read, and a page past maxIssuePages. The id is checked on every
// page: owner/name may name another repository, or none, by the time GraphQL reads it,
// as when a rename or a transfer lands after the name was read by the id, and such a
// page is never taken for the repository's. Neither error wraps [ErrRepositoryGone]:
// the read by the id is what says the repository is gone, as it says for a transfer to
// an account the installation is not on, and never for a rename, and a later listing,
// which reads the name again, may list it. When no token for the repository is kept,
// the mint of one, which names the repository by its id, fails first, wrapping
// [ErrMintRefused], before that read runs. A page of the repository whose
// hasIssuesEnabled is false, as GraphQL answers once Issues are turned off for it,
// fails with an error that wraps [ErrIssuesOff], and its issues are not taken; a page
// without hasIssuesEnabled is taken as one with Issues on.
func (g *issuePager) next(ctx context.Context) (ghRepo, []ghIssue, bool, error) {
	if g.done {
		return g.r, nil, false, nil
	}
	if g.read == maxIssuePages {
		return g.r, nil, false, fmt.Errorf("%s: GitHub has more than %d pages, which a listing never reads", g.what, maxIssuePages)
	}
	vars := map[string]any{"owner": g.repo.Owner, "name": g.repo.Name, "first": g.first, "after": nil}
	if g.after != "" {
		vars["after"] = g.after
	}
	body := map[string]any{"query": openIssuesQuery, "variables": vars}
	var got gqlOpenIssues
	for try := 1; ; try++ {
		token, err := g.l.Token(ctx)
		if err != nil {
			return g.r, nil, false, fmt.Errorf("%s: the installation token: %w", g.what, &tokenError{err})
		}
		a, err := g.l.Client.send(ctx, g.p, true, g.what, http.MethodPost, "/graphql", token, body)
		if err != nil {
			return g.r, nil, false, err
		}
		if a.status != http.StatusOK {
			return g.r, nil, false, a.err(g.what)
		}
		got = gqlOpenIssues{}
		if err := json.Unmarshal(a.body, &got); err != nil {
			return g.r, nil, false, fmt.Errorf("%s: GitHub's answer: %w", g.what, err)
		}
		if !rateLimited(got.Errors) || try == limitedTries {
			break
		}
		g.p.limited()
	}
	if err := g.answered(got); err != nil {
		return g.r, nil, false, err
	}
	repo := got.Data.Repository
	id, ok := fullDatabaseID(repo.FullDatabaseID)
	r := ghRepo{ID: id, FullName: repo.NameWithOwner, HTMLURL: repo.URL}
	if !ok || r.ID != g.id {
		return g.r, nil, false, fmt.Errorf("%s: GitHub answers a repository whose id is not %d, or no id; it may have been renamed or transferred since its name was read, so a later listing reads it again", g.what, g.id)
	}
	if repo.HasIssuesEnabled != nil && !*repo.HasIssuesEnabled {
		return g.r, nil, false, fmt.Errorf("%s: %w", g.what, ErrIssuesOff)
	}
	g.r = r
	g.read++
	issues := make([]ghIssue, 0, len(repo.Issues.Nodes))
	for _, n := range repo.Issues.Nodes {
		if n == nil {
			return g.r, nil, false, fmt.Errorf("%s: GitHub answered an issue as null", g.what)
		}
		issues = append(issues, n.issue())
	}
	info := repo.Issues.PageInfo
	if !info.HasNextPage {
		g.done = true
		return g.r, issues, true, nil
	}
	if info.EndCursor == nil || *info.EndCursor == "" {
		return g.r, nil, false, fmt.Errorf("%s: GitHub says there is a next page and names no cursor for it", g.what)
	}
	if c := *info.EndCursor; c == g.after || g.cursors[c] {
		return g.r, nil, false, fmt.Errorf("%s: GitHub's next cursor repeats one already read", g.what)
	}
	g.after = *info.EndCursor
	g.cursors[g.after] = true
	return g.r, issues, true, nil
}

// fullDatabaseID is the id a repository's fullDatabaseId says, or false when it is
// missing, null, not a JSON string, as GraphQL writes a BigInt, or not an id by the
// rules of a ref's, [parseID]: decimal digits alone, with no sign and no leading zero,
// within an int64.
func fullDatabaseID(raw json.RawMessage) (int64, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return 0, false
	}
	return parseID(s)
}

// answered is the error GraphQL's answer says, or nil: a repository it cannot resolve
// by owner/name, or that it answers as null, is the race of a rename or a transfer
// with the read of the name, see [issuePager.next], and wraps no [ErrRepositoryGone];
// any other error, a rate limit that held among them, is the error of the page. Only
// GitHub's type and message are said, never the query or the token.
func (g *issuePager) answered(got gqlOpenIssues) error {
	for _, e := range got.Errors {
		if e.Type == "NOT_FOUND" && len(e.Path) > 0 && e.Path[0] == "repository" {
			return fmt.Errorf("%s: GitHub answers no repository by that name; it may have been renamed or transferred since its name was read, so a later listing reads it again; GitHub answered: %s", g.what, e.Message)
		}
	}
	if len(got.Errors) > 0 {
		e := got.Errors[0]
		if len(got.Errors) == 1 {
			return fmt.Errorf("%s: GitHub answered an error, %s: %s", g.what, orUntyped(e.Type), e.Message)
		}
		return fmt.Errorf("%s: GitHub answered %d errors, the first %s: %s", g.what, len(got.Errors), orUntyped(e.Type), e.Message)
	}
	if got.Data.Repository == nil {
		return fmt.Errorf("%s: GitHub answers no repository by that name; it may have been renamed or transferred since its name was read, so a later listing reads it again", g.what)
	}
	return nil
}

// orUntyped is a GraphQL error's type, or that it has none.
func orUntyped(t string) string {
	if t == "" {
		return "untyped"
	}
	return t
}

// rateLimited is whether GraphQL's errors say the query was refused for a rate limit.
func rateLimited(errs []gqlError) bool {
	for _, e := range errs {
		if e.Type == "RATE_LIMITED" {
			return true
		}
	}
	return false
}

// ListOpenIssuesComplete lists the repository's open issues by GraphQL's cursor, oldest
// first, and their comments, and sends them to Qory Apiary; the fill and the daily
// listing of open issues use it. GraphQL names a repository by owner/name, repo, which
// a read of /repositories/{id} gives, see [Lister.ReadRepository], and answers its id,
// which must be repository, the id the listing is for, and which the refs of its
// collection and its items are. Items go in parts of at most 100 items and 1 MiB, and
// after each part the comments of its items, for an issue that has any, read by REST
// through the repository's id in requests of at most 100 comments and 1 MiB, the App's
// work item comment left out. It reads at most 2,000 pages of 100 issues, and 100 pages
// of an issue's comments.
//
// The last part says the listing is complete, since paging by cursor does not skip an
// issue, so Qory Apiary closes every item of the collection the listing left out and
// did not hear of since it started. An item skipped, as Qory Apiary would refuse it,
// leaves the listing not complete, so Qory Apiary never closes an open issue for that.
// Comments are no part of complete: no request of comments says it is complete.
//
// A repository with Issues turned on and no open issue, read without error, sends one
// part without items that says the listing is complete, so Qory Apiary closes every
// item of the collection it did not hear of since the listing started. A listing
// stopped early, by an error or its context, before every open issue is read and sent,
// sends the items it read and had not sent as its last part, which never says it is
// complete, nor does any part before it; one that fails on its first page sends
// nothing. A listing that fails on the comments of its last part's items, once that
// part is sent, returns the error, and that part, sent already, says it is complete,
// since every open issue was read and sent and comments are no part of complete. A page
// that GraphQL answers with no repository by owner/name, or with one whose id is not
// repository or that has none, as when a rename or a transfer lands after the name was
// read, stops the listing with an error that does not wrap [ErrRepositoryGone], so a
// later listing, which reads the name again, lists it; when that is the first page,
// nothing is sent. An issue whose comments GitHub answers are gone has its comments
// skipped and logged by its ref, and the listing goes on.
//
// A repository with Issues turned off on GitHub is not a failure, and is never taken
// for one with no open issue. When GraphQL answers the first page with
// hasIssuesEnabled false, the listing sends nothing, no part and so none that says it
// is complete, and Qory Apiary closes nothing and keeps the items it has of the
// collection as they are; it logs a line and returns nil. When a later page answers it,
// as when Issues are turned off while the listing reads, the listing stops as an error
// would stop it, the items it read and had not sent going as its last part, which never
// says it is complete, and it logs a line that says it listed no more open issues and
// returns nil, or the error of sending that part. [Lister.ReadRepository] says whether Issues are on, so a caller that reads
// the name by it can leave the listing out.
func (l Lister) ListOpenIssuesComplete(ctx context.Context, repository int64, repo Repository) error {
	return l.listOpenComplete(ctx, repository, repo, openIssuesPerPage)
}

// listOpenComplete is [Lister.ListOpenIssuesComplete], first issues to a page.
func (l Lister) listOpenComplete(ctx context.Context, repository int64, repo Repository, first int) error {
	if repository <= 0 {
		return errors.New("the repository's id is not one")
	}
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return fmt.Errorf("%q is not owner/name", repo.String())
	}
	if l.Sink == nil || l.Token == nil || l.Slug == "" {
		return errors.New("the lister has no sink, no token or no App slug")
	}
	p := l.pacerOr()
	// The listing starts before its first request to GitHub: Qory Apiary closes what a
	// complete listing left out and did not hear of since it started, so a later start
	// would close an item that changed meanwhile.
	listing := contracts.Listing{ID: randomHex(), StartedAt: contracts.FormatTime(p.now())}
	g := l.issuePager(p, repository, repo, first)
	var o *openParts
	for {
		r, page, more, err := g.next(ctx)
		if errors.Is(err, ErrIssuesOff) {
			if o == nil {
				l.logf("skipped the open issues of %s: Issues are turned off for the repository on GitHub", CollectionRef(repository))
				return nil
			}
			l.logf("listed no more open issues of %s: GitHub answers that Issues are turned off for the repository", CollectionRef(repository))
			return o.stop(ctx, nil)
		}
		if err != nil {
			if o == nil {
				return err
			}
			return o.stop(ctx, err)
		}
		if !more {
			break
		}
		if o == nil {
			coll := collectionOf(r)
			if why := checkCollection(coll); why != "" {
				return fmt.Errorf("the repository %s cannot be a collection: %s", repo, why)
			}
			o = l.openParts(p, listing, coll)
		}
		for _, is := range page {
			// An issue the listing returns as not open, one closed during the read say, is
			// rightly left out of the open listing and is not a skip, so a complete listing
			// may then close it.
			if is.State != StateOpen {
				continue
			}
			if err := o.add(ctx, r, is); err != nil {
				return o.stop(ctx, err)
			}
		}
	}
	return o.end(ctx, !o.skipped)
}

// A collection's environment_ref is the id of its repository's environment definition
// at the head of the default branch: the object id of the tree .devcontainer when that
// path is a tree, else of the blob .devcontainer.json when that path is a blob, else
// none. GraphQL reads both paths by the revision HEAD, which on GitHub names the default
// branch, the branch a clone checks out; an empty repository has no HEAD, so it has none.

// environmentsPerRequest is the most repositories one GraphQL request reads the
// environment definitions of, the most ids GitHub's nodes takes.
const environmentsPerRequest = 100

// environmentQuery reads the environment definitions of the repositories whose node ids
// are $ids. Each node names its repository's id, fullDatabaseId, by which the answer is
// matched to the repositories asked for, so an answer that holds fewer nodes, or holds
// them in another order, is read right.
const environmentQuery = `query($ids: [ID!]!) {
  nodes(ids: $ids) {
    ... on Repository {
      fullDatabaseId
      dir: object(expression: "HEAD:.devcontainer") { __typename oid }
      file: object(expression: "HEAD:.devcontainer.json") { __typename oid }
    }
  }
}`

// The fields of GraphQL's answer to environmentQuery the adapter reads.
type (
	gqlObject struct {
		Typename string `json:"__typename"`
		OID      string `json:"oid"`
	}
	gqlEnvironments struct {
		Data *struct {
			Nodes []*struct {
				FullDatabaseID json.RawMessage `json:"fullDatabaseId"`
				Dir            *gqlObject      `json:"dir"`
				File           *gqlObject      `json:"file"`
			} `json:"nodes"`
		} `json:"data"`
		Errors []gqlError `json:"errors"`
	}
)

// oidShape is a Git object id: SHA-1's 40 hexadecimal digits, or SHA-256's 64, in lower
// case.
var oidShape = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// environmentRef is the environment_ref the objects at .devcontainer, dir, and at
// .devcontainer.json, file, say, each nil when the path names nothing: dir's id when it
// is a tree, else file's when it is a blob, else none. A .devcontainer of another kind
// of Git object, a blob, as a symbolic link is, a commit, as a submodule is, or a tag, is
// passed for .devcontainer.json, and a .devcontainer.json that is a tree, a commit or a
// tag is none. It is false, the environment definition not read, when an object GraphQL
// answers has no __typename or one that is no kind of Git object, or when the id it
// takes is not a Git object id.
func environmentRef(dir, file *gqlObject) (string, bool) {
	if dir != nil {
		switch dir.Typename {
		case "Tree":
			return dir.OID, oidShape.MatchString(dir.OID)
		case "Blob", "Commit", "Tag":
		default:
			return "", false
		}
	}
	if file == nil {
		return "", true
	}
	switch file.Typename {
	case "Blob":
		return file.OID, oidShape.MatchString(file.OID)
	case "Tree", "Commit", "Tag":
		return "", true
	}
	return "", false
}

// envRepo is a repository whose environment definition is read: its id and its node id.
type envRepo struct {
	id   int64
	node string
}

// errStillLimited is the error of a GraphQL request GitHub refused for a rate limit on
// every try.
var errStillLimited = errors.New("GitHub returned a rate-limit error on all 5 tries")

// environments reads the environment_ref of each of repos, at most
// environmentsPerRequest, in one GraphQL request, and returns those it read by the
// repository's id, "" for one that has none, and the errors GraphQL answered for single
// nodes. A repository GraphQL answers with an error, as null, more than once or not at
// all, or with an object id that is not one, is not among them. err is the failure of
// the whole request, and then none is read: the token, GitHub unreached, an answer that
// is not 200 or not JSON, or an error GraphQL answers that names no node. A rate limit
// GitHub answers in the body is waited out and the request sent again, as
// [issuePager.next] does, and one that holds through every try is errStillLimited.
// Only GitHub's type and message are said, never the query or the token.
func (l Lister) environments(ctx context.Context, p *Pacer, what string, repos []envRepo) (map[int64]string, []gqlError, error) {
	if len(repos) > environmentsPerRequest {
		return nil, nil, fmt.Errorf("%s: more than %d repositories in one request", what, environmentsPerRequest)
	}
	refs := map[int64]string{}
	if len(repos) == 0 {
		return refs, nil, nil
	}
	ids := make([]string, len(repos))
	asked := make(map[int64]bool, len(repos))
	for i, r := range repos {
		ids[i] = r.node
		asked[r.id] = true
	}
	body := map[string]any{"query": environmentQuery, "variables": map[string]any{"ids": ids}}
	var got gqlEnvironments
	for try := 1; ; try++ {
		token, err := l.Token(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: the installation token: %w", what, &tokenError{err})
		}
		a, err := l.Client.send(ctx, p, true, what, http.MethodPost, "/graphql", token, body)
		if err != nil {
			return nil, nil, err
		}
		if a.status != http.StatusOK {
			return nil, nil, a.err(what)
		}
		got = gqlEnvironments{}
		if err := json.Unmarshal(a.body, &got); err != nil {
			return nil, nil, fmt.Errorf("%s: GitHub's answer: %w", what, err)
		}
		if !rateLimited(got.Errors) {
			break
		}
		if try == limitedTries {
			return nil, nil, fmt.Errorf("%s: %w", what, errStillLimited)
		}
		p.limited()
	}
	// An error that names a node, by its place in the answer, leaves that node unread;
	// one that names none fails the whole request.
	failed := map[int]bool{}
	for _, e := range got.Errors {
		i, ok := nodeIndex(e.Path)
		if !ok {
			return nil, nil, graphQLErrors(what, got.Errors)
		}
		failed[i] = true
	}
	if got.Data == nil {
		return refs, got.Errors, nil
	}
	unread := map[int64]bool{}
	for i, n := range got.Data.Nodes {
		if n == nil {
			continue
		}
		id, ok := fullDatabaseID(n.FullDatabaseID)
		if !ok || !asked[id] {
			continue
		}
		ref, ok := environmentRef(n.Dir, n.File)
		if _, again := refs[id]; again || failed[i] || !ok {
			unread[id] = true
			continue
		}
		refs[id] = ref
	}
	for id := range unread {
		delete(refs, id)
	}
	return refs, got.Errors, nil
}

// nodeIndex is the place in nodes a GraphQL error's path names, or false when it names
// none: a path that begins with nodes and a place, such as ["nodes", 3, "dir"].
func nodeIndex(path []any) (int, bool) {
	if len(path) < 2 || path[0] != "nodes" {
		return 0, false
	}
	f, ok := path[1].(float64)
	if !ok || f < 0 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

// graphQLErrors is the error GraphQL's errors say, at least one: the first's type and
// message, and how many there are.
func graphQLErrors(what string, errs []gqlError) error {
	e := errs[0]
	if len(errs) == 1 {
		return fmt.Errorf("%s: GitHub returned an error, %s: %s", what, orUntyped(e.Type), e.Message)
	}
	return fmt.Errorf("%s: GitHub returned %d errors, the first %s: %s", what, len(errs), orUntyped(e.Type), e.Message)
}

// ReadEnvironmentRef reads the environment_ref of the repository whose id is id and
// whose node id is nodeID, as a listing of the installation's repositories reads it, by
// the same GraphQL query, with the lister's token, which must read the repository's
// contents: "" when the repository has none. It fails when GitHub's answer does not say
// it, as [Lister.ListRepositories] then leaves the repository's collection out.
func (l Lister) ReadEnvironmentRef(ctx context.Context, id int64, nodeID string) (string, error) {
	if id <= 0 || nodeID == "" {
		return "", errors.New("the repository's id or node id is missing")
	}
	if l.Token == nil {
		return "", errors.New("the lister has no token")
	}
	what := "reading the environment definition (.devcontainer or .devcontainer.json) of the repository " + CollectionRef(id)
	refs, errs, err := l.environments(ctx, l.pacerOr(), what, []envRepo{{id: id, node: nodeID}})
	if err != nil {
		return "", err
	}
	ref, ok := refs[id]
	switch {
	case ok:
		return ref, nil
	case len(errs) > 0:
		return "", graphQLErrors(what, errs)
	}
	return "", fmt.Errorf("%s: GitHub's GraphQL response has no usable entry for the repository: it is null, missing, repeated, or has an invalid object id or type", what)
}
