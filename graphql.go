package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
// the refs of its collection and its items are.
const openIssuesQuery = `query($owner: String!, $name: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    databaseId
    nameWithOwner
    url
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
				DatabaseID    int64  `json:"databaseId"`
				NameWithOwner string `json:"nameWithOwner"`
				URL           string `json:"url"`
				Issues        struct {
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
// listing with it, for any error GraphQL answers, a repository it cannot resolve, which
// wraps [ErrRepositoryGone], a repository whose id is not the pager's or that has none,
// an issue it answers as null, a next cursor that is missing or repeats one already
// read, and a page past maxIssuePages. The id is checked on every page: owner/name may
// name another repository by the time GraphQL reads it, as when a rename or a transfer
// lands after the name was read, and such a page is never taken for the repository's.
// That error does not wrap [ErrRepositoryGone], since the repository is there by its
// id, and a later listing, which reads its name again, may list it.
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
	r := ghRepo{ID: repo.DatabaseID, FullName: repo.NameWithOwner, HTMLURL: repo.URL}
	if r.ID != g.id {
		return g.r, nil, false, fmt.Errorf("%s: GitHub answers a repository whose id is not %d, or no id; it may have been renamed or transferred since its name was read, so a later listing reads it again", g.what, g.id)
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

// answered is the error GraphQL's answer says, or nil: a repository it cannot resolve,
// or that it answers as null, wraps [ErrRepositoryGone]; any other error, a rate limit
// that held among them, is the error of the page. Only GitHub's type and message are
// said, never the query or the token.
func (g *issuePager) answered(got gqlOpenIssues) error {
	for _, e := range got.Errors {
		if e.Type == "NOT_FOUND" && len(e.Path) > 0 && e.Path[0] == "repository" {
			return fmt.Errorf("%w: %s: GitHub answered: %s", ErrRepositoryGone, g.what, e.Message)
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
		return fmt.Errorf("%w: %s: GitHub answered no repository", ErrRepositoryGone, g.what)
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
// A repository with no open issue, read without error, sends one part without items
// that says the listing is complete, so Qory Apiary closes every item of the
// collection it did not hear of since the listing started. A listing stopped early, by
// an error or its context, before every open issue is read and sent, sends the items it
// read and had not sent as its last part, which never says it is complete, nor does any
// part before it; one that fails on its first page sends nothing. A listing that fails
// on the comments of its last part's items, once that part is sent, returns the error,
// and that part, sent already, says it is complete, since every open issue was read and
// sent and comments are no part of complete. A repository GitHub answers it cannot
// resolve stops the listing with an error that wraps [ErrRepositoryGone]. A page whose
// repository's id is not repository, or that has none, as when owner/name names another
// repository by the time GraphQL reads it, stops the listing with an error that does
// not, so a later listing, which reads the name again, lists it; when that is the first
// page, nothing is sent. An issue whose comments GitHub answers are gone has its
// comments skipped and logged by its ref, and the listing goes on.
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
