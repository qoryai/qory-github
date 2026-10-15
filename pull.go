package github

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// maxChangedCommentPages is the most pages of a repository's comments [Lister.ListChanged]
// reads, as many as of its issues.
const maxChangedCommentPages = maxIssuePages

// ghRepoComment is a comment as GitHub lists a repository's comments: the comment, and
// the API's URL of the issue or pull request it is on.
type ghRepoComment struct {
	ghComment
	IssueURL string `json:"issue_url"`
}

// ListChanged sends Qory Apiary what changed in the repository at or after since, which
// is how the adapter catches what the webhooks missed: the issues GitHub says changed,
// in every state, pull requests left out, and then the comments on the repository's
// issues that changed. Unlike [Lister.ListIssues], it sends a closed issue too, with its
// state and its reason, so Qory Apiary learns of a close whose webhook it missed.
//
// Every request is an event's, an upsert: none is a listing's part and none says it is
// complete, so Qory Apiary closes and drops nothing for it. Items go in requests of at
// most 100 items and 1 MiB. Comments go after every item, grouped by their item on each
// page GitHub answers, in requests of at most 100 comments and 1 MiB; a comment on a pull
// request and the App's work item comment are left out. The skip and cut rules are the
// listing's. GitHub lists neither a deleted comment nor an issue deleted or transferred,
// so those reach Qory Apiary only by the webhooks' events.
//
// Both are read oldest change first, by page number, at most 2,000 pages each. An issue
// or a comment that changes while they are read moves to the end, which shifts the pages
// after its place, so one that follows it can be missed: that is a limit. Most pulls read
// one page, which nothing can shift, and the daily listing of open issues reads again
// every issue that is open. A repository GitHub answers is gone or moved stops it with an
// error that wraps [ErrRepositoryGone]. It stops at the first error, and sends nothing
// more.
func (l Lister) ListChanged(ctx context.Context, repo Repository, since time.Time) error {
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return fmt.Errorf("%q is not owner/name", repo.String())
	}
	if l.Sink == nil || l.Token == nil || l.Slug == "" {
		return errors.New("the lister has no sink, no token or no App slug")
	}
	p := l.pacerOr()
	var r ghRepo
	if _, err := l.get(ctx, p, "reading the repository "+repo.String(), "/repos/"+repo.String(), &r); err != nil {
		return repositoryGone(err)
	}
	coll := collectionOf(r)
	if why := checkCollection(coll); why != "" {
		return fmt.Errorf("the repository %s cannot be a collection: %s", repo, why)
	}
	at := url.QueryEscape(since.UTC().Format(time.RFC3339))
	if err := l.changedIssues(ctx, p, repo, r, at); err != nil {
		return err
	}
	return l.changedComments(ctx, p, repo, coll, at)
}

// changedIssues sends the issues of the repository r that changed at or after at, a
// time in RFC 3339 escaped for a query, every state's.
func (l Lister) changedIssues(ctx context.Context, p *Pacer, repo Repository, r ghRepo, at string) error {
	system := l.Client.WebHost()
	ref := r.FullName
	req := contracts.SourceItems{Version: contracts.Version, CollectionRef: ref, Items: []contracts.Item{}}
	envelope := sized(req)
	used := envelope
	send := func() error {
		if len(req.Items) == 0 {
			return nil
		}
		err := l.Sink.Items(ctx, req)
		req.Items, used = []contracts.Item{}, envelope
		return err
	}
	what := "listing the issues of " + repo.String() + " that changed"
	read := pages{what: what, max: maxIssuePages}
	path := "/repos/" + repo.String() + "/issues?state=all&sort=updated&direction=asc&since=" + at + "&per_page=100"
	for path != "" {
		if err := read.read(path); err != nil {
			return err
		}
		var page []ghIssue
		next, err := l.get(ctx, p, what, path, &page)
		if err != nil {
			return repositoryGone(err)
		}
		for _, is := range page {
			if is.PullRequest != nil {
				continue
			}
			it, why, cuts := itemOf(system, r, is)
			n := size(it)
			if why == "" && envelope+n > contracts.MaxRequest {
				why = "it is larger than a request may be"
			}
			if why != "" {
				l.logf("skipped the item %s: %s", it.Ref, why)
				continue
			}
			l.logCuts(cuts)
			if len(req.Items) == contractLimits().items || used+n+1 > contracts.MaxRequest {
				if err := send(); err != nil {
					return err
				}
			}
			req.Items = append(req.Items, it)
			used += n + 1
		}
		path = next
	}
	return send()
}

// changedComments sends the comments on the issues of the repository, the collection
// coll, that changed at or after at, grouped by their item on each page.
func (l Lister) changedComments(ctx context.Context, p *Pacer, repo Repository, coll contracts.Collection, at string) error {
	what := "listing the comments of " + repo.String() + " that changed"
	read := pages{what: what, max: maxChangedCommentPages}
	path := "/repos/" + repo.String() + "/issues/comments?sort=updated&direction=asc&since=" + at + "&per_page=100"
	for path != "" {
		if err := read.read(path); err != nil {
			return err
		}
		var page []ghRepoComment
		next, err := l.get(ctx, p, what, path, &page)
		if err != nil {
			return repositoryGone(err)
		}
		var order []string
		byItem := map[string][]contracts.Comment{}
		for _, c := range page {
			if workItemComment(c.ghComment, l.Slug) || onPullRequest(c.HTMLURL) {
				continue
			}
			sc, why, cuts := commentOf(c.ghComment)
			number, ok := issueNumber(c.IssueURL)
			itemRef := coll.Ref + "#" + strconv.FormatInt(number, 10)
			switch {
			case why != "":
			case !ok:
				why = "it names no issue"
			default:
				if iw := checkRef(itemRef); iw != "" {
					why = "its item: " + iw
				}
			}
			if why == "" && sized(contracts.SourceItemComments{Version: contracts.Version, ItemRef: itemRef, Comments: []contracts.Comment{sc}}) > contracts.MaxRequest {
				why = "it is larger than a request may be"
			}
			if why != "" {
				l.logf("skipped the comment %s: %s", sc.Ref, why)
				continue
			}
			l.logCuts(cuts)
			if _, seen := byItem[itemRef]; !seen {
				order = append(order, itemRef)
			}
			byItem[itemRef] = append(byItem[itemRef], sc)
		}
		for _, itemRef := range order {
			if err := l.sendComments(ctx, itemRef, byItem[itemRef]); err != nil {
				return err
			}
		}
		path = next
	}
	return nil
}

// sendComments sends comments on the item itemRef, each of which fits a request alone,
// in requests of at most 100 comments and 1 MiB.
func (l Lister) sendComments(ctx context.Context, itemRef string, comments []contracts.Comment) error {
	req := contracts.SourceItemComments{Version: contracts.Version, ItemRef: itemRef, Comments: []contracts.Comment{}}
	envelope := sized(req)
	used := envelope
	for _, c := range comments {
		n := size(c)
		if len(req.Comments) == contractLimits().comments || used+n+1 > contracts.MaxRequest {
			if err := l.Sink.Comments(ctx, req); err != nil {
				return err
			}
			req.Comments, used = []contracts.Comment{}, envelope
		}
		req.Comments = append(req.Comments, c)
		used += n + 1
	}
	if len(req.Comments) == 0 {
		return nil
	}
	return l.Sink.Comments(ctx, req)
}

// onPullRequest is whether a comment's page, its html_url, is a pull request's:
// owner/name/pull/number. GitHub lists a pull request's comments among the issues'.
func onPullRequest(htmlURL string) bool {
	u, err := url.Parse(htmlURL)
	if err != nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(parts) >= 3 && parts[2] == "pull"
}

// issueNumber is the number of the issue a comment's issue_url names, the API's
// .../issues/number, or false when it names none.
func issueNumber(issueURL string) (int64, bool) {
	i := strings.LastIndex(issueURL, "/issues/")
	if i < 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(issueURL[i+len("/issues/"):], 10, 64)
	return n, err == nil && n > 0
}
