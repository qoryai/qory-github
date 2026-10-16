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

// changedPerPage is how many entries a page of what changed holds, and
// maxChangedPages the most pages [Lister.ListChanged] reads of the issues, and again of
// the comments: as many as a listing reads of the issues. A pull that would read more
// fails.
const changedPerPage = 100

var maxChangedPages = maxIssuePages

// ghRepoComment is a comment as GitHub lists a repository's comments: the comment, and
// the API's URL of the issue or pull request it is on.
type ghRepoComment struct {
	ghComment
	IssueURL string `json:"issue_url"`
}

// ListChanged sends Qory Apiary what changed in the repository whose id is repository at
// or after since, which is how the adapter catches what the webhooks missed: the issues
// GitHub says changed, in every state, pull requests left out, and then the comments on
// the repository's issues that changed. Unlike [Lister.ListOpenIssuesComplete], it sends
// a closed issue too, with its state and its reason, so Qory Apiary learns of a close
// whose webhook it missed. Each request reaches the repository through its id,
// /repositories/{id}, so the collection's ref, which is that id, is all it needs.
//
// Every request is an event's, an upsert: none is a listing's part and none says it is
// complete, so Qory Apiary closes and drops nothing for it. Items go in requests of at
// most 100 items and 1 MiB. Comments go after every item, grouped by their item on each
// page GitHub answers, in requests of at most 100 comments and 1 MiB; a comment on a pull
// request and the App's work item comment are left out. The skip and cut rules are the
// listing's. GitHub lists neither a deleted comment nor an issue deleted or transferred:
// a deleted comment reaches Qory Apiary only by its webhook's event; such an issue
// reaches it by its webhook's event, or Qory Apiary closes it after the next daily
// listing of open issues, which leaves it out and says it is complete, unless it
// skipped an item.
//
// Both are read oldest change first, by time rather than by page number, see
// [changedPages]: each page is asked for from the latest change the page before it
// showed. An issue or a comment edited while they are read moves after that time, where
// a later page reads it, and moves no other entry onto a page already read, so no entry
// is skipped by an edit. The one exception is a second, as GitHub dates a change, that
// more than a page of entries share: that second's entries are read by page number, and
// an edit to one of them while they are read can shift another onto a page already read,
// which skips it. Such an entry stays as Qory Apiary has it until it changes again, or,
// for an issue, until the next daily listing of open issues, which sends it when it is
// open and, since that listing says it is complete unless it skipped an item, has
// Qory Apiary close it when it is not. Each is read in at most 2,000 pages; a pull that
// would read more fails, and so does one GitHub answers that the repository is gone or
// moved, with an error that wraps [ErrRepositoryGone]. It stops at the first error, and
// sends nothing more.
func (l Lister) ListChanged(ctx context.Context, repository int64, since time.Time) error {
	if repository <= 0 {
		return errors.New("the repository's id is not one")
	}
	if l.Sink == nil || l.Token == nil || l.Slug == "" {
		return errors.New("the lister has no sink, no token or no App slug")
	}
	p := l.pacerOr()
	repo := CollectionRef(repository)
	var r ghRepo
	if _, err := l.get(ctx, p, "reading the repository "+repo, "/repositories/"+repo, &r); err != nil {
		return repositoryGone(err)
	}
	// The repository GitHub answers for /repositories/{id} is the one whose id it is.
	r.ID = repository
	coll := collectionOf(r)
	if why := checkCollection(coll); why != "" {
		return fmt.Errorf("the repository %s cannot be a collection: %s", repo, why)
	}
	if err := l.changedIssues(ctx, p, r, since); err != nil {
		return err
	}
	return l.changedComments(ctx, p, coll, since)
}

// changedPages reads, oldest change first, what the listing at base, a path and a query
// sorted by updated ascending, says changed at or after since, and calls page with each
// page's entries that no page before it showed. key and updated are an entry's key and
// the time GitHub says it last changed.
//
// It pages by time: the next page is asked for from the latest change the page showed,
// page 1 again. GitHub's since takes what changed at that time too, so the entries a page
// showed at its latest time are kept, and left out when the next page shows them again.
// When a whole page shares the time it was asked from, that time has more entries than a
// page, and it reads on by page number at that time, until a page shows a later one, and
// then by time again. It stops at a page shorter than a page, and fails with what as its
// error's start once it has read maxChangedPages pages.
func changedPages[T any](ctx context.Context, l Lister, p *Pacer, what, base string, since time.Time, key func(T) string, updated func(T) string, page func([]T) error) error {
	at := since.UTC().Truncate(time.Second)
	seen := map[string]bool{}
	number := 1
	for read := 0; ; read++ {
		if read == maxChangedPages {
			return fmt.Errorf("%s: GitHub has more than %d pages, which a pull never reads", what, maxChangedPages)
		}
		path := base + "&since=" + url.QueryEscape(at.Format(time.RFC3339)) + "&per_page=" + strconv.Itoa(changedPerPage)
		if number > 1 {
			path += "&page=" + strconv.Itoa(number)
		}
		var got []T
		if _, err := l.get(ctx, p, what, path, &got); err != nil {
			return repositoryGone(err)
		}
		latest := at
		var fresh []T
		for _, x := range got {
			t, err := time.Parse(time.RFC3339, updated(x))
			if err == nil && t.Equal(at) {
				if seen[key(x)] {
					continue
				}
				seen[key(x)] = true
			}
			if err == nil && t.After(latest) {
				latest = t
			}
			fresh = append(fresh, x)
		}
		if err := page(fresh); err != nil {
			return err
		}
		if len(got) < changedPerPage {
			return nil
		}
		if !latest.After(at) {
			number++
			continue
		}
		at, number, seen = latest, 1, map[string]bool{}
		for _, x := range got {
			if t, err := time.Parse(time.RFC3339, updated(x)); err == nil && t.Equal(latest) {
				seen[key(x)] = true
			}
		}
	}
}

// changedIssues sends the issues of the repository r that changed at or after since,
// every state's.
func (l Lister) changedIssues(ctx context.Context, p *Pacer, r ghRepo, since time.Time) error {
	system := l.Client.WebHost()
	ref := CollectionRef(r.ID)
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
	what := "listing the issues of " + ref + " that changed"
	base := "/repositories/" + ref + "/issues?state=all&sort=updated&direction=asc"
	err := changedPages(ctx, l, p, what, base, since,
		func(is ghIssue) string { return strconv.FormatInt(is.Number, 10) },
		func(is ghIssue) string { return is.UpdatedAt },
		func(page []ghIssue) error {
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
			return nil
		})
	if err != nil {
		return err
	}
	return send()
}

// changedComments sends the comments on the issues of the repository, the collection
// coll, whose ref is the repository's id, that changed at or after since, grouped by
// their item on each page.
func (l Lister) changedComments(ctx context.Context, p *Pacer, coll contracts.Collection, since time.Time) error {
	what := "listing the comments of " + coll.Ref + " that changed"
	base := "/repositories/" + coll.Ref + "/issues/comments?sort=updated&direction=asc"
	return changedPages(ctx, l, p, what, base, since,
		func(c ghRepoComment) string { return strconv.FormatInt(c.ID, 10) },
		func(c ghRepoComment) string { return c.UpdatedAt },
		func(page []ghRepoComment) error {
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
			return nil
		})
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
