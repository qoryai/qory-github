package github

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// onIssue is the comment c moved to the issue or pull request numbered n, as GitHub
// lists a repository's comments: its page under kind, issues or pull, and its issue_url.
func onIssue(c map[string]any, kind, n string) map[string]any {
	c["html_url"] = "https://github.com/acme/widgets/" + kind + "/" + n + "#issuecomment-" + strings.TrimPrefix(c["html_url"].(string), "https://github.com/acme/widgets/issues/1#issuecomment-")
	c["issue_url"] = "https://api.github.com/repos/acme/widgets/issues/" + n
	return c
}

// TestAPullSendsWhatChangedInEveryStateAndTheCommentsByItem lists two pages of issues
// that changed, one closed and one a pull request, and two pages of the repository's
// comments, and checks the requests: every issue's state, oldest change first, from the
// time asked. The items are sent as an event, closed ones with their reason, and the
// comments grouped by item on each page, none complete; a pull request's comment and
// the App's work item comment are left out, and a comment that names no issue is
// skipped by its ref.
func TestAPullSendsWhatChangedInEveryStateAndTheCommentsByItem(t *testing.T) {
	closed := issue(2, 1)
	closed["state"], closed["state_reason"] = "closed", "not_planned"
	pr := issue(3, 0)
	pr["pull_request"] = map[string]any{"url": "https://api.github.com/repos/acme/widgets/pulls/3"}
	noIssue := comment(51, "bob", "User", "Lost.")
	noIssue["issue_url"] = "https://api.github.com/repos/acme/widgets"
	f := &fakeIssues{
		pageSize: 3,
		issues:   []map[string]any{issue(1, 2), closed, pr, issue(4, 0)},
		repoComments: []map[string]any{
			onIssue(comment(11, "bob", "User", "First."), "issues", "1"),
			onIssue(comment(21, "carol", "User", "Closed it."), "issues", "2"),
			onIssue(comment(12, "bob", "User", "Again."), "issues", "1"),
			onIssue(comment(31, "bob", "User", "On a pull request."), "pull", "3"),
			onIssue(comment(13, "qory-test[bot]", "Bot", "<!-- qory:work-item 7 -->"), "issues", "1"),
			noIssue,
		},
	}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	if err := l.ListChanged(context.Background(), widgets, since); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/repos/acme/widgets",
		"/repos/acme/widgets/issues?state=all&sort=updated&direction=asc&since=2026-01-02T02%3A04%3A05Z&per_page=100",
		"/repos/acme/widgets/issues?direction=asc&page=2&per_page=100&since=2026-01-02T02%3A04%3A05Z&sort=updated&state=all",
		"/repos/acme/widgets/issues/comments?sort=updated&direction=asc&since=2026-01-02T02%3A04%3A05Z&per_page=100",
		"/repos/acme/widgets/issues/comments?direction=asc&page=2&per_page=100&since=2026-01-02T02%3A04%3A05Z&sort=updated",
	}
	if got := f.requested(); !reflect.DeepEqual(got, want) {
		t.Errorf("requested\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	items := s.items()
	if len(items) != 1 || items[0].Listing != nil || items[0].CollectionRef != "acme/widgets" {
		t.Fatalf("items requests %+v", items)
	}
	var got []string
	for _, it := range items[0].Items {
		reason := ""
		if it.StateReason != nil {
			reason = " " + *it.StateReason
		}
		got = append(got, it.Ref+" "+it.State+reason)
	}
	if strings.Join(got, ", ") != "acme/widgets#1 open, acme/widgets#2 closed Not planned, acme/widgets#4 open" {
		t.Errorf("items %v", got)
	}
	cs := s.comments()
	got = nil
	for _, c := range cs {
		if c.Complete != nil {
			t.Errorf("comments on %s say they are complete", c.ItemRef)
		}
		var refs []string
		for _, x := range c.Comments {
			refs = append(refs, x.Ref)
		}
		got = append(got, c.ItemRef+": "+strings.Join(refs, " "))
	}
	if strings.Join(got, ", ") != "acme/widgets#1: 11 12, acme/widgets#2: 21" {
		t.Errorf("comments %v", got)
	}
	if _, ok := s.reqs[0].(contracts.SourceItems); !ok {
		t.Errorf("first request %T, want the items", s.reqs[0])
	}
	if strings.Join(logs, "\n") != "skipped the comment 51: it names no issue" {
		t.Errorf("logged %q", logs)
	}
}

// TestAPullOfARepositoryGoneWrapsErrRepositoryGone has GitHub answer the repository 404
// and checks the pull's error, and that nothing is sent.
func TestAPullOfARepositoryGoneWrapsErrRepositoryGone(t *testing.T) {
	f := &fakeIssues{goneStatus: 404}
	s := &sink{}
	var logs []string
	l := f.lister(t, s, &logs)
	if err := l.ListChanged(context.Background(), widgets, time.Now()); !errors.Is(err, ErrRepositoryGone) {
		t.Errorf("err %v", err)
	}
	if len(s.reqs) != 0 {
		t.Errorf("sent %+v", s.reqs)
	}
}

// TestACommentsPageIsAPullRequestsOnlyByItsPath checks which pages are a pull
// request's.
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
