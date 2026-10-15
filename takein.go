package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Change is one entry of Qory Apiary's change feed: a work item Qory Apiary took in
// from an issue, or a take in that was undone. It mirrors the change feed's entry as
// agreed for the integrations contract, which is not published yet.
type Change struct {
	// WorkItemID is the work item's id in Qory Apiary, such as wi_42.
	WorkItemID string `json:"work_item_id"`
	// Ref is the item ref the adapter sent Qory Apiary for the issue,
	// owner/name#number.
	Ref string `json:"ref"`
	// Status is [StatusTakenIn] or [StatusUndone]; any other is not acted on.
	Status string `json:"status"`
	// URL is the work item's page in Qory Apiary.
	URL string `json:"url"`
}

// The statuses of a [Change] that [Client.ApplyChange] acts on.
const (
	StatusTakenIn = "taken_in"
	StatusUndone  = "undone"
)

// takeInLabel is the label a taken in issue carries, and takeInLabelColor and
// takeInLabelDescription are what the label is created with in a repository that has
// none.
const (
	takeInLabel            = "qory"
	takeInLabelColor       = "6E56CF"
	takeInLabelDescription = "Qory took this into Factory. The work item is in Qory Apiary."
)

// TokenFunc returns an installation token that may write the issues of repo, that one
// repository, with issues: write. Its error never contains a token.
type TokenFunc func(ctx context.Context, repo Repository) (string, error)

// ErrIssueGone is what [Client.ApplyChange] wraps when GitHub answers 404 or 410 for the
// issue of a take in: the issue was deleted, or the App no longer reaches it. Asking
// again would get the same answer, so a caller drops the change instead of retrying it.
var ErrIssueGone = errors.New("the issue is deleted or out of the App's reach")

// ErrUnreachable is what [Client.ApplyChange] wraps when GitHub's answer says the App
// cannot write the change where it asked to: a 404 for the repository when the label is
// created, a permanent redirect, 301 or 308, for a repository that moved or an issue
// that was transferred, which is never followed, or a 403 that is no rate limit when
// the label is added to the issue or the comment posted. Asking again would get the
// same answer, so a caller drops the change instead of retrying it.
var ErrUnreachable = errors.New("the repository or issue moved, or the App cannot write it")

// ErrInvalidChange is what [Client.ApplyChange] wraps when it refuses a change as it
// checks it: a ref, work_item_id or url that is not one, see [Change]. The same change
// is refused every time, so a caller drops it instead of retrying it.
var ErrInvalidChange = errors.New("the change is not one the adapter can apply")

// invalidChange is a change refused as it is checked, with the rule it fails; it
// matches [ErrInvalidChange].
type invalidChange string

// Error is the rule the change fails.
func (e invalidChange) Error() string { return string(e) }

// Is matches [ErrInvalidChange].
func (e invalidChange) Is(target error) bool { return target == ErrInvalidChange }

var (
	// workItemIDShape is a work item's id. Qory Apiary's code sets no format for one
	// yet, so this is a bounded shape that keeps the comment's marker one line and
	// closes it where it should.
	workItemIDShape = regexp.MustCompile(`^wi_[A-Za-z0-9_-]{1,64}$`)
	// issueNumberShape is an issue's number: positive, decimal, without a sign or
	// leading zero, and small enough for an int64.
	issueNumberShape = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
	// changeURLShape is a work item's URL in the characters RFC 3986 allows in a URI,
	// which leave out <, >, ", `, \, {, }, |, ^, spaces, control characters and every
	// character outside ASCII, with every % the start of an escape.
	changeURLShape = regexp.MustCompile(`^(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+$`)
	// slugShape is an App's slug, which its bot's login is made of.
	slugShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
)

// CheckSlug refuses what is not an App's slug: 1 to 100 letters, digits, dots,
// underscores or hyphens, starting with a letter or a digit. Its bot's login is the
// slug and [bot]. The error names the rule, never the value.
func CheckSlug(slug string) error {
	if !slugShape.MatchString(slug) {
		return errors.New("is not an App's slug, 1 to 100 letters, digits, dots, underscores or hyphens")
	}
	return nil
}

// maxChangeURL is the longest work item URL a change may carry.
const maxChangeURL = 2048

// maxMarkerPages is how many pages of an issue's comments, a hundred to a page, are read
// looking for the work item's comment. An issue with more is refused, not commented on
// a second time.
const maxMarkerPages = 100

// issueRef is the issue a change refers to.
type issueRef struct {
	repo   Repository
	number int64
}

// path is the issue's path in GitHub's API.
func (i issueRef) path() string {
	return "/repos/" + i.repo.String() + "/issues/" + strconv.FormatInt(i.number, 10)
}

// parseChange checks a change before anything is sent: its ref is owner/name#number by
// GitHub's rules for owners and names and with a positive number, its work item id has
// the shape of one, and its URL is https, at most 2,048 characters of RFC 3986, and has
// no user. The errors name the rule, never the value.
func parseChange(e Change) (issueRef, error) {
	repoPart, number, ok := strings.Cut(e.Ref, "#")
	if !ok || !issueNumberShape.MatchString(number) {
		return issueRef{}, invalidChange("the change's ref is not owner/name#number")
	}
	repos, err := ParseRepositories(repoPart)
	if err != nil || len(repos) != 1 {
		return issueRef{}, invalidChange("the change's ref is not owner/name#number")
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return issueRef{}, invalidChange("the change's ref is not owner/name#number")
	}
	if !workItemIDShape.MatchString(e.WorkItemID) {
		return issueRef{}, invalidChange("the change's work_item_id is not wi_ and 1 to 64 letters, digits, underscores or hyphens")
	}
	if err := checkChangeURL(e.URL); err != nil {
		return issueRef{}, err
	}
	return issueRef{repo: repos[0], number: n}, nil
}

// checkChangeURL takes a work item's URL: https with a host, at most 2,048 characters,
// each one RFC 3986 allows in a URI, so no space, control character, non-ASCII
// character, <, >, ", `, \, {, }, | or ^; and no user or password, which a public
// comment must not show. The comment writes the URL as an autolink, <url>, in which
// Markdown and HTML are not read, and none of what is left can end it, so the line is
// one link to the URL and nothing else.
func checkChangeURL(s string) error {
	const rule = "the change's url is not an https URL of at most 2,048 characters that RFC 3986 allows, without a user"
	if len(s) > maxChangeURL || !changeURLShape.MatchString(s) {
		return invalidChange(rule)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return invalidChange(rule)
	}
	return nil
}

// marker is the first line of the comment a take in posts, by which a repeat finds it.
func marker(workItemID string) string {
	return workItemMarker + workItemID + " -->"
}

// ApplyChange writes on GitHub what one entry of Qory Apiary's change feed says about an
// issue, with a token token returns for the issue's repository, each request paced by p,
// the installation's [Pacer], or a new Pacer when p is nil. slug is the App's slug:
// only a comment by its bot, slug[bot], counts as the one a take in posted.
//
// The change is checked before anything is sent, see [Change], and refused whole when it
// fails. On [StatusTakenIn] it creates the label qory in the repository when it is
// missing, adds it to the issue, and posts one comment that links the work item, unless
// the App's bot has posted it already. On [StatusUndone] it removes the label from the
// issue and posts nothing; the comment stays. Any other status is not acted on, and nil
// is returned. Each step is one a repeat finds done, so a change applied again after a
// failure or a crash writes nothing twice. The comment is never edited nor deleted.
//
// Three errors are permanent, since asking again would get the same answer, and a
// caller drops the change rather than retry it: one that wraps [ErrInvalidChange], a
// change refused as it is checked; one that wraps [ErrIssueGone], a 404 or 410 for the
// issue during a take in; and one that wraps [ErrUnreachable], see there. During an
// undo a 404 or 410 leaves the issue without the label, so it is done. Every other
// error may pass, and the change can be applied again; a slug that is not one is among
// them, since it is the caller's setting and not the change. No error contains the
// token.
func (c Client) ApplyChange(ctx context.Context, p *Pacer, token TokenFunc, slug string, e Change) error {
	if e.Status != StatusTakenIn && e.Status != StatusUndone {
		return nil
	}
	issue, err := parseChange(e)
	if err != nil {
		return err
	}
	if !slugShape.MatchString(slug) {
		return errors.New("the App's slug is not one, 1 to 100 letters, digits, dots, underscores or hyphens")
	}
	if err := CheckAPIURL(c.base()); err != nil {
		return err
	}
	if token == nil {
		return errors.New("no token function")
	}
	tok, err := token(ctx, issue.repo)
	if err != nil {
		return fmt.Errorf("the installation token for %s: %w", issue.repo, err)
	}
	if tok == "" {
		return fmt.Errorf("the installation token for %s is empty", issue.repo)
	}
	if p == nil {
		p = &Pacer{}
	}
	if e.Status == StatusUndone {
		return c.undo(ctx, p, tok, issue)
	}
	return c.takeIn(ctx, p, tok, slug, issue, e)
}

// takeIn creates the label when the repository has none, adds it to the issue, and posts
// the work item's comment when the App's bot has not.
func (c Client) takeIn(ctx context.Context, p *Pacer, tok, slug string, issue issueRef, e Change) error {
	const creating = "creating the label " + takeInLabel
	label := map[string]string{"name": takeInLabel, "color": takeInLabelColor, "description": takeInLabelDescription}
	a, err := c.send(ctx, p, false, creating, http.MethodPost, "/repos/"+issue.repo.String()+"/labels", tok, label)
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated && !a.labelExists() {
		return failed(a, creating, repoGone)
	}
	const adding = "adding the label " + takeInLabel + " to the issue"
	a, err = c.send(ctx, p, false, adding, http.MethodPost, issue.path()+"/labels", tok, map[string][]string{"labels": {takeInLabel}})
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return failed(a, adding, issueGone|mayNotWrite)
	}
	found, err := c.commented(ctx, p, tok, slug, issue, marker(e.WorkItemID))
	if err != nil || found {
		return err
	}
	const commenting = "commenting on the issue"
	body := marker(e.WorkItemID) + "\nQory took this into Factory: <" + e.URL + ">"
	a, err = c.send(ctx, p, false, commenting, http.MethodPost, issue.path()+"/comments", tok, map[string]string{"body": body})
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return failed(a, commenting, issueGone|mayNotWrite)
	}
	return nil
}

// commented is whether the App's bot, slug[bot] of type Bot, has a comment on the issue
// that starts with the marker. It reads the comments a page at a time, following the
// next page [nextPage] reads, on the API alone; a comment anyone else wrote counts for nothing, so pasting the marker does not stop the comment.
func (c Client) commented(ctx context.Context, p *Pacer, tok, slug string, issue issueRef, mark string) (bool, error) {
	const reading = "reading the issue's comments"
	bot := slug + "[bot]"
	path := issue.path() + "/comments?per_page=100"
	for range maxMarkerPages {
		a, err := c.send(ctx, p, false, reading, http.MethodGet, path, tok, nil)
		if err != nil {
			return false, err
		}
		if a.status != http.StatusOK {
			return false, failed(a, reading, issueGone)
		}
		var comments []struct {
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"user"`
		}
		if err := json.Unmarshal(a.body, &comments); err != nil {
			return false, fmt.Errorf("%s: GitHub's answer: %w", reading, err)
		}
		for _, cm := range comments {
			// Logins are ASCII, so EqualFold folds ASCII's cases alone.
			if cm.User.Type == "Bot" && strings.EqualFold(cm.User.Login, bot) && strings.HasPrefix(cm.Body, mark) {
				return true, nil
			}
		}
		next, err := nextPage(a.header.Values("Link"), c.base())
		if err != nil {
			return false, fmt.Errorf("%s: %w", reading, err)
		}
		if next == "" {
			return false, nil
		}
		path = next
	}
	return false, fmt.Errorf("%s: the issue has more than %d pages of comments; none is posted, since one may be there already", reading, maxMarkerPages)
}

// undo removes the label from the issue. A 404, the label not on the issue, and a 410,
// the issue deleted, both leave the issue without the label, so either is done.
func (c Client) undo(ctx context.Context, p *Pacer, tok string, issue issueRef) error {
	const removing = "removing the label " + takeInLabel + " from the issue"
	a, err := c.send(ctx, p, false, removing, http.MethodDelete, issue.path()+"/labels/"+takeInLabel, tok, nil)
	if err != nil {
		return err
	}
	switch a.status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound, http.StatusGone:
		return nil
	}
	return failed(a, removing, 0)
}

// What a step's answer means, besides a permanent redirect, which is [ErrUnreachable]
// for every step.
const (
	// issueGone makes a 404 or 410 [ErrIssueGone].
	issueGone = 1 << iota
	// repoGone makes a 404 [ErrUnreachable].
	repoGone
	// mayNotWrite makes a 403 that is no rate limit [ErrUnreachable].
	mayNotWrite
)

// failed is the error for an answer whose status is not the one the step wants. It wraps
// [ErrIssueGone] or [ErrUnreachable] when the answer is one asking again would get, as
// means says, and is GitHub's answer alone otherwise.
func failed(a *apiReply, what string, means int) error {
	err := a.err(what)
	switch {
	case a.status == http.StatusMovedPermanently || a.status == http.StatusPermanentRedirect:
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	case means&issueGone != 0 && (a.status == http.StatusNotFound || a.status == http.StatusGone):
		return fmt.Errorf("%w: %w", ErrIssueGone, err)
	case means&repoGone != 0 && a.status == http.StatusNotFound:
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	case means&mayNotWrite != 0 && a.status == http.StatusForbidden && !a.rateLimited():
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return err
}

// rateLimited is whether a 403 is GitHub's rate limit, which passes, rather than a
// refusal: it says when to retry, says no request is left, or its message says so.
func (a *apiReply) rateLimited() bool {
	if a.header.Get("Retry-After") != "" || a.header.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	var e struct {
		Message string `json:"message"`
	}
	json.Unmarshal(a.body, &e)
	return strings.Contains(strings.ToLower(e.Message), "rate limit")
}

// labelExists is whether the answer is GitHub's 422 for a label the repository has
// already: an error whose code is already_exists.
func (a *apiReply) labelExists() bool {
	if a.status != http.StatusUnprocessableEntity {
		return false
	}
	var e struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(a.body, &e) != nil {
		return false
	}
	for _, x := range e.Errors {
		if x.Code == "already_exists" {
			return true
		}
	}
	return false
}
