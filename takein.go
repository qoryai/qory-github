package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Change is one entry of Qory Apiary's change feed: a work item Qory Apiary took in
// from an issue, or a take in that was undone. It mirrors the change feed's entry in
// the integrations contract draft.
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

var (
	// workItemIDShape is a work item's id. Qory Apiary's code sets no format for one
	// yet, so this is a bounded shape that keeps the comment's marker one line and
	// closes it where it should.
	workItemIDShape = regexp.MustCompile(`^wi_[A-Za-z0-9_-]{1,64}$`)
	// issueNumberShape is an issue's number: positive, decimal, without a sign or
	// leading zero, and small enough for an int64.
	issueNumberShape = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
	// slugShape is an App's slug, which its bot's login is made of.
	slugShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
)

// maxChangeURL is the longest work item URL a change may carry.
const maxChangeURL = 2048

// maxAnswer is the largest answer [Client.send] reads: a page of a hundred comments of
// GitHub's longest, 65,536 characters, fits even with every character escaped as JSON.
const maxAnswer = 64 << 20

// maxCommentPages is how many pages of an issue's comments, a hundred to a page, are read
// looking for the work item's comment. An issue with more is refused, not commented on
// a second time.
const maxCommentPages = 100

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
// the shape of one, and its URL is https, at most 2,048 characters, with no control
// character, no space and no user. The errors name the rule, never the value.
func parseChange(e Change) (issueRef, error) {
	repoPart, number, ok := strings.Cut(e.Ref, "#")
	if !ok || !issueNumberShape.MatchString(number) {
		return issueRef{}, errors.New("the change's ref is not owner/name#number")
	}
	repos, err := ParseRepositories(repoPart)
	if err != nil || len(repos) != 1 {
		return issueRef{}, errors.New("the change's ref is not owner/name#number")
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return issueRef{}, errors.New("the change's ref is not owner/name#number")
	}
	if !workItemIDShape.MatchString(e.WorkItemID) {
		return issueRef{}, errors.New("the change's work_item_id is not wi_ and 1 to 64 letters, digits, underscores or hyphens")
	}
	if err := checkChangeURL(e.URL); err != nil {
		return issueRef{}, err
	}
	return issueRef{repo: repos[0], number: n}, nil
}

// checkChangeURL takes a work item's URL: https with a host, at most 2,048 characters of
// UTF-8, and no control character, space or format character such as a bidirectional
// override, so the comment's line is one link that reads as it is; and no user or
// password, which a public comment must not show.
func checkChangeURL(s string) error {
	const rule = "the change's url is not an https URL of at most 2,048 characters without spaces, control characters or a user"
	if len(s) > maxChangeURL || !utf8.ValidString(s) {
		return errors.New(rule)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return errors.New(rule)
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return errors.New(rule)
	}
	return nil
}

// marker is the first line of the comment a take in posts, by which a repeat finds it.
func marker(workItemID string) string {
	return "<!-- qory:work-item " + workItemID + " -->"
}

// ApplyChange writes on GitHub what one entry of Qory Apiary's change feed says about an
// issue, with a token token returns for the issue's repository. slug is the App's slug:
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
// When GitHub answers 404 or 410 for the issue during a take in, the error wraps
// [ErrIssueGone]; during an undo, either leaves the issue without the label, so it is
// done. No error contains the token.
func (c Client) ApplyChange(ctx context.Context, token TokenFunc, slug string, e Change) error {
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
	if e.Status == StatusUndone {
		return c.undo(ctx, tok, issue)
	}
	return c.takeIn(ctx, tok, slug, issue, e)
}

// takeIn creates the label when the repository has none, adds it to the issue, and posts
// the work item's comment when the App's bot has not.
func (c Client) takeIn(ctx context.Context, tok, slug string, issue issueRef, e Change) error {
	const creating = "creating the label " + takeInLabel
	label := map[string]string{"name": takeInLabel, "color": takeInLabelColor, "description": takeInLabelDescription}
	a, err := c.send(ctx, creating, http.MethodPost, "/repos/"+issue.repo.String()+"/labels", tok, label)
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated && !a.labelExists() {
		return a.err(creating)
	}
	const adding = "adding the label " + takeInLabel + " to the issue"
	a, err = c.send(ctx, adding, http.MethodPost, issue.path()+"/labels", tok, map[string][]string{"labels": {takeInLabel}})
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return gone(a, adding)
	}
	found, err := c.commented(ctx, tok, slug, issue, marker(e.WorkItemID))
	if err != nil || found {
		return err
	}
	const commenting = "commenting on the issue"
	body := marker(e.WorkItemID) + "\nQory took this into Factory: " + e.URL
	a, err = c.send(ctx, commenting, http.MethodPost, issue.path()+"/comments", tok, map[string]string{"body": body})
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return gone(a, commenting)
	}
	return nil
}

// commented is whether the App's bot, slug[bot] of type Bot, has a comment on the issue
// that starts with the marker. It reads the comments a page at a time, following the
// Link header's next page only on the API's scheme and host; a comment anyone
// else wrote counts for nothing, so pasting the marker does not stop the comment.
func (c Client) commented(ctx context.Context, tok, slug string, issue issueRef, mark string) (bool, error) {
	const reading = "reading the issue's comments"
	bot := slug + "[bot]"
	path := issue.path() + "/comments?per_page=100"
	for range maxCommentPages {
		a, err := c.send(ctx, reading, http.MethodGet, path, tok, nil)
		if err != nil {
			return false, err
		}
		if a.status != http.StatusOK {
			return false, gone(a, reading)
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
		next, ok, err := c.nextCommentsPage(a.header.Values("Link"))
		if err != nil {
			return false, fmt.Errorf("%s: %w", reading, err)
		}
		if !ok {
			return false, nil
		}
		path = next
	}
	return false, fmt.Errorf("%s: the issue has more than %d pages of comments; none is posted, since one may be there already", reading, maxCommentPages)
}

// undo removes the label from the issue. A 404, the label not on the issue, and a 410,
// the issue deleted, both leave the issue without the label, so either is done.
func (c Client) undo(ctx context.Context, tok string, issue issueRef) error {
	const removing = "removing the label " + takeInLabel + " from the issue"
	a, err := c.send(ctx, removing, http.MethodDelete, issue.path()+"/labels/"+takeInLabel, tok, nil)
	if err != nil {
		return err
	}
	switch a.status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound, http.StatusGone:
		return nil
	}
	return a.err(removing)
}

// gone is the error for an answer about the issue whose status is not the one wanted: it
// wraps [ErrIssueGone] when the answer is 404 or 410.
func gone(a *apiReply, what string) error {
	err := a.err(what)
	if a.status == http.StatusNotFound || a.status == http.StatusGone {
		return fmt.Errorf("%w: %w", ErrIssueGone, err)
	}
	return err
}

// nextCommentsPage is the path and query of the Link header's next page, when there is one. A
// next page on another scheme or host than the API's is refused, so the token goes to
// GitHub's API alone.
func (c Client) nextCommentsPage(links []string) (string, bool, error) {
	for _, l := range links {
		for part := range strings.SplitSeq(l, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
			if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
				continue
			}
			next := false
			for p := range strings.SplitSeq(params, ";") {
				if strings.TrimSpace(p) == `rel="next"` {
					next = true
				}
			}
			if !next {
				continue
			}
			u, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">"))
			base, berr := url.Parse(c.base())
			if err != nil || berr != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.EscapedPath(), "/") {
				return "", false, errors.New("the next page GitHub names is not on the API, so it is not read")
			}
			return u.RequestURI(), true, nil
		}
	}
	return "", false, nil
}

// apiReply is GitHub's answer to one request [Client.send] made: its status, its header
// and its body.
type apiReply struct {
	status int
	header http.Header
	body   []byte
}

// err is the answer as an [answerError] for the request what names.
func (a *apiReply) err(what string) error {
	var e struct {
		Message string `json:"message"`
	}
	json.Unmarshal(a.body, &e)
	if e.Message == "" {
		e.Message = http.StatusText(a.status)
	}
	return &answerError{what: what, status: a.status, message: e.Message}
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

// send makes one request to the API with an installation token and returns GitHub's
// answer whatever its status, so the caller reads the status, and the Link header for
// a list's next page. It is [Client.call] with the answer handed back: it refuses an
// API [CheckAPIURL] refuses before anything is sent, follows no redirect, and its error
// begins with what and never says the request, its path, its header or its body.
func (c Client) send(ctx context.Context, what, method, path, tok string, body any) (*apiReply, error) {
	base := c.base()
	if err := CheckAPIURL(base); err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, r)
	if err != nil {
		return nil, fmt.Errorf("%s: the request could not be made: %w", what, unsent(err, path))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "qory-github")
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: GitHub's API could not be reached: %w", what, unsent(err, path))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("%s: GitHub's answer could not be read: %w", what, unsent(err, path))
	}
	if len(b) > maxAnswer {
		return nil, fmt.Errorf("%s: GitHub's answer is larger than %d bytes", what, maxAnswer)
	}
	return &apiReply{status: resp.StatusCode, header: resp.Header, body: b}, nil
}
