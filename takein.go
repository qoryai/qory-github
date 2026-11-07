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
	"unicode/utf8"
)

// Change is one entry of Qory Apiary's change feed: a work item Qory Apiary took in
// from an issue, or a take in that was undone. It has the members of the work_item
// entry of changes.schema.json, in the integration/v1 contract of
// github.com/qoryai/integrations, without kind. serve reads the entry as that module's
// contracts.Change and passes these members to [Client.ApplyChange].
type Change struct {
	// WorkItemID is the work item's id in Qory Apiary, such as wi_42.
	WorkItemID string `json:"work_item_id"`
	// Ref is the item ref the adapter sent Qory Apiary for the issue: the repository's
	// id, #, and the issue's number, see [ParseItemRef].
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

// takeInLabel is the label a taken in issue carries, and takeInLabelColor the colour it
// is created with, without a description, in a repository that has none.
const (
	takeInLabel      = "qory"
	takeInLabelColor = "6E56CF"
)

// TokenFunc returns an installation token that may write the issues of the repository
// whose id is repository, that one repository, with issues: write. Its error never
// contains a token.
type TokenFunc func(ctx context.Context, repository int64) (string, error)

// ErrIssueGone is what [Client.ApplyChange] wraps when GitHub answers 404 or 410 for the
// issue of a take in: the issue was deleted, or the App no longer reaches it. Asking
// again would get the same answer, so a caller drops the change instead of retrying it.
var ErrIssueGone = errors.New("the issue is deleted or out of the App's reach")

// ErrUnreachable is what [Client.ApplyChange] wraps when GitHub's answer says the App
// cannot write the change where it asked to: a 404 for the repository when the label is
// created, a permanent redirect, 301 or 308, as for an issue that was transferred, which
// is never followed, or a 403 that is no rate limit when the label is created, as
// GitHub answers a write in an archived repository, or added to the issue, or the
// comment posted. Asking again would get the
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

// issueRef is the issue a change refers to: its repository's id and its number.
type issueRef struct {
	repository int64
	number     int64
}

// repoPath is the repository's path in GitHub's API, by its id: /repositories/{id},
// under which GitHub's API answers as it does under /repos/{owner}/{name}.
func (i issueRef) repoPath() string {
	return "/repositories/" + strconv.FormatInt(i.repository, 10)
}

// path is the issue's path in GitHub's API.
func (i issueRef) path() string {
	return i.repoPath() + "/issues/" + strconv.FormatInt(i.number, 10)
}

// parseChange checks a change before anything is sent: its ref is an item's ref, the
// repository's id, #, and the issue's number, each decimal digits alone with no sign and
// no leading zero, see [ParseItemRef], so no path is built from any other text; its work
// item id has the shape of one, and its URL is https, at most 2,048 characters of RFC
// 3986, and has no user. The errors name the rule, never the value.
func parseChange(e Change) (issueRef, error) {
	repository, number, ok := ParseItemRef(e.Ref)
	if !ok {
		return issueRef{}, invalidChange("the change's ref is not a repository's id, #, and an issue's number")
	}
	if !workItemIDShape.MatchString(e.WorkItemID) {
		return issueRef{}, invalidChange("the change's work_item_id is not wi_ and 1 to 64 letters, digits, underscores or hyphens")
	}
	if err := checkChangeURL(e.URL); err != nil {
		return issueRef{}, err
	}
	return issueRef{repository: repository, number: number}, nil
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
// only a comment by its bot, slug[bot], counts as the one a take in posted. Each
// request reaches the repository through the id the change's ref names,
// /repositories/{id}, so no request asks for its owner/name first.
//
// The change is checked before anything is sent, see [Change], and refused whole when it
// fails. On [StatusTakenIn] it creates the label qory in the repository when it is
// missing, adds it to the issue, and posts one comment that links the work item, unless
// the App's bot has posted it already. On [StatusUndone] it removes the label from the
// issue and posts nothing; the comment stays. Any other status is not acted on, and nil
// is returned. Each step is one a repeat finds done, so a change applied again after a
// failure or a crash writes nothing twice. The comment is never edited nor deleted. A
// comment entry of the feed, a person's comment, is posted by [Client.PostComment].
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
	tok, err := token(ctx, issue.repository)
	if err != nil {
		return fmt.Errorf("the installation token for the repository %d: %w", issue.repository, err)
	}
	if tok == "" {
		return fmt.Errorf("the installation token for the repository %d is empty", issue.repository)
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
	label := map[string]string{"name": takeInLabel, "color": takeInLabelColor}
	a, err := c.send(ctx, p, false, creating, http.MethodPost, issue.repoPath()+"/labels", tok, label)
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated && !a.labelExists() {
		return failed(a, creating, repoGone|mayNotWrite)
	}
	const adding = "adding the label " + takeInLabel + " to the issue"
	a, err = c.send(ctx, p, false, adding, http.MethodPost, issue.path()+"/labels", tok, map[string][]string{"labels": {takeInLabel}})
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return failed(a, adding, issueGone|mayNotWrite)
	}
	mark := marker(e.WorkItemID)
	takeInFailed := func(a *apiReply, what string) error { return failed(a, what, issueGone) }
	found, err := c.commented(ctx, p, tok, slug, issue, func(body string) bool { return strings.HasPrefix(body, mark) }, takeInFailed)
	if err != nil || found {
		return err
	}
	const commenting = "commenting on the issue"
	body := mark + "\nQory took this into Factory: <" + e.URL + ">"
	a, err = c.send(ctx, p, false, commenting, http.MethodPost, issue.path()+"/comments", tok, map[string]string{"body": body})
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return failed(a, commenting, issueGone|mayNotWrite)
	}
	return nil
}

// Comment is a comment entry of Qory Apiary's change feed: a comment a person wrote in
// Qory Apiary on a work item taken in from an issue, which [Client.PostComment] posts on
// the issue. It has the members of the comment entry of changes.schema.json, in the
// integration/v1 contract of github.com/qoryai/integrations, without kind.
type Comment struct {
	// CommentID is the comment's id in Qory Apiary: sc_ and 16 lower-case Crockford
	// base32 characters, see [CheckCommentID].
	CommentID string
	// Ref is the item ref of the issue, see [ParseItemRef].
	Ref string
	// AuthorName is the name of the person who wrote the comment, as members of Qory
	// Apiary see it: 1 to 100 characters on one line.
	AuthorName string
	// Body is the person's text, posted unchanged.
	Body string
}

// The values of a failure report's reason, for a comment the adapter stopped trying to
// post, changes-failed.schema.json.
const (
	// ReasonItemGone: GitHub answered that the issue does not exist or moved, or no
	// installation reaches its repository.
	ReasonItemGone = "item_gone"
	// ReasonNotPermitted: GitHub answered that the App may not comment on the issue.
	ReasonNotPermitted = "not_permitted"
	// ReasonTooLong: the comment with its first line is longer than GitHub takes.
	ReasonTooLong = "too_long"
	// ReasonUnreachable: GitHub did not take the comment before the retries ended.
	ReasonUnreachable = "unreachable"
)

// CommentRefused is the error of a comment GitHub does not take for good: asking again
// would get the same answer. Reason is the failure report's reason, one of the Reason
// constants; Err is GitHub's answer or the check that refused the comment.
type CommentRefused struct {
	Reason string
	Err    error
}

func (e *CommentRefused) Error() string { return e.Err.Error() }
func (e *CommentRefused) Unwrap() error { return e.Err }

// maxCommentBody is the most characters GitHub takes in a comment's body.
const maxCommentBody = 65536

// maxAuthorName is the most characters of a comment entry's author_name.
const maxAuthorName = 100

var (
	// commentIDShape is a comment's id in Qory Apiary, definitions.schema.json's
	// comment_id.
	commentIDShape = regexp.MustCompile(`^sc_[0-9a-hjkmnp-tv-z]{16}$`)
	// nameControls are the control characters, C0, DEL and C1, which the contract's
	// rule of a prose line, description.schema.json's line, forbids in author_name.
	nameControls = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
	// nameBreaks are the line and paragraph separators, which that rule forbids too.
	// Each becomes a space in the name before it is posted, so the words on either
	// side stay apart.
	nameBreaks = strings.NewReplacer("\u2028", " ", "\u2029", " ")
	// nameHidden are the other characters that rule forbids: the bidirectional
	// controls and the format characters that are usually not shown. They are removed
	// from the name before it is posted.
	nameHidden = regexp.MustCompile(`[\x{00ad}\x{061c}\x{180e}\x{200b}\x{200e}\x{200f}\x{202a}-\x{202e}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{feff}\x{fff9}-\x{fffb}]`)
)

// CheckCommentID refuses what is not a comment's id in Qory Apiary: sc_ and 16
// lower-case Crockford base32 characters. The error contains the rule, never the value.
func CheckCommentID(id string) error {
	if !commentIDShape.MatchString(id) {
		return invalidChange("the comment's comment_id is not sc_ and 16 lower-case Crockford base32 characters")
	}
	return nil
}

// commentMarker begins the last line of a comment the App posts for a comment entry,
// see [Client.PostComment]; the comment's id and " -->" end that line.
const commentMarker = "<!-- qory:comment "

// commentMark is the last line of the comment posted for the comment entry with id.
func commentMark(id string) string { return commentMarker + id + " -->" }

// lastLine is body's last line, after one trailing newline is trimmed.
func lastLine(body string) string {
	body = strings.TrimSuffix(body, "\n")
	return body[strings.LastIndexByte(body, '\n')+1:]
}

// markedID is the comment id of the comment marker that is body's last line, see
// [lastLine], or "" when that line is no comment marker of an id.
func markedID(body string) string {
	id, ok := strings.CutPrefix(lastLine(body), commentMarker)
	if !ok {
		return ""
	}
	id, ok = strings.CutSuffix(id, " -->")
	if !ok || !commentIDShape.MatchString(id) {
		return ""
	}
	return id
}

// nameEscapes are the characters of Markdown, and & and $, that a backslash escapes in
// the author's name: & so no character reference, such as &#8238;, is read, and $ so
// no math is read.
const nameEscapes = "\\`*_{}[]()#+-.!|<>~&$"

// zeroWidthSpace follows each @ and # in the author's name, see [escapeName].
const zeroWidthSpace = "\u200b"

// cleanName is the author's name as the first line contains it, before it is escaped:
// each line or paragraph separator a space, see nameBreaks, without the characters
// nameHidden matches, and without leading and trailing spaces, ASCII or Unicode, such
// as U+00A0 and U+3000, since four leading spaces would make the line a code block.
func cleanName(name string) string {
	return strings.TrimSpace(nameHidden.ReplaceAllString(nameBreaks.Replace(name), ""))
}

// escapeName is the author's name as the first line contains it: each character of
// nameEscapes after a backslash, so the name changes no formatting, and a zero-width
// space after each @ and #, as Dependabot writes them. GitHub finds mentions and issue
// references in the rendered text, so a backslash or a character reference such as
// &#64; still mentions the user; the zero-width space breaks the pattern, so @octocat
// notifies no one and #123 links to nothing.
func escapeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(nameEscapes, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
		if r == '@' || r == '#' {
			b.WriteString(zeroWidthSpace)
		}
	}
	return b.String()
}

// commentBody is the comment posted for e: the first line, which contains the author's
// name, cleaned and escaped, see [cleanName] and [escapeName], an empty line, the
// person's text unchanged, an empty line, and the marker, see [commentMark], as the last
// line.
func commentBody(e Comment) string {
	return escapeName(cleanName(e.AuthorName)) + " wrote in Qory Apiary:\n\n" + e.Body + "\n\n" + commentMark(e.CommentID)
}

// parseComment checks a comment entry before anything is sent: its ref is an item's
// ref, see [ParseItemRef], so no path is built from any other text; its comment_id has
// the shape of one, see [CheckCommentID]; and its author_name is 1 to 100 characters of
// UTF-8 with no control character, as the contract's rule of a prose line has it, and
// is not empty once cleaned, see [cleanName]. The errors contain the rule, never the
// value.
func parseComment(e Comment) (issueRef, error) {
	repository, number, ok := ParseItemRef(e.Ref)
	if !ok {
		return issueRef{}, invalidChange("the comment's ref is not a repository's id, #, and an issue's number")
	}
	if err := CheckCommentID(e.CommentID); err != nil {
		return issueRef{}, err
	}
	name := e.AuthorName
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxAuthorName || nameControls.MatchString(name) || cleanName(name) == "" {
		return issueRef{}, invalidChange("the comment's author_name is not 1 to 100 characters with no control character, or has no character to show")
	}
	return issueRef{repository: repository, number: number}, nil
}

// PostComment posts on the issue the comment of one comment entry of Qory Apiary's
// change feed, as the App's bot, with a token token returns for the issue's
// repository, each request paced by p, the installation's [Pacer], or a new Pacer when
// p is nil. slug is the App's slug. Each request reaches the repository through the id
// in the comment's ref, /repositories/{id}.
//
// The entry is checked before anything is sent, see [Comment], and refused whole with
// an error that wraps [ErrInvalidChange] when it fails. The comment is
// "<author_name> wrote in Qory Apiary:", an empty line, the person's text unchanged, an
// empty line, and the marker <!-- qory:comment {comment_id} --> as its last line; the
// name is cleaned and escaped so it mentions no one and changes no formatting, see
// [cleanName] and [escapeName].
// Before it posts, PostComment reads the issue's comments, and posts nothing when the
// App's bot, slug[bot] of type Bot, has a comment whose last line is that marker: the
// comment of a repeated entry, or of a post whose answer was lost, is posted once.
// Text a person wrote cannot be that last line, since the marker follows it. The
// comment is never edited nor deleted.
//
// A comment GitHub does not take for good is a [*CommentRefused], with its reason: a
// comment longer than 65,536 characters with its first line and marker, too_long, with
// no request sent; a 404 or 410, or a permanent redirect, 301 or 308, item_gone; a 403
// that is no rate limit, not_permitted; a 422 whose errors have the field body,
// too_long, and any other 422, not_permitted. Every other error may pass, and the entry
// can be posted again. No error contains the token, the name or the text.
func (c Client) PostComment(ctx context.Context, p *Pacer, token TokenFunc, slug string, e Comment) error {
	issue, err := parseComment(e)
	if err != nil {
		return err
	}
	if !slugShape.MatchString(slug) {
		return errors.New("the App's slug is not one, 1 to 100 letters, digits, dots, underscores or hyphens")
	}
	body := commentBody(e)
	if n := utf8.RuneCountInString(body); n > maxCommentBody {
		return &CommentRefused{Reason: ReasonTooLong, Err: fmt.Errorf("the comment with its first line is %d characters, and GitHub takes at most %d", n, maxCommentBody)}
	}
	if err := CheckAPIURL(c.base()); err != nil {
		return err
	}
	if token == nil {
		return errors.New("no token function")
	}
	tok, err := token(ctx, issue.repository)
	if err != nil {
		return fmt.Errorf("the installation token for the repository %d: %w", issue.repository, err)
	}
	if tok == "" {
		return fmt.Errorf("the installation token for the repository %d is empty", issue.repository)
	}
	if p == nil {
		p = &Pacer{}
	}
	mark := commentMark(e.CommentID)
	found, err := c.commented(ctx, p, tok, slug, issue, func(body string) bool { return lastLine(body) == mark }, commentFailed)
	if err != nil || found {
		return err
	}
	const commenting = "posting the comment on the issue"
	a, err := c.send(ctx, p, false, commenting, http.MethodPost, issue.path()+"/comments", tok, map[string]string{"body": body})
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return commentFailed(a, commenting)
	}
	return nil
}

// commentFailed is the error for an answer to a step of [Client.PostComment] whose
// status is not the one the step wants: a [*CommentRefused] when asking again would get
// the same answer, and GitHub's answer alone otherwise.
func commentFailed(a *apiReply, what string) error {
	err := a.err(what)
	switch {
	case a.status == http.StatusNotFound || a.status == http.StatusGone ||
		a.status == http.StatusMovedPermanently || a.status == http.StatusPermanentRedirect:
		return &CommentRefused{Reason: ReasonItemGone, Err: err}
	case a.status == http.StatusForbidden && !a.rateLimited():
		return &CommentRefused{Reason: ReasonNotPermitted, Err: err}
	case a.status == http.StatusUnprocessableEntity && a.fieldRefused("body"):
		return &CommentRefused{Reason: ReasonTooLong, Err: err}
	case a.status == http.StatusUnprocessableEntity:
		return &CommentRefused{Reason: ReasonNotPermitted, Err: err}
	}
	return err
}

// commented is whether the App's bot, slug[bot] of type Bot, has a comment on the issue
// whose body match takes. It reads the comments a page at a time, following the next
// page [nextPage] reads, on the API alone; a comment anyone else wrote counts for
// nothing, so pasting the marker does not stop the comment. fail is the error of a page
// GitHub does not answer 200.
func (c Client) commented(ctx context.Context, p *Pacer, tok, slug string, issue issueRef, match func(body string) bool, fail func(a *apiReply, what string) error) (bool, error) {
	const reading = "reading the issue's comments"
	bot := slug + "[bot]"
	path := issue.path() + "/comments?per_page=100"
	for range maxMarkerPages {
		a, err := c.send(ctx, p, false, reading, http.MethodGet, path, tok, nil)
		if err != nil {
			return false, err
		}
		if a.status != http.StatusOK {
			return false, fail(a, reading)
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
			if cm.User.Type == "Bot" && strings.EqualFold(cm.User.Login, bot) && match(cm.Body) {
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

// fieldRefused is whether the answer is GitHub's 422 with an error whose field is
// field.
func (a *apiReply) fieldRefused(field string) bool {
	if a.status != http.StatusUnprocessableEntity {
		return false
	}
	var e struct {
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	if json.Unmarshal(a.body, &e) != nil {
		return false
	}
	for _, x := range e.Errors {
		if x.Field == field {
			return true
		}
	}
	return false
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
