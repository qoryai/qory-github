package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The names that [Client.SubmitDraft] and its callers use, in one place. The states are
// those of a pull request in the data of the reply for a pull-request change request:
// draft, open, closed and merged, the last two for a pull request that GitHub closed or
// merged, which SubmitDraft never edits. The actions are those of [Client.SubmitDraft]:
// opened, updated and kept.
const (
	DraftStateDraft  = "draft"
	DraftStateOpen   = "open"
	DraftStateClosed = "closed"
	DraftStateMerged = "merged"

	DraftOpened  = "opened"
	DraftUpdated = "updated"
	DraftKept    = "kept"

	// ReasonTargetGone is the failure report's reason for a repository that GitHub
	// returns as moved: the address of the change request's target does not exist any
	// more.
	ReasonTargetGone = "target_gone"

	// ReasonRefused is the failure report's reason for a request that GitHub refused
	// with a status that no other reason covers, such as 400, or for a head or base
	// branch that GitHub returns as not existing, so the same request fails again.
	ReasonRefused = "refused"

	// ChangeKindPullRequest is the one change kind the adapter applies, the kind that
	// roles.source.change_kinds of the description lists.
	ChangeKindPullRequest = "pull-request"
)

const (
	// MaxDraftDescription is the most characters of the run's text for the description
	// of a draft, as the change request schema caps it.
	MaxDraftDescription = 20000
	// MaxDraftTitle is the most characters of a draft's title.
	MaxDraftTitle = 256
	// MaxPullBody is the most characters GitHub keeps in the description of a pull
	// request, the person's text and the marked block together. The check before an
	// update counts code points; GitHub's 422 for a text too long, reported as too_long
	// too, is the backstop for any other way it counts.
	MaxPullBody = 65536
	// MaxDetail is the most characters of the detail of a failure report.
	MaxDetail = 1000
)

// The lines that begin and end the block of the description that the adapter writes. A
// line is a marker line when it is the marker followed by nothing but spaces, tabs or a
// carriage return.
const (
	markerStart = "<!-- qory:start -->"
	markerEnd   = "<!-- qory:end -->"
)

// isMarker is whether line is marker, alone on its line.
func isMarker(line, marker string) bool {
	return strings.TrimRight(line, " \t\r") == marker
}

// hasMarkerLine is whether a line of text is a marker line.
func hasMarkerLine(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if isMarker(line, markerStart) || isMarker(line, markerEnd) {
			return true
		}
	}
	return false
}

// markedDescription is the description of a draft after the run's text is written:
// existing is the description now, empty for a draft being opened, and text the run's text,
// the content of the block, which has no marker line, see [CheckMarkers]. The block is the
// start marker, a line ending, text, a line ending and the end marker; the line ending is
// CRLF when the first one of existing is, otherwise LF, and only the line endings that
// this function adds use it. The end line is the first end marker line that has a start
// marker line before it, and the start line is the last start marker line before it. The
// block replaces the text from the start of the start line to the end marker, and every
// other byte of existing stays, the spaces, tabs and carriage return after the end marker
// included. Without such a pair, as when a person removed a marker, existing stays whole
// and the block follows it after a blank line.
func markedDescription(existing, text string) string {
	eol := "\n"
	if i := strings.Index(existing, "\n"); i > 0 && existing[i-1] == '\r' {
		eol = "\r\n"
	}
	block := markerStart + eol + text + eol + markerEnd
	if existing == "" {
		return block
	}
	lines := strings.Split(existing, "\n")
	start := -1
	for i, line := range lines {
		switch {
		case isMarker(line, markerStart):
			start = i
		case start >= 0 && isMarker(line, markerEnd):
			head := strings.Join(lines[:start], "\n")
			if start > 0 {
				head += "\n"
			}
			tail := strings.Join(lines[i+1:], "\n")
			if i+1 < len(lines) {
				tail = "\n" + tail
			}
			return head + block + lines[i][len(strings.TrimRight(lines[i], " \t\r")):] + tail
		}
	}
	rest, endings := existing, 0
	for endings < 2 {
		switch {
		case strings.HasSuffix(rest, "\r\n"):
			rest = rest[:len(rest)-2]
		case strings.HasSuffix(rest, "\n"):
			rest = rest[:len(rest)-1]
		default:
			return existing + strings.Repeat(eol, 2-endings) + block
		}
		endings++
	}
	return existing + block
}

// nextTitle is the title of a pull request after an update: next, the title of the new
// version, while current, the title on GitHub, equals previous, the title of the previous
// version; otherwise current, which a person edited. With an empty previous the title
// stays as it is.
func nextTitle(current, previous, next string) string {
	if previous != "" && current == previous {
		return next
	}
	return current
}

// commitAddress is the address of a commit of the repository on GitHub's site.
func commitAddress(repo Repository, commit string) string {
	return "https://github.com/" + repo.String() + "/commit/" + commit
}

// CommitAddresses returns the address on GitHub of each commit of the repository, in the
// order given. No request is sent.
func CommitAddresses(repo Repository, commits ...string) []string {
	out := make([]string, len(commits))
	for i, c := range commits {
		out[i] = commitAddress(repo, c)
	}
	return out
}

var changeRequestIDShape = regexp.MustCompile(`^av_[0-9a-hjkmnp-tv-z]{16}$`)

// CheckChangeRequestID returns an error when id is not a change request's id in Qory
// Apiary: av_ and 16 lower-case Crockford base32 characters. The error contains the
// rule, never the value.
func CheckChangeRequestID(id string) error {
	if !changeRequestIDShape.MatchString(id) {
		return invalidChange("report this Qory Apiary defect: the change_request_id is not av_ and 16 lower-case base32 characters")
	}
	return nil
}

// Draft is what a change request entry asks for one repository: the pull request from
// Branch into Base, with the run's text, a draft when AsDraft. Number is the number of the
// pull request at the previous version's address, a hint, or 0 for an entry with none.
// Description is the content of the marked block of the description, see
// [markedDescription]. PreviousTitle is the title of the previous version, see
// [nextTitle].
type Draft struct {
	Repository         Repository
	Branch, Base       string
	Number             int
	AsDraft            bool
	Title, Description string
	PreviousTitle      string
}

// DraftResult is the pull request after [Client.SubmitDraft]: its number, address, title
// and state, one of the DraftState constants, and what SubmitDraft did, one of
// [DraftOpened], [DraftUpdated] and [DraftKept].
type DraftResult struct {
	Number                    int
	URL, Title, State, Action string
}

// SubmitRefused is the error of a draft that a retry cannot open or update, since the
// retry would fail the same way. Reason is the failure report's reason,
// [ReasonNotPermitted], [ReasonUnreachable], [ReasonTargetGone], [ReasonTooLong] or
// [ReasonRefused]. Fix starts the text of the error, as one line of what a person does.
// A different Fix goes with each failing case, see the Fix constants: at most 100
// characters, ending with a period. The exception is a must_understand for which
// [contracts.CheckChangeMustUnderstand] returns an error, a pointer that the entry's kind
// does not define or a malformed list: Fix is that error, at most 1000 characters, which
// ends with a period for the pointer and has no period for a malformed list. Err is the
// cause: GitHub's status and message, or the check that stopped the call. Status and
// Message are GitHub's answer when the refusal comes from one, else 0 and empty; Message
// is one line with no token, see [OneLine]. The text of the error is Fix, then Err's
// text.
type SubmitRefused struct {
	Reason  string
	Fix     string
	Err     error
	Status  int
	Message string
}

// The fix lines of the failures that do not come from an answer of GitHub to a request of
// [Client.SubmitDraft]: the caller makes them. Each is a line for a person, at most 100
// characters.
const (
	FixNotInstalled = "Install the App on the repository with the permission Pull requests: write."
	FixPermission   = "Give the App's installation the permission Pull requests: write on the repository."
	FixTokenRefused = "Check that the App's key and installation are valid on GitHub, then submit again."
	// FixReplyRefused is the fix line for a repository that is on GitHub, whose reply
	// Qory Apiary did not take for the time the retries last.
	FixReplyRefused = "The pull request exists: check that Qory Apiary is reachable and takes the reply."
	FixSuspended    = "Unsuspend the App's installation on GitHub."
	FixAppForbidden = "Check on GitHub that the App is not suspended or blocked, then submit again."
	FixUnreachable  = "Check that GitHub is reachable, then submit again, or open the pull request by hand."
	// FixMoved is the fix line for a repository for which GitHub returns 301 or 308.
	FixMoved = "Link the repository by its new name: GitHub moved it."
	// FixGone is the fix line for a repository that GitHub returns as deleted, or out of
	// the App's reach.
	FixGone = "Check that the repository exists and the App's installation reaches it, then submit again."
	// FixChangeKind is the fix line for a change request of a kind the adapter does not
	// apply.
	FixChangeKind     = "Use the kind pull-request, or connect an adapter that lists the kind of the change."
	fixHeadGone       = "Push the run's branch to the repository again, then submit again."
	fixBaseGone       = "Create the base branch on GitHub, or choose another base branch, then submit again."
	fixBranchGone     = "Push the run's branch again and check that the base branch exists on GitHub."
	fixRunDescription = "Shorten the description of the run to 20000 characters or fewer."
	fixRunTitle       = "Shorten the title of the run to 256 characters or fewer."
	fixMarkerLine     = "Remove the lines <!-- qory:start --> and <!-- qory:end --> from the text, then submit again."
	fixTitleStopped   = "Remove control and invisible format characters from the title, then submit again."
	fixTitleBlank     = "Give the title a character that is not a space, then submit again."
	fixPullBody       = "Shorten the description of the pull request on GitHub outside the Qory block."
	fixPullTitle      = "Shorten the title of the pull request on GitHub to 256 characters or fewer."
	fixPullText       = "Shorten the title or the description of the pull request on GitHub."
	fixUnreadable     = "Report to the maintainers of qory-github that GitHub's answer could not be read."
	FixForgeRefused   = "Change the pull request or the run as GitHub's answer says, then submit again."
)

func (e *SubmitRefused) Error() string {
	if e.Fix != "" {
		return e.Fix + " " + e.Err.Error()
	}
	return e.Err.Error()
}
func (e *SubmitRefused) Unwrap() error { return e.Err }

// Detail is the text of the failure report's detail: Fix, then GitHub's status and
// message when the refusal comes from an answer (the status alone when it has no
// message), else Message when it has one. It is one line of at most [MaxDetail]
// characters, with no control character, and no token: see [OneLine].
func (e *SubmitRefused) Detail() string {
	d := e.Fix
	switch {
	case e.Status != 0 && e.Message == "":
		d += " GitHub returned " + strconv.Itoa(e.Status) + "."
	case e.Status != 0:
		d += " GitHub returned " + strconv.Itoa(e.Status) + ": " + e.Message
	case e.Message != "":
		d += " " + e.Message
	}
	return OneLine(d, MaxDetail)
}

// AnswerOf is the status and the message of GitHub's answer that err, or an error it
// wraps, is, as one line with no token, or 0 and empty when err is no answer.
func AnswerOf(err error) (int, string) {
	var scrubbed *scrubbedError
	if errors.As(err, &scrubbed) && scrubbed.status != 0 {
		return scrubbed.status, scrubbed.message
	}
	var e *answerError
	if errors.As(err, &e) {
		return e.status, OneLine(e.message, MaxDetail)
	}
	return 0, ""
}

// ghPull is a pull request as GitHub's API writes it.
type ghPull struct {
	Number   int     `json:"number"`
	HTMLURL  string  `json:"html_url"`
	State    string  `json:"state"`
	Draft    bool    `json:"draft"`
	Merged   bool    `json:"merged"`
	MergedAt *string `json:"merged_at"`
	Title    string  `json:"title"`
	Body     *string `json:"body"`
	Head     struct {
		Ref  string `json:"ref"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

// state is the pull request's state as the reply of a change request has it: merged and
// closed for a pull request that was, else draft or open. It is the only place that
// maps GitHub's words to the contract's.
func (p ghPull) state() string {
	switch {
	case p.Merged || p.MergedAt != nil:
		return DraftStateMerged
	case p.State == "closed":
		return DraftStateClosed
	case p.Draft:
		return DraftStateDraft
	}
	return DraftStateOpen
}

// body is the pull request's description, empty when GitHub has none.
func (p ghPull) body() string {
	if p.Body == nil {
		return ""
	}
	return *p.Body
}

// SubmitDraft puts the pull request of a change request on GitHub, as the App, with
// tok, an installation token of the App for the repository with the permission
// pull_requests: write, each request paced by p, the installation's [Pacer], or a new
// Pacer when p is nil. It looks for the pull request from d.Branch of the repository,
// into any base branch, of any state: by the number d.Number when it is above 0, which is a
// hint, and by the head branch otherwise or when GitHub has no pull request with that
// number and head. Of several pull requests from the branch it takes the one with the
// number d.Number, else the open one with the highest number, else the closed or merged
// one with the highest number. It never changes the base branch of a pull request.
//
//   - None found: it opens a pull request, a draft when d.AsDraft, from d.Branch into
//     d.Base, with d.Title and the description [markedDescription] writes for no earlier
//     one; the action is [DraftOpened].
//   - One found, closed or merged: it changes nothing; the action is [DraftKept], and
//     the state is closed or merged.
//   - One found, open or draft: it changes the description to the one
//     [markedDescription] writes for the description it has, which is the block
//     alone for an empty description, and the title to the one [nextTitle]
//     gives, and sends only what changes; the action is [DraftUpdated], or [DraftKept]
//     when nothing changes. It never changes whether the pull request is a draft.
//
// A description of more than [MaxDraftDescription] characters, or a title of more than
// [MaxDraftTitle], is refused as too_long before any request, and so is a description
// that the update would make longer than [MaxPullBody]. Every error that a retry cannot
// change is a [*SubmitRefused] with its reason: a 404 or a 403 that is no rate limit,
// not_permitted; a permanent redirect, target_gone; a 422 for a text too long, too_long;
// a 400, a 422 for a head or base branch that does not exist, any other 422, and any
// other 4xx status that is no 401, 403, 404, 408 or 429, refused. Each carries GitHub's
// status and message, see [SubmitRefused.Detail]. Every other error may pass, as a 5xx, a
// timeout or a 401, and the call can be made again; a 422 that says a pull request exists
// already is among them, since the next call finds it. No error contains the token, the
// title or the description.
func (c Client) SubmitDraft(ctx context.Context, p *Pacer, tok string, d Draft) (DraftResult, error) {
	repo := d.Repository
	if !ownerShape.MatchString(repo.Owner) || !nameShape.MatchString(repo.Name) || repo.Name == "." || repo.Name == ".." {
		return DraftResult{}, invalidChange("report this Qory Apiary defect: the path is not owner/name")
	}
	if d.Branch == "" || d.Base == "" || d.Title == "" || tok == "" {
		return DraftResult{}, invalidChange("report this Qory Apiary defect: the entry has no branch, base branch or title")
	}
	if err := CheckDraftText(d.Title, d.Description); err != nil {
		return DraftResult{}, err
	}
	if err := CheckMarkers(d.Description); err != nil {
		return DraftResult{}, err
	}
	if err := CheckAPIURL(c.base()); err != nil {
		return DraftResult{}, err
	}
	if p == nil {
		p = &Pacer{}
	}
	var res DraftResult
	found, err := c.findPull(ctx, p, tok, d)
	switch {
	case err != nil:
	case found == nil:
		res, err = c.openPull(ctx, p, tok, d)
	default:
		res, err = c.updatePull(ctx, p, tok, d, *found)
	}
	return res, Scrubbed(err, tok)
}

// CheckDraftText returns a [*SubmitRefused] with the reason too_long for a description of
// more than [MaxDraftDescription] characters, or a title of more than [MaxDraftTitle],
// and nil otherwise. [Client.SubmitDraft] checks them first; a caller may check them
// before it asks GitHub for anything else.
func CheckDraftText(title, description string) error {
	if n := utf8.RuneCountInString(description); n > MaxDraftDescription {
		return &SubmitRefused{Reason: ReasonTooLong, Fix: fixRunDescription, Err: fmt.Errorf("the description of the run is %d characters; the limit is %d", n, MaxDraftDescription)}
	}
	if n := utf8.RuneCountInString(title); n > MaxDraftTitle {
		return &SubmitRefused{Reason: ReasonTooLong, Fix: fixRunTitle, Err: fmt.Errorf("the title of the run is %d characters; the limit is %d", n, MaxDraftTitle)}
	}
	return nil
}

// CheckMarkers returns a [*SubmitRefused] with the reason refused for a text that has a
// marker line, a line that is the start or the end marker of the description's block, and
// nil otherwise: the adapter writes the text between those lines, and a marker line in it
// would end the block early on the next update.
func CheckMarkers(text string) error {
	if hasMarkerLine(text) {
		cause := "the text of the run has a line that is a qory marker"
		return &SubmitRefused{Reason: ReasonRefused, Fix: fixMarkerLine, Err: errors.New(cause), Message: cause + "."}
	}
	return nil
}

// CheckTitle returns a [*SubmitRefused] with the reason refused for a title that the
// contract's change_title stops: a character that [LineStopped] stops, or no character
// that is not a space, see [HasVisible]. It is nil otherwise. The message has the code
// point of the first stopped character, never the title.
func CheckTitle(title string) error {
	if i := strings.IndexFunc(title, LineStopped); i >= 0 {
		r, _ := utf8.DecodeRuneInString(title[i:])
		cause := fmt.Sprintf("the title of the run has U+%04X, which a title may not have", r)
		return &SubmitRefused{Reason: ReasonRefused, Fix: fixTitleStopped, Err: errors.New(cause), Message: cause + "."}
	}
	if !HasVisible(title) {
		cause := "the title of the run has no character that is not a space"
		return &SubmitRefused{Reason: ReasonRefused, Fix: fixTitleBlank, Err: errors.New(cause), Message: cause + "."}
	}
	return nil
}

// pullsPath is the path of the repository's pull requests in GitHub's API.
func pullsPath(repo Repository) string { return "/repos/" + repo.String() + "/pulls" }

// isDraftOf is whether p is a pull request from d.Branch of d's repository itself, not of
// a fork, into any base branch: the base branch is the one a person set, and a later
// version of a change request with another base branch edits the same pull request, which
// keeps its base.
func (p ghPull) isDraftOf(d Draft) bool {
	return p.Head.Ref == d.Branch && p.Head.Repo != nil && strings.EqualFold(p.Head.Repo.FullName, d.Repository.String())
}

// chosenOf is the pull request of ps, which all have the head branch of the draft, that
// the draft belongs to: the open one with the highest number, else, when none is open,
// the closed or merged one with the highest number. The pull request with the entry's
// number is not among ps: [Client.findPull] reads it first. ps has at least one.
func chosenOf(ps []ghPull) ghPull {
	best := -1
	for i, p := range ps {
		switch {
		case best < 0:
			best = i
		case (p.State == "open") != (ps[best].State == "open"):
			if p.State == "open" {
				best = i
			}
		case p.Number > ps[best].Number:
			best = i
		}
	}
	return ps[best]
}

// findPull finds the pull request from d.Branch, of any state, and reads it. It is nil
// when there is none.
func (c Client) findPull(ctx context.Context, p *Pacer, tok string, d Draft) (*ghPull, error) {
	if d.Number > 0 {
		const reading = "reading the pull request of an earlier change request"
		a, err := c.send(ctx, p, false, reading, http.MethodGet, pullsPath(d.Repository)+"/"+strconv.Itoa(d.Number), tok, nil)
		if err != nil {
			return nil, err
		}
		switch {
		case a.status == http.StatusOK:
			var got ghPull
			if err := json.Unmarshal(a.body, &got); err != nil {
				return nil, unreadable(a.status, reading, err)
			}
			if got.Number == d.Number && got.isDraftOf(d) {
				return &got, nil
			}
		case a.status != http.StatusNotFound && a.status != http.StatusGone:
			return nil, submitFailed(a, reading, false)
		}
	}
	const listing = "looking for the pull request from the branch"
	query := url.Values{"head": {d.Repository.Owner + ":" + d.Branch}, "state": {"all"}, "per_page": {"100"}}
	a, err := c.send(ctx, p, false, listing, http.MethodGet, pullsPath(d.Repository)+"?"+query.Encode(), tok, nil)
	if err != nil {
		return nil, err
	}
	if a.status != http.StatusOK {
		return nil, submitFailed(a, listing, false)
	}
	var listed []ghPull
	if err := json.Unmarshal(a.body, &listed); err != nil {
		return nil, unreadable(a.status, listing, err)
	}
	var ours []ghPull
	for _, l := range listed {
		if l.isDraftOf(d) {
			ours = append(ours, l)
		}
	}
	if len(ours) == 0 {
		return nil, nil
	}
	const reading = "reading the pull request from the branch"
	a, err = c.send(ctx, p, false, reading, http.MethodGet, pullsPath(d.Repository)+"/"+strconv.Itoa(chosenOf(ours).Number), tok, nil)
	if err != nil {
		return nil, err
	}
	if a.status != http.StatusOK {
		return nil, submitFailed(a, reading, false)
	}
	var got ghPull
	if err := json.Unmarshal(a.body, &got); err != nil {
		return nil, unreadable(a.status, reading, err)
	}
	return &got, nil
}

// openPull opens the pull request, as a draft when d.AsDraft.
func (c Client) openPull(ctx context.Context, p *Pacer, tok string, d Draft) (DraftResult, error) {
	const opening = "opening the pull request"
	req := map[string]any{"title": d.Title, "body": markedDescription("", d.Description), "head": d.Branch, "base": d.Base, "draft": d.AsDraft}
	a, err := c.send(ctx, p, false, opening, http.MethodPost, pullsPath(d.Repository), tok, req)
	if err != nil {
		return DraftResult{}, err
	}
	if a.status != http.StatusCreated {
		return DraftResult{}, submitFailed(a, opening, true)
	}
	return resultOf(a, opening, DraftOpened)
}

// updatePull changes the title and the description of an open or draft pull request, or
// nothing for a closed or merged one, or when they stay as they are.
func (c Client) updatePull(ctx context.Context, p *Pacer, tok string, d Draft, found ghPull) (DraftResult, error) {
	kept := DraftResult{Number: found.Number, URL: found.HTMLURL, Title: found.Title, State: found.state(), Action: DraftKept}
	if kept.State == DraftStateClosed || kept.State == DraftStateMerged {
		return kept, nil
	}
	body := markedDescription(found.body(), d.Description)
	title := nextTitle(found.Title, d.PreviousTitle, d.Title)
	patch := map[string]string{}
	// GitHub may store a description with CRLF line breaks, which is the same text.
	if lineFeeds(body) != lineFeeds(found.body()) {
		patch["body"] = body
	}
	if title != found.Title {
		patch["title"] = title
	}
	if len(patch) == 0 {
		return kept, nil
	}
	if n := utf8.RuneCountInString(patch["body"]); n > MaxPullBody {
		return DraftResult{}, &SubmitRefused{Reason: ReasonTooLong, Fix: fixPullBody, Err: fmt.Errorf("updating the pull request: the description with the block would be %d characters; GitHub's limit is %d", n, MaxPullBody)}
	}
	const updating = "updating the pull request"
	a, err := c.send(ctx, p, false, updating, http.MethodPatch, pullsPath(d.Repository)+"/"+strconv.Itoa(found.Number), tok, patch)
	if err != nil {
		return DraftResult{}, err
	}
	if a.status != http.StatusOK {
		return DraftResult{}, submitFailed(a, updating, false)
	}
	return resultOf(a, updating, DraftUpdated)
}

// lineFeeds is s with each CRLF as LF.
func lineFeeds(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// resultOf reads the pull request in GitHub's answer a to what.
func resultOf(a *apiReply, what, action string) (DraftResult, error) {
	var got ghPull
	if err := json.Unmarshal(a.body, &got); err != nil {
		return DraftResult{}, unreadable(a.status, what, err)
	}
	if got.Number <= 0 || got.HTMLURL == "" {
		return DraftResult{}, unreadable(a.status, what, errors.New("it has no number or address"))
	}
	return DraftResult{Number: got.Number, URL: got.HTMLURL, Title: got.Title, State: got.state(), Action: action}, nil
}

// submitFailed is the error for an answer to a step of [Client.SubmitDraft] whose status
// is not the step's success status: a [*SubmitRefused] when a retry would get the same
// status, and GitHub's status and message alone otherwise. A retry gets another status
// after a 401 (the token is dropped), a rate limit, a 408, a 5xx, or a 422 that says the
// pull request exists already. creating is whether the step creates the pull request,
// whose 422 can name a head or base branch that does not exist.
func submitFailed(a *apiReply, what string, creating bool) error {
	err := a.detailedErr(what)
	switch {
	case a.status == http.StatusMovedPermanently || a.status == http.StatusPermanentRedirect:
		return refusedBy(a, ReasonTargetGone, FixMoved, err)
	case a.status == http.StatusNotFound:
		return refusedBy(a, ReasonNotPermitted, FixNotInstalled, err)
	case a.status == http.StatusForbidden && !a.rateLimited():
		return refusedBy(a, ReasonNotPermitted, FixPermission, err)
	case a.status == http.StatusUnprocessableEntity:
		v := a.validation()
		switch {
		case v.exists:
			return err
		case v.tooLong:
			fix := fixPullText
			switch {
			case v.bodyLong && !v.titleLong:
				fix = fixPullBody
			case v.titleLong && !v.bodyLong:
				fix = fixPullTitle
			}
			return refusedBy(a, ReasonTooLong, fix, err)
		case creating && v.branch:
			fix := fixBranchGone
			switch {
			case v.head && !v.base:
				fix = fixHeadGone
			case v.base && !v.head:
				fix = fixBaseGone
			}
			return refusedBy(a, ReasonRefused, fix, err)
		}
		return forgeRefused(a, err)
	case refusedStatus(a.status):
		return forgeRefused(a, err)
	}
	return err
}

// refusedStatus is whether a retry gets the same answer to a status: a 4xx status other
// than 401 (the token is dropped), 403 and 404 (not_permitted), 408 and 429 (busy).
func refusedStatus(status int) bool {
	return status >= 400 && status < 500 && status != http.StatusUnauthorized && status != http.StatusForbidden &&
		status != http.StatusNotFound && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}

// AnswerRefused is whether err, or an error it wraps, is GitHub's answer with a 4xx status
// that a retry does not change and that no other reason covers, see [ReasonRefused].
func AnswerRefused(err error) bool {
	var e *answerError
	return errors.As(err, &e) && refusedStatus(e.status)
}

// ErrUnreadableAnswer is wrapped in the error of an answer of GitHub to a request of
// [Client.SubmitDraft] that is not JSON of the shape GitHub documents.
var ErrUnreadableAnswer = errors.New("GitHub's answer could not be read")

// unreadable is the error for GitHub's answer to what, which could not be read, for cause.
func unreadable(status int, what string, cause error) error {
	return unreadableAt(status, fmt.Sprintf("%s: %v: %v", what, ErrUnreadableAnswer, cause), cause)
}

// fixUnclassified is the fix line for an error that is neither an answer of GitHub nor a
// failure to reach it.
const fixUnclassified = "Report to the maintainers of qory-github that the adapter failed in a way it does not know."

// EndedRefusal is the refusal to report for a repository whose retries ended after cause,
// the error of its last try. A [*SubmitRefused] is itself. Otherwise the reason is by the
// last error:
//   - unreachable, only for a failure to reach GitHub or read its answer from the
//     connection ([ErrTransport], a timeout), a rate limit (a 403 that says so, or a
//     429), 408, and a 5xx status;
//   - not_permitted, for a 401 that kept coming, a 403 that is no rate limit, and a 404;
//   - target_gone, for a redirect, which the adapter never follows and which comes again:
//     a 301 or 308 has the fix that says GitHub moved the repository, [FixMoved];
//   - refused, for any other 4xx status, an answer that arrived but cannot be used, and an
//     error that is none of these, whose clean text is the message.
func EndedRefusal(cause error) *SubmitRefused {
	var refused *SubmitRefused
	if errors.As(cause, &refused) {
		return refused
	}
	status, message := AnswerOf(cause)
	report := func(reason, fix string) *SubmitRefused {
		return &SubmitRefused{Reason: reason, Fix: fix, Err: cause, Status: status, Message: message}
	}
	var answered *answerError
	switch {
	case errors.As(cause, &answered):
		switch s := answered.status; {
		case s == http.StatusUnauthorized:
			return report(ReasonNotPermitted, FixTokenRefused)
		case s == http.StatusForbidden && answered.limited, s == http.StatusRequestTimeout, s == http.StatusTooManyRequests, s >= 500:
			return report(ReasonUnreachable, FixUnreachable)
		case s == http.StatusForbidden:
			return report(ReasonNotPermitted, FixPermission)
		case s == http.StatusNotFound:
			return report(ReasonNotPermitted, FixNotInstalled)
		case s == http.StatusMovedPermanently || s == http.StatusPermanentRedirect:
			return report(ReasonTargetGone, FixMoved)
		}
		return report(ReasonRefused, FixForgeRefused)
	case errors.Is(cause, ErrUnreadableAnswer):
		r := report(ReasonRefused, fixUnreadable)
		var unread *unreadableError
		if errors.As(cause, &unread) {
			r.Status = unread.status
		}
		if r.Status == 0 {
			r.Message = "No answer status was read."
		}
		return r
	case errors.Is(cause, errMintRedirected):
		return report(ReasonRefused, FixForgeRefused)
	case errors.Is(cause, ErrTransport), errors.Is(cause, context.DeadlineExceeded), errors.Is(cause, context.Canceled):
		return report(ReasonUnreachable, FixUnreachable)
	}
	r := report(ReasonRefused, fixUnclassified)
	r.Message = OneLine(cause.Error(), MaxDetail)
	return r
}

// refusedBy is the [*SubmitRefused] for the answer a, with its status and message.
func refusedBy(a *apiReply, reason, fix string, err error) error {
	return &SubmitRefused{Reason: reason, Fix: fix, Err: err, Status: a.status, Message: a.forgeMessage()}
}

// forgeRefused is the [*SubmitRefused] of an answer that no other reason covers.
func forgeRefused(a *apiReply, err error) error {
	return refusedBy(a, ReasonRefused, FixForgeRefused, err)
}

// detailedErr is [apiReply.err] with the message of [apiReply.forgeMessage], which has the
// errors GitHub lists too.
func (a *apiReply) detailedErr(what string) error {
	e := a.err(what).(*answerError)
	e.message = a.forgeMessage()
	return e
}

// forgeMessage is the text of GitHub's refusal: its message, and each error it lists, as
// "resource field code message", joined by semicolons. It is raw: [Scrubbed] makes it one
// line with no credential, since only it knows the token.
func (a *apiReply) forgeMessage() string {
	var e struct {
		Message string            `json:"message"`
		Errors  []json.RawMessage `json:"errors"`
	}
	json.Unmarshal(a.body, &e)
	parts := []string{e.Message}
	for _, raw := range e.Errors {
		var x struct{ Resource, Field, Code, Message string }
		if json.Unmarshal(raw, &x) != nil {
			var text string
			if json.Unmarshal(raw, &text) == nil {
				parts = append(parts, text)
			}
			continue
		}
		parts = append(parts, strings.Join(slices.DeleteFunc([]string{x.Resource, x.Field, x.Code, x.Message}, func(s string) bool { return s == "" }), " "))
	}
	text := strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), "; ")
	if text == "" {
		text = http.StatusText(a.status)
	}
	return text
}

// branchInvalid matches GitHub's message for a head or base that is no branch, which it
// writes as "head invalid" with a space or a line break, when it sets no field.
var branchInvalid = regexp.MustCompile(`(?i)^(head|base)\s+invalid`)

// validationOf is what GitHub's 422 says: a text too long, in the title or in the
// description, a head or base that is not a branch of the repository, which of the two,
// or a pull request that exists already.
type validationOf struct {
	tooLong, titleLong, bodyLong bool
	branch, head, base           bool
	exists                       bool
}

// validation reads GitHub's 422.
func (a *apiReply) validation() validationOf {
	var e struct {
		Message string `json:"message"`
		Errors  []struct {
			Field   string `json:"field"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	var v validationOf
	if json.Unmarshal(a.body, &e) != nil {
		return v
	}
	for _, x := range e.Errors {
		text := strings.ToLower(x.Message)
		switch {
		case strings.Contains(text, "too long"):
			v.tooLong = true
			v.titleLong = v.titleLong || x.Field == "title" || strings.HasPrefix(text, "title ")
			v.bodyLong = v.bodyLong || x.Field == "body" || strings.HasPrefix(text, "body ")
		case strings.Contains(text, "already exists"):
			v.exists = true
		case (x.Field == "head" || x.Field == "base") && x.Code == "invalid":
			v.branch = true
			v.head = v.head || x.Field == "head"
			v.base = v.base || x.Field == "base"
		case branchInvalid.MatchString(x.Message):
			v.branch = true
			v.head = v.head || strings.HasPrefix(text, "head")
			v.base = v.base || strings.HasPrefix(text, "base")
		}
	}
	v.tooLong = v.tooLong || strings.Contains(strings.ToLower(e.Message), "too long")
	return v
}
