package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
)

// The names of the submission entry's contract that [Client.SubmitDraft] and its callers
// use, in one place. The states and actions are those of the draft in
// changes-submitted.schema.json. closed and merged are the states of a pull request that
// GitHub closed or merged, which SubmitDraft never edits.
const (
	DraftStateDraft  = contracts.DraftStateDraft
	DraftStateOpen   = contracts.DraftStateOpen
	DraftStateClosed = "closed"
	DraftStateMerged = "merged"

	DraftOpened  = contracts.DraftOpened
	DraftUpdated = contracts.DraftUpdated
	DraftKept    = contracts.DraftKept

	// ReasonBranchGone is the failure report's reason for a draft whose head branch or
	// base branch GitHub returns as not existing.
	ReasonBranchGone = "branch_gone"
)

const (
	// MaxDraftDescription is the most characters of the run's text for the description
	// of a draft, as the submission schema caps it.
	MaxDraftDescription = 20000
	// MaxDraftTitle is the most characters of a draft's title.
	MaxDraftTitle = 256
)

// forgeTitlePrefix is the text GitHub puts before the title of a draft that is not ready:
// none, as GitHub's API returns the title as it was written, see [contracts.NextTitle].
const forgeTitlePrefix = ""

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

var submissionIDShape = regexp.MustCompile(`^av_[0-9a-hjkmnp-tv-z]{16}$`)

// CheckSubmissionID returns an error when id is not a submission's id in Qory Apiary:
// av_ and 16 lower-case Crockford base32 characters. The error contains the rule, never
// the value.
func CheckSubmissionID(id string) error {
	if !submissionIDShape.MatchString(id) {
		return invalidChange("report this Qory Apiary defect: the submission_id is not av_ and 16 lower-case base32 characters")
	}
	return nil
}

// Draft is what a submission entry asks for one repository: the draft pull request
// from Branch into Base, with the run's text. Number is the number of the pull request
// of an earlier version's reply, a hint, or 0 for an entry that asks to open one.
// Description is the content of the marked block of the description, see
// [contracts.MarkedDescription]. PreviousTitle is the title of the previous version, see
// [contracts.NextTitle].
type Draft struct {
	Repository         Repository
	Branch, Base       string
	Number             int
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
// retry would fail the same way. Reason is the failure report's reason, [ReasonNotPermitted],
// [ReasonUnreachable], [ReasonBranchGone] or [ReasonTooLong]; Err contains GitHub's
// status and message, or the check that stopped the call. Its text is the fix for
// Reason, see [submitFixes], then Err's text.
type SubmitRefused struct {
	Reason string
	Err    error
}

// submitFixes is the fix that starts the text of a [*SubmitRefused], for each reason.
var submitFixes = map[string]string{
	ReasonNotPermitted: "check the App's installation: it needs the repository and the permission pull requests: write",
	ReasonUnreachable:  "open the draft pull request on GitHub by hand, or submit again later",
	ReasonBranchGone:   "push the branch again, and check that the base branch exists on GitHub",
	ReasonTooLong:      "shorten the title or the description of the pull request on GitHub, and submit again",
}

func (e *SubmitRefused) Error() string {
	if fix, ok := submitFixes[e.Reason]; ok {
		return fix + ": " + e.Err.Error()
	}
	return e.Err.Error()
}
func (e *SubmitRefused) Unwrap() error { return e.Err }

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

// state is the pull request's state as the reply of a submission has it: merged and
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

// SubmitDraft puts the draft pull request of a submission on GitHub, as the App, with
// tok, an installation token of the App for the repository with the permission
// pull_requests: write, each request paced by p, the installation's [Pacer], or a new
// Pacer when p is nil. It looks for the pull request from d.Branch of the repository
// into d.Base, of any state, by the number d.Number when it is above 0, which is a hint, and by the
// head branch otherwise or when GitHub has no pull request with that number and head.
//
//   - None found: it opens a draft pull request from d.Branch into d.Base, with d.Title
//     and the description [contracts.MarkedDescription] writes for no earlier one;
//     the action is [DraftOpened].
//   - One found, closed or merged: it changes nothing; the action is [DraftKept], and
//     the state is closed or merged.
//   - One found, open or draft: it changes the description to the one
//     [contracts.MarkedDescription] writes for the description it has, and the title to
//     the one [contracts.NextTitle] gives, and sends only what changes; the action is
//     [DraftUpdated], or [DraftKept] when nothing changes.
//
// A description of more than [MaxDraftDescription] characters, or a title of more than
// [MaxDraftTitle], is refused as too_long before any request. Every error that a retry
// cannot change is a [*SubmitRefused] with its reason: a 404, a 403 that is no rate
// limit, or a permanent redirect, not_permitted; a 422 for a head or base branch that
// does not exist, branch_gone; a 422 for a text too long, too_long; a 400, any other 422,
// or more than one pull request from the branch, unreachable. Every other error may pass,
// as a 5xx, a timeout or a 401, and the call can be made again; a 422 that says a pull
// request exists already is among them, since the next call finds it. No error contains
// the token, the title or the description.
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
	if err := CheckAPIURL(c.base()); err != nil {
		return DraftResult{}, err
	}
	if p == nil {
		p = &Pacer{}
	}
	found, err := c.findPull(ctx, p, tok, d)
	if err != nil {
		return DraftResult{}, err
	}
	if found == nil {
		return c.openPull(ctx, p, tok, d)
	}
	return c.updatePull(ctx, p, tok, d, *found)
}

// CheckDraftText returns a [*SubmitRefused] with the reason too_long for a description of
// more than [MaxDraftDescription] characters, or a title of more than [MaxDraftTitle],
// and nil otherwise. [Client.SubmitDraft] checks them first; a caller may check them
// before it asks GitHub for anything else.
func CheckDraftText(title, description string) error {
	if n := utf8.RuneCountInString(description); n > MaxDraftDescription {
		return &SubmitRefused{Reason: ReasonTooLong, Err: fmt.Errorf("the description is %d characters; the limit is %d", n, MaxDraftDescription)}
	}
	if n := utf8.RuneCountInString(title); n > MaxDraftTitle {
		return &SubmitRefused{Reason: ReasonTooLong, Err: fmt.Errorf("the title is %d characters; the limit is %d", n, MaxDraftTitle)}
	}
	return nil
}

// pullsPath is the path of the repository's pull requests in GitHub's API.
func pullsPath(repo Repository) string { return "/repos/" + repo.String() + "/pulls" }

// isDraftOf is whether p is a pull request from d.Branch of d's repository itself, not of
// a fork, into d.Base, as the program bin/open-draft chooses it.
func (p ghPull) isDraftOf(d Draft) bool {
	return p.Head.Ref == d.Branch && p.Base.Ref == d.Base && p.Head.Repo != nil && strings.EqualFold(p.Head.Repo.FullName, d.Repository.String())
}

// findPull finds the pull request from d.Branch, of any state, and reads it. It is nil
// when there is none.
func (c Client) findPull(ctx context.Context, p *Pacer, tok string, d Draft) (*ghPull, error) {
	if d.Number > 0 {
		const reading = "reading the pull request of an earlier submission"
		a, err := c.send(ctx, p, false, reading, http.MethodGet, pullsPath(d.Repository)+"/"+strconv.Itoa(d.Number), tok, nil)
		if err != nil {
			return nil, err
		}
		switch {
		case a.status == http.StatusOK:
			var got ghPull
			if err := json.Unmarshal(a.body, &got); err != nil {
				return nil, fmt.Errorf("%s: GitHub's answer: %w", reading, err)
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
		return nil, fmt.Errorf("%s: GitHub's answer: %w", listing, err)
	}
	var numbers []int
	for _, l := range listed {
		if l.isDraftOf(d) {
			numbers = append(numbers, l.Number)
		}
	}
	switch len(numbers) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, &SubmitRefused{Reason: ReasonUnreachable, Err: fmt.Errorf("%s: %d pull requests have that head branch, so none is chosen", listing, len(numbers))}
	}
	const reading = "reading the pull request from the branch"
	a, err = c.send(ctx, p, false, reading, http.MethodGet, pullsPath(d.Repository)+"/"+strconv.Itoa(numbers[0]), tok, nil)
	if err != nil {
		return nil, err
	}
	if a.status != http.StatusOK {
		return nil, submitFailed(a, reading, false)
	}
	var got ghPull
	if err := json.Unmarshal(a.body, &got); err != nil {
		return nil, fmt.Errorf("%s: GitHub's answer: %w", reading, err)
	}
	return &got, nil
}

// openPull opens the draft pull request.
func (c Client) openPull(ctx context.Context, p *Pacer, tok string, d Draft) (DraftResult, error) {
	const opening = "opening the draft pull request"
	req := map[string]any{"title": d.Title, "body": contracts.MarkedDescription("", d.Description), "head": d.Branch, "base": d.Base, "draft": true}
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
	body := contracts.MarkedDescription(found.body(), d.Description)
	title := contracts.NextTitle(found.Title, d.PreviousTitle, d.Title, forgeTitlePrefix)
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
		return DraftResult{}, fmt.Errorf("%s: GitHub's answer: %w", what, err)
	}
	if got.Number <= 0 || got.HTMLURL == "" {
		return DraftResult{}, fmt.Errorf("%s: GitHub's answer has no number or address", what)
	}
	return DraftResult{Number: got.Number, URL: got.HTMLURL, Title: got.Title, State: got.state(), Action: action}, nil
}

// submitFailed is the error for an answer to a step of [Client.SubmitDraft] whose status
// is not the step's success status: a [*SubmitRefused] when a retry would get the same
// status, and GitHub's status and message alone otherwise. creating is whether the step
// creates the pull request, whose 422 can name a head or base branch that does not exist.
func submitFailed(a *apiReply, what string, creating bool) error {
	err := a.err(what)
	switch {
	case a.status == http.StatusNotFound || a.status == http.StatusMovedPermanently || a.status == http.StatusPermanentRedirect:
		return &SubmitRefused{Reason: ReasonNotPermitted, Err: err}
	case a.status == http.StatusForbidden && !a.rateLimited():
		return &SubmitRefused{Reason: ReasonNotPermitted, Err: err}
	case a.status == http.StatusUnprocessableEntity:
		v := a.validation()
		switch {
		case v.tooLong:
			return &SubmitRefused{Reason: ReasonTooLong, Err: err}
		case v.exists:
			return err
		case creating && v.branch:
			return &SubmitRefused{Reason: ReasonBranchGone, Err: err}
		}
		return &SubmitRefused{Reason: ReasonUnreachable, Err: err}
	case a.status == http.StatusBadRequest:
		return &SubmitRefused{Reason: ReasonUnreachable, Err: err}
	}
	return err
}

// branchInvalid matches GitHub's message for a head or base that is no branch, which it
// writes as "head invalid" with a space or a line break, when it sets no field.
var branchInvalid = regexp.MustCompile(`(?i)^(head|base)\s+invalid`)

// validationOf is what GitHub's 422 says: a text too long, a head or base that is not a
// branch of the repository, or a pull request that exists already.
type validationOf struct{ tooLong, branch, exists bool }

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
		case strings.Contains(text, "already exists"):
			v.exists = true
		case (x.Field == "head" || x.Field == "base") && x.Code == "invalid", branchInvalid.MatchString(x.Message):
			v.branch = true
		}
	}
	v.tooLong = v.tooLong || strings.Contains(strings.ToLower(e.Message), "too long")
	return v
}
