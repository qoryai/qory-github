package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// pullPermissions are the permissions of the token that opens and updates a draft pull
// request: the pull requests of one repository, and nothing else.
var pullPermissions = map[string]string{"pull_requests": "write"}

// pullToken is an installation token for installation, limited to the repository repo,
// by name, with the permissions in [pullPermissions]. It is kept until shortly before it
// expires, as [Adapter.token] keeps its tokens, and dropped with the installation's
// others, see [Adapter.forgetTokens].
func (a *Adapter) pullToken(ctx context.Context, installation int64, repo github.Repository) (string, error) {
	key := strconv.FormatInt(installation, 10) + " " + strings.ToLower(repo.String()) + " pull_requests:write"
	a.mu.Lock()
	t, ok := a.tokens[key]
	gen := a.generation(&a.gens, installation)
	a.mu.Unlock()
	if ok && time.Until(t.ExpiresAt) > tokenMargin {
		return t.Token, nil
	}
	gh := a.GitHub
	gh.Checked = a.presence.installationSeen
	t, err := gh.MintInstallationToken(ctx, github.Request{AppID: a.AppID, Key: a.Key, InstallationID: installation, Repositories: []github.Repository{repo}, Permissions: pullPermissions})
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gens[installation] != gen {
		return t.Token, nil
	}
	if a.tokens == nil {
		a.tokens = map[string]github.InstallationToken{}
	}
	a.tokens[key] = t
	return t.Token, nil
}

// isOwnerName is whether an address's path has the shape owner/name.
func isOwnerName(path string) bool {
	owner, name, ok := strings.Cut(path, "/")
	return ok && owner != "" && name != "" && !strings.Contains(name, "/")
}

// commitAddress is a commit and its address on GitHub, as the reply's data has it.
type commitAddress struct {
	Commit    string `json:"commit"`
	CommitURL string `json:"commit_url"`
}

// replyDraft is the pull request in the reply's data.
type replyDraft struct {
	Number int64  `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
}

// pullRequestReply is the data of the reply for a change request of the kind
// pull-request: the address of the base commit and of each commit, and the draft, nil
// exactly when the entry asks for none.
type pullRequestReply struct {
	Base    commitAddress   `json:"base"`
	Commits []commitAddress `json:"commits"`
	Draft   *replyDraft     `json:"draft,omitempty"`
}

// addressesOf are the addresses of the base commit and of each commit of d, no request
// sent.
func addressesOf(repo github.Repository, d github.PullRequestData) pullRequestReply {
	r := pullRequestReply{Base: commitAddress{Commit: d.BaseCommit, CommitURL: github.CommitAddresses(repo, d.BaseCommit)[0]}}
	for _, c := range d.Commits {
		r.Commits = append(r.Commits, commitAddress{Commit: c, CommitURL: github.CommitAddresses(repo, c)[0]})
	}
	return r
}

// actions maps the action of [github.Client.SubmitDraft] to the reply's action.
var actions = map[string]string{
	github.DraftOpened:  contracts.ChangeCreated,
	github.DraftUpdated: contracts.ChangeUpdated,
	github.DraftKept:    contracts.ChangeKept,
}

// submitRefusal is the [*github.SubmitRefused] of reason, with the fix and the cause err.
func submitRefusal(reason, fix string, err error) error {
	return &github.SubmitRefused{Reason: reason, Fix: fix, Err: err}
}

// checkTarget is the id of the repository that the target of the pull-request entry ch
// is found by, its collection ref, after the checks of the target, no request sent. The
// address of the target, where it has one, must be on the system of the client's web host,
// see [github.Client.WebHost], and have a path of the shape owner/name; it is no source of
// the repository. Qory Apiary writes the address that serve sent for the collection, so
// an address of another system, a path of another shape and a collection that is not a
// repository's id are Qory Apiary's defects, and [Permanent].
func (a *Adapter) checkTarget(ch contracts.Change, where string) (int64, error) {
	t := ch.Target
	if t.Address != nil {
		if t.Address.System != a.GitHub.WebHost() {
			return 0, Permanent(errors.New("report this Qory Apiary defect: the address's system is not GitHub's host" + where))
		}
		if !isOwnerName(t.Address.Path) {
			return 0, Permanent(errors.New("report this Qory Apiary defect: the address's path is not owner/name" + where))
		}
	}
	id, err := repositoryID(t.Collection)
	if err != nil {
		return 0, Permanent(fmt.Errorf("report this Qory Apiary defect: %w%s", err, where))
	}
	return id, nil
}

// repositoryOf is the repository with the id id, the one that the target of ch is found
// by, see [Adapter.checkTarget]: the installation that reaches it reads the repository's
// current owner/name from GitHub, GET /repositories/{id}, so a repository that was renamed
// still gets its draft when the entry has its old name. The entry is refused with
// not_permitted when no installation reaches the repository, the installation is
// suspended, the mint is refused or GitHub returns 403 for the read; with target_gone when
// GitHub returns that the repository is gone; and with refused for another 4xx status that
// a retry does not change. Any other failure may pass.
func (a *Adapter) repositoryOf(ctx context.Context, id int64, ch contracts.Change, where string) (github.Repository, error) {
	t := ch.Target
	installation, ok, err := reachOf(a.Store, t.Collection)
	if err != nil {
		return github.Repository{}, err
	}
	if !ok {
		return github.Repository{}, submitRefusal(github.ReasonNotPermitted, github.FixNotInstalled, fmt.Errorf("%w%s", errNoInstallation, where))
	}
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, id, "read") },
		Slug:   a.Slug,
	}
	repo, _, err := l.ReadRepository(ctx, id)
	err = a.forgetOn401(installation, github.Scrubbed(err))
	switch {
	case errors.Is(err, github.ErrRepositoryGone):
		return github.Repository{}, submitRefusal(github.ReasonTargetGone, github.FixGone, fmt.Errorf("%w%s", err, where))
	case errors.Is(err, github.ErrSuspended):
		return github.Repository{}, submitRefusal(github.ReasonNotPermitted, github.FixSuspended, fmt.Errorf("%w%s", err, where))
	case errors.Is(err, github.ErrMintRefused):
		return github.Repository{}, submitRefusal(github.ReasonNotPermitted, github.FixPermission, fmt.Errorf("%w%s", err, where))
	case github.Forbidden(err) && !github.RateLimited(err):
		return github.Repository{}, submitRefusal(github.ReasonNotPermitted, github.FixAppForbidden, fmt.Errorf("%w%s", err, where))
	case github.AnswerRefused(err):
		return github.Repository{}, submitRefusal(github.ReasonRefused, github.FixForgeRefused, fmt.Errorf("%w%s", err, where))
	case err != nil:
		return github.Repository{}, fmt.Errorf("%w%s", err, where)
	}
	return repo, nil
}

// applyChangeRequest puts one change_request entry on GitHub and returns the reply for
// it, see [github.Client.SubmitDraft]. The reply has the address of the base commit and
// of each commit in its data, made with no request. It has the address and the action of
// the draft exactly when the data asks for a draft, which the adapter opens or updates
// with an installation token for that repository with pull_requests: write alone, from
// the installation that RepositoryInstallation finds by the repository's current path.
//
// The checks come in this order, each before any request: the kind, the target, see
// [Adapter.checkTarget], the data, see [github.ParsePullRequestData], and the title. A
// change kind that the adapter does not apply, and data that breaks a rule of the kind,
// are a [*github.SubmitRefused] with the reason refused. So is a draft that a retry cannot
// open or update, whose reason is the reason of the failure report, see
// [feed.changeRequest]: also not_permitted when no installation reaches the repository,
// or the mint fails permanently, [github.ErrMintRefused], or GitHub returns that the
// installation is suspended, [github.ErrSuspended]. A target whose address is of another
// system or has a path that is not owner/name, a collection that is not a repository's
// id, or a title with no visible character, is [Permanent]. Every other error may pass,
// and the entry is applied again. Every error but the first ends with "(change request
// {id}, {collection})".
func (a *Adapter) applyChangeRequest(ctx context.Context, ch contracts.Change) (contracts.ChangesSubmitted, error) {
	where := " (change request " + ch.ChangeRequestID + ", " + ch.Target.Collection + ")"
	if ch.ChangeKind != github.ChangeKindPullRequest {
		cause := fmt.Sprintf("qory-github applies only the kind %s, and the entry has the kind %q.", github.ChangeKindPullRequest, prefixOf(ch.ChangeKind, maxLogged))
		return contracts.ChangesSubmitted{}, &github.SubmitRefused{Reason: github.ReasonRefused, Fix: github.FixChangeKind, Err: errors.New(cause + where), Message: github.OneLine(cause, github.MaxDetail)}
	}
	id, err := a.checkTarget(ch, where)
	if err != nil {
		return contracts.ChangesSubmitted{}, err
	}
	data, err := github.ParsePullRequestData(ch.Data)
	if err != nil {
		return contracts.ChangesSubmitted{}, within(err, where)
	}
	// The run's title, cleaned, is what the reply has when the pull request's title is
	// left with nothing. The contract requires a title with a character that is not a
	// space, so an entry without one is Qory Apiary's defect. Both checks come before any
	// request.
	var fallback string
	if data.Draft != nil {
		var ok bool
		if fallback, ok = cleanTitle(ch.Title); !ok {
			return contracts.ChangesSubmitted{}, Permanent(errors.New("report this Qory Apiary defect: the entry's title has no character that is not a space or forbidden" + where))
		}
		if err := github.CheckDraftText(ch.Title, ch.Text); err != nil {
			return contracts.ChangesSubmitted{}, within(err, where)
		}
	}
	repo, err := a.repositoryOf(ctx, id, ch, where)
	if err != nil {
		return contracts.ChangesSubmitted{}, err
	}
	result := addressesOf(repo, data)
	reply := contracts.ChangesSubmitted{Version: contracts.Version, ChangeRequestID: ch.ChangeRequestID, Target: *ch.Target}
	if data.Draft == nil {
		return withData(reply, result)
	}
	refuse := func(reason, fix string, err error) error {
		status, message := github.AnswerOf(err)
		return &github.SubmitRefused{Reason: reason, Fix: fix, Err: fmt.Errorf("%w%s", err, where), Status: status, Message: message}
	}
	// shortcut: the installation and the pull token are found by the name read a moment
	// ago, so a rename in between ends the entry as not_permitted or target_gone; replace
	// it with a token by repository id when that window shows in a log.
	installation, _, err := a.GitHub.RepositoryInstallation(ctx, a.AppID, a.Key, repo)
	err = github.Scrubbed(err)
	switch {
	case errors.Is(err, github.ErrRepositoryMoved):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonTargetGone, github.FixMoved, err)
	case errors.Is(err, github.ErrNotInstalled):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonNotPermitted, github.FixNotInstalled, err)
	case github.Forbidden(err) && !github.RateLimited(err):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonNotPermitted, github.FixAppForbidden, err)
	case github.AnswerRefused(err):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonRefused, github.FixForgeRefused, err)
	case err != nil:
		return contracts.ChangesSubmitted{}, fmt.Errorf("%w%s", err, where)
	}
	tok, err := a.pullToken(ctx, installation, repo)
	err = github.Scrubbed(err)
	switch {
	case errors.Is(err, github.ErrSuspended):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonNotPermitted, github.FixSuspended, err)
	case errors.Is(err, github.ErrMintRefused):
		return contracts.ChangesSubmitted{}, refuse(github.ReasonNotPermitted, github.FixPermission, err)
	case err != nil:
		return contracts.ChangesSubmitted{}, fmt.Errorf("%w%s", err, where)
	}
	// shortcut: int is 64 bits on amd64 and arm64, widen github.Draft.Number for a
	// 32-bit build.
	d := github.Draft{Repository: repo, Branch: data.Branch, Base: data.BaseBranch, Title: ch.Title, Description: ch.Text, Number: int(data.Draft.Number)}
	if ch.Previous != nil {
		d.PreviousTitle = ch.Previous.Title
	}
	got, err := a.GitHub.SubmitDraft(ctx, a.pacer(installation), tok, d)
	err = a.forgetOn401(installation, err)
	var refused *github.SubmitRefused
	switch {
	case err == nil:
	case errors.As(err, &refused):
		return contracts.ChangesSubmitted{}, within(refused, where)
	case errors.Is(err, github.ErrInvalidChange):
		return contracts.ChangesSubmitted{}, Permanent(fmt.Errorf("%w%s", err, where))
	default:
		return contracts.ChangesSubmitted{}, fmt.Errorf("%w%s", err, where)
	}
	result.Draft = &replyDraft{Number: int64(got.Number), Title: replyTitle(got.Title, fallback), State: got.State}
	reply.Action = actions[got.Action]
	reply.Address = &contracts.ChangeAddress{URL: got.URL, Ref: strconv.Itoa(got.Number)}
	return withData(reply, result)
}

// withData is reply with the data result.
func withData(reply contracts.ChangesSubmitted, result pullRequestReply) (contracts.ChangesSubmitted, error) {
	b, err := json.Marshal(result)
	if err != nil {
		return contracts.ChangesSubmitted{}, Permanent(err)
	}
	reply.Data = b
	return reply, nil
}

// within is the refusal err, a [*github.SubmitRefused], with where after its cause, so
// the text still starts with the fix, once.
func within(err error, where string) error {
	var refused *github.SubmitRefused
	errors.As(err, &refused)
	r := *refused
	r.Err = fmt.Errorf("%w%s", refused.Err, where)
	return &r
}

// titleForbidden matches the characters that a draft's title in a reply may not have, as
// the contract's rule of a prose line lists them, see [github.LineForbidden].
var titleForbidden = github.LineForbidden

// cleanTitle is title without the characters in [titleForbidden], and whether it has a
// character that is not a space, as the contract's draft_title needs.
func cleanTitle(title string) (string, bool) {
	shown := titleForbidden.ReplaceAllString(strings.ToValidUTF8(title, ""), "")
	return shown, strings.Trim(shown, "                　") != ""
}

// replyTitle is the title of the pull request on GitHub as the reply sends it, without
// the characters in [titleForbidden], which a person may have put in it: Qory Apiary
// refuses a reply that has one. The pull request is not changed. A title left with
// nothing but spaces is replaced by fallback, the run's title, which [cleanTitle] made
// valid.
func replyTitle(current, fallback string) string {
	if shown, ok := cleanTitle(current); ok {
		return shown
	}
	return fallback
}

// targetState is what the feed keeps of a change_request entry's target: whether it is
// done, reported or passed or replied to; the reply for it, when it is put on GitHub and
// waits for the entry's reply; and the refusal whose failure report did not reach Qory
// Apiary, or nil.
type targetState struct {
	done    bool
	reply   *contracts.ChangesSubmitted
	refused *github.SubmitRefused
	// cause is the error of the last try that failed, not for good.
	cause error
}

// changeRequest applies a change_request entry, which has one target. A change that is
// put on GitHub waits for the entry's reply. One that a retry cannot put on GitHub, a
// [*github.SubmitRefused], is reported with the error's reason, see [feed.reportTarget],
// and has no reply; one that is [Permanent] is logged and passed. A change that waits for
// the reply, or is reported or passed, is not applied again while state, the entry's
// state, stands. The feed sends Qory Apiary the reply for a change that is put on GitHub,
// see [feed.reply], and the entry is done once the reply is sent. An entry with no
// change_request_id of the contract's shape, or no target, is [Permanent]; so is a
// pull-request entry whose target is not one that the adapter reads, see
// [Adapter.checkTarget].
func (f *feed) changeRequest(ctx context.Context, state *entryState, ch contracts.Change) error {
	if err := github.CheckChangeRequestID(ch.ChangeRequestID); err != nil {
		return Permanent(err)
	}
	if ch.Target == nil {
		return Permanent(fmt.Errorf("report this Qory Apiary defect: the entry has no target (change request %s)", ch.ChangeRequestID))
	}
	ts := &state.applied
	if !ts.done && ts.reply == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		reply, err := f.target(ctx, ch, ts)
		switch {
		case err != nil:
			ts.cause = err
			return err
		case reply != nil:
			ts.reply = reply
		default:
			ts.done = true
		}
	}
	return f.reply(ctx, state)
}

// target applies the target of a change_request entry, see [feed.changeRequest]. It
// returns the reply once the change is put on GitHub, and nil with a nil error once the
// change is reported or passed.
func (f *feed) target(ctx context.Context, ch contracts.Change, ts *targetState) (*contracts.ChangesSubmitted, error) {
	reply, err := f.adapter.applyChangeRequest(ctx, ch)
	var refused *github.SubmitRefused
	switch {
	case err == nil:
		return &reply, nil
	case errors.As(err, &refused):
		ts.refused = refused
		return nil, f.reportTarget(ctx, ch, refused, err)
	case IsPermanent(err):
		f.log.Error("a change request failed, and is passed", slog.String("change_request_id", ch.ChangeRequestID), slog.String("collection", ch.Target.Collection), slog.String("error", err.Error()))
		return nil, nil
	}
	return nil, err
}

// reply sends Qory Apiary the reply for the entry that state is the state of, when its
// change waits for it. It sends nothing otherwise, as when the change is reported or
// passed. Once the reply is sent, or fails permanently, as with Qory Apiary's 400 or 403,
// the entry is done; the draft exists, and the reply is not sent again. Any other
// failure leaves the change waiting, and the next step sends the reply again.
func (f *feed) reply(ctx context.Context, state *entryState) error {
	ts := &state.applied
	if ts.reply == nil || ts.done {
		return nil
	}
	err := f.apiary.ChangesSubmitted(ctx, *ts.reply)
	switch {
	case err == nil:
	case IsPermanent(err):
		f.log.Error("the reply for a change request failed permanently, and is passed", slog.String("change_request_id", ts.reply.ChangeRequestID), slog.String("collection", ts.reply.Target.Collection), slog.String("error", err.Error()))
	default:
		return err
	}
	ts.done = true
	return nil
}

// reportTarget sends Qory Apiary the failure report of the change_request entry ch, with
// the reason and the detail of refused, after cause, see [Apiary.ChangeRequestFailed], and
// logs it. It returns nil once the report is sent, or failed permanently, as with Qory
// Apiary's 400 or 403; the change is then passed. A report that fails otherwise is a
// [*reportPending], and the change is applied again, until each limit of the entry's
// retries has passed by one more stuckFor, see [feed.entry].
func (f *feed) reportTarget(ctx context.Context, ch contracts.Change, refused *github.SubmitRefused, cause error) error {
	reason := refused.Reason
	err := f.apiary.ChangeRequestFailed(ctx, contracts.ChangesFailed{Version: contracts.Version, ChangeRequestID: ch.ChangeRequestID, Target: ch.Target, Reason: reason}, refused.Detail())
	attrs := []any{slog.String("change_request_id", ch.ChangeRequestID), slog.String("collection", ch.Target.Collection), slog.String("reason", reason)}
	switch {
	case err == nil:
		f.log.Error("a change request failed, and is passed", append(attrs, slog.String("error", cause.Error()+"; failure report sent to Qory Apiary with the reason "+reason))...)
		return nil
	case IsPermanent(err):
		f.log.Error("a change request failed, and is passed", append(attrs, slog.String("error", cause.Error()+"; the failure report to Qory Apiary failed permanently: "+err.Error()))...)
		return nil
	}
	// The cause is kept as text alone, as [feed.report] keeps it.
	return &reportPending{reason: reason, err: fmt.Errorf("%s; %w", cause.Error(), err)}
}

// changeRequestEnded ends the retries of a change_request entry whose retries limit has
// ended: a change that is not put on GitHub is reported and passed, with the refusal of
// its report that did not reach Qory Apiary, or else with the reason that
// [github.EndedRefusal] gives for the last error of its tries; then the reply for a
// change that is put on GitHub is sent. A report or a reply that fails, not permanently,
// keeps the entry for one more stuckFor, as a comment's report does, see [feed.entry];
// then a reply that keeps failing is replaced by a failure report with the reason
// unreachable. It returns whether the entry is done, and the error that keeps it.
func (f *feed) changeRequestEnded(ctx context.Context, state *entryState, ch contracts.Change, cause error, failed, since time.Duration, limit string) (bool, error) {
	// A cancelled context ends the step, not the entry: no report is sent, and no
	// change is passed for a request that the cancellation made fail.
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	more := func(what string, rerr error) bool {
		if retriesEnded(failed, since, stuckFor) == "" {
			return false
		}
		f.log.Error("check that Qory Apiary returns 204 for "+what+": one failed for a day or more; the change request is passed", slog.String("change_request_id", ch.ChangeRequestID), slog.String("collection", ch.Target.Collection), slog.String("error", rerr.Error()), slog.String("retries_ended", limit))
		return true
	}
	ts := &state.applied
	if !ts.done && ts.reply == nil {
		refused := ts.refused
		if refused == nil {
			last := ts.cause
			if last == nil {
				last = cause
			}
			refused = github.EndedRefusal(last)
		}
		if rerr := f.reportTarget(ctx, ch, refused, refused); rerr != nil && !more("failure reports", rerr) {
			return false, rerr
		}
		ts.done = true
	}
	rerr := f.reply(ctx, state)
	if rerr == nil {
		return true, nil
	}
	if retriesEnded(failed, since, stuckFor) == "" {
		return false, rerr
	}
	if ts.reply != nil && !ts.done {
		replyRefused := &github.SubmitRefused{Reason: github.ReasonUnreachable, Fix: github.FixReplyRefused, Err: rerr, Message: github.OneLine(rerr.Error(), github.MaxDetail)}
		if err := f.reportTarget(ctx, ch, replyRefused, rerr); err != nil {
			more("failure reports", err)
		}
		ts.done = true
	}
	return true, nil
}
