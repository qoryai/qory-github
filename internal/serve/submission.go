package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// githubSystem is the host name of the system a submission entry's repository must be on
// for this adapter.
const githubSystem = "github.com"

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

// repositoryAt is the repository of a submission target's path, owner/name, on GitHub.
func repositoryAt(path string) (github.Repository, bool) {
	owner, name, ok := strings.Cut(path, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return github.Repository{}, false
	}
	return github.Repository{Owner: owner, Name: name}, true
}

// addressesOf are the addresses of the base commit and of each
// commit of a target, no request sent.
func addressesOf(repo github.Repository, t contracts.SubmissionTarget) (contracts.CommitAddress, []contracts.CommitAddress) {
	base := contracts.CommitAddress{Commit: t.Base.Commit, CommitURL: github.CommitAddresses(repo, t.Base.Commit)[0]}
	commits := make([]contracts.CommitAddress, len(t.Commits))
	for i, c := range t.Commits {
		commits[i] = contracts.CommitAddress{Commit: c.Commit, CommitURL: github.CommitAddresses(repo, c.Commit)[0]}
	}
	return base, commits
}

// applySubmission puts one repository of a submission entry on GitHub and returns the
// reply for it, see [github.Client.SubmitDraft]. The reply has the address of the base
// commit and of each commit, made with no request; it has the draft exactly when the
// target has one, which a repository opens or updates with an installation token for
// that repository with pull_requests: write alone, from the installation that
// RepositoryInstallation finds by the path. A target of another system, or with a path
// that is not owner/name, or with a draft but no text or no base branch, is
// [Permanent]. A draft that a retry cannot open or update is a [*github.SubmitRefused],
// whose reason is the reason of the failure report, see [feed.submission]: also
// not_permitted when no installation reaches the repository, or the mint fails
// permanently, [github.ErrMintRefused], or GitHub returns that the installation is
// suspended, [github.ErrSuspended]. Every other error may pass, and the target is applied
// again. Every error but the first ends with "(submission {id}, {path})".
func (a *Adapter) applySubmission(ctx context.Context, ch contracts.Change, t contracts.SubmissionTarget) (contracts.SubmittedTarget, error) {
	where := " (submission " + ch.SubmissionID + ", " + t.Path + ")"
	// The schema of the entry makes the cases below unreachable: Qory Apiary writes only
	// the system and the paths of the adapter's repositories, and a draft only with a
	// text and a base branch. They are Qory Apiary's defects, so they are logged and
	// passed, with no report.
	if t.System != githubSystem {
		return contracts.SubmittedTarget{}, Permanent(errors.New("report this Qory Apiary defect: the entry's system is not github.com" + where))
	}
	repo, ok := repositoryAt(t.Path)
	if !ok {
		return contracts.SubmittedTarget{}, Permanent(errors.New("report this Qory Apiary defect: the entry's path is not owner/name" + where))
	}
	base, commits := addressesOf(repo, t)
	reply := contracts.SubmittedTarget{System: t.System, Path: t.Path, Base: base, Commits: commits}
	if t.Draft == nil {
		return reply, nil
	}
	if ch.Text == nil || t.Base.Branch == "" {
		return contracts.SubmittedTarget{}, Permanent(errors.New("report this Qory Apiary defect: the entry asks for a draft without text or without a base branch" + where))
	}
	refuse := func(reason, fix string, err error) error {
		status, message := github.AnswerOf(err)
		return &github.SubmitRefused{Reason: reason, Fix: fix, Err: fmt.Errorf("%w%s", err, where), Status: status, Message: message}
	}
	// The run's title, cleaned, is what the reply has when the pull request's title is
	// left with nothing. The schema of the entry gives it a character that is not a space,
	// so an entry without one is Qory Apiary's defect, found before any request.
	fallback, ok := cleanTitle(ch.Text.Title)
	if !ok {
		return contracts.SubmittedTarget{}, Permanent(errors.New("report this Qory Apiary defect: the entry's title has no character that is not a space or forbidden" + where))
	}
	if err := github.CheckDraftText(ch.Text.Title, ch.Text.Description); err != nil {
		return contracts.SubmittedTarget{}, within(err, where)
	}
	installation, _, err := a.GitHub.RepositoryInstallation(ctx, a.AppID, a.Key, repo)
	err = github.Scrubbed(err)
	switch {
	case errors.Is(err, github.ErrRepositoryMoved):
		return contracts.SubmittedTarget{}, refuse(github.ReasonForgeRefused, github.FixMoved, err)
	case errors.Is(err, github.ErrNotInstalled):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, github.FixNotInstalled, err)
	case github.Forbidden(err) && !github.RateLimited(err):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, github.FixAppForbidden, err)
	case github.AnswerRefused(err):
		return contracts.SubmittedTarget{}, refuse(github.ReasonForgeRefused, github.FixForgeRefused, err)
	case err != nil:
		return contracts.SubmittedTarget{}, fmt.Errorf("%w%s", err, where)
	}
	tok, err := a.pullToken(ctx, installation, repo)
	err = github.Scrubbed(err)
	switch {
	case errors.Is(err, github.ErrSuspended):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, github.FixSuspended, err)
	case errors.Is(err, github.ErrMintRefused):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, github.FixPermission, err)
	case err != nil:
		return contracts.SubmittedTarget{}, fmt.Errorf("%w%s", err, where)
	}
	d := github.Draft{Repository: repo, Branch: t.Branch, Base: t.Base.Branch, Title: ch.Text.Title, Description: ch.Text.Description, PreviousTitle: ch.PreviousTitle}
	if t.Draft.Action == contracts.DraftUpdate {
		d.Number = t.Draft.Number
	}
	got, err := a.GitHub.SubmitDraft(ctx, a.pacer(installation), tok, d)
	err = a.forgetOn401(installation, err)
	var refused *github.SubmitRefused
	switch {
	case err == nil:
	case errors.As(err, &refused):
		return contracts.SubmittedTarget{}, within(refused, where)
	case errors.Is(err, github.ErrInvalidChange):
		return contracts.SubmittedTarget{}, Permanent(fmt.Errorf("%w%s", err, where))
	default:
		return contracts.SubmittedTarget{}, fmt.Errorf("%w%s", err, where)
	}
	reply.Draft = &contracts.SubmittedDraft{Number: got.Number, URL: got.URL, Title: replyTitle(got.Title, fallback), State: got.State, Action: got.Action}
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
	return shown, strings.Trim(shown, " \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000") != ""
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

// targetState is what the feed keeps of one repository of a submission entry: whether it
// is done, reported or passed or replied to; the reply for it, when it is put on GitHub
// and waits for the entry's reply; and the refusal whose failure report did not reach
// Qory Apiary, or nil.
type targetState struct {
	done    bool
	reply   *contracts.SubmittedTarget
	refused *github.SubmitRefused
	// cause is the error of the last try that failed, not for good.
	cause error
}

// target is the state of the repository with the system and path of t.
func (s *entryState) target(t contracts.SubmissionTarget) *targetState {
	if s.targets == nil {
		s.targets = map[string]*targetState{}
	}
	key := t.System + " " + t.Path
	ts := s.targets[key]
	if ts == nil {
		ts = &targetState{}
		s.targets[key] = ts
	}
	return ts
}

// submission applies a submission entry: each repository in turn, each by itself, so one
// that fails does not stop the others. A repository that is put on GitHub waits for the
// entry's reply. One that a retry cannot put on GitHub, a [*github.SubmitRefused], is
// reported with the error's reason, see [feed.reportTarget], and is not in the reply; one
// that is [Permanent] is logged and passed. Once no repository is left to apply, the
// feed sends Qory Apiary one reply for the entry, with each repository that is put on
// GitHub, see [feed.reply]. A repository that waits for the reply, or is reported or
// passed, is not applied again while state, the entry's state, stands. The entry is done
// once its reply, if it has one, is sent. The error of a repository that is not applied
// is the first error of the entry, with the count of the others, see [failures], and no
// reply is sent until each repository is. An entry with no submission_id of the
// contract's shape, or with no repository or more than 20, is [Permanent].
func (f *feed) submission(ctx context.Context, state *entryState, ch contracts.Change) error {
	if err := github.CheckSubmissionID(ch.SubmissionID); err != nil {
		return Permanent(err)
	}
	if len(ch.Targets) == 0 || len(ch.Targets) > maxSubmissionTargets {
		return Permanent(fmt.Errorf("report this Qory Apiary defect: the entry has %d repositories, not 1 to %d (submission %s)", len(ch.Targets), maxSubmissionTargets, ch.SubmissionID))
	}
	var errs []error
	for _, t := range ch.Targets {
		ts := state.target(t)
		if ts.done || ts.reply != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		reply, err := f.target(ctx, ch, t, ts)
		switch {
		case err != nil:
			ts.cause = err
			errs = append(errs, err)
		case reply != nil:
			ts.reply = reply
		default:
			ts.done = true
		}
	}
	if len(errs) > 0 {
		return failures(errs)
	}
	return f.reply(ctx, state, ch)
}

// maxSubmissionTargets is the most repositories of a submission entry, as the contract
// allows.
const maxSubmissionTargets = 20

// target applies one repository of a submission entry, see [feed.submission]. It returns
// the reply for the repository once it is put on GitHub, and nil with a nil error once
// the repository is reported or passed.
func (f *feed) target(ctx context.Context, ch contracts.Change, t contracts.SubmissionTarget, ts *targetState) (*contracts.SubmittedTarget, error) {
	reply, err := f.adapter.applySubmission(ctx, ch, t)
	var refused *github.SubmitRefused
	switch {
	case err == nil:
		return &reply, nil
	case errors.As(err, &refused):
		ts.refused = refused
		return nil, f.reportTarget(ctx, ch, t, refused, err)
	case IsPermanent(err):
		f.log.Error("a repository of a submission failed, and is passed", slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("error", err.Error()))
		return nil, nil
	}
	return nil, err
}

// reply sends Qory Apiary the reply for the entry ch: the repositories that wait for it
// in state, in the entry's order. It sends nothing when none waits, as when each is
// reported or passed. Once the reply is sent, or fails permanently, as with Qory Apiary's
// 400 or 403, each is done; the draft exists, and the reply is not sent again. Any other
// failure leaves the repositories waiting, and the next step sends the reply again.
func (f *feed) reply(ctx context.Context, state *entryState, ch contracts.Change) error {
	var held []*targetState
	var targets []contracts.SubmittedTarget
	for _, t := range ch.Targets {
		ts := state.target(t)
		if ts.reply == nil || ts.done || slices.Contains(held, ts) {
			continue
		}
		held = append(held, ts)
		targets = append(targets, *ts.reply)
	}
	if len(held) == 0 {
		return nil
	}
	err := f.apiary.ChangesSubmitted(ctx, contracts.ChangesSubmitted{Version: contracts.Version, SubmissionID: ch.SubmissionID, Targets: targets})
	switch {
	case err == nil:
	case IsPermanent(err):
		f.log.Error("the reply for a submission failed permanently, and is passed", slog.String("submission_id", ch.SubmissionID), slog.Int("repositories", len(held)), slog.String("error", err.Error()))
	default:
		return err
	}
	for _, ts := range held {
		ts.done = true
	}
	return nil
}

// reportTarget sends Qory Apiary the failure report of the repository t of the entry ch,
// with the reason and the detail of refused, after cause, see [Apiary.SubmissionFailed],
// and logs it. It returns nil once the report is sent, or failed permanently, as with
// Qory Apiary's 400 or 403; the repository is then passed. A report that fails otherwise
// is a [*reportPending], and the repository is applied again, until each limit of the
// entry's retries has passed by one more stuckFor, see [feed.entry].
func (f *feed) reportTarget(ctx context.Context, ch contracts.Change, t contracts.SubmissionTarget, refused *github.SubmitRefused, cause error) error {
	reason := refused.Reason
	err := f.apiary.SubmissionFailed(ctx, contracts.ChangesFailed{Version: contracts.Version, SubmissionID: ch.SubmissionID, System: t.System, Path: t.Path, Reason: reason}, refused.Detail())
	attrs := []any{slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("reason", reason)}
	switch {
	case err == nil:
		f.log.Error("a repository of a submission failed, and is passed", append(attrs, slog.String("error", cause.Error()+"; failure report sent to Qory Apiary with the reason "+reason))...)
		return nil
	case IsPermanent(err):
		f.log.Error("a repository of a submission failed, and is passed", append(attrs, slog.String("error", cause.Error()+"; the failure report to Qory Apiary failed permanently: "+err.Error()))...)
		return nil
	}
	// The cause is kept as text alone, as [feed.report] keeps it.
	return &reportPending{reason: reason, err: fmt.Errorf("%s; %w", cause.Error(), err)}
}

// submissionEnded ends the retries of a submission entry whose retries limit has ended:
// each repository that is not put on GitHub is reported and passed, with the refusal of
// its report that did not reach Qory Apiary, or else with the reason that
// [github.EndedRefusal] gives for the last error of that repository's tries; then the
// reply for the repositories that are put on GitHub is sent. A report or a reply that fails, not
// permanently, keeps the entry for one more stuckFor, as a comment's report does, see
// [feed.entry]; then a reply that keeps failing is replaced by a failure report with the
// reason unreachable for each of its repositories. It returns whether the entry is done,
// and the error that keeps it.
func (f *feed) submissionEnded(ctx context.Context, state *entryState, ch contracts.Change, cause error, failed, since time.Duration, limit string) (bool, error) {
	// A cancelled context ends the step, not the entry: no report is sent, and no
	// repository is passed for a request that the cancellation made fail.
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	more := func(what string, t contracts.SubmissionTarget, rerr error) bool {
		if retriesEnded(failed, since, stuckFor) == "" {
			return false
		}
		f.log.Error("check that Qory Apiary returns 204 for "+what+": one failed for a day or more; the repository is passed", slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("error", rerr.Error()), slog.String("retries_ended", limit))
		return true
	}
	for _, t := range ch.Targets {
		ts := state.target(t)
		if ts.done || ts.reply != nil {
			continue
		}
		refused := ts.refused
		if refused == nil {
			// The error of this repository, not the entry's first, which may be another's.
			last := ts.cause
			if last == nil {
				last = cause
			}
			refused = github.EndedRefusal(last)
		}
		if rerr := f.reportTarget(ctx, ch, t, refused, refused); rerr != nil && !more("failure reports", t, rerr) {
			return false, rerr
		}
		ts.done = true
	}
	rerr := f.reply(ctx, state, ch)
	if rerr == nil {
		return true, nil
	}
	if retriesEnded(failed, since, stuckFor) == "" {
		return false, rerr
	}
	for _, t := range ch.Targets {
		if ts := state.target(t); ts.reply != nil && !ts.done {
			replyRefused := &github.SubmitRefused{Reason: github.ReasonUnreachable, Fix: github.FixReplyRefused, Err: rerr, Message: github.OneLine(rerr.Error(), github.MaxDetail)}
			if err := f.reportTarget(ctx, ch, t, replyRefused, rerr); err != nil {
				more("failure reports", t, err)
			}
			ts.done = true
		}
	}
	return true, nil
}
