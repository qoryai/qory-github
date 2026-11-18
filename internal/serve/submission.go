package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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
	refuse := func(reason string, err error) error {
		return &github.SubmitRefused{Reason: reason, Err: fmt.Errorf("%w%s", err, where)}
	}
	if err := github.CheckDraftText(ch.Text.Title, ch.Text.Description); err != nil {
		var refused *github.SubmitRefused
		errors.As(err, &refused)
		return contracts.SubmittedTarget{}, refuse(refused.Reason, refused.Err)
	}
	installation, _, err := a.GitHub.RepositoryInstallation(ctx, a.AppID, a.Key, repo)
	switch {
	case errors.Is(err, github.ErrNotInstalled):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, err)
	case github.Forbidden(err) && !strings.Contains(strings.ToLower(err.Error()), "rate limit"):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, err)
	case err != nil:
		return contracts.SubmittedTarget{}, fmt.Errorf("%w%s", err, where)
	}
	tok, err := a.pullToken(ctx, installation, repo)
	switch {
	case errors.Is(err, github.ErrMintRefused) || errors.Is(err, github.ErrSuspended):
		return contracts.SubmittedTarget{}, refuse(github.ReasonNotPermitted, err)
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
		// refused.Err, not err: the new error's text starts with the fix once.
		return contracts.SubmittedTarget{}, refuse(refused.Reason, refused.Err)
	case errors.Is(err, github.ErrInvalidChange):
		return contracts.SubmittedTarget{}, Permanent(fmt.Errorf("%w%s", err, where))
	default:
		return contracts.SubmittedTarget{}, fmt.Errorf("%w%s", err, where)
	}
	reply.Draft = &contracts.SubmittedDraft{Number: got.Number, URL: got.URL, Title: replyTitle(got.Title, ch.Text.Title), State: got.State, Action: got.Action}
	return reply, nil
}

// titleForbidden matches the characters that a draft's title in a reply may not have, as
// the contract's rule of a prose line lists them: the control characters, C0, DEL and
// C1, the bidirectional controls, the line and paragraph separators, and the format
// characters that are usually not shown.
var titleForbidden = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f\x{00ad}\x{061c}\x{180e}\x{200b}\x{200e}\x{200f}\x{2028}\x{2029}\x{202a}-\x{202e}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{feff}\x{fff9}-\x{fffb}]`)

// replyTitle is the title of the pull request on GitHub as the reply sends it, without
// the characters in [titleForbidden], which a person may have put in it: Qory Apiary
// refuses a reply that has one. The pull request is not changed. A title left with
// nothing but spaces is replaced by title, the run's title.
func replyTitle(current, title string) string {
	shown := titleForbidden.ReplaceAllString(strings.ToValidUTF8(current, ""), "")
	if strings.Trim(shown, " \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000") == "" {
		return title
	}
	return shown
}

// targetState is what the feed keeps of one repository of a submission entry: whether it
// is done, replied or reported or passed, and the reason of its failure report that did
// not reach Qory Apiary, or empty.
type targetState struct {
	done   bool
	reason string
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
// that fails does not stop the others. A repository that is put on GitHub is replied to
// Qory Apiary, see [Apiary.ChangesSubmitted]; one that a retry cannot put on GitHub, a
// [*github.SubmitRefused], is reported with the error's reason, see [feed.reportTarget];
// one that is [Permanent] is logged and passed. A repository that is done, replied,
// reported or passed, is not applied again while state, the entry's state, stands. The
// entry is done once every repository is; the error of one that is not is the first
// error of the entry, with the count of the others, see [failures]. An entry with no
// submission_id of the contract's shape, or with no repository or more than 20, is
// [Permanent].
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
		if ts.done {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := f.target(ctx, ch, t, ts); err != nil {
			errs = append(errs, err)
			continue
		}
		ts.done = true
	}
	if len(errs) > 0 {
		return failures(errs)
	}
	return nil
}

// maxSubmissionTargets is the most repositories of a submission entry, as the contract
// allows.
const maxSubmissionTargets = 20

// target applies one repository of a submission entry, see [feed.submission]. A nil
// error means the repository is done.
func (f *feed) target(ctx context.Context, ch contracts.Change, t contracts.SubmissionTarget, ts *targetState) error {
	reply, err := f.adapter.applySubmission(ctx, ch, t)
	var refused *github.SubmitRefused
	switch {
	case err == nil:
		err = f.apiary.ChangesSubmitted(ctx, contracts.ChangesSubmitted{Version: contracts.Version, SubmissionID: ch.SubmissionID, Targets: []contracts.SubmittedTarget{reply}})
		if IsPermanent(err) {
			f.log.Error("the reply for a repository of a submission failed permanently, and is passed", slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("error", err.Error()))
			return nil
		}
		return err
	case errors.As(err, &refused):
		ts.reason = refused.Reason
		return f.reportTarget(ctx, ch, t, refused.Reason, err)
	case IsPermanent(err):
		f.log.Error("a repository of a submission failed, and is passed", slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("error", err.Error()))
		return nil
	}
	return err
}

// reportTarget sends Qory Apiary the failure report of the repository t of the entry ch,
// for reason, after cause, see [Apiary.ChangesFailed], and logs it. It returns nil once
// the report is sent, or failed permanently, as with Qory Apiary's 400 or 403; the
// repository is then passed. A report that fails otherwise is a [*reportPending], and
// the repository is applied again, until each limit of the entry's retries has passed by
// one more stuckFor, see [feed.entry].
func (f *feed) reportTarget(ctx context.Context, ch contracts.Change, t contracts.SubmissionTarget, reason string, cause error) error {
	err := f.apiary.ChangesFailed(ctx, contracts.ChangesFailed{Version: contracts.Version, SubmissionID: ch.SubmissionID, System: t.System, Path: t.Path, Reason: reason})
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
// each repository that is not done is reported, with the reason of its report that did
// not reach Qory Apiary, or unreachable, and passed. A report that fails, not
// permanently, keeps the entry for one more stuckFor, as a comment's does, see
// [feed.entry]. It returns whether the entry is done, and the error that keeps it.
func (f *feed) submissionEnded(ctx context.Context, state *entryState, ch contracts.Change, cause error, failed, since time.Duration, limit string) (bool, error) {
	for _, t := range ch.Targets {
		ts := state.target(t)
		if ts.done {
			continue
		}
		reason := github.ReasonUnreachable
		if ts.reason != "" {
			reason = ts.reason
		}
		var repoCause error = &github.SubmitRefused{Reason: reason, Err: cause}
		if rerr := f.reportTarget(ctx, ch, t, reason, repoCause); rerr != nil {
			if retriesEnded(failed, since, stuckFor) == "" {
				return false, rerr
			}
			f.log.Error("check that Qory Apiary returns 204 for failure reports: one failed for a day or more; the repository is passed", slog.String("submission_id", ch.SubmissionID), slog.String("path", t.Path), slog.String("reason", reason), slog.String("error", rerr.Error()), slog.String("retries_ended", limit))
		}
		ts.done = true
	}
	return true, nil
}
