package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// maxActionsAnswer is the largest answer [Actions] reads, 1 MiB: a workflow run as
// GitHub answers it, with its repositories and its head commit, is a few tens of
// kilobytes. A larger answer is refused, never read in part.
const maxActionsAnswer = 1 << 20

// actionsTokenMargin is how long before its expiry an [Actions] token is minted again.
const actionsTokenMargin = 5 * time.Minute

var (
	// workflowShape is a workflow's file name: letters, digits, dots, underscores and
	// hyphens, ending in .yml or .yaml.
	workflowShape = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,250}\.ya?ml$`)
	// dispatchIDShape is a dispatch's id: the provisioner contract's pattern for
	// dispatch_id, read from its definitions, so the starter and the contract cannot
	// drift apart. The schemas are embedded in the contracts package, so a pattern
	// missing from them is the program's fault, and it panics.
	dispatchIDShape = sync.OnceValue(func() *regexp.Regexp {
		doc, err := contracts.ProvisionerDocument("definitions.schema.json")
		if err != nil {
			panic(err)
		}
		return regexp.MustCompile(text(doc, "$defs", "dispatch_id", "pattern"))
	})
)

// CheckWorkflowFile takes a workflow's file name in a repository's .github/workflows:
// letters, digits, dots, underscores or hyphens, ending in .yml or .yaml, at most 255
// characters. The error names the rule, never the value.
func CheckWorkflowFile(s string) error {
	if !workflowShape.MatchString(s) {
		return errors.New("is not a workflow's file name: letters, digits, dots, underscores or hyphens, ending in .yml or .yaml")
	}
	return nil
}

// CheckRef takes a branch or a tag: a short name is a branch, as refs/heads/NAME is,
// and a tag is given as refs/tags/NAME; a name under any other refs/ prefix, such as
// refs/pull/ or refs/remotes/, is refused. The name is one git takes as a branch's or a
// tag's, git check-ref-format's rules in ASCII: printable characters but a space and
// ~ ^ : ? * [ \, no .. and no @{, not @ alone, no part that is empty, starts with a dot
// or ends in .lock, no dot or slash at its end, not HEAD, and no hyphen at its start;
// and further, no later part begins with a hyphen. The error names the rule, never the
// value.
func CheckRef(s string) error {
	bad := errors.New("is not a branch or tag name git takes")
	if len(s) > 255 || s == "@" || strings.Contains(s, "..") || strings.Contains(s, "@{") || strings.HasSuffix(s, ".") {
		return bad
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || strings.IndexByte(`~^:?*[\`, c) >= 0 {
			return bad
		}
	}
	name, full := strings.CutPrefix(s, "refs/heads/")
	if !full {
		name, full = strings.CutPrefix(s, "refs/tags/")
	}
	if !full && strings.HasPrefix(s, "refs/") {
		return errors.New("is neither a branch, NAME or refs/heads/NAME, nor a tag, refs/tags/NAME")
	}
	if name == "HEAD" || strings.HasPrefix(name, "-") {
		return bad
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return bad
		}
	}
	for _, part := range parts {
		if strings.HasPrefix(part, "-") {
			return errors.New("has a part that begins with a hyphen")
		}
	}
	return nil
}

// FullRef is the full ref of a branch or a tag [CheckRef] takes, as a dispatch sends it
// to GitHub: a short name is a branch, sent as refs/heads/NAME, and a name that begins
// with refs/heads/ or refs/tags/ is sent as it is.
func FullRef(ref string) string {
	if strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "refs/tags/") {
		return ref
	}
	return "refs/heads/" + ref
}

// The errors [Actions] wraps, by what a caller does next. Each error it returns wraps
// exactly one of them; one of GitHub's answers wraps the answer too, which [Gone] and
// [Unauthorized] read as they read any other.
var (
	// ErrActionsInvalid is wrapped in the error of a request refused before anything is
	// sent: an id that is not one, a workflow's file name or a ref that is not one, or a
	// dispatch_id outside the provisioner contract's pattern; or an App id or key that
	// is not one. The same request is refused every time.
	ErrActionsInvalid = errors.New("the request is refused before it is sent")
	// ErrActionsGone is wrapped in the error of a request GitHub answers 404 or 410, as
	// for a repository, a workflow or a run that is deleted or out of the App's reach, or
	// with a redirect, which is never followed, as for a mint or a request by an id GitHub
	// redirects. Asking again does not change it.
	ErrActionsGone = errors.New("the repository, the workflow or the run is deleted or out of the App's reach, or GitHub redirects the request")
	// ErrActionsRefused is wrapped in the error of a request GitHub refuses for good: a
	// 403 that is no rate limit, as for a token without actions: write, or any other 4xx
	// but 401, 404, 408, 410 and 429, such as 422 for a workflow without a
	// workflow_dispatch trigger or with inputs it does not take; or a mint GitHub
	// refuses for good, [ErrMintRefused], or answers 401, as for an App id or key it does
	// not take. Asking again does not change it.
	ErrActionsRefused = errors.New("GitHub refuses the request")
	// ErrActionsTransient is wrapped in the error of a request that may pass when it is
	// sent again: GitHub's API could not be reached, the request was given up, GitHub
	// answered 5xx, 401, 408 or 429, or a 403 for a rate limit after the [Pacer]'s tries,
	// or an answer it cannot read, but a dispatch's 200, which wraps [ErrActionsNoRun]. A
	// 401 drops the token it answers, so the next request mints a new one.
	ErrActionsTransient = errors.New("the request failed, and may pass when it is sent again")
	// ErrActionsNoRun is wrapped in the error of a dispatch GitHub took without naming
	// the workflow run it made: it answered 204, with no run's details, or 200 without a
	// run's id above 0, as an answer that does not decode, is larger than 1 MiB or cannot
	// be read. The workflow may be running all the same, so a dispatch sent again may
	// start a second run.
	ErrActionsNoRun = errors.New("GitHub took the dispatch and named no workflow run")
)

// invalidActions is a request refused before anything is sent, with the rule it fails;
// it matches [ErrActionsInvalid].
type invalidActions string

// Error is the rule the request fails.
func (e invalidActions) Error() string { return string(e) }

// Is matches [ErrActionsInvalid].
func (e invalidActions) Is(target error) bool { return target == ErrActionsInvalid }

// Actions starts, watches and cancels GitHub Actions workflow runs through a GitHub App
// that may write actions, in a repository it reaches by its id. Each request goes with an
// installation token [Client.MintInstallationToken] mints for that one repository, by
// its id, with actions: write, or actions: read for [Actions.ReadWorkflowRun]. A token is
// kept in memory until five minutes before it expires, or until GitHub answers 401 to a
// request made with it. Every request reaches the repository through its id,
// /repositories/{id}, follows no redirect, and reads at most 1 MiB of GitHub's answer.
//
// An Actions is used through a pointer and is safe for concurrent use. Printed, it says
// its App and how many tokens it keeps, never a token or the App's key.
type Actions struct {
	// Client reaches GitHub's API.
	Client Client
	// AppID and Key are the App's id and private key, which mint installation tokens.
	AppID string
	Key   *rsa.PrivateKey
	// Pacer is the installation's, shared with every other caller for it; nil is a new
	// one for each request.
	Pacer *Pacer

	mu     sync.Mutex
	tokens map[actionsTokenKey]InstallationToken
}

// actionsTokenKey is what a kept token is for: an installation, a repository's id, and
// the level of actions it grants.
type actionsTokenKey struct {
	installation, repository int64
	level                    string
}

// DispatchedRun is the workflow run GitHub made for a dispatch.
type DispatchedRun struct {
	// ID is the run's id, above 0, which [Actions.ReadWorkflowRun] and
	// [Actions.CancelWorkflowRun] take: [Actions.DispatchWorkflow] never returns ID 0
	// with a nil error.
	ID int64
	// URL is the run in GitHub's API, its run_url.
	URL string
	// HTMLURL is the run's page on GitHub, its html_url.
	HTMLURL string
}

// WorkflowRun is a workflow run as GitHub reads it.
type WorkflowRun struct {
	// ID is the run's id.
	ID int64
	// Status is GitHub's, such as queued, in_progress or completed; "" when GitHub
	// answers null.
	Status string
	// Conclusion is GitHub's, such as success, failure or cancelled; "" when GitHub
	// answers null, as it does until the run completes.
	Conclusion string
	// RunAttempt is which attempt of the run this is, 1 for the first; 0 when GitHub
	// leaves it out.
	RunAttempt int64
	// HTMLURL is the run's page on GitHub.
	HTMLURL string
	// HeadSHA is the commit the run is at.
	HeadSHA string
	// Path is the workflow's path in the repository, such as
	// .github/workflows/runner.yml.
	Path string
}

// DispatchWorkflow starts the workflow whose file name is workflow, in the repository
// whose id is repository, of the installation installation, on the branch or tag ref,
// with one input, dispatch_id, POST
// /repositories/{id}/actions/workflows/{workflow}/dispatches. A short ref is a branch,
// and a tag is given as refs/tags/NAME; the ref is sent as [FullRef] writes it, so a
// short name goes as refs/heads/NAME. The workflow's file name, see
// [CheckWorkflowFile], the ref, see [CheckRef], and the dispatch_id, which must fit the
// provisioner contract's pattern, are checked before anything is sent, and a request
// that fails wraps [ErrActionsInvalid].
//
// The body asks for the run's details, return_run_details, and GitHub answers 200 with
// the run's id, its API URL and its page, which it returns, the id above 0. A caller
// never receives a run whose ID is 0 with a nil error: GitHub answers 204 with no body
// for a dispatch that does not ask for the run's details, and should it answer 204 all
// the same, or 200 without a run's id above 0, as an answer that does not decode, is
// larger than 1 MiB or cannot be read, the error wraps [ErrActionsNoRun]. Any
// other answer fails, see [ErrActionsGone], [ErrActionsRefused] and
// [ErrActionsTransient]. No error contains the token.
func (a *Actions) DispatchWorkflow(ctx context.Context, installation, repository int64, workflow, ref, dispatchID string) (DispatchedRun, error) {
	if repository <= 0 {
		return DispatchedRun{}, invalidActions("the repository's id is not one")
	}
	if err := CheckWorkflowFile(workflow); err != nil {
		return DispatchedRun{}, invalidActions("the workflow " + err.Error())
	}
	if err := CheckRef(ref); err != nil {
		return DispatchedRun{}, invalidActions("the ref " + err.Error())
	}
	if !dispatchIDShape().MatchString(dispatchID) {
		return DispatchedRun{}, invalidActions("the dispatch_id is not dp_ and 16 lower-case Crockford base32 characters, as the provisioner contract writes one")
	}
	body := struct {
		Ref    string `json:"ref"`
		Inputs struct {
			DispatchID string `json:"dispatch_id"`
		} `json:"inputs"`
		ReturnRunDetails bool `json:"return_run_details"`
	}{Ref: FullRef(ref), ReturnRunDetails: true}
	body.Inputs.DispatchID = dispatchID
	what := "dispatching the workflow " + workflow
	path := repositoryPath(repository) + "/actions/workflows/" + workflow + "/dispatches"
	reply, err := a.request(ctx, what, http.MethodPost, path, installation, repository, "write", body)
	var unread *unreadAnswer
	if errors.As(err, &unread) && unread.status == http.StatusOK {
		return DispatchedRun{}, fmt.Errorf("%w: %w", ErrActionsNoRun, unread)
	}
	if err != nil {
		return DispatchedRun{}, err
	}
	switch reply.status {
	case http.StatusNoContent:
		return DispatchedRun{}, fmt.Errorf("%w: %s: GitHub answered 204, with no run's details", ErrActionsNoRun, what)
	case http.StatusOK:
	default:
		return DispatchedRun{}, actionsFailed(reply, what)
	}
	var got struct {
		WorkflowRunID int64  `json:"workflow_run_id"`
		RunURL        string `json:"run_url"`
		HTMLURL       string `json:"html_url"`
	}
	if err := json.Unmarshal(reply.body, &got); err != nil {
		return DispatchedRun{}, fmt.Errorf("%w: %s: GitHub's answer: %w", ErrActionsNoRun, what, err)
	}
	if got.WorkflowRunID <= 0 {
		return DispatchedRun{}, fmt.Errorf("%w: %s: GitHub answered 200 without a run's id above 0", ErrActionsNoRun, what)
	}
	return DispatchedRun{ID: got.WorkflowRunID, URL: got.RunURL, HTMLURL: got.HTMLURL}, nil
}

// ReadWorkflowRun reads the workflow run run in the repository whose id is repository,
// of the installation installation, GET /repositories/{id}/actions/runs/{run}, with a
// token that reads actions alone. A run GitHub answers is deleted or out of the App's
// reach, or whose request it redirects, wraps [ErrActionsGone]; see [ErrActionsRefused]
// and [ErrActionsTransient] for the rest. No error contains the token.
func (a *Actions) ReadWorkflowRun(ctx context.Context, installation, repository, run int64) (WorkflowRun, error) {
	if repository <= 0 || run <= 0 {
		return WorkflowRun{}, invalidActions("the repository's id or the run's id is not one")
	}
	what := "reading the workflow run " + strconv.FormatInt(run, 10)
	path := repositoryPath(repository) + "/actions/runs/" + strconv.FormatInt(run, 10)
	reply, err := a.request(ctx, what, http.MethodGet, path, installation, repository, "read", nil)
	if err != nil {
		return WorkflowRun{}, err
	}
	if reply.status != http.StatusOK {
		return WorkflowRun{}, actionsFailed(reply, what)
	}
	var got struct {
		Status     *string `json:"status"`
		Conclusion *string `json:"conclusion"`
		RunAttempt int64   `json:"run_attempt"`
		HTMLURL    string  `json:"html_url"`
		HeadSHA    string  `json:"head_sha"`
		Path       string  `json:"path"`
	}
	if err := json.Unmarshal(reply.body, &got); err != nil {
		return WorkflowRun{}, fmt.Errorf("%w: %s: GitHub's answer: %w", ErrActionsTransient, what, err)
	}
	r := WorkflowRun{ID: run, RunAttempt: got.RunAttempt, HTMLURL: got.HTMLURL, HeadSHA: got.HeadSHA, Path: got.Path}
	if got.Status != nil {
		r.Status = *got.Status
	}
	if got.Conclusion != nil {
		r.Conclusion = *got.Conclusion
	}
	return r, nil
}

// CancelWorkflowRun cancels the workflow run run in the repository whose id is
// repository, of the installation installation, POST
// /repositories/{id}/actions/runs/{run}/cancel. GitHub answers 202 when it takes the
// cancel, and 409 for a run it cannot cancel, as one that has completed: both return
// nil, so a cancel sent again is done, and a caller reads the run to learn how it ended.
// Any other answer fails, see [ErrActionsGone], [ErrActionsRefused] and
// [ErrActionsTransient]. No error contains the token.
func (a *Actions) CancelWorkflowRun(ctx context.Context, installation, repository, run int64) error {
	if repository <= 0 || run <= 0 {
		return invalidActions("the repository's id or the run's id is not one")
	}
	what := "cancelling the workflow run " + strconv.FormatInt(run, 10)
	path := repositoryPath(repository) + "/actions/runs/" + strconv.FormatInt(run, 10) + "/cancel"
	reply, err := a.request(ctx, what, http.MethodPost, path, installation, repository, "write", nil)
	if err != nil {
		return err
	}
	switch reply.status {
	case http.StatusAccepted, http.StatusConflict:
		return nil
	}
	return actionsFailed(reply, what)
}

// repositoryPath is the repository's path in GitHub's API by its id.
func repositoryPath(repository int64) string {
	return "/repositories/" + strconv.FormatInt(repository, 10)
}

// request sends one request with a token for the repository that grants actions at
// level, and returns GitHub's answer whatever its status. An error is the token's or the
// request's, classed; a 401 drops the token.
func (a *Actions) request(ctx context.Context, what, method, path string, installation, repository int64, level string, body any) (*apiReply, error) {
	if installation <= 0 {
		return nil, invalidActions("the installation's id is not one")
	}
	if !appIDShape.MatchString(a.AppID) {
		return nil, invalidActions("the App id is not an id, 1 to 64 letters, digits or dots")
	}
	if a.Key == nil {
		return nil, invalidActions("no private key")
	}
	if err := CheckAPIURL(a.Client.base()); err != nil {
		return nil, invalidActions(err.Error())
	}
	key := actionsTokenKey{installation: installation, repository: repository, level: level}
	tok, err := a.token(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("%s: the installation token: %w", what, mintFailed(err))
	}
	reply, err := a.Client.sendBounded(ctx, a.Pacer, false, what, method, path, tok, body, maxActionsAnswer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrActionsTransient, err)
	}
	if reply.status == http.StatusUnauthorized {
		a.forget(key)
	}
	return reply, nil
}

// token is a kept token for key while it has more than [actionsTokenMargin] left, or a
// new one, which it keeps.
func (a *Actions) token(ctx context.Context, key actionsTokenKey) (string, error) {
	now := time.Now
	if a.Client.Now != nil {
		now = a.Client.Now
	}
	a.mu.Lock()
	t, ok := a.tokens[key]
	a.mu.Unlock()
	if ok && t.ExpiresAt.Sub(now()) > actionsTokenMargin {
		return t.Token, nil
	}
	t, err := a.Client.MintInstallationToken(ctx, Request{AppID: a.AppID, Key: a.Key, InstallationID: key.installation, RepositoryIDs: []int64{key.repository}, Permissions: map[string]string{"actions": key.level}})
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokens == nil {
		a.tokens = map[actionsTokenKey]InstallationToken{}
	}
	a.tokens[key] = t
	return t.Token, nil
}

// forget drops the token kept for key.
func (a *Actions) forget(key actionsTokenKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokens, key)
}

// mintFailed is a mint's error, classed: a redirect is [ErrActionsGone]; a mint GitHub
// refuses for good, [ErrMintRefused], or answers 401 is [ErrActionsRefused]; anything
// else is [ErrActionsTransient].
func mintFailed(err error) error {
	var answered *answerError
	switch {
	case errors.Is(err, errMintRedirected) || errors.Is(err, errCheckRedirected):
		return fmt.Errorf("%w: %w", ErrActionsGone, err)
	case errors.Is(err, ErrMintRefused) || errors.As(err, &answered) && answered.status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", ErrActionsRefused, err)
	}
	return fmt.Errorf("%w: %w", ErrActionsTransient, err)
}

// actionsFailed is the error for an answer whose status is not one the request takes,
// classed: a redirect, a 404 or a 410 is [ErrActionsGone]; a 403 that is no rate limit,
// and any other 4xx but 401, 408 and 429, is [ErrActionsRefused]; anything else is
// [ErrActionsTransient].
func actionsFailed(a *apiReply, what string) error {
	err := a.err(what)
	switch {
	case a.status >= 300 && a.status < 400, a.status == http.StatusNotFound, a.status == http.StatusGone:
		return fmt.Errorf("%w: %w", ErrActionsGone, err)
	case a.status == http.StatusForbidden && !a.rateLimited():
		return fmt.Errorf("%w: %w", ErrActionsRefused, err)
	case a.status >= 400 && a.status < 500 && a.status != http.StatusForbidden && a.status != http.StatusUnauthorized && a.status != http.StatusRequestTimeout && a.status != http.StatusTooManyRequests:
		return fmt.Errorf("%w: %w", ErrActionsRefused, err)
	}
	return fmt.Errorf("%w: %w", ErrActionsTransient, err)
}

// String says the App and how many tokens are kept, never a token or the App's key, so
// an Actions printed by mistake gives none away.
func (a *Actions) String() string {
	a.mu.Lock()
	n := len(a.tokens)
	a.mu.Unlock()
	return fmt.Sprintf("github.Actions{AppID: %q, tokens: %d kept}", a.AppID, n)
}

// GoString is String, for %#v.
func (a *Actions) GoString() string { return a.String() }

// Format writes String for every verb, %+v and %#v among them, which would otherwise
// print the fields, the tokens and the App's key among them.
func (a *Actions) Format(f fmt.State, _ rune) { io.WriteString(f, a.String()) }
