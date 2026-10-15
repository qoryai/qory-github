package serve

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// tokenMargin is how long before its expiry an installation token is minted again.
const tokenMargin = 5 * time.Minute

// Adapter is what serve does with GitHub's deliveries and Qory Apiary's change feed: it
// sends an installation's repositories, issues and comments to Qory Apiary, and writes
// on GitHub what the feed says. It serves only an installation the store holds as
// linked, see [Link], and sends only the items of a collection Qory Apiary linked.
type Adapter struct {
	// Store keeps the links, the repositories' installations and the feed's cursor.
	Store *store.Store
	// GitHub reaches GitHub's API.
	GitHub github.Client
	// AppID and Key are the App's id and private key, which mint installation tokens.
	AppID string
	Key   *rsa.PrivateKey
	// Slug is the App's slug, whose bot writes the work item comment.
	Slug string
	// Sink is Qory Apiary's client.
	Sink github.Sink
	// Log takes what is skipped or failed; nil logs nothing.
	Log *slog.Logger

	mu     sync.Mutex
	pacers map[int64]*github.Pacer
	tokens map[string]github.InstallationToken

	// cutsOnce makes cuts, which logs the texts cut to the contract's limit as the
	// receiver logs its refusals, once each refusalEvery at most.
	cutsOnce sync.Once
	cuts     *throttle
}

func (a *Adapter) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

// Register registers the adapter's handlers: installation, installation_repositories,
// issues and issue_comment. workflow_run has none yet, so its deliveries are done.
func (a *Adapter) Register(hs *Handlers) {
	hs.HandleFunc("installation", a.linked(a.installation))
	hs.HandleFunc("installation_repositories", a.linked(a.installationRepositories))
	hs.HandleFunc("issues", a.linked(a.issues))
	hs.HandleFunc("issue_comment", a.linked(a.issueComment))
}

// linked is h for the deliveries of a linked installation; another's is done and
// logged.
func (a *Adapter) linked(h func(ctx context.Context, d Delivery) error) func(context.Context, Delivery) error {
	return func(ctx context.Context, d Delivery) error {
		ok, err := Linked(a.Store, d.InstallationID)
		if err != nil {
			return err
		}
		if !ok {
			a.log().Info("the installation is not linked to Qory Apiary, so the delivery is not handled", deliveryArgs(d)...)
			return nil
		}
		return h(ctx, d)
	}
}

// deliveryArgs are a delivery's attributes for a line: its event, action and GUID.
func deliveryArgs(d Delivery) []any {
	var args []any
	for _, a := range deliveryAttrs(d.Event, d.Action, d.GUID, "") {
		if a.Key != "outcome" {
			args = append(args, a)
		}
	}
	return args
}

// pacer is the installation's Pacer, one for everything that reaches GitHub for it.
func (a *Adapter) pacer(installation int64) *github.Pacer {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pacers == nil {
		a.pacers = map[int64]*github.Pacer{}
	}
	p, ok := a.pacers[installation]
	if !ok {
		p = &github.Pacer{}
		a.pacers[installation] = p
	}
	return p
}

// token is an installation token for installation, limited to repo, or, when repo is
// empty, the listing token that reads which repositories it reaches; permission is the
// one it grants on issues. A token is kept until shortly before it expires.
func (a *Adapter) token(ctx context.Context, installation int64, repo github.Repository, permission string) (string, error) {
	key := strconv.FormatInt(installation, 10) + " " + strings.ToLower(repo.String()) + " " + permission
	a.mu.Lock()
	t, ok := a.tokens[key]
	a.mu.Unlock()
	if ok && time.Until(t.ExpiresAt) > tokenMargin {
		return t.Token, nil
	}
	var err error
	if repo == (github.Repository{}) {
		t, err = a.GitHub.MintListingToken(ctx, a.AppID, a.Key, installation)
	} else {
		t, err = a.GitHub.MintInstallationToken(ctx, github.Request{AppID: a.AppID, Key: a.Key, InstallationID: installation, Repositories: []github.Repository{repo}, Permissions: map[string]string{"issues": permission}})
	}
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokens == nil {
		a.tokens = map[string]github.InstallationToken{}
	}
	a.tokens[key] = t
	return t.Token, nil
}

// forgetOn401 drops the installation's tokens when err is GitHub's 401, which a token
// GitHub no longer takes brings, so the next request mints a new one; it returns err.
func (a *Adapter) forgetOn401(installation int64, err error) error {
	if !github.Unauthorized(err) {
		return err
	}
	prefix := strconv.FormatInt(installation, 10) + " "
	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.tokens {
		if strings.HasPrefix(key, prefix) {
			delete(a.tokens, key)
		}
	}
	return err
}

// String says the adapter's App and how many tokens it keeps, never a token or the
// App's key, so an adapter printed by mistake gives none away.
func (a *Adapter) String() string {
	a.mu.Lock()
	n := len(a.tokens)
	a.mu.Unlock()
	return fmt.Sprintf("serve.Adapter{AppID: %q, Slug: %q, tokens: %d kept}", a.AppID, a.Slug, n)
}

// GoString is String, for %#v.
func (a *Adapter) GoString() string { return a.String() }

// Format writes String for every verb, %+v and %#v among them, which would otherwise
// print the fields, the tokens and the App's key among them.
func (a *Adapter) Format(f fmt.State, _ rune) { io.WriteString(f, a.String()) }

// logf logs a line a listing writes: what it skipped, by ref, never by text.
func (a *Adapter) logf(format string, args ...any) {
	a.log().Info(fmt.Sprintf(format, args...))
}

func (a *Adapter) cutLog() *throttle {
	a.cutsOnce.Do(func() {
		a.cuts = &throttle{every: refusalEvery, flush: func(dropped int) {
			a.log().LogAttrs(context.Background(), slog.LevelWarn, "cuts dropped", slog.Int("cuts_dropped", dropped))
		}}
	})
	return a.cuts
}

// logCut logs a text GitHub sent past the contract's limit, cut to it: the ref, the
// field and its length before the cut, never the text. It is not expected, since
// GitHub's limits fit inside the contract's, and the lines are throttled as the
// receiver's refusals are, a burst's count logged on the next line or after it.
func (a *Adapter) logCut(c github.Cut) {
	ok, dropped := a.cutLog().allow()
	if !ok {
		return
	}
	attrs := []slog.Attr{slog.String("ref", c.Ref), slog.String("field", c.Field), slog.Int("length", c.Length)}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("cuts_dropped", dropped))
	}
	a.log().LogAttrs(context.Background(), slog.LevelWarn, "cut to the contract's limit", attrs...)
}

// stopLog logs the count of cuts held back, if any, as [throttle.stop] does.
func (a *Adapter) stopLog() {
	a.cutLog().stop()
}

// reachSink is the adapter's sink for a listing of an installation's repositories: it
// keeps which installation reaches each repository it lists before it sends them.
type reachSink struct {
	github.Sink
	st           *store.Store
	installation int64
}

// Collections keeps each collection's installation and sends them.
func (s reachSink) Collections(ctx context.Context, req contracts.SourceCollections) error {
	for _, c := range req.Collections {
		if err := setReach(s.st, c.Ref, s.installation); err != nil {
			return err
		}
	}
	return s.Sink.Collections(ctx, req)
}

// listRepositories sends Qory Apiary the repositories the installation reaches.
func (a *Adapter) listRepositories(ctx context.Context, installation int64) error {
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, github.Repository{}, "") },
		Slug:   a.Slug,
		Sink:   reachSink{Sink: a.Sink, st: a.Store, installation: installation},
		Logf:   a.logf,
		LogCut: a.logCut,
	}
	return a.forgetOn401(installation, l.ListRepositories(ctx))
}

// installation handles the installation event: deleted disconnects each repository
// of the installation the store knows, ended, then forgets them and unlinks it;
// suspend disconnects each, paused; unsuspend lists the repositories again.
func (a *Adapter) installation(ctx context.Context, d Delivery) error {
	switch d.Action {
	case "deleted":
		refs, err := reachedBy(a.Store, d.InstallationID)
		if err != nil {
			return err
		}
		if err := a.disconnect(ctx, refs, github.ReasonEnded); err != nil {
			return err
		}
		for _, ref := range refs {
			if err := a.Store.Delete(nsRepositories, collectionKey(ref)); err != nil {
				return err
			}
		}
		return Unlink(a.Store, d.InstallationID)
	case "suspend":
		refs, err := reachedBy(a.Store, d.InstallationID)
		if err != nil {
			return err
		}
		return a.disconnect(ctx, refs, github.ReasonPaused)
	case "unsuspend":
		return a.listRepositories(ctx, d.InstallationID)
	}
	return nil
}

// installationRepositories handles the installation_repositories event: each
// repository removed is disconnected, removed, and forgotten, and the installation's
// repositories are listed again, which a listing of more than one page needs, since it
// never says it is complete.
func (a *Adapter) installationRepositories(ctx context.Context, d Delivery) error {
	if d.Action != "added" && d.Action != "removed" {
		return nil
	}
	var ev struct {
		Removed []struct {
			FullName string `json:"full_name"`
		} `json:"repositories_removed"`
	}
	if err := json.Unmarshal(d.Body, &ev); err != nil {
		return Permanent(errors.New("the installation_repositories event is not JSON GitHub sends"))
	}
	var refs []string
	for _, r := range ev.Removed {
		if r.FullName != "" {
			refs = append(refs, r.FullName)
		}
	}
	if err := a.disconnect(ctx, refs, github.ReasonRemoved); err != nil {
		return err
	}
	for _, ref := range refs {
		if err := a.Store.Delete(nsRepositories, collectionKey(ref)); err != nil {
			return err
		}
	}
	return a.listRepositories(ctx, d.InstallationID)
}

// disconnect sends a disconnect for each collection, for reason. One Qory Apiary refuses
// for good is logged and passed; any other error stops it, to be tried again.
func (a *Adapter) disconnect(ctx context.Context, refs []string, reason string) error {
	for _, ref := range refs {
		err := a.Sink.Disconnect(ctx, contracts.SourcesDisconnect{Version: contracts.Version, CollectionRef: ref, Reason: reason})
		if IsPermanent(err) {
			a.log().Error("the disconnect is refused", slog.String("collection", ref), slog.String("error", err.Error()))
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// issues handles the issues event: the issue, as [github.IssuesWebhook] makes it, goes
// to Qory Apiary when its collection is linked.
func (a *Adapter) issues(ctx context.Context, d Delivery) error {
	active := func(r github.Repository) bool {
		ok, _ := collectionLinked(a.Store, r.String())
		return ok
	}
	t, err := github.IssuesWebhook(d.Body, a.GitHub.WebHost(), active)
	if err != nil {
		return Permanent(err)
	}
	return a.send(ctx, t)
}

// issueComment handles the issue_comment event, as [github.IssueCommentWebhook] makes
// it, as [Adapter.issues] does.
func (a *Adapter) issueComment(ctx context.Context, d Delivery) error {
	t, err := github.IssueCommentWebhook(d.Body, a.Slug)
	if err != nil {
		return Permanent(err)
	}
	return a.send(ctx, t)
}

// send sends what an event became, the items of a linked collection and the comments
// on its items, and logs what is skipped. A request Qory Apiary refuses for good is
// logged and passed; any other error stops it, to be tried again, which sends again
// what went before, which Qory Apiary takes as the same.
func (a *Adapter) send(ctx context.Context, t github.ToSend) error {
	for _, s := range t.Skipped {
		a.log().Info("skipped", slog.String("ref", s.Ref), slog.String("why", s.Why))
	}
	for _, c := range t.Cut {
		a.logCut(c)
	}
	for _, req := range t.Items {
		if err := a.sendLinked(ctx, req.CollectionRef, "items", func() error { return a.Sink.Items(ctx, req) }); err != nil {
			return err
		}
	}
	for _, req := range t.Comments {
		collection, _, _ := strings.Cut(req.ItemRef, "#")
		if err := a.sendLinked(ctx, collection, "comments", func() error { return a.Sink.Comments(ctx, req) }); err != nil {
			return err
		}
	}
	return nil
}

// sendLinked calls send, which sends the collection's items or comments, as what says,
// when the collection is linked.
func (a *Adapter) sendLinked(ctx context.Context, collection, what string, send func() error) error {
	ok, err := collectionLinked(a.Store, collection)
	if err != nil {
		return err
	}
	if !ok {
		a.log().Info("the collection is not linked, so its "+what+" are not sent", slog.String("collection", collection))
		return nil
	}
	err = send()
	if IsPermanent(err) {
		a.log().Error("the request is refused", slog.String("collection", collection), slog.String("error", err.Error()))
		return nil
	}
	return err
}

// errNoInstallation is a repository whose installation the store does not know: no
// listing of an installation's repositories named it.
var errNoInstallation = errors.New("no installation is known to reach the repository")

// fill sends Qory Apiary the open issues of a collection it linked, and their comments.
// A repository GitHub answers is gone or moved, [github.ErrRepositoryGone], or for which
// GitHub refuses to mint a token for good, [github.ErrMintRefused], fails for good, so
// the change feed passes it.
func (a *Adapter) fill(ctx context.Context, ref string) error {
	repo, err := repository(ref)
	if err != nil {
		return Permanent(err)
	}
	installation, ok, err := reachOf(a.Store, ref)
	if err != nil {
		return err
	}
	if !ok {
		return Permanent(fmt.Errorf("filling %s: %w", ref, errNoInstallation))
	}
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, repo, "read") },
		Slug:   a.Slug,
		Sink:   a.Sink,
		Logf:   a.logf,
		LogCut: a.logCut,
	}
	err = a.forgetOn401(installation, l.ListIssues(ctx, repo))
	if errors.Is(err, github.ErrRepositoryGone) || errors.Is(err, github.ErrMintRefused) {
		return Permanent(err)
	}
	return err
}

// applyChange writes on GitHub what a work_item entry of the feed says, with a token
// that writes the issues of that one repository, from the installation that reaches it.
// A token GitHub refuses to mint for good, [github.ErrMintRefused], fails it for good.
func (a *Adapter) applyChange(ctx context.Context, ch contracts.Change) error {
	collection, _, _ := strings.Cut(ch.Ref, "#")
	installation, ok, err := reachOf(a.Store, collection)
	if err != nil {
		return err
	}
	if !ok {
		return Permanent(fmt.Errorf("applying a change: %w", errNoInstallation))
	}
	token := func(ctx context.Context, repo github.Repository) (string, error) {
		return a.token(ctx, installation, repo, "write")
	}
	err = a.forgetOn401(installation, a.GitHub.ApplyChange(ctx, a.pacer(installation), token, a.Slug, github.Change{WorkItemID: ch.WorkItemID, Ref: ch.Ref, Status: ch.Status, URL: ch.URL}))
	if errors.Is(err, github.ErrMintRefused) {
		return Permanent(err)
	}
	return err
}

// repository is a collection's ref as a repository, owner/name.
func repository(ref string) (github.Repository, error) {
	repos, err := github.ParseRepositories(ref)
	if err != nil || len(repos) != 1 {
		return github.Repository{}, errors.New("the collection's ref is not owner/name")
	}
	return repos[0], nil
}
