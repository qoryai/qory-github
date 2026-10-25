package serve

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
// linked to a connection, see [Link], and sends only the items of a collection Qory
// Apiary linked.
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
	// gens are the installations' token generations, see [Adapter.generation], which
	// [Adapter.forgetTokens] moves on and [Adapter.forgetInstallation] forgets: a token
	// minted across either is used and not kept. genSeq is the last generation given,
	// of gens or of firstGens.
	gens   map[int64]uint64
	genSeq uint64
	// turns are the collections' turns, see [Adapter.collectionTurn], by key. now is
	// the clock a fill's start is read from; nil is time.Now.
	turns map[string]chan struct{}
	now   func() time.Time
	// installs are the installations' locks, see [Adapter.lockInstallation], by id,
	// each while one holds it or waits for it. lockWaits, when set, is called each time
	// a lock is held by another and its taker waits.
	installs  map[int64]*installLock
	lockWaits func(installation int64)
	// firsts are the links' first listings kept, see [Adapter.sendFirst], in memory
	// alone, by installation and connection. firstGens are the installations'
	// generations of them, see [Adapter.generation], which [Adapter.dropFirsts] and
	// [Adapter.dropFirstsNaming] move on and [Adapter.forgetInstallation] forgets: a
	// listing read across any of them is sent and not kept.
	firsts    map[firstKey]*firstListing
	firstGens map[int64]uint64

	// presence is what the pull rounds count toward an installation's end and a
	// collection's disconnect, and the signs that start a count over, see [presence].
	presence presence

	// heldBack are the installations a listing of which left collections out because
	// Qory Apiary's copy of the grants did not have the installation's grant, see
	// [reachSink], until a report of the grant is taken, see [Connect.reportSoon]. It
	// is read and written under installMu.
	heldBack map[int64]bool

	// ends are the grant ends sent again, by installation, see [Adapter.endSoon], under
	// endMu, with endsStopped, after which none starts. endCtx stops them all, by
	// endStop, and endWG waits for them. endSleep, when set, waits between their tries;
	// nil waits on a timer.
	endMu       sync.Mutex
	ends        map[int64]*grantEnding
	endsStopped bool
	endCtx      context.Context
	endStop     context.CancelFunc
	endWG       sync.WaitGroup
	endSleep    func(ctx context.Context, d time.Duration) error
	// endRefused are the grant ends for which Qory Apiary returned an error that a
	// retry does not change, by installation, under endMu, see [Adapter.endRefusedFor].
	endRefused map[int64]refusedEnd
	// grantRead, when set, is called once [Adapter.dropUngranted] has read the copy.
	grantRead func()

	// cutsOnce makes cuts, which logs the texts cut to the contract's limit as the
	// receiver logs its refusals, once each refusalEvery at most; envsOnce makes envs,
	// which logs a push's failed reads of an environment definition the same way.
	cutsOnce sync.Once
	cuts     *throttle
	envsOnce sync.Once
	envs     *throttle
}

func (a *Adapter) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

// Register registers the adapter's handlers: installation, installation_repositories,
// issues, issue_comment, repository and push. workflow_run and pull_request have none,
// so their deliveries are not kept, see [Receiver.Handlers]. Each delivery that
// names a repository, whatever its event, is a sign for the pull rounds, see
// [Adapter.delivered].
func (a *Adapter) Register(hs *Handlers) {
	hs.HandleFunc("installation", a.linked(a.installation))
	hs.HandleFunc("installation_repositories", a.linked(a.installationRepositories))
	hs.HandleFunc("issues", a.linked(a.issues))
	hs.HandleFunc("issue_comment", a.linked(a.issueComment))
	hs.HandleFunc("repository", a.linked(a.repository))
	hs.HandleFunc("push", a.linked(a.push))
	hs.handleSeen(a.delivered)
}

// delivered notes a delivery of GitHub's webhook, of event and action, whose signature
// the receiver checked and which names the repository whose id is repository, as a sign
// for the pull rounds that GitHub holds the repository, see [presence]: GitHub sends a
// delivery about a repository it holds. The repository event's deleted and transferred,
// after which the installation that had the repository no longer holds it, and
// installation_repositories' removed are no sign; installation_repositories' added is
// one for each repository it adds, see [Adapter.installationRepositories].
func (a *Adapter) delivered(event, action string, repository int64) {
	switch {
	case event == "repository" && (action == "deleted" || action == "transferred"):
	case event == "installation_repositories" && action == "removed":
	default:
		a.presence.repositorySeen(github.CollectionRef(repository))
	}
}

// linked is h for the deliveries of a linked installation that Qory Apiary's copy of the
// grants holds, see [granted]; another's is done and logged. The installation event's deleted is [Adapter.deleted]'s, and the repository
// event's transferred is [Adapter.transferred]'s, for any installation whose id is
// above 0; one that names an id of 0 or below, or none, is done and logged as an
// installation not linked, before any state changes or any request is sent.
func (a *Adapter) linked(h func(ctx context.Context, d Delivery) error) func(context.Context, Delivery) error {
	return func(ctx context.Context, d Delivery) error {
		if d.Event == "installation" && d.Action == "deleted" && d.InstallationID > 0 {
			return a.deleted(ctx, d)
		}
		if d.Event == "repository" && d.Action == "transferred" && d.InstallationID > 0 {
			return a.transferred(ctx, d)
		}
		ok, err := granted(a.Store, d.InstallationID, a.clock())
		if err != nil {
			return err
		}
		if !ok && d.Event == "installation" && d.Action == "created" && d.InstallationID > 0 {
			// GitHub sends created for an installation Connect makes too, before its link,
			// so the line says what serve knows: the installation is not linked yet.
			a.log().Info("the installation is not linked to Qory Apiary, so nothing of it is listed until a person connects it", slog.Int64("installation", d.InstallationID))
			return keepUnlinked(a.Store, d.InstallationID)
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

// pacer is the installation's Pacer, one for everything that reaches GitHub for it
// until GitHub deletes the installation, see [Adapter.forgetInstallation].
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

// token is an installation token for installation, limited to the repository whose id
// is repository, which GitHub's mint takes as repository_ids, or, when repository is 0,
// the listing token that reads which repositories it reaches and their contents, see
// [github.Client.MintListingToken]; permission is the one it grants on issues. A token
// is kept until shortly before it expires, unless the installation's tokens were
// dropped while it was minted. Each mint is a sign for the
// pull rounds, see [presence]: GitHub's 200 to the installation's check, which the mint
// asks first, says GitHub holds the installation, and a token minted for the repository
// alone says it holds the repository.
func (a *Adapter) token(ctx context.Context, installation, repository int64, permission string) (string, error) {
	key := strconv.FormatInt(installation, 10) + " " + strconv.FormatInt(repository, 10) + " " + permission
	a.mu.Lock()
	t, ok := a.tokens[key]
	gen := a.generation(&a.gens, installation)
	a.mu.Unlock()
	if ok && time.Until(t.ExpiresAt) > tokenMargin {
		return t.Token, nil
	}
	var err error
	gh := a.GitHub
	gh.Checked = a.presence.installationSeen
	if repository == 0 {
		t, err = gh.MintListingToken(ctx, a.AppID, a.Key, installation)
	} else {
		t, err = gh.MintInstallationToken(ctx, github.Request{AppID: a.AppID, Key: a.Key, InstallationID: installation, RepositoryIDs: []int64{repository}, Permissions: map[string]string{"issues": permission}})
	}
	if err != nil {
		return "", err
	}
	if repository != 0 {
		a.presence.repositorySeen(github.CollectionRef(repository))
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

// forgetOn401 drops the installation's tokens when err is GitHub's 401, which a token
// GitHub no longer takes brings, so the next request mints a new one; it returns err.
func (a *Adapter) forgetOn401(installation int64, err error) error {
	if github.Unauthorized(err) {
		a.forgetTokens(installation)
	}
	return err
}

// forgetTokens drops the installation's tokens, so the next request mints a new one,
// and moves its generation on, see [Adapter.moveGeneration], so a mint in flight does
// not keep its token.
func (a *Adapter) forgetTokens(installation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forgetTokensLocked(installation)
}

// forgetListingToken drops the installation's listing token, see [Adapter.token], so the
// next listing mints a new one, whose mint checks the installation with GitHub first,
// and moves its generation on, see [Adapter.moveGeneration]. All the installation's
// tokens share that generation, so any token of the installation being minted across
// the drop, a listing token or a repository's, is used once and not kept. The
// installation's repository tokens kept before the drop stay.
func (a *Adapter) forgetListingToken(installation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.moveGeneration(&a.gens, installation)
	delete(a.tokens, strconv.FormatInt(installation, 10)+" 0 ")
}

// forgetTokensLocked is [Adapter.forgetTokens] for a caller that holds mu.
func (a *Adapter) forgetTokensLocked(installation int64) {
	prefix := strconv.FormatInt(installation, 10) + " "
	a.moveGeneration(&a.gens, installation)
	for key := range a.tokens {
		if strings.HasPrefix(key, prefix) {
			delete(a.tokens, key)
		}
	}
}

// generation is the installation's generation in gens, for a caller that holds mu: the
// one gens has, or else a new one, which it keeps in gens. Each generation given, a
// move's among them, is genSeq moved on, which never goes back, so none is given twice
// and none is 0: a read that keeps what it read only while the generation it began with
// stands keeps nothing read across a move, nor across [Adapter.forgetInstallation],
// after which gens has none for the installation, which reads as 0, or a newer one.
func (a *Adapter) generation(gens *map[int64]uint64, installation int64) uint64 {
	if g, ok := (*gens)[installation]; ok {
		return g
	}
	if *gens == nil {
		*gens = map[int64]uint64{}
	}
	a.genSeq++
	(*gens)[installation] = a.genSeq
	return a.genSeq
}

// moveGeneration moves the installation's generation in gens on, see
// [Adapter.generation], for a caller that holds mu, when gens has one, and makes none
// when it has none: every read takes its generation through [Adapter.generation] before
// it reads, which keeps one in gens, so an installation with none has no read in flight
// but one that began before [Adapter.forgetInstallation] forgot it, which finds 0 and
// keeps nothing, and an installation GitHub deleted is never made again by a move.
func (a *Adapter) moveGeneration(gens *map[int64]uint64, installation int64) {
	if _, ok := (*gens)[installation]; ok {
		a.genSeq++
		(*gens)[installation] = a.genSeq
	}
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

// issuesOff logs that the open issues of the collection ref are not listed, as GitHub
// answers that Issues are turned off for its repository, see
// [github.Lister.ReadRepository].
func (a *Adapter) issuesOff(ref string) {
	a.logf("skipped the open issues of %s: Issues are turned off for the repository on GitHub", ref)
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
// field and its length before the cut, never the text. The lines are throttled as the
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

// stopLog logs the count of cuts and of failed reads of a push's environment
// definition held back, if any, as [throttle.stop] does.
func (a *Adapter) stopLog() {
	a.cutLog().stop()
	a.envLog().stop()
}

func (a *Adapter) envLog() *throttle {
	a.envsOnce.Do(func() {
		a.envs = &throttle{every: refusalEvery, flush: func(dropped int) {
			a.log().LogAttrs(context.Background(), slog.LevelWarn, "log lines of failed environment definition reads not printed", slog.Int("reads_dropped", dropped))
		}}
	})
	return a.envs
}

// logLeftOut logs a listing of the installation's repositories that left out n
// collections whose environment definition it could not read: the count and the
// installation alone.
func (a *Adapter) logLeftOut(installation int64, n int) {
	a.log().Warn("left out collections whose environment definition (.devcontainer or .devcontainer.json) could not be read; the listing is not complete, and the next listing reads them again", slog.Int64("installation", installation), slog.Int("left_out", n))
}

// reachSink is the adapter's sink for a listing of an installation's repositories,
// which names the installation's connection: before it sends a part, it claims each
// repository the part lists for the installation, with the listing's started_at, see
// [claimReach], and once Qory Apiary takes a part, which it does once the connection is
// made, it keeps the environment_ref the part sent for each collection, see
// [keepEnvironment], and marks the installation's link live. The part is sent with
// every repository GitHub granted the installation in it, whether its claim took the
// record or not, while Qory Apiary's copy of the grants has the installation's grant
// for the connection. While it does not, as before Qory Apiary takes the grant's report,
// see [Connect.reportSoon], the part is sent with no collection, and the listing is not
// complete, see [reachSink.Collections].
type reachSink struct {
	github.Sink
	adapter      *Adapter
	st           *store.Store
	installation int64
	connection   string
	// seen, when set, notes each collection a part names as a sign for the pull rounds
	// that GitHub holds its repository, see [presence]: set for a part GitHub's listing
	// read now, never for one kept and sent again.
	seen *presence
	// held is whether a part of the listing was sent without its collections, which
	// every part of one listing shares: from then on no part of the listing says it is
	// complete.
	held *bool
}

// Collections sends one part of the listing. When Qory Apiary's copy of the grants does
// not have the installation's grant for the connection, it leaves every collection out
// of the part and notes the installation, see [Adapter.heldBack], so the report of the
// grant, once taken, lists it again. Once a part of the listing left collections out,
// no part of it says it is complete, so the listing disconnects none of the collections
// it left out. It claims each collection the part sends for the installation, with the
// listing's started_at, or the zero time when it does not parse, sends the part, and
// once Qory Apiary took it keeps each collection's environment_ref. When Qory Apiary
// returns 400 invalid_request for a part that has collections, as for a grant_ref its
// copy of the grants does not have, it reads that copy again, see [Adapter.readGrants],
// and when the copy does not have the installation's grant for the connection, it sends
// the part again, built anew, without its collections. When the copy has the grant, the
// refusal has another cause, and the part is not sent again.
func (s reachSink) Collections(ctx context.Context, req contracts.SourceCollections) error {
	read, err := time.Parse(contracts.TimeLayout, req.Listing.StartedAt)
	if err != nil {
		read = time.Time{}
	}
	if s.seen != nil {
		for _, c := range req.Collections {
			s.seen.repositorySeen(c.Ref)
		}
	}
	sent, err := s.send(ctx, req, read)
	if refusedAs(err, http.StatusBadRequest, codeInvalidRequest) && len(sent) > 0 && s.adapter != nil {
		if _, _, serr := s.adapter.readGrants(ctx); serr != nil {
			return errors.Join(err, serr)
		}
		held, gerr := grantOf(s.st, s.installation)
		if gerr != nil {
			return errors.Join(err, gerr)
		}
		if held != s.connection {
			sent, err = s.send(ctx, req, read)
		}
	}
	if err != nil {
		return err
	}
	for _, c := range sent {
		if err := keepEnvironment(s.st, c.Ref, c.EnvironmentRef); err != nil {
			return err
		}
	}
	return goLive(s.st, s.installation, s.connection)
}

// send sends the part req, without its collections while Qory Apiary's copy of the
// grants does not have the installation's grant for the connection, and not complete
// once a part of the listing left collections out, see [reachSink.Collections]. It
// claims each collection it sends first, and returns them.
func (s reachSink) send(ctx context.Context, req contracts.SourceCollections, read time.Time) ([]contracts.Collection, error) {
	installMu.Lock()
	held, err := grantOf(s.st, s.installation)
	if err == nil && held != s.connection && len(req.Collections) > 0 {
		req.Collections = []contracts.Collection{}
		if s.held != nil {
			*s.held = true
		}
		if s.adapter != nil {
			s.adapter.noteHeldBack(s.installation)
		}
	}
	installMu.Unlock()
	if err != nil {
		return nil, err
	}
	if s.held != nil && *s.held {
		req.Listing.Complete = false
	}
	for _, c := range req.Collections {
		if err := claimReach(s.st, c.Ref, s.installation, read); err != nil {
			return nil, err
		}
	}
	return req.Collections, s.Sink.Collections(ctx, req)
}

// noteHeldBack notes that a listing of the installation left its collections out, see
// [reachSink], for a caller that holds installMu.
func (a *Adapter) noteHeldBack(installation int64) {
	if a.heldBack == nil {
		a.heldBack = map[int64]bool{}
	}
	a.heldBack[installation] = true
}

// takeHeldBack is whether a listing of the installation left its collections out since
// the last call, see [reachSink], for a caller that holds installMu, and forgets it.
func (a *Adapter) takeHeldBack(installation int64) bool {
	held := a.heldBack[installation]
	delete(a.heldBack, installation)
	return held
}

// listRepositories sends Qory Apiary the repositories the installation reaches, as
// collections of the connection it is linked to; an installation not linked sends
// nothing.
func (a *Adapter) listRepositories(ctx context.Context, installation int64) error {
	l, ok, err := linkOf(a.Store, installation)
	if err != nil || !ok {
		return err
	}
	return a.listConnection(ctx, installation, l.Connection)
}

// lockInstallation takes the installation's lock, waiting while another holds it until
// ctx is done, and returns what gives it back, or ctx's error. A listing of the
// installation and the change of its link that the listing's answer makes, [goLive],
// hold it, and so does a connect from its first read of the link to its write, see
// [Connect.link], so no answer to a listing lands between a connect's read and its
// write, and so does a drop of a repository's records that a disconnect makes, see
// [Adapter.dropRemoved] and [Adapter.dropRepository], so no listing claims a
// repository between the drop's read of its record and its drop. It is held across
// requests to GitHub and Qory Apiary, one installation's alone. installMu and reachMu
// are taken under it, never it under them, and no holder of it waits for a
// collection's turn, which a pull holds as it takes it, see [Adapter.dropRefused]. The
// lock is forgotten once nobody holds it or waits for it, see [installLock], so an
// installation GitHub deleted keeps none.
func (a *Adapter) lockInstallation(ctx context.Context, installation int64) (func(), error) {
	a.mu.Lock()
	if a.installs == nil {
		a.installs = map[int64]*installLock{}
	}
	lock, ok := a.installs[installation]
	if !ok {
		lock = &installLock{ch: make(chan struct{}, 1)}
		a.installs[installation] = lock
	}
	lock.users++
	waits := a.lockWaits
	a.mu.Unlock()
	unlock := func() {
		<-lock.ch
		a.leaveLock(installation, lock)
	}
	select {
	case lock.ch <- struct{}{}:
		return unlock, nil
	default:
	}
	if waits != nil {
		waits(installation)
	}
	select {
	case lock.ch <- struct{}{}:
		return unlock, nil
	case <-ctx.Done():
		a.leaveLock(installation, lock)
		return nil, ctx.Err()
	}
}

// installLock is an installation's lock: ch holds one value while one holds the lock,
// and users counts its holder and its takers waiting, under mu. The lock stays in
// installs while users is above 0 and goes when it falls to 0, so every taker of the
// installation's lock takes one lock, and no two hold it at once.
type installLock struct {
	ch    chan struct{}
	users int
}

// leaveLock counts off a holder of the installation's lock who gave it back, or a taker
// who stopped waiting, and forgets the lock once it has no holder and no taker waiting.
func (a *Adapter) leaveLock(installation int64, lock *installLock) {
	a.mu.Lock()
	defer a.mu.Unlock()
	lock.users--
	if lock.users == 0 {
		delete(a.installs, installation)
	}
}

// listConnection sends Qory Apiary the listing of connection for the installation,
// holding the installation's lock, see [Adapter.listFor].
func (a *Adapter) listConnection(ctx context.Context, installation int64, connection string) error {
	return a.listFor(ctx, installation, connection)
}

// listFor sends Qory Apiary the listing of connection for the installation, holding
// the installation's lock:
//
//   - while the installation is linked to connection, the repositories it reaches, as
//     collections of connection, see [reachSink];
//   - for a connection a connect replaced, see [keepReplaced], a complete listing with
//     no collections, see [Adapter.listReplaced];
//   - for any other, nothing.
//
// A link pending past its connect return's expiry, which the link keeps, and
// [returnSkew] more, on the adapter's clock, is settled by the listing, its last: a
// signed 204 makes it live, as any listing's does; a signed 403 connection_unknown says
// the connection was not made, and the link is dropped, with its collections' records,
// see [dropInstallation]; a 409 connection_ended drops it as any does; any other answer
// keeps it, to be listed again: a 409 connection_suspended, which says the connection
// was made, and a 403 forbidden among them. Before that a 403 drops nothing, since Qory
// Apiary answers 403 connection_unknown by design until the browser brings the return,
// while a 409 connection_ended drops the link at any listing. No caller chooses the
// moment: a re-connect's later return moves it, and an earlier one never brings it
// forward. The first listing kept for the installation and connection, if any, see
// [Adapter.sendFirst], is forgotten once the installation is not linked to connection,
// and once the link is dropped.
func (a *Adapter) listFor(ctx context.Context, installation int64, connection string) error {
	return a.listLink(ctx, installation, connection, func(ctx context.Context, _ link) error {
		return a.listLocked(ctx, installation, connection)
	})
}

// listFirst is [Adapter.listFor] for a try of a link's first listing before the moment
// of its last listing, see [Connect.listSoon]: while the installation is linked to
// connection, [Adapter.sendFirst] sends the listing.
func (a *Adapter) listFirst(ctx context.Context, installation int64, connection string) error {
	return a.listLink(ctx, installation, connection, func(ctx context.Context, l link) error {
		return a.sendFirst(ctx, installation, l)
	})
}

// listLink is [Adapter.listFor], whose listing of the installation's link l, which
// names connection, list sends.
func (a *Adapter) listLink(ctx context.Context, installation int64, connection string, list func(ctx context.Context, l link) error) error {
	unlock, err := a.lockInstallation(ctx, installation)
	if err != nil {
		return err
	}
	defer unlock()
	l, ok, err := linkOf(a.Store, installation)
	if err != nil {
		return err
	}
	if !ok || l.Connection != connection {
		a.dropFirsts(installation, connection)
		return a.listReplaced(ctx, installation, connection)
	}
	// A record of the connection as replaced is stale once a link names it again.
	if err := forgetReplaced(a.Store, connection); err != nil {
		return err
	}
	err = list(ctx, l)
	last := !a.clock().Before(time.Unix(l.Return, 0).Add(returnSkew))
	if l.State != linkPending || !refusedAs(err, http.StatusForbidden, codeConnectionUnknown) || !last {
		return err
	}
	installMu.Lock()
	defer installMu.Unlock()
	now, ok, lerr := linkOf(a.Store, installation)
	if lerr != nil || !ok || now.Connection != connection || now.State != linkPending {
		return lerr
	}
	if err := dropInstallation(a.Store, installation); err != nil {
		return err
	}
	a.dropFirsts(installation, connection)
	a.log().Info("the connection was not made in time, so its pending link is dropped", slog.String("connection", connection), slog.Int64("installation", installation))
	return nil
}

// listReplaced sends Qory Apiary, for connection, which a connect replaced on the
// installation, see [keepReplaced], a complete listing with no collections, which
// never names the installation's repositories, holding the installation's lock: a
// signed 204, or a 409 connection_suspended, which Qory Apiary answers only for a
// connection made, says the connection was made meanwhile, and it is ended, see
// [Adapter.endConnection], so the installation stays linked to one connection; a 409
// connection_ended, or a 403 connection_unknown to its last listing, past the replaced
// link's return's expiry, which the record keeps, and [returnSkew] more, on the
// adapter's clock, says it was not made, and it is forgotten; any other answer keeps
// it, to be listed again. A connection not replaced on the installation is sent
// nothing, and so is one an installation's link names again, whose record is stale and
// is forgotten.
func (a *Adapter) listReplaced(ctx context.Context, installation int64, connection string) error {
	r, ok, err := replacedOf(a.Store, connection)
	if err != nil || !ok || r.Installation != installation {
		return err
	}
	if again, err := linkedTo(a.Store, connection); err != nil || len(again) > 0 {
		if err != nil {
			return err
		}
		return forgetReplaced(a.Store, connection)
	}
	b := make([]byte, 16)
	rand.Read(b)
	err = a.Sink.Collections(ctx, contracts.SourceCollections{
		Version: contracts.Version, ConnectionID: connection, Collections: []contracts.Collection{},
		Listing: contracts.Listing{ID: hex.EncodeToString(b), Part: 1, Complete: true, StartedAt: contracts.FormatTime(a.clock())},
	})
	last := !a.clock().Before(time.Unix(r.Return, 0).Add(returnSkew))
	switch {
	case err == nil, refusedAs(err, http.StatusConflict, codeConnectionSuspended):
		if err := a.endConnection(ctx, connection); err != nil {
			return err
		}
		a.log().Info("the replaced connection was made meanwhile, so it is disconnected", slog.String("connection", connection), slog.Int64("installation", installation))
	case refusedAs(err, http.StatusConflict, codeConnectionEnded):
	case last && refusedAs(err, http.StatusForbidden, codeConnectionUnknown):
		a.log().Info("the replaced connection was not made, so it is forgotten", slog.String("connection", connection), slog.Int64("installation", installation))
	default:
		return err
	}
	return forgetReplaced(a.Store, connection)
}

// listLocked is [Adapter.listConnection] for a caller that holds the installation's
// lock and has read its link.
func (a *Adapter) listLocked(ctx context.Context, installation int64, connection string) error {
	return a.forgetOn401(installation, a.lister(installation, connection).ListRepositories(ctx))
}

// lister is the Lister of the installation's repositories, as collections of
// connection, whose parts go through [reachSink].
func (a *Adapter) lister(installation int64, connection string) github.Lister {
	return github.Lister{
		Client:       a.GitHub,
		Pacer:        a.pacer(installation),
		Token:        func(ctx context.Context) (string, error) { return a.token(ctx, installation, 0, "") },
		Slug:         a.Slug,
		ConnectionID: connection,
		GrantRef:     grantRef(installation),
		Sink:         reachSink{Sink: a.Sink, adapter: a, st: a.Store, installation: installation, connection: connection, seen: &a.presence, held: new(bool)},
		Logf:         a.logf,
		LogCut:       a.logCut,
		LogLeftOut:   func(n int) { a.logLeftOut(installation, n) },
	}
}

// firstKey is a first listing's key, see [Adapter.sendFirst]: its installation and
// its connection.
type firstKey struct {
	installation int64
	connection   string
}

// firstListing is a link's first listing as [Adapter.sendFirst] keeps it: its parts,
// read from GitHub once; next, the index of the first part the next try sends, the
// first Qory Apiary has not taken, or 0 after a 403 connection_unknown; and held,
// whether a part was sent without its collections, see [reachSink], false again after
// a 403 connection_unknown. Only a holder of the installation's lock
// reads or moves next and held.
type firstListing struct {
	parts []contracts.SourceCollections
	next  int
	held  bool
}

// sendFirst sends the first listing of the installation's link l, for a caller that
// holds the installation's lock and has read the link: a try of [Connect.listSoon]
// before the moment of the link's last listing. While l is pending and no listing is
// kept for the installation and l's connection, it first reads every page of the
// repositories the installation reaches, see [github.Lister.ReadRepositories]: the parts
// [Adapter.listLocked] would send, under the same rules, with one listing's id and
// started_at; and it keeps them, in memory alone, never in the store. Then it sends,
// through [reachSink], in order, each part Qory Apiary has not taken, and stops at the
// first it does not take, with no part that ends the listing, so the next try sends
// the parts again, each built anew with its time, and reads GitHub no more: from part 1
// after a 403 connection_unknown to any part, a part after one Qory Apiary took among
// them, and from the part that failed after a failure that passes. A read
// that fails, or is stopped, before every page is read keeps and sends nothing, and the
// next try reads again. A listing read while [Adapter.dropFirsts] forgot the
// installation's listings, which moves its generation on, is sent, as a listing in
// flight was before, and not kept, so the next try reads again: a drop for the
// installation that lands while GitHub is read, a change of the installation's
// repositories among them, never leaves a listing read before it kept. A link live with
// no listing kept, a re-connect's, is listed as [Adapter.listLocked] lists it. The
// listing kept is forgotten, see [Adapter.dropFirsts], once the try that makes the link
// live has sent every part, once the last listing is due, which reads GitHub again,
// once a connect replaces the link or writes it again, once the link is dropped, by its
// last listing, a 409 connection_ended, a newer pass or GitHub's deletion of the
// installation, once the installation's repositories change, as
// installation_repositories says, and once a repository it names is transferred, see
// [Adapter.dropFirstsNaming]; and [Connect.listSoon] forgets it as it stops, for any
// reason, so none outlives its tries.
func (a *Adapter) sendFirst(ctx context.Context, installation int64, l link) error {
	key := firstKey{installation, l.Connection}
	a.mu.Lock()
	f := a.firsts[key]
	a.mu.Unlock()
	if f == nil {
		if l.State != linkPending {
			return a.listLocked(ctx, installation, l.Connection)
		}
		a.mu.Lock()
		gen := a.generation(&a.firstGens, installation)
		a.mu.Unlock()
		parts, err := a.lister(installation, l.Connection).ReadRepositories(ctx)
		if err != nil {
			return a.forgetOn401(installation, err)
		}
		for _, part := range parts {
			for _, c := range part.Collections {
				a.presence.repositorySeen(c.Ref)
			}
		}
		f = &firstListing{parts: parts}
		a.mu.Lock()
		if a.firstGens[installation] == gen {
			if a.firsts == nil {
				a.firsts = map[firstKey]*firstListing{}
			}
			a.firsts[key] = f
		}
		a.mu.Unlock()
	}
	sink := reachSink{Sink: a.Sink, adapter: a, st: a.Store, installation: installation, connection: l.Connection, held: &f.held}
	for ; f.next < len(f.parts); f.next++ {
		if err := sink.Collections(ctx, f.parts[f.next]); err != nil {
			if refusedAs(err, http.StatusForbidden, codeConnectionUnknown) {
				f.next, f.held = 0, false
			}
			return err
		}
	}
	return nil
}

// forgetEnded is ended, what serve does when Qory Apiary answers that a connection
// ended, see [endedIn], which then forgets the connection's first listings kept, see
// [Adapter.sendFirst], with its link: those of each installation linked to the
// connection before it ended, whose generations move on, and any other of the
// connection. A store that fails to read which installations were linked to it is
// logged, and the connection's first listings kept are forgotten all the same.
func (a *Adapter) forgetEnded(ended func(connection string)) func(connection string) {
	return func(connection string) {
		linked, err := linkedTo(a.Store, connection)
		if err != nil {
			a.log().Error("reading the installations linked to an ended connection", slog.String("connection", connection), slog.String("error", err.Error()))
		}
		ended(connection)
		for _, installation := range linked {
			a.dropFirsts(installation, connection)
		}
		a.dropFirsts(0, connection)
	}
}

// dropFirsts forgets the first listings kept, see [Adapter.sendFirst]: those of the
// installation, unless it is 0, and of connection, unless it is "". It moves on the
// generation, see [Adapter.moveGeneration], of the installation, unless it is 0, and of
// each installation whose listing it forgets, so a listing being read for an
// installation whose generation it moves on is not kept.
func (a *Adapter) dropFirsts(installation int64, connection string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropFirstsLocked(installation, connection)
}

// dropFirstsLocked is [Adapter.dropFirsts] for a caller that holds mu.
func (a *Adapter) dropFirstsLocked(installation int64, connection string) {
	if installation != 0 {
		a.moveGeneration(&a.firstGens, installation)
	}
	for k := range a.firsts {
		if (installation == 0 || k.installation == installation) && (connection == "" || k.connection == connection) {
			delete(a.firsts, k)
			if k.installation != installation {
				a.moveGeneration(&a.firstGens, k.installation)
			}
		}
	}
}

// dropFirstsNaming forgets each first listing kept, see [Adapter.sendFirst], one of
// whose parts names the collection ref, of any installation, and moves on the
// first-listing generation, see [Adapter.moveGeneration], of every installation that
// has one, whether a listing of it is kept or not, so a first listing being read for
// any installation as it runs, which may name ref, is sent and not kept. A transfer of
// the repository calls it, see [Adapter.transferred].
func (a *Adapter) dropFirstsNaming(ref string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, f := range a.firsts {
		if f.names(ref) {
			delete(a.firsts, k)
		}
	}
	for installation := range a.firstGens {
		a.moveGeneration(&a.firstGens, installation)
	}
}

// names is whether one of the listing's parts names the collection ref.
func (f *firstListing) names(ref string) bool {
	for _, part := range f.parts {
		for _, c := range part.Collections {
			if c.Ref == ref {
				return true
			}
		}
	}
	return false
}

// forgetInstallation forgets what the adapter keeps in memory for the installation,
// for [Adapter.deleted]: its tokens, its first listings kept, its pacer and its
// generations, at once, under mu, so a token minted or a first listing read across it
// is used, or sent, and not kept, see [Adapter.generation], and no move after it makes
// a generation again, see [Adapter.moveGeneration]. Its lock goes once nobody holds it
// or waits for it, see [installLock]. A request for the installation after it, one
// that reads GitHub, makes what it needs again.
func (a *Adapter) forgetInstallation(installation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forgetTokensLocked(installation)
	a.dropFirstsLocked(installation, "")
	delete(a.gens, installation)
	delete(a.firstGens, installation)
	delete(a.pacers, installation)
}

// connectionSink is a sink that ends a connection, as [Apiary.DisconnectConnection]
// does.
type connectionSink interface {
	DisconnectConnection(ctx context.Context, req contracts.ConnectionsDisconnect) error
}

// deleted handles the installation event's deleted, for any installation, linked or
// not, by [Adapter.endInstallation]; an installation that was not linked is logged.
func (a *Adapter) deleted(ctx context.Context, d Delivery) error {
	connection, err := a.endInstallation(ctx, d.InstallationID)
	if err == nil && connection == "" {
		a.log().Info("the installation is not linked to Qory Apiary, so the delivery is not handled", deliveryArgs(d)...)
	}
	return err
}

// endInstallation ends what serve keeps of an installation GitHub deleted, as the
// installation event's deleted says, see [Adapter.deleted], or as the pull round finds
// when GitHub answers 404 for it under the App's token, see [puller.ended], holding the
// installation's lock, so no connect's link lands between its read and its drop, see
// [Connect.link]: it keeps that GitHub deleted the installation, see [keepDeleted],
// which a connect checks before it links, forgets what the adapter keeps in memory for
// the installation, see [Adapter.forgetInstallation], its first listings kept, see
// [Adapter.sendFirst], among them, and the record of [keepUnlinked], and, for a linked
// installation, reports the end of its grant, see [Adapter.endGrant], which drops the
// installation's link and the records of its collections once Qory Apiary has ended the
// grant. The connection stays, with the links of other installations. It returns the
// connection of the installation's link, or "" when the installation was not linked, as
// once the webhook or a round ended it already. Each step is one a repeat finds done,
// so a run that fails is run again whole.
func (a *Adapter) endInstallation(ctx context.Context, installation int64) (string, error) {
	unlock, err := a.lockInstallation(ctx, installation)
	if err != nil {
		return "", err
	}
	defer unlock()
	l, ok, err := linkOf(a.Store, installation)
	if err != nil {
		return "", err
	}
	if err := keepDeleted(a.Store, installation, l.Account); err != nil {
		return "", err
	}
	a.forgetInstallation(installation)
	if err := dropUnlinked(a.Store, installation); err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	if err := a.endGrant(ctx, installation, l); err != nil {
		return "", err
	}
	return l.Connection, nil
}

// installation handles the installation event of a linked installation: suspend is
// logged and changes nothing, since a suspended installation is no disconnect, and the
// next round lists it again; unsuspend lists the repositories again. deleted is
// [Adapter.deleted]'s.
func (a *Adapter) installation(ctx context.Context, d Delivery) error {
	switch d.Action {
	case "suspend":
		a.log().Info("GitHub suspended the installation, so its link stays and it is read again later", slog.Int64("installation", d.InstallationID))
	case "unsuspend":
		return a.listRepositories(ctx, d.InstallationID)
	}
	return nil
}

// endConnection tells Qory Apiary the source no longer grants the connection access,
// POST /v1/connections/disconnect, which [Apiary.DisconnectConnection] sends again while
// Qory Apiary answers 403. A 403 that lasts, or another refusal for good, is logged and
// passed; any other error stops it, to be tried again.
func (a *Adapter) endConnection(ctx context.Context, connection string) error {
	cs, ok := a.Sink.(connectionSink)
	if !ok {
		return Permanent(errors.New("the sink cannot disconnect a connection"))
	}
	err := cs.DisconnectConnection(ctx, contracts.ConnectionsDisconnect{Version: contracts.Version, ConnectionID: connection})
	if IsPermanent(err) {
		a.log().Error("the disconnect is refused", slog.String("connection", connection), slog.String("error", err.Error()))
		return nil
	}
	return err
}

// installationRepositories handles the installation_repositories event: each
// repository removed, by its id, which is its collection's ref, that the store holds as
// the installation's is disconnected, under the connection of the installation's link,
// see [Adapter.disconnect], and its records are dropped: which installation reaches it,
// unless a listing of another installation claimed it since, see [dropReach], the
// environment_ref sent for it and whether its collection is linked, unless the change
// feed linked it after serve began to remove it, see [unlinkSince], holding the installation's lock, see
// [Adapter.dropRemoved]. One whose disconnect Qory Apiary answers 409
// connection_suspended keeps its records, see [Adapter.disconnect], and that refusal is
// returned once the rest is done; one it does not hold is passed; and the
// installation's repositories are listed again, which a listing of more than one page
// needs, since it never says it is complete. The installation's tokens are dropped
// first, so the listing never reads with a token minted before the
// change, and so are its first listings kept, see [Adapter.sendFirst], which the change
// makes stale: one being read as they are dropped is sent and not kept, so the next try
// reads GitHub again. Each repository added, by its id, is a sign for the pull rounds
// that GitHub holds it, see [presence], so an absence a round found for it before is
// counted as none.
func (a *Adapter) installationRepositories(ctx context.Context, d Delivery) error {
	if d.Action != "added" && d.Action != "removed" {
		return nil
	}
	a.forgetTokens(d.InstallationID)
	a.dropFirsts(d.InstallationID, "")
	var ev struct {
		Added []struct {
			ID int64 `json:"id"`
		} `json:"repositories_added"`
		Removed []struct {
			ID int64 `json:"id"`
		} `json:"repositories_removed"`
	}
	if err := json.Unmarshal(d.Body, &ev); err != nil {
		return Permanent(errors.New("the installation_repositories event is not JSON GitHub sends"))
	}
	for _, r := range ev.Added {
		if ref := github.CollectionRef(r.ID); ref != "" {
			a.presence.repositorySeen(ref)
		}
	}
	var removed []string
	for _, r := range ev.Removed {
		if ref := github.CollectionRef(r.ID); ref != "" {
			removed = append(removed, ref)
		}
	}
	var suspended error
	if len(removed) > 0 {
		var err error
		if suspended, err = a.dropRemoved(ctx, d.InstallationID, removed); err != nil {
			return err
		}
	}
	return errors.Join(a.listRepositories(ctx, d.InstallationID), suspended)
}

// dropRemoved disconnects and drops the repositories removed from the installation, by
// their refs, as [Adapter.installationRepositories] says, holding the installation's
// lock from its first read of a repository's record to the last drop, so a listing of
// the installation under way, which claims the repositories it names before it sends
// them, see [reachSink], lands wholly before it or wholly after it. It gives the lock
// back before it returns, since the listing that follows takes it, and a wait for it
// that ctx cuts short is the error, with every record kept. It returns the first 409
// connection_suspended, as suspended.
func (a *Adapter) dropRemoved(ctx context.Context, installation int64, removed []string) (suspended, err error) {
	unlock, err := a.lockInstallation(ctx, installation)
	if err != nil {
		return nil, err
	}
	defer unlock()
	began := linkMoment()
	var refs []string
	for _, ref := range removed {
		reached, ok, err := reachOf(a.Store, ref)
		if err != nil {
			return nil, err
		}
		if ok && reached == installation {
			refs = append(refs, ref)
		}
	}
	l, _, err := linkOf(a.Store, installation)
	if err != nil {
		return nil, err
	}
	refs, suspended, err = a.disconnect(ctx, l.Connection, refs)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if err := dropReach(a.Store, ref, installation); err != nil {
			return nil, err
		}
		if err := a.Store.Delete(nsEnvironments, collectionKey(ref)); err != nil {
			return nil, err
		}
		if _, err := unlinkSince(a.Store, ref, began); err != nil {
			return nil, err
		}
	}
	return suspended, nil
}

// repository handles the repository event of a linked installation, for the repository
// the event names by its id, which is its collection's ref:
//
//   - deleted: a repository serve listed for the installation, see [reachOf], is
//     disconnected and its records dropped, see [Adapter.dropRepository]; any other is
//     logged and changes nothing. GitHub's docs say an App is not sent deleted. A
//     deleted repository is left out of the installation's next listing of its
//     repositories, the pull round's among them, and a listing GitHub answers with one
//     page, none skipped, is complete, so Qory Apiary disconnects the collection it
//     leaves out, see [github.Lister.ListRepositories]; a fill or a pull of it fails as
//     gone. A deleted that arrives is handled all the same.
//   - created: the installation's tokens and first listings kept, see
//     [Adapter.sendFirst], are dropped, as installation_repositories drops them, and its
//     repositories are listed again, the new one among them.
//   - renamed: the installation's first listings kept, see [Adapter.sendFirst], are
//     dropped, as for created, so no try of a pending link's first listing sends the
//     repository's old title, URL and target again, and a listing being read as they
//     are dropped is sent and not kept; then the repositories are listed again, which
//     names the repository by the same ref with its new title, URL and target. Nothing
//     is disconnected.
//
// Any other action, archived, unarchived, privatized, publicized and edited among them,
// changes nothing. transferred is [Adapter.transferred]'s.
func (a *Adapter) repository(ctx context.Context, d Delivery) error {
	switch d.Action {
	case "deleted":
		ref, err := repositoryRef(d)
		if err != nil {
			return err
		}
		installation, ok, err := reachOf(a.Store, ref)
		if err != nil {
			return err
		}
		if !ok || installation != d.InstallationID {
			a.log().Info("the repository is not one serve listed for the installation, so nothing is disconnected", slog.String("collection", ref), slog.Int64("installation", d.InstallationID))
			return nil
		}
		sent, err := a.dropRepository(ctx, ref, installation)
		if sent {
			a.log().Info("GitHub deleted the repository, so its collection is disconnected", slog.String("collection", ref), slog.Int64("installation", installation))
		}
		return err
	case "created":
		a.forgetTokens(d.InstallationID)
		a.dropFirsts(d.InstallationID, "")
		return a.listRepositories(ctx, d.InstallationID)
	case "renamed":
		a.dropFirsts(d.InstallationID, "")
		return a.listRepositories(ctx, d.InstallationID)
	}
	return nil
}

// transferred handles the repository event's transferred, for any installation whose
// id is above 0, see [Adapter.linked], linked or not. GitHub sends it only to the
// installation on the account the repository was transferred to, with the repository
// as it is now, by the same id, which is its collection's ref. When that installation
// is linked, its tokens and first listings kept are dropped and its repositories are
// listed again, as for created, and the repository's installation becomes this one,
// since the listing starts after the transfer, so no earlier than any listing of
// another installation that named the repository, and claims it, see [claimReach]. The
// listing names the repository by the same ref under this installation's connection,
// which is not the connection of the installation serve listed it for before, since a
// connection holds one installation. When the collection is still live under the
// previous connection, Qory Apiary ends it, as a disconnect would, and makes a new one
// under this one; when it is not, Qory Apiary only makes the new one. A person links
// the collection again only if the previous one was linked. Every first listing kept
// that names the repository, of any installation, is dropped too, whichever
// installation the store's record names by then, and one being read for any
// installation as they are dropped is sent and not kept, see
// [Adapter.dropFirstsNaming], so no try of a first listing sends the repository as
// another installation's again. When the installation is not linked, the repository's
// collection is disconnected under the installation serve listed it for, see
// [reachOf], and its records dropped, see [Adapter.dropRepository]; a repository serve
// never listed is logged and changes nothing.
func (a *Adapter) transferred(ctx context.Context, d Delivery) error {
	ref, err := repositoryRef(d)
	if err != nil {
		return err
	}
	linked, err := granted(a.Store, d.InstallationID, a.clock())
	if err != nil {
		return err
	}
	before, listed, err := reachOf(a.Store, ref)
	if err != nil {
		return err
	}
	if linked {
		a.forgetTokens(d.InstallationID)
		a.dropFirsts(d.InstallationID, "")
		a.dropFirstsNaming(ref)
		return a.listRepositories(ctx, d.InstallationID)
	}
	if !listed {
		a.log().Info("the repository is not one serve listed, so nothing is disconnected", slog.String("collection", ref), slog.Int64("installation", d.InstallationID))
		return nil
	}
	sent, err := a.dropRepository(ctx, ref, before)
	if sent {
		a.log().Info("GitHub transferred the repository to an installation not linked to Qory Apiary, so its collection is disconnected", slog.String("collection", ref), slog.Int64("installation", before))
	}
	return err
}

// dropRepository sends a disconnect for the collection ref, a repository the
// installation reaches, which names the connection of the installation's link, the
// connection the collection was listed under, then drops the repository's records,
// which installation reaches it, unless a listing of another installation claimed it
// since, see [dropReach], its pulls, the environment_ref sent for it and whether its
// collection is linked, unless the change feed linked it after the drop began, see
// [unlinkSince], and the installation's first listings kept, see [Adapter.sendFirst], which name it. It says
// whether Qory Apiary took the disconnect. A 409 connection_suspended, which the
// contract says changes no state, keeps the records and is returned, so the collection
// stays the installation's, and the round's pull sends the disconnect again on its
// periodic check, see [Adapter.dropRefused]. A disconnect Qory Apiary refuses for good
// otherwise is logged, as [Adapter.disconnect] logs it, and the records are dropped all
// the same; any other error stops it, to be tried again, with the records kept. Qory
// Apiary answers a ref with no live collection under the connection with the signed
// 204, so a disconnect sent again, or after the collection ended, is taken. An
// installation whose link is gone sends no disconnect, as [Adapter.disconnect] sends
// none, and the records are dropped all the same; it says false.
//
// It holds the installation's lock throughout, so a listing of the installation under
// way, which claims the repositories it names before it sends them, see [reachSink],
// lands wholly before it or wholly after it, and it reads the repository's record
// again under the lock: a record that no longer names the installation, as after a
// webhook dropped it or a listing of another installation that started no earlier
// claimed it, see [claimReach], sends nothing and drops nothing, and it says false. A wait for
// the lock that ctx cuts short is the error, with the records kept. No caller holds
// the installation's lock, which is not taken twice; the round's pull calls it holding
// the collection's turn, see [Adapter.dropRefused].
func (a *Adapter) dropRepository(ctx context.Context, ref string, installation int64) (bool, error) {
	unlock, err := a.lockInstallation(ctx, installation)
	if err != nil {
		return false, err
	}
	defer unlock()
	reached, ok, err := reachOf(a.Store, ref)
	if err != nil || !ok || reached != installation {
		return false, err
	}
	began := linkMoment()
	l, linked, err := linkOf(a.Store, installation)
	if err != nil {
		return false, err
	}
	if linked {
		err = a.Sink.Disconnect(ctx, contracts.SourcesDisconnect{Version: contracts.Version, ConnectionID: l.Connection, CollectionRef: ref})
	}
	if err != nil && (!IsPermanent(err) || refusedAs(err, http.StatusConflict, codeConnectionSuspended)) {
		return false, err
	}
	if err != nil {
		a.log().Error("the disconnect is refused", slog.String("collection", ref), slog.String("error", err.Error()))
	}
	if err := dropReach(a.Store, ref, installation); err != nil {
		return false, err
	}
	for _, ns := range repositoryRecords {
		if err := a.Store.Delete(ns, collectionKey(ref)); err != nil {
			return false, err
		}
	}
	if _, err := unlinkSince(a.Store, ref, began); err != nil {
		return false, err
	}
	a.dropFirsts(installation, "")
	return linked && err == nil, nil
}

// errStillListed is a repository GitHub refuses a token for alone, 422 to the mint by
// repository_ids, that the installation's list of repositories still holds, so it is not
// disconnected, see [Adapter.dropRefused].
var errStillListed = errors.New("the installation's list of repositories still holds the repository, so its collection is not disconnected")

// errAbsentOnce is a repository GitHub refuses a token for alone, 422 to the mint by
// repository_ids, that the installation's list of repositories, read in full, no longer
// holds, in the first round in a row that finds so, so it is not disconnected yet, see
// [Adapter.dropRefused].
var errAbsentOnce = errors.New("the installation's list of repositories no longer holds the repository, so its collection is disconnected if the next round finds the same and GitHub shows the repository nowhere in between")

// dropRefused disconnects the collection ref, the repository whose id is id, that the
// installation reaches as the store holds it, once GitHub answered 422 to a token for
// that repository alone, refused, which wraps [github.ErrRepositoryRefused], and the
// installation's list of repositories, read in full once in the round, listed, no
// longer holds it, see [Adapter.confirmGone], in this round and, under the same
// installation, in the last that pulled the collection, with no sign that GitHub holds
// the repository after the last round's read of the list began, up to the decision,
// which comes once this round's read answered, see [presence.absentAgain]: the round's
// pull calls it, holding the collection's turn. It says whether this round found the
// repository absent from the installation's list and did not disconnect it, which the
// collection's next pull counts only when the same installation pulls it and no sign
// that GitHub holds the repository came after this round's read of the list began.
//
// The 422 alone does not say the repository is gone, since GitHub answers it too for a
// permission the installation does not grant, and the list read in full does: so a
// repository the list still holds, a public one among them, is not disconnected, and the
// error wraps refused and [errStillListed]; a page of the list that fails, or a list
// whose pages do not add up to the count GitHub gives, decides nothing, and the error
// wraps refused and the list's; either way the next round tries again. A repository the
// store no longer holds as the installation's, as after a webhook dropped it or a
// listing of another installation that started no earlier named it, see [claimReach], is
// logged and sends nothing. A disconnect
// cannot be undone, and a page whose contents shifted while the list was read can miss
// a repository, so one list alone does not disconnect it: the first round in a row that
// finds it absent sends nothing, and the error wraps refused and [errAbsentOnce].
// Otherwise [Adapter.dropRepository] disconnects it and drops its records, and its error
// is returned; a line says when Qory Apiary took the disconnect.
func (a *Adapter) dropRefused(ctx context.Context, ref string, id, installation int64, listed *listedRepositories, refused error) (absent bool, err error) {
	gone, err := a.confirmGone(ctx, installation, id, listed)
	switch {
	case err != nil:
		return false, fmt.Errorf("%w; reading the installation's list of repositories to confirm it no longer holds the repository: %w", refused, err)
	case !gone:
		return false, fmt.Errorf("%w; %w", refused, errStillListed)
	}
	reached, ok, err := reachOf(a.Store, ref)
	if err != nil {
		return false, err
	}
	if !ok || reached != installation {
		a.log().Info("the repository is not one serve listed for the installation, so nothing is disconnected", slog.String("collection", ref), slog.Int64("installation", installation))
		return false, nil
	}
	if !a.presence.absentAgain(ref, installation, listed.since) {
		return true, fmt.Errorf("%w; %w", refused, errAbsentOnce)
	}
	sent, err := a.dropRepository(ctx, ref, installation)
	if sent {
		a.log().Info("GitHub refuses a token for the repository alone, and the installation's list of repositories, read in full, no longer holds it, so its collection is disconnected", slog.String("collection", ref), slog.Int64("installation", installation))
	}
	return err != nil, err
}

// listedRepositories is one pull round's read, in full, of an installation's list of
// repositories, see [Adapter.confirmGone]: the installation's round makes it, empty, as
// it begins, and keeps it nowhere else; it is filled at the first collection of the
// round GitHub refuses a token for alone, and used by every other one of the
// installation in the round, whether the read gave the ids of the repositories the list
// holds or an error. It ends with the round, and the next round reads the list again.
// since is the number of the last sign for the pull rounds as the read began, see
// [presence.at].
type listedRepositories struct {
	read  bool
	since uint64
	ids   map[int64]bool
	err   error
}

// confirmGone is whether the installation's list of the repositories it reaches, read
// in full, see [github.Lister.ListedRepositories], no longer holds the repository whose
// id is id: true when the list does not name it, false when it does, and an error,
// which decides nothing, when a page fails or the pages do not add up to the count
// GitHub gives. The list is read once in the round, at its first call, and kept in
// listed, the error with it: every later call in the round answers from it. It reads
// with the installation's listing token, which reaches every repository the
// installation does: the pull round drops it as it begins, see
// [Adapter.forgetListingToken], so it was minted in the round, at its listing or here,
// and each mint checks first that GitHub answers 200 for the installation and that it
// is not suspended. A 401 drops the installation's tokens. Each repository the list
// names is a sign for the pull rounds that GitHub holds it, see [presence].
func (a *Adapter) confirmGone(ctx context.Context, installation, id int64, listed *listedRepositories) (bool, error) {
	if !listed.read {
		l := github.Lister{
			Client: a.GitHub,
			Pacer:  a.pacer(installation),
			Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, 0, "") },
		}
		listed.since = a.presence.at()
		ids, err := l.ListedRepositories(ctx)
		listed.read, listed.ids, listed.err = true, ids, a.forgetOn401(installation, err)
		for named := range ids {
			a.presence.repositorySeen(github.CollectionRef(named))
		}
	}
	if listed.err != nil {
		return false, listed.err
	}
	return !listed.ids[id], nil
}

// push handles the push event of a linked installation: a push to the default branch,
// whose ref is refs/heads/ and the repository's default_branch, of a repository whose
// collection is linked and which the store holds as the installation's, see [reachOf],
// reads the repository's environment_ref, as a listing reads it, see
// [github.Lister.ReadEnvironmentRef], with the listing's token; when it is not the one
// serve last sent for the collection, see [sentEnvironment], the installation's
// repositories are listed again, which sends it. A push of another branch or of a tag,
// one that deletes its ref, and one of a repository whose collection is not linked
// change nothing. A read that fails is logged, throttled as [Adapter.logCut] is, and
// changes nothing: the next listing, the pull round's among them, reads it again.
func (a *Adapter) push(ctx context.Context, d Delivery) error {
	var ev struct {
		Ref        string `json:"ref"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			ID            int64  `json:"id"`
			NodeID        string `json:"node_id"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(d.Body, &ev); err != nil {
		return Permanent(errors.New("the push event is not JSON GitHub sends"))
	}
	r := ev.Repository
	ref := github.CollectionRef(r.ID)
	if ev.Deleted || r.DefaultBranch == "" || ev.Ref != "refs/heads/"+r.DefaultBranch || ref == "" {
		return nil
	}
	linked, err := collectionLinked(a.Store, ref)
	if err != nil || !linked {
		return err
	}
	installation, ok, err := reachOf(a.Store, ref)
	if err != nil || !ok || installation != d.InstallationID {
		return err
	}
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, 0, "") },
	}
	env, err := l.ReadEnvironmentRef(ctx, r.ID, r.NodeID)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		a.logEnvRead(ref, installation, a.forgetOn401(installation, err))
		return nil
	}
	sent, err := sentEnvironment(a.Store, ref)
	if err != nil || env == sent {
		return err
	}
	return a.listRepositories(ctx, installation)
}

// logEnvRead logs a push's read of the collection's environment definition that failed,
// throttled as [Adapter.logCut] is.
func (a *Adapter) logEnvRead(ref string, installation int64, err error) {
	ok, dropped := a.envLog().allow()
	if !ok {
		return
	}
	attrs := []slog.Attr{slog.String("collection", ref), slog.Int64("installation", installation), slog.String("error", err.Error())}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("reads_dropped", dropped))
	}
	a.log().LogAttrs(context.Background(), slog.LevelWarn, "reading the environment definition (.devcontainer or .devcontainer.json) after a push failed; the next listing reads it again", attrs...)
}

// repositoryRef is the collection ref of the repository a repository event names, its
// id; an event that names none fails for good.
func repositoryRef(d Delivery) (string, error) {
	var ev struct {
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(d.Body, &ev); err != nil {
		return "", Permanent(errors.New("the repository event is not JSON GitHub sends"))
	}
	ref := github.CollectionRef(ev.Repository.ID)
	if ref == "" {
		return "", Permanent(errors.New("the repository event names no repository's id"))
	}
	return ref, nil
}

// disconnect sends a disconnect for each collection, which names connection, the
// connection of the link of the installation the collections were listed for, and
// returns those whose records may be dropped. One Qory Apiary answers 409
// connection_suspended, which the contract says changes no state, is left out of them,
// so its records are kept and the round's pull sends the disconnect again on its
// periodic check, see [Adapter.dropRefused], and the first such refusal is returned as
// suspended. One Qory Apiary refuses for good otherwise is logged and passed; any other
// error stops it, to be tried again. A connection of "", as for an installation whose
// link is gone, sends nothing, and every collection's records may be dropped: a link
// goes with its connection's end or disconnect, or while it is pending, when its
// connection holds no collection of the installation's.
func (a *Adapter) disconnect(ctx context.Context, connection string, refs []string) (done []string, suspended, err error) {
	if connection == "" {
		return refs, nil, nil
	}
	for _, ref := range refs {
		err := a.Sink.Disconnect(ctx, contracts.SourcesDisconnect{Version: contracts.Version, ConnectionID: connection, CollectionRef: ref})
		switch {
		case refusedAs(err, http.StatusConflict, codeConnectionSuspended):
			if suspended == nil {
				suspended = err
			}
			continue
		case IsPermanent(err):
			a.log().Error("the disconnect is refused", slog.String("collection", ref), slog.String("error", err.Error()))
		case err != nil:
			return nil, nil, err
		}
		done = append(done, ref)
	}
	return done, suspended, nil
}

// issues handles the issues event: the issue, as [github.IssuesWebhook] makes it, goes
// to Qory Apiary when its collection is linked.
func (a *Adapter) issues(ctx context.Context, d Delivery) error {
	active := func(ref string) bool {
		ok, _ := collectionLinked(a.Store, ref)
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

// fill sends Qory Apiary the open issues of a collection it linked, and their comments,
// by [github.Lister.ListOpenIssuesComplete]: its last part says the listing is complete
// unless an item was skipped, so Qory Apiary closes every item of the collection the
// listing left out and did not hear of since it started. A fill that fails or is
// stopped before every open issue is read and sent sends no part that says it is
// complete; one that fails on the comments of its last part's items has sent that part
// already, complete, since comments are no part of complete. A repository with no open
// issue sends one part without items that says it is complete. A repository GitHub
// answers is deleted or out of the App's reach, or whose request by the id GitHub
// redirects, [github.ErrRepositoryGone], or for which GitHub refuses to mint a token
// for good, [github.ErrMintRefused], or whose installation GitHub answers as suspended,
// [github.ErrSuspended], fails for good, so the change feed passes it: the collection
// stays linked with no pull mark, so the round's pull of it, once the installation is
// no longer suspended, lists it as the fill does. A 401 or a 403 GitHub answers to a
// read, or to the mint of its token, drops the installation's tokens, so the feed's next
// try mints anew, and the mint's check says whether the installation is suspended. It
// waits for a pull of the collection that runs, and once it has sent everything, the
// next pull reads what changed from when it began. The listing is GraphQL's, which
// names a repository by owner/name, so the fill first reads that name by the
// collection's ref, the repository's id, [github.Lister.ReadRepository], and keeps it
// nowhere: a 404 or a 410 there says the repository is deleted or out of the App's
// reach, as after a transfer to an account the installation is not on, never after a
// rename, which keeps its id, and fails for good as [github.ErrRepositoryGone]; any
// other failure of that read fails the fill as a failure of the listing would, to be
// tried again. A listing that finds the name naming another repository, or none, by
// then, as a rename or a transfer that lands between the two requests makes it, fails
// without sending anything, to be tried again, which reads the name again.
//
// A repository with Issues turned off on GitHub fills without error and keeps its
// pullMark, unless sending what was read before GitHub said so fails: when that read
// says Issues are off, the fill logs a line and lists nothing; when GraphQL says so on
// the first page, the listing sends nothing and returns nil, and on a later page it
// stops and returns nil, or the error of sending the items it read before, see
// [github.Lister.ListOpenIssuesComplete]. Either way no part says the listing is
// complete, so Qory Apiary closes no item of the collection for it.
func (a *Adapter) fill(ctx context.Context, ref string) error {
	id, err := repositoryID(ref)
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
	done, err := a.waitTurn(ctx, ref)
	if err != nil {
		return err
	}
	defer done()
	start := a.clock()
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, id, "read") },
		Slug:   a.Slug,
		Sink:   a.Sink,
		Logf:   a.logf,
		LogCut: a.logCut,
	}
	repo, issuesOn, err := l.ReadRepository(ctx, id)
	switch {
	case err != nil:
	case issuesOn:
		err = l.ListOpenIssuesComplete(ctx, id, repo)
	default:
		a.issuesOff(ref)
	}
	err = a.forgetOn401(installation, err)
	if github.Forbidden(err) {
		a.forgetTokens(installation)
	}
	if errors.Is(err, github.ErrRepositoryGone) || errors.Is(err, github.ErrMintRefused) || errors.Is(err, github.ErrSuspended) {
		return Permanent(err)
	}
	if err != nil {
		return err
	}
	return keepPulled(a.Store, ref, pullMark{Since: start, Listed: start})
}

// applyChange writes on GitHub what a work_item entry of the feed says, with a token
// that writes the issues of that one repository, from the installation that reaches it.
// A ref that is not an item's, the repository's id, #, and the issue's number, see
// [github.ParseItemRef], fails for good before the store is read or GitHub is asked,
// as [github.Client.ApplyChange] refuses it. A token GitHub refuses to mint for good,
// [github.ErrMintRefused], fails it for good, and so does an installation GitHub
// answers as suspended, [github.ErrSuspended]: the change is not written on GitHub,
// then or later, and the feed moves past it, so no entry of a suspended installation
// holds the feed for the others.
func (a *Adapter) applyChange(ctx context.Context, ch contracts.Change) error {
	id, _, ok := github.ParseItemRef(ch.Ref)
	if !ok {
		return Permanent(fmt.Errorf("applying a change: %w", errNotItemRef))
	}
	installation, ok, err := reachOf(a.Store, github.CollectionRef(id))
	if err != nil {
		return err
	}
	if !ok {
		return Permanent(fmt.Errorf("applying a change: %w", errNoInstallation))
	}
	token := func(ctx context.Context, repository int64) (string, error) {
		return a.token(ctx, installation, repository, "write")
	}
	err = a.forgetOn401(installation, a.GitHub.ApplyChange(ctx, a.pacer(installation), token, a.Slug, github.Change{WorkItemID: ch.WorkItemID, Ref: ch.Ref, Status: ch.Status, URL: ch.URL}))
	if errors.Is(err, github.ErrMintRefused) || errors.Is(err, github.ErrSuspended) {
		return Permanent(err)
	}
	return err
}

// errNotItemRef refuses a change's ref that is not an item's, see [github.ParseItemRef].
var errNotItemRef = errors.New("the change's ref is not a repository's id, #, and an issue's number")

// repositoryID is the id of the repository a collection's ref names, see
// [github.ParseCollectionRef].
func repositoryID(ref string) (int64, error) {
	id, ok := github.ParseCollectionRef(ref)
	if !ok {
		return 0, errors.New("the collection's ref is not a repository's id")
	}
	return id, nil
}
