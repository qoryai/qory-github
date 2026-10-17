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
	// generations of them, see [Adapter.generation], which [Adapter.dropFirsts] moves on
	// and [Adapter.forgetInstallation] forgets: a listing read across either is sent and
	// not kept.
	firsts    map[firstKey]*firstListing
	firstGens map[int64]uint64

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
// issues and issue_comment. workflow_run, pull_request and push have none yet, so their
// deliveries are not kept, see [Receiver.Handlers].
func (a *Adapter) Register(hs *Handlers) {
	hs.HandleFunc("installation", a.linked(a.installation))
	hs.HandleFunc("installation_repositories", a.linked(a.installationRepositories))
	hs.HandleFunc("issues", a.linked(a.issues))
	hs.HandleFunc("issue_comment", a.linked(a.issueComment))
}

// linked is h for the deliveries of a linked installation; another's is done and
// logged. The installation event's deleted is [Adapter.deleted]'s, for any
// installation.
func (a *Adapter) linked(h func(ctx context.Context, d Delivery) error) func(context.Context, Delivery) error {
	return func(ctx context.Context, d Delivery) error {
		if d.Event == "installation" && d.Action == "deleted" && d.InstallationID > 0 {
			return a.deleted(ctx, d)
		}
		ok, err := Linked(a.Store, d.InstallationID)
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
// the listing token that reads which repositories it reaches; permission is the one it
// grants on issues. A token is kept until shortly before it expires, unless the
// installation's tokens were dropped while it was minted.
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
	if repository == 0 {
		t, err = a.GitHub.MintListingToken(ctx, a.AppID, a.Key, installation)
	} else {
		t, err = a.GitHub.MintInstallationToken(ctx, github.Request{AppID: a.AppID, Key: a.Key, InstallationID: installation, RepositoryIDs: []int64{repository}, Permissions: map[string]string{"issues": permission}})
	}
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

// stopLog logs the count of cuts held back, if any, as [throttle.stop] does.
func (a *Adapter) stopLog() {
	a.cutLog().stop()
}

// reachSink is the adapter's sink for a listing of an installation's repositories,
// which names the installation's connection: it keeps which installation reaches each
// repository it lists before it sends them, and once Qory Apiary takes a part, which it
// does once the connection is made, it marks the installation's link live.
type reachSink struct {
	github.Sink
	st           *store.Store
	installation int64
	connection   string
}

// Collections keeps each collection's installation and sends them.
func (s reachSink) Collections(ctx context.Context, req contracts.SourceCollections) error {
	for _, c := range req.Collections {
		if err := setReach(s.st, c.Ref, s.installation); err != nil {
			return err
		}
	}
	if err := s.Sink.Collections(ctx, req); err != nil {
		return err
	}
	return goLive(s.st, s.installation, s.connection)
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
// write. It is held across requests to GitHub and Qory Apiary, one installation's
// alone. The lock is forgotten once nobody holds it or waits for it, see
// [installLock], so an installation GitHub deleted keeps none.
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
		Sink:         reachSink{Sink: a.Sink, st: a.Store, installation: installation, connection: connection},
		Logf:         a.logf,
		LogCut:       a.logCut,
	}
}

// firstKey is a first listing's key, see [Adapter.sendFirst]: its installation and
// its connection.
type firstKey struct {
	installation int64
	connection   string
}

// firstListing is a link's first listing as [Adapter.sendFirst] keeps it: its parts,
// read from GitHub once, and next, the index of the first part the next try sends, the
// first Qory Apiary has not taken, or 0 after a 403 connection_unknown, which only a
// holder of the installation's lock reads or moves.
type firstListing struct {
	parts []contracts.SourceCollections
	next  int
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
// installation, and once the installation's repositories change, as
// installation_repositories says; and [Connect.listSoon] forgets it as it stops, for any
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
	sink := reachSink{Sink: a.Sink, st: a.Store, installation: installation, connection: l.Connection}
	for ; f.next < len(f.parts); f.next++ {
		if err := sink.Collections(ctx, f.parts[f.next]); err != nil {
			if refusedAs(err, http.StatusForbidden, codeConnectionUnknown) {
				f.next = 0
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
// not, holding the installation's lock, so no connect's link lands between its read
// and its drop, see [Connect.link]: it keeps that GitHub deleted the installation, see
// [keepDeleted], which a connect checks before it links, forgets what the adapter keeps
// in memory for the installation, see [Adapter.forgetInstallation], its first listings
// kept, see [Adapter.sendFirst], among them, and the record of [keepUnlinked], and, for
// a linked installation, ends its connection, see [Adapter.endConnection], then
// drops what the store keeps of the installation.
func (a *Adapter) deleted(ctx context.Context, d Delivery) error {
	unlock, err := a.lockInstallation(ctx, d.InstallationID)
	if err != nil {
		return err
	}
	defer unlock()
	if err := keepDeleted(a.Store, d.InstallationID); err != nil {
		return err
	}
	a.forgetInstallation(d.InstallationID)
	if err := dropUnlinked(a.Store, d.InstallationID); err != nil {
		return err
	}
	l, ok, err := linkOf(a.Store, d.InstallationID)
	if err != nil {
		return err
	}
	if !ok {
		a.log().Info("the installation is not linked to Qory Apiary, so the delivery is not handled", deliveryArgs(d)...)
		return nil
	}
	if err := a.endConnection(ctx, l.Connection); err != nil {
		return err
	}
	installMu.Lock()
	defer installMu.Unlock()
	return dropInstallation(a.Store, d.InstallationID)
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
// the installation's is disconnected, removed, and forgotten, one it does not hold is
// passed, and the installation's repositories are listed again, which a listing of
// more than one page needs, since it never says it is complete. The installation's
// tokens are dropped first, so the listing never reads with a token minted before the
// change, and so are its first listings kept, see [Adapter.sendFirst], which the change
// makes stale: one being read as they are dropped is sent and not kept, so the next try
// reads GitHub again.
func (a *Adapter) installationRepositories(ctx context.Context, d Delivery) error {
	if d.Action != "added" && d.Action != "removed" {
		return nil
	}
	a.forgetTokens(d.InstallationID)
	a.dropFirsts(d.InstallationID, "")
	var ev struct {
		Removed []struct {
			ID int64 `json:"id"`
		} `json:"repositories_removed"`
	}
	if err := json.Unmarshal(d.Body, &ev); err != nil {
		return Permanent(errors.New("the installation_repositories event is not JSON GitHub sends"))
	}
	var refs []string
	for _, r := range ev.Removed {
		ref := github.CollectionRef(r.ID)
		if ref == "" {
			continue
		}
		installation, ok, err := reachOf(a.Store, ref)
		if err != nil {
			return err
		}
		if ok && installation == d.InstallationID {
			refs = append(refs, ref)
		}
	}
	if err := a.disconnect(ctx, refs); err != nil {
		return err
	}
	for _, ref := range refs {
		if err := a.Store.Delete(nsRepositories, collectionKey(ref)); err != nil {
			return err
		}
	}
	return a.listRepositories(ctx, d.InstallationID)
}

// disconnect sends a disconnect for each collection. One Qory Apiary refuses for good is
// logged and passed; any other error stops it, to be tried again.
func (a *Adapter) disconnect(ctx context.Context, refs []string) error {
	for _, ref := range refs {
		err := a.Sink.Disconnect(ctx, contracts.SourcesDisconnect{Version: contracts.Version, CollectionRef: ref})
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
// for good, [github.ErrMintRefused], fails for good, so the change feed passes it. It
// waits for a pull of the collection that runs, and once it has sent everything, the
// next pull reads what changed from when it began. The listing is GraphQL's, which
// names a repository by owner/name, so the fill first reads that name by the
// collection's ref, the repository's id, [github.Lister.ReadRepository], and keeps it
// nowhere: a 404 there says the repository is deleted or out of the App's reach, as
// after a transfer to an account the installation is not on, never after a rename,
// which keeps its id, and fails for good as [github.ErrRepositoryGone]; any other
// failure of that read fails the fill as a failure of the listing would, to be tried
// again. A listing that finds the name naming another repository, or none, by then, as
// a rename or a transfer that lands between the two requests makes it, fails without
// sending anything, to be tried again, which reads the name again.
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
	repo, err := l.ReadRepository(ctx, id)
	if err == nil {
		err = l.ListOpenIssuesComplete(ctx, id, repo)
	}
	err = a.forgetOn401(installation, err)
	if errors.Is(err, github.ErrRepositoryGone) || errors.Is(err, github.ErrMintRefused) {
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
// [github.ErrMintRefused], fails it for good.
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
	if errors.Is(err, github.ErrMintRefused) {
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
