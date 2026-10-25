package serve

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// The pull's times. A pull reads what changed from pullOverlap before the last pull of
// the collection that finished without error began, so a change GitHub dates a little
// before a pull's start, as a clock that is off or a request under way when it began
// does, is read again. A collection's open issues are listed once each listEvery. The
// wait for the next round is cut into steps of pullCheck at most, each of which reads
// the sync interval again, so a new interval counts from the round that began last. A
// failure of the pull rounds is logged once each pullFailEvery at most, the lines held
// back counted. A pull that keeps failing is logged again once it has failed for
// pullStuckFor.
const (
	pullOverlap   = 5 * time.Minute
	listEvery     = 24 * time.Hour
	pullCheck     = time.Minute
	pullFailEvery = time.Minute
	pullStuckFor  = 24 * time.Hour
)

// errNotLinked stops a pull whose collection is no longer linked.
var errNotLinked = errors.New("the collection is not linked")

// pullMark is what the store keeps of a collection's pulls, in [nsPulls]: when the last
// pull that finished without error began, or the fill that linked it, and when the last
// listing of its open issues that finished without error began. A zero time is none.
type pullMark struct {
	Since  time.Time `json:"since"`
	Listed time.Time `json:"listed"`
}

// pulledOf is the collection's pullMark, zero when the store keeps none.
func pulledOf(st *store.Store, ref string) (pullMark, error) {
	var m pullMark
	b, err := st.Get(nsPulls, collectionKey(ref))
	if errors.Is(err, store.ErrNotFound) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return pullMark{}, errors.New("the store's entry for a collection's pulls is not one")
	}
	return m, nil
}

// keepPulled keeps the collection's pullMark.
func keepPulled(st *store.Store, ref string, m pullMark) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return st.Put(nsPulls, collectionKey(ref), b, 0)
}

// syncInterval is how often serve pulls from GitHub: the interval the change feed's last
// sync entry set, or the default when none did, never less than the minimum or more
// than the contract's maximum.
func syncInterval(st *store.Store) (time.Duration, error) {
	seconds := defaultSyncInterval
	b, err := st.Get(nsAdapter, keySyncInterval)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return defaultSyncInterval * time.Second, err
	default:
		if n, err := strconv.Atoi(string(b)); err == nil {
			seconds = n
		}
	}
	return time.Duration(min(max(seconds, minimumSyncInterval), maximumSyncInterval)) * time.Second, nil
}

// collectionTurn is the collection's turn: a fill or a pull of it holds the turn while
// it runs, so the two never run at once for one collection.
func (a *Adapter) collectionTurn(ref string) chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.turns == nil {
		a.turns = map[string]chan struct{}{}
	}
	turn, ok := a.turns[collectionKey(ref)]
	if !ok {
		turn = make(chan struct{}, 1)
		a.turns[collectionKey(ref)] = turn
	}
	return turn
}

// waitTurn takes the collection's turn, waiting while another holds it, and returns
// what gives it back; it returns ctx's error when ctx is done first.
func (a *Adapter) waitTurn(ctx context.Context, ref string) (func(), error) {
	turn := a.collectionTurn(ref)
	select {
	case turn <- struct{}{}:
		return func() { <-turn }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// takeTurn takes the collection's turn when no other holds it, and returns what gives
// it back.
func (a *Adapter) takeTurn(ref string) (func(), bool) {
	turn := a.collectionTurn(ref)
	select {
	case turn <- struct{}{}:
		return func() { <-turn }, true
	default:
		return nil, false
	}
}

func (a *Adapter) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// linkedSink is a pull's sink: it sends the collection's items and comments while the
// collection is linked, and stops the pull with errNotLinked once it is not, as the
// change feed, or Qory Apiary's 409 collection_not_linked to the collection's items,
// says. A request Qory Apiary refuses for good is logged and passed, as a webhook's is.
type linkedSink struct {
	github.Sink
	adapter *Adapter
	ref     string
}

// Items sends the items while the collection is linked.
func (s linkedSink) Items(ctx context.Context, req contracts.SourceItems) error {
	return s.send(func() error { return s.Sink.Items(ctx, req) })
}

// Comments sends the comments while the collection is linked.
func (s linkedSink) Comments(ctx context.Context, req contracts.SourceItemComments) error {
	return s.send(func() error { return s.Sink.Comments(ctx, req) })
}

func (s linkedSink) send(send func() error) error {
	ok, err := collectionLinked(s.adapter.Store, s.ref)
	if err != nil {
		return err
	}
	if !ok {
		return errNotLinked
	}
	err = send()
	if IsPermanent(err) {
		s.adapter.log().Error("the request is refused", slog.String("collection", s.ref), slog.String("error", err.Error()))
		return nil
	}
	return err
}

// puller pulls from GitHub what the webhooks missed, one for each serve, once the
// adapter is declared. Every sync interval, the one the change feed's last sync entry
// set, it begins a round: for each linked installation, the listing of its repositories,
// as the installation's events send it, and then a pull of each linked collection it
// reaches, see [puller.pull]. An installation's round runs apart from the others', so
// one that is slow or fails holds no other, and its collections are pulled one after
// another, each at a random moment in the first half of the interval, so many
// collections do not reach GitHub and Qory Apiary at once. An installation whose last
// round still runs passes the round. An installation GitHub answers 404 for under the
// App's token in two rounds in a row, with no sign between that GitHub holds it, is
// ended, as the webhook's deleted ends it, see [puller.installationGone]. A collection
// whose repository GitHub refuses a token for alone, and that the installation's list
// of repositories, read in full, no longer holds, in two rounds in a row, with no sign
// between that GitHub holds the repository, is disconnected, see [Adapter.dropRefused]
// and [presence]. A pull
// that fails is tried again at the next round; see [puller.report] for its lines: the
// first failure since it last passed, throttled with the rounds' other failures and
// those held back counted, unless GitHub answers that the repository is deleted or out
// of the App's reach, or redirects a request by its id, or refuses to mint a token for
// good, which is logged unthrottled; and one more once it has failed for a day.
type puller struct {
	adapter *Adapter
	store   *store.Store
	log     *slog.Logger
	// now is the clock, nil time.Now; sleep waits d or until ctx is done, nil on a
	// timer; jitter is a random duration in [0, d), nil math/rand's. began, when set,
	// is called as each round begins, with its start and interval.
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
	began  func(start time.Time, interval time.Duration)

	mu     sync.Mutex
	busy   map[int64]bool
	rounds sync.WaitGroup
	// replacing is the replaced connections whose listing a round has under way, see
	// [puller.listReplaced]; mu guards it.
	replacing map[string]bool

	once  sync.Once
	fails *throttle
	// failing is the failures of each target whose last pull or listing failed, by
	// the key of its line's attr, see [puller.report]; mu guards it.
	failing map[string]*failure
}

// presence is what the pull rounds count toward an installation's end and a
// collection's disconnect, and the signs between them that GitHub still holds the
// installation or the repository, which make a count start over: the adapter keeps it,
// see [Adapter.token], [reachSink], [Adapter.confirmGone] and [Adapter.delivered], so
// every path that asks GitHub, and every delivery of GitHub's webhook, sees it, and the
// rounds read it, see [puller.installationGone] and
// [puller.refused]. Each sign takes the next number of seq; each count keeps the number
// seq had as a round's read it rests on began, and a round decides whether its count is
// the second in a row, under mu, once that round's read answered: a sign that came after the
// count's number, before that decision, makes the count start over, and one that came
// while that round's read ran makes the next round's start over too. It is kept in
// memory alone, so a restart counts from the next round again. mu guards it.
type presence struct {
	mu  sync.Mutex
	seq uint64
	// installations and repositories are the number of the last sign of each
	// installation, by id, and of each repository, by its collection's ref: GitHub
	// answered 200 to the installation's check, which every mint of the adapter asks
	// first, see [github.Client.Checked]; it minted a token for the repository alone; a
	// listing of an installation's repositories named it; GitHub's webhook said it was
	// added to an installation, see [Adapter.installationRepositories]; or a delivery of
	// GitHub's webhook named it, but for the deliveries [Adapter.delivered] says are no
	// sign.
	installations map[int64]uint64
	repositories  map[string]uint64
	// gone is the installations whose last round GitHub answered 404 for at the check of
	// its listing, by id, with the number seq had as the first of the rounds in a row
	// that met it began, with no sign of the installation between: a second 404 whose
	// end fails keeps it, see [presence.goneAgain].
	gone map[int64]uint64
	// absent is the collections whose last pull GitHub refused a token for alone while
	// the installation's list of repositories, read in that round, no longer held the
	// repository: by ref, the installation whose list it was and the number seq had as
	// the read began.
	absent map[string]absence
}

// absence is a collection's count in [presence]: the installation whose list no longer
// held its repository, and the number seq had as the list's read began.
type absence struct {
	installation int64
	since        uint64
}

// at is the number of the last sign, which a round's read that begins now keeps.
func (s *presence) at() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// installationSeen notes a sign that GitHub holds the installation: it answered 200 to
// its check.
func (s *presence) installationSeen(installation int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if s.installations == nil {
		s.installations = map[int64]uint64{}
	}
	s.installations[installation] = s.seq
}

// repositorySeen notes a sign that GitHub holds the repository whose collection's ref is
// ref: it minted a token for the repository alone, a listing named it, GitHub's webhook
// said it was added to an installation, or a delivery of GitHub's webhook named it, see
// [Adapter.delivered].
func (s *presence) repositorySeen(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if s.repositories == nil {
		s.repositories = map[string]uint64{}
	}
	s.repositories[ref] = s.seq
}

// goneAgain notes GitHub's 404 to the check of the installation's listing in a round
// that began at since, see [presence.at], and says whether it is the second in a row: the
// last round's listing met one too, and no sign of the installation came after the first
// of the rounds in a row that met one began, up to now; a second whose end fails keeps
// that first round's number, so the next 404 is a second too. Otherwise this 404 is the
// first, and is kept as it.
func (s *presence) goneAgain(installation int64, since uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if began, ok := s.gone[installation]; ok && s.installations[installation] <= began {
		return true
	}
	if s.gone == nil {
		s.gone = map[int64]uint64{}
	}
	s.gone[installation] = since
	return false
}

// notGone forgets a 404 the installation's last round met at the check of its listing.
func (s *presence) notGone(installation int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.gone, installation)
}

// absentAgain notes that the collection ref's pull found its repository absent from the
// list of the installation installation, whose read began at since, and says whether it
// is the second in a row: the last pull found it absent from the same installation's
// list, and no sign of the repository came after that list's read began, up to now.
// Otherwise this absence is the first, and is kept as it.
func (s *presence) absentAgain(ref string, installation int64, since uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.absent[ref]; ok && a.installation == installation && s.repositories[ref] <= a.since {
		return true
	}
	if s.absent == nil {
		s.absent = map[string]absence{}
	}
	s.absent[ref] = absence{installation, since}
	return false
}

// setAbsent keeps that the collection ref's pull found its repository absent from the
// list of the installation installation, whose read began at since.
func (s *presence) setAbsent(ref string, installation int64, since uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.absent == nil {
		s.absent = map[string]absence{}
	}
	s.absent[ref] = absence{installation, since}
}

// notAbsent forgets an absence the collection ref's last pull found.
func (s *presence) notAbsent(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.absent, ref)
}

// forget forgets what it keeps of the installations not linked and of the collections
// not reached, by ref.
func (s *presence) forget(linked map[int64]bool, reached map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.installations {
		if !linked[id] {
			delete(s.installations, id)
		}
	}
	for id := range s.gone {
		if !linked[id] {
			delete(s.gone, id)
		}
	}
	for ref := range s.repositories {
		if !reached[ref] {
			delete(s.repositories, ref)
		}
	}
	for ref := range s.absent {
		if !reached[ref] {
			delete(s.absent, ref)
		}
	}
}

// failure is a target's failures: when the first of them came since the target last
// passed, and whether the line for a day of them is logged.
type failure struct {
	since time.Time
	told  bool
}

func (p *puller) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *puller) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if p.sleep != nil {
		return p.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *puller) random(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if p.jitter != nil {
		return p.jitter(d)
	}
	return rand.N(d)
}

// failLog is the throttle of the lines for what failed in the pull rounds: a pull, a
// listing of an installation's repositories, or a read of the store.
func (p *puller) failLog() *throttle {
	p.once.Do(func() {
		p.fails = &throttle{every: pullFailEvery, now: p.now, flush: func(dropped int) {
			p.log.LogAttrs(context.Background(), slog.LevelError, "failures of the pull rounds dropped", slog.Int("failed_dropped", dropped))
		}}
	})
	return p.fails
}

// failed logs, at most once each pullFailEvery, that what failed, with err and attrs.
func (p *puller) failed(what string, err error, attrs ...slog.Attr) {
	ok, dropped := p.failLog().allow()
	if !ok {
		return
	}
	attrs = append(attrs, slog.String("error", err.Error()))
	if dropped > 0 {
		attrs = append(attrs, slog.Int("failed_dropped", dropped))
	}
	p.log.LogAttrs(context.Background(), slog.LevelError, what, attrs...)
}

// interval is the sync interval, the default when the store cannot be read.
func (p *puller) interval() time.Duration {
	d, err := syncInterval(p.store)
	if err != nil {
		p.failed("reading the sync interval", err)
	}
	return d
}

// run begins a round at once, and the next each interval after the last began, until
// ctx is done; it then waits for the rounds that run to return.
func (p *puller) run(ctx context.Context) {
	defer p.failLog().stop()
	defer p.rounds.Wait()
	for ctx.Err() == nil {
		start := p.clock()
		interval := p.interval()
		if p.began != nil {
			p.began(start, interval)
		}
		p.round(ctx, start, interval)
		for {
			d := start.Add(p.interval()).Sub(p.clock())
			if d <= 0 {
				break
			}
			if p.wait(ctx, min(d, pullCheck)) != nil {
				return
			}
		}
	}
}

// pullTarget is a collection a round pulls, and when, from the round's start.
type pullTarget struct {
	ref    string
	offset time.Duration
}

// round begins a round, one for each linked installation whose last round is over, and
// returns without waiting for them.
func (p *puller) round(ctx context.Context, start time.Time, interval time.Duration) {
	var installations []int64
	err := p.store.Each(nsInstallations, func(key string, _ []byte) error {
		if id, err := strconv.ParseInt(key, 10, 64); err == nil && id > 0 {
			installations = append(installations, id)
		}
		return nil
	})
	if err != nil {
		p.failed("reading the linked installations", err)
		return
	}
	var keys []string
	if err := p.store.Each(nsCollections, func(key string, _ []byte) error {
		keys = append(keys, key)
		return nil
	}); err != nil {
		p.failed("reading the linked collections", err)
		return
	}
	spread := interval / 2
	targets := map[int64][]pullTarget{}
	for _, key := range keys {
		r, ok, err := reachRecord(p.store, key)
		if err != nil {
			p.failed("reading a collection's installation", err, slog.String("collection", key))
			continue
		}
		if !ok || !slices.Contains(installations, r.Installation) {
			p.log.Info("no linked installation is known to reach the collection, so it is not pulled", slog.String("collection", key))
			continue
		}
		targets[r.Installation] = append(targets[r.Installation], pullTarget{ref: r.Ref, offset: p.random(spread)})
	}
	p.forgetGone(installations, targets)
	p.listReplaced(ctx)
	for _, id := range installations {
		p.mu.Lock()
		if p.busy[id] {
			p.mu.Unlock()
			p.log.Info("the installation's last pull round still runs, so it passes this one", slog.Int64("installation", id))
			continue
		}
		if p.busy == nil {
			p.busy = map[int64]bool{}
		}
		p.busy[id] = true
		p.mu.Unlock()
		ts := targets[id]
		slices.SortFunc(ts, func(a, b pullTarget) int { return cmp.Compare(a.offset, b.offset) })
		p.rounds.Add(1)
		go func() {
			defer p.rounds.Done()
			defer func() {
				p.mu.Lock()
				delete(p.busy, id)
				p.mu.Unlock()
			}()
			p.installationRound(ctx, id, ts, start, p.random(spread))
		}()
	}
}

// listReplaced sends, without waiting for it, the last listing of each connection a
// connect replaced whose moment has come, see [Adapter.listReplaced], which [Connect]
// sends too, unless serve stopped meanwhile: so a restart settles it as well. One
// listing of a connection is under way at a time: a round that finds one under way
// leaves it.
func (p *puller) listReplaced(ctx context.Context) {
	var connections []string
	if err := p.store.Each(nsReplaced, func(key string, _ []byte) error {
		connections = append(connections, key)
		return nil
	}); err != nil {
		p.failed("reading the replaced connections", err)
		return
	}
	for _, connection := range connections {
		r, ok, err := replacedOf(p.store, connection)
		if err != nil || !ok || p.clock().Before(time.Unix(r.Return, 0).Add(returnSkew)) {
			continue
		}
		p.mu.Lock()
		if p.replacing[connection] {
			p.mu.Unlock()
			continue
		}
		if p.replacing == nil {
			p.replacing = map[string]bool{}
		}
		p.replacing[connection] = true
		p.mu.Unlock()
		p.rounds.Add(1)
		go func() {
			defer p.rounds.Done()
			defer func() {
				p.mu.Lock()
				delete(p.replacing, connection)
				p.mu.Unlock()
			}()
			if err := p.adapter.listFor(ctx, r.Installation, connection); err != nil {
				p.report(ctx, slog.String("connection", connection), "listing a replaced connection", err)
			}
		}()
	}
}

// installationRound is one installation's round: at begin from start, the listing of
// its repositories, with a listing token minted for the round, see
// [Adapter.forgetListingToken], so the installation is checked with GitHub each round,
// then a pull of each target, each at its offset from start or once the pull before it
// is over. An installation GitHub answers 404 for under the App's token, at the listing
// or at a pull, has nothing more of it pulled this round. Only the check of the round's
// listing counts toward its end: a 404 there, and again at the next round's listing,
// with no sign between that GitHub holds the installation, ends it, see
// [puller.installationGone]; a 404 at a pull is reported as the collection's failure,
// see [puller.report], and counts toward nothing. An installation GitHub answers as suspended,
// [github.ErrSuspended], at the listing or at a pull, as when GitHub suspends it after
// the listing passed, is reported, and no more of its targets is pulled this round;
// nothing of it changes, and the next round lists it again. Nothing holds back a
// listing the same as the one before, so a repository whose Issues were turned off or
// on since the last listing is sent with items false, or with no items, by the next
// round that lists the installation, see [github.Lister.ListRepositories].
func (p *puller) installationRound(ctx context.Context, installation int64, targets []pullTarget, start time.Time, begin time.Duration) {
	if p.wait(ctx, start.Add(begin).Sub(p.clock())) != nil {
		return
	}
	listing := slog.Int64("installation", installation)
	listed := &listedRepositories{}
	p.adapter.forgetListingToken(installation)
	since := p.adapter.presence.at()
	err := p.adapter.listRepositories(ctx, installation)
	if !errors.Is(err, github.ErrInstallationGone) {
		p.adapter.presence.notGone(installation)
	}
	switch {
	case errors.Is(err, github.ErrInstallationGone):
		p.installationGone(ctx, listing, installation, since, err)
		return
	case errors.Is(err, github.ErrSuspended):
		p.report(ctx, listing, "listing the installation's repositories", err)
		return
	case err != nil:
		p.report(ctx, listing, "listing the installation's repositories", err)
	default:
		p.passed(listing)
	}
	for _, t := range targets {
		if p.wait(ctx, start.Add(t.offset).Sub(p.clock())) != nil {
			return
		}
		if err := p.pull(ctx, t.ref, installation, listed); err != nil {
			p.report(ctx, slog.String("collection", t.ref), "pulling the collection", err)
			if errors.Is(err, github.ErrSuspended) || errors.Is(err, github.ErrInstallationGone) {
				return
			}
		}
	}
}

// installationGone is a round's answer to GitHub's 404 for the installation's check,
// GET /app/installations/{id} with the App's token, [github.ErrInstallationGone], err,
// at the listing of the round that began at since, see [presence.at]: the round pulls
// nothing more of the installation. The first 404 in a row is logged with a line that
// says so, and nothing more changes. The next round the installation runs, a second 404
// at its listing ends it, see [puller.ended], unless a sign that GitHub holds the
// installation came after the first round began: GitHub's 200 to the installation's
// check, on any path, a webhook's listing, a connect's, a fill or a write among them,
// see [presence]; that 404 is a first again. A 404 at a pull counts toward nothing, see
// [puller.installationRound]; any other answer to the round's listing, a 200, a
// suspension or another error, forgets the first, see [presence.notGone]. A round that
// does not run, as one the installation's last round still runs for, changes nothing.
func (p *puller) installationGone(ctx context.Context, attr slog.Attr, installation int64, since uint64, err error) {
	if !p.adapter.presence.goneAgain(installation, since) {
		p.log.Warn("GitHub returns 404 for the installation under the App's token, as for an installation deleted, so nothing more of it is pulled this round, and a 404 in the next round handles it as deleted unless GitHub shows the installation in between", attr, slog.String("error", err.Error()))
		return
	}
	p.ended(ctx, attr, installation)
}

// ended handles as deleted the installation, whose check returned 404 under the App's
// token, [github.ErrInstallationGone], in two rounds in a row, see
// [puller.installationGone], the way the webhook's deleted does, see
// [Adapter.endInstallation], with a line, and pulls none of its collections. Only
// GitHub's 404 to the installation's check brings it: a 401, as for an App key GitHub
// does not take, or a suspension never does. An installation that is no longer linked,
// as once the webhook or an earlier round ended it, is passed with no line, and so is
// one whose grant end serve sends again, or whose grant end failed with an error from
// Qory Apiary that a retry does not change, see [Adapter.endHeld], since the round
// changes nothing of it. A failure is reported, see [puller.report], and the 404s stay
// counted, so the next round's 404 tries again.
func (p *puller) ended(ctx context.Context, attr slog.Attr, installation int64) {
	held := p.adapter.endHeld(installation)
	connection, err := p.adapter.endInstallation(ctx, installation)
	if err != nil {
		p.report(ctx, attr, "ending a deleted installation's grant", err)
		return
	}
	p.adapter.presence.notGone(installation)
	p.passed(attr)
	if connection != "" && !held {
		p.log.Info("GitHub returns 404 for the installation under the App's token in two rounds in a row, as for an installation deleted, so serve handles it as deleted", slog.Int64("installation", installation), slog.String("connection", connection))
	}
}

// report logs a round's error, what failed of the target attr names: nothing for a
// stop; a line for a collection that is no longer linked; and for any other error, a
// line at the target's first failure since it last passed, then none while it keeps
// failing, round after round, and one more once it has failed for pullStuckFor. The
// first line is throttled, unless the error wraps [github.ErrRepositoryGone], as GitHub
// answers the read of the repository by its id 404 or 410, or a page of what changed
// in it 404, or redirects either request, a 301 or a 308, or [github.ErrMintRefused], as
// GitHub refuses to mint a token for good. A suspension, [github.ErrSuspended], is
// logged at its first failure alone, unthrottled, and never as a failure of a day,
// since a suspension is lifted by the account that made it. A repository GitHub refuses
// a token for alone that the installation's list of repositories still holds,
// [errStillListed], is logged at its first failure with a line that says so,
// unthrottled, see [Adapter.dropRefused]. One that the list no longer holds, in the
// first round in a row that finds so, [errAbsentOnce], is logged each time,
// unthrottled, and forgets the target's failures, since the next round either
// disconnects its collection, when it finds the same and no sign that GitHub holds the
// repository came between, or does not, and what it finds, a disconnect that fails
// among them, is logged as a first failure. Issues turned off for a
// repository on GitHub fail no pull, see [github.Lister.ListChanged]. The next round tries the target again
// whatever the error. The failures are timed in memory alone, so a restart times them from the next
// failure again.
func (p *puller) report(ctx context.Context, attr slog.Attr, what string, err error) {
	switch {
	case ctx.Err() != nil:
		return
	case errors.Is(err, errNotLinked):
		p.passed(attr)
		p.log.Info("the collection is not linked, so its pull stops", attr)
		return
	case errors.Is(err, errAbsentOnce):
		p.passed(attr)
		p.log.Warn(what+" failed: GitHub refuses a token for the repository alone, and the installation's list of repositories, read in full, no longer holds it, so its collection is disconnected if the next round finds the same and GitHub shows the repository nowhere in between", attr, slog.String("error", err.Error()))
		return
	}
	first, day := p.fail(attr)
	switch {
	case errors.Is(err, github.ErrSuspended):
		if first {
			p.log.Warn(what+" failed: GitHub answers that the installation is suspended, so its link stays, nothing more of it is pulled this round, and the next round tries again", attr, slog.String("error", err.Error()))
		}
	case day:
		p.log.Error(what+" has failed for a day, and the next round tries again", attr, slog.String("error", err.Error()))
	case !first:
	case errors.Is(err, errStillListed):
		p.log.Warn(what+" failed: GitHub refuses a token for the repository alone, yet the installation's list of repositories still holds it, so its collection is not disconnected, and the next round tries again", attr, slog.String("error", err.Error()))
	case errors.Is(err, github.ErrRepositoryGone) || errors.Is(err, github.ErrMintRefused):
		p.log.Warn(what+" failed: GitHub answers it is deleted or out of the App's reach, or redirects a request by its id, and the next round tries again", attr, slog.String("error", err.Error()))
	default:
		p.failed(what+" failed", err, attr)
	}
}

// fail notes a failure of the target attr names, and says whether it is the first
// since the target last passed, and whether it is the first once the target has failed
// for pullStuckFor.
func (p *puller) fail(attr slog.Attr) (first, day bool) {
	now := p.clock()
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.failing[attr.String()]
	if !ok {
		if p.failing == nil {
			p.failing = map[string]*failure{}
		}
		p.failing[attr.String()] = &failure{since: now}
		return true, false
	}
	if !f.told && now.Sub(f.since) >= pullStuckFor {
		f.told = true
		return false, true
	}
	return false, false
}

// passed forgets the failures of the target attr names.
func (p *puller) passed(attr slog.Attr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.failing, attr.String())
}

// forgetGone forgets the failures of the targets a round no longer has: installations
// no longer linked and collections no longer reached; the 404s counted for an
// installation no longer linked, see [puller.installationGone]; and the absence from
// the list kept for a collection no longer reached, see [puller.refused].
func (p *puller) forgetGone(installations []int64, targets map[int64][]pullTarget) {
	keep := map[string]bool{}
	linked := map[int64]bool{}
	reached := map[string]bool{}
	for _, id := range installations {
		linked[id] = true
		keep[slog.Int64("installation", id).String()] = true
		for _, t := range targets[id] {
			keep[slog.String("collection", t.ref).String()] = true
			reached[t.ref] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.failing {
		if !keep[key] {
			delete(p.failing, key)
		}
	}
	p.adapter.presence.forget(linked, reached)
}

// pull pulls one collection that the installation reaches, unless a fill or another
// pull of it runs, which sends it already. It sends the items and comments that
// changed since the last pull that finished without error began, less pullOverlap, see
// [github.Lister.ListChanged]; and, once each listEvery, the open issues and their
// comments, as the fill does. A collection that has no pull and no fill kept, as one
// linked before serve pulled, is listed as the fill lists it. The pull's start is kept
// once it has finished without error, and the listing's once it has; so a pull that
// failed, Qory Apiary's outage among the causes, is read again from the same time by
// the next. A pull whose token GitHub refuses to mint for the repository alone, a 422,
// [github.ErrRepositoryRefused], ends as [puller.refused] says: the collection is
// disconnected once the installation's list of repositories, read in full, no longer
// holds the repository in two rounds in a row, with no sign between that GitHub holds
// it, and its turn is held meanwhile, so no
// fill of it runs. A pull whose reads pass forgets an absence an earlier pull found,
// even when it then stops before keeping its start.
//
// The listing of open issues is the fill's, [github.Lister.ListOpenIssuesComplete]: it
// pages by GraphQL's cursor, which does not skip an item, so its last part says the
// listing is complete unless an item was skipped, and Qory Apiary closes every item of
// the collection it left out and did not hear of since it started. A listing that fails
// or is stopped before every open issue is read and sent sends no part that says it is
// complete; one that fails on the comments of its last part's items has sent that part
// already, complete, since comments are no part of complete. Either way its start is
// not kept, so the next pull lists again. A repository with no open issue sends one
// part without items that says the listing is complete. What changed is read through
// the repository's id, which needs no name. The listing is GraphQL's, which names a
// repository by owner/name: it takes the name the read of what changed got in the same
// run, and a pull that read no change, its collection's first, or whose read of what
// changed got a full_name that is not owner/name, reads the name first,
// [github.Lister.ReadRepository], which refuses one that is not owner/name; the name is
// kept nowhere. A listing that finds the name naming another repository, or none, by
// then fails without sending anything, and its start is not kept, so the next pull
// reads the name again and lists again.
//
// A repository with Issues turned off on GitHub passes, and both starts are kept,
// unless sending what was read before GitHub said so fails: the read of what changed
// reads no more once it learns that Issues are off, and returns the name without error,
// see [github.Lister.ListChanged]; the listing of open issues is left out, with a line
// logged, when the read of the name says Issues are off, and otherwise stops once
// GraphQL says they are, sending nothing when that is its first page, see
// [github.Lister.ListOpenIssuesComplete]. No part says the listing is complete, so
// Qory Apiary closes no item of the collection for it.
func (p *puller) pull(ctx context.Context, ref string, installation int64, listed *listedRepositories) error {
	a := p.adapter
	id, err := repositoryID(ref)
	if err != nil {
		return err
	}
	done, ok := a.takeTurn(ref)
	if !ok {
		p.log.Info("a fill or another pull of the collection runs, so it is not pulled this round", slog.String("collection", ref))
		return nil
	}
	defer done()
	if ok, err := collectionLinked(p.store, ref); err != nil || !ok {
		return err
	}
	mark, err := pulledOf(p.store, ref)
	if err != nil {
		return err
	}
	start := p.clock()
	l := github.Lister{
		Client: a.GitHub,
		Pacer:  a.pacer(installation),
		Token:  func(ctx context.Context) (string, error) { return a.token(ctx, installation, id, "read") },
		Slug:   a.Slug,
		Sink:   linkedSink{Sink: a.Sink, adapter: a, ref: ref},
		Logf:   a.logf,
		LogCut: a.logCut,
	}
	next := pullMark{Since: start, Listed: mark.Listed}
	// repo is the repository's owner/name as the read of what changed got it, which the
	// listing of open issues takes, or zero when that read did not run or GitHub's name
	// is not owner/name, and the listing reads it first.
	var repo github.Repository
	if !mark.Since.IsZero() {
		repo, err = l.ListChanged(ctx, id, mark.Since.Add(-pullOverlap))
		if err := a.forgetOn401(installation, err); err != nil {
			return p.refused(ctx, ref, id, installation, listed, err)
		}
	}
	if mark.Since.IsZero() || mark.Listed.IsZero() || start.Sub(mark.Listed) >= listEvery {
		issuesOn := true
		if repo == (github.Repository{}) {
			repo, issuesOn, err = l.ReadRepository(ctx, id)
			if err := a.forgetOn401(installation, err); err != nil {
				return p.refused(ctx, ref, id, installation, listed, err)
			}
		}
		if issuesOn {
			if err := a.forgetOn401(installation, l.ListOpenIssuesComplete(ctx, id, repo)); err != nil {
				return p.refused(ctx, ref, id, installation, listed, err)
			}
		} else {
			a.issuesOff(ref)
		}
		next.Listed = start
	}
	// GitHub read the repository with its token, so an absence an earlier pull found is
	// forgotten, whatever comes after.
	p.adapter.presence.notAbsent(ref)
	// The collection may have been unlinked after the last request was sent.
	if ok, err := collectionLinked(p.store, ref); err != nil || !ok {
		return err
	}
	if err := keepPulled(p.store, ref, next); err != nil {
		return err
	}
	p.passed(slog.String("collection", ref))
	return nil
}

// refused is the error of a pull of the collection ref, the repository whose id is id,
// that failed with err: err itself, unless GitHub answered 422 to a token for the
// repository alone, [github.ErrRepositoryRefused], when [Adapter.dropRefused] decides
// whether the collection is disconnected, with the round's read of the installation's
// list, listed, and its error, or nil once it is, or is no longer the installation's,
// which passes the collection. The collection's pull keeps, with
// the installation, whether this one found it absent for the next: it does when the
// list no longer holds it and it is not disconnected, and an absence the list of
// another installation found counts as none, as does one after which a sign came that
// GitHub holds the repository, on any path, up to the decision: a token minted for it
// alone, a listing of the installation's repositories that names it, GitHub's webhook
// saying it was added to an installation, or a delivery of GitHub's webhook that names
// it, but for the repository event's deleted and transferred and
// installation_repositories' removed, see [presence]. A list that holds
// it, a list that fails, and a pull whose token GitHub refuses otherwise, or whose read
// fails after GitHub minted its token, forget it; so does a pull whose reads pass, see
// [puller.pull]. Only a round's pull finds an absence: no other path counts toward a
// disconnect.
func (p *puller) refused(ctx context.Context, ref string, id, installation int64, listed *listedRepositories, err error) error {
	if !errors.Is(err, github.ErrRepositoryRefused) {
		p.adapter.presence.notAbsent(ref)
		return err
	}
	absent, err := p.adapter.dropRefused(ctx, ref, id, installation, listed, err)
	if absent {
		p.adapter.presence.setAbsent(ref, installation, listed.since)
	} else {
		p.adapter.presence.notAbsent(ref)
	}
	if err != nil {
		return err
	}
	p.passed(slog.String("collection", ref))
	return nil
}

// reachRecord is what the store keeps of the repository whose key is key, or false when
// it keeps none.
func reachRecord(st *store.Store, key string) (reach, bool, error) {
	b, err := st.Get(nsRepositories, key)
	if errors.Is(err, store.ErrNotFound) {
		return reach{}, false, nil
	}
	if err != nil {
		return reach{}, false, err
	}
	var r reach
	if err := json.Unmarshal(b, &r); err != nil || r.Installation <= 0 || r.Ref == "" {
		return reach{}, false, errors.New("the store's entry for a repository is not one")
	}
	return r, true, nil
}
