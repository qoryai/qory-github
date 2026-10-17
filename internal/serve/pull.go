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
// round still runs passes the round. A pull that fails is tried again at the next round;
// see [puller.report] for its lines: the first failure since it last passed, throttled
// with the rounds' other failures and those held back counted, unless GitHub answers
// that the repository is deleted or out of the App's reach, or redirects a request by
// its id, or refuses to mint a token for good, which is logged unthrottled; and one more
// once it has failed for a day.
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
// its repositories, then a pull of each target, each at its offset from start or once
// the pull before it is over.
func (p *puller) installationRound(ctx context.Context, installation int64, targets []pullTarget, start time.Time, begin time.Duration) {
	if p.wait(ctx, start.Add(begin).Sub(p.clock())) != nil {
		return
	}
	listing := slog.Int64("installation", installation)
	if err := p.adapter.listRepositories(ctx, installation); err != nil {
		p.report(ctx, listing, "listing the installation's repositories", err)
	} else {
		p.passed(listing)
	}
	for _, t := range targets {
		if p.wait(ctx, start.Add(t.offset).Sub(p.clock())) != nil {
			return
		}
		if err := p.pull(ctx, t.ref, installation); err != nil {
			p.report(ctx, slog.String("collection", t.ref), "pulling the collection", err)
		}
	}
}

// report logs a round's error, what failed of the target attr names: nothing for a
// stop; a line for a collection that is no longer linked; and for any other error, a
// line at the target's first failure since it last passed, then none while it keeps
// failing, round after round, and one more once it has failed for pullStuckFor. The
// first line is throttled, unless GitHub answers that the repository is deleted or out
// of the App's reach, or redirects a request by its id, or refuses to mint a token for
// good. The next round tries the target again whatever the error. The failures are
// timed in memory alone, so a restart times them from the next failure again.
func (p *puller) report(ctx context.Context, attr slog.Attr, what string, err error) {
	switch {
	case ctx.Err() != nil:
		return
	case errors.Is(err, errNotLinked):
		p.passed(attr)
		p.log.Info("the collection is not linked, so its pull stops", attr)
		return
	}
	first, day := p.fail(attr)
	switch {
	case day:
		p.log.Error(what+" has failed for a day, and the next round tries again", attr, slog.String("error", err.Error()))
	case !first:
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
// no longer linked and collections no longer reached.
func (p *puller) forgetGone(installations []int64, targets map[int64][]pullTarget) {
	keep := map[string]bool{}
	for _, id := range installations {
		keep[slog.Int64("installation", id).String()] = true
		for _, t := range targets[id] {
			keep[slog.String("collection", t.ref).String()] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.failing {
		if !keep[key] {
			delete(p.failing, key)
		}
	}
}

// pull pulls one collection that the installation reaches, unless a fill or another
// pull of it runs, which sends it already. It sends the items and comments that
// changed since the last pull that finished without error began, less pullOverlap, see
// [github.Lister.ListChanged]; and, once each listEvery, the open issues and their
// comments, as the fill does. A collection that has no pull and no fill kept, as one
// linked before serve pulled, is listed as the fill lists it. The pull's start is kept
// once it has finished without error, and the listing's once it has; so a pull that
// failed, Qory Apiary's outage among the causes, is read again from the same time by
// the next.
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
func (p *puller) pull(ctx context.Context, ref string, installation int64) error {
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
			return err
		}
	}
	if mark.Since.IsZero() || mark.Listed.IsZero() || start.Sub(mark.Listed) >= listEvery {
		if repo == (github.Repository{}) {
			repo, err = l.ReadRepository(ctx, id)
			if err := a.forgetOn401(installation, err); err != nil {
				return err
			}
		}
		if err := a.forgetOn401(installation, l.ListOpenIssuesComplete(ctx, id, repo)); err != nil {
			return err
		}
		next.Listed = start
	}
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
