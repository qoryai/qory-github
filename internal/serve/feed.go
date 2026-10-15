package serve

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// The change feed reader's waits: after an error, a wait that doubles from two seconds
// to a minute; and from the last request for the feed sent, a 429's retry among them,
// to the next, feedFloor at least, so a feed that answers at once with nothing new is
// not read more than once a second, and no two reads have the same timestamp and
// cursor, whose signature Qory Apiary would refuse as a replay. An answer serve cannot
// apply is logged once each unknownEvery at most, the lines held back counted.
const (
	feedFirstBackoff = 2 * time.Second
	feedMaxBackoff   = time.Minute
	feedFloor        = time.Second
	unknownEvery     = time.Minute
	// stuckFor is how long one entry may fail, not for good, before it is logged and
	// passed, so no entry stops the feed for ever.
	stuckFor = 24 * time.Hour
)

// feed reads Qory Apiary's change feed and applies its entries, after it has declared
// the adapter. One feed runs for each serve, and only one: the entries apply in the
// feed's order, and two readers would apply one entry twice at once, which could post
// a take in's comment twice, since each would look for it before either had posted it.
type feed struct {
	apiary    *Apiary
	adapter   *Adapter
	store     *store.Store
	publicURL string
	log       *slog.Logger
	// sleep waits d or until ctx is done; nil waits on a timer. now is the clock an
	// entry's failures are timed by; nil is time.Now.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time

	// failing is what the feed keeps of the page read after the cursor after, by the
	// entries' places in it: when each entry that failed, not for good, first failed,
	// and the entries passed, which a read of the same page again skips. down is when
	// the feed's reads began to fail, or zero. They are kept in memory alone, so a
	// restart times the entries from their next failures again.
	failing struct {
		after  string
		since  map[int]time.Time
		passed map[int]bool
		down   time.Time
	}

	once    sync.Once
	unknown *throttle
}

func (f *feed) wait(ctx context.Context, d time.Duration) error {
	if f.sleep != nil {
		return f.sleep(ctx, d)
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

// unknownLog is the throttle of the lines for answers serve cannot apply.
func (f *feed) unknownLog() *throttle {
	f.once.Do(func() {
		f.unknown = &throttle{every: unknownEvery, flush: func(dropped int) {
			f.log.LogAttrs(context.Background(), slog.LevelError, "answers of the change feed refused", slog.Int("refused_dropped", dropped))
		}}
	})
	return f.unknown
}

// run declares the adapter, then reads the feed until ctx is done. Qory Apiary holds a
// read while nothing follows the cursor, so the next read follows each answer as soon
// as feedFloor has passed since the last request for the feed was sent; an error waits
// longer, a wait that doubles. The cursor is kept in the store, and moves only once
// every entry of the page it ends is applied, or failed for good and logged, so an
// entry is never skipped by a stop or a restart, and one may be applied again, which
// does no harm: every entry's action is one a repeat finds done. An entry that fails,
// not for good, is read again after the wait, and passed and logged once it has failed
// for stuckFor, see [feed.step], so no entry stops the feed for ever. An answer that holds an entry
// serve cannot apply is refused whole, see [feed.step], and read again after the wait.
func (f *feed) run(ctx context.Context) {
	defer f.unknownLog().stop()
	backoff := feedFirstBackoff
	fail := func(what string, err error) bool {
		var u *unknownChange
		if errors.As(err, &u) {
			if ok, dropped := f.unknownLog().allow(); ok {
				attrs := []slog.Attr{slog.String("after", u.after), slog.String("kind", u.kind), slog.String("status", u.status)}
				if dropped > 0 {
					attrs = append(attrs, slog.Int("refused_dropped", dropped))
				}
				f.log.LogAttrs(ctx, slog.LevelError, "an answer of the change feed holds an entry serve does not know, so none of it is applied", attrs...)
			}
		} else {
			f.log.Error(what, slog.String("error", err.Error()))
		}
		if f.wait(ctx, backoff) != nil {
			return false
		}
		backoff = min(2*backoff, feedMaxBackoff)
		return true
	}
	for ctx.Err() == nil {
		err := f.apiary.Declare(ctx, f.publicURL)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !fail("declaring the adapter to Qory Apiary", err) {
			return
		}
	}
	backoff = feedFirstBackoff
	for ctx.Err() == nil {
		if last := f.apiary.lastChanges(); !last.IsZero() {
			if d := last.Add(feedFloor).Sub(f.apiary.now()); d > 0 {
				if f.wait(ctx, d) != nil {
					return
				}
			}
		}
		if err := f.step(ctx); err != nil {
			if ctx.Err() != nil || !fail("reading the change feed", err) {
				return
			}
			continue
		}
		backoff = feedFirstBackoff
	}
}

// maxLogged is the most characters of an entry's kind or status a line says.
const maxLogged = 64

// prefixOf is s cut to at most n characters, on a character's boundary.
func prefixOf(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}

// unknownChange is an answer of the feed that holds an entry of a kind, or a status of
// a known kind, that serve does not know: the cursor the answer was read after, and the
// entry's kind and status as Qory Apiary sent them, maxLogged characters of each.
type unknownChange struct {
	after, kind, status string
}

func (e *unknownChange) Error() string {
	return "reading the change feed: an answer holds an entry serve does not know, so none of it is applied"
}

// known is whether serve knows the entry's kind, and its status for a kind that has one.
func known(ch contracts.Change) bool {
	switch ch.Kind {
	case contracts.ChangeWorkItem:
		return ch.Status == github.StatusTakenIn || ch.Status == github.StatusUndone
	case contracts.ChangeCollection:
		return ch.Status == "linked" || ch.Status == "unlinked"
	case contracts.ChangeSync:
		return true
	}
	return false
}

// step reads one page of the feed after the cursor kept, applies its entries in order,
// and keeps the page's cursor. An entry that fails for good is logged and passed; any
// other error stops the page, whose cursor is not kept, to be read again.
//
// An entry that fails, not for good, is timed from its first failure: once it has
// failed for stuckFor, it is logged and passed too. The feed keeps, for the page read
// after the cursor, each entry's first failure and the entries passed, which a read
// of the same page again skips, so every entry of a page is timed and passed alone,
// and the page's cursor is kept once none is left; it forgets them when the cursor
// moves. A time the feed cannot be read, its read failing or its answer refused, does
// not count: the first failures are moved later by as long, so an outage of Qory
// Apiary passes no entry. All this is kept in memory alone, so a restart times the
// entries from their next failures again.
//
// A page that holds an entry serve does not know is refused whole, an
// [*unknownChange], before any of its entries is applied, and its cursor is not kept:
// Qory Apiary sends only the kinds and statuses of the contract's revision, which serve
// implements, so such an entry is Qory Apiary's defect, and passing it could lose what
// it says.
func (f *feed) step(ctx context.Context) error {
	cursor, err := f.store.Get(nsAdapter, keyCursor)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	page, err := f.apiary.Changes(ctx, string(cursor))
	if err != nil {
		f.feedDown()
		return err
	}
	for _, ch := range page.Changes {
		if !known(ch) {
			f.feedDown()
			return &unknownChange{after: string(cursor), kind: prefixOf(ch.Kind, maxLogged), status: prefixOf(ch.Status, maxLogged)}
		}
	}
	f.feedUp(string(cursor))
	for i, ch := range page.Changes {
		if f.failing.passed[i] {
			continue
		}
		err := f.apply(ctx, ch)
		if IsPermanent(err) {
			f.log.Error("a change of the feed failed, and is passed", slog.String("kind", ch.Kind), slog.String("error", err.Error()))
			f.failing.passed[i] = true
			continue
		}
		if err != nil {
			if f.failedFor(i) < stuckFor {
				return err
			}
			f.log.Error("a change of the feed has failed for a day, and is passed", slog.String("kind", ch.Kind), slog.String("error", err.Error()))
			f.failing.passed[i] = true
		}
	}
	if err := f.store.Put(nsAdapter, keyCursor, []byte(page.Cursor), 0); err != nil {
		return err
	}
	f.failing.after, f.failing.since, f.failing.passed = page.Cursor, map[int]time.Time{}, map[int]bool{}
	return nil
}

func (f *feed) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// feedDown notes that the feed could not be read, from now unless it is noted already.
func (f *feed) feedDown() {
	if f.failing.down.IsZero() {
		f.failing.down = f.clock()
	}
}

// feedUp notes that the page after the cursor after was read: the entries' first
// failures are moved later by as long as the feed could not be read, and forgotten,
// with the entries passed, when the page is another cursor's.
func (f *feed) feedUp(after string) {
	if f.failing.after != after || f.failing.since == nil {
		f.failing.after, f.failing.since, f.failing.passed = after, map[int]time.Time{}, map[int]bool{}
	}
	if !f.failing.down.IsZero() {
		d := f.clock().Sub(f.failing.down)
		for i, t := range f.failing.since {
			f.failing.since[i] = t.Add(d)
		}
		f.failing.down = time.Time{}
	}
}

// failedFor is how long the entry at index of the page read has failed, from its first
// failure, not counting the time the feed could not be read.
func (f *feed) failedFor(index int) time.Duration {
	now := f.clock()
	if _, ok := f.failing.since[index]; !ok {
		f.failing.since[index] = now
	}
	return now.Sub(f.failing.since[index])
}

// apply applies one entry of the feed, one [known] says serve knows; another fails for
// good. A collection's entry whose ref is not owner/name fails for good, before the
// store is written.
func (f *feed) apply(ctx context.Context, ch contracts.Change) error {
	switch ch.Kind {
	case contracts.ChangeWorkItem:
		if ch.Status != github.StatusTakenIn && ch.Status != github.StatusUndone {
			break
		}
		return f.adapter.applyChange(ctx, ch)
	case contracts.ChangeCollection:
		if _, err := repository(ch.CollectionRef); err != nil {
			return Permanent(err)
		}
		switch ch.Status {
		case "linked":
			if err := linkCollection(f.store, ch.CollectionRef); err != nil {
				return err
			}
			return f.adapter.fill(ctx, ch.CollectionRef)
		case "unlinked":
			return unlinkCollection(f.store, ch.CollectionRef)
		}
	case contracts.ChangeSync:
		interval := defaultSyncInterval
		if ch.Interval != nil {
			interval = max(*ch.Interval, minimumSyncInterval)
		}
		return f.store.Put(nsAdapter, keySyncInterval, []byte(strconv.Itoa(interval)), 0)
	}
	return Permanent(errors.New("the change is not one serve knows"))
}
