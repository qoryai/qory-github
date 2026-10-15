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
	// sleep waits d or until ctx is done; nil waits on a timer.
	sleep func(ctx context.Context, d time.Duration) error

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
// does no harm: every entry's action is one a repeat finds done. An answer that holds
// an entry serve cannot apply is refused whole, see [feed.step], and read again after
// the wait.
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

// first is s cut to at most n characters, on a character's boundary.
func first(s string, n int) string {
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
// other error stops the page, whose cursor is not kept, to be read again. A page that
// holds an entry serve does not know is refused whole, an [*unknownChange], before any
// of its entries is applied, and its cursor is not kept: Qory Apiary sends only the
// kinds and statuses of the contract's revision, which serve implements, so such an
// entry is Qory Apiary's defect, and passing it could lose what it says.
func (f *feed) step(ctx context.Context) error {
	cursor, err := f.store.Get(nsAdapter, keyCursor)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	page, err := f.apiary.Changes(ctx, string(cursor))
	if err != nil {
		return err
	}
	for _, ch := range page.Changes {
		if !known(ch) {
			return &unknownChange{after: string(cursor), kind: first(ch.Kind, maxLogged), status: first(ch.Status, maxLogged)}
		}
	}
	for _, ch := range page.Changes {
		err := f.apply(ctx, ch)
		if IsPermanent(err) {
			f.log.Error("a change of the feed failed, and is passed", slog.String("kind", ch.Kind), slog.String("error", err.Error()))
			continue
		}
		if err != nil {
			return err
		}
	}
	return f.store.Put(nsAdapter, keyCursor, []byte(page.Cursor), 0)
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
