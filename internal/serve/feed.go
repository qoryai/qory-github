package serve

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// The change feed reader's waits: after an error, a wait that doubles from two seconds
// to a minute; and between two reads, feedFloor at least, so a feed that answers at
// once with nothing new is not read more than once a second, and no two reads have the
// same timestamp and cursor, whose signature Qory Apiary would refuse as a replay.
const (
	feedFirstBackoff = 2 * time.Second
	feedMaxBackoff   = time.Minute
	feedFloor        = time.Second
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
	// sleep waits d or until ctx is done; nil waits on a timer. now is the clock; nil
	// is time.Now.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
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

func (f *feed) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// run declares the adapter, then reads the feed until ctx is done. Qory Apiary holds a
// read while nothing follows the cursor, so the next read follows each answer at once;
// only an error waits. The cursor is kept in the store, and moves only once every
// entry of the page it ends is applied, or failed for good and logged, so an entry is
// never skipped by a stop or a restart, and one may be applied again, which does no
// harm: every entry's action is one a repeat finds done.
func (f *feed) run(ctx context.Context) {
	backoff := feedFirstBackoff
	fail := func(what string, err error) bool {
		f.log.Error(what, slog.String("error", err.Error()))
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
	var last time.Time
	for ctx.Err() == nil {
		if d := last.Add(feedFloor).Sub(f.clock()); d > 0 {
			if f.wait(ctx, d) != nil {
				return
			}
		}
		last = f.clock()
		if err := f.step(ctx); err != nil {
			if ctx.Err() != nil || !fail("reading the change feed", err) {
				return
			}
			continue
		}
		backoff = feedFirstBackoff
	}
}

// step reads one page of the feed after the cursor kept, applies its entries in order,
// and keeps the page's cursor. An entry that fails for good is logged and passed; any
// other error stops the page, whose cursor is not kept, to be read again.
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

// apply applies one entry of the feed. An entry of a kind or a status serve does not
// know is skipped and logged.
func (f *feed) apply(ctx context.Context, ch contracts.Change) error {
	switch ch.Kind {
	case contracts.ChangeWorkItem:
		if ch.Status != github.StatusTakenIn && ch.Status != github.StatusUndone {
			break
		}
		return f.adapter.applyChange(ctx, ch)
	case contracts.ChangeCollection:
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
	f.log.Info("a change of the feed is not one serve knows, and is skipped", slog.String("kind", ch.Kind), slog.String("status", ch.Status))
	return nil
}
