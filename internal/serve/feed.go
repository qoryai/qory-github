package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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
	// passed, so no entry stops the feed for ever: stuckFor of failures, the time that
	// counts as down left out, or 2*stuckFor since its first failure, whichever ends
	// first, see [retriesEnded].
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
	// keepInterval keeps the interval of a sync entry, in seconds; nil puts it in the
	// store.
	keepInterval func(seconds int) error
	// declared, when set, is closed once the adapter is declared.
	declared chan struct{}

	// failing is what the feed keeps of the page read after the cursor after: the
	// state of each entry the feed has tried, by its place in the page, see
	// [entryState]. down is when the feed's reads began to fail, or zero; allFailed
	// is when the last step in which every entry tried failed ended, or zero. entries
	// has at most one key for each entry of that one page, and a page is at most
	// maxChangesAnswer bytes. They are kept in memory alone, so a restart applies the
	// page's entries again and times them from their next failures.
	failing struct {
		after     string
		entries   map[int]*entryState
		down      time.Time
		allFailed time.Time
	}

	// grantsRead is whether the page being applied has read Qory Apiary's copy of the
	// grants already, see [feed.apply].
	grantsRead bool

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

// run declares the adapter, without setup_url, since a feed is read only once an App
// is in use, then reads Qory Apiary's copy of the grants, see [Adapter.syncGrants],
// then reads the feed until ctx is done. A declaration or a read of the grants that
// fails is tried again after a wait that doubles. Qory Apiary holds a
// read while nothing follows the cursor, so the next read follows each answer as soon
// as feedFloor has passed since the last request for the feed was sent; an error waits
// longer, a wait that doubles. The cursor is kept in the store, and moves only once
// every entry of the page it ends is applied, or failed for good and logged, so an
// entry is never skipped by a stop or a restart, and one may be applied again, which
// does no harm: every entry's action is one a repeat finds done, a comment's post among
// them, see [github.Client.PostComment]. An entry that fails, not for good, is applied
// again after the wait, while the entries after it that do not wait for it apply, see
// [feed.step]; it is passed and logged once its retries end, see [retriesEnded], so no
// entry stops the feed for ever; a comment entry is reported as not posted first, see
// [feed.report]. A response that contains an entry serve cannot apply is rejected
// whole, see [feed.step], and read again after the wait.
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
		err := f.apiary.Declare(ctx, f.publicURL, "")
		if err == nil {
			if f.declared != nil {
				close(f.declared)
			}
			break
		}
		if ctx.Err() != nil || !fail("declaring the adapter to Qory Apiary", err) {
			return
		}
	}
	backoff = feedFirstBackoff
	for ctx.Err() == nil {
		err := f.adapter.syncGrants(ctx)
		if err == nil {
			break
		}
		if IsPermanent(err) {
			f.log.Error("reading the grants from Qory Apiary failed, and is passed", slog.String("error", err.Error()))
			break
		}
		if ctx.Err() != nil || !fail("reading the grants from Qory Apiary", err) {
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
	case contracts.ChangeComment:
		return true
	case contracts.ChangeCollection, contracts.ChangeGrant:
		return ch.Status == "linked" || ch.Status == "unlinked"
	case contracts.ChangeSync:
		return true
	}
	return false
}

// step reads one page of the feed after the cursor kept, applies its entries in order,
// and keeps the page's cursor once every entry is done. An entry that fails for good
// is logged and passed; one that fails otherwise is not done, and the page's cursor is
// not kept, so the next step reads the page again, and a restart applies it again. A
// comment entry whose comment a retry cannot post is reported to Qory Apiary as not
// posted, with the reason, before it is passed, see [feed.comment]. The error of a
// step that leaves an entry not done is the first error of the step, with the count
// of the other entries that failed in it, see [failures].
//
// An entry that is not done does not stop the page: the entries after it apply,
// except those that wait for it, see [notDone.waits], so a work item's or a comment's
// entries apply in the feed's order for each item. The feed keeps, for the page read
// after the cursor, each entry's first failure and whether it is done, see
// [entryState]; a read of the same page again skips the entries done, and the feed
// forgets them all when the cursor moves. The page read again contains the entries
// Qory Apiary has added to the feed since, up to the page's limit, so they apply too.
// A step stops when ctx is done, before the next entry. A restart applies the done
// entries again, which does no harm, see [feed.run].
//
// An entry that fails, not for good, is timed from its first failure: once its retries
// end, after stuckFor of failures or 2*stuckFor since the first failure, see
// [retriesEnded], it is logged and passed too, and the line has the limit that ended
// them. A comment entry is reported first, with the reason unreachable, or with the
// reason of a report that failed before, see [reportPending]; a report that fails, not
// permanently, leaves the entry not done, so the report is sent again. Once each limit
// has passed by one more stuckFor, a failed report is logged once, with the comment_id
// and the reason, and the entry is passed with no report, so a report that keeps
// failing keeps the cursor for one more day at most.
// A time the feed cannot be read, its read failing or its response rejected, counts
// toward neither limit: the first failures are moved later by as long, so an outage
// that stops the feed's reads passes no entry. The time after a step in which 2 or
// more entries failed and none applied, up to the next step, counts toward 2*stuckFor
// since the first failure alone, so an outage of GitHub shorter than 2*stuckFor does
// not pass the first entry of every item at once. The time after a step in which only
// one entry failed, or an entry applied, counts toward both. All this is kept in
// memory alone, so a restart times the entries from their next failures again.
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
	f.grantsRead = false
	var errs []error
	open := newNotDone()
	applied := false
	for i, ch := range page.Changes {
		state := f.state(i, ch)
		if state.done {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if open.waits(ch) {
			open.add(ch)
			continue
		}
		ok, err := f.entry(ctx, state, ch)
		if err != nil {
			errs = append(errs, err)
			open.add(ch)
			continue
		}
		applied = applied || ok
		state.done = true
	}
	if len(errs) > 0 {
		if !applied && len(errs) >= 2 {
			// Every entry tried failed, as in an outage of GitHub, which leaves the
			// feed's reads alone: the time to the next step does not count toward
			// stuckFor of failures, see [feed.feedUp].
			if f.failing.allFailed.IsZero() {
				f.failing.allFailed = f.clock()
			}
		}
		return failures(errs)
	}
	if err := f.store.Put(nsAdapter, keyCursor, []byte(page.Cursor), 0); err != nil {
		return err
	}
	f.failing.after, f.failing.entries = page.Cursor, map[int]*entryState{}
	return nil
}

// entryState is what the feed keeps of an entry of the page read: its kind, status,
// ref and comment_id, which identify it; when it first failed, not for good, or zero,
// as first and as since, which [feed.feedUp] moves later; and whether
// it is done, applied or passed. A collection's entry has its collection_ref as its
// ref, and a grant's its grant_ref.
type entryState struct {
	kind, status, ref, commentID string
	first, since                 time.Time
	done                         bool
}

// entryRef is the ref that identifies ch in its [entryState].
func entryRef(ch contracts.Change) string {
	switch ch.Kind {
	case contracts.ChangeCollection:
		return ch.CollectionRef
	case contracts.ChangeGrant:
		return ch.GrantRef
	}
	return ch.Ref
}

// state is what the feed keeps of ch, the entry at index i of the page read: a new
// state when the feed keeps none for that place, or one of another entry, as when
// the page read again has other entries there.
func (f *feed) state(i int, ch contracts.Change) *entryState {
	s := f.failing.entries[i]
	if s == nil || s.kind != ch.Kind || s.status != ch.Status || s.ref != entryRef(ch) || s.commentID != ch.CommentID {
		s = &entryState{kind: ch.Kind, status: ch.Status, ref: entryRef(ch), commentID: ch.CommentID}
		f.failing.entries[i] = s
	}
	return s
}

// failures is the error of a step whose entries failed with errs, at least one: the
// first error, and the count of the others, so the error stays one entry's long.
func failures(errs []error) error {
	switch n := len(errs) - 1; n {
	case 0:
		return errs[0]
	case 1:
		return fmt.Errorf("%w; and 1 more entry failed", errs[0])
	default:
		return fmt.Errorf("%w; and %d more entries failed", errs[0], n)
	}
}

// notDone are the entries of a page that are not done, read so far: the refs of the
// work item and comment entries; the repositories, by id, of those entries and of the
// collection entries; whether a grant entry is among them, whether a sync entry is,
// and whether any entry other than a sync entry is. Each map has at most one key for
// each entry of the page.
type notDone struct {
	refs, itemRepos, collections map[string]bool
	grant, any, sync             bool
}

func newNotDone() *notDone {
	return &notDone{refs: map[string]bool{}, itemRepos: map[string]bool{}, collections: map[string]bool{}}
}

// itemRepository is the repository id of an item's ref, the part before #.
func itemRepository(ref string) string {
	repo, _, _ := strings.Cut(ref, "#")
	return repo
}

// waits is whether ch waits for an earlier entry of the page that is not done, so the
// entries apply in the feed's order wherever one reads what another writes:
//   - A work item's or a comment's entry reads the reach of its repository, and writes
//     on GitHub alone. It waits for an entry with the same ref, so one item's entries
//     keep their order, and for a collection entry of its repository.
//   - A collection entry writes the link and the pull mark of its collection_ref, and
//     its fill reads the reach of that repository. It waits for any entry of that
//     repository, and no other repository's entry waits for it.
//   - A grant entry reads Qory Apiary's copy of the grants, which can drop the links
//     and the reach of any repository, see [Adapter.syncGrants]. It waits for every
//     earlier entry, and every later entry except a sync entry waits for it.
//   - A sync entry writes the sync interval alone, which only the pulls read, see
//     [syncInterval]. It waits for an earlier sync entry, so the last one sets the
//     interval, and only a later sync entry waits for it.
func (p *notDone) waits(ch contracts.Change) bool {
	switch ch.Kind {
	case contracts.ChangeSync:
		return p.sync
	case contracts.ChangeGrant:
		return p.any
	case contracts.ChangeCollection:
		return p.grant || p.itemRepos[ch.CollectionRef] || p.collections[ch.CollectionRef]
	}
	return p.grant || p.refs[ch.Ref] || p.collections[itemRepository(ch.Ref)]
}

// add adds ch to the entries not done.
func (p *notDone) add(ch contracts.Change) {
	switch ch.Kind {
	case contracts.ChangeSync:
		p.sync = true
		return
	case contracts.ChangeGrant:
		p.grant = true
	case contracts.ChangeCollection:
		p.collections[ch.CollectionRef] = true
	default:
		p.refs[ch.Ref] = true
		p.itemRepos[itemRepository(ch.Ref)] = true
	}
	p.any = true
}

// entry applies ch, an entry of the page read whose state is state. It returns a nil
// error once ch is done, and true when ch is applied rather than passed and logged.
// Any other error leaves ch to be applied again on the next read of the page, see
// [feed.step].
func (f *feed) entry(ctx context.Context, state *entryState, ch contracts.Change) (bool, error) {
	err := f.apply(ctx, ch)
	if err == nil {
		return true, nil
	}
	if IsPermanent(err) {
		f.log.Error("a change of the feed failed, and is passed", slog.String("kind", ch.Kind), slog.String("error", err.Error()))
		return false, nil
	}
	failed, since := f.failedFor(state)
	limit := retriesEnded(failed, since, 0)
	if limit == "" {
		return false, err
	}
	if ch.Kind == contracts.ChangeComment {
		reason := github.ReasonUnreachable
		// The cause's text starts with the fix for its reason: a pending
		// report's text has it already, and any other error gets it here.
		var cause error = &github.CommentRefused{Reason: reason, Err: err}
		var p *reportPending
		if errors.As(err, &p) {
			reason, cause = p.reason, err
		}
		rerr := f.report(ctx, ch.CommentID, reason, cause)
		if !IsPermanent(rerr) {
			reportLimit := retriesEnded(failed, since, stuckFor)
			if reportLimit == "" {
				return false, rerr
			}
			f.log.Error("check that Qory Apiary returns 204 for failure reports: one failed for a day or more; the entry is passed", slog.String("comment_id", ch.CommentID), slog.String("reason", reason), slog.String("error", rerr.Error()), slog.String("retries_ended", reportLimit))
			return false, nil
		}
		err = rerr
	}
	f.log.Error("a change of the feed kept failing until its retries ended, and is passed", slog.String("kind", ch.Kind), slog.String("error", err.Error()), slog.String("retries_ended", limit))
	return false, nil
}

// retriesEnded is the limit that ends the retries of an entry, as the line logged
// shows it, or "" while neither limit has passed. failed is how long the entry has
// failed without the time that counts as down, and since how long ago it first failed
// without the time the feed could not be read, see [feed.feedUp].
// The limits are stuckFor+more of failed and 2*stuckFor+more of since. The second ends
// the retries of entries that fail while nothing applies, as when 2 issues always
// fail, and passes none in an outage of GitHub shorter than 2*stuckFor.
func retriesEnded(failed, since, more time.Duration) string {
	switch {
	case failed >= stuckFor+more:
		return fmt.Sprintf("%s of failures, outages left out", hoursOf(stuckFor+more))
	case since >= 2*stuckFor+more:
		return fmt.Sprintf("%s since the first failure, feed read outages left out", hoursOf(2*stuckFor+more))
	}
	return ""
}

// hoursOf is d in whole hours, as "48 hours".
func hoursOf(d time.Duration) string {
	return strconv.Itoa(int(d/time.Hour)) + " hours"
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

// feedUp notes that the page after the cursor after was read, and forgets the
// entries' states when the page is another cursor's. The entries' first failures, both
// first and since, are moved later by as long as the feed could not be read; since is
// moved later by as long as the feed could not be read or every entry tried failed,
// the two times counted once where they overlap, see [retriesEnded].
func (f *feed) feedUp(after string) {
	if f.failing.after != after || f.failing.entries == nil {
		f.failing.after, f.failing.entries = after, map[int]*entryState{}
	}
	now := f.clock()
	var unread, failed time.Duration
	if !f.failing.down.IsZero() {
		unread = now.Sub(f.failing.down)
	}
	if !f.failing.allFailed.IsZero() {
		failed = now.Sub(f.failing.allFailed)
	}
	for _, s := range f.failing.entries {
		if !s.since.IsZero() {
			s.since = s.since.Add(max(unread, failed))
			s.first = s.first.Add(unread)
		}
	}
	f.failing.down, f.failing.allFailed = time.Time{}, time.Time{}
}

// failedFor is how long the entry whose state is state has failed, from its first
// failure: without the time that counts as down, and without the time the feed could
// not be read alone, see [feed.feedUp].
func (f *feed) failedFor(state *entryState) (failed, since time.Duration) {
	now := f.clock()
	if state.since.IsZero() {
		state.since, state.first = now, now
	}
	return now.Sub(state.since), now.Sub(state.first)
}

// apply applies one entry of the feed, one [known] says serve knows; another fails for
// good. A comment entry posts its comment, see [feed.comment]. A collection's entry
// whose ref is not a repository's id fails for good, before the store is written. A
// grant's entry, linked or unlinked, reads Qory Apiary's copy of the grants again, once
// for each page, see [Adapter.syncGrants]: the copy wins, so the entries after the
// first of a page find it read; one whose grant_ref is not an installation's id, or
// whose connection_id is not a connection's, fails for good.
func (f *feed) apply(ctx context.Context, ch contracts.Change) error {
	switch ch.Kind {
	case contracts.ChangeWorkItem:
		if ch.Status != github.StatusTakenIn && ch.Status != github.StatusUndone {
			break
		}
		return f.adapter.applyChange(ctx, ch)
	case contracts.ChangeComment:
		return f.comment(ctx, ch)
	case contracts.ChangeCollection:
		if _, err := repositoryID(ch.CollectionRef); err != nil {
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
	case contracts.ChangeGrant:
		if !installationShape.MatchString(ch.GrantRef) || !connectionShape.MatchString(ch.ConnectionID) {
			return Permanent(errors.New("the grant's entry has no installation's id as grant_ref, or no connection's id"))
		}
		if f.grantsRead {
			return nil
		}
		if err := f.adapter.syncGrants(ctx); err != nil {
			return err
		}
		f.grantsRead = true
		return nil
	case contracts.ChangeSync:
		interval := defaultSyncInterval
		if ch.Interval != nil {
			interval = min(max(*ch.Interval, minimumSyncInterval), maximumSyncInterval)
		}
		if f.keepInterval != nil {
			return f.keepInterval(interval)
		}
		return f.store.Put(nsAdapter, keySyncInterval, []byte(strconv.Itoa(interval)), 0)
	}
	return Permanent(errors.New("the change is not one serve knows"))
}

// comment posts the comment of a comment entry, see [Adapter.applyComment]. When a
// retry cannot post the comment, a [*github.CommentRefused], it reports the comment to
// Qory Apiary as not posted, with the error's reason, see [feed.report], before the
// entry is passed.
func (f *feed) comment(ctx context.Context, ch contracts.Change) error {
	err := f.adapter.applyComment(ctx, ch)
	var refused *github.CommentRefused
	if !errors.As(err, &refused) {
		return err
	}
	return f.report(ctx, ch.CommentID, refused.Reason, err)
}

// report sends Qory Apiary the failure report of the comment entry with commentID, for
// reason, after cause, the post's failure, see [Apiary.ChangesFailed]. Sent, or failed
// permanently, as with Qory Apiary's 400 or 403, it is a [Permanent] error, so the feed
// logs the entry and passes it. A report that fails otherwise is a [*reportPending],
// which may pass, so the page stays and the entry is posted again, until each limit of
// its retries has passed by one more stuckFor, see [feed.step].
func (f *feed) report(ctx context.Context, commentID, reason string, cause error) error {
	err := f.apiary.ChangesFailed(ctx, contracts.ChangesFailed{Version: contracts.Version, CommentID: commentID, Reason: reason})
	switch {
	case err == nil:
		return Permanent(fmt.Errorf("%w; failure report sent to Qory Apiary with the reason %s", cause, reason))
	case IsPermanent(err):
		return Permanent(fmt.Errorf("%w; the failure report to Qory Apiary failed permanently: %w", cause, err))
	}
	// The cause is kept as text alone: an error it wraps may be one that IsPermanent
	// returns true for.
	return &reportPending{reason: reason, err: fmt.Errorf("%s; %w", cause.Error(), err)}
}

// reportPending is a failure report of a comment entry that failed, not permanently:
// its reason, and the report's error.
type reportPending struct {
	reason string
	err    error
}

func (e *reportPending) Error() string { return e.err.Error() }
func (e *reportPending) Unwrap() error { return e.err }
