package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// routeGrants is where serve reports a grant to Qory Apiary, POST, and reads Qory
// Apiary's copy of its grants, GET: contracts' grant.schema.json and grants.schema.json.
// A grant is the access an installation of the App gives, and its grant_ref is the
// installation's id in decimal.
const routeGrants = "/v1/grants"

// maxGrantsAnswer is the most bytes of an answer to GET /v1/grants that serve reads.
const maxGrantsAnswer = 4 << 20

// routeGrantsEnd is where serve reports to Qory Apiary that GitHub no longer covers a
// grant, POST: contracts' grant-end.schema.json.
const routeGrantsEnd = "/v1/grants/end"

// codePassUnknown is Qory Apiary's 409 to a grant's report whose pass it has not taken
// the linked connect return of yet, contracts' refusal.schema.json.
const codePassUnknown = "pass_unknown"

// The waits between the tries of a grant's report that Qory Apiary refuses 409
// pass_unknown or 403 connection_unknown, as grant.schema.json sets them: from
// grantFirstWait, doubling, to grantMaxWait.
const (
	grantFirstWait = 2 * time.Second
	grantMaxWait   = time.Minute
)

// nsGrants is the store's namespace of Qory Apiary's copy of the adapter's grants: the
// connection that holds each, by its grant_ref, an installation's id. serve reads it
// from GET /v1/grants at each start, and again for each page of the change feed that
// has a grant entry, and replaces what it keeps with it; a report Qory Apiary takes adds
// its grant. The copy wins: an installation whose link the copy does not hold for the
// link's connection is not linked, but while its report is being sent, see [Linked].
const nsGrants = "grants"

// grantRef is the grant_ref of the installation: its id in decimal.
func grantRef(installation int64) string { return strconv.FormatInt(installation, 10) }

// maxAccountTitle is the most characters of a grant's account title, grant.schema.json.
const maxAccountTitle = 1024

// accountOf is the account of an installation's grant, as the grant's report sends it:
// ref, the GitHub account's id in decimal, and title, its login. A login that is not
// one line of 1 to [maxAccountTitle] characters with none of the characters the
// contract does not allow in a line, see [lineRune], is sent as the ref instead, so the
// report never breaks the contract.
func accountOf(a github.Account) contracts.Account {
	ref := strconv.FormatInt(a.ID, 10)
	title := a.Login
	if n := utf8.RuneCountInString(title); n == 0 || n > maxAccountTitle || !utf8.ValidString(title) || strings.IndexFunc(title, func(r rune) bool { return !lineRune(r) }) >= 0 {
		title = ref
	}
	return contracts.Account{Ref: ref, Title: title}
}

// lineRune is whether r may be in a line of the contract, grant.schema.json's account
// title: no control character, no bidirectional control and none of the format
// characters that are usually not shown.
func lineRune(r rune) bool {
	switch {
	case r <= 0x1f, r >= 0x7f && r <= 0x9f:
		return false
	case r == 0xad, r == 0x61c, r == 0x180e, r == 0x200b, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029, r == 0xfeff:
		return false
	case r >= 0x202a && r <= 0x202e, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069, r >= 0xfff9 && r <= 0xfffb:
		return false
	}
	return true
}

// grantEntry is the store's value of a grant in nsGrants.
type grantEntry struct {
	Connection string `json:"connection_id"`
}

// grantOf is the connection that holds the installation's grant in the copy, or "".
func grantOf(st *store.Store, installation int64) (string, error) {
	b, err := st.Get(nsGrants, grantRef(installation))
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var g grantEntry
	if json.Unmarshal(b, &g) != nil || !connectionShape.MatchString(g.Connection) {
		return "", errors.New("the store's entry for a grant is not one")
	}
	return g.Connection, nil
}

// dropGrant drops the installation's grant from the copy while the copy has it for
// connection.
func dropGrant(st *store.Store, installation int64, connection string) error {
	held, err := grantOf(st, installation)
	if err != nil || held != connection {
		return err
	}
	return st.Delete(nsGrants, grantRef(installation))
}

// putGrant keeps in the copy that connection holds the installation's grant.
func putGrant(st *store.Store, installation int64, connection string) error {
	if installation <= 0 || !connectionShape.MatchString(connection) {
		return errors.New("a grant names an installation and a connection")
	}
	b, err := json.Marshal(grantEntry{Connection: connection})
	if err != nil {
		return err
	}
	return st.Put(nsGrants, grantRef(installation), b, 0)
}

// replaceGrants makes the copy the grants of g, connection by installation, and drops
// every other.
func replaceGrants(st *store.Store, g map[int64]string) error {
	var stale []string
	err := st.Each(nsGrants, func(key string, _ []byte) error {
		if id, err := strconv.ParseInt(key, 10, 64); err != nil || g[id] == "" {
			stale = append(stale, key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, key := range stale {
		if err := st.Delete(nsGrants, key); err != nil {
			return err
		}
	}
	for id, connection := range g {
		if err := putGrant(st, id, connection); err != nil {
			return err
		}
	}
	return nil
}

// granted is whether the installation is linked and Qory Apiary's copy of the grants,
// as the store keeps it, holds its grant for the link's connection; or, while its
// grant's report may still be sent, until now passes the expiry of the linked connect
// return its link keeps, whether it is linked, see [Connect.reportSoon]. Only a granted
// installation's deliveries are handled.
func granted(st *store.Store, installation int64, now time.Time) (bool, error) {
	l, ok, err := linkOf(st, installation)
	if err != nil || !ok {
		return false, err
	}
	if now.Unix() < l.Return {
		return true, nil
	}
	held, err := grantOf(st, installation)
	return err == nil && held == l.Connection, err
}

// grantSink is a sink that reports a grant, as [Apiary.ReportGrant] does, and reads
// Qory Apiary's copy of the grants, as [Apiary.Grants] does.
type grantSink interface {
	ReportGrant(ctx context.Context, connection string, installation int64, nonce string, account contracts.Account) error
	Grants(ctx context.Context) (map[int64]string, error)
}

// ReportGrant sends POST /v1/grants: the installation's grant for the GitHub account
// account, see [accountOf], linked to connection under the connect pass whose nonce is
// nonce. A 429 is waited out as any POST's is; every other answer is the caller's, see
// [Connect.reportSoon].
func (a *Apiary) ReportGrant(ctx context.Context, connection string, installation int64, nonce string, account contracts.Account) error {
	return a.post(ctx, "reporting the installation's grant to Qory Apiary", routeGrants, "", connection, func(t string) any {
		return contracts.Grant{Version: contracts.Version, Time: t, ConnectionID: connection, GrantRef: grantRef(installation), Account: account, PassNonce: nonce}
	})
}

// Grants reads Qory Apiary's copy of the adapter's grants, GET /v1/grants: the
// connection that holds each, by installation. The answer is used only once its
// signature under the pin, bound to this request's, is checked, see [Apiary.judge], and
// then its document, see [checkGrants]. A 429 is waited out as a POST's is.
func (a *Apiary) Grants(ctx context.Context) (map[int64]string, error) {
	const what = "reading the grants from Qory Apiary"
	for try := 1; ; try++ {
		ans, err := a.send(ctx, what, http.MethodGet, routeGrants, nil, maxGrantsAnswer, postTimeout)
		if err == nil {
			err = a.judge(what, ans, "", "")
		}
		if wait, ok := retryWait(err); ok && try < rateLimitedTries {
			if err := a.sleep(ctx, wait); err != nil {
				return nil, fmt.Errorf("%s: %w", what, err)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		g, err := checkGrants(ans.body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return g, nil
	}
}

// checkGrants reads the answer body of GET /v1/grants, whose signature is checked
// already. It refuses one that is not grants.schema.json, of version 1 and the
// contract's revision, and one with a grant whose connection_id is not a connection's
// id, whose grant_ref is not an installation's id, or whose grant_ref is listed twice:
// serve reports one grant per installation.
func checkGrants(body []byte) (map[int64]string, error) {
	var doc struct {
		Version  *int `json:"version"`
		Revision *int `json:"revision"`
		Grants   *[]struct {
			ConnectionID *string `json:"connection_id"`
			GrantRef     *string `json:"grant_ref"`
		} `json:"grants"`
	}
	if !strictObject(body, &doc) || doc.Version == nil || doc.Revision == nil || doc.Grants == nil {
		return nil, errors.New("the answer is not the grants' document")
	}
	switch {
	case *doc.Version != contracts.Version:
		return nil, fmt.Errorf("the answer is not of version %d", contracts.Version)
	case *doc.Revision != contracts.Revision:
		return nil, fmt.Errorf("the answer is not of the contract's revision %d", contracts.Revision)
	}
	out := map[int64]string{}
	for _, g := range *doc.Grants {
		if g.ConnectionID == nil || g.GrantRef == nil || !connectionShape.MatchString(*g.ConnectionID) {
			return nil, errors.New("the answer is not the grants' document")
		}
		if !installationShape.MatchString(*g.GrantRef) {
			return nil, errors.New("the answer has a grant whose grant_ref is not an installation's id")
		}
		id, _ := strconv.ParseInt(*g.GrantRef, 10, 64)
		if _, twice := out[id]; twice {
			return nil, errors.New("the answer has two grants for one installation")
		}
		out[id] = *g.ConnectionID
	}
	return out, nil
}

// syncGrants reads Qory Apiary's copy of the grants, see [Apiary.Grants], keeps it in
// place of the one the store has, and drops the link of each installation the copy
// does not hold for the link's connection, with the records of the collections it
// reaches, see [dropInstallation], but for one whose grant's report may still be sent,
// see [granted]. A grant of the copy whose installation has no link here stays in the
// copy alone: serve lists an installation's repositories only after a connect. When
// GitHub deleted that installation, see [keepDeleted], as when the deletion came while
// the grant's report was being sent or before its 204 arrived, serve ends the grant,
// see [Adapter.endUnlinked].
func (a *Adapter) syncGrants(ctx context.Context) error {
	g, ends, err := a.readGrants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ends {
		a.endUnlinked(id, g[id])
	}
	return nil
}

// readGrants is [Adapter.syncGrants] without the grant ends: it returns the copy it
// kept, and the installations of the copy that have no link and that GitHub deleted.
// A caller that holds an installation's lock, as a listing does, uses it, since a
// grant end takes another installation's lock.
func (a *Adapter) readGrants(ctx context.Context) (map[int64]string, []int64, error) {
	gs, ok := a.Sink.(grantSink)
	if !ok {
		return nil, nil, Permanent(errors.New("the sink cannot read the grants"))
	}
	g, err := gs.Grants(ctx)
	if err != nil {
		return nil, nil, err
	}
	ends, err := a.keepGrants(g)
	return g, ends, err
}

// keepGrants is the part of [Adapter.syncGrants] that holds installMu: it keeps g in
// place of the store's copy, drops the links g does not hold, and returns the
// installations of g that have no link and that GitHub deleted.
func (a *Adapter) keepGrants(g map[int64]string) ([]int64, error) {
	installMu.Lock()
	defer installMu.Unlock()
	if err := replaceGrants(a.Store, g); err != nil {
		return nil, err
	}
	var drop []int64
	now := a.clock().Unix()
	err := a.Store.Each(nsInstallations, func(key string, v []byte) error {
		var l link
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil || json.Unmarshal(v, &l) != nil {
			return nil
		}
		if g[id] != l.Connection && now >= l.Return {
			drop = append(drop, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, id := range drop {
		if err := dropInstallation(a.Store, id); err != nil {
			return nil, err
		}
		a.log().Info("Qory Apiary's copy of the grants does not contain the installation for its connection, so serve drops its link", slog.Int64("installation", id))
	}
	var ends []int64
	for id := range g {
		_, linked, err := linkOf(a.Store, id)
		if err != nil {
			return nil, err
		}
		gone, err := wasDeleted(a.Store, id)
		if err != nil {
			return nil, err
		}
		if !linked && gone {
			ends = append(ends, id)
		}
	}
	slices.Sort(ends)
	return ends, nil
}

// endUnlinked starts the end of the grant of the installation, which connection has in
// Qory Apiary's copy, after GitHub deleted the installation and serve dropped its link,
// see [Adapter.syncGrants]: the tries of [Adapter.endSoon], the first at once, for the
// GitHub account of the deletion record, see [keepDeleted], so a connect for that
// account stops them, see [Adapter.stopEnd]. It returns before the first try, so a
// caller such as the change feed does not wait for Qory Apiary. It starts nothing while
// the grant end is being sent again, or after Qory Apiary returned an error for it that
// a retry does not change, see [Adapter.endRefusedFor], or once the installation has a
// link, or the copy no longer has the grant for connection.
func (a *Adapter) endUnlinked(installation int64, connection string) {
	if a.ending(installation) || a.endRefusedFor(installation, connection) {
		return
	}
	if send, err := unlinkedGrant(a.Store, installation, connection); err != nil || !send {
		return
	}
	if a.endSoon(installation, connection, deletedAccount(a.Store, installation), false, true) {
		a.log().Info("Qory Apiary's copy of the grants has the grant of an installation GitHub deleted, so serve reports the end of the grant", slog.Int64("installation", installation), slog.String("connection", connection))
	}
}

// unlinkedGrant is whether the installation has no link and the copy has its grant for
// connection, read under installMu.
func unlinkedGrant(st *store.Store, installation int64, connection string) (bool, error) {
	installMu.Lock()
	defer installMu.Unlock()
	if _, ok, err := linkOf(st, installation); err != nil || ok {
		return false, err
	}
	held, err := grantOf(st, installation)
	return err == nil && held == connection, err
}

// reportSoon reports the installation's grant for account to Qory Apiary, linked to
// connection under the pass whose nonce is nonce, beside the connect's answer, see
// [Apiary.ReportGrant].
// While Qory Apiary answers 409 pass_unknown or 403 connection_unknown, as it does until
// the person's browser brings the linked connect return, or the report fails as a
// request that may pass, it is sent again after a wait that doubles from
// [grantFirstWait] to [grantMaxWait], until expires, the expiry of the linked connect
// return minted for it. It stops before a try once GitHub has deleted the installation,
// see [keepDeleted]. A report Qory Apiary takes adds the grant to the copy, and when
// a listing of the installation left its collections out meanwhile, since the copy did
// not have the grant, see [reachSink], the installation's repositories are listed again
// with them, see [Adapter.listFor]; a listing that fails is logged. Once
// expires has passed, or Qory Apiary refuses the report for good, the installation's
// link to connection is dropped unless the copy holds the grant. A 409 connection_ended
// drops the link at once, as it does for any request, see [Apiary.Ended].
func (c *Connect) reportSoon(installation int64, connection, nonce string, account contracts.Account, expires time.Time) {
	c.init()
	gs, ok := c.Adapter.Sink.(grantSink)
	if !ok {
		return
	}
	c.fillMu.Lock()
	defer c.fillMu.Unlock()
	if c.stopped {
		return
	}
	c.fills.Add(1)
	go func() {
		defer c.fills.Done()
		wait := grantFirstWait
		for {
			// GitHub deleted the installation: its grant is not reported, see
			// [Adapter.endGrant].
			if gone, err := wasDeleted(c.Store, installation); err != nil || gone {
				return
			}
			err := gs.ReportGrant(c.fillCtx, connection, installation, nonce, account)
			if c.fillCtx.Err() != nil {
				return
			}
			if err == nil {
				installMu.Lock()
				l, ok, lerr := linkOf(c.Store, installation)
				relist := false
				if lerr == nil && ok && l.Connection == connection {
					lerr = putGrant(c.Store, installation, connection)
					relist = lerr == nil && c.Adapter.takeHeldBack(installation)
				}
				installMu.Unlock()
				if lerr != nil {
					c.log().Error("keeping the installation's grant failed", slog.Int64("installation", installation), slog.String("connection", connection), slog.String("error", lerr.Error()))
				}
				if relist {
					if err := c.Adapter.listFor(c.fillCtx, installation, connection); err != nil && c.fillCtx.Err() == nil {
						c.listFailed(installation, connection, err)
					}
				}
				return
			}
			again := refusedAs(err, http.StatusConflict, codePassUnknown) || refusedAs(err, http.StatusForbidden, codeConnectionUnknown) || (!IsPermanent(err) && !refusedFor(err))
			now := c.Adapter.clock()
			if !again || !now.Before(expires) {
				c.reportFailed(installation, connection, err)
				return
			}
			if c.reportWait(c.fillCtx, min(wait, expires.Sub(now))) != nil {
				return
			}
			wait = min(2*wait, grantMaxWait)
		}
	}()
}

// refusedFor is whether err is a signed refusal of Qory Apiary's that a try again
// does not change: any 4xx but a 429.
func refusedFor(err error) bool {
	var refused *refusedError
	return errors.As(err, &refused) && refused.status >= 400 && refused.status < 500 && refused.status != http.StatusTooManyRequests
}

// reportFailed ends a grant's report that Qory Apiary did not take: the installation's
// link to connection is dropped unless the copy holds its grant for connection, with a
// line that says so.
func (c *Connect) reportFailed(installation int64, connection string, err error) {
	installMu.Lock()
	defer installMu.Unlock()
	attrs := []slog.Attr{slog.Int64("installation", installation), slog.String("connection", connection), slog.String("error", err.Error())}
	held, gerr := grantOf(c.Store, installation)
	l, ok, lerr := linkOf(c.Store, installation)
	if gerr != nil || lerr != nil || !ok || l.Connection != connection || held == connection {
		c.log().LogAttrs(context.Background(), slog.LevelWarn, "reporting the installation's grant to Qory Apiary failed", attrs...)
		return
	}
	if derr := dropInstallation(c.Store, installation); derr != nil {
		attrs = append(attrs, slog.String("drop_error", derr.Error()))
	}
	c.log().LogAttrs(context.Background(), slog.LevelWarn, "reporting the installation's grant to Qory Apiary failed, so serve drops its link: connect it again", attrs...)
}

// reportWait waits d between a report's tries, or until ctx is done, with reportSleep
// when it is set.
func (c *Connect) reportWait(ctx context.Context, d time.Duration) error {
	if c.reportSleep != nil {
		return c.reportSleep(ctx, d)
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

// grantEndSink is a sink that reports the end of a grant, as [Apiary.EndGrant] does.
type grantEndSink interface {
	EndGrant(ctx context.Context, connection string, installation int64) error
}

// EndGrant sends POST /v1/grants/end: GitHub no longer covers the installation's grant,
// which connection has. A 429 is waited out as any POST's is; every other answer is the
// caller's, see [Adapter.endGrant].
func (a *Apiary) EndGrant(ctx context.Context, connection string, installation int64) error {
	return a.post(ctx, "reporting the end of the installation's grant to Qory Apiary", routeGrantsEnd, "", connection, func(t string) any {
		return contracts.GrantEnd{Version: contracts.Version, Time: t, ConnectionID: connection, GrantRef: grantRef(installation)}
	})
}

// grantEnding is a grant end that serve sends again, see [Adapter.endSoon]: the GitHub
// account of the installation's grant, by its id, 0 when the link does not have it,
// and what stops the tries.
type grantEnding struct {
	account int64
	cancel  context.CancelFunc
}

// endGrant reports to Qory Apiary that GitHub no longer covers the grant of the
// installation, whose link is l, for a caller that holds the installation's lock, see
// [Apiary.EndGrant], and acts on the answer, see [Adapter.grantEnded]. When grantEnded
// returns true, the tries of [Adapter.endSoon] start, and so nothing is sent while
// those tries run. Nothing is sent either for a grant end for which Qory Apiary
// returned an error that a retry does not change, see [Adapter.endRefusedFor]. A
// request stopped by ctx is the error, with the state kept. While Qory Apiary's copy of
// the grants does not have the installation's grant for l's connection, as while the
// grant's report is being sent again, see [Connect.reportSoon], it sends no grant end:
// it drops the installation's link and the records of the collections it reaches, see
// [dropInstallation], and the report stops at its next try, since GitHub deleted the
// installation, see [keepDeleted]. A grant that reaches the copy after that drop is
// ended when serve next reads the copy, see [Adapter.syncGrants].
func (a *Adapter) endGrant(ctx context.Context, installation int64, l link) error {
	if a.ending(installation) || a.endRefusedFor(installation, l.Connection) {
		return nil
	}
	if dropped, err := a.dropUngranted(installation, l.Connection); err != nil || dropped {
		return err
	}
	es, ok := a.Sink.(grantEndSink)
	if !ok {
		return Permanent(errors.New("the sink cannot end a grant"))
	}
	err := es.EndGrant(ctx, l.Connection, installation)
	if ctx.Err() != nil {
		return err
	}
	if a.grantEnded(installation, l.Connection, l.Account, true, err) {
		a.endSoon(installation, l.Connection, l.Account, true, false)
	}
	return nil
}

// dropUngranted drops the installation's link to connection, with the records of the
// collections it reaches, see [dropInstallation], when the copy does not have the
// installation's grant for connection, and returns whether to send no grant end: true
// after that drop, and when the link no longer names connection. It reads the copy and drops the link
// under installMu, so a report's 204, which adds the grant to the copy under installMu
// only while the link names connection, see [Connect.reportSoon], comes either before
// the read, and the grant end is sent, or after the drop, and adds nothing.
func (a *Adapter) dropUngranted(installation int64, connection string) (bool, error) {
	installMu.Lock()
	defer installMu.Unlock()
	held, err := grantOf(a.Store, installation)
	if a.grantRead != nil {
		a.grantRead()
	}
	if err != nil || held == connection {
		return false, err
	}
	if now, ok, err := linkOf(a.Store, installation); err != nil || !ok || now.Connection != connection {
		return err == nil, err
	}
	if err := dropInstallation(a.Store, installation); err != nil {
		return false, err
	}
	a.log().Info("Qory Apiary's copy of the grants does not contain the installation's grant, so serve sends no grant end and drops its link", slog.Int64("installation", installation), slog.String("connection", connection))
	return true, nil
}

// grantEnded acts on Qory Apiary's answer err to the end of the installation's grant,
// which connection has, for the GitHub account whose id is account, and says whether to
// send the grant end again. linked is whether the installation's link named connection
// as the grant end began, false for a grant end of [Adapter.endUnlinked]:
//
//   - the signed 204, or 409 grant_unknown, which means the copy has no such grant:
//     serve drops the grant from the copy, and the installation's link with the records
//     of the collections it reaches, see [dropInstallation];
//   - 409 connection_ended: [Apiary.Ended] has dropped the connection's links and their
//     collections' records, and serve drops the grant from the copy;
//   - 403 connection_unknown: it returns true, so the grant end is sent again, until
//     the 403 has lasted [forbiddenFor] for a live connection, see [noteAnswer], which
//     drops the connection's links as on 409 connection_ended, see [answeredIn]; once
//     the installation's link no longer names connection, serve drops the grant from
//     the copy and stops. A pending link is never dropped by 403s, so its grant end is
//     sent again, at most [grantMaxWait] apart, until another step drops the link. A
//     grant end of [Adapter.endUnlinked] is never stopped by counting 403s either: it
//     stops once [Apiary.Ended] or [noteAnswer] has dropped the connection's grants from
//     the copy, see [dropConnection];
//   - a failure that may pass, no answer, a 5xx or an answer not signed: it returns
//     true, so the grant end is sent again;
//   - any other refusal, 403 forbidden and 400 among them: serve logs it, keeps its
//     state, since neither ends a connection or a grant, and sends no more grant end for
//     the grant, see [Adapter.endRefusedFor].
//
// It drops the grant from the copy whatever the link is, and drops the installation's
// link only while the link names connection.
func (a *Adapter) grantEnded(installation int64, connection string, account int64, linked bool, err error) bool {
	attrs := []slog.Attr{slog.Int64("installation", installation), slog.String("connection", connection)}
	switch {
	case err == nil, refusedAs(err, http.StatusConflict, codeGrantUnknown), refusedAs(err, http.StatusConflict, codeConnectionEnded):
		installMu.Lock()
		derr := dropGrant(a.Store, installation, connection)
		if l, ok, lerr := linkOf(a.Store, installation); derr == nil && lerr == nil && ok && l.Connection == connection {
			derr = dropInstallation(a.Store, installation)
		}
		installMu.Unlock()
		if derr != nil {
			a.log().LogAttrs(context.Background(), slog.LevelError, pick(linked, "dropping the link of an installation whose grant ended", "dropping the grant of an installation that has no link"), append(attrs, slog.String("error", derr.Error()))...)
			return false
		}
		a.log().LogAttrs(context.Background(), slog.LevelInfo, pick(linked, "the installation's grant ended in Qory Apiary, so serve drops its link", "the grant of an installation that has no link ended in Qory Apiary, so serve drops the grant from the copy"), attrs...)
		return false
	case refusedAs(err, http.StatusForbidden, codeConnectionUnknown):
		installMu.Lock()
		l, ok, derr := linkOf(a.Store, installation)
		gone := derr == nil && linked && (!ok || l.Connection != connection)
		if gone {
			derr = dropGrant(a.Store, installation, connection)
		}
		installMu.Unlock()
		if derr != nil {
			a.log().LogAttrs(context.Background(), slog.LevelError, "dropping the grant of an installation whose connection was dropped", append(attrs, slog.String("error", derr.Error()))...)
			return false
		}
		if gone {
			a.log().LogAttrs(context.Background(), slog.LevelInfo, "the installation's link was dropped with its connection, so serve drops its grant and sends no more grant end", attrs...)
			return false
		}
		if !linked {
			// The connection's grants were dropped as it ended, see [dropConnection].
			if send, err := unlinkedGrant(a.Store, installation, connection); err == nil && !send {
				return false
			}
		}
		a.log().LogAttrs(context.Background(), slog.LevelWarn, "reporting the end of the installation's grant to Qory Apiary failed, so serve sends it again later", append(attrs, slog.String("error", err.Error()))...)
		return true
	case !IsPermanent(err) && !refusedFor(err):
		a.log().LogAttrs(context.Background(), slog.LevelWarn, "reporting the end of the installation's grant to Qory Apiary failed, so serve sends it again later", append(attrs, slog.String("error", err.Error()))...)
		return true
	}
	a.refuseEnd(installation, connection, account)
	a.log().LogAttrs(context.Background(), slog.LevelError, pick(linked,
		"Qory Apiary returned an error for the end of the installation's grant that a retry does not change, so serve keeps its link and sends no more grant end for it until a connect for its account or a restart",
		"The end of the grant of an installation that has no link failed with an error from Qory Apiary that a retry does not change, so serve keeps the grant in the copy and sends no more grant end for it until a connect for its account or a restart"),
		append(attrs, slog.String("error", err.Error()))...)
	return false
}

// pick is linked's text when linked is set, and unlinked's otherwise, for a line of
// [Adapter.grantEnded] that a grant end of [Adapter.endUnlinked] logs about no link.
func pick(linked bool, linkedText, unlinkedText string) string {
	if linked {
		return linkedText
	}
	return unlinkedText
}

// endSoon starts the tries of the end of the installation's grant, which connection
// has, in the background, each try holding the installation's lock, see
// [Adapter.endAgain]. linked is as for [Adapter.grantEnded].
//
// Without now, as for a linked grant end whose first try in [Adapter.endGrant] made
// grantEnded return true, it waits before each try. With now, as for
// [Adapter.endUnlinked], it makes the first try at once and waits before each later
// one. The waits double from [grantFirstWait] to [grantMaxWait], as for a grant's
// report.
//
// The tries stop once grantEnded returns false. A linked grant end also stops once the
// installation's link names another connection, or none, as after [Apiary.Ended]
// dropped it. An unlinked one also stops once the installation has a link, or the copy
// no longer has the grant for connection. Both stop once a linked connect return is
// minted for account, the GitHub account of the grant, see [Adapter.stopEnd], and once
// [Adapter.stopEnds] has run. A stop changes no state.
//
// One installation has one grant end sent again at a time: endSoon starts nothing while
// the installation's tries run, or once stopEnds has run. It returns whether it started
// the tries.
func (a *Adapter) endSoon(installation int64, connection string, account int64, linked, now bool) bool {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	a.initEnds()
	if a.endsStopped || a.ends[installation] != nil {
		return false
	}
	ctx, cancel := context.WithCancel(a.endCtx)
	e := &grantEnding{account: account, cancel: cancel}
	a.ends[installation] = e
	a.endWG.Add(1)
	go func() {
		defer a.endWG.Done()
		defer a.forgetEnding(installation, e)
		wait := grantFirstWait
		for first := now; ; first = false {
			if !first {
				if a.endWait(ctx, wait) != nil {
					return
				}
				wait = min(2*wait, grantMaxWait)
			}
			if !a.endAgain(ctx, installation, connection, account, linked) {
				return
			}
		}
	}()
	return true
}

// endAgain is one try of [Adapter.endSoon], holding the installation's lock, and says
// whether to try again. linked is as for [Adapter.grantEnded]: a linked grant end stops
// once the link no longer names connection, and one of [Adapter.endUnlinked] once the
// installation has a link or the copy no longer has the grant for connection.
func (a *Adapter) endAgain(ctx context.Context, installation int64, connection string, account int64, linked bool) bool {
	unlock, err := a.lockInstallation(ctx, installation)
	if err != nil {
		return false
	}
	defer unlock()
	if linked {
		l, ok, err := linkOf(a.Store, installation)
		if err != nil || !ok || l.Connection != connection {
			return false
		}
	} else if send, err := unlinkedGrant(a.Store, installation, connection); err != nil || !send {
		return false
	}
	es, ok := a.Sink.(grantEndSink)
	if !ok {
		return false
	}
	err = es.EndGrant(ctx, connection, installation)
	if ctx.Err() != nil {
		return false
	}
	return a.grantEnded(installation, connection, account, linked, err)
}

// initEnds makes what [Adapter.endSoon] keeps, for a caller that holds endMu.
func (a *Adapter) initEnds() {
	if a.ends == nil {
		a.ends = map[int64]*grantEnding{}
		a.endCtx, a.endStop = context.WithCancel(context.Background())
	}
}

// ending is whether the installation's grant end is being sent again, see
// [Adapter.endSoon].
func (a *Adapter) ending(installation int64) bool {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	return a.ends[installation] != nil
}

// forgetEnding forgets the installation's grant end e as its tries stop.
func (a *Adapter) forgetEnding(installation int64, e *grantEnding) {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	if a.ends[installation] == e {
		delete(a.ends, installation)
	}
	e.cancel()
}

// stopEnd stops each grant end being sent again, see [Adapter.endSoon], for the GitHub
// account whose id is account, as a linked connect return minted for that account does,
// and forgets the grant ends of that account for which Qory Apiary returned an error
// that a retry does not change, see [Adapter.endRefusedFor], so a later end of the
// installation's grant is sent; an account of 0 or below stops none. The installation's
// link and state stay.
func (a *Adapter) stopEnd(account int64) {
	if account <= 0 {
		return
	}
	a.endMu.Lock()
	defer a.endMu.Unlock()
	for installation, e := range a.ends {
		if e.account == account {
			delete(a.ends, installation)
			e.cancel()
			a.log().Info("a connect for the account stops the end of its earlier installation's grant", slog.Int64("installation", installation))
		}
	}
	for installation, r := range a.endRefused {
		if r.account == account {
			delete(a.endRefused, installation)
		}
	}
}

// refusedEnd is a grant end to which Qory Apiary returned an error that a retry does
// not change: the connection it named, and the GitHub account of the installation's
// grant, by its id, 0 when the link does not have it.
type refusedEnd struct {
	connection string
	account    int64
}

// refuseEnd keeps that the end of the installation's grant, which connection has,
// failed with an error from Qory Apiary that a retry does not change, see
// [Adapter.endRefusedFor].
func (a *Adapter) refuseEnd(installation int64, connection string, account int64) {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	if a.endRefused == nil {
		a.endRefused = map[int64]refusedEnd{}
	}
	a.endRefused[installation] = refusedEnd{connection: connection, account: account}
}

// endRefusedFor is whether the end of the installation's grant, which connection has,
// failed with an error from Qory Apiary that a retry does not change, such as 403
// forbidden or 400, see [Adapter.grantEnded]. Serve
// keeps it in memory alone, so it holds until a connect for the grant's account, see
// [Adapter.stopEnd], or until serve starts again.
func (a *Adapter) endRefusedFor(installation int64, connection string) bool {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	r, ok := a.endRefused[installation]
	return ok && r.connection == connection
}

// endHeld is whether serve sends no grant end for the installation now: its grant end
// is being sent again, see [Adapter.endSoon], or one failed with an error from Qory
// Apiary that a retry does not change, see [Adapter.endRefusedFor].
func (a *Adapter) endHeld(installation int64) bool {
	a.endMu.Lock()
	defer a.endMu.Unlock()
	_, refused := a.endRefused[installation]
	return a.ends[installation] != nil || refused
}

// stopEnds stops the grant ends being sent again, see [Adapter.endSoon], and waits for
// them; none starts after it.
func (a *Adapter) stopEnds() {
	a.endMu.Lock()
	a.initEnds()
	a.endsStopped = true
	a.endStop()
	a.endMu.Unlock()
	a.endWG.Wait()
}

// endWait waits d between a grant end's tries, or until ctx is done, with endSleep
// when it is set.
func (a *Adapter) endWait(ctx context.Context, d time.Duration) error {
	if a.endSleep != nil {
		return a.endSleep(ctx, d)
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
