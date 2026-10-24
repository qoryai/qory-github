package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github/internal/store"
)

// routeGrants is where serve reports a grant to Qory Apiary, POST, and reads Qory
// Apiary's copy of its grants, GET: contracts' grant.schema.json and grants.schema.json.
// A grant is the access an installation of the App gives, and its grant_ref is the
// installation's id in decimal.
const routeGrants = "/v1/grants"

// maxGrantsAnswer is the most bytes of an answer to GET /v1/grants that serve reads.
const maxGrantsAnswer = 4 << 20

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
	ReportGrant(ctx context.Context, connection string, installation int64, nonce string) error
	Grants(ctx context.Context) (map[int64]string, error)
}

// ReportGrant sends POST /v1/grants: the installation's grant, linked to connection
// under the connect pass whose nonce is nonce. A 429 is waited out as any POST's is;
// every other answer is the caller's, see [Connect.reportSoon].
func (a *Apiary) ReportGrant(ctx context.Context, connection string, installation int64, nonce string) error {
	return a.post(ctx, "reporting the installation's grant to Qory Apiary", routeGrants, "", connection, func(t string) any {
		return contracts.Grant{Version: contracts.Version, Time: t, ConnectionID: connection, GrantRef: grantRef(installation), PassNonce: nonce}
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
// copy alone: serve lists an installation's repositories only after a connect.
func (a *Adapter) syncGrants(ctx context.Context) error {
	gs, ok := a.Sink.(grantSink)
	if !ok {
		return Permanent(errors.New("the sink cannot read the grants"))
	}
	g, err := gs.Grants(ctx)
	if err != nil {
		return err
	}
	installMu.Lock()
	defer installMu.Unlock()
	if err := replaceGrants(a.Store, g); err != nil {
		return err
	}
	var drop []int64
	now := a.clock().Unix()
	err = a.Store.Each(nsInstallations, func(key string, v []byte) error {
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
		return err
	}
	for _, id := range drop {
		if err := dropInstallation(a.Store, id); err != nil {
			return err
		}
		a.log().Info("Qory Apiary's copy of the grants does not contain the installation for its connection, so serve drops its link", slog.Int64("installation", id))
	}
	return nil
}

// reportSoon reports the installation's grant to Qory Apiary, linked to connection under
// the pass whose nonce is nonce, beside the connect's answer, see [Apiary.ReportGrant].
// While Qory Apiary answers 409 pass_unknown or 403 connection_unknown, as it does until
// the person's browser brings the linked connect return, or the report fails as a
// request that may pass, it is sent again after a wait that doubles from
// [grantFirstWait] to [grantMaxWait], until expires, the expiry of the linked connect
// return minted for it. A report Qory Apiary takes adds the grant to the copy. Once
// expires has passed, or Qory Apiary refuses the report for good, the installation's
// link to connection is dropped unless the copy holds the grant. A 409 connection_ended
// drops the link at once, as it does for any request, see [Apiary.Ended].
func (c *Connect) reportSoon(installation int64, connection, nonce string, expires time.Time) {
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
			err := gs.ReportGrant(c.fillCtx, connection, installation, nonce)
			if c.fillCtx.Err() != nil {
				return
			}
			if err == nil {
				installMu.Lock()
				l, ok, lerr := linkOf(c.Store, installation)
				if lerr == nil && ok && l.Connection == connection {
					lerr = putGrant(c.Store, installation, connection)
				}
				installMu.Unlock()
				if lerr != nil {
					c.log().Error("keeping the installation's grant failed", slog.Int64("installation", installation), slog.String("connection", connection), slog.String("error", lerr.Error()))
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
