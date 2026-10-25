package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// reportClock is a fake clock for a connect's grant report: each wait between the
// report's tries is noted and moves the clock on, which the adapter and the Connect
// read.
type reportClock struct {
	mu    sync.Mutex
	t     time.Time
	waits []time.Duration
}

func (c *reportClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *reportClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	c.t = c.t.Add(d)
	return nil
}

func (c *reportClock) waited() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.waits)
}

// reportRig is a connect rig whose Connect and adapter read a [reportClock], which
// starts at a whole second.
func reportRig(t *testing.T) (*connectRig, *reportClock) {
	t.Helper()
	rig := newConnectRig(t)
	clock := &reportClock{t: time.Now().Truncate(time.Second)}
	rig.c.now, rig.adapter.now, rig.c.reportSleep, rig.client.Now = clock.now, clock.now, clock.sleep, clock.now
	return rig, clock
}

// connectWith connects the installation 42 to testConnection through rig's Connect, with
// a pass whose nonce is nonce.
func connectWith(t *testing.T, rig *connectRig, nonce string) {
	t.Helper()
	pass := signPass(rig.signer, payload(testAdapterID, testConnection, nonce, time.Now().Add(10*time.Minute)))
	rig.secrets = append(rig.secrets, pass)
	b := rig.browser(t)
	if r := rig.backTo(t, b.connect(pass, "42"), testConnection); r.Outcome != outcomeLinked {
		t.Fatalf("the connect return %+v", r)
	}
}

// TestAConnectReportsTheGrant pins that a connect's checked return reports the
// installation's grant to Qory Apiary, POST /v1/grants, with the connection, the
// installation's id as grant_ref, its GitHub account's id and login as the account, and
// the pass's nonce, once, and that the grant Qory Apiary takes is added to the store's
// copy, so the installation's deliveries are handled once the linked connect return has
// expired too.
func TestAConnectReportsTheGrant(t *testing.T) {
	rig, clock := reportRig(t)
	nonce := newNonce()
	connectWith(t, rig, nonce)
	eventually(t, "the grant kept", func() bool { c, _ := grantOf(rig.st, 42); return c == testConnection })
	sent := rig.apiary.sent(routeGrants)
	if len(sent) != 1 || sent[0].body["connection_id"] != testConnection || sent[0].body["grant_ref"] != "42" || sent[0].body["pass_nonce"] != nonce || sent[0].body["version"] != 1.0 {
		t.Fatalf("reported %d times: %v", len(sent), sent)
	}
	if account, _ := sent[0].body["account"].(map[string]any); len(account) != 2 || account["ref"] != "500" || account["title"] != "acme" {
		t.Errorf("the account %v", sent[0].body["account"])
	}
	if w := clock.waited(); len(w) != 0 {
		t.Errorf("waited %v", w)
	}
	clock.sleep(context.Background(), returnFor+time.Second)
	if ok, err := granted(rig.st, 42, clock.now()); !ok || err != nil {
		t.Errorf("granted %v %v", ok, err)
	}
	rig.noLeak(t)
}

// TestAGrantRefusedUntilTheReturnArrivesIsSentAgain pins that a report Qory Apiary
// answers 409 pass_unknown, or 403 connection_unknown, is sent again after a wait that
// doubles from 2 seconds, each try built anew, until Qory Apiary takes it.
func TestAGrantRefusedUntilTheReturnArrivesIsSentAgain(t *testing.T) {
	rig, clock := reportRig(t)
	rig.apiary.refuse = func(route string, n int) (int, string) {
		switch {
		case route != routeGrants:
			return 0, ""
		case n == 1:
			return http.StatusForbidden, `{"error":"connection_unknown"}`
		case n <= 3:
			return http.StatusConflict, `{"error":"pass_unknown"}`
		}
		return 0, ""
	}
	connectWith(t, rig, newNonce())
	eventually(t, "the grant kept", func() bool { c, _ := grantOf(rig.st, 42); return c == testConnection })
	sent := rig.apiary.sent(routeGrants)
	if len(sent) != 4 || sent[0].signature == sent[1].signature {
		t.Errorf("reported %d times", len(sent))
	}
	if w := clock.waited(); !slices.Equal(w, []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}) {
		t.Errorf("waited %v", w)
	}
	if l, ok, _ := linkOf(rig.st, 42); !ok || l.Connection != testConnection {
		t.Errorf("the link is %+v %v", l, ok)
	}
}

// TestAGrantNeverTakenDropsTheLink pins that a report Qory Apiary refuses until the
// linked connect return expires stops then, after waits that double to a minute and end
// at the expiry, and drops the installation's link, with the line that says so; and
// that a report refused for good stops at once and drops it too.
func TestAGrantNeverTakenDropsTheLink(t *testing.T) {
	rig, clock := reportRig(t)
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrants {
			return http.StatusForbidden, `{"error":"connection_unknown"}`
		}
		return 0, ""
	}
	connectWith(t, rig, newNonce())
	const line = `"level":"WARN","msg":"reporting the installation's grant to Qory Apiary failed, so serve drops its link: connect it again","installation":42,"connection":"` + testConnection + `"`
	eventually(t, "the line", func() bool { return strings.Contains(rig.log.String(), line) })
	if _, ok, _ := linkOf(rig.st, 42); ok {
		t.Error("the link is kept")
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute, 58 * time.Second}
	if w := clock.waited(); !slices.Equal(w, want) {
		t.Errorf("waited %v, want %v", w, want)
	}
	if c, _ := grantOf(rig.st, 42); c != "" {
		t.Errorf("the grant %s is kept", c)
	}

	rig, clock = reportRig(t)
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrants {
			return http.StatusBadRequest, `{"error":"invalid_request"}`
		}
		return 0, ""
	}
	connectWith(t, rig, newNonce())
	eventually(t, "the line", func() bool { return strings.Contains(rig.log.String(), line) })
	if _, ok, _ := linkOf(rig.st, 42); ok {
		t.Error("the link is kept")
	}
	if n := len(rig.apiary.sent(routeGrants)); n != 1 || len(clock.waited()) != 0 {
		t.Errorf("reported %d times, waited %v", n, clock.waited())
	}
}

// TestAGrantIsNotSentAfterTheReturnExpires pins that a report Qory Apiary refuses until
// the linked connect return expires is sent last at that return's expires_at, a whole
// second, when the connect starts half a second into a second.
func TestAGrantIsNotSentAfterTheReturnExpires(t *testing.T) {
	rig, clock := reportRig(t)
	clock.t = clock.t.Add(500 * time.Millisecond)
	var mu sync.Mutex
	var at []time.Time
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route != routeGrants {
			return 0, ""
		}
		mu.Lock()
		defer mu.Unlock()
		at = append(at, clock.now())
		return http.StatusForbidden, `{"error":"connection_unknown"}`
	}
	pass := signPass(rig.signer, payload(testAdapterID, testConnection, newNonce(), time.Now().Add(10*time.Minute)))
	rig.secrets = append(rig.secrets, pass)
	r := rig.backTo(t, rig.browser(t).connect(pass, "42"), testConnection)
	if r.Outcome != outcomeLinked {
		t.Fatalf("the connect return %+v", r)
	}
	expires, err := time.Parse(contracts.TimeLayout, r.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "the link dropped", func() bool { _, ok, _ := linkOf(rig.st, 42); return !ok })
	mu.Lock()
	defer mu.Unlock()
	if len(at) == 0 || !at[len(at)-1].Equal(expires) {
		t.Errorf("reported at %v, the connect return expires at %v", at, expires)
	}
	for _, a := range at {
		if a.After(expires) {
			t.Errorf("reported at %v, after the connect return's expires_at %v", a, expires)
		}
	}
}

// TestTheGrantsCopyReplacesTheStores pins that a read of Qory Apiary's copy replaces the
// store's: a grant the copy does not hold is dropped and one it holds is kept; that the
// link of an installation the copy does not hold for the link's connection is dropped,
// with its repositories' records and the line that says so, while one whose linked
// connect return has not expired stays; and that a grant without a link here stays in
// the copy alone.
func TestTheGrantsCopyReplacesTheStores(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	const other = "ac_0000000000000002"
	if err := grantedLink(w.st, 7, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	if err := grantedLink(w.st, 8, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	if err := grantedLink(w.st, 9, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	if err := claimReach(w.st, widgetsRef, 8, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := putLink(w.st, 10, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	w.apiary.grant("7", testConnection)
	w.apiary.grant("9", other)
	w.apiary.grant("11", other)
	if err := w.adapter.syncGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int64]string{7: testConnection, 8: "", 9: other, 10: "", 11: other} {
		if c, err := grantOf(w.st, id); c != want || err != nil {
			t.Errorf("the grant of %d is %q %v, want %q", id, c, err, want)
		}
	}
	for id, want := range map[int64]bool{7: true, 8: false, 9: false, 10: true, 11: false} {
		if _, ok, _ := linkOf(w.st, id); ok != want {
			t.Errorf("the link of %d is there %v", id, ok)
		}
	}
	if _, ok, _ := reachOf(w.st, widgetsRef); ok {
		t.Error("the dropped installation's repository is kept")
	}
	for _, id := range []string{"8", "9"} {
		if !strings.Contains(w.log.String(), `"msg":"Qory Apiary's copy of the grants does not contain the installation for its connection, so serve drops its link","installation":`+id) {
			t.Errorf("no line for %s: %s", id, w.log.String())
		}
	}
	if ok, _ := granted(w.st, 10, time.Now()); !ok {
		t.Error("the installation whose report may still be sent is not linked")
	}
	if ok, _ := granted(w.st, 10, time.Now().Add(2*time.Minute)); ok {
		t.Error("the installation whose return expired is linked though the copy does not hold it")
	}
}

// TestAnInstallationTheCopyDoesNotHoldIsNotHandled pins that a delivery of an
// installation linked here, whose grant the copy does not hold, is done unhandled, and
// that one whose grant the copy holds is handled.
func TestAnInstallationTheCopyDoesNotHoldIsNotHandled(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if err := Link(w.st, 42, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	if err := claimReach(w.st, widgetsRef, 42, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := linkCollection(w.st, widgetsRef); err != nil {
		t.Fatal(err)
	}
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	if n := len(w.apiary.sent(routeItems)); n != 0 || !strings.Contains(w.log.String(), `"msg":"the installation is not linked to Qory Apiary, so the delivery is not handled"`) {
		t.Errorf("%d items sent; the log: %s", n, w.log.String())
	}
	if err := putGrant(w.st, 42, testConnection); err != nil {
		t.Fatal(err)
	}
	w.deliver(t, "issues", guid2, issueEvent(42, "acme/widgets", "opened"))
	if n := len(w.apiary.sent(routeItems)); n != 1 {
		t.Errorf("%d items sent", n)
	}
}

// TestAGrantEntryReadsTheCopyOncePerPage pins that the change feed's grant entries,
// linked and unlinked, read Qory Apiary's copy once for each page that has them, and
// that a grant entry that names no installation fails for good, logged and passed.
func TestAGrantEntryReadsTheCopyOncePerPage(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if err := grantedLink(w.st, 42, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	w.apiary.changes = []contracts.Change{
		{Kind: contracts.ChangeGrant, ConnectionID: testConnection, GrantRef: "42", Status: "linked"},
		{Kind: contracts.ChangeGrant, ConnectionID: testConnection, GrantRef: "42", Status: "unlinked"},
		{Kind: contracts.ChangeGrant, ConnectionID: testConnection, GrantRef: "acme", Status: "linked"},
	}
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(w.apiary.sent("GET " + routeGrants)); n != 1 {
		t.Errorf("the copy was read %d times", n)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the link the copy does not hold is kept")
	}
	if !strings.Contains(w.log.String(), `"msg":"a change of the feed failed, and is passed","kind":"grant","error":"the grant's entry has no installation's id as grant_ref, or no connection's id"`) {
		t.Errorf("the log: %s", w.log.String())
	}
}

// TestAWrongGrantsAnswerIsRefused pins the refusals of an answer to GET /v1/grants.
func TestAWrongGrantsAnswerIsRefused(t *testing.T) {
	for body, want := range map[string]string{
		`{"version":1,"revision":1,"grants":[]}`:          "",
		`{"version":1,"revision":2,"grants":[]}`:          "the answer is not of the contract's revision 1",
		`{"version":2,"revision":1,"grants":[]}`:          "the answer is not of version 1",
		`{"version":1,"revision":1}`:                      "the answer is not the grants' document",
		`{"version":1,"revision":1,"grants":[],"more":1}`: "the answer is not the grants' document",
		`{"version":1,"revision":1,"grants":[{"connection_id":"ac_0000000000000001","grant_ref":"acme"}]}`:                                                      "the answer has a grant whose grant_ref is not an installation's id",
		`{"version":1,"revision":1,"grants":[{"connection_id":"ac_x","grant_ref":"7"}]}`:                                                                        "the answer is not the grants' document",
		`{"version":1,"revision":1,"grants":[{"connection_id":"ac_0000000000000001","grant_ref":"7"},{"connection_id":"ac_0000000000000002","grant_ref":"7"}]}`: "the answer has two grants for one installation",
	} {
		_, err := checkGrants([]byte(body))
		if (want == "") != (err == nil) || err != nil && err.Error() != want {
			t.Errorf("%s: err %v, want %q", body, err, want)
		}
	}
}

// TestTheFeedReadsTheCopyAtStart pins that the change feed's reader reads Qory Apiary's
// copy of the grants once it has declared the adapter and before it reads the feed, and
// that the copy it reads wins over the store's.
func TestTheFeedReadsTheCopyAtStart(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if err := grantedLink(w.st, 42, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	w.apiary.hold = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.feed.run(ctx); close(done) }()
	eventually(t, "the feed read", func() bool { return len(w.apiary.sent("GET "+routeChanges)) == 1 })
	cancel()
	<-done
	w.apiary.mu.Lock()
	var order []string
	for _, r := range w.apiary.requests {
		order = append(order, r.method+" "+strings.SplitN(r.target, "?", 2)[0])
	}
	w.apiary.mu.Unlock()
	if !slices.Equal(order, []string{"POST " + routeAdapter, "GET " + routeGrants, "GET " + routeChanges}) {
		t.Errorf("the requests %v", order)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the link the copy does not hold is kept")
	}
}

// TestACallServesOnlyAnInstallationTheCopyHolds pins the rule a call for a harness
// follows, the one intake follows, see [granted]: an installation whose link's connect
// return has expired and that Qory Apiary's copy of the grants does not hold is refused
// 409 grant_unknown, and nothing is minted for it; while its connect return has not
// expired, or once the copy holds it, a run credential is minted. A call for work
// counts only the copy: while the connect return has not expired and the copy does not
// hold the grant, as while the grant's report is still being sent, it gets 403
// resource_not_covered and nothing is minted.
func TestACallServesOnlyAnInstallationTheCopyHolds(t *testing.T) {
	rig := newCallsRig(t)
	send := func() callAnswer {
		return rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(harnessCall("42", []string{widgetsRef}, "read")))
	}
	sendWork := func() callAnswer {
		return rig.send(t, signedCall{path: contracts.RunCredentialPath}, rig.callBody(workCall(testConnection, widgetsRef, "read")))
	}
	if err := replaceGrants(rig.st, nil); err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, send(), http.StatusConflict, "refusal.schema.json", codeGrantUnknown)
	checkAnswer(t, sendWork(), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Fatalf("minted %q for an installation the copy does not hold", mints)
	}
	if err := putLink(rig.st, 42, link{Connection: testConnection, State: linkLive, Return: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, sendWork(), http.StatusForbidden, "refusal.schema.json", codeResourceNotCovered)
	if mints := rig.gh.mintsSoFar(); len(mints) != 0 {
		t.Fatalf("minted %q for work under a grant whose report is still being sent", mints)
	}
	checkAnswer(t, send(), http.StatusOK, "run-credential-answer.schema.json", "")
	if err := putLink(rig.st, 42, link{Connection: testConnection, State: linkLive}); err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, send(), http.StatusConflict, "refusal.schema.json", codeGrantUnknown)
	if err := putGrant(rig.st, 42, testConnection); err != nil {
		t.Fatal(err)
	}
	checkAnswer(t, send(), http.StatusOK, "run-credential-answer.schema.json", "")
	checkAnswer(t, sendWork(), http.StatusOK, "run-credential-answer.schema.json", "")
	if mints := rig.gh.mintsSoFar(); len(mints) != 3 {
		t.Errorf("minted %d credentials, want 3", len(mints))
	}
}

// TestAnAccountIsItsIDAndLogin pins the account a grant's report sends: the GitHub
// account's id in decimal as ref and its login as title, and the ref as title for a
// login that is not one line of 1 to 1024 characters the contract takes.
func TestAnAccountIsItsIDAndLogin(t *testing.T) {
	for login, title := range map[string]string{
		"acme":                    "acme",
		"octo-org":                "octo-org",
		strings.Repeat("a", 1024): strings.Repeat("a", 1024),
		strings.Repeat("a", 1025): "500",
		"":                        "500",
		"two\nlines":              "500",
		"right\u202eleft":         "500",
		"zero\u200bwidth":         "500",
		"\xff":                    "500",
	} {
		got := accountOf(github.Account{Login: login, ID: 500, Type: "Organization"})
		if got != (contracts.Account{Ref: "500", Title: title}) {
			t.Errorf("%q: %+v, want the title %q", login, got, title)
		}
	}
}

// TestACollectionWaitsForItsGrantsReport pins that a connect's first listing, sent
// while Qory Apiary has not taken the grant's report, contains no collection and is
// not complete, and that once Qory Apiary takes the report the installation's
// repositories are listed again, each collection with the installation's grant_ref,
// complete.
func TestACollectionWaitsForItsGrantsReport(t *testing.T) {
	rig, _ := reportRig(t)
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		// The report returns 409 pass_unknown until a listing has reached Qory Apiary.
		if route == routeGrants && len(rig.apiary.sent(routeCollections)) == 0 {
			return http.StatusConflict, `{"error":"pass_unknown"}`
		}
		return 0, ""
	}
	connectWith(t, rig, newNonce())
	eventually(t, "the second listing", func() bool { return len(rig.apiary.sent(routeCollections)) >= 2 })
	rig.c.stop()
	sent := rig.apiary.sent(routeCollections)
	var first, second contracts.SourceCollections
	json.Unmarshal(sent[0].raw, &first)
	json.Unmarshal(sent[1].raw, &second)
	if len(first.Collections) != 0 || first.Listing.Complete {
		t.Errorf("the listing before the report is taken: %s", sent[0].raw)
	}
	if len(second.Collections) != 2 || !second.Listing.Complete || second.Listing.ID == first.Listing.ID {
		t.Fatalf("the listing after the report is taken: %s", sent[1].raw)
	}
	for _, c := range second.Collections {
		if c.GrantRef != "42" {
			t.Errorf("the collection %s names the grant %q", c.Ref, c.GrantRef)
		}
	}
	if n := len(sent); n != 2 {
		t.Errorf("%d listings", n)
	}
}

// TestAPartRefused400IsSentAgainAfterTheGrantsAreRead pins that when Qory Apiary
// returns 400 invalid_request for a part, as for a grant_ref its copy does not have,
// serve reads the copy again, GET /v1/grants. When the copy does not have the grant,
// the part is sent again, built anew, without its collections and not complete. When
// the copy has it, the refusal has another cause: the part is not sent again, and the
// refusal is the listing's error.
func TestAPartRefused400IsSentAgainAfterTheGrantsAreRead(t *testing.T) {
	for _, inCopy := range []bool{false, true} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		grantedPutLink(w.st, 42, link{Connection: testConnection, State: linkLive, Return: time.Now().Add(time.Minute).Unix()})
		if inCopy {
			w.apiary.grant("42", testConnection)
		}
		w.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeCollections && n == 1 {
				return http.StatusBadRequest, `{"error":"invalid_request"}`
			}
			return 0, ""
		}
		err := w.adapter.listRepositories(context.Background(), 42)
		if refused := refusedAs(err, http.StatusBadRequest, codeInvalidRequest); refused != inCopy {
			t.Errorf("in the copy %v: err %v", inCopy, err)
		}
		if n := len(w.apiary.sent("GET " + routeGrants)); n != 1 {
			t.Errorf("in the copy %v: the copy was read %d times", inCopy, n)
		}
		sent := w.apiary.sent(routeCollections)
		if inCopy {
			if len(sent) != 1 {
				t.Errorf("in the copy: %d parts", len(sent))
			}
			continue
		}
		if len(sent) != 2 {
			t.Fatalf("not in the copy: %d parts", len(sent))
		}
		var again contracts.SourceCollections
		json.Unmarshal(sent[1].raw, &again)
		if len(again.Collections) != 0 || again.Listing.Complete || again.Listing.Part != 1 {
			t.Errorf("not in the copy: the part sent again %s", sent[1].raw)
		}
		if held, _ := grantOf(w.st, 42); held != "" {
			t.Errorf("not in the copy: the grant is kept for %s", held)
		}
	}
}

// TestAConnectForTheAccountStopsItsGrantEnd pins that a grant end that returns 503,
// sent again later, stops once a connect mints a linked connect return for the GitHub
// account of its installation, acme: no try follows, and the deleted
// installation's link stays, while the grant end of an installation on another account
// is sent again and taken.
func TestAConnectForTheAccountStopsItsGrantEnd(t *testing.T) {
	rig, _ := reportRig(t)
	grantedPutLink(rig.st, 99, link{Connection: otherConnection, State: linkLive, Account: acme.ID})
	grantedPutLink(rig.st, 98, link{Connection: "ac_0000000000000002", State: linkLive, Account: alice.ID})
	rig.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeGrantsEnd && n <= 2 {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	// Each wait before a try lasts until the connect is done, or until its grant end is
	// stopped.
	connected := make(chan struct{})
	rig.adapter.endSleep = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-connected:
		case <-ctx.Done():
		}
		return ctx.Err()
	}
	for _, id := range []int64{99, 98} {
		if _, err := rig.adapter.endInstallation(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if !rig.adapter.ending(id) {
			t.Fatalf("the grant end of %d is not sent again", id)
		}
	}
	connectWith(t, rig, newNonce())
	if rig.adapter.ending(99) {
		t.Error("the grant end of the account's installation is still sent again")
	}
	if !rig.adapter.ending(98) {
		t.Error("the grant end of another account's installation stopped")
	}
	close(connected)
	rig.endsDone(t, 98)
	rig.adapter.stopEnds()
	tries := map[any]int{}
	for _, s := range rig.apiary.sent(routeGrantsEnd) {
		tries[s.body["grant_ref"]]++
	}
	if tries["99"] != 1 || tries["98"] != 2 {
		t.Errorf("grant ends by grant_ref %v", tries)
	}
	if l, ok, _ := linkOf(rig.st, 99); !ok || l.Connection != otherConnection {
		t.Errorf("the deleted installation's link %+v %v", l, ok)
	}
	if _, ok, _ := linkOf(rig.st, 98); ok {
		t.Error("the link of the installation on another account is kept")
	}
	if !strings.Contains(rig.log.String(), `"msg":"a connect for the account stops the end of its earlier installation's grant","installation":99`) {
		t.Errorf("the log %s", rig.log.String())
	}
	if l, ok, _ := linkOf(rig.st, 42); !ok || l.Account != acme.ID {
		t.Errorf("the connected installation's link %+v %v", l, ok)
	}
}

// unlinkedEndLine is the line serve logs as it ends the grant of an installation
// GitHub deleted that reached the copy after serve dropped its link.
const unlinkedEndLine = `"msg":"Qory Apiary's copy of the grants has the grant of an installation GitHub deleted, so serve reports the end of the grant","installation":42,"connection":"` + testConnection + `"`

// deletedBeforeTheReport links 42 to testConnection, live, while Qory Apiary's copy has
// its grant and serve's does not, as when the report's 204 was lost, and deletes 42:
// serve drops the link and sends no grant end.
func deletedBeforeTheReport(t *testing.T) *wired {
	t.Helper()
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if err := putLink(w.st, 42, link{Connection: testConnection, State: linkLive}); err != nil {
		t.Fatal(err)
	}
	w.apiary.grant("42", testConnection)
	if _, err := w.adapter.endInstallation(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Fatal("the link is kept")
	}
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 0 {
		t.Fatalf("%d grant ends at the deletion", n)
	}
	w.apiary.changes = []contracts.Change{{Kind: contracts.ChangeGrant, ConnectionID: testConnection, GrantRef: "42", Status: "linked"}}
	return w
}

// TestAGrantTheFeedAddsAfterItsInstallationWasDeletedIsEnded deletes 42 before serve
// has its grant, see [deletedBeforeTheReport], and then reads the change feed's grant
// entry: the copy the entry has serve read has the grant of a deleted installation, so
// serve sends one grant end, with a line, and its 204 drops the grant from serve's
// copy. A second read of the copy sends nothing.
func TestAGrantTheFeedAddsAfterItsInstallationWasDeletedIsEnded(t *testing.T) {
	w := deletedBeforeTheReport(t)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.endsDone(t, 42)
	sent := w.apiary.sent(routeGrantsEnd)
	if len(sent) != 1 || sent[0].body["connection_id"] != testConnection || sent[0].body["grant_ref"] != "42" {
		t.Fatalf("the grant ends %v", sent)
	}
	if held, _ := grantOf(w.st, 42); held != "" {
		t.Errorf("the grant %q is kept", held)
	}
	if !strings.Contains(w.log.String(), unlinkedEndLine) {
		t.Errorf("the log %s", w.log.String())
	}
	if err := w.adapter.syncGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends after a second read", n)
	}
}

// TestAGrantOfADeletedInstallationIsEndedOnceAtATime has the grant end of a deleted
// installation's grant, see [deletedBeforeTheReport], return 503, so it is sent again
// later: a second read of the copy, which still has the grant, starts no second set of
// tries and sends nothing.
func TestAGrantOfADeletedInstallationIsEndedOnceAtATime(t *testing.T) {
	w := deletedBeforeTheReport(t)
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrantsEnd {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the first grant end", func() bool { return len(w.apiary.sent(routeGrantsEnd)) == 1 })
	if !w.adapter.ending(42) {
		t.Fatal("the grant end is not sent again")
	}
	if err := w.adapter.syncGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
	if held, _ := grantOf(w.st, 42); held != testConnection {
		t.Errorf("the grant is %q", held)
	}
}

// TestAReportTakenDuringADeletionLeavesNoGrantBehind deletes 42 while serve's copy does
// not have its grant yet, and adds the grant to the copy as a report's 204 does, see
// [Connect.reportSoon], right after the deletion reads the copy: under installMu, and
// only while 42's link names the connection. The deletion reads the copy and drops the
// link under installMu, so the report comes after the drop and adds nothing, and no
// grant of 42 stays in the copy without a grant end.
func TestAReportTakenDuringADeletionLeavesNoGrantBehind(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if err := putLink(w.st, 42, link{Connection: testConnection, State: linkLive}); err != nil {
		t.Fatal(err)
	}
	report := func() {
		if l, ok, _ := linkOf(w.st, 42); ok && l.Connection == testConnection {
			putGrant(w.st, 42, testConnection)
		}
	}
	reported := make(chan struct{})
	var once sync.Once
	w.adapter.grantRead = func() {
		once.Do(func() {
			// While the deletion holds installMu, the report waits for it.
			if installMu.TryLock() {
				report()
				installMu.Unlock()
				close(reported)
				return
			}
			go func() {
				installMu.Lock()
				report()
				installMu.Unlock()
				close(reported)
			}()
		})
	}
	if _, err := w.adapter.endInstallation(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	<-reported
	if held, _ := grantOf(w.st, 42); held != "" {
		t.Errorf("the grant is kept for %s, with %d grant ends", held, len(w.apiary.sent(routeGrantsEnd)))
	}
	if _, ok, _ := linkOf(w.st, 42); ok {
		t.Error("the link is kept")
	}
}

// everyHour sets the adapter's clock and the client's to one clock that each grant end
// moves an hour on, and has each grant end return 403 connection_unknown.
func everyHour(w *wired) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var clock sync.Mutex
	read := func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	w.adapter.now, w.client.Now = read, read
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route != routeGrantsEnd {
			return 0, ""
		}
		clock.Lock()
		now = now.Add(time.Hour)
		clock.Unlock()
		return 403, `{"error":"connection_unknown"}`
	}
}

// TestAnEndedConnectionDropsItsGrants pins that a connection serve takes as ended drops
// the grants of that connection from the copy, and keeps those of another connection.
func TestAnEndedConnectionDropsItsGrants(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	putGrant(w.st, 42, testConnection)
	putGrant(w.st, 44, otherConnection)
	if _, err := dropConnection(w.st, testConnection); err != nil {
		t.Fatal(err)
	}
	if held, _ := grantOf(w.st, 42); held != "" {
		t.Errorf("the grant of the ended connection is kept for %s", held)
	}
	if held, _ := grantOf(w.st, 44); held != otherConnection {
		t.Errorf("the grant of another connection is %q", held)
	}
}

// TestAnUnlinkedGrantEndStopsOnceItsConnectionEnds deletes 42 before serve has its
// grant, see [deletedBeforeTheReport], while 43 is linked live to the same connection,
// and has each grant end of 42 return 403 connection_unknown an hour apart: once 43's
// link has counted the 403s for a day, see [noteAnswer], serve drops the connection
// and its grants, and the grant end of 42 stops with them.
func TestAnUnlinkedGrantEndStopsOnceItsConnectionEnds(t *testing.T) {
	w := deletedBeforeTheReport(t)
	w.retryEnds()
	if err := grantedLink(w.st, 43, testConnection, linkLive); err != nil {
		t.Fatal(err)
	}
	w.apiary.grant("43", testConnection)
	everyHour(w)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.endsDone(t, 42)
	if held, _ := grantOf(w.st, 42); held != "" {
		t.Errorf("the grant of 42 is kept for %s", held)
	}
	if _, ok, _ := linkOf(w.st, 43); ok {
		t.Error("the link of 43 is kept")
	}
	log := w.log.String()
	if !strings.Contains(log, `"msg":"Qory Apiary answered connection_unknown for a day, so the connection is dropped","connection":"`+testConnection+`"`) || strings.Contains(log, "to the end of the grant of an installation that has no link") {
		t.Errorf("the log %s", log)
	}
}

// TestAnUnlinkedGrantEndIsNeverStoppedBy403s deletes 42 before serve has its grant,
// see [deletedBeforeTheReport], with no other link to the connection, and has each
// grant end return 403 connection_unknown an hour apart: no live link counts the 403s,
// so past a day, see [forbiddenFor], the grant end is still sent again, at most a
// minute apart, and the grant stays in the copy.
func TestAnUnlinkedGrantEndIsNeverStoppedBy403s(t *testing.T) {
	w := deletedBeforeTheReport(t)
	w.retryEnds()
	everyHour(w)
	hourly := w.apiary.refuse
	const tries = 30
	past := make(chan struct{})
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeGrantsEnd && n == tries {
			close(past)
		}
		return hourly(route, n)
	}
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-past:
	case <-time.After(5 * time.Second):
		t.Fatalf("%d grant ends", len(w.apiary.sent(routeGrantsEnd)))
	}
	if !w.adapter.ending(42) {
		t.Error("the grant end is no longer sent again")
	}
	w.adapter.stopEnds()
	if held, _ := grantOf(w.st, 42); held != testConnection {
		t.Errorf("the grant is %q", held)
	}
	w.mu.Lock()
	for _, d := range w.endWaits {
		if d > time.Minute {
			t.Errorf("waited %v", d)
		}
	}
	w.mu.Unlock()
}

// TestAnUnlinkedGrantEndLeavesTheFeedAtOnce deletes 42 before serve has its grant, see
// [deletedBeforeTheReport], and holds Qory Apiary's answer to the grant end: the
// change feed's step that starts the grant end returns while the grant end waits.
func TestAnUnlinkedGrantEndLeavesTheFeedAtOnce(t *testing.T) {
	w := deletedBeforeTheReport(t)
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrantsEnd {
			<-release
		}
		return 0, ""
	}
	stepped := make(chan error, 1)
	go func() { stepped <- w.feed.step(context.Background()) }()
	select {
	case err := <-stepped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the feed's step waits for the grant end")
	}
	eventually(t, "the grant end", func() bool { return len(w.apiary.sent(routeGrantsEnd)) == 1 || w.adapter.ending(42) })
	close(release)
	w.endsDone(t, 42)
	if n := len(w.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
	if held, _ := grantOf(w.st, 42); held != "" {
		t.Errorf("the grant is kept for %s", held)
	}
}

// TestAConnectForTheAccountStopsAnUnlinkedGrantEnd deletes 99, on acme's account,
// before serve has its grant, and has the grant end that the change feed's grant entry
// starts return 503, so it is sent again later: a connect for acme, which links 42,
// stops it, and no try follows.
func TestAConnectForTheAccountStopsAnUnlinkedGrantEnd(t *testing.T) {
	rig, _ := reportRig(t)
	if err := putLink(rig.st, 99, link{Connection: otherConnection, State: linkLive, Account: acme.ID}); err != nil {
		t.Fatal(err)
	}
	rig.apiary.grant("99", otherConnection)
	if _, err := rig.adapter.endInstallation(context.Background(), 99); err != nil {
		t.Fatal(err)
	}
	// Each wait before a try lasts until the connect is done, or until the grant end is
	// stopped.
	connected := make(chan struct{})
	rig.adapter.endSleep = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-connected:
		case <-ctx.Done():
		}
		return ctx.Err()
	}
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrantsEnd {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	rig.apiary.changes = []contracts.Change{{Kind: contracts.ChangeGrant, ConnectionID: otherConnection, GrantRef: "99", Status: "linked"}}
	if err := rig.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the first grant end", func() bool { return len(rig.apiary.sent(routeGrantsEnd)) == 1 })
	if !rig.adapter.ending(99) {
		t.Fatal("the grant end is not sent again")
	}
	connectWith(t, rig, newNonce())
	if rig.adapter.ending(99) {
		t.Error("the grant end is still sent again after the connect")
	}
	close(connected)
	rig.adapter.stopEnds()
	if n := len(rig.apiary.sent(routeGrantsEnd)); n != 1 {
		t.Errorf("%d grant ends", n)
	}
	if held, _ := grantOf(rig.st, 99); held != otherConnection {
		t.Errorf("the grant is %q", held)
	}
}

// TestAnUnlinkedGrantEndLogsNoLink deletes 42 before serve has its grant, see
// [deletedBeforeTheReport], and has the grant end that the change feed's grant entry
// starts return the signed 204, then, for another run, 403 forbidden: each line says
// what serve does with the grant in the copy, and none mentions a link.
func TestAnUnlinkedGrantEndLogsNoLink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		line   string
	}{
		{name: "204", line: `"level":"INFO","msg":"the grant of an installation that has no link ended in Qory Apiary, so serve drops the grant from the copy","installation":42`},
		{name: "forbidden", status: 403, line: `"level":"ERROR","msg":"The end of the grant of an installation that has no link failed with an error from Qory Apiary that a retry does not change, so serve keeps the grant in the copy and sends no more grant end for it until a connect for its account or a restart","installation":42`},
	} {
		w := deletedBeforeTheReport(t)
		w.apiary.refuse = func(route string, _ int) (int, string) {
			if route == routeGrantsEnd && tc.status != 0 {
				return tc.status, `{"error":"forbidden"}`
			}
			return 0, ""
		}
		if err := w.feed.step(context.Background()); err != nil {
			t.Fatal(err)
		}
		w.endsDone(t, 42)
		log := w.log.String()
		if !strings.Contains(log, tc.line) || strings.Contains(log, `"msg":"the installation's grant ended in Qory Apiary, so serve drops its link"`) || strings.Contains(log, "keeps its link") {
			t.Errorf("%s: the log %s", tc.name, log)
		}
	}
}
