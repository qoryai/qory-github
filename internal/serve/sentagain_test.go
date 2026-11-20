package serve

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github/internal/store"
)

// unreadable are signed answers that change nothing and are sent again, see [sentAgain]:
// a 409 and a 403 whose body the adapter cannot read, a 403 whose must_understand lists a
// pointer it does not define, and a readable 409 connection_suspended.
var unreadable = []struct {
	name   string
	status int
	body   string
}{
	{"a 409 with no JSON", 409, `<html>`},
	{"a 403 with no JSON", 403, `<html>`},
	{"a 403 with a must_understand it does not meet", 403, `{"error":"forbidden","zz":1,"must_understand":["/zz"]}`},
	{"a 409 connection_suspended", 409, `{"error":"connection_suspended"}`},
}

// TestAGrantReportAnsweredWithoutACodeIsSentAgain has Qory Apiary answer the first report
// of a grant with each answer in unreadable: the report is sent again after 2 seconds,
// built anew, and Qory Apiary takes it, so the link and the grant stay. A report refused
// 409 grant_taken, which is final, is sent once and drops the link.
func TestAGrantReportAnsweredWithoutACodeIsSentAgain(t *testing.T) {
	for _, tc := range unreadable {
		rig, clock := reportRig(t)
		rig.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeGrants && n == 1 {
				return tc.status, tc.body
			}
			return 0, ""
		}
		connectWith(t, rig, newNonce())
		eventually(t, tc.name+": the grant kept", func() bool { c, _ := grantOf(rig.st, 42); return c == testConnection })
		sent := rig.apiary.sent(routeGrants)
		if len(sent) != 2 || sent[0].signature == sent[1].signature {
			t.Errorf("%s: reported %d times", tc.name, len(sent))
		}
		if w := clock.waited(); !slices.Equal(w, []time.Duration{2 * time.Second}) {
			t.Errorf("%s: waited %v", tc.name, w)
		}
		// The first listing, sent at the same time, makes the link live.
		eventually(t, tc.name+": the link live", func() bool {
			l, ok, _ := linkOf(rig.st, 42)
			return ok && l.Connection == testConnection && l.State == linkLive
		})
		if strings.Contains(rig.log.String(), "so serve drops its link") {
			t.Errorf("%s: the log says the link is dropped: %s", tc.name, rig.log.String())
		}
	}

	rig, clock := reportRig(t)
	rig.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeGrants {
			return 409, `{"error":"grant_taken"}`
		}
		return 0, ""
	}
	connectWith(t, rig, newNonce())
	eventually(t, "the link dropped", func() bool { _, ok, _ := linkOf(rig.st, 42); return !ok })
	if n := len(rig.apiary.sent(routeGrants)); n != 1 || len(clock.waited()) != 0 {
		t.Errorf("grant_taken: reported %d times, waited %v", n, clock.waited())
	}
}

// TestAGrantEndAnsweredWithoutACodeIsSentAgain deletes the linked installation 42, and has
// Qory Apiary answer its grant end with each answer in unreadable three times: the grant
// end is sent again after 2, 4 and 8 seconds, no line says it is refused for good, the
// refusal is not kept, and the signed 204 that follows drops the grant and the link.
func TestAGrantEndAnsweredWithoutACodeIsSentAgain(t *testing.T) {
	for _, tc := range unreadable {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.retryEnds()
		grantedLink(w.st, 42, testConnection, linkLive)
		w.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeGrantsEnd && n <= 3 {
				return tc.status, tc.body
			}
			return 0, ""
		}
		w.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
		w.endsDone(t, 42)
		if n := len(w.apiary.sent(routeGrantsEnd)); n != 4 {
			t.Errorf("%s: %d grant ends", tc.name, n)
		}
		w.mu.Lock()
		if !slices.Equal(w.endWaits, []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}) {
			t.Errorf("%s: waited %v", tc.name, w.endWaits)
		}
		w.mu.Unlock()
		if w.adapter.endRefusedFor(42, testConnection) || strings.Contains(w.log.String(), "that a retry does not change") {
			t.Errorf("%s: the grant end is refused for good: %s", tc.name, w.log.String())
		}
		if linked, _ := Linked(w.st, 42); linked {
			t.Errorf("%s: the link is kept after the 204", tc.name)
		}
		if held, _ := grantOf(w.st, 42); held != "" {
			t.Errorf("%s: the grant %q is kept after the 204", tc.name, held)
		}
	}
}

// TestAFirstListingAnsweredWithoutACodeIsSentAgain has Qory Apiary answer a pending
// link's first listing with each answer in unreadable: no line says the listing failed,
// the listing is sent again, read from GitHub once, after waits that double from a
// second, and the link stays. A listing refused 400 invalid_request is final: its part is
// sent once, with no wait, and a line says it failed.
func TestAFirstListingAnsweredWithoutACodeIsSentAgain(t *testing.T) {
	for _, tc := range append(unreadable, struct {
		name   string
		status int
		body   string
	}{"a 400 invalid_request", 400, `{"error":"invalid_request"}`}) {
		rig := newConnectRig(t)
		rig.apiary.refuse = func(route string, _ int) (int, string) {
			if route == routeCollections {
				return tc.status, tc.body
			}
			return 0, ""
		}
		grantedPutLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
		rig.c.listSoon(42, testConnection, false)
		const failed = `"msg":"listing the installation's repositories failed"`
		if tc.status == 400 {
			eventually(t, tc.name+": the line", func() bool { return strings.Contains(rig.log.String(), failed) })
			rig.c.stop()
			rig.mu.Lock()
			// A refused part is followed by the listing's empty part, complete: false.
			if n := len(rig.apiary.sent(routeCollections)); len(rig.waits) != 0 || n != 2 {
				t.Errorf("%s: waited %v, %d parts", tc.name, rig.waits, n)
			}
			rig.mu.Unlock()
			continue
		}
		eventually(t, tc.name+": three waits", func() bool { rig.mu.Lock(); defer rig.mu.Unlock(); return len(rig.waits) >= 3 })
		rig.c.stop()
		rig.mu.Lock()
		waits := slices.Clone(rig.waits[:3])
		rig.mu.Unlock()
		if !slices.Equal(waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
			t.Errorf("%s: waited %v", tc.name, waits)
		}
		rig.linked(t, 42, testConnection, linkPending)
		if n := rig.gh.listings(); n != 1 {
			t.Errorf("%s: GitHub's repositories read %d times", tc.name, n)
		}
		if strings.Contains(rig.log.String(), failed) {
			t.Errorf("%s: the log says the listing failed: %s", tc.name, rig.log.String())
		}
	}
}

// TestADeliveryAnswered403WithoutACodeIsSentAgainAndKeepsTheRecords has Qory Apiary answer
// each request of a delivered comment with a signed 403 whose body the adapter cannot
// read: it changes nothing, so the installation's link, the collection and the
// repository's installation stay, and the worker sends the comment again up to its
// attempts (3 in the test) and marks the delivery failed. The refusal is no known end of
// a connection, so noteAnswer does not count it.
func TestADeliveryAnswered403WithoutACodeIsSentAgainAndKeepsTheRecords(t *testing.T) {
	for _, body := range []string{`<html>`, `{"error":"forbidden","zz":1,"must_understand":["/zz"]}`} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		grantedLink(w.st, 42, testConnection, linkLive)
		setReach(w.st, widgetsRef, 42)
		linkCollection(w.st, widgetsRef)
		w.apiary.refuse = func(string, int) (int, string) { return 403, body }
		ev := issueEvent(42, "acme/widgets", "created")
		ev["comment"] = map[string]any{"id": 5, "html_url": "https://github.com/acme/widgets/issues/1#issuecomment-5", "body": "Same here.", "user": map[string]any{"login": "bob", "type": "User"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z"}
		w.deliver(t, "issue_comment", guid1, ev)
		if s := state(w.st, guid1); s != store.Failed {
			t.Errorf("%q: the delivery is %s", body, s)
		}
		if n := len(w.apiary.sent(routeComments)); n != 3 {
			t.Errorf("%q: %d comments requests, want 3", body, n)
		}
		if ok, _ := Linked(w.st, 42); !ok {
			t.Errorf("%q: the installation is unlinked", body)
		}
		if ok, _ := collectionLinked(w.st, widgetsRef); !ok {
			t.Errorf("%q: the collection is unlinked", body)
		}
		if _, ok, _ := reachOf(w.st, widgetsRef); !ok {
			t.Errorf("%q: the repository's installation is dropped", body)
		}
		if ok, _ := present(w.st.Get(nsForbidden, testConnection)); ok {
			t.Errorf("%q: the 403 is kept as the first of a lasting one", body)
		}
	}
}

// TestADisconnectOfAConnectionAnswered403WithoutACodeIsTriedAgain has Qory Apiary answer
// each POST /v1/connections/disconnect 403: with a code (forbidden) the error is final
// after the disconnectTries sends, with the waits that double from disconnectWait; with
// no code, because the body cannot be read, it is an error that may pass, so the caller
// sends the request again.
func TestADisconnectOfAConnectionAnswered403WithoutACodeIsTriedAgain(t *testing.T) {
	for _, tc := range []struct {
		body      string
		permanent bool
	}{{`{"error":"forbidden"}`, true}, {`<html>`, false}, {`{"error":"forbidden","zz":1,"must_understand":["/zz"]}`, false}} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.apiary.refuse = func(string, int) (int, string) { return 403, tc.body }
		var mu sync.Mutex
		var waits []time.Duration
		w.client.Sleep = func(_ context.Context, d time.Duration) error {
			mu.Lock()
			defer mu.Unlock()
			waits = append(waits, d)
			return nil
		}
		err := w.adapter.endConnection(context.Background(), testConnection)
		var refused *refusedError
		if tc.permanent {
			// A 403 with a code that lasts is logged and passed.
			if err != nil {
				t.Errorf("%q: err %v", tc.body, err)
			}
		} else if !errors.As(err, &refused) || refused.status != http.StatusForbidden || refused.code != "" || IsPermanent(err) {
			t.Errorf("%q: err %v", tc.body, err)
		}
		mu.Lock()
		if n := len(w.apiary.sent(routeConnectionsDisconnect)); n != disconnectTries || len(waits) != disconnectTries-1 || waits[0] != disconnectWait || waits[len(waits)-1] != disconnectWait<<(disconnectTries-2) {
			t.Errorf("%q: %d sends, waited %v", tc.body, n, waits)
		}
		mu.Unlock()
	}
}

// TestAReplacedConnectionWhoseEndAnswers403WithoutACodeIsListedAgain has Qory Apiary take
// the empty listing of a replaced connection, and answer its disconnect 403 with a body the
// adapter cannot read, as many times as one call sends it (disconnectTries). The end is an
// error that may pass: the replaced record stays, the first listing's loop waits a second
// and sends the listing and the disconnect again, and the second disconnect, the signed 204,
// forgets the record.
func TestAReplacedConnectionWhoseEndAnswers403WithoutACodeIsListedAgain(t *testing.T) {
	rig := newConnectRig(t)
	rig.client.Sleep = func(context.Context, time.Duration) error { return nil }
	rig.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeConnectionsDisconnect && n <= disconnectTries {
			return 403, `<html>`
		}
		return 0, ""
	}
	grantedPutLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	keepReplaced(rig.st, 42, link{Connection: otherConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	var mu sync.Mutex
	type moment struct {
		kept               bool
		listings, disconns int
	}
	var first *moment
	orig := rig.c.sleep
	rig.c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		if first == nil {
			_, kept, _ := replacedOf(rig.st, otherConnection)
			first = &moment{kept, len(rig.apiary.sent(routeCollections)), len(rig.apiary.sent(routeConnectionsDisconnect))}
		}
		mu.Unlock()
		return orig(ctx, d)
	}
	rig.c.listSoon(42, otherConnection, false)
	eventually(t, "the replaced connection forgotten", func() bool { _, ok, _ := replacedOf(rig.st, otherConnection); return !ok })
	rig.c.stop()
	mu.Lock()
	defer mu.Unlock()
	if first == nil || *first != (moment{true, 1, disconnectTries}) {
		t.Errorf("at the first wait: %+v", first)
	}
	if n, m := len(rig.apiary.sent(routeCollections)), len(rig.apiary.sent(routeConnectionsDisconnect)); n != 2 || m != disconnectTries+1 {
		t.Errorf("%d listings and %d disconnects", n, m)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if !slices.Equal(rig.waits, []time.Duration{time.Second}) {
		t.Errorf("waited %v", rig.waits)
	}
	rig.linked(t, 42, testConnection, linkPending)
}

// TestAGrantReportIsBoundedByTheConnectReturn sends the report of the installation 42's
// grant while the injected clock runs, and has Qory Apiary answer it as the table says.
// An answer that is not final, a 403 or a 409 with no code or a 409 connection_suspended,
// is sent again after waits that double from 2 seconds to a minute, 10 sends in all, until
// the clock passes the expiry of the connect return, 300 seconds after the connect: then
// reportFailed drops the installation's link, its repository's reach, its collection's
// link and its pull mark, nothing is sent again, and the grant is never in the copy. The
// signed 204 before the expiry keeps all of it and adds the grant to the copy. A 409
// grant_taken is final: one send, no wait, and the same drop.
func TestAGrantReportIsBoundedByTheConnectReturn(t *testing.T) {
	untilExpiry := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute, 58 * time.Second}
	for _, tc := range []struct {
		name    string
		answer  func(n int) (int, string)
		sends   int
		waits   []time.Duration
		dropped bool
	}{
		{"a 403 with no code", func(int) (int, string) { return 403, `<html>` }, 10, untilExpiry, true},
		{"a 409 with no code", func(int) (int, string) { return 409, `<html>` }, 10, untilExpiry, true},
		{"a 409 connection_suspended", func(int) (int, string) { return 409, `{"error":"connection_suspended"}` }, 10, untilExpiry, true},
		{"a 204 after three answers", func(n int) (int, string) {
			if n <= 3 {
				return 409, `{"error":"connection_suspended"}`
			}
			return 0, ""
		}, 4, untilExpiry[:3], false},
		{"a 409 grant_taken", func(int) (int, string) { return 409, `{"error":"grant_taken"}` }, 1, nil, true},
	} {
		rig, clock := reportRig(t)
		rig.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeGrants {
				return tc.answer(n)
			}
			return 0, ""
		}
		expires := clock.now().Add(returnFor)
		ref := refOf("acme/widgets")
		putLink(rig.st, 42, link{Connection: testConnection, State: linkPending, Return: expires.Unix()})
		setReach(rig.st, ref, 42)
		linkCollection(rig.st, ref)
		keepPulled(rig.st, ref, pullMark{Since: clock.now()})
		rig.c.reportSoon(42, testConnection, newNonce(), contracts.Account{Ref: "500", Title: "acme"}, expires)
		eventually(t, tc.name+": the report ends", func() bool {
			g, _ := grantOf(rig.st, 42)
			_, linked, _ := linkOf(rig.st, 42)
			return (g != "") != tc.dropped && linked != tc.dropped
		})
		rig.c.stop()
		if n := len(rig.apiary.sent(routeGrants)); n != tc.sends {
			t.Errorf("%s: %d sends, want %d", tc.name, n, tc.sends)
		}
		if w := clock.waited(); !slices.Equal(w, tc.waits) {
			t.Errorf("%s: waited %v, want %v", tc.name, w, tc.waits)
		}
		if tc.dropped && !clock.now().Equal(expires) && len(tc.waits) > 0 {
			t.Errorf("%s: the clock is at %v, want the expiry %v", tc.name, clock.now(), expires)
		}
		_, linked, _ := linkOf(rig.st, 42)
		held, _ := grantOf(rig.st, 42)
		_, reached, _ := reachOf(rig.st, ref)
		collection, _ := collectionLinked(rig.st, ref)
		pulled, _ := pulledOf(rig.st, ref)
		if linked == tc.dropped || reached == tc.dropped || collection == tc.dropped || pulled.Since.IsZero() != tc.dropped || (held == testConnection) == tc.dropped {
			t.Errorf("%s: link %v, grant %q, reach %v, collection linked %v, pull mark %v", tc.name, linked, held, reached, collection, pulled.Since)
		}
		if line := strings.Contains(rig.log.String(), "so serve drops its link: connect it again"); line != tc.dropped {
			t.Errorf("%s: the drop line is %v: %s", tc.name, line, rig.log.String())
		}
	}
}
