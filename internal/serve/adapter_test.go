package serve

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// wired is the adapter whole: a receiver and a worker with the adapter's handlers, the
// change feed's reader, Qory Apiary's client, a fake Qory Apiary and a fake GitHub.
type wired struct {
	st      *store.Store
	apiary  *fakeApiary
	gh      *fakeGitHub
	client  *Apiary
	adapter *Adapter
	feed    *feed
	mux     http.Handler
	log     *syncBuffer

	mu    sync.Mutex
	slept []time.Duration
}

func newWired(t *testing.T, dir string) *wired {
	t.Helper()
	st := openStore(t, dir)
	access := newKey(t)
	w := &wired{st: st, apiary: newFakeApiary(t, access), gh: newFakeGitHub(t), log: &syncBuffer{}}
	logger := slog.New(slog.NewJSONHandler(w.log, nil))
	w.client = w.apiary.client(access)
	w.client.Log = logger
	w.client.Unlinked = func(ref string, began uint64) { unlinkSince(st, ref, began) }
	w.client.Sleep = func(_ context.Context, d time.Duration) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.slept = append(w.slept, d)
		return nil
	}
	w.adapter = &Adapter{Store: st, GitHub: github.Client{API: w.gh.srv.URL}, AppID: "1", Key: appKey(), Slug: testSlug, Sink: w.client, Log: logger}
	hs := &Handlers{}
	w.adapter.Register(hs)
	worker := &Worker{Store: st, Handlers: hs, Log: logger, Attempts: 3, Backoff: func(int) time.Duration { return time.Millisecond }}
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: logger, Stored: worker.Notify}
	worker.Start()
	t.Cleanup(func() { worker.Stop(5 * time.Second) })
	w.mux = rc.Mux()
	w.feed = &feed{apiary: w.client, adapter: w.adapter, store: st, publicURL: "https://qory-github.example.com", log: logger}
	return w
}

// deliver sends GitHub's delivery of event with body and waits until it is handled.
func (w *wired) deliver(t *testing.T, event, guid string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	if rec := post(w.mux, event, guid, string(b), sign(string(b))); rec.Code != http.StatusAccepted {
		t.Fatalf("%s: status %d", event, rec.Code)
	}
	eventually(t, event+" handled", func() bool { s := state(w.st, guid); return s == store.Done || s == store.Failed })
}

// issueEvent is an issues event of the installation on an issue of repo.
func issueEvent(installation int64, repo, action string) map[string]any {
	is := ghIssue(1, 0)
	is["html_url"] = "https://github.com/" + repo + "/issues/1"
	return map[string]any{
		"action": action, "installation": map[string]any{"id": installation}, "issue": is,
		"repository": map[string]any{"full_name": repo, "html_url": "https://github.com/" + repo},
	}
}

// TestAnIssueIsSentOnlyForALinkedInstallationAndCollection delivers an issue of a
// linked collection, which is one signed POST /v1/source-items with its time, then one
// of a collection that is not linked, and one of an installation that is not linked,
// which send nothing.
func TestAnIssueIsSentOnlyForALinkedInstallationAndCollection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	linkCollection(w.st, "Acme/Widgets")
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	sent := w.apiary.sent(routeItems)
	if len(sent) != 1 {
		t.Fatalf("%d items requests", len(sent))
	}
	var req contracts.SourceItems
	json.Unmarshal(sent[0].raw, &req)
	if req.CollectionRef != "acme/widgets" || len(req.Items) != 1 || req.Items[0].Ref != "acme/widgets#1" || req.Listing != nil || !timeShape.MatchString(req.Time) {
		t.Errorf("sent %s", sent[0].raw)
	}
	if tm, _ := time.Parse(time.RFC3339, req.Time); time.Since(tm).Abs() > time.Minute {
		t.Errorf("the time %s", req.Time)
	}
	w.deliver(t, "issues", guid2, issueEvent(42, "acme/gadgets", "opened"))
	w.deliver(t, "issues", guid3, issueEvent(43, "acme/widgets", "opened"))
	if n := len(w.apiary.sent(routeItems)); n != 1 {
		t.Errorf("%d items requests", n)
	}
	if !strings.Contains(w.log.String(), "the collection is not linked") || !strings.Contains(w.log.String(), "the installation is not linked") {
		t.Errorf("the log: %s", w.log.String())
	}
}

// TestACommentIsSentForALinkedCollection delivers a comment on an issue of a linked
// collection.
func TestACommentIsSentForALinkedCollection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	linkCollection(w.st, "acme/widgets")
	ev := issueEvent(42, "acme/widgets", "created")
	ev["comment"] = map[string]any{"id": 5, "html_url": "https://github.com/acme/widgets/issues/1#issuecomment-5", "body": "Same here.", "user": map[string]any{"login": "bob", "type": "User"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z"}
	w.deliver(t, "issue_comment", guid1, ev)
	sent := w.apiary.sent(routeComments)
	if len(sent) != 1 || sent[0].body["item_ref"] != "acme/widgets#1" {
		t.Fatalf("sent %v", sent)
	}
}

// TestRepositoriesAddedListsTheCollections delivers installation_repositories added,
// and checks the listing reaches Qory Apiary, complete, read with a token that reads
// metadata alone, and that each repository's installation is kept.
func TestRepositoriesAddedListsTheCollections(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{map[string]any{"full_name": "acme/gadgets"}}})
	sent := w.apiary.sent(routeCollections)
	if len(sent) != 1 {
		t.Fatalf("%d collections requests", len(sent))
	}
	var req contracts.SourceCollections
	json.Unmarshal(sent[0].raw, &req)
	if len(req.Collections) != 2 || req.Collections[0].Ref != "acme/widgets" || !req.Listing.Complete || req.Listing.Part != 1 || req.Collections[0].Target == nil {
		t.Errorf("sent %s", sent[0].raw)
	}
	for _, ref := range []string{"acme/widgets", "ACME/gadgets"} {
		if inst, ok, err := reachOf(w.st, ref); inst != 42 || !ok || err != nil {
			t.Errorf("%s: %d %v %v", ref, inst, ok, err)
		}
	}
	if len(w.gh.mints) != 1 || w.gh.mints[0] != `{"permissions":{"metadata":"read"}}` {
		t.Errorf("mints %v", w.gh.mints)
	}
	if strings.Contains(w.log.String(), ghToken) {
		t.Errorf("the log carries the token")
	}
}

// TestRepositoriesRemovedAreDisconnected delivers installation_repositories removed.
func TestRepositoriesRemovedAreDisconnected(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	setReach(w.st, "acme/old", 42)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "removed", "installation": map[string]any{"id": 42}, "repositories_removed": []any{map[string]any{"full_name": "acme/old"}}})
	sent := w.apiary.sent(routeDisconnect)
	if len(sent) != 1 || sent[0].body["collection_ref"] != "acme/old" || sent[0].body["reason"] != "removed" {
		t.Fatalf("sent %v", sent)
	}
	if _, ok, _ := reachOf(w.st, "acme/old"); ok {
		t.Error("the removed repository's installation is kept")
	}
	if len(w.apiary.sent(routeCollections)) != 1 {
		t.Error("the repositories are not listed again")
	}
}

// TestAnInstallationSuspendedThenDeletedDisconnectsItsCollections suspends the
// installation, which disconnects its collections paused, and deletes it, which
// disconnects them ended and unlinks it; another installation's stay.
func TestAnInstallationSuspendedThenDeletedDisconnectsItsCollections(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	Link(w.st, 43)
	setReach(w.st, "acme/widgets", 42)
	setReach(w.st, "acme/gadgets", 42)
	setReach(w.st, "other/thing", 43)
	w.deliver(t, "installation", guid1, map[string]any{"action": "suspend", "installation": map[string]any{"id": 42}})
	w.deliver(t, "installation", guid2, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	var got []string
	for _, r := range w.apiary.sent(routeDisconnect) {
		got = append(got, r.body["collection_ref"].(string)+" "+r.body["reason"].(string))
	}
	if strings.Join(got, ", ") != "acme/gadgets paused, acme/widgets paused, acme/gadgets ended, acme/widgets ended" {
		t.Errorf("disconnected %v", got)
	}
	if ok, _ := Linked(w.st, 42); ok {
		t.Error("the deleted installation is still linked")
	}
	if ok, _ := Linked(w.st, 43); !ok {
		t.Error("another installation is unlinked")
	}
	if refs, _ := reachedBy(w.st, 42); len(refs) != 0 {
		t.Errorf("the deleted installation's repositories are kept: %v", refs)
	}
	// Its deliveries are not handled any more.
	w.deliver(t, "installation", guid3, map[string]any{"action": "unsuspend", "installation": map[string]any{"id": 42}})
	if len(w.apiary.sent(routeCollections)) != 0 {
		t.Error("an unlinked installation is listed")
	}
}

// TestAListingOf250CollectionsIsSentInThreeParts lists 250 repositories, which GitHub
// answers in one page, and checks the three parts: 100, 100 and 50, one listing id and
// start, and complete on the last alone. With part 2 refused, no part says complete.
func TestAListingOf250CollectionsIsSentInThreeParts(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.gh.repos = nil
		for i := range 250 {
			w.gh.repos = append(w.gh.repos, "acme/repo-"+strconv.Itoa(i))
		}
		if refuse {
			w.apiary.refuse = func(route string, n int) (int, string) {
				if route == routeCollections && n == 2 {
					return 400, `{"error":"invalid_request"}`
				}
				return 0, ""
			}
		}
		err := w.adapter.listRepositories(context.Background(), 42)
		if refuse != (err != nil) || refuse != IsPermanent(err) {
			t.Fatalf("refused %v: err %v", refuse, err)
		}
		var parts []string
		var first contracts.Listing
		for i, r := range w.apiary.sent(routeCollections) {
			var req contracts.SourceCollections
			json.Unmarshal(r.raw, &req)
			if i == 0 {
				first = req.Listing
			}
			if req.Listing.ID != first.ID || req.Listing.StartedAt != first.StartedAt || req.Listing.Part != i+1 {
				t.Errorf("part %d: listing %+v, first %+v", i+1, req.Listing, first)
			}
			parts = append(parts, strconv.Itoa(len(req.Collections))+" "+strconv.FormatBool(req.Listing.Complete))
		}
		want := "100 false, 100 false, 50 true"
		if refuse {
			// Part 2 is refused; the part that ends the listing says it is not complete.
			want = "100 false, 100 false, 0 false"
		}
		if strings.Join(parts, ", ") != want {
			t.Errorf("refused %v: parts %v", refuse, parts)
		}
	}
}

// TestTheFeedLinksACollectionAndFillsIt reads a feed that links a collection, which
// sends its open issues, and then unlinks it.
func TestTheFeedLinksACollectionAndFillsIt(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, "acme/widgets", 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0), ghIssue(2, 0)}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); !ok {
		t.Error("the collection is not linked")
	}
	sent := w.apiary.sent(routeItems)
	if len(sent) != 1 {
		t.Fatalf("%d items requests", len(sent))
	}
	var req contracts.SourceItems
	json.Unmarshal(sent[0].raw, &req)
	if req.CollectionRef != "acme/widgets" || len(req.Items) != 2 || req.Listing == nil || req.Listing.Complete {
		t.Errorf("filled with %s", sent[0].raw)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" {
		t.Errorf("the cursor %q", c)
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "unlinked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); ok {
		t.Error("the collection is still linked")
	}
	if gets := w.apiary.sent("GET " + routeChanges); len(gets) != 2 || gets[0].target != routeChanges || gets[1].target != routeChanges+"?after=c_1" {
		t.Errorf("read %v", gets)
	}
}

// TestTextsPastTheContractsLimitsReachQoryApiaryValid fills a collection from GitHub's
// API on a loopback host and port, and delivers an event, whose issue has a label of 101
// characters and a filer of 300, and whose comment has an author of 300, and checks
// every body reaches Qory Apiary as the contract takes it: the fake checks each against
// the contract's schema, and the texts are cut and the system is the host alone. The
// cuts are logged by ref, field and length, never by their text, throttled, and the
// count held back is logged when the log stops.
func TestTextsPastTheContractsLimitsReachQoryApiaryValid(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	if !strings.Contains(strings.TrimPrefix(w.gh.srv.URL, "http://"), ":") {
		t.Fatalf("GitHub's API is at %s, without a port", w.gh.srv.URL)
	}
	is := ghIssue(1, 1)
	is["labels"] = []any{map[string]any{"name": strings.Repeat("a", 101)}}
	is["user"] = map[string]any{"login": strings.Repeat("n", 300), "type": "User"}
	w.gh.issues = []map[string]any{is}
	w.gh.comments[1] = []map[string]any{{
		"id": 5, "html_url": "https://github.com/acme/widgets/issues/1#issuecomment-5", "body": "Same here.",
		"user": map[string]any{"login": strings.Repeat("m", 300), "type": "User"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z",
	}}
	Link(w.st, 42)
	setReach(w.st, "acme/widgets", 42)
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	ev := issueEvent(42, "acme/widgets", "edited")
	ev["issue"] = is
	w.deliver(t, "issues", guid1, ev)
	items := w.apiary.sent(routeItems)
	if len(items) != 2 {
		t.Fatalf("%d items requests", len(items))
	}
	for _, sent := range items {
		var req contracts.SourceItems
		json.Unmarshal(sent.raw, &req)
		it := req.Items[0]
		if len(req.Items) != 1 || !reflect.DeepEqual(it.Labels, []string{strings.Repeat("a", 100)}) || it.FiledBy.Name != strings.Repeat("n", 100) || it.Target == nil || it.Target.System != "127.0.0.1" {
			t.Errorf("sent %s", sent.raw)
		}
	}
	comments := w.apiary.sent(routeComments)
	if len(comments) != 1 {
		t.Fatalf("%d comments requests", len(comments))
	}
	var req contracts.SourceItemComments
	json.Unmarshal(comments[0].raw, &req)
	if len(req.Comments) != 1 || req.Comments[0].Author.Name != strings.Repeat("m", 100) {
		t.Errorf("sent %s", comments[0].raw)
	}
	w.adapter.stopLog()
	logged := w.log.String()
	if !strings.Contains(logged, `"msg":"cut to the contract's limit","ref":"acme/widgets#1","field":"label","length":101`) || !strings.Contains(logged, `"msg":"cuts dropped","cuts_dropped":`) {
		t.Errorf("the log: %s", logged)
	}
	if strings.Contains(logged, strings.Repeat("a", 100)) || strings.Contains(logged, strings.Repeat("n", 100)) || strings.Contains(logged, strings.Repeat("m", 100)) {
		t.Errorf("a text is logged: %s", logged)
	}
}

// TestTheFeedTakesInAWorkItemOnceThroughAReplay reads a work item taken in, which
// labels the issue and comments once, and reads the feed again from the start, which
// posts no second comment; and stores the sync interval, clamped.
func TestTheFeedTakesInAWorkItemOnceThroughAReplay(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, "acme/widgets", 42)
	sixty, day := 60, 86400
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: "acme/widgets#7", Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
		contracts.Change{Kind: contracts.ChangeSync, Interval: &sixty},
	)
	for range 2 {
		if err := w.feed.step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := w.st.Delete(nsAdapter, keyCursor); err != nil {
			t.Fatal(err)
		}
	}
	posted := w.gh.postedComments()
	if len(posted) != 1 || !strings.HasPrefix(posted[0], "<!-- qory:work-item wi_42 -->") || len(w.gh.labelled) != 2 {
		t.Errorf("posted %q, labelled %v", posted, w.gh.labelled)
	}
	if !strings.Contains(strings.Join(w.gh.mints, " "), `{"permissions":{"issues":"write"},"repositories":["widgets"]}`) {
		t.Errorf("mints %v", w.gh.mints)
	}
	if v, _ := w.st.Get(nsAdapter, keySyncInterval); string(v) != "900" {
		t.Errorf("the interval %s", v)
	}
	for interval, want := range map[*int]string{nil: "3600", &day: "86400"} {
		if err := w.feed.apply(context.Background(), contracts.Change{Kind: contracts.ChangeSync, Interval: interval}); err != nil {
			t.Fatal(err)
		}
		if v, _ := w.st.Get(nsAdapter, keySyncInterval); string(v) != want {
			t.Errorf("the interval %s, want %s", v, want)
		}
	}
}

// TestAFeedEntryThatFailsForGoodIsPassed reads a work item of a repository no listing
// named and a collection whose ref is not owner/name, both logged and passed, so the
// cursor moves, and the store holds no link for the bad ref.
func TestAFeedEntryThatFailsForGoodIsPassed(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: "acme/unknown#7", Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
		contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "", Status: "linked"},
		contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: strings.Repeat("a", 300), Status: "linked"},
		contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme", Status: "unlinked"},
	)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_4" {
		t.Errorf("the cursor %q", c)
	}
	logged := w.log.String()
	if !strings.Contains(logged, "no installation is known") || strings.Count(logged, "the collection's ref is not owner/name") != 3 || len(w.gh.requests) != 0 {
		t.Errorf("the log %s, GitHub %v", logged, w.gh.requests)
	}
	n := 0
	w.st.Each(nsCollections, func(string, []byte) error { n++; return nil })
	if n != 0 {
		t.Errorf("%d collections stored", n)
	}
}

// TestAFeedEntryThatMayPassKeepsTheCursor links a collection whose fill Qory Apiary
// answers 500, and checks the step fails and the cursor stays, so the entry is read
// again.
func TestAFeedEntryThatMayPassKeepsTheCursor(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, "acme/widgets", 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeItems {
			return 500, `{"error":"internal"}`
		}
		return 0, ""
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "linked"})
	err := w.feed.step(context.Background())
	if err == nil || IsPermanent(err) || !IsOutage(err) {
		t.Errorf("err %v", err)
	}
	if _, err := w.st.Get(nsAdapter, keyCursor); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the cursor is kept: %v", err)
	}
}

// TestAnAnswerWithAnEntryServeDoesNotKnowIsRefusedWhole serves a page whose last entry
// has a kind, or a status, serve does not know, and checks none of the page is
// applied, its cursor is not kept, and the refusal is logged with the cursor it was
// read after and the entry's kind and status; then serves a page serve knows, which
// moves the feed on.
func TestAnAnswerWithAnEntryServeDoesNotKnowIsRefusedWhole(t *testing.T) {
	for _, bad := range []contracts.Change{
		{Kind: "label", Status: "added"},
		{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: "acme/widgets#7", Status: "shelved", URL: "https://apiary.example.com/work-items/wi_42"},
		{Kind: contracts.ChangeCollection, CollectionRef: "acme/widgets", Status: "archived"},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.apiary.add(contracts.Change{Kind: contracts.ChangeSync})
		if err := w.feed.step(context.Background()); err != nil {
			t.Fatal(err)
		}
		w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: "acme/gadgets", Status: "linked"}, bad)
		var u *unknownChange
		if err := w.feed.step(context.Background()); !errors.As(err, &u) || u.after != "c_1" || u.kind != bad.Kind || u.status != bad.Status {
			t.Errorf("%s %s: err %v", bad.Kind, bad.Status, err)
		}
		if ok, _ := collectionLinked(w.st, "acme/gadgets"); ok {
			t.Errorf("%s %s: an entry of the refused page is applied", bad.Kind, bad.Status)
		}
		if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" {
			t.Errorf("%s %s: the cursor %q", bad.Kind, bad.Status, c)
		}
		// run logs the refusal and waits, then reads the same cursor again.
		ctx, cancel := context.WithCancel(context.Background())
		var waits []time.Duration
		after := -1
		w.feed.sleep = func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			switch {
			case d == feedFirstBackoff && after < 0:
				// Qory Apiary's next answer is one serve knows.
				w.apiary.mu.Lock()
				w.apiary.changes = w.apiary.changes[:2]
				w.apiary.mu.Unlock()
				after = 0
			case after >= 0:
				// The floor before that read, then the floor after it, which stops.
				if after++; after == 2 {
					cancel()
					return ctx.Err()
				}
			}
			return nil
		}
		w.feed.run(ctx)
		cancel()
		logged := w.log.String()
		want := `"level":"ERROR","msg":"an answer of the change feed holds an entry serve does not know, so none of it is applied","after":"c_1","kind":"` + bad.Kind + `","status":"` + bad.Status + `"`
		if !strings.Contains(logged, want) {
			t.Errorf("%s %s: the log %s", bad.Kind, bad.Status, logged)
		}
		if !slices.Contains(waits, feedFirstBackoff) {
			t.Errorf("%s %s: waited %v", bad.Kind, bad.Status, waits)
		}
		if ok, _ := collectionLinked(w.st, "acme/gadgets"); !ok {
			t.Errorf("%s %s: the page that followed is not applied", bad.Kind, bad.Status)
		}
		if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_2" {
			t.Errorf("%s %s: the cursor %q", bad.Kind, bad.Status, c)
		}
		gets := w.apiary.sent("GET " + routeChanges)
		if len(gets) < 3 || gets[1].target != routeChanges+"?after=c_1" || gets[2].target != routeChanges+"?after=c_1" {
			t.Errorf("%s %s: read %v", bad.Kind, bad.Status, gets)
		}
	}
}

// TestTheFeedWaitsFromItsLastRequest has Qory Apiary answer the feed's first read 429,
// which the read waits out and sends again a second later, and checks the next read
// waits a second from that retry, not from the step's start.
func TestTheFeedWaitsFromItsLastRequest(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	var mu sync.Mutex
	now := time.Now()
	w.client.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	w.client.Sleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
		return nil
	}
	w.apiary.refuseGet = func(n int) (int, string) {
		if n == 1 {
			return 429, `{"error":"rate_limited"}`
		}
		return 0, ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	w.feed.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		cancel()
		return ctx.Err()
	}
	w.feed.run(ctx)
	if len(waits) != 1 || waits[0] != feedFloor {
		t.Errorf("waited %v", waits)
	}
	if gets := w.apiary.sent("GET " + routeChanges); len(gets) != 2 {
		t.Errorf("read %d times", len(gets))
	}
}

// TestTheFeedStopsDuringALongRead has Qory Apiary hold the feed's read, and checks run
// returns soon after its context is done.
func TestTheFeedStopsDuringALongRead(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.hold = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.feed.run(ctx); close(done) }()
	eventually(t, "the read is held", func() bool { return len(w.apiary.sent("GET "+routeChanges)) == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
}

// TestA409OnCommentsUnlinksTheCollection has Qory Apiary answer comments with 409
// collection_not_linked, and checks the collection is no longer linked.
func TestA409OnCommentsUnlinksTheCollection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	linkCollection(w.st, "acme/widgets")
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	req := contracts.SourceItemComments{Version: contracts.Version, ItemRef: "acme/widgets#1", Comments: []contracts.Comment{{
		Ref: "5", URL: "https://github.com/acme/widgets/issues/1#issuecomment-5", Author: contracts.Person{Name: "bob", Kind: github.KindPerson},
		Body: "Same here.", BodyFormat: github.FormatMarkdown, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z",
	}}}
	if err := w.client.Comments(context.Background(), req); !IsPermanent(err) {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); ok {
		t.Error("the collection is still linked")
	}
}

// TestA409ForARequestBeforeALinkKeepsTheLink has the change feed unlink and link the
// collection again while a request for it is answered 409 collection_not_linked, and
// checks the link stored after the request began stands.
func TestA409ForARequestBeforeALinkKeepsTheLink(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	linkCollection(w.st, "acme/widgets")
	w.apiary.refuse = func(string, int) (int, string) {
		unlinkCollection(w.st, "acme/widgets")
		linkCollection(w.st, "acme/widgets")
		return 409, `{"error":"collection_not_linked"}`
	}
	if err := w.client.Items(context.Background(), widgetsItem()); !IsPermanent(err) {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); !ok {
		t.Error("a 409 for a request that began before the link unlinked the collection")
	}
}

// TestAGitHub401DropsTheInstallationsTokens has GitHub answer a fill 401, and checks
// the installation's tokens are dropped, so the next request mints a new one.
func TestAGitHub401DropsTheInstallationsTokens(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, "acme/widgets", 42)
	w.gh.unauthorized = true
	if err := w.adapter.fill(context.Background(), "acme/widgets"); !github.Unauthorized(err) {
		t.Fatalf("err %v", err)
	}
	w.adapter.mu.Lock()
	n := len(w.adapter.tokens)
	w.adapter.mu.Unlock()
	if n != 0 {
		t.Errorf("%d tokens kept", n)
	}
	w.gh.mu.Lock()
	w.gh.unauthorized = false
	w.gh.mu.Unlock()
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	linkCollection(w.st, "acme/widgets")
	if err := w.adapter.fill(context.Background(), "acme/widgets"); err != nil {
		t.Fatal(err)
	}
	if len(w.gh.mints) != 2 {
		t.Errorf("%d tokens minted, want 2", len(w.gh.mints))
	}
}

// TestAnAdapterPrintsNoTokenAndNoKey prints an adapter that keeps a token with every
// verb, and checks neither the token nor the App's key is printed.
func TestAnAdapterPrintsNoTokenAndNoKey(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, "acme/widgets", 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	linkCollection(w.st, "acme/widgets")
	if err := w.adapter.fill(context.Background(), "acme/widgets"); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		out := fmt.Sprintf(verb, w.adapter)
		if strings.Contains(out, ghToken) || strings.Contains(out, appKey().D.String()) || strings.Contains(out, fmt.Sprintf("%x", ghToken)) {
			t.Errorf("%s prints %s", verb, out)
		}
	}
	if got := fmt.Sprintf("%+v", w.adapter); got != `serve.Adapter{AppID: "1", Slug: "qory-test", tokens: 1 kept}` {
		t.Errorf("printed %s", got)
	}
}

// TestTheCursorSurvivesARestart reads the feed, closes the store, opens it again, and
// checks the next read starts after the cursor kept.
func TestTheCursorSurvivesARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	w := newWired(t, dir)
	w.apiary.add(contracts.Change{Kind: contracts.ChangeSync})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.st.Close()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := &feed{apiary: w.client, adapter: w.adapter, store: st, log: slog.New(slog.DiscardHandler)}
	if err := f.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets := w.apiary.sent("GET " + routeChanges); len(gets) != 2 || gets[1].target != routeChanges+"?after=c_1" {
		t.Errorf("read %v", gets)
	}
}

// TestAnAnswerNotSignedUnderThePinIsRefused has Qory Apiary sign its answers under a
// key the pin does not list, and checks no answer is used: a POST fails, not for good,
// and the feed's page is refused and its cursor not kept.
func TestAnAnswerNotSignedUnderThePinIsRefused(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.signer = newKey(t)
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	linkCollection(w.st, "acme/widgets")
	err := w.client.Items(context.Background(), widgetsItem())
	if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "is not signed under a key of apiary_public_key") {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); !ok {
		t.Error("an unsigned refusal unlinked the collection")
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeSync})
	if err := w.feed.step(context.Background()); err == nil {
		t.Error("the feed's page is used")
	}
	if _, err := w.st.Get(nsAdapter, keyCursor); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the cursor is kept: %v", err)
	}
}

// TestTheFeedRefusesAnotherRevision checks a page of another revision, or none, is
// refused and its cursor not kept.
func TestTheFeedRefusesAnotherRevision(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	two := 2
	w.apiary.revision = &two
	w.apiary.add(contracts.Change{Kind: contracts.ChangeSync})
	if err := w.feed.step(context.Background()); err == nil || !strings.Contains(err.Error(), "revision 1") {
		t.Errorf("err %v", err)
	}
	if _, err := w.st.Get(nsAdapter, keyCursor); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the cursor is kept: %v", err)
	}
	for body, want := range map[string]string{
		`{"version":1,"cursor":"c_1","changes":[]}`:                                                   "revision 1",
		`{"version":1,"revision":1,"cursor":"c_1","changes":[],"more":true}`:                          "not the feed's document",
		`{"version":2,"revision":1,"cursor":"c_1","changes":[]}`:                                      "version 1",
		`{"version":1,"revision":1,"cursor":"","changes":[]}`:                                         "cursor",
		`{"version":1,"revision":1,"cursor":"c_1","changes":[{"kind":"sync","interval":null,"x":1}]}`: "not the feed's document",
	} {
		if _, err := checkChanges([]byte(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v", body, err)
		}
	}
	if ch, err := checkChanges([]byte(`{"version":1,"revision":1,"cursor":"c_1","changes":[{"kind":"sync","interval":null}]}`)); err != nil || ch.Revision != 1 || len(ch.Changes) != 1 {
		t.Errorf("%+v %v", ch, err)
	}
}

// TestQoryApiarysRefusals checks what each refusal is: permanent, held, waited out or
// one that may pass.
func TestQoryApiarysRefusals(t *testing.T) {
	for _, tc := range []struct {
		status          int
		body            string
		permanent, held bool
	}{
		{400, `{"error":"invalid_request"}`, true, false},
		{400, `{"error":"unsupported_contract_version"}`, true, false},
		{403, `{"error":"forbidden"}`, true, false},
		{413, `{}`, true, false},
		{409, `{"error":"collection_not_linked"}`, true, false},
		{401, `{"error":"unauthorized"}`, false, true},
		{404, `{"error":"not_found"}`, false, false},
		{422, `{}`, false, false},
		{500, `oops`, false, false},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		linkCollection(w.st, "acme/widgets")
		w.apiary.refuse = func(string, int) (int, string) { return tc.status, tc.body }
		err := w.client.Items(context.Background(), widgetsItem())
		if err == nil || IsPermanent(err) != tc.permanent || IsHeld(err) != tc.held || !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
			t.Errorf("%d %s: err %v", tc.status, tc.body, err)
		}
		if ok, _ := collectionLinked(w.st, "acme/widgets"); ok == (tc.status == 409) {
			t.Errorf("%d %s: linked %v", tc.status, tc.body, ok)
		}
	}
	// A 401 is logged once a minute at most, with a hint.
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(string, int) (int, string) { return 401, `{"error":"unauthorized"}` }
	for range 3 {
		w.client.Disconnect(context.Background(), contracts.SourcesDisconnect{Version: 1, CollectionRef: "acme/widgets", Reason: "ended"})
	}
	if n := strings.Count(w.log.String(), "answered 401"); n != 1 || !strings.Contains(w.log.String(), "is approved, and that this machine's clock is right") {
		t.Errorf("logged %d times: %s", n, w.log.String())
	}
}

// TestA429IsWaitedOutAndBuiltAgain has Qory Apiary refuse a request 429 once, and
// checks the wait is its Retry-After, and the request sent again is built again.
func TestA429IsWaitedOutAndBuiltAgain(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(_ string, n int) (int, string) {
		if n == 1 {
			return 429, `{"error":"rate_limited"}`
		}
		return 0, ""
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	w.client.Now = func() time.Time { now = now.Add(time.Second); return now }
	if err := w.client.Disconnect(context.Background(), contracts.SourcesDisconnect{Version: 1, CollectionRef: "acme/widgets", Reason: "ended"}); err != nil {
		t.Fatal(err)
	}
	sent := w.apiary.sent(routeDisconnect)
	if len(sent) != 2 || sent[0].signature == sent[1].signature || sent[0].body["time"] == sent[1].body["time"] {
		t.Errorf("sent %v", sent)
	}
	if len(w.slept) != 1 || w.slept[0] != time.Second {
		t.Errorf("slept %v", w.slept)
	}
	for v, want := range map[string]time.Duration{"7": 7 * time.Second, "0": time.Second, "": time.Second, "99999": time.Hour, "x": time.Second} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("Retry-After %q: %v, want %v", v, got, want)
		}
	}
}

// TestAPermanentRefusalOfADeliveryIsNotTriedAgain has Qory Apiary refuse an issue's
// item for good, and checks the delivery is done after one request, logged.
func TestAPermanentRefusalOfADeliveryIsNotTriedAgain(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42)
	linkCollection(w.st, "acme/widgets")
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	if n := len(w.apiary.sent(routeItems)); n != 1 || state(w.st, guid1) != store.Done || !strings.Contains(w.log.String(), "collection_not_linked") {
		t.Errorf("%d requests, %s, log %s", n, state(w.st, guid1), w.log.String())
	}
	if ok, _ := collectionLinked(w.st, "acme/widgets"); ok {
		t.Error("the collection is still linked")
	}
}

// signedFixture is a signed request or answer of the contract's fixtures.
type signedFixture struct {
	Status  int               `json:"status"`
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

func readFixture(t *testing.T, name string, out any) {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, "fixtures/adapter/signed/"+name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

// TestTheWireMatchesTheContractsSignedFixtures sends the contract's signed fixtures,
// under its fixture keys, and checks the requests are the fixtures' byte for byte,
// their signatures among them, and the fixture's signed answer verifies.
func TestTheWireMatchesTheContractsSignedFixtures(t *testing.T) {
	var keys struct {
		AccessKey struct {
			Secret      string `json:"secret"`
			AccessKeyID string `json:"access_key_id"`
			InstanceID  string `json:"instance_id"`
		} `json:"access_key"`
		ServerKey struct {
			Seed string `json:"seed"`
		} `json:"server_key"`
	}
	readFixture(t, "keys.json", &keys)
	var post, get, answer signedFixture
	readFixture(t, "post-source-items.json", &post)
	readFixture(t, "get-changes.json", &get)
	readFixture(t, "answer-changes.json", &answer)
	access, err := accesskey.ParseSecret(keys.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.RawURLEncoding.DecodeString(keys.ServerKey.Seed)
	server, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []signedFixture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		mu.Lock()
		got = append(got, signedFixture{Method: r.Method, Target: r.URL.RequestURI(), Body: &body, Headers: map[string]string{
			"X-Qory-Access-Key-Id": r.Header.Get("X-Qory-Access-Key-Id"), "X-Qory-Instance-Id": r.Header.Get("X-Qory-Instance-Id"),
			"X-Qory-Contract-Version": r.Header.Get("X-Qory-Contract-Version"), "X-Qory-Timestamp": r.Header.Get("X-Qory-Timestamp"),
			"X-Qory-Signature-Ed25519": r.Header.Get("X-Qory-Signature-Ed25519"), "Content-Type": r.Header.Get("Content-Type"),
		}})
		mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set(accesskey.HeaderSignature, answer.Headers[accesskey.HeaderSignature])
			w.WriteHeader(answer.Status)
			io.WriteString(w, *answer.Body)
			return
		}
		w.Header().Set(accesskey.HeaderSignature, server.SignAnswer(accesskey.Answer{Status: 200, RequestSignature: r.Header.Get(accesskey.HeaderSignature), Body: []byte("{}")}))
		io.WriteString(w, "{}")
	}))
	defer srv.Close()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	a := &Apiary{URL: srv.URL, KeyID: keys.AccessKey.AccessKeyID, Key: access, InstanceID: keys.AccessKey.InstanceID, Pin: pinOf(server), Now: func() time.Time { return at }}
	var items contracts.SourceItems
	if err := json.Unmarshal([]byte(*post.Body), &items); err != nil {
		t.Fatal(err)
	}
	if err := a.Items(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	page, err := a.Changes(context.Background(), "c_00000040")
	if err != nil {
		t.Fatal(err)
	}
	if page.Cursor != "c_00000046" || len(page.Changes) != 6 {
		t.Errorf("the page %+v", page)
	}
	if len(got) != 2 {
		t.Fatalf("%d requests", len(got))
	}
	for i, want := range []signedFixture{post, get} {
		g := got[i]
		if g.Method != want.Method || g.Target != want.Target {
			t.Errorf("%s %s, want %s %s", g.Method, g.Target, want.Method, want.Target)
		}
		if want.Body != nil && *g.Body != *want.Body {
			t.Errorf("%s: the body\n%s\nwant\n%s", want.Target, *g.Body, *want.Body)
		}
		for k, v := range want.Headers {
			if g.Headers[k] != v {
				t.Errorf("%s: %s %q, want %q", want.Target, k, g.Headers[k], v)
			}
		}
	}
}
