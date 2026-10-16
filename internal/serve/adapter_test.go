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
	"sync/atomic"
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
	access  *accesskey.Key
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
	w := &wired{st: st, access: access, apiary: newFakeApiary(t, access), gh: newFakeGitHub(t), log: &syncBuffer{}}
	logger := slog.New(slog.NewJSONHandler(w.log, nil))
	w.client = w.apiary.client(access)
	w.client.Log = logger
	w.client.Unlinked = func(ref string, began uint64) { unlinkSince(st, ref, began) }
	w.client.Ended = endedIn(st, logger)
	w.client.Answered = answeredIn(st, logger)
	w.client.ConnectionOf = func(ref string) string { c, _ := connectionOf(st, ref); return c }
	w.client.Sleep = func(_ context.Context, d time.Duration) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.slept = append(w.slept, d)
		return nil
	}
	w.adapter = &Adapter{Store: st, GitHub: github.Client{API: w.gh.srv.URL}, AppID: "1", Key: appKey(), Slug: testSlug, Sink: w.client, Log: logger, openRepository: openRepoOf}
	w.client.Ended = w.adapter.forgetEnded(w.client.Ended)
	hs := &Handlers{}
	w.adapter.Register(hs)
	worker := &Worker{Store: st, Handlers: hs, Log: logger, Attempts: 3, Backoff: func(int) time.Duration { return time.Millisecond }}
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: logger, Stored: worker.Notify, Handlers: hs, Linked: func(id int64) (bool, error) { return Linked(st, id) }}
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
		"repository": map[string]any{"id": repoID(repo), "full_name": repo, "html_url": "https://github.com/" + repo},
	}
}

// refsOf are the collection refs of the repositories names, owner/name, see [refOf].
func refsOf(names ...string) []string {
	refs := []string{}
	for _, n := range names {
		refs = append(refs, refOf(n))
	}
	return refs
}

// TestAnIssueIsSentOnlyForALinkedInstallationAndCollection delivers an issue of a
// linked collection, which is one signed POST /v1/source-items with its time, then one
// of a collection that is not linked, and one of an installation that is not linked,
// which send nothing.
func TestAnIssueIsSentOnlyForALinkedInstallationAndCollection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	linkCollection(w.st, widgetsRef)
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	sent := w.apiary.sent(routeItems)
	if len(sent) != 1 {
		t.Fatalf("%d items requests", len(sent))
	}
	var req contracts.SourceItems
	json.Unmarshal(sent[0].raw, &req)
	if req.CollectionRef != refOf("acme/widgets") || len(req.Items) != 1 || req.Items[0].Ref != itemOf("acme/widgets", 1) || req.Listing != nil || !timeShape.MatchString(req.Time) {
		t.Errorf("sent %s", sent[0].raw)
	}
	if tm, _ := time.Parse(time.RFC3339, req.Time); time.Since(tm).Abs() > time.Minute {
		t.Errorf("the time %s", req.Time)
	}
	w.deliver(t, "issues", guid2, issueEvent(42, "acme/gadgets", "opened"))
	// The installation 43 is not linked: its delivery is answered and not kept.
	b, _ := json.Marshal(issueEvent(43, "acme/widgets", "opened"))
	if rec := post(w.mux, "issues", guid3, string(b), sign(string(b))); rec.Code != http.StatusAccepted || state(w.st, guid3) != "" {
		t.Errorf("%d %q", rec.Code, state(w.st, guid3))
	}
	if n := len(w.apiary.sent(routeItems)); n != 1 {
		t.Errorf("%d items requests", n)
	}
	if !strings.Contains(w.log.String(), "the collection is not linked") || !strings.Contains(w.log.String(), `"guid":"`+guid3+`","outcome":"not_linked"`) {
		t.Errorf("the log: %s", w.log.String())
	}
}

// TestACommentIsSentForALinkedCollection delivers a comment on an issue of a linked
// collection.
func TestACommentIsSentForALinkedCollection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	linkCollection(w.st, refOf("acme/widgets"))
	ev := issueEvent(42, "acme/widgets", "created")
	ev["comment"] = map[string]any{"id": 5, "html_url": "https://github.com/acme/widgets/issues/1#issuecomment-5", "body": "Same here.", "user": map[string]any{"login": "bob", "type": "User"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z"}
	w.deliver(t, "issue_comment", guid1, ev)
	sent := w.apiary.sent(routeComments)
	if len(sent) != 1 || sent[0].body["item_ref"] != itemOf("acme/widgets", 1) {
		t.Fatalf("sent %v", sent)
	}
}

// TestRepositoriesAddedListsTheCollections delivers installation_repositories added,
// and checks the listing reaches Qory Apiary, complete, read with a token that reads
// metadata alone, and that each repository's installation is kept.
func TestRepositoriesAddedListsTheCollections(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "added", "installation": map[string]any{"id": 42}, "repositories_added": []any{map[string]any{"id": gadgetsID, "full_name": "acme/gadgets"}}})
	sent := w.apiary.sent(routeCollections)
	if len(sent) != 1 {
		t.Fatalf("%d collections requests", len(sent))
	}
	var req contracts.SourceCollections
	json.Unmarshal(sent[0].raw, &req)
	if len(req.Collections) != 2 || req.Collections[0].Ref != widgetsRef || !req.Listing.Complete || req.Listing.Part != 1 || req.Collections[0].Target == nil {
		t.Errorf("sent %s", sent[0].raw)
	}
	// The collections are named by their repositories' ids; their titles, URLs and
	// targets name the repositories as GitHub does.
	want := []contracts.Collection{
		{Ref: widgetsRef, Title: "acme/widgets", URL: "https://github.com/acme/widgets", Target: &contracts.Target{System: w.adapter.GitHub.WebHost(), Path: "acme/widgets"}},
		{Ref: gadgetsRef, Title: "acme/gadgets", URL: "https://github.com/acme/gadgets", Target: &contracts.Target{System: w.adapter.GitHub.WebHost(), Path: "acme/gadgets"}},
	}
	for i, c := range req.Collections {
		if c.Ref != want[i].Ref || c.Title != want[i].Title || c.URL != want[i].URL || c.Target == nil || *c.Target != *want[i].Target {
			t.Errorf("collection %d: %+v, want %+v", i, c, want[i])
		}
	}
	for _, ref := range []string{widgetsRef, gadgetsRef} {
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
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, refOf("acme/old"), 42)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "removed", "installation": map[string]any{"id": 42}, "repositories_removed": []any{map[string]any{"id": oldID, "full_name": "acme/old"}}})
	sent := w.apiary.sent(routeDisconnect)
	if len(sent) != 1 || sent[0].body["collection_ref"] != refOf("acme/old") || len(sent[0].body) != 3 {
		t.Fatalf("sent %v", sent)
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
		t.Error("the removed repository's installation is kept")
	}
	if len(w.apiary.sent(routeCollections)) != 1 {
		t.Error("the repositories are not listed again")
	}
}

// lastListed are the refs of the collections the last listing sent Qory Apiary, one
// part.
func (w *wired) lastListed(t *testing.T) []string {
	t.Helper()
	sent := w.apiary.sent(routeCollections)
	if len(sent) == 0 {
		t.Fatal("no listing is sent")
	}
	var req contracts.SourceCollections
	json.Unmarshal(sent[len(sent)-1].raw, &req)
	if !req.Listing.Complete || req.Listing.Part != 1 {
		t.Errorf("the listing is not complete in one part: %s", sent[len(sent)-1].raw)
	}
	var refs []string
	for _, c := range req.Collections {
		refs = append(refs, c.Ref)
	}
	return refs
}

// installed sets the repositories the fake GitHub lists for the installation 42.
func (f *fakeGitHub) installed(repos ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos = repos
}

// repositoriesEvent is an installation_repositories event of the installation 42: action
// with the repository selection selection, the repositories added and those removed.
func repositoriesEvent(action, selection string, added, removed []string) map[string]any {
	list := func(names []string) []any {
		out := []any{}
		for _, n := range names {
			out = append(out, map[string]any{"id": repoID(n), "full_name": n, "name": n[strings.Index(n, "/")+1:], "private": false})
		}
		return out
	}
	return map[string]any{
		"action": action, "installation": map[string]any{"id": 42}, "repository_selection": selection,
		"repositories_added": list(added), "repositories_removed": list(removed),
	}
}

// disconnected are the collections of the disconnects Qory Apiary was sent, from the one
// numbered from on, counted from 0; a disconnect that names a reason, which none does,
// shows it.
func (w *wired) disconnected(from int) []string {
	var got []string
	for _, r := range w.apiary.sent(routeDisconnect)[from:] {
		ref := r.body["collection_ref"].(string)
		if reason, ok := r.body["reason"]; ok {
			ref += fmt.Sprintf(" reason %v", reason)
		}
		got = append(got, ref)
	}
	return got
}

// TestASelectionSwitchedToAllRepositoriesIsListed switches an installation that GitHub
// gave a selection of repositories to all of the account's, which GitHub delivers as
// installation_repositories added, repository_selection all, with each repository the
// installation now reaches beside the selection: the installation is listed again, the
// new repositories in it, each kept as reached by the installation, and nothing is
// disconnected.
func TestASelectionSwitchedToAllRepositoriesIsListed(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.gh.installed("acme/widgets")
	w.deliver(t, "installation_repositories", guid1, repositoriesEvent("added", "selected", []string{"acme/widgets"}, nil))
	if got := w.lastListed(t); !slices.Equal(got, refsOf("acme/widgets")) {
		t.Fatalf("listed %v", got)
	}
	w.gh.installed("acme/widgets", "acme/gadgets", "acme/tools", "acme/docs")
	w.deliver(t, "installation_repositories", guid2, repositoriesEvent("added", "all", []string{"acme/gadgets", "acme/tools", "acme/docs"}, nil))
	if got := w.lastListed(t); !slices.Equal(got, refsOf("acme/widgets", "acme/gadgets", "acme/tools", "acme/docs")) {
		t.Errorf("listed %v", got)
	}
	for _, ref := range refsOf("acme/widgets", "acme/gadgets", "acme/tools", "acme/docs") {
		if inst, ok, err := reachOf(w.st, ref); inst != 42 || !ok || err != nil {
			t.Errorf("%s: %d %v %v", ref, inst, ok, err)
		}
	}
	if got := w.disconnected(0); len(got) != 0 {
		t.Errorf("disconnected %v", got)
	}
	if s := state(w.st, guid2); s != store.Done {
		t.Errorf("the delivery is %v", s)
	}
}

// TestAllRepositoriesSwitchedToASelectionDisconnectsTheOthers switches an installation
// on all of the account's repositories to a selection, which GitHub delivers as
// installation_repositories removed, repository_selection selected, with each
// repository left out: each is disconnected, removed, and forgotten, and the
// installation is listed again with the selection alone.
func TestAllRepositoriesSwitchedToASelectionDisconnectsTheOthers(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.gh.installed("acme/widgets", "acme/gadgets", "acme/tools", "acme/docs")
	w.deliver(t, "installation_repositories", guid1, repositoriesEvent("added", "all", []string{"acme/widgets", "acme/gadgets", "acme/tools", "acme/docs"}, nil))
	w.gh.installed("acme/gadgets")
	w.deliver(t, "installation_repositories", guid2, repositoriesEvent("removed", "selected", nil, []string{"acme/widgets", "acme/tools", "acme/docs"}))
	if got := w.disconnected(0); !slices.Equal(got, refsOf("acme/widgets", "acme/tools", "acme/docs")) {
		t.Errorf("disconnected %v", got)
	}
	for _, ref := range refsOf("acme/widgets", "acme/tools", "acme/docs") {
		if _, ok, _ := reachOf(w.st, ref); ok {
			t.Errorf("%s: the removed repository's installation is kept", ref)
		}
	}
	if inst, ok, _ := reachOf(w.st, refOf("acme/gadgets")); inst != 42 || !ok {
		t.Errorf("acme/gadgets: %d %v", inst, ok)
	}
	if got := w.lastListed(t); !slices.Equal(got, refsOf("acme/gadgets")) {
		t.Errorf("listed %v", got)
	}
}

// TestRemovingARepositoryNeverKnownIsHarmless removes from the installation a
// repository serve never listed, and one the store holds as another installation's:
// no disconnect is sent for either, the delivery is done, the repositories serve knows
// stay as they were, and the installation is listed again.
func TestRemovingARepositoryNeverKnownIsHarmless(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, refOf("acme/widgets"), 42)
	setReach(w.st, refOf("acme/gadgets"), 42)
	setReach(w.st, refOf("octo-org/tools"), 43)
	w.deliver(t, "installation_repositories", guid1, repositoriesEvent("removed", "selected", nil, []string{"acme/never", "octo-org/tools"}))
	if s := state(w.st, guid1); s != store.Done {
		t.Errorf("the delivery is %v", s)
	}
	if got := w.disconnected(0); len(got) != 0 {
		t.Errorf("disconnected %v", got)
	}
	for name, want := range map[string]int64{"acme/widgets": 42, "acme/gadgets": 42, "octo-org/tools": 43} {
		if inst, ok, _ := reachOf(w.st, refOf(name)); inst != want || !ok {
			t.Errorf("%s: %d %v", name, inst, ok)
		}
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/never")); ok {
		t.Error("acme/never is kept")
	}
	if got := w.lastListed(t); !slices.Equal(got, refsOf("acme/widgets", "acme/gadgets")) {
		t.Errorf("listed %v", got)
	}
}

// TestAChangeOfRepositoriesListsWithANewToken lists the installation, which keeps its
// listing token, then delivers installation_repositories added and removed in turn:
// each drops the installation's tokens, so each listing after a change reads with a
// token minted after it, and another installation's token is kept.
func TestAChangeOfRepositoriesListsWithANewToken(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	if err := w.adapter.listRepositories(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	w.adapter.mu.Lock()
	w.adapter.tokens["43 "+refOf("octo-org/tools")+" read"] = github.InstallationToken{Token: "another", ExpiresAt: time.Now().Add(time.Hour)}
	w.adapter.mu.Unlock()
	w.deliver(t, "installation_repositories", guid1, repositoriesEvent("added", "all", []string{"acme/gadgets"}, nil))
	w.deliver(t, "installation_repositories", guid2, repositoriesEvent("removed", "selected", nil, []string{"acme/gadgets"}))
	w.gh.mu.Lock()
	mints := slices.Clone(w.gh.mints)
	w.gh.mu.Unlock()
	if len(mints) != 3 {
		t.Errorf("%d listing tokens minted, want 3: %v", len(mints), mints)
	}
	w.adapter.mu.Lock()
	_, kept := w.adapter.tokens["43 "+refOf("octo-org/tools")+" read"]
	w.adapter.mu.Unlock()
	if !kept {
		t.Error("another installation's token is dropped")
	}
	if n := len(w.apiary.sent(routeCollections)); n != 3 {
		t.Errorf("%d listings", n)
	}
}

// TestRepositoriesAddedAndRemovedInTurnEndInTheSetGitHubHas adds and removes
// repositories in turn, a selection grown, switched to all and back to a selection, and
// checks after each that the listing and the repositories kept are the installation's
// and that each repository removed is disconnected once.
func TestRepositoriesAddedAndRemovedInTurnEndInTheSetGitHubHas(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	guids := []string{guid1, guid2, guid3, "a4c5d6e7-1b2c-11ef-8f4b-0242ac120004", "b5d6e7f8-1c2d-11ef-8f4b-0242ac120005"}
	for i, step := range []struct {
		action, selection string
		added, removed    []string
		repos             []string
		disconnected      []string
	}{
		{"added", "selected", []string{"acme/widgets"}, nil, []string{"acme/widgets"}, nil},
		{"added", "selected", []string{"acme/gadgets"}, nil, []string{"acme/widgets", "acme/gadgets"}, nil},
		{"removed", "selected", nil, []string{"acme/widgets"}, []string{"acme/gadgets"}, []string{"acme/widgets"}},
		{"added", "all", []string{"acme/widgets", "acme/tools"}, nil, []string{"acme/widgets", "acme/gadgets", "acme/tools"}, nil},
		{"removed", "selected", nil, []string{"acme/gadgets", "acme/tools"}, []string{"acme/widgets"}, []string{"acme/gadgets", "acme/tools"}},
	} {
		before := len(w.apiary.sent(routeDisconnect))
		w.gh.installed(step.repos...)
		w.deliver(t, "installation_repositories", guids[i], repositoriesEvent(step.action, step.selection, step.added, step.removed))
		if got := w.lastListed(t); !slices.Equal(got, refsOf(step.repos...)) {
			t.Errorf("step %d: listed %v, want %v", i+1, got, step.repos)
		}
		if got := w.disconnected(before); !slices.Equal(got, refsOf(step.disconnected...)) {
			t.Errorf("step %d: disconnected %v, want %v", i+1, got, step.disconnected)
		}
		refs, _ := reachedBy(w.st, 42)
		slices.Sort(refs)
		want := slices.Sorted(slices.Values(refsOf(step.repos...)))
		if !slices.Equal(refs, want) {
			t.Errorf("step %d: kept %v, want %v", i+1, refs, want)
		}
	}
}

// TestEveryTokenServeMintsIsNarrowedToItsStep lists an installation's repositories,
// fills a collection and applies a work item's change, each step serve mints a token
// for, and pins every mint: each names its permissions, since a mint that names none
// is granted every permission the installation has, and none asks for one the App
// holds for steps serve does not take with an installation token, so an App with more
// permissions does not widen serve's tokens. The listing reads metadata alone, on every
// repository; the fill reads issues and the change writes them, on one repository.
func TestEveryTokenServeMintsIsNarrowedToItsStep(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.deliver(t, "installation_repositories", guid1, repositoriesEvent("added", "all", []string{"acme/widgets", "acme/gadgets"}, nil))
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	linkCollection(w.st, refOf("acme/widgets"))
	if err := w.adapter.fill(context.Background(), refOf("acme/widgets")); err != nil {
		t.Fatal(err)
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.gh.mu.Lock()
	mints := slices.Clone(w.gh.mints)
	w.gh.mu.Unlock()
	want := []string{
		`{"permissions":{"metadata":"read"}}`,
		`{"permissions":{"issues":"read"},"repository_ids":[` + widgetsRef + `]}`,
		`{"permissions":{"issues":"write"},"repository_ids":[` + widgetsRef + `]}`,
	}
	if !slices.Equal(mints, want) {
		t.Errorf("mints\n%s\nwant\n%s", strings.Join(mints, "\n"), strings.Join(want, "\n"))
	}
	for _, m := range mints {
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		if err := json.Unmarshal([]byte(m), &body); err != nil || len(body.Permissions) == 0 {
			t.Errorf("a mint names no permission: %s", m)
		}
		for _, wider := range []string{"contents", "pull_requests", "actions", "checks", "administration", "members"} {
			if _, ok := body.Permissions[wider]; ok {
				t.Errorf("a mint asks for %s: %s", wider, m)
			}
		}
	}
}

// holdMint is a transport that holds the first mint of an installation token until
// release is closed, once it has closed minting, and passes every other request on.
type holdMint struct {
	once             *sync.Once
	minting, release chan struct{}
}

func (h holdMint) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens") {
		held := false
		h.once.Do(func() { held = true })
		if held {
			close(h.minting)
			<-h.release
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// TestATokenMintedAcrossAForgetIsNotKept holds a mint of the installation's listing
// token in flight while its tokens are dropped: the token is handed to the request
// that minted it, and not kept, so the next request mints again; a token minted after
// the drop is kept.
func TestATokenMintedAcrossAForgetIsNotKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	h := holdMint{once: &sync.Once{}, minting: make(chan struct{}), release: make(chan struct{})}
	w.adapter.GitHub.HTTP = &http.Client{Transport: h}
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		tok, err := w.adapter.token(context.Background(), 42, 0, "")
		done <- result{tok, err}
	}()
	<-h.minting
	w.adapter.forgetTokens(42)
	close(h.release)
	if r := <-done; r.token != ghToken || r.err != nil {
		t.Fatalf("the token minted in flight: %v", r.err)
	}
	w.adapter.mu.Lock()
	n := len(w.adapter.tokens)
	w.adapter.mu.Unlock()
	if n != 0 {
		t.Errorf("%d tokens kept, the one minted across the drop among them", n)
	}
	if _, err := w.adapter.token(context.Background(), 42, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.adapter.token(context.Background(), 42, 0, ""); err != nil {
		t.Fatal(err)
	}
	w.gh.mu.Lock()
	mints := len(w.gh.mints)
	w.gh.mu.Unlock()
	w.adapter.mu.Lock()
	n = len(w.adapter.tokens)
	w.adapter.mu.Unlock()
	if mints != 2 || n != 1 {
		t.Errorf("%d mints and %d tokens kept, want 2 and 1", mints, n)
	}
}

// heldFor names the adapter's maps that hold an entry for the installation.
func (a *Adapter) heldFor(installation int64) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var held []string
	for key := range a.tokens {
		if strings.HasPrefix(key, strconv.FormatInt(installation, 10)+" ") {
			held = append(held, "tokens")
			break
		}
	}
	for k := range a.firsts {
		if k.installation == installation {
			held = append(held, "firsts")
			break
		}
	}
	if _, ok := a.gens[installation]; ok {
		held = append(held, "gens")
	}
	if _, ok := a.firstGens[installation]; ok {
		held = append(held, "firstGens")
	}
	if _, ok := a.pacers[installation]; ok {
		held = append(held, "pacers")
	}
	if _, ok := a.installs[installation]; ok {
		held = append(held, "installs")
	}
	return held
}

// TestAnInstallationDeletedLeavesNothingOfItInMemory has the adapter keep, for two
// installations, a token, a first listing, a pacer and their generations, and hold the
// other's lock, then GitHub deletes one: the adapter's maps hold nothing of it, and the
// other's entries stay; the other's lock goes once it is given back.
func TestAnInstallationDeletedLeavesNothingOfItInMemory(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	Link(w.st, 9, otherConnection, linkLive)
	for _, id := range []int64{42, 9} {
		w.adapter.pacer(id)
		w.adapter.mu.Lock()
		w.adapter.generation(&w.adapter.gens, id)
		w.adapter.generation(&w.adapter.firstGens, id)
		if w.adapter.tokens == nil {
			w.adapter.tokens = map[string]github.InstallationToken{}
		}
		w.adapter.tokens[strconv.FormatInt(id, 10)+" "+widgetsRef+" read"] = github.InstallationToken{Token: ghToken, ExpiresAt: time.Now().Add(time.Hour)}
		if w.adapter.firsts == nil {
			w.adapter.firsts = map[firstKey]*firstListing{}
		}
		w.adapter.firsts[firstKey{id, testConnection}] = &firstListing{}
		w.adapter.mu.Unlock()
	}
	unlock, err := w.adapter.lockInstallation(context.Background(), 9)
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"tokens", "firsts", "gens", "firstGens", "pacers", "installs"}
	if held := w.adapter.heldFor(9); !slices.Equal(held, all) {
		t.Fatalf("the other installation's entries %v, want %v", held, all)
	}
	w.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	if s := state(w.st, guid1); s != store.Done {
		t.Fatalf("the deletion is %s", s)
	}
	if held := w.adapter.heldFor(42); len(held) != 0 {
		t.Errorf("the deleted installation's entries are kept in %v", held)
	}
	if held := w.adapter.heldFor(9); !slices.Equal(held, all) {
		t.Errorf("the other installation's entries %v, want %v", held, all)
	}
	unlock()
	if held := w.adapter.heldFor(9); slices.Contains(held, "installs") {
		t.Errorf("the other installation's lock is kept once it is given back: %v", held)
	}
}

// TestAnInstallationDeletedWhoseConnectionEndedLeavesNothingOfItInMemory deletes a
// linked installation whose disconnect Qory Apiary answers 409 connection_ended, which
// forgets the connection's first listings, those of the installation still linked
// among them, after the installation's are forgotten: the adapter's maps hold nothing
// of it.
func TestAnInstallationDeletedWhoseConnectionEndedLeavesNothingOfItInMemory(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.adapter.mu.Lock()
	w.adapter.generation(&w.adapter.gens, 42)
	w.adapter.generation(&w.adapter.firstGens, 42)
	w.adapter.mu.Unlock()
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeConnectionsDisconnect {
			return 409, `{"error":"connection_ended"}`
		}
		return 0, ""
	}
	w.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	if s := state(w.st, guid1); s != store.Done {
		t.Fatalf("the deletion is %s", s)
	}
	if n := len(w.apiary.sent(routeConnectionsDisconnect)); n != 1 {
		t.Errorf("%d disconnects sent", n)
	}
	if held := w.adapter.heldFor(42); len(held) != 0 {
		t.Errorf("the deleted installation's entries are kept in %v", held)
	}
}

// TestAReadInFlightAcrossAnInstallationsDeletionIsNotKept holds a mint of the
// installation's listing token, and a read of a pending link's first listing, while
// GitHub deletes the installation, and after the deletion, before the read in flight
// ends: nothing more; a move of the generation, which makes no generation again; or a
// reader that takes a generation, which is a new one, never one given before the
// deletion. The token is handed to the request that minted it, and the listing is
// sent, and neither is kept: the adapter's maps hold nothing of the installation but,
// after a reader, the generation it took.
func TestAReadInFlightAcrossAnInstallationsDeletionIsNotKept(t *testing.T) {
	deleted := map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}}
	for _, after := range []string{"nothing", "a move", "a reader"} {
		t.Run("token, then "+after, func(t *testing.T) {
			w := newWired(t, filepath.Join(t.TempDir(), "state"))
			Link(w.st, 42, testConnection, linkLive)
			h := holdMint{once: &sync.Once{}, minting: make(chan struct{}), release: make(chan struct{})}
			w.adapter.GitHub.HTTP = &http.Client{Transport: h}
			done := make(chan error, 1)
			go func() {
				_, err := w.adapter.token(context.Background(), 42, 0, "")
				done <- err
			}()
			<-h.minting
			w.deliver(t, "installation", guid1, deleted)
			var want []string
			switch after {
			case "a move":
				w.adapter.forgetTokens(42)
			case "a reader":
				w.adapter.mu.Lock()
				w.adapter.generation(&w.adapter.gens, 42)
				w.adapter.mu.Unlock()
				want = []string{"gens"}
			}
			close(h.release)
			if err := <-done; err != nil {
				t.Fatalf("the token minted in flight: %v", err)
			}
			if held := w.adapter.heldFor(42); !slices.Equal(held, want) {
				t.Errorf("the installation's entries %v, want %v", held, want)
			}
		})
		t.Run("first listing, then "+after, func(t *testing.T) {
			w := newWired(t, filepath.Join(t.TempDir(), "state"))
			Link(w.st, 42, testConnection, linkPending)
			var derr error
			var want []string
			w.gh.repoAfter = func(*fakeGitHub, int) {
				// GitHub has answered the page; now GitHub deletes the installation.
				derr = w.adapter.deleted(context.Background(), Delivery{Event: "installation", Action: "deleted", InstallationID: 42})
				switch after {
				case "a move":
					w.adapter.dropFirsts(42, "")
				case "a reader":
					w.adapter.mu.Lock()
					w.adapter.generation(&w.adapter.firstGens, 42)
					w.adapter.mu.Unlock()
					want = []string{"firstGens"}
				}
			}
			// The read runs without the installation's lock, which a try of the listing
			// holds, so the deletion lands while GitHub is read.
			if err := w.adapter.sendFirst(context.Background(), 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()}); err != nil || derr != nil {
				t.Fatalf("the listing: %v; the deletion: %v", err, derr)
			}
			if n := len(w.apiary.sent(routeCollections)); n != 1 {
				t.Errorf("%d parts sent", n)
			}
			if held := w.adapter.heldFor(42); !slices.Equal(held, want) {
				t.Errorf("the installation's entries %v, want %v", held, want)
			}
		})
	}
}

// TestDeliveriesOfAnEventWithoutAHandlerAreNotKept posts many deliveries of push and
// pull_request, and one each of workflow_run and an event GitHub may add, which no
// handler takes: each is answered 202, as a delivery kept is, and logged unhandled,
// and the store keeps none of them, so the next delivery kept is the first.
func TestDeliveriesOfAnEventWithoutAHandlerAreNotKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	body := `{"action":"opened","installation":{"id":42},"repository":{"full_name":"acme/widgets"}}`
	var guids []string
	for i := range 200 {
		event := []string{"push", "pull_request"}[i%2]
		switch i {
		case 198:
			event = "workflow_run"
		case 199:
			event = "some_future_event"
		}
		guid := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
		guids = append(guids, guid)
		if rec := post(w.mux, event, guid, body, sign(body)); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d", event, rec.Code)
		}
	}
	for _, guid := range guids {
		if d, err := w.st.Lookup(guid); err == nil {
			t.Fatalf("%s %s is kept", d.Event, guid)
		}
	}
	if pending, err := w.st.Pending(); err != nil || len(pending) != 0 {
		t.Errorf("pending %d %v", len(pending), err)
	}
	if n := strings.Count(w.log.String(), `"outcome":"unhandled"`); n != 200 {
		t.Errorf("%d deliveries logged unhandled", n)
	}
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	if d, err := w.st.Lookup(guid1); err != nil || d.Seq != 1 {
		t.Errorf("the delivery kept next is %d: %v", d.Seq, err)
	}
}

// TestAnInstallationSuspendedThenDeletedEndsItsConnection suspends the installation,
// which is logged and changes nothing, and deletes it, which ends its connection, one
// POST /v1/connections/disconnect, and drops its link and its collections' records;
// another installation's stay.
func TestAnInstallationSuspendedThenDeletedEndsItsConnection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	Link(w.st, 43, otherConnection, linkLive)
	setReach(w.st, refOf("acme/widgets"), 42)
	setReach(w.st, refOf("acme/gadgets"), 42)
	setReach(w.st, refOf("other/thing"), 43)
	linkCollection(w.st, refOf("acme/widgets"))
	keepPulled(w.st, refOf("acme/widgets"), pullMark{Since: time.Now()})
	linkCollection(w.st, refOf("other/thing"))
	w.deliver(t, "installation", guid1, map[string]any{"action": "suspend", "installation": map[string]any{"id": 42}})
	if n := w.apiary.count(); n != 0 {
		t.Errorf("a suspend sent %d requests", n)
	}
	if l, ok, _ := linkOf(w.st, 42); !ok || l.State != linkLive {
		t.Error("a suspend changed the link")
	}
	if !strings.Contains(w.log.String(), `"msg":"GitHub suspended the installation, so its link stays and it is read again later","installation":42`) {
		t.Errorf("the log: %s", w.log.String())
	}
	w.deliver(t, "installation", guid2, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
	sent := w.apiary.sent(routeConnectionsDisconnect)
	if len(sent) != 1 || sent[0].body["connection_id"] != testConnection || len(sent[0].body) != 3 || len(w.apiary.sent(routeDisconnect)) != 0 {
		t.Errorf("sent %v", sent)
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
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
		t.Error("the deleted installation's collection is still linked")
	}
	if m, _ := pulledOf(w.st, refOf("acme/widgets")); !m.Since.IsZero() {
		t.Error("the deleted installation's collection's pulls are kept")
	}
	if ok, _ := collectionLinked(w.st, refOf("other/thing")); !ok {
		t.Error("another installation's collection is unlinked")
	}
	// Its deliveries are not kept any more.
	b, _ := json.Marshal(map[string]any{"action": "unsuspend", "installation": map[string]any{"id": 42}})
	if rec := post(w.mux, "installation", guid3, string(b), sign(string(b))); rec.Code != http.StatusAccepted || state(w.st, guid3) != "" {
		t.Errorf("%d %q", rec.Code, state(w.st, guid3))
	}
	if len(w.apiary.sent(routeCollections)) != 0 {
		t.Error("an unlinked installation is listed")
	}
}

// TestADisconnectOfAConnectionIsSentAgainOn403 has Qory Apiary answer POST
// /v1/connections/disconnect 403, as it answers one sent while the linked connect
// return is being saved: it is sent again, built anew, after waits that double, until
// a signed 204, a 409 connection_ended, or five tries, after which the 403 is logged
// and the installation's records are dropped all the same.
func TestADisconnectOfAConnectionIsSentAgainOn403(t *testing.T) {
	for name, tc := range map[string]struct {
		refuse func(n int) (int, string)
		tries  int
	}{
		"204 at the third": {func(n int) (int, string) {
			if n < 3 {
				return 403, `{"error":"connection_unknown"}`
			}
			return 0, ""
		}, 3},
		"connection_ended at the second": {func(n int) (int, string) {
			if n < 2 {
				return 403, `{"error":"connection_unknown"}`
			}
			return 409, `{"error":"connection_ended"}`
		}, 2},
		"403 that lasts": {func(int) (int, string) { return 403, `{"error":"connection_unknown"}` }, 5},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		Link(w.st, 42, testConnection, linkPending)
		setReach(w.st, refOf("acme/widgets"), 42)
		// Each try is built anew, with a later time: the waits between them pass.
		now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
		var clock sync.Mutex
		w.client.Now = func() time.Time { clock.Lock(); defer clock.Unlock(); now = now.Add(time.Second); return now }
		w.apiary.refuse = func(route string, n int) (int, string) {
			if route == routeConnectionsDisconnect {
				return tc.refuse(n)
			}
			return 0, ""
		}
		w.deliver(t, "installation", guid1, map[string]any{"action": "deleted", "installation": map[string]any{"id": 42}})
		sent := w.apiary.sent(routeConnectionsDisconnect)
		if len(sent) != tc.tries || state(w.st, guid1) != store.Done {
			t.Errorf("%s: %d tries, %s", name, len(sent), state(w.st, guid1))
		}
		for i := 1; i < len(sent); i++ {
			if sent[i].signature == sent[i-1].signature {
				t.Errorf("%s: a try is sent unchanged", name)
			}
		}
		want := []time.Duration{8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second}[:tc.tries-1]
		w.mu.Lock()
		if !reflect.DeepEqual(w.slept, want) {
			t.Errorf("%s: slept %v", name, w.slept)
		}
		w.mu.Unlock()
		if ok, _ := Linked(w.st, 42); ok {
			t.Errorf("%s: still linked", name)
		}
		if refused := strings.Contains(w.log.String(), `"msg":"the disconnect is refused","connection":"`+testConnection+`"`); refused != (name == "403 that lasts") {
			t.Errorf("%s: the log %s", name, w.log.String())
		}
	}
}

// TestAStoreThatFailsToReadAnEndedConnectionsLinksIsLogged ends a connection while
// the store, closed, fails every read: the failure is logged, ended runs, and the
// connection's first listing kept is forgotten all the same.
func TestAStoreThatFailsToReadAnEndedConnectionsLinksIsLogged(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	log := &syncBuffer{}
	a := &Adapter{Store: st, Log: slog.New(slog.NewJSONHandler(log, nil))}
	a.firsts = map[firstKey]*firstListing{{42, testConnection}: {}}
	st.Close()
	var ended []string
	a.forgetEnded(func(connection string) { ended = append(ended, connection) })(testConnection)
	if !slices.Equal(ended, []string{testConnection}) {
		t.Errorf("ended %v", ended)
	}
	if !strings.Contains(log.String(), `"level":"ERROR","msg":"reading the installations linked to an ended connection","connection":"`+testConnection+`","error":"`) {
		t.Errorf("the log: %s", log.String())
	}
	if a.keptFirst(42, testConnection) {
		t.Error("the connection's first listing is kept")
	}
}

// TestAConnectionEndedDropsItsRecordsAndOneSuspendedChangesNothing has Qory Apiary
// answer a listing, an item and a disconnect 409 connection_ended or
// connection_suspended: ended drops the link of the installation linked to the
// connection and its collections' records, and only that connection's; suspended
// changes nothing. Each is a refusal for good, sent again on the periodic check.
func TestAConnectionEndedDropsItsRecordsAndOneSuspendedChangesNothing(t *testing.T) {
	for _, code := range []string{"connection_ended", "connection_suspended"} {
		for _, send := range []string{"listing", "items", "disconnect"} {
			w := newWired(t, filepath.Join(t.TempDir(), "state"))
			Link(w.st, 42, testConnection, linkLive)
			Link(w.st, 43, otherConnection, linkLive)
			setReach(w.st, refOf("acme/widgets"), 42)
			setReach(w.st, refOf("other/thing"), 43)
			linkCollection(w.st, refOf("acme/widgets"))
			linkCollection(w.st, refOf("other/thing"))
			w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"` + code + `"}` }
			var err error
			switch send {
			case "listing":
				err = w.adapter.listRepositories(context.Background(), 42)
			case "items":
				err = w.client.Items(context.Background(), widgetsItem())
			case "disconnect":
				err = w.client.Disconnect(context.Background(), contracts.SourcesDisconnect{Version: 1, CollectionRef: refOf("acme/widgets")})
			}
			if !IsPermanent(err) || !strings.Contains(err.Error(), "409 "+code) {
				t.Errorf("%s, %s: err %v", code, send, err)
			}
			ended := code == "connection_ended"
			if ok, _ := Linked(w.st, 42); ok == ended {
				t.Errorf("%s, %s: linked %v", code, send, ok)
			}
			if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok == ended {
				t.Errorf("%s, %s: the collection linked %v", code, send, ok)
			}
			if _, ok, _ := reachOf(w.st, refOf("acme/widgets")); ok == ended && send != "listing" {
				t.Errorf("%s, %s: the repository's installation kept %v", code, send, ok)
			}
			if ok, _ := Linked(w.st, 43); !ok {
				t.Errorf("%s, %s: another connection's installation is unlinked", code, send)
			}
			if ok, _ := collectionLinked(w.st, refOf("other/thing")); !ok {
				t.Errorf("%s, %s: another connection's collection is unlinked", code, send)
			}
		}
	}
	// A connection_ended about a connection the installation is no longer linked to
	// drops nothing.
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	if dropped, err := dropConnection(w.st, otherConnection); dropped || err != nil {
		t.Errorf("dropped %v, %v", dropped, err)
	}
	if ok, _ := Linked(w.st, 42); !ok {
		t.Error("unlinked")
	}
}

// TestAListingNamesTheConnectionAndMakesItsLinkLive lists a pending installation's
// repositories: each part names the link's connection, a 403 leaves the link pending
// while its connect return lives, and a signed 204 makes it live.
func TestAListingNamesTheConnectionAndMakesItsLinkLive(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	putLink(w.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	w.apiary.refuse = func(_ string, n int) (int, string) {
		if n <= 2 {
			return 403, `{"error":"connection_unknown"}`
		}
		return 0, ""
	}
	if err := w.adapter.listRepositories(context.Background(), 42); !refusedAs(err, 403, "") {
		t.Errorf("err %v", err)
	}
	if l, _, _ := linkOf(w.st, 42); l.State != linkPending {
		t.Errorf("a 403 made the link %s", l.State)
	}
	if err := w.adapter.listRepositories(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := linkOf(w.st, 42); l.State != linkLive || l.Connection != testConnection {
		t.Errorf("the link %+v", l)
	}
	for _, r := range w.apiary.sent(routeCollections) {
		if r.body["connection_id"] != testConnection {
			t.Errorf("sent %s", r.raw)
		}
	}
	// An installation not linked is not listed.
	if err := w.adapter.listRepositories(context.Background(), 43); err != nil || len(w.apiary.sent(routeCollections)) != 3 {
		t.Errorf("err %v, %d listings", err, len(w.apiary.sent(routeCollections)))
	}
}

// TestDeliveriesOfAnInstallationNotLinkedAreNotKept sends many deliveries of an
// installation that is not linked, of each event, and checks each is answered 202 and
// none is kept, but the installation event's created and deleted, which are. An event
// no handler takes is logged unhandled, before its installation is looked at.
func TestDeliveriesOfAnInstallationNotLinkedAreNotKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	events := []struct {
		event string
		body  map[string]any
	}{
		{"issues", issueEvent(43, "acme/widgets", "opened")},
		{"issue_comment", issueEvent(43, "acme/widgets", "created")},
		{"installation_repositories", map[string]any{"action": "added", "installation": map[string]any{"id": 43}}},
		{"installation", map[string]any{"action": "suspend", "installation": map[string]any{"id": 43}}},
		{"workflow_run", map[string]any{"action": "completed", "installation": map[string]any{"id": 43}}},
		{"ping", map[string]any{"zen": "Keep it logically awesome."}},
	}
	for i := range 300 {
		e := events[i%len(events)]
		b, _ := json.Marshal(e.body)
		if rec := post(w.mux, e.event, fmt.Sprintf("00000000-0000-4000-8000-%012d", i), string(b), sign(string(b))); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: %d", e.event, rec.Code)
		}
	}
	if n := len(pending(t, w.st)); n != 0 {
		t.Errorf("%d deliveries pending", n)
	}
	for i := range 300 {
		if s := state(w.st, fmt.Sprintf("00000000-0000-4000-8000-%012d", i)); s != "" {
			t.Fatalf("delivery %d is kept, %s", i, s)
		}
	}
	notLinked, unhandled := strings.Count(w.log.String(), `"outcome":"not_linked"`), strings.Count(w.log.String(), `"outcome":"unhandled"`)
	if notLinked != 200 || unhandled != 100 || w.apiary.count() != 0 {
		t.Errorf("%d lines not_linked, %d unhandled, %d requests", notLinked, unhandled, w.apiary.count())
	}
	// The installation event's created and deleted are kept, and a linked
	// installation's deliveries.
	w.deliver(t, "installation", guid1, map[string]any{"action": "created", "installation": map[string]any{"id": 43}})
	w.deliver(t, "installation", guid2, map[string]any{"action": "deleted", "installation": map[string]any{"id": 43}})
	w.deliver(t, "issues", guid3, issueEvent(42, "acme/widgets", "opened"))
}

// TestAListingOf250CollectionsIsSentInThreeParts lists 250 repositories, which GitHub
// answers in one page, and checks the three parts: 100, 100 and 50, one listing id and
// start, and complete on the last alone. With part 2 refused, no part says complete.
func TestAListingOf250CollectionsIsSentInThreeParts(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		Link(w.st, 42, testConnection, linkLive)
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
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0), ghIssue(2, 0)}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
		t.Error("the collection is not linked")
	}
	sent := w.apiary.sent(routeItems)
	if len(sent) != 1 {
		t.Fatalf("%d items requests", len(sent))
	}
	var req contracts.SourceItems
	json.Unmarshal(sent[0].raw, &req)
	if req.CollectionRef != refOf("acme/widgets") || len(req.Items) != 2 || req.Listing == nil || !req.Listing.Complete {
		t.Errorf("filled with %s", sent[0].raw)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" {
		t.Errorf("the cursor %q", c)
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "unlinked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
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
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, refOf("acme/widgets"), 42)
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
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
	if !strings.Contains(logged, `"msg":"cut to the contract's limit","ref":"`+widgetsRef+`#1","field":"label","length":101`) || !strings.Contains(logged, `"msg":"cuts dropped","cuts_dropped":`) {
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
	setReach(w.st, refOf("acme/widgets"), 42)
	sixty, day := 60, 86400
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
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
	if !strings.Contains(strings.Join(w.gh.mints, " "), `{"permissions":{"issues":"write"},"repository_ids":[`+widgetsRef+`]}`) {
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
// named and a collection whose ref is not a repository's id, both logged and passed, so the
// cursor moves, and the store holds no link for the bad ref.
func TestAFeedEntryThatFailsForGoodIsPassed(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/unknown", 7), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
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
	if !strings.Contains(logged, "no installation is known") || strings.Count(logged, "the collection's ref is not a repository's id") != 3 || len(w.gh.requests) != 0 {
		t.Errorf("the log %s, GitHub %v", logged, w.gh.requests)
	}
	n := 0
	w.st.Each(nsCollections, func(string, []byte) error { n++; return nil })
	if n != 0 {
		t.Errorf("%d collections stored", n)
	}
}

// TestAnEntryWhoseRefIsNotAnIDIsRefusedBeforeGitHub reads work items and collections
// whose refs are not a repository's id, and #, and an issue's number for a work item:
// letters, empty, a leading zero, a sign, past an int64, without #, with a second #, a
// path, and owner/name. Each fails for good and is passed, the cursor moves, the store
// holds no link, and GitHub is asked nothing, though the installation that reaches
// acme/widgets, whose id some of them write with a leading zero or a sign, is linked: no
// path is built from the ref's text.
func TestAnEntryWhoseRefIsNotAnIDIsRefusedBeforeGitHub(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, widgetsRef, 42)
	items := []string{"widgets#7", "", "#7", widgetsRef + "#", "0" + widgetsRef + "#7", widgetsRef + "#07", "+" + widgetsRef + "#7", "-" + widgetsRef + "#7", widgetsRef + "#-7", "9223372036854775808#7", widgetsRef + "#9223372036854775808", widgetsRef, widgetsRef + "#7#8", "../" + widgetsRef + "#7", widgetsRef + "/../#7", "acme/widgets#7", "0#7", widgetsRef + "#0", " " + widgetsRef + "#7"}
	collections := []string{"widgets", "", "0" + widgetsRef, "+" + widgetsRef, "-" + widgetsRef, "9223372036854775808", widgetsRef + "#7", "acme/widgets", "acme", "0", widgetsRef + " ", "../" + widgetsRef}
	var chs []contracts.Change
	for _, ref := range items {
		chs = append(chs, contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: ref, Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"})
	}
	for _, ref := range collections {
		chs = append(chs, contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: ref, Status: "linked"})
	}
	w.apiary.add(chs...)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_"+strconv.Itoa(len(chs)) {
		t.Errorf("the cursor %q", c)
	}
	logged := w.log.String()
	if n := strings.Count(logged, "the change's ref is not a repository's id, #, and an issue's number"); n != len(items) {
		t.Errorf("%d work items refused, want %d: %s", n, len(items), logged)
	}
	if n := strings.Count(logged, "the collection's ref is not a repository's id"); n != len(collections) {
		t.Errorf("%d collections refused, want %d: %s", n, len(collections), logged)
	}
	w.gh.mu.Lock()
	asked := slices.Clone(w.gh.requests)
	w.gh.mu.Unlock()
	if len(asked) != 0 {
		t.Errorf("GitHub was asked %v", asked)
	}
	n := 0
	w.st.Each(nsCollections, func(string, []byte) error { n++; return nil })
	if n != 0 {
		t.Errorf("%d collections stored", n)
	}
}

// TestATakeInAndAnUndoReachGitHubByTheRepositoryID applies a work item taken in and then
// undone whose ref is acme/widgets's id and the issue's number: each request reaches the
// repository through its id, /repositories/{id}, none by owner/name, and the token that
// writes the issue is minted for the repository's id alone.
func TestATakeInAndAnUndoReachGitHubByTheRepositoryID(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, widgetsRef, 42)
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: widgetsRef + "#7", Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: widgetsRef + "#7", Status: "undone", URL: "https://apiary.example.com/work-items/wi_42"},
	)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.log.String(), "a change of the feed failed") {
		t.Errorf("the log %s", w.log.String())
	}
	w.gh.mu.Lock()
	asked := slices.Clone(w.gh.requests)
	mints := slices.Clone(w.gh.mints)
	w.gh.mu.Unlock()
	const repo = "/repositories/" + widgetsRef
	var reached []string
	for _, r := range asked {
		if !strings.Contains(r, " /app/") {
			reached = append(reached, r)
		}
	}
	want := []string{
		"POST " + repo + "/labels",
		"POST " + repo + "/issues/7/labels",
		"GET " + repo + "/issues/7/comments?per_page=100",
		"POST " + repo + "/issues/7/comments",
		"DELETE " + repo + "/issues/7/labels/qory",
	}
	if !slices.Equal(reached, want) {
		t.Errorf("GitHub was asked\n%s\nwant\n%s", strings.Join(reached, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(mints, []string{`{"permissions":{"issues":"write"},"repository_ids":[` + widgetsRef + `]}`}) {
		t.Errorf("mints %v", mints)
	}
	if posted := w.gh.postedComments(); len(posted) != 1 || !strings.HasPrefix(posted[0], "<!-- qory:work-item wi_42 -->") {
		t.Errorf("posted %q", posted)
	}
}

// TestAFillWhoseRepositoryHasNoNameFailsForGood fills a linked collection, directly and
// from the feed, with no way to name its repository for GraphQL's listing, as serve
// has it: each fails for good, errOpenByID, the feed's entry is passed, and GitHub is
// asked nothing.
func TestAFillWhoseRepositoryHasNoNameFailsForGood(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.adapter.openRepository = nil
	setReach(w.st, widgetsRef, 42)
	linkCollection(w.st, widgetsRef)
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	err := w.adapter.fill(context.Background(), widgetsRef)
	if !IsPermanent(err) || !errors.Is(err, errOpenByID) {
		t.Errorf("err %v", err)
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: gadgetsRef, Status: "linked"})
	setReach(w.st, gadgetsRef, 42)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" || !strings.Contains(w.log.String(), errOpenByID.Error()) {
		t.Errorf("the cursor %q; the log %s", c, w.log.String())
	}
	w.gh.mu.Lock()
	asked := slices.Clone(w.gh.requests)
	w.gh.mu.Unlock()
	if len(asked) != 0 || len(w.apiary.sent(routeItems)) != 0 {
		t.Errorf("GitHub was asked %v; %d items requests", asked, len(w.apiary.sent(routeItems)))
	}
	if m, _ := pulledOf(w.st, widgetsRef); !m.Since.IsZero() {
		t.Errorf("kept %+v", m)
	}
}

// TestARepositoryRemovedIsFoundByItsID delivers installation_repositories removed whose
// repository GitHub names by an id the store holds, under a name no listing gave, and
// one it names by owner/name alone: the first is disconnected by its id and forgotten,
// and the second, whose id the event leaves out, is not, though the store holds its
// repository.
func TestARepositoryRemovedIsFoundByItsID(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	setReach(w.st, refOf("acme/old"), 42)
	setReach(w.st, gadgetsRef, 42)
	w.deliver(t, "installation_repositories", guid1, map[string]any{"action": "removed", "installation": map[string]any{"id": 42}, "repositories_removed": []any{
		map[string]any{"id": oldID, "full_name": "acme/elsewhere"},
		map[string]any{"full_name": "acme/gadgets"},
	}})
	if got := w.disconnected(0); !slices.Equal(got, refsOf("acme/old")) {
		t.Errorf("disconnected %v", got)
	}
	if _, ok, _ := reachOf(w.st, refOf("acme/old")); ok {
		t.Error("the removed repository's installation is kept")
	}
	if inst, ok, _ := reachOf(w.st, gadgetsRef); !ok || inst != 42 {
		t.Errorf("acme/gadgets: %d %v", inst, ok)
	}
}

// TestAnEntryForAnIssueOrARepositoryGoneIsPassed reads a work item whose issue GitHub
// answers 404, one in a repository GitHub answers 301, a linked collection whose
// repository GitHub answers 404 or 301, and a work item and a linked collection of a
// repository the installation no longer reaches, whose token's mint GitHub answers 422,
// each before an entry serve can apply, and checks each is passed, the entry after it
// applied and the cursor moved.
func TestAnEntryForAnIssueOrARepositoryGoneIsPassed(t *testing.T) {
	for name, gone := range map[string]contracts.Change{
		"a work item whose issue is gone":       {Kind: contracts.ChangeWorkItem, WorkItemID: "wi_8", Ref: itemOf("acme/widgets", 8), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_8"},
		"a work item whose repository moved":    {Kind: contracts.ChangeWorkItem, WorkItemID: "wi_9", Ref: itemOf("acme/moved", 9), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_9"},
		"a collection whose repository is gone": {Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/gone"), Status: "linked"},
		"a collection whose repository moved":   {Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/moved"), Status: "linked"},
		"a collection out of reach":             {Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/old"), Status: "linked"},
		"a work item out of reach":              {Kind: contracts.ChangeWorkItem, WorkItemID: "wi_10", Ref: itemOf("acme/old", 9), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_10"},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		for _, repo := range []string{"acme/widgets", "acme/moved", "acme/old", "acme/gone"} {
			setReach(w.st, refOf(repo), 42)
		}
		w.apiary.add(gone, contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"})
		if err := w.feed.step(context.Background()); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_2" {
			t.Errorf("%s: the cursor %q", name, c)
		}
		if posted := w.gh.postedComments(); len(posted) != 1 || !strings.HasPrefix(posted[0], "<!-- qory:work-item wi_42 -->") {
			t.Errorf("%s: posted %q", name, posted)
		}
		if !strings.Contains(w.log.String(), "a change of the feed failed, and is passed") {
			t.Errorf("%s: the log %s", name, w.log.String())
		}
	}
}

// TestAFillLosesOnlyTheCommentsOfAnIssueGone links a collection of 150 open issues, the
// first of which GitHub answers 404 for its comments, and checks every issue is sent,
// the others' comments too, and the entry passes.
func TestAFillLosesOnlyTheCommentsOfAnIssueGone(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.goneComments = 1
	for i := 1; i <= 150; i++ {
		w.gh.issues = append(w.gh.issues, ghIssue(i, 1))
		w.gh.comments[i] = []map[string]any{{
			"id": 1000 + i, "html_url": "https://github.com/acme/widgets/issues/" + strconv.Itoa(i) + "#issuecomment-1", "body": "c",
			"user": map[string]any{"login": "bob", "type": "User"}, "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z",
		}}
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	items := 0
	for _, r := range w.apiary.sent(routeItems) {
		items += len(r.body["items"].([]any))
	}
	if comments := len(w.apiary.sent(routeComments)); items != 150 || comments != 149 {
		t.Errorf("%d items, %d comments requests", items, comments)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" {
		t.Errorf("the cursor %q", c)
	}
	if !strings.Contains(w.log.String(), "skipped the comments on "+widgetsRef+"#1: GitHub answers that the issue is gone or moved") {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAnEntryIsPassedOnceItHasFailedForADay links a collection whose issues GitHub
// answers 502, on a clock that moves on between the reads, and checks the entry keeps
// the cursor until it has failed for a day, and is then logged and passed, the entry
// after it applied.
func TestAnEntryIsPassedOnceItHasFailedForADay(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.issuesDown = true
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"}, contracts.Change{Kind: contracts.ChangeSync})
	for _, d := range []time.Duration{0, time.Hour, 22*time.Hour + 59*time.Minute} {
		now = now.Add(d)
		err := w.feed.step(context.Background())
		if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "GitHub answered 502") {
			t.Fatalf("after %v: err %v", d, err)
		}
		if _, err := w.st.Get(nsAdapter, keyCursor); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("after %v: the cursor is kept", d)
		}
	}
	now = now.Add(time.Minute)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_2" {
		t.Errorf("the cursor %q", c)
	}
	if v, _ := w.st.Get(nsAdapter, keySyncInterval); string(v) != "3600" {
		t.Errorf("the entry after it is not applied: %q", v)
	}
	if !strings.Contains(w.log.String(), `"level":"ERROR","msg":"a change of the feed has failed for a day, and is passed","kind":"collection"`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestTwoEntriesThatFailOnOnePageArePassedEachAfterADay serves a page of two entries
// GitHub answers 502 for, a linked collection and a take in, and a sync entry, on a
// clock that moves a day between reads, and checks each failing entry is passed a day
// after its own first failure, the first not tried again, and the cursor moves once
// the sync is applied.
func TestTwoEntriesThatFailOnOnePageArePassedEachAfterADay(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.reposDown = true
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(
		contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"},
		contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "taken_in", URL: "https://apiary.example.com/work-items/wi_42"},
		contracts.Change{Kind: contracts.ChangeSync},
	)
	read := func(what string, passed bool) {
		t.Helper()
		err := w.feed.step(context.Background())
		cursor, _ := w.st.Get(nsAdapter, keyCursor)
		if passed && (err != nil || string(cursor) != "c_3") || !passed && (err == nil || !strings.Contains(err.Error(), "502") || len(cursor) != 0) {
			t.Fatalf("%s: err %v, cursor %q", what, err, cursor)
		}
	}
	read("the collection fails", false)
	now = now.Add(23 * time.Hour)
	read("the collection fails 23 hours later", false)
	now = now.Add(time.Hour)
	read("the collection is passed, and the take in fails", false)
	now = now.Add(23 * time.Hour)
	read("the take in fails 23 hours later", false)
	now = now.Add(time.Hour)
	read("the take in is passed, and the sync applied", true)
	if v, _ := w.st.Get(nsAdapter, keySyncInterval); string(v) != "3600" {
		t.Errorf("the sync is not applied: %q", v)
	}
	logged := w.log.String()
	if strings.Count(logged, "a change of the feed has failed for a day, and is passed") != 2 || !strings.Contains(logged, `"kind":"collection"`) || !strings.Contains(logged, `"kind":"work_item"`) {
		t.Errorf("the log %s", logged)
	}
}

// TestAnOutageOfTheFeedDoesNotCountTowardADay has an entry fail, then the feed's reads
// fail for a day, then the entry fail again, and checks it is not passed then, only once
// its failures, the outage left out, add up to a day.
func TestAnOutageOfTheFeedDoesNotCountTowardADay(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.issuesDown = true
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
	if err := w.feed.step(context.Background()); err == nil || IsOutage(err) {
		t.Fatalf("err %v", err)
	}
	down := true
	w.apiary.mu.Lock()
	w.apiary.refuseGet = func(int) (int, string) {
		if down {
			return 503, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	w.apiary.mu.Unlock()
	for range 25 {
		now = now.Add(time.Hour)
		if err := w.feed.step(context.Background()); !IsOutage(err) {
			t.Fatalf("err %v", err)
		}
	}
	w.apiary.mu.Lock()
	down = false
	w.apiary.mu.Unlock()
	if err := w.feed.step(context.Background()); err == nil || IsOutage(err) {
		t.Fatalf("the entry is passed after the feed's outage: err %v", err)
	}
	if _, err := w.st.Get(nsAdapter, keyCursor); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the cursor is kept")
	}
	// The entry failed an hour before the outage: a day of its failures is 23 hours
	// after the outage.
	now = now.Add(22 * time.Hour)
	if err := w.feed.step(context.Background()); err == nil {
		t.Fatal("the entry is passed before a day of its failures")
	}
	now = now.Add(time.Hour)
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.st.Get(nsAdapter, keyCursor); string(c) != "c_1" {
		t.Errorf("the cursor %q", c)
	}
}

// TestAFeedEntryThatMayPassKeepsTheCursor links a collection whose fill Qory Apiary
// answers 500, and checks the step fails and the cursor stays, so the entry is read
// again.
func TestAFeedEntryThatMayPassKeepsTheCursor(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeItems {
			return 500, `{"error":"internal"}`
		}
		return 0, ""
	}
	w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "linked"})
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
		{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "shelved", URL: "https://apiary.example.com/work-items/wi_42"},
		{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/widgets"), Status: "archived"},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.apiary.add(contracts.Change{Kind: contracts.ChangeSync})
		if err := w.feed.step(context.Background()); err != nil {
			t.Fatal(err)
		}
		w.apiary.add(contracts.Change{Kind: contracts.ChangeCollection, CollectionRef: refOf("acme/gadgets"), Status: "linked"}, bad)
		var u *unknownChange
		if err := w.feed.step(context.Background()); !errors.As(err, &u) || u.after != "c_1" || u.kind != bad.Kind || u.status != bad.Status {
			t.Errorf("%s %s: err %v", bad.Kind, bad.Status, err)
		}
		if ok, _ := collectionLinked(w.st, refOf("acme/gadgets")); ok {
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
		if ok, _ := collectionLinked(w.st, refOf("acme/gadgets")); !ok {
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

// TestAnUnknownEntrysKindAndStatusAreCut serves an entry whose kind and status are long,
// and checks the refusal keeps 64 characters of each.
func TestAnUnknownEntrysKindAndStatusAreCut(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(contracts.Change{Kind: strings.Repeat("ü", 100), Status: strings.Repeat("s", 100)})
	var u *unknownChange
	if err := w.feed.step(context.Background()); !errors.As(err, &u) || u.kind != strings.Repeat("ü", 64) || u.status != strings.Repeat("s", 64) {
		t.Errorf("err %v", err)
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
	linkCollection(w.st, refOf("acme/widgets"))
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	req := contracts.SourceItemComments{Version: contracts.Version, ItemRef: itemOf("acme/widgets", 1), Comments: []contracts.Comment{{
		Ref: "5", URL: "https://github.com/acme/widgets/issues/1#issuecomment-5", Author: contracts.Person{Name: "bob", Kind: github.KindPerson},
		Body: "Same here.", BodyFormat: github.FormatMarkdown, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z",
	}}}
	if err := w.client.Comments(context.Background(), req); !IsPermanent(err) {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
		t.Error("the collection is still linked")
	}
}

// TestA409ForARequestBeforeALinkKeepsTheLink has the change feed unlink and link the
// collection again while a request for it is answered 409 collection_not_linked, and
// checks the link stored after the request began stands.
func TestA409ForARequestBeforeALinkKeepsTheLink(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	linkCollection(w.st, refOf("acme/widgets"))
	w.apiary.refuse = func(string, int) (int, string) {
		unlinkCollection(w.st, refOf("acme/widgets"))
		linkCollection(w.st, refOf("acme/widgets"))
		return 409, `{"error":"collection_not_linked"}`
	}
	if err := w.client.Items(context.Background(), widgetsItem()); !IsPermanent(err) {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
		t.Error("a 409 for a request that began before the link unlinked the collection")
	}
}

// TestAGitHub401DropsTheInstallationsTokens has GitHub answer a fill 401, and checks
// the installation's tokens are dropped, so the next request mints a new one.
func TestAGitHub401DropsTheInstallationsTokens(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.unauthorized = true
	if err := w.adapter.fill(context.Background(), refOf("acme/widgets")); !github.Unauthorized(err) {
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
	linkCollection(w.st, refOf("acme/widgets"))
	if err := w.adapter.fill(context.Background(), refOf("acme/widgets")); err != nil {
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
	setReach(w.st, refOf("acme/widgets"), 42)
	w.gh.issues = []map[string]any{ghIssue(1, 0)}
	linkCollection(w.st, refOf("acme/widgets"))
	if err := w.adapter.fill(context.Background(), refOf("acme/widgets")); err != nil {
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
	linkCollection(w.st, refOf("acme/widgets"))
	err := w.client.Items(context.Background(), widgetsItem())
	if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "is not signed under a key of apiary_public_key") {
		t.Errorf("err %v", err)
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); !ok {
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

// TestASuccessNotSignedUnderThePinIsAnOutage has Qory Apiary answer a POST with its
// success, a 204 and no body, signed under a key the pin does not list, and checks the
// answer is not taken as a success: the POST fails as an [Outage], not for good.
func TestASuccessNotSignedUnderThePinIsAnOutage(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.signer = newKey(t)
	linkCollection(w.st, refOf("acme/widgets"))
	err := w.client.Items(context.Background(), widgetsItem())
	if err == nil || !IsOutage(err) || IsPermanent(err) || !strings.Contains(err.Error(), "204, is not signed under a key of apiary_public_key") {
		t.Errorf("err %v", err)
	}
	if got := w.apiary.sent("/v1/source-items"); len(got) != 1 {
		t.Errorf("sent %d", len(got))
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
		{403, `{"error":"connection_unknown"}`, true, false},
		{413, `{}`, true, false},
		{409, `{"error":"collection_not_linked"}`, true, false},
		{401, `{"error":"unauthorized"}`, false, true},
		{404, `{"error":"not_found"}`, false, false},
		{422, `{}`, false, false},
		{500, `oops`, false, false},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		linkCollection(w.st, refOf("acme/widgets"))
		w.apiary.refuse = func(string, int) (int, string) { return tc.status, tc.body }
		err := w.client.Items(context.Background(), widgetsItem())
		if err == nil || IsPermanent(err) != tc.permanent || IsHeld(err) != tc.held || !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
			t.Errorf("%d %s: err %v", tc.status, tc.body, err)
		}
		if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok == (tc.status == 409) {
			t.Errorf("%d %s: linked %v", tc.status, tc.body, ok)
		}
	}
	// A 401 is logged once a minute at most, with a hint.
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(string, int) (int, string) { return 401, `{"error":"unauthorized"}` }
	for range 3 {
		w.client.Disconnect(context.Background(), contracts.SourcesDisconnect{Version: 1, CollectionRef: refOf("acme/widgets")})
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
	if err := w.client.Disconnect(context.Background(), contracts.SourcesDisconnect{Version: 1, CollectionRef: refOf("acme/widgets")}); err != nil {
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
	Link(w.st, 42, testConnection, linkLive)
	linkCollection(w.st, refOf("acme/widgets"))
	w.apiary.refuse = func(string, int) (int, string) { return 409, `{"error":"collection_not_linked"}` }
	w.deliver(t, "issues", guid1, issueEvent(42, "acme/widgets", "opened"))
	if n := len(w.apiary.sent(routeItems)); n != 1 || state(w.st, guid1) != store.Done || !strings.Contains(w.log.String(), "collection_not_linked") {
		t.Errorf("%d requests, %s, log %s", n, state(w.st, guid1), w.log.String())
	}
	if ok, _ := collectionLinked(w.st, refOf("acme/widgets")); ok {
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

// TestA403ConnectionUnknownForADayEndsALiveConnection notes Qory Apiary's answers about
// a connection: one 403 connection_unknown ends nothing, and its time survives in the
// store; 403s that run for a day end it; a 2xx between them starts the day again; a 403
// with another code never counts; and a pending connection is never ended by them.
func TestA403ConnectionUnknownForADayEndsALiveConnection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st := openStore(t, dir)
	Link(st, 42, testConnection, linkLive)
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	note := func(status int, code string, d time.Duration) bool {
		t.Helper()
		end, err := noteAnswer(st, testConnection, status, code, at.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		return end
	}
	if note(403, codeConnectionUnknown, 0) || note(403, codeConnectionUnknown, forbiddenFor-time.Second) {
		t.Error("a 403 within a day ends the connection")
	}
	if b, err := st.Get(nsForbidden, testConnection); err != nil || string(b) != strconv.FormatInt(at.Unix(), 10) {
		t.Errorf("the first 403 is kept as %q, %v", b, err)
	}
	if !note(403, codeConnectionUnknown, forbiddenFor) {
		t.Error("403s for a day do not end the connection")
	}
	// A 2xx starts the day again.
	if note(204, "", forbiddenFor) || note(403, codeConnectionUnknown, forbiddenFor+time.Hour) || note(403, codeConnectionUnknown, 2*forbiddenFor) {
		t.Error("a 2xx did not start the day again")
	}
	if !note(403, codeConnectionUnknown, 2*forbiddenFor+time.Hour) {
		t.Error("403s for a day after the 2xx do not end the connection")
	}
	// A 409 connection_suspended starts the day again too: Qory Apiary holds the
	// connection.
	st4 := openStore(t, filepath.Join(t.TempDir(), "state"))
	Link(st4, 42, testConnection, linkLive)
	for i, a := range []struct {
		status int
		code   string
		d      time.Duration
		end    bool
	}{{403, codeConnectionUnknown, 0, false}, {409, codeConnectionSuspended, forbiddenFor - time.Hour, false}, {403, codeConnectionUnknown, forbiddenFor + time.Hour, false}, {403, codeConnectionUnknown, 2*forbiddenFor + time.Hour, true}} {
		if end, err := noteAnswer(st4, testConnection, a.status, a.code, at.Add(a.d)); end != a.end || err != nil {
			t.Errorf("after a 409 connection_suspended, answer %d: %v, %v", i, end, err)
		}
	}
	// A 403 forbidden, or a 409 with another code, collection_not_linked, which an items
	// request may get, neither counts nor starts the day again.
	st5 := openStore(t, filepath.Join(t.TempDir(), "state"))
	Link(st5, 42, testConnection, linkLive)
	for i, a := range []struct {
		status int
		code   string
		d      time.Duration
		end    bool
	}{{403, codeConnectionUnknown, 0, false}, {403, codeForbidden, time.Hour, false}, {409, codeCollectionNotLinked, 2 * time.Hour, false}, {403, codeConnectionUnknown, forbiddenFor, true}} {
		if end, err := noteAnswer(st5, testConnection, a.status, a.code, at.Add(a.d)); end != a.end || err != nil {
			t.Errorf("after a 403 forbidden and a 409 collection_not_linked, answer %d: %v, %v", i, end, err)
		}
	}
	// Another code never counts.
	st2 := openStore(t, filepath.Join(t.TempDir(), "state"))
	Link(st2, 42, testConnection, linkLive)
	for _, d := range []time.Duration{0, 2 * forbiddenFor} {
		if end, err := noteAnswer(st2, testConnection, 403, "forbidden", at.Add(d)); end || err != nil {
			t.Errorf("a 403 forbidden counts: %v, %v", end, err)
		}
	}
	if ok, _ := present(st2.Get(nsForbidden, testConnection)); ok {
		t.Error("a 403 forbidden is kept")
	}
	// A pending connection is never ended.
	st3 := openStore(t, filepath.Join(t.TempDir(), "state"))
	Link(st3, 42, testConnection, linkPending)
	for _, d := range []time.Duration{0, 2 * forbiddenFor} {
		if end, err := noteAnswer(st3, testConnection, 403, codeConnectionUnknown, at.Add(d)); end || err != nil {
			t.Errorf("a pending connection ends: %v, %v", end, err)
		}
	}
	// The first 403's time survives a restart.
	st.Close()
	st = openStore(t, dir)
	if end, err := noteAnswer(st, testConnection, 403, codeConnectionUnknown, at.Add(3*forbiddenFor+2*time.Hour)); !end || err != nil {
		t.Errorf("after a restart: %v, %v", end, err)
	}
}

// TestAConnectionRefusedForADayIsDropped has the connection's first 403 kept 25 hours
// ago: the next 403 connection_unknown to a listing drops the installation's link and
// logs it.
func TestAConnectionRefusedForADayIsDropped(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.st.Put(nsForbidden, testConnection, []byte(strconv.FormatInt(time.Now().Add(-25*time.Hour).Unix(), 10)), 0)
	w.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	if err := w.adapter.listRepositories(context.Background(), 42); !refusedAs(err, 403, codeConnectionUnknown) {
		t.Errorf("err %v", err)
	}
	if ok, _ := Linked(w.st, 42); ok {
		t.Error("still linked")
	}
	if ok, _ := present(w.st.Get(nsForbidden, testConnection)); ok {
		t.Error("the first 403 is kept")
	}
	if !strings.Contains(w.log.String(), `"msg":"Qory Apiary answered connection_unknown for a day, so the connection is dropped","connection":"`+testConnection+`"`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAPendingLinksLastListingDecidesIt lists a pending link past its connect return's
// expiry and returnSkew more: a signed 204 makes it live; a 403 connection_unknown drops
// it and logs it; a 409 connection_ended drops it; a 409 connection_suspended, which
// says the connection was made, a 500, an answer not signed under the pin, or a 403
// forbidden keeps it. Before that moment, a 403
// connection_unknown keeps it.
func TestAPendingLinksLastListingDecidesIt(t *testing.T) {
	past := time.Now().Add(-returnSkew - time.Minute).Unix()
	for name, tc := range map[string]struct {
		status   int
		body     string
		unsigned bool
		ret      int64
		want     string
	}{
		"204":                      {0, "", false, past, linkLive},
		"403 connection_unknown":   {403, `{"error":"connection_unknown"}`, false, past, ""},
		"409 connection_ended":     {409, `{"error":"connection_ended"}`, false, past, ""},
		"500":                      {500, `{"error":"internal"}`, false, past, linkPending},
		"409 connection_suspended": {409, `{"error":"connection_suspended"}`, false, past, linkPending},
		"not signed":               {0, "", true, past, linkPending},
		"403 forbidden":            {403, `{"error":"forbidden"}`, false, past, linkPending},
		"before the moment":        {403, `{"error":"connection_unknown"}`, false, time.Now().Add(returnFor).Unix(), linkPending},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		putLink(w.st, 42, link{Connection: testConnection, State: linkPending, Return: tc.ret})
		if tc.status != 0 {
			w.apiary.refuse = func(string, int) (int, string) { return tc.status, tc.body }
		}
		if tc.unsigned {
			w.apiary.signer = newKey(t)
		}
		err := w.adapter.listFor(context.Background(), 42, testConnection)
		l, ok, _ := linkOf(w.st, 42)
		if got := map[bool]string{true: l.State}[ok]; got != tc.want {
			t.Errorf("%s: the link %q, err %v", name, got, err)
		}
		dropped := strings.Contains(w.log.String(), `"msg":"the connection was not made in time, so its pending link is dropped","connection":"`+testConnection+`","installation":42`)
		if dropped != (name == "403 connection_unknown") {
			t.Errorf("%s: the log %s", name, w.log.String())
		}
		if (err == nil) != (name == "204" || name == "403 connection_unknown") && name != "409 connection_ended" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

// TestAReplacedConnectionAnsweredSuspendedIsEnded lists a connection a connect replaced
// on the installation 42 while Qory Apiary answers its listing 409
// connection_suspended, which it answers only for a connection made: the connection is
// ended, POST /v1/connections/disconnect, and forgotten, and 42 stays linked to the
// connection that replaced it.
func TestAReplacedConnectionAnsweredSuspendedIsEnded(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	putLink(w.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	keepReplaced(w.st, 42, link{Connection: otherConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	w.apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeCollections {
			return 409, `{"error":"connection_suspended"}`
		}
		return 0, ""
	}
	if err := w.adapter.listFor(context.Background(), 42, otherConnection); err != nil {
		t.Errorf("err %v", err)
	}
	if sent := w.apiary.sent(routeConnectionsDisconnect); len(sent) != 1 || sent[0].body["connection_id"] != otherConnection {
		t.Errorf("disconnects %v", sent)
	}
	if _, ok, _ := replacedOf(w.st, otherConnection); ok {
		t.Error("the replaced connection is kept")
	}
	if l, _, _ := linkOf(w.st, 42); l.Connection != testConnection || l.State != linkPending {
		t.Errorf("the link %+v", l)
	}
	if !strings.Contains(w.log.String(), `"msg":"the replaced connection was made meanwhile, so it is disconnected","connection":"`+otherConnection+`"`) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestTheContractsRefusalFixturesAreRead has Qory Apiary answer an items request with
// each of the contract's refusal fixtures that serve reads, signed, and checks serve
// reads its status and code. A fixture the contract's revision does not hold is
// skipped: connection-unknown.json came after 6f182ad.
func TestTheContractsRefusalFixturesAreRead(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		code   string
	}{
		"connection-unknown.json":    {403, codeConnectionUnknown},
		"connection-ended.json":      {409, codeConnectionEnded},
		"connection-suspended.json":  {409, codeConnectionSuspended},
		"collection-not-linked.json": {409, codeCollectionNotLinked},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := fs.ReadFile(contracts.FS, "fixtures/adapter/refusal/"+name)
			if errors.Is(err, fs.ErrNotExist) {
				t.Skipf("the contract's revision has no %s", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			w := newWired(t, filepath.Join(t.TempDir(), "state"))
			Link(w.st, 42, testConnection, linkLive)
			w.apiary.refuse = func(string, int) (int, string) { return tc.status, string(b) }
			if err := w.client.Items(context.Background(), widgetsItem()); !refusedAs(err, tc.status, tc.code) {
				t.Errorf("err %v", err)
			}
		})
	}
}

// TestAnUnsigned403KeepsNothing has Qory Apiary answer a request for a live connection
// 403 connection_unknown under a key the pin does not list: serve acts on no unsigned
// answer, so no first 403 is kept.
func TestAnUnsigned403KeepsNothing(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	Link(w.st, 42, testConnection, linkLive)
	w.apiary.signer = newKey(t)
	w.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	if err := w.adapter.listRepositories(context.Background(), 42); err == nil {
		t.Error("an unsigned 403 passed")
	}
	if ok, _ := present(w.st.Get(nsForbidden, testConnection)); ok {
		t.Error("an unsigned 403 is kept as the first")
	}
}

// TestTheRoundSettlesAReplacedConnection runs a round, as after a restart, with a
// connection a connect replaced on the installation 42 whose last listing is due: the
// round sends that listing, empty, and its 403 connection_unknown forgets the
// connection.
func TestTheRoundSettlesAReplacedConnection(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	putLink(w.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	keepReplaced(w.st, 42, link{Connection: otherConnection, Return: time.Now().Add(-returnFor - returnSkew).Unix()})
	w.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	clock := &pullClock{t: time.Now()}
	p := &puller{adapter: w.adapter, store: w.st, log: w.adapter.Log, now: clock.now, sleep: clock.sleep, jitter: func(time.Duration) time.Duration { return 0 }}
	p.round(context.Background(), clock.now(), time.Hour)
	p.rounds.Wait()
	n := 0
	for _, s := range w.apiary.sent(routeCollections) {
		if s.body["connection_id"] == otherConnection {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d listings of the replaced connection", n)
	}
	if _, ok, _ := replacedOf(w.st, otherConnection); ok {
		t.Error("the replaced connection is kept")
	}
}

// TestOneListingOfAReplacedConnectionAtATime has two rounds find the same replaced
// connection due while the first round's listing of it waits for the installation's
// lock: the second round leaves it, and one listing is sent.
func TestOneListingOfAReplacedConnectionAtATime(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	putLink(w.st, 42, link{Connection: testConnection, State: linkPending, Return: time.Now().Add(returnFor).Unix()})
	keepReplaced(w.st, 42, link{Connection: otherConnection, Return: time.Now().Add(-returnFor - returnSkew).Unix()})
	w.apiary.refuse = func(string, int) (int, string) { return 403, `{"error":"connection_unknown"}` }
	unlock, err := w.adapter.lockInstallation(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	var waits atomic.Int32
	w.adapter.lockWaits = func(int64) { waits.Add(1) }
	p := &puller{adapter: w.adapter, store: w.st, log: w.adapter.Log}
	p.listReplaced(context.Background())
	eventually(t, "the first listing waits", func() bool { return waits.Load() == 1 })
	p.listReplaced(context.Background())
	unlock()
	p.rounds.Wait()
	n := 0
	for _, s := range w.apiary.sent(routeCollections) {
		if s.body["connection_id"] == otherConnection {
			n++
		}
	}
	if n != 1 || waits.Load() != 1 {
		t.Errorf("%d listings, %d waits", n, waits.Load())
	}
}
