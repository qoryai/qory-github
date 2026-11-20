package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	testChangeID  = "av_0123456789abcdef"
	testChangeID2 = "av_fedcba9876543210"
	testBranch    = "qory/wi_42"
	testTitle     = "Fix the widget"
)

// testHost is the web host of the stand-in GitHub, the system of the targets' addresses.
var testHost = github.Client{API: "http://127.0.0.1:1"}.WebHost()

// sha is the commit id the tests give commit n: 40 hexadecimal digits.
func sha(n int) string { return fmt.Sprintf("%040x", n) }

// draftAsk is what the test sets for the pull request: Number 0 for an entry that has no
// previous address, or the number in the ref of the previous version's address.
type draftAsk struct {
	Number int64
}

var (
	openDraft = &draftAsk{}
	update    = func(n int64) *draftAsk { return &draftAsk{Number: n} }
)

// crTarget is the target of a change request entry for the repository path on system:
// the branch the run pushed, a base at sha(1) on the branch base, and commits commits,
// sha(2) on; with draft, the entry has a previous address with the number of draft, and
// ready sets the data's draft to false, so the pull request is no draft.
type crTarget struct {
	path, system, base string
	commits            int
	draft              *draftAsk
	ready              bool
}

func targetOf(path string, commits int, draft *draftAsk) crTarget {
	return crTarget{path: path, system: testHost, base: "main", commits: commits, draft: draft}
}

// commitRef is a commit as the pull-request type writes it: the repository as collection,
// and the commit id as the path of the address.
func (t crTarget) commitRef(id string) map[string]any {
	return map[string]any{"collection": refOf(t.path), "address": map[string]any{"system": t.system, "path": id}}
}

// data is the data of the pull-request change request for t, in the form of the
// pull-request artifact type.
func (t crTarget) data() json.RawMessage {
	d := map[string]any{
		"target":      map[string]any{"collection": refOf(t.path), "address": map[string]any{"system": t.system, "path": t.path}},
		"title":       testTitle,
		"text":        "Text.",
		"branch":      testBranch,
		"base_branch": t.base,
		"base":        t.commitRef(sha(1)),
		"head":        t.commitRef(sha(1 + t.commits)),
		"draft":       !t.ready,
	}
	var commits, steps []any
	for i := range t.commits {
		commits = append(commits, t.commitRef(sha(2+i)))
		steps = append(steps, map[string]any{"commit": sha(2 + i), "step": "deliverable:d-" + fmt.Sprint(i+1)})
	}
	d["commits"], d["steps"] = commits, steps
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

// changeOf is a change_request entry of the kind pull-request with the id id, the title
// and text, for the target t.
func changeOf(id, title, text string, t crTarget) contracts.Change {
	ch := contracts.Change{
		Kind: contracts.ChangeRequest, ChangeRequestID: id, ChangeKind: github.ChangeKindPullRequest,
		Target: &contracts.Target{Collection: refOf(t.path), Address: &contracts.TargetAddress{System: t.system, Path: t.path}},
		Title:  title, Text: text, Data: t.data(),
	}
	if t.draft != nil && t.draft.Number > 0 {
		n := strconv.FormatInt(t.draft.Number, 10)
		ch.Previous = &contracts.ChangePrevious{Address: &contracts.ChangeAddress{URL: "https://" + t.system + "/" + t.path + "/pull/" + n, Ref: n}}
	}
	return ch
}

// previously is ch with the previous version's title.
func previously(ch contracts.Change, title string) contracts.Change {
	if ch.Previous == nil {
		ch.Previous = &contracts.ChangePrevious{}
	}
	ch.Previous.Title = title
	return ch
}

// entrySchema is the closed copy of changes.schema.json, which a writer of entries, as the
// fake is, is tested against.
var entrySchema = func() *jsonschema.Schema {
	s, err := contracts.CompileClosed("changes.schema.json")
	if err != nil {
		panic(err)
	}
	return s
}()

// checkEntries reports an entry that breaks the contract's changes.schema.json.
func checkEntries(t *testing.T, entries ...contracts.Change) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 1, "revision": contracts.Revision, "cursor": "c_1", "changes": entries})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err == nil {
		err = entrySchema.Validate(doc)
	}
	if err != nil {
		t.Errorf("an entry breaks the contract: %v", err)
	}
}

// step reads the feed once and fails the test on an error.
func (w *wired) stepOK(t *testing.T) {
	t.Helper()
	if err := w.feed.step(context.Background()); err != nil {
		t.Fatalf("step: %v", err)
	}
}

// replies are the replies to change_request entries Qory Apiary received.
func (f *fakeApiary) replies() []contracts.ChangesSubmitted {
	var out []contracts.ChangesSubmitted
	for _, r := range f.sent(routeChangesSubmitted) {
		var c contracts.ChangesSubmitted
		json.Unmarshal(r.raw, &c)
		out = append(out, c)
	}
	return out
}

// replyData is the data of the reply r.
func replyData(r contracts.ChangesSubmitted) pullRequestReply {
	var d pullRequestReply
	json.Unmarshal(r.Data, &d)
	return d
}

// gotDraft is the draft of a reply: the address and action, and the number, title and
// state of its data.
type gotDraft struct {
	Number                    int64
	URL, Title, State, Action string
}

// draftsReplied are the drafts of the replies, by the path of the target's address.
func (f *fakeApiary) draftsReplied() map[string]*gotDraft {
	out := map[string]*gotDraft{}
	for _, r := range f.replies() {
		d := replyData(r).Draft
		if d == nil || r.Address == nil {
			out[r.Target.Address.Path] = nil
			continue
		}
		out[r.Target.Address.Path] = &gotDraft{Number: d.Number, URL: r.Address.URL, Title: d.Title, State: d.State, Action: r.Action}
	}
	return out
}

// changeReports are the failure reports for change_request entries, each "path reason",
// with the path of the target's address, or its collection when it has none.
func (f *fakeApiary) changeReports() []string {
	var out []string
	for _, r := range f.sent(routeChangesFailed) {
		if id, _ := r.body["change_request_id"].(string); id != "" {
			target, _ := r.body["target"].(map[string]any)
			where, _ := target["collection"].(string)
			if address, ok := target["address"].(map[string]any); ok {
				where, _ = address["path"].(string)
			}
			out = append(out, fmt.Sprint(where, " ", r.body["reason"]))
		}
	}
	return out
}

// newChangeWired is [newWired] with the installation 42 reaching acme/widgets, acme/gadgets
// and acme/old, as an entry's repository is found through it.
func newChangeWired(t *testing.T) *wired {
	t.Helper()
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	for _, ref := range []string{widgetsRef, gadgetsRef, refOf("acme/old")} {
		if err := setReach(w.st, ref, 42); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// pullMints are the tokens minted for the pull requests of one repository.
func (w *wired) pullMints() []string {
	w.gh.mu.Lock()
	defer w.gh.mu.Unlock()
	var out []string
	for _, m := range w.gh.mints {
		if strings.Contains(m, "pull_requests") {
			out = append(out, m)
		}
	}
	return out
}

// endOf is the cursor after the last entry the fake has.
func endOf(w *wired) string {
	w.apiary.mu.Lock()
	defer w.apiary.mu.Unlock()
	return "c_" + fmt.Sprint(len(w.apiary.changes))
}

// cursorIs reports whether the feed's cursor is c.
func cursorIs(w *wired, c string) bool {
	got, err := w.st.Get(nsAdapter, keyCursor)
	if errors.Is(err, store.ErrNotFound) {
		return c == ""
	}
	return err == nil && string(got) == c
}

// blockOf is the marked block with text, as the description of a draft has it.
func blockOf(text string) string { return "<!-- qory:start -->\n" + text + "\n<!-- qory:end -->" }

// editPull changes the stand-in's pull request n of repo.
func editPull(w *wired, repo string, n int, edit func(p *ghPullRec)) {
	setGitHub(w.gh, func(f *fakeGitHub) {
		for _, p := range f.pulls {
			if p.repo == repo && p.number == n {
				edit(p)
			}
		}
	})
}

// TestAChangeRequestOfTheKindPullRequestOpensOneDraftAndRepliesWithItsAddress reads a
// change_request entry of the kind pull-request that asks for a draft: one draft pull
// request is opened with the marked body, from the branch into the base branch, with a
// token that has pull_requests: write alone; the reply, which passes the contract's
// schema, echoes the entry's target, has the pull request's address, its number as the
// ref and the action created, and in its data the draft's number, title and state draft
// and the address of the base and of each of four commits; the cursor moves.
func TestAChangeRequestOfTheKindPullRequestOpensOneDraftAndRepliesWithItsAddress(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "What changed.", targetOf("acme/widgets", 4, openDraft))
	entry.Ref = itemOf("acme/widgets", 7)
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 {
		t.Fatalf("%d pull requests", len(pulls))
	}
	p := pulls[0]
	if !p.draft || p.head != testBranch || p.base != "main" || p.title != testTitle || p.body != blockOf("What changed.") {
		t.Errorf("the pull request is %+v", p)
	}
	if mints := w.pullMints(); len(mints) != 1 || mints[0] != `{"permissions":{"pull_requests":"write"},"repositories":["widgets"]}` {
		t.Errorf("mints %v", mints)
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || replies[0].ChangeRequestID != testChangeID || !reflect.DeepEqual(replies[0].Target, *entry.Target) {
		t.Fatalf("replies %+v", replies)
	}
	wantDraft := gotDraft{Number: 1, URL: "https://github.com/acme/widgets/pull/1", Title: testTitle, State: "draft", Action: "created"}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || *d != wantDraft {
		t.Errorf("the draft is %+v, want %+v", d, wantDraft)
	}
	if a := replies[0].Address; a == nil || a.Ref != "1" {
		t.Errorf("the address is %+v, want the ref 1", a)
	}
	// The contract needs the address's host to equal the target's system. The stand-in
	// answers html_url on github.com while its system is the loopback host, so the
	// equality cannot show here; the form of the url and the system can.
	u, err := url.Parse(replies[0].Address.URL)
	if err != nil || u.Scheme != "https" || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || strings.Trim(u.Path, "/") == "" {
		t.Errorf("the address's url %q breaks the contract's form: %v", replies[0].Address.URL, err)
	}
	if sys := replies[0].Target.Address.System; sys != w.adapter.GitHub.WebHost() {
		t.Errorf("the target's system is %q, want the client's web host %q", sys, w.adapter.GitHub.WebHost())
	}
	r := replyData(replies[0])
	if r.Base.Commit != sha(1) || r.Base.CommitURL != "https://github.com/acme/widgets/commit/"+sha(1) || len(r.Commits) != 4 {
		t.Errorf("the reply is %+v", r)
	}
	for i, c := range r.Commits {
		if c.Commit != sha(2+i) || c.CommitURL != "https://github.com/acme/widgets/commit/"+sha(2+i) {
			t.Errorf("commit %d is %+v", i, c)
		}
	}
	if !cursorIs(w, "c_1") || len(w.apiary.changeReports()) != 0 {
		t.Errorf("the cursor or the reports are wrong: %v", w.apiary.changeReports())
	}
	if strings.Contains(w.log.String(), ghToken) || strings.Contains(w.log.String(), "What changed.") {
		t.Errorf("the log contains the token or the text: %s", w.log.String())
	}
}

// TestALaterChangeRequestUpdatesTheSameDraft reads a second entry with action update: the
// same pull request changes, and only the text between the markers: a person's lines
// before and after the block stay. The title changes while it equals previous.title.
func TestALaterChangeRequestUpdatesTheSameDraft(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) {
		p.body = "Dana's line above.\n\n" + p.body + "\n\nDana's line below."
	})
	second := changeOf(testChangeID2, "Fix the widget well", "Second text.", targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	checkEntries(t, second)
	w.apiary.add(second)
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 {
		t.Fatalf("%d pull requests", len(pulls))
	}
	if want := "Dana's line above.\n\n" + blockOf("Second text.") + "\n\nDana's line below."; pulls[0].body != want {
		t.Errorf("the body is %q, want %q", pulls[0].body, want)
	}
	if pulls[0].title != "Fix the widget well" || !pulls[0].draft {
		t.Errorf("the pull request is %+v", pulls[0])
	}
	d := w.apiary.draftsReplied()
	if len(w.apiary.replies()) != 2 || d["acme/widgets"] == nil || *d["acme/widgets"] != (gotDraft{Number: 1, URL: "https://github.com/acme/widgets/pull/1", Title: "Fix the widget well", State: "draft", Action: "updated"}) {
		t.Errorf("the replies are %+v", w.apiary.replies())
	}
}

// TestAnUpdateKeepsATitleAPersonChanged: the title changes only while it equals
// previous_title; a title a person edited stays, and the description still changes.
func TestAnUpdateKeepsATitleAPersonChanged(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = "Dana's title" })
	second := changeOf(testChangeID2, "A new title", "Second text.", targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	p := w.gh.pullRequests("acme/widgets")[0]
	if p.title != "Dana's title" || p.body != blockOf("Second text.") {
		t.Errorf("the pull request is %+v", p)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != "Dana's title" || d.Action != "updated" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAnUpdateWithNoMarkersAddsOneBlockAtTheEnd: when a person removed the markers, the
// update adds a new marked block after a blank line, and changes nothing else.
func TestAnUpdateWithNoMarkersAddsOneBlockAtTheEnd(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = "Dana wrote all of this." })
	w.apiary.add(changeOf(testChangeID2, testTitle, "Second text.", targetOf("acme/widgets", 2, update(1))))
	w.stepOK(t)
	if got, want := w.gh.pullRequests("acme/widgets")[0].body, "Dana wrote all of this.\n\n"+blockOf("Second text."); got != want {
		t.Errorf("the body is %q, want %q", got, want)
	}
}

// TestAnUpdateThatChangesNothingIsKept: the entry's text is the block's already and the
// title stands, so no request writes, and the reply has the action kept.
func TestAnUpdateThatChangesNothingIsKept(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Same text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	// GitHub may store the body with CRLF line breaks, which is the same text.
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = strings.ReplaceAll(p.body, "\n", "\r\n") })
	second := changeOf(testChangeID2, testTitle, "Same text.", targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	for _, c := range w.gh.pullCalls() {
		if strings.HasPrefix(c, "PATCH ") {
			t.Errorf("a write: %s", c)
		}
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "kept" || d.Number != 1 || d.State != "draft" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAClosedOrMergedPullRequestIsNotEdited: an update for a pull request that GitHub
// shows as closed or merged writes nothing, and the reply has its real state and the
// action kept. The reply's state closed or merged is valid only under the contract's
// changes-submitted.schema.json that lists those states, which the fake Qory Apiary
// checks every reply against.
func TestAClosedOrMergedPullRequestIsNotEdited(t *testing.T) {
	for _, state := range []string{"closed", "merged"} {
		w := newChangeWired(t)
		w.apiary.add(changeOf(testChangeID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.closed, p.merged = true, state == "merged" })
		second := changeOf(testChangeID2, "New title", "Second text.", targetOf("acme/widgets", 2, update(1)))
		second = previously(second, testTitle)
		w.apiary.add(second)
		w.stepOK(t)
		p := w.gh.pullRequests("acme/widgets")[0]
		if p.title != testTitle || p.body != blockOf("First text.") {
			t.Errorf("%s: the pull request is %+v", state, p)
		}
		posts := 0
		for _, c := range w.gh.pullCalls() {
			if strings.HasPrefix(c, "PATCH ") {
				t.Errorf("%s: a write: %s", state, c)
			}
			if strings.HasPrefix(c, "POST ") {
				posts++
			}
		}
		if posts != 1 {
			t.Errorf("%s: %d posts, want the first entry's alone", state, posts)
		}
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.State != state || d.Action != "kept" || d.Number != 1 || d.Title != testTitle {
			t.Errorf("%s: the draft is %+v", state, d)
		}
		if got := len(w.gh.pullRequests("acme/widgets")); got != 1 {
			t.Errorf("%s: %d pull requests", state, got)
		}
	}
}

// TestAnEntryThatWantsNoDraftOpensAReadyPullRequest: an entry whose data has draft false
// opens a pull request that is no draft, from the branch into the base branch, with the
// block as its description; the reply has the pull request's address, the action created,
// the state open, and the address of each of four commits.
func TestAnEntryThatWantsNoDraftOpensAReadyPullRequest(t *testing.T) {
	w := newChangeWired(t)
	target := targetOf("acme/widgets", 4, openDraft)
	target.ready = true
	entry := changeOf(testChangeID, testTitle, "Text.", target)
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].draft || pulls[0].head != testBranch || pulls[0].base != "main" || pulls[0].body != blockOf("Text.") {
		t.Fatalf("pull requests %+v", pulls)
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || replies[0].Action != "created" || replies[0].Address == nil || replyData(replies[0]).Draft == nil || replyData(replies[0]).Draft.State != "open" || len(replyData(replies[0]).Commits) != 4 {
		t.Fatalf("replies %+v", replies)
	}
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
}

// TestTwoEntriesOfOneVersionGetOneDraftAndOneReplyEach: a version with two repositories has
// two entries with one change_request_id and two target collections. Each opens a draft
// in its repository and gets one reply, with the target of its entry and the addresses
// of that repository.
func TestTwoEntriesOfOneVersionGetOneDraftAndOneReplyEach(t *testing.T) {
	w := newChangeWired(t)
	first := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	second := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 2, openDraft))
	checkEntries(t, first, second)
	w.apiary.add(first, second)
	w.stepOK(t)
	for _, repo := range []string{"acme/widgets", "acme/gadgets"} {
		if got := len(w.gh.pullRequests(repo)); got != 1 {
			t.Errorf("%s: %d pull requests", repo, got)
		}
	}
	replies := w.apiary.replies()
	if len(replies) != 2 {
		t.Fatalf("replies %+v", replies)
	}
	for i, r := range replies {
		path := []string{"acme/widgets", "acme/gadgets"}[i]
		data := replyData(r)
		if r.ChangeRequestID != testChangeID || r.Target.Address.Path != path || len(data.Commits) != i+1 || !strings.HasPrefix(data.Base.CommitURL, "https://github.com/"+path+"/commit/") || r.Address == nil || !strings.HasPrefix(r.Address.URL, "https://github.com/"+path+"/pull/") {
			t.Errorf("the reply is %+v", r)
		}
	}
}

// TestAReplayOfADoneEntryOpensNoSecondDraft reads the feed from the start again, as a
// restart does: the pull request is found by its head, not opened again, and the reply
// has the same number, address, title and state.
func TestAReplayOfADoneEntryOpensNoSecondDraft(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	w.feed = &feed{apiary: w.client, adapter: w.adapter, store: w.st, publicURL: "https://qory-github.example.com", log: w.feed.log}
	if err := w.st.Delete(nsAdapter, keyCursor); err != nil {
		t.Fatal(err)
	}
	w.stepOK(t)
	if got := len(w.gh.pullRequests("acme/widgets")); got != 1 {
		t.Errorf("%d pull requests", got)
	}
	replies := w.apiary.replies()
	if len(replies) != 2 {
		t.Fatalf("%d replies", len(replies))
	}
	if replies[1].Action != "kept" {
		t.Errorf("the replay's action is %s", replies[1].Action)
	}
	replies[1].Action = replies[0].Action
	if !reflect.DeepEqual(replies[0].Address, replies[1].Address) || string(replies[0].Data) != string(replies[1].Data) {
		t.Errorf("the replies differ: %+v and %+v", replies[0], replies[1])
	}
}

// TestAPageReadAgainAppliesADoneEntryOnce: a page whose cursor does not move, as when
// another entry of it fails, applies a change request that is done once.
func TestAPageReadAgainAppliesADoneEntryOnce(t *testing.T) {
	w := newChangeWired(t)
	setReach(w.st, widgetsRef, 42)
	setGitHub(w.gh, func(f *fakeGitHub) { f.commentStatus, f.commentAnswer = 502, `{"message":"Bad Gateway"}` })
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), commentEntry("acme/widgets", 7))
	for range 2 {
		if err := w.feed.step(context.Background()); err == nil {
			t.Fatal("the comment fails, but the step passed")
		}
	}
	if got := len(w.apiary.replies()); got != 1 {
		t.Errorf("%d replies", got)
	}
	posts := 0
	for _, c := range w.gh.pullCalls() {
		if c == "POST /repos/acme/widgets/pulls" {
			posts++
		}
	}
	if posts != 1 {
		t.Errorf("%d posts", posts)
	}
}

// TestADraftNumberThatIsGoneIsOnlyAHint: an update whose number GitHub has no pull
// request for opens a new draft when none has the head, and updates the pull request
// that has the head when there is one, with another number.
func TestADraftNumberThatIsGoneIsOnlyAHint(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, update(9))))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].number != 1 {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "created" || d.Number != 1 {
		t.Errorf("the draft is %+v", d)
	}
	second := changeOf(testChangeID2, testTitle, "New text.", targetOf("acme/widgets", 2, update(9)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	pulls = w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].body != blockOf("New text.") {
		t.Errorf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "updated" || d.Number != 1 {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAPullRequestIntoAnotherBaseIsTheDraftAndKeepsItsBase: the pull request is found by
// its head branch and repository alone. A pull request from the branch into another base
// branch, as a person set it, is edited, not joined by a second one, and its base stays;
// a later version with another base.branch changes no base either.
func TestAPullRequestIntoAnotherBaseIsTheDraftAndKeepsItsBase(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "release", number: 1, title: "Into release", draft: true})
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].base != "release" || pulls[0].body != blockOf("Text.") {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 1 || d.Action != "updated" {
		t.Errorf("the draft is %+v", d)
	}
	later := targetOf("acme/widgets", 2, update(1))
	later.base = "develop"
	w.apiary.add(changeOf(testChangeID2, testTitle, "New text.", later))
	w.stepOK(t)
	pulls = w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].base != "release" || pulls[0].body != blockOf("New text.") {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestSeveralPullRequestsFromTheBranchAreChosenByNumberThenNewestOpen: of two or more
// pull requests from the head branch, the entry's number is taken when it is among them;
// otherwise the newest open one. A closed or merged one is never chosen by the branch,
// see TestWithNoUsableAddressOnlyAnOpenPullRequestFromTheBranchIsUpdated. No case is
// reported unreachable.
func TestSeveralPullRequestsFromTheBranchAreChosenByNumberThenNewestOpen(t *testing.T) {
	pull := func(n int, base string, closed, merged bool) *ghPullRec {
		return &ghPullRec{repo: "acme/widgets", head: testBranch, base: base, number: n, title: fmt.Sprint("Pull ", n), draft: !closed, closed: closed, merged: merged}
	}
	for _, tc := range []struct {
		name   string
		pulls  []*ghPullRec
		draft  *draftAsk
		number int
		action string
		state  string
	}{
		{"the entry's number, though an open one is newer", []*ghPullRec{pull(1, "main", false, false), pull(2, "main", false, false)}, update(1), 1, "updated", "draft"},
		{"a number that is not among them: the newest open one", []*ghPullRec{pull(1, "main", false, false), pull(2, "main", true, false), pull(3, "main", false, false), pull(4, "main", true, false)}, update(9), 3, "updated", "draft"},
		{"an open one, with bases that differ", []*ghPullRec{pull(1, "release", true, false), pull(2, "develop", false, false)}, openDraft, 2, "updated", "draft"},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.pulls = tc.pulls })
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, tc.draft)))
		w.stepOK(t)
		d := w.apiary.draftsReplied()["acme/widgets"]
		if d == nil || d.Number != int64(tc.number) || d.Action != tc.action || d.State != tc.state || len(w.apiary.changeReports()) != 0 || len(w.gh.pullRequests("acme/widgets")) != len(tc.pulls) {
			t.Errorf("%s: the draft is %+v, reports %v", tc.name, d, w.apiary.changeReports())
		}
	}
}

// TestWithNoUsableAddressOnlyAnOpenPullRequestFromTheBranchIsUpdated: an entry with no
// previous.address, or one that is unusable or gone, makes the change at the target (the
// contract's README, "Without previous.address, it makes the change at the target"), and
// "kept" is for what is at an address (changes-submitted.schema.json, action: "kept: it
// changed nothing, because what is at the address was finished at the target, or already
// had the entry's text"). So a branch whose pull requests are all closed or merged gets a
// new pull request, action created, and an open one from the branch is updated. A usable
// address whose pull request is closed or merged is kept.
func TestWithNoUsableAddressOnlyAnOpenPullRequestFromTheBranchIsUpdated(t *testing.T) {
	pull := func(n int, closed, merged bool) *ghPullRec {
		return &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: n, title: fmt.Sprint("Pull ", n), draft: !closed, closed: closed, merged: merged}
	}
	noRef := func(ch contracts.Change) contracts.Change { return previously(ch, "") }
	for _, tc := range []struct {
		name   string
		pulls  []*ghPullRec
		entry  func(contracts.Change) contracts.Change
		calls  []string
		number int64
		action string
		state  string
	}{
		{"no address, a closed one", []*ghPullRec{pull(4, true, false)}, nil, []string{"LIST", "POST "}, 5, "created", "draft"},
		{"no address, a merged one", []*ghPullRec{pull(4, true, true)}, nil, []string{"LIST", "POST "}, 5, "created", "draft"},
		{"no address, a previous with a title alone, a merged one", []*ghPullRec{pull(4, true, true)}, noRef, []string{"LIST", "POST "}, 5, "created", "draft"},
		{"no address, a closed one and an open one", []*ghPullRec{pull(4, true, false), pull(2, false, false)}, nil, []string{"LIST", "GET /2", "PATCH /2"}, 2, "updated", "draft"},
		{"no address, an open one", []*ghPullRec{pull(3, false, false)}, nil, []string{"LIST", "GET /3", "PATCH /3"}, 3, "updated", "draft"},
		{"an address 0, a merged one", []*ghPullRec{pull(4, true, true)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "0") }, []string{"LIST", "POST "}, 5, "created", "draft"},
		{"an address that is no number, a closed one", []*ghPullRec{pull(4, true, false)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "seven") }, []string{"LIST", "POST "}, 5, "created", "draft"},
		{"a gone address 9, a merged one", []*ghPullRec{pull(4, true, true)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "9") }, []string{"GET /9", "LIST", "POST "}, 5, "created", "draft"},
		{"a gone address 9, a closed one and an open one", []*ghPullRec{pull(4, true, false), pull(2, false, false)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "9") }, []string{"GET /9", "LIST", "GET /2", "PATCH /2"}, 2, "updated", "draft"},
		{"an address 4 that is merged", []*ghPullRec{pull(4, true, true)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "4") }, []string{"GET /4"}, 4, "kept", "merged"},
		{"an address 4 that is closed, an open one on the branch", []*ghPullRec{pull(4, true, false), pull(6, false, false)}, func(ch contracts.Change) contracts.Change { return withAddress(ch, "4") }, []string{"GET /4"}, 4, "kept", "closed"},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.pulls = tc.pulls })
		ch := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
		if tc.entry != nil {
			ch = tc.entry(ch)
		}
		w.apiary.add(ch)
		w.stepOK(t)
		if got := pullCallsOf(w, 0); !slices.Equal(got[1:], tc.calls) {
			t.Errorf("%s: the calls are %v, want %v after the installation lookup", tc.name, got, tc.calls)
		}
		d := w.apiary.draftsReplied()["acme/widgets"]
		if d == nil || d.Number != tc.number || d.Action != tc.action || d.State != tc.state || len(w.apiary.changeReports()) != 0 {
			t.Errorf("%s: the draft is %+v, reports %v", tc.name, d, w.apiary.changeReports())
		}
	}
}

// TestWithNoAddressANewPullRequestThatGitHubRefusesForNoCommitsIsReported: the branch has
// a merged pull request and no address, so the adapter opens a new one, and GitHub
// answers 422 "No commits between" for it. The contract's reason for a 422 "for a cause
// other than a missing place or a length limit" is refused (changes-failed.schema.json,
// reason), so the entry gets a failure report with the reason refused and the fix first,
// and no reply.
func TestWithNoAddressANewPullRequestThatGitHubRefusesForNoCommitsIsReported(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = []*ghPullRec{{repo: "acme/widgets", head: testBranch, base: "main", number: 4, title: "Four", closed: true, merged: true}}
		f.pullFail = func(m, p string) (int, string) {
			if m == "POST" && p == "/repos/acme/widgets/pulls" {
				return 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"No commits between main and ` + testBranch + `"}]}`
			}
			return 0, ""
		}
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if got, want := pullCallsOf(w, 0), []string{"LIST", "POST "}; !slices.Equal(got[1:], want) {
		t.Errorf("the calls are %v, want %v after the installation lookup", got, want)
	}
	if r := w.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets refused" || len(w.apiary.replies()) != 0 {
		t.Fatalf("reports %v, replies %+v", r, w.apiary.replies())
	}
	if d := detailOf(w, 0); !strings.HasPrefix(d, "Push a commit that the base branch lacks, then submit again.") || !strings.Contains(d, "No commits between main and "+testBranch) {
		t.Errorf("the detail is %q", d)
	}
}

// TestAPullRequestFromAForkIsNotTheDraft: a pull request with the head branch's name
// from another repository is not the draft, so a draft is opened.
func TestAPullRequestFromAForkIsNotTheDraft(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", headRepo: "acme/widgets-fork", head: testBranch, base: "main", number: 1, title: "A fork's"})
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 2 || pulls[1].number != 2 || pulls[0].title != "A fork's" {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestAChangeRequestThatCannotBePutOnGitHubIsReportedWithItsReason: each case is an entry
// whose draft a retry cannot open or update; one failure report, which passes the
// contract's schema, has the change_request_id, the target as the entry has it, the
// reason and a detail that starts with the fix line of that case, at most 100
// characters; no reply is sent; the cursor moves; the log has the fix once, with the
// change_request_id and without the text or the token.
func TestAChangeRequestThatCannotBePutOnGitHubIsReportedWithItsReason(t *testing.T) {
	long := strings.Repeat("a", 20001)
	forbidden := func(method, path string, status int, body string) func(f *fakeGitHub) {
		return func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				if m == method && p == path {
					return status, body
				}
				return 0, ""
			}
		}
	}
	const (
		fixNotInstalled = "Install the App on the repository with the permission Pull requests: write."
		fixPermission   = "Give the App's installation the permission Pull requests: write on the repository."
		fixRefused      = "Change the pull request or the run as GitHub's answer says, then submit again."
	)
	for _, tc := range []struct {
		name        string
		description string
		set         func(f *fakeGitHub)
		want        string
		fix         string
		forge       string // what the detail has of GitHub's answer after the fix, or none
		quiet       bool   // GitHub is asked nothing
	}{
		{"the list is 403", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 403, `{"message":"Resource not accessible by integration"}`), "not_permitted", fixPermission, "GitHub returned 403: Resource not accessible by integration", false},
		{"the list is 404", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 404, `{"message":"Not Found"}`), "not_permitted", fixNotInstalled, "GitHub returned 404: Not Found", false},
		{"no installation", "Text.", func(f *fakeGitHub) { f.noInstallation = map[string]bool{"acme/widgets": true} }, "not_permitted", fixNotInstalled, "", false},
		{"the installation lookup is 403", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 403, `{"message":"Forbidden"}`), "not_permitted", "Check on GitHub that the App is not suspended or blocked, then submit again.", "GitHub returned 403: Forbidden", false},
		{"the installation lookup is 301", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 301, `{"message":"Moved Permanently"}`), "target_gone", github.FixMoved, "GitHub returned 301: Moved Permanently", false},
		{"the installation lookup is 308", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 308, `{"message":"Permanent Redirect"}`), "target_gone", github.FixMoved, "GitHub returned 308: Permanent Redirect", false},
		{"the installation lookup is 404", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 404, `{"message":"Not Found"}`), "not_permitted", fixNotInstalled, "", false},
		{"the installation lookup is 302", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 302, `{"message":"Found"}`), "not_permitted", fixNotInstalled, "", false},
		{"the installation lookup is 307", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 307, `{"message":"Temporary Redirect"}`), "not_permitted", fixNotInstalled, "", false},
		{"a suspended installation", "Text.", func(f *fakeGitHub) { f.installSuspended = true }, "not_permitted", "Unsuspend the App's installation on GitHub.", "", false},
		{"the create is 403", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 403, `{"message":"Resource not accessible by integration"}`), "not_permitted", fixPermission, "GitHub returned 403: Resource not accessible by integration", false},
		{"the repository moved", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 301, `{"message":"Moved Permanently"}`), "target_gone", "Link the repository by its new name: GitHub moved it.", "GitHub returned 301: Moved Permanently", false},
		{"the head branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{testBranch: true} }, "refused", "Push the run's branch to the repository again, then submit again.", "GitHub returned 422: Validation Failed; PullRequest head invalid", false},
		{"GitHub's message for an invalid head", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"invalid","message":"head\ninvalid"}]}`), "refused", "Push the run's branch to the repository again, then submit again.", "GitHub returned 422: Validation Failed; PullRequest invalid head invalid", false},
		{"the base branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{"main": true} }, "refused", "Create the base branch on GitHub, or choose another base branch, then submit again.", "GitHub returned 422: Validation Failed; PullRequest base invalid", false},
		{"a description over 20000 characters", long, nil, "too_long", "Shorten the description of the run to 20000 characters or fewer.", "", true},
		{"GitHub's 422 for a body too long", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"body","code":"custom","message":"body is too long (maximum is 65536 characters)"}]}`), "too_long", "Shorten the description of the pull request on GitHub outside the Qory block.", "GitHub returned 422: Validation Failed; PullRequest body custom body is too long (maximum is 65536 characters)", false},
		{"GitHub's 422 for a title too long", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"title","code":"custom","message":"title is too long (maximum is 256 characters)"}]}`), "too_long", "Shorten the title of the pull request on GitHub to 256 characters or fewer.", "GitHub returned 422: Validation Failed; PullRequest title custom title is too long (maximum is 256 characters)", false},
		{"400", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 400, `{"message":"Problems parsing JSON"}`), "refused", fixRefused, "GitHub returned 400: Problems parsing JSON", false},
		{"another 422", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"Something else is wrong"}]}`), "refused", fixRefused, "GitHub returned 422: Validation Failed; PullRequest custom Something else is wrong", false},
		{"GitHub's 422 for no commits between", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"No commits between main and `+testBranch+`"}]}`), "refused", "Push a commit that the base branch lacks, then submit again.", "GitHub returned 422: Validation Failed; PullRequest custom No commits between main and " + testBranch, false},
		{"a 422 on the list", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed"}`), "refused", fixRefused, "GitHub returned 422: Validation Failed", false},
		{"409", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 409, `{"message":"Conflict"}`), "refused", fixRefused, "GitHub returned 409: Conflict", false},
		{"451", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 451, `{"message":"Unavailable For Legal Reasons"}`), "refused", fixRefused, "GitHub returned 451: Unavailable For Legal Reasons", false},
	} {
		w := newChangeWired(t)
		if tc.set != nil {
			setGitHub(w.gh, tc.set)
		}
		w.apiary.add(changeOf(testChangeID, testTitle, tc.description, targetOf("acme/widgets", 2, openDraft)))
		if err := w.feed.step(context.Background()); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !cursorIs(w, "c_1") {
			t.Errorf("%s: the cursor did not move", tc.name)
		}
		if r := w.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets "+tc.want {
			t.Errorf("%s: reports %v, want %s", tc.name, r, tc.want)
			continue
		}
		if len(w.apiary.replies()) != 0 {
			t.Errorf("%s: replies %+v", tc.name, w.apiary.replies())
		}
		report := w.apiary.sent(routeChangesFailed)[0].body
		if target, _ := report["target"].(map[string]any); report["change_request_id"] != testChangeID || target["collection"] != widgetsRef || target["address"].(map[string]any)["system"] != testHost || report["comment_id"] != nil {
			t.Errorf("%s: the report is %v", tc.name, report)
		}
		detail, _ := report["detail"].(string)
		if len(tc.fix) > 100 || !strings.HasSuffix(tc.fix, ".") || !strings.HasPrefix(detail, tc.fix) || (tc.forge == "" && detail != tc.fix) || (tc.forge != "" && detail != tc.fix+" "+tc.forge) {
			t.Errorf("%s: the detail is %q, want the fix %q and %q", tc.name, detail, tc.fix, tc.forge)
		}
		logged := w.log.String()
		if strings.Count(logged, tc.fix) != 1 || !strings.Contains(logged, testChangeID) || !strings.Contains(logged, "failure report sent to Qory Apiary with the reason "+tc.want) {
			t.Errorf("%s: the log %s", tc.name, logged)
		}
		if strings.Contains(logged, "aaaaaaaa") || strings.Contains(logged, ghToken) {
			t.Errorf("%s: the log has the text or the token", tc.name)
		}
		w.gh.mu.Lock()
		asked := len(w.gh.requests)
		w.gh.mu.Unlock()
		if tc.quiet && asked != 0 {
			t.Errorf("%s: GitHub was asked %d times", tc.name, asked)
		}
	}
}

// TestAnAnswerThatTryingAgainCanChangeIsNotReported: GitHub's 408 and 5xx on the create
// and the 401, each the same as for the other pull request calls, leave the entry to be
// applied again: the step fails, nothing is reported, and the cursor stays.
func TestAnAnswerThatTryingAgainCanChangeIsNotReported(t *testing.T) {
	for _, status := range []int{408, 500, 502, 503} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				if m == "POST" && p == "/repos/acme/widgets/pulls" {
					return status, `{"message":"Try again"}`
				}
				return 0, ""
			}
		})
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || len(w.apiary.changeReports()) != 0 || !cursorIs(w, "") {
			t.Errorf("%d: step %v, reports %v", status, err, w.apiary.changeReports())
		}
	}
}

// TestTheDetailOfAForgeRefusalIsOneCleanLine: GitHub's message with a newline and control
// characters, a token and a bearer value in it, and 5000 characters, is one line of at
// most 1000 characters that starts with the fix, with no token and no header value of the
// answer.
func TestTheDetailOfAForgeRefusalIsOneCleanLine(t *testing.T) {
	const installationToken = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"
	message := "Line one\nline two\r\n\x07bell\u2028separator \u202eflipped " + installationToken + " and Authorization: Bearer abc.def-123 and https://user:secret@example.com/x " + strings.Repeat("long ", 1000)
	body, err := json.Marshal(map[string]any{"message": message})
	if err != nil {
		t.Fatal(err)
	}
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.failHeader = map[string]string{"X-Secret-Header": "header-value-9f3a", "Set-Cookie": "session=cookie-value-77", "X-GitHub-Request-Id": "ABCD:1234"}
		f.pullFail = func(m, p string) (int, string) {
			if m == "POST" && p == "/repos/acme/widgets/pulls" {
				return 400, string(body)
			}
			return 0, ""
		}
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	sent := w.apiary.sent(routeChangesFailed)
	if len(sent) != 1 {
		t.Fatalf("%d reports", len(sent))
	}
	detail, _ := sent[0].body["detail"].(string)
	if n := utf8.RuneCountInString(detail); n < 900 || n > 1000 || !strings.HasPrefix(detail, "Change the pull request or the run as GitHub's answer says, then submit again. GitHub returned 400: Line one line two bell separator flipped [removed] and Authorization: [removed] and [removed] ") || github.OneLine(detail, 1000) != detail {
		t.Errorf("the detail has %d characters: %q", n, detail)
	}
	for _, secret := range []string{installationToken, "abc.def-123", "secret@", "header-value-9f3a", "cookie-value-77", "ABCD:1234", ghToken} {
		if strings.Contains(string(sent[0].raw), secret) {
			t.Errorf("the report has %q", secret)
		}
	}
}

// TestTheCapsOf20000And256Characters: a description of exactly 20000 characters and a
// title of exactly 256 open a draft; 20001 and 257 are too_long before GitHub is asked.
func TestTheCapsOf20000And256Characters(t *testing.T) {
	w := newChangeWired(t)
	exact := changeOf(testChangeID, strings.Repeat("t", 256), strings.Repeat("d", 20000), targetOf("acme/widgets", 1, openDraft))
	checkEntries(t, exact)
	w.apiary.add(exact)
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "created" || len(d.Title) != 256 {
		t.Errorf("the draft is %+v", d)
	}
	w2 := newChangeWired(t)
	w2.apiary.add(changeOf(testChangeID, strings.Repeat("t", 257), "Text.", targetOf("acme/widgets", 1, openDraft)))
	w2.stepOK(t)
	w2.gh.mu.Lock()
	asked := len(w2.gh.requests)
	w2.gh.mu.Unlock()
	if r := w2.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets too_long" || asked != 0 {
		t.Errorf("reports %v, GitHub asked %d times", r, asked)
	}
}

// TestAPullRequestWhoseBodyGrowsPastGitHubsLimitIsTooLong: a person's long description
// plus the block is over GitHub's limit of 65536 characters, so the update is reported as
// too_long with the fix for that description, and GitHub is sent no update.
func TestAPullRequestWhoseBodyGrowsPastGitHubsLimitIsTooLong(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = strings.Repeat("b", 65530) })
	w.apiary.add(changeOf(testChangeID2, testTitle, "Second text.", targetOf("acme/widgets", 2, update(1))))
	w.stepOK(t)
	if r := w.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets too_long" {
		t.Errorf("reports %v", r)
	}
	if d, _ := w.apiary.sent(routeChangesFailed)[0].body["detail"].(string); d != "Shorten the description of the pull request on GitHub outside the Qory block." {
		t.Errorf("the detail is %q", d)
	}
	if slices.Contains(w.gh.pullCalls(), "PATCH /repos/acme/widgets/pulls/1") {
		t.Error("GitHub was sent the update")
	}
}

// TestOneEntryFailingDoesNotBlockTheEntryOfAnotherRepository: of two entries for two
// repositories, the entry of a refused repository is reported and the other is replied
// to, in one step that moves the cursor.
func TestOneEntryFailingDoesNotBlockTheEntryOfAnotherRepository(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.noInstallation = map[string]bool{"acme/widgets": true} })
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	if r := w.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets not_permitted" {
		t.Errorf("reports %v", r)
	}
	if d, r := w.apiary.draftsReplied(), w.apiary.replies(); len(d) != 1 || d["acme/gadgets"] == nil || len(r) != 1 {
		t.Errorf("drafts %+v, replies %+v", d, r)
	}
	if !cursorIs(w, endOf(w)) {
		t.Error("the cursor did not move")
	}
}

// TestTheCursorMovesOnlyWhenEveryEntryIsDone: of two entries of one version, one fails,
// not for good, while the other's draft is opened once and replied to; the cursor stays,
// and the next read applies the one that failed alone and sends its reply.
func TestTheCursorMovesOnlyWhenEveryEntryIsDone(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			if strings.HasPrefix(p, "/repos/acme/widgets/pulls") {
				return 502, `{"message":"Bad Gateway"}`
			}
			return 0, ""
		}
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)))
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if !cursorIs(w, "") {
		t.Error("the cursor moved")
	}
	if d := w.apiary.draftsReplied(); len(d) != 1 || d["acme/gadgets"] == nil || len(w.gh.pullRequests("acme/gadgets")) != 1 {
		t.Errorf("drafts %+v before the other entry is put on GitHub", d)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
	w.stepOK(t)
	if !cursorIs(w, endOf(w)) {
		t.Error("the cursor did not move")
	}
	if d := w.apiary.draftsReplied(); len(d) != 2 || len(w.apiary.replies()) != 2 {
		t.Errorf("drafts %+v, %d replies", d, len(w.apiary.replies()))
	}
	if got := len(w.gh.pullRequests("acme/gadgets")); got != 1 {
		t.Errorf("%d pull requests in gadgets", got)
	}
	gadgets := 0
	for _, c := range w.gh.pullCalls() {
		if strings.Contains(c, "/repos/acme/gadgets/pulls") {
			gadgets++
		}
	}
	if gadgets != 2 {
		t.Errorf("GitHub was asked %d times for gadgets' pull requests, want 2 (list, open), none in the second step", gadgets)
	}
}

// TestAChangeRequestThatFailsForADayIsReportedUnreachable has GitHub return 502 for a day
// on one of two entries of a version: the entry stays, with no report, until the day has
// passed, then it is reported unreachable and passed. The other entry, which is put on
// GitHub, is replied to at once and is not reported.
func TestAChangeRequestThatFailsForADayIsReportedUnreachable(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			if strings.HasPrefix(p, "/repos/acme/widgets/pulls") {
				return 502, `{"message":"Bad Gateway"}`
			}
			return 0, ""
		}
	})
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)))
	for _, after := range []time.Duration{0, stuckFor - time.Second} {
		now = now.Add(after)
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
			t.Fatalf("after %v: err %v", after, err)
		}
		if !cursorIs(w, "") {
			t.Fatalf("after %v: the cursor is kept", after)
		}
	}
	if r := w.apiary.changeReports(); len(r) != 0 {
		t.Errorf("reported before a day: %v", r)
	}
	now = now.Add(time.Second)
	w.stepOK(t)
	if r := w.apiary.changeReports(); len(r) != 1 || r[0] != "acme/widgets unreachable" {
		t.Errorf("reports %v", r)
	}
	if !cursorIs(w, endOf(w)) {
		t.Error("the cursor did not move")
	}
	if !strings.Contains(w.log.String(), github.FixUnreachable) {
		t.Errorf("the log %s", w.log.String())
	}
	if d, _ := w.apiary.sent(routeChangesFailed)[0].body["detail"].(string); d != github.FixUnreachable+" GitHub returned 502: Bad Gateway" {
		t.Errorf("the detail is %q", d)
	}
	if r := w.apiary.replies(); len(r) != 1 || r[0].Target.Address.Path != "acme/gadgets" {
		t.Errorf("replies %+v", r)
	}
}

// TestALaterChangeRequestWaitsForAnEarlierOneOfItsCollection: while the first entry of a
// target collection fails, not for good, the second, which would write older text over
// newer if it ran first, is not applied.
func TestALaterChangeRequestWaitsForAnEarlierOneOfItsCollection(t *testing.T) {
	w := newChangeWired(t)
	// Only the pull request calls fail, so the first entry reaches them, and the second,
	// if it were applied, would ask for pulls/1.
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			if strings.HasPrefix(p, "/repos/acme/widgets/pulls") {
				return 502, `{"message":"Bad Gateway"}`
			}
			return 0, ""
		}
	})
	second := changeOf(testChangeID2, testTitle, "Second.", targetOf("acme/widgets", 2, update(1)))
	w.apiary.add(changeOf(testChangeID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)), second)
	if err := w.feed.step(context.Background()); err == nil {
		t.Fatal("no error")
	}
	calls := w.gh.pullCalls()
	if !slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "GET /repos/acme/widgets/pulls?") }) {
		t.Errorf("the first entry did not reach the pull request calls: %v", calls)
	}
	for _, c := range calls {
		if strings.Contains(c, "pulls/1") {
			t.Errorf("the second entry was applied: %s", c)
		}
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
	w.stepOK(t)
	if p := w.gh.pullRequests("acme/widgets"); len(p) != 1 || p[0].body != blockOf("Second.") {
		t.Errorf("pull requests %+v", p)
	}
}

// TestATargetOfAnotherSystemIsPassedAndTheOtherEntryIsApplied: the entry whose address is
// on another system is logged and passed, no reply, no report, and no request to GitHub
// for it; the other entry is replied to.
func TestATargetOfAnotherSystemIsPassedAndTheOtherEntryIsApplied(t *testing.T) {
	w := newChangeWired(t)
	other := targetOf("acme/widgets", 1, openDraft)
	other.system = "gitlab.example.com"
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", other), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	if d := w.apiary.draftsReplied(); len(d) != 1 || d["acme/gadgets"] == nil {
		t.Errorf("drafts %+v", d)
	}
	if len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.gh.pullRequests("acme/widgets")) != 0 {
		t.Error("a report was sent, or a draft opened")
	}
	if !strings.Contains(w.log.String(), "the address's system is not GitHub's host") || !cursorIs(w, endOf(w)) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAMalformedChangeRequestEntryIsPassedWithoutAReport: an entry whose
// change_request_id is not one, that has no target, or whose target collection is not a
// repository's id, fails for good and is passed with no request.
func TestAMalformedChangeRequestEntryIsPassedWithoutAReport(t *testing.T) {
	noTarget := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	noTarget.Target = nil
	badCollection := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	badCollection.Target.Collection = "R_1001"
	for _, entry := range []contracts.Change{
		changeOf("av_nope", testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)),
		noTarget,
		badCollection,
	} {
		w := newChangeWired(t)
		w.apiary.add(entry)
		w.stepOK(t)
		if !cursorIs(w, "c_1") || len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.apiary.replies()) != 0 || len(w.gh.pullCalls()) != 0 {
			t.Errorf("entry %+v: the step did not pass it quietly", entry)
		}
		if !strings.Contains(w.log.String(), "failed, and is passed") {
			t.Errorf("the log %s", w.log.String())
		}
	}
}

// TestAPullRequestCallAnswered401DropsTheTokens: a pull request call that GitHub answers 401
// drops the tokens kept, so the next try mints a new one.
func TestAPullRequestCallAnswered401DropsTheTokens(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			return map[bool]int{true: 401}[m == "GET" && strings.HasPrefix(p, "/repos/acme/widgets/pulls")], `{"message":"Bad credentials"}`
		}
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	w.adapter.mu.Lock()
	kept := len(w.adapter.tokens)
	w.adapter.mu.Unlock()
	if kept != 0 {
		t.Errorf("%d tokens kept after a 401", kept)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
	w.stepOK(t)
	if mints := len(w.pullMints()); mints != 2 {
		t.Errorf("%d mints, want 2", mints)
	}
}

// TestTheDeclarationHasNoSubmitModuleAndListsTheChangeKind: the start-up body, checked
// against the contract's adapter.schema.json, has no submit_module, and the source role
// of its description lists the change kind pull-request.
func TestTheDeclarationHasNoSubmitModuleAndListsTheChangeKind(t *testing.T) {
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	if err := apiary.client(access).Declare(context.Background(), "https://qory-github.example.com", ""); err != nil {
		t.Fatal(err)
	}
	declared := apiary.sent(routeAdapter)
	if len(declared) != 1 {
		t.Fatalf("declared %d times", len(declared))
	}
	checkBody(t, routeAdapter, declared[0].raw)
	if _, has := declared[0].body["submit_module"]; has {
		t.Errorf("the declaration has submit_module: %s", declared[0].raw)
	}
	source := declared[0].body["description"].(map[string]any)["roles"].(map[string]any)["source"].(map[string]any)
	if got := fmt.Sprint(source["change_kinds"]); got != "["+github.ChangeKindPullRequest+"]" || source["submissions"] != nil {
		t.Errorf("the source role is %v", source)
	}
}

// TestEachRepositoryIsMintedAToken pins that two entries of a version for two
// repositories mint one token for each repository, with that repository's name and
// pull_requests: write, so the token of one is never used for the other; a later entry
// for the same repository mints no new one.
func TestEachRepositoryIsMintedAToken(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	mints := w.pullMints()
	want := []string{
		`{"permissions":{"pull_requests":"write"},"repositories":["widgets"]}`,
		`{"permissions":{"pull_requests":"write"},"repositories":["gadgets"]}`,
	}
	if !slices.Equal(mints, want) {
		t.Errorf("mints %v, want %v", mints, want)
	}
	second := changeOf(testChangeID2, testTitle, "More text.", targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	if again := len(w.pullMints()); again != 2 {
		t.Errorf("%d mints after a later entry for the same repository, want 2", again)
	}
}

// TestAGitHubRateLimitIsRetriedAndAPlain403IsNotPermitted: a 403 with Retry-After, and a
// 403 whose message says rate limit, are waited out and sent again, so the draft opens
// and no failure report is sent; a plain 403 is not_permitted; a 403 for a rate limit
// that lasts is no refusal, so the entry stays and nothing is reported.
func TestAGitHubRateLimitIsRetriedAndAPlain403IsNotPermitted(t *testing.T) {
	const limited = `{"message":"You have exceeded a secondary rate limit."}`
	const plain = `{"message":"Resource not accessible by integration"}`
	for _, tc := range []struct {
		name   string
		header map[string]string
		body   string
		times  int // how many of the list's requests are answered 403; 0 for all
		want   string
	}{
		{"403 with Retry-After", map[string]string{"Retry-After": "7"}, plain, 2, "opened"},
		{"403 with a rate limit message", nil, limited, 2, "opened"},
		{"403 for a rate limit that lasts", map[string]string{"Retry-After": "7"}, plain, 0, "stays"},
		{"a plain 403", nil, plain, 0, "not_permitted"},
	} {
		w := newChangeWired(t)
		var slept []time.Duration
		w.adapter.pacers = map[int64]*github.Pacer{42: {Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }}}
		asked := 0
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.failHeader = tc.header
			f.pullFail = func(m, p string) (int, string) {
				if m == "GET" && p == "/repos/acme/widgets/pulls" {
					asked++
					if tc.times == 0 || asked <= tc.times {
						return 403, tc.body
					}
				}
				return 0, ""
			}
		})
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		err := w.feed.step(context.Background())
		switch tc.want {
		case "opened":
			if err != nil || !cursorIs(w, "c_1") || len(w.gh.pullRequests("acme/widgets")) != 1 || len(w.apiary.changeReports()) != 0 {
				t.Errorf("%s: err %v, reports %v", tc.name, err, w.apiary.changeReports())
			}
			if len(slept) < 2 {
				t.Errorf("%s: waited %v, want a wait after each refusal", tc.name, slept)
			}
		case "stays":
			if err == nil || IsPermanent(err) || !cursorIs(w, "") || len(w.apiary.changeReports()) != 0 {
				t.Errorf("%s: err %v, reports %v", tc.name, err, w.apiary.changeReports())
			}
		default:
			if err != nil || !cursorIs(w, "c_1") || !slices.Equal(w.apiary.changeReports(), []string{"acme/widgets not_permitted"}) || len(slept) != 0 {
				t.Errorf("%s: err %v, reports %v, waits %v", tc.name, err, w.apiary.changeReports(), slept)
			}
		}
	}
}

// TestACRLFBodyWithAMultiLineBlockIsKept: GitHub may store a description with CRLF line
// breaks, the block's text among them. The entry's text has LF breaks, so the new
// description differs from it by line breaks alone, which is no change: no write, and the
// action kept.
func TestACRLFBodyWithAMultiLineBlockIsKept(t *testing.T) {
	w := newChangeWired(t)
	text := "Line one.\nLine two.\n\nLine four."
	w.apiary.add(changeOf(testChangeID, testTitle, text, targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	crlf := "Dana above.\r\n" + strings.ReplaceAll(blockOf(text), "\n", "\r\n") + "\r\nDana below."
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = crlf })
	second := changeOf(testChangeID2, testTitle, text, targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	for _, c := range w.gh.pullCalls() {
		if strings.HasPrefix(c, "PATCH ") {
			t.Errorf("a write: %s", c)
		}
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "kept" {
		t.Errorf("the draft is %+v", d)
	}
	if got := w.gh.pullRequests("acme/widgets")[0].body; got != crlf {
		t.Errorf("the body changed to %q", got)
	}
}

// TestTheReplyTitleHasNoCharacterTheContractForbids: a person put invisible and
// bidirectional characters in the title on GitHub. The reply, which the fake Qory Apiary
// checks against the contract, has the title without them; the pull request keeps its
// title. A title of invisible characters alone is replaced by the run's title.
func TestTheReplyTitleHasNoCharacterTheContractForbids(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	const edited = "Fix\u200b the\u00ad widget\u202e\u0085"
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = edited })
	second := changeOf(testChangeID2, "Another title", "Second.", targetOf("acme/widgets", 2, update(1)))
	second = previously(second, testTitle)
	w.apiary.add(second)
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != "Fix the widget" {
		t.Errorf("the draft is %+v", d)
	}
	if got := w.gh.pullRequests("acme/widgets")[0].title; got != edited {
		t.Errorf("the pull request's title is %q, want it unchanged", got)
	}
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = "\u200b\u2060 \u00a0" })
	third := changeOf("av_0a0a0a0a0a0a0a0a", "A third title", "Third.", targetOf("acme/widgets", 3, update(1)))
	third = previously(third, "Another title")
	w.apiary.add(third)
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != "A third title" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAFailedReplyAfterTheDraftOpenedOpensNoSecondDraft: Qory Apiary answers the first
// reply 503, so the step fails with the cursor kept; the next step finds the draft by its
// head, opens no second one, and sends the reply, with the action kept.
func TestAFailedReplyAfterTheDraftOpenedOpensNoSecondDraft(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted && n == 1 {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if !cursorIs(w, "") || len(w.gh.pullRequests("acme/widgets")) != 1 {
		t.Fatal("the cursor moved, or the draft was not opened")
	}
	w.stepOK(t)
	if got := len(w.gh.pullRequests("acme/widgets")); got != 1 {
		t.Errorf("%d pull requests", got)
	}
	posts := 0
	for _, c := range w.gh.pullCalls() {
		if c == "POST /repos/acme/widgets/pulls" {
			posts++
		}
	}
	sent := w.apiary.sent(routeChangesSubmitted)
	if posts != 1 || len(sent) != 2 || !cursorIs(w, "c_1") {
		t.Errorf("%d posts, %d replies sent", posts, len(sent))
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "created" || d.Number != 1 {
		t.Errorf("the draft is %+v", d)
	}
	lists := 0
	for _, c := range w.gh.pullCalls() {
		if strings.HasPrefix(c, "GET /repos/acme/widgets/pulls?") {
			lists++
		}
	}
	if lists != 1 {
		t.Errorf("GitHub was asked %d times for the pull requests of the branch, want 1", lists)
	}
}

// TestARateLimitOnTheInstallationLookupIsRetriedAndAPlain403IsNotPermitted: GitHub's 403
// for a rate limit on the lookup of the repository's installation, which its headers say
// (Retry-After, or X-RateLimit-Remaining 0), is no refusal, so the entry stays and
// nothing is reported, and the next step opens the draft; a plain 403 on the lookup is
// reported not_permitted.
func TestARateLimitOnTheInstallationLookupIsRetriedAndAPlain403IsNotPermitted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  map[string]string
		message string
		retried bool
	}{
		{"Retry-After", map[string]string{"Retry-After": "60"}, "Forbidden", true},
		{"no request left", map[string]string{"X-RateLimit-Remaining": "0"}, "Forbidden", true},
		{"a request left", map[string]string{"X-RateLimit-Remaining": "4999"}, "Forbidden", false},
		{"no header", nil, "Resource not accessible by integration", false},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.failHeader = tc.header
			f.pullFail = func(m, p string) (int, string) {
				if m == "GET" && p == "/repos/acme/widgets/installation" {
					return 403, `{"message":"` + tc.message + `"}`
				}
				return 0, ""
			}
		})
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if !tc.retried {
			w.stepOK(t)
			if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets not_permitted"}) || !cursorIs(w, "c_1") {
				t.Errorf("%s: reports %v", tc.name, r)
			}
			continue
		}
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") || len(w.apiary.changeReports()) != 0 {
			t.Fatalf("%s: err %v, reports %v", tc.name, err, w.apiary.changeReports())
		}
		setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
		w.stepOK(t)
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "created" || !cursorIs(w, "c_1") {
			t.Errorf("%s: the draft is %+v", tc.name, d)
		}
	}
}

// TestAnUpdateOfAnEmptyDescriptionWritesTheBlockAlone: a pull request whose description
// is empty, which GitHub returns as null, gets the block alone, with no blank line before
// it and no other text; with CRLF in the run's text nothing else changes.
func TestAnUpdateOfAnEmptyDescriptionWritesTheBlockAlone(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 1, title: testTitle, draft: true})
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, update(1))))
	w.stepOK(t)
	if pulls := w.gh.pullRequests("acme/widgets"); len(pulls) != 1 || pulls[0].body != blockOf("Text.") || !strings.HasPrefix(pulls[0].body, "<!-- qory:start -->\n") {
		t.Errorf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "updated" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAReplyThatKeepsFailingEndsAsAFailureReport: Qory Apiary refuses the reply of an
// entry with a 503 for two days after the first failure; the draft exists, so the entry
// is applied once, and when its retries end it is reported unreachable, once, and
// passed.
func TestAReplyThatKeepsFailingEndsAsAFailureReport(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	for _, after := range []time.Duration{0, stuckFor, stuckFor - time.Second} {
		now = now.Add(after)
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") {
			t.Fatalf("after %v: err %v", after, err)
		}
	}
	if r := w.apiary.changeReports(); len(r) != 0 {
		t.Errorf("reported too early: %v", r)
	}
	now = now.Add(time.Second)
	w.stepOK(t)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets unreachable"}) || !cursorIs(w, endOf(w)) {
		t.Errorf("reports %v", r)
	}
	for _, repo := range []string{"acme/widgets"} {
		if got := len(w.gh.pullRequests(repo)); got != 1 {
			t.Errorf("%s: %d pull requests", repo, got)
		}
	}
	for n := range 1 {
		if d := detailOf(w, n); !strings.HasPrefix(d, github.FixReplyRefused+" ") || !strings.Contains(d, "503") {
			t.Errorf("the detail %d is %q", n, d)
		}
	}
}

// TestAReplyThatQoryApiaryRefusesIsLoggedAndTheEntryIsDone: a 400 for the reply is
// Permanent, as for every request; the entry is done, with no failure report, and the
// reply is not sent again.
func TestAReplyThatQoryApiaryRefusesIsLoggedAndTheEntryIsDone(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted {
			return http.StatusBadRequest, `{"error":"invalid_request"}`
		}
		return 0, ""
	}
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if !cursorIs(w, "c_1") || len(w.apiary.changeReports()) != 0 || len(w.apiary.sent(routeChangesSubmitted)) != 1 || !strings.Contains(w.log.String(), "the reply for a change request failed permanently") {
		t.Errorf("reports %v, log %s", w.apiary.changeReports(), w.log.String())
	}
}

// TestTheTitleOfThePullRequestInTheReplyIsCleaned: a pull request on GitHub whose title
// is nothing but invisible characters gets the run's title in the reply, and one whose
// title a person gave a stopped character gets the title without it. The pull request is
// not changed.
func TestTheTitleOfThePullRequestInTheReplyIsCleaned(t *testing.T) {
	for _, tc := range []struct{ name, onGitHub, want string }{
		{"invisible characters only", "\u200b\u2060", testTitle},
		{"a stopped character", "Fix\u200b the widget\U000E0041", "Fix the widget"},
		{"a ZWJ sequence stays", "Fix \U0001F468\u200d\U0001F469", "Fix \U0001F468\u200d\U0001F469"},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 1, title: tc.onGitHub, draft: true})
		})
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != tc.want {
			t.Errorf("%s: the draft is %+v", tc.name, d)
		}
		if pulls := w.gh.pullRequests("acme/widgets"); len(pulls) != 1 || pulls[0].title != tc.onGitHub {
			t.Errorf("%s: pull requests %+v", tc.name, pulls)
		}
	}
}

// TestATitleThatTheRuleStopsIsReportedRefusedBeforeAnyRequest: a title with a stopped
// character, or none that is not a space, ZWNJ or ZWJ, gets a failure report with the
// reason refused whose detail starts with the fix. Nothing is sent to GitHub, and no pull
// request is made. A title with a ZWJ emoji sequence is put on GitHub as it is.
func TestATitleThatTheRuleStopsIsReportedRefusedBeforeAnyRequest(t *testing.T) {
	for _, tc := range []struct{ name, title, fix string }{
		{"a right-to-left override", "Fix \u202e the widget", "Remove control, line-break or invisible format characters"},
		{"a tag letter", "Fix \U000E0041 the widget", "Remove control, line-break or invisible format characters"},
		{"a line break", "Fix\nthe widget", "Remove control, line-break or invisible format characters"},
		{"spaces only", "   ", "Give the title a character that is not a space"},
		{"ZWJ and ZWNJ only", "\u200d\u200c", "Give the title a character that is not a space"},
	} {
		w := newChangeWired(t)
		w.apiary.add(changeOf(testChangeID, tc.title, "Text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !cursorIs(w, "c_1") {
			t.Errorf("%s: reports %v", tc.name, r)
			continue
		}
		if d := detailOf(w, 0); !strings.HasPrefix(d, tc.fix) || strings.ContainsFunc(d, github.LineStopped) || len([]rune(strings.SplitN(d, ".", 2)[0]))+1 > 100 {
			t.Errorf("%s: the detail is %q", tc.name, d)
		}
		if calls := w.gh.pullCalls(); len(calls) != 0 || len(w.gh.pullRequests("acme/widgets")) != 0 || len(w.apiary.replies()) != 0 {
			t.Errorf("%s: GitHub calls %v, replies %v", tc.name, calls, w.apiary.replies())
		}
	}
	const emoji = "Fix \U0001F468\u200d\U0001F469 the widget"
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, emoji, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if pulls := w.gh.pullRequests("acme/widgets"); len(pulls) != 1 || pulls[0].title != emoji || len(w.apiary.changeReports()) != 0 {
		t.Errorf("pull requests %+v, reports %v", pulls, w.apiary.changeReports())
	}
}

// TestAStoppedCharacterInTheDataIsReportedRefusedBeforeAnyRequest: a character that the
// line rule of the pull-request type stops (U+202E, U+E0041, U+0007, U+2028), in the
// branch, the base branch, a step, or the collection of the head, the base or a commit,
// gives a failure report with the reason refused. The detail starts with the fix, names
// the code point, and has no stopped character, and no request reaches GitHub. U+200C and
// U+200D open a pull request.
func TestAStoppedCharacterInTheDataIsReportedRefusedBeforeAnyRequest(t *testing.T) {
	members := map[string]func(m map[string]any, v string){
		"data.branch":      func(m map[string]any, v string) { m["branch"] = "qory/a" + v },
		"data.base_branch": func(m map[string]any, v string) { m["base_branch"] = "a" + v },
		"the step of a step of data.steps": func(m map[string]any, v string) {
			m["steps"].([]any)[0].(map[string]any)["step"] = "a" + v
		},
		"the collection of data.head": func(m map[string]any, v string) { m["head"].(map[string]any)["collection"] = "a" + v },
		"the collection of data.base": func(m map[string]any, v string) { m["base"].(map[string]any)["collection"] = "a" + v },
		"the collection of a commit of data.commits": func(m map[string]any, v string) {
			m["commits"].([]any)[0].(map[string]any)["collection"] = "a" + v
		},
	}
	entry := func(edit func(m map[string]any, v string), v string) contracts.Change {
		target := targetOf("acme/widgets", 2, openDraft)
		ch := changeOf(testChangeID, testTitle, "Text.", target)
		var data map[string]any
		if err := json.Unmarshal(ch.Data, &data); err != nil {
			t.Fatal(err)
		}
		edit(data, v)
		ch.Data, _ = json.Marshal(data)
		return ch
	}
	for name, edit := range members {
		for _, c := range []struct{ value, code string }{{"\u202e", "U+202E"}, {"\U000E0041", "U+E0041"}, {"\u0007", "U+0007"}, {"\u2028", "U+2028"}} {
			w := newChangeWired(t)
			w.apiary.add(entry(edit, c.value))
			w.stepOK(t)
			if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !cursorIs(w, "c_1") {
				t.Errorf("%s with %s: reports %v", name, c.code, r)
				continue
			}
			if d := detailOf(w, 0); !strings.HasPrefix(d, github.FixChangeData+" ") || !strings.Contains(d, name+" has "+c.code) || strings.ContainsFunc(d, github.LineStopped) || len([]rune(strings.SplitN(d, ".", 2)[0]))+1 > 100 {
				t.Errorf("%s with %s: the detail is %q", name, c.code, d)
			}
			if calls := w.gh.pullCalls(); len(calls) != 0 || len(w.apiary.replies()) != 0 {
				t.Errorf("%s with %s: GitHub calls %v, replies %v", name, c.code, calls, w.apiary.replies())
			}
		}
		for _, joiner := range []string{"\u200c", "\u200d"} {
			w := newChangeWired(t)
			w.apiary.add(entry(edit, joiner))
			w.stepOK(t)
			if r := w.apiary.changeReports(); len(r) != 0 || len(w.apiary.replies()) != 1 {
				t.Errorf("%s with U+%04X: reports %v", name, []rune(joiner)[0], r)
			}
		}
	}
}

// TestATextWithAMarkerLineIsReportedRefusedBeforeAnyRequest: the adapter writes the text
// between marker lines, so a text with one gets a failure report with the reason refused
// and a detail that starts with the fix. Nothing is sent to GitHub.
func TestATextWithAMarkerLineIsReportedRefusedBeforeAnyRequest(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.\n<!-- qory:end -->\nMore.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !cursorIs(w, "c_1") {
		t.Fatalf("reports %v", r)
	}
	if d := detailOf(w, 0); !strings.HasPrefix(d, "Remove the lines that mark a qory block (qory:start and qory:end) from the text") {
		t.Errorf("the detail is %q", d)
	}
	if calls := w.gh.pullCalls(); len(calls) != 0 || len(w.gh.pullRequests("acme/widgets")) != 0 {
		t.Errorf("GitHub calls %v", calls)
	}
}

// TestThePullRequestBodyHasOneBlockOfMarkerLines: the body of a pull request that the
// adapter opens is the start marker, the text, and the end marker, so a text without a
// marker line makes the one block.
func TestThePullRequestBodyHasOneBlockOfMarkerLines(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].body != "<!-- qory:start -->\nText.\n<!-- qory:end -->" {
		t.Fatalf("pull requests %+v", pulls)
	}
}

// pullCallsOf are the requests for pull requests that w made since from, each as METHOD
// and the path, with the listing of the branch's pull requests written as LIST.
func pullCallsOf(w *wired, from int) []string {
	var out []string
	for _, c := range w.gh.pullCalls()[from:] {
		method, uri, _ := strings.Cut(c, " ")
		if strings.Contains(uri, "?head=") {
			out = append(out, "LIST")
			continue
		}
		out = append(out, method+" "+strings.TrimPrefix(uri, "/repos/acme/widgets/pulls"))
	}
	return out
}

// withAddress is the entry ch with a previous version whose address has the ref ref, and
// no title.
func withAddress(ch contracts.Change, ref string) contracts.Change {
	ch.Previous = &contracts.ChangePrevious{Address: &contracts.ChangeAddress{URL: "https://" + testHost + "/acme/widgets/pull/" + ref, Ref: ref}}
	return ch
}

// TestTheDraftIsFoundAtThePreviousAddress: an update entry whose previous address has the
// ref "7" edits pull request 7, whatever other pull requests the branch has: GitHub is
// asked for pull request 7, and for no listing, and one request writes it. The reply has
// the address of pull request 7 and the action updated.
func TestTheDraftIsFoundAtThePreviousAddress(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls,
			&ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 3, title: "Three", draft: true},
			&ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 7, title: "Seven", draft: true},
			&ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 9, title: "Nine", draft: true})
	})
	w.apiary.add(changeOf(testChangeID, "Seven", "New text.", targetOf("acme/widgets", 1, update(7))))
	w.stepOK(t)
	if got, want := pullCallsOf(w, 0)[len(pullCallsOf(w, 0))-2:], []string{"GET /7", "PATCH /7"}; !slices.Equal(got, want) || slices.Contains(pullCallsOf(w, 0), "LIST") {
		t.Errorf("the calls are %v", pullCallsOf(w, 0))
	}
	d := w.apiary.draftsReplied()["acme/widgets"]
	if d == nil || d.Number != 7 || d.Action != "updated" || d.URL != "https://github.com/acme/widgets/pull/7" {
		t.Errorf("the draft is %+v", d)
	}
	if pulls := w.gh.pullRequests("acme/widgets"); pulls[1].body != blockOf("New text.") || pulls[0].body != "" || pulls[2].body != "" {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestADraftWithoutAUsableAddressIsFoundByItsBranch: an entry with no previous address,
// or whose ref is no pull request number as the reply writes it (empty, 0, 007, +7, a
// word, a number past int64), finds the pull request by its head branch: GitHub is asked
// for the listing, and for no pull request by number first, and the open pull request
// with the highest number is edited.
func TestADraftWithoutAUsableAddressIsFoundByItsBranch(t *testing.T) {
	for _, ref := range []string{"-", "", "0", "007", "+7", "seven", "-3", "9223372036854775808", "1.0", " 7"} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pulls = append(f.pulls,
				&ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 7, title: "Seven", draft: true},
				&ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 8, title: "Eight", draft: true})
		})
		ch := changeOf(testChangeID, "Eight", "New text.", targetOf("acme/widgets", 1, openDraft))
		if ref != "-" {
			ch = withAddress(ch, ref)
		}
		w.apiary.add(ch)
		w.stepOK(t)
		calls := pullCallsOf(w, 0)
		if i := slices.Index(calls, "LIST"); i < 0 || slices.Contains(calls, "GET /7") || slices.Contains(calls, "POST ") || len(w.apiary.changeReports()) != 0 {
			t.Errorf("ref %q: the calls are %v, reports %v", ref, calls, w.apiary.changeReports())
		}
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 8 || d.Action != "updated" {
			t.Errorf("ref %q: the draft is %+v", ref, d)
		}
	}
}

// TestAPullRequestThatIsGoneOpensANewOne: the previous address has the ref "7", and
// GitHub has no pull request 7 and none from the branch: GitHub is asked for pull request
// 7, then for the listing, and a pull request is opened. With no address, and none from
// the branch, the listing and the opening are the only requests.
func TestAPullRequestThatIsGoneOpensANewOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		draft *draftAsk
		calls []string
	}{
		{"a pull request 7 that is gone", update(7), []string{"GET /7", "LIST", "POST "}},
		{"no address and no pull request from the branch", openDraft, []string{"LIST", "POST "}},
	} {
		w := newChangeWired(t)
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, tc.draft)))
		w.stepOK(t)
		calls := pullCallsOf(w, 0)
		if got := calls[len(calls)-len(tc.calls):]; !slices.Equal(got, tc.calls) {
			t.Errorf("%s: the calls are %v", tc.name, calls)
		}
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 1 || d.Action != "created" || len(w.apiary.changeReports()) != 0 {
			t.Errorf("%s: the draft is %+v", tc.name, d)
		}
	}
}

// TestAPullRequestAtTheAddressThatAPersonFinishedIsKept: the previous address has the ref
// "7", and pull request 7 is closed on GitHub: nothing is written, GitHub is asked for
// pull request 7 alone, and the reply has the action kept and the state closed.
func TestAPullRequestAtTheAddressThatAPersonFinishedIsKept(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 7, title: "Seven", closed: true})
	})
	w.apiary.add(changeOf(testChangeID, "Seven", "New text.", targetOf("acme/widgets", 1, update(7))))
	w.stepOK(t)
	calls := pullCallsOf(w, 0)
	if slices.Contains(calls, "PATCH /7") || slices.Contains(calls, "LIST") || slices.Contains(calls, "POST ") {
		t.Errorf("the calls are %v", calls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 7 || d.Action != "kept" || d.State != "closed" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAnUpdateKeepsWhetherThePullRequestIsADraft: the data of an update has draft false,
// and pull request 7 is a draft: the update changes the text and leaves it a draft.
func TestAnUpdateKeepsWhetherThePullRequestIsADraft(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 7, title: "Seven", draft: true})
	})
	target := targetOf("acme/widgets", 1, update(7))
	target.ready = true
	w.apiary.add(changeOf(testChangeID, "Seven", "New text.", target))
	w.stepOK(t)
	if pulls := w.gh.pullRequests("acme/widgets"); len(pulls) != 1 || !pulls[0].draft || pulls[0].body != blockOf("New text.") {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestAnEntryWithTheMostCommitsThatTheContractAllowsIsApplied: the contract bounds the
// data of an entry (README, "data": at most 786432 bytes and arrays of at most 1024
// items, which the control plane enforces), and the adapter sets no cap on the number of
// commits. An entry with 1024 commits is applied, and its reply, 1024 commit addresses
// with the pull request, is smaller than contracts.MaxRequest, the most that the adapter
// sends.
func TestAnEntryWithTheMostCommitsThatTheContractAllowsIsApplied(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1024, openDraft)))
	w.stepOK(t)
	replies := w.apiary.replies()
	if len(replies) != 1 || len(w.apiary.changeReports()) != 0 {
		t.Fatalf("replies %d, reports %v", len(replies), w.apiary.changeReports())
	}
	if r := replyData(replies[0]); len(r.Commits) != 1024 {
		t.Errorf("the reply has %d commits", len(r.Commits))
	}
	if n := len(w.apiary.sent(routeChangesSubmitted)[0].raw); n >= contracts.MaxRequest {
		t.Errorf("the reply is %d bytes, over %d", n, contracts.MaxRequest)
	}
}

// TestTheReplyHasTheAddressesOfTheCommitsListNotOfHeadOrEarlierCommits: an entry whose
// head is another commit than the last of commits, and that has earlier_commits, is
// applied; the reply has the address of the base commit and of each commit of commits, in
// order.
func TestTheReplyHasTheAddressesOfTheCommitsListNotOfHeadOrEarlierCommits(t *testing.T) {
	w := newChangeWired(t)
	target := targetOf("acme/widgets", 3, openDraft)
	ch := changeOf(testChangeID, testTitle, "Text.", target)
	var data map[string]any
	if err := json.Unmarshal(ch.Data, &data); err != nil {
		t.Fatal(err)
	}
	data["head"], data["earlier_commits"] = target.commitRef(sha(99)), 7
	ch.Data, _ = json.Marshal(data)
	w.apiary.add(ch)
	w.stepOK(t)
	replies := w.apiary.replies()
	if len(replies) != 1 || len(w.apiary.changeReports()) != 0 {
		t.Fatalf("replies %+v, reports %v", replies, w.apiary.changeReports())
	}
	r := replyData(replies[0])
	if r.Base.Commit != sha(1) || len(r.Commits) != 3 || r.Commits[0].Commit != sha(2) || r.Commits[2].Commit != sha(4) {
		t.Errorf("the reply is %+v", r)
	}
}

// failAt makes the stand-in GitHub answer the request method path with status and body.
func failAt(method, path string, status int, body string) func(f *fakeGitHub) {
	return func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			if m == method && p == path {
				return status, body
			}
			return 0, ""
		}
	}
}

// runPastRetries steps the feed once, moves the clock on by the limit of the entry's
// retries and steps again, which must pass the entry.
func runPastRetries(t *testing.T, w *wired) {
	t.Helper()
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") {
		t.Fatalf("the first step: err %v", err)
	}
	if len(w.apiary.changeReports()) != 0 {
		t.Fatalf("reported before the retries ended: %v", w.apiary.changeReports())
	}
	now = now.Add(stuckFor)
	w.stepOK(t)
	if !cursorIs(w, endOf(w)) {
		t.Fatal("the cursor did not move")
	}
}

// TestACancelledContextKeepsAnEntryWhoseRetriesEnded: the retries of an entry have ended,
// and the step that would report it is cancelled. The step returns the cancellation, sends
// no report, and keeps the entry and its cursor; the next step reports it once.
func TestACancelledContextKeepsAnEntryWhoseRetriesEnded(t *testing.T) {
	w := newChangeWired(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := false
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullMint = func() (int, string) {
			if cancelling {
				cancel()
			}
			return 502, `{"message":"Bad Gateway"}`
		}
	})
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	if err := w.feed.step(context.Background()); err == nil {
		t.Fatal("the first step did not fail")
	}
	now = now.Add(3 * stuckFor)
	cancelling = true
	if err := w.feed.step(ctx); err == nil {
		t.Error("the cancelled step did not fail")
	}
	if r := w.apiary.changeReports(); len(r) != 0 || !cursorIs(w, "") {
		t.Fatalf("reports %v, cursor moved: %v", r, !cursorIs(w, ""))
	}
	cancelling = false
	w.stepOK(t)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets unreachable"}) || !cursorIs(w, "c_1") {
		t.Errorf("reports %v", r)
	}
}

// detailOf is the detail of the failure report n of the change_request entries.
func detailOf(w *wired, n int) string {
	d, _ := w.apiary.sent(routeChangesFailed)[n].body["detail"].(string)
	return d
}

// TestADraftNumberOfAnotherBranchOrAForkIsNotTheDraft: the number of an update names a
// pull request of another head branch, or one from a fork with the same branch name: it is
// edited by neither, the branch's pull request is, and the reply has that one's number.
func TestADraftNumberOfAnotherBranchOrAForkIsNotTheDraft(t *testing.T) {
	for _, tc := range []struct {
		name  string
		other *ghPullRec
	}{
		{"another head branch", &ghPullRec{repo: "acme/widgets", head: "feature/other", base: "main", number: 1, title: "Other", body: "Other text.", draft: true}},
		{"a fork's branch of the same name", &ghPullRec{repo: "acme/widgets", headRepo: "acme/widgets-fork", head: testBranch, base: "main", number: 1, title: "Fork", body: "Fork text.", draft: true}},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pulls = append(f.pulls, tc.other, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 2, title: testTitle, draft: true})
		})
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, update(1))))
		w.stepOK(t)
		pulls := w.gh.pullRequests("acme/widgets")
		if len(pulls) != 2 || pulls[0].title != tc.other.title || pulls[0].body != tc.other.body || pulls[1].body != blockOf("Text.") {
			t.Errorf("%s: pull requests %+v", tc.name, pulls)
		}
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 2 || d.Action != "updated" {
			t.Errorf("%s: the draft is %+v", tc.name, d)
		}
	}
}

// TestNoTextOfAnErrorHasTheTokenOrALineBreak: GitHub answers with a message that has the
// installation token, whole and split by a line break, and a line break: with a 400, which
// is reported, and with a 502, which is tried again. The error's text, the log and the
// failure report have no token and no line break.
func TestNoTextOfAnErrorHasTheTokenOrALineBreak(t *testing.T) {
	split := ghToken[:9] + "\r\n" + ghToken[9:]
	message := "echo " + ghToken + " and\n" + split + "\nend"
	body, err := json.Marshal(map[string]any{"message": message})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{400, 502} {
		w := newChangeWired(t)
		setGitHub(w.gh, failAt("POST", "/repos/acme/widgets/pulls", status, string(body)))
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		stepErr := w.feed.step(context.Background())
		texts := []string{w.log.String()}
		if status == 400 {
			texts = append(texts, detailOf(w, 0))
			if stepErr != nil {
				t.Errorf("%d: step %v", status, stepErr)
			}
		} else {
			if stepErr == nil {
				t.Fatalf("%d: no error", status)
			}
			texts = append(texts, stepErr.Error())
		}
		for _, text := range texts {
			if strings.Contains(text, ghToken) || strings.Contains(text, ghToken[:9]) && strings.Contains(text, ghToken[9:]) {
				t.Errorf("%d: a text has the token: %s", status, text)
			}
		}
		if status == 502 && strings.ContainsAny(stepErr.Error(), "\r\n") {
			t.Errorf("%d: the error has a line break: %q", status, stepErr.Error())
		}
	}
}

// TestTheErrorOfTheInstallationLookupHasNoCredentialOrLineBreak: GitHub's message to the
// lookup of the installation has a signed token and a line break; the error of the step
// has neither.
func TestTheErrorOfTheInstallationLookupHasNoCredentialOrLineBreak(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, failAt("GET", "/repos/acme/widgets/installation", 502, `{"message":"first\njwt eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0In0.c2lnbmF0dXJl end"}`))
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	err := w.feed.step(context.Background())
	if err == nil || strings.Contains(err.Error(), "eyJ") || strings.ContainsAny(err.Error(), "\r\n") || !strings.Contains(err.Error(), "first jwt [removed] end") {
		t.Errorf("err %v", err)
	}
}

// TestWhenTheRetriesEndEachEntryIsReportedByItsLastCause: the first entry of a version
// fails with 502, the second with a 422 that says a pull request exists though none is
// found, so each is tried again; at the end the first is unreachable and the second
// refused, with GitHub's message in its detail, not the first's.
func TestWhenTheRetriesEndEachEntryIsReportedByItsLastCause(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			switch {
			case m == "POST" && p == "/repos/acme/widgets/pulls":
				return 502, `{"message":"Bad Gateway"}`
			case m == "POST" && p == "/repos/acme/gadgets/pulls":
				return 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"A pull request already exists for acme:qory/wi_42."}]}`
			}
			return 0, ""
		}
	})
	// A sync entry applies, so the step is not one where every entry fails, see [feed.step].
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/gadgets", 1, openDraft)), contracts.Change{Kind: contracts.ChangeSync})
	runPastRetries(t, w)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets unreachable", "acme/gadgets refused"}) {
		t.Fatalf("reports %v", r)
	}
	if d := detailOf(w, 0); !strings.HasSuffix(d, "GitHub returned 502: Bad Gateway") {
		t.Errorf("the first detail is %q", d)
	}
	if d := detailOf(w, 1); !strings.Contains(d, "GitHub returned 422: Validation Failed; PullRequest custom A pull request already exists") || strings.Contains(d, "502") {
		t.Errorf("the second detail is %q", d)
	}
}

// TestACauseThatKeepsComingEndsAsItsReason: each case fails on every try, not for good, so
// the entry is applied again until its retries end, then reported with the reason of its
// last error: a 401 that never stops is not_permitted, an answer that is no JSON is
// refused with a detail that says so, a 4xx from the installation lookup is
// refused at once, and only 5xx, a rate limit and a timeout are unreachable.
func TestACauseThatKeepsComingEndsAsItsReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(f *fakeGitHub)
		now    bool // reported at once, not after the retries
		reason string
		detail string
	}{
		{"401 on the pull requests", failAt("GET", "/repos/acme/widgets/pulls", 401, `{"message":"Bad credentials"}`), false, "not_permitted", github.FixTokenRefused + " GitHub returned 401: Bad credentials"},
		{"401 on the installation lookup", failAt("GET", "/repos/acme/widgets/installation", 401, `{"message":"A JSON web token could not be decoded"}`), false, "not_permitted", github.FixTokenRefused + " GitHub returned 401: A JSON web token could not be decoded"},
		{"an answer that is no JSON", failAt("GET", "/repos/acme/widgets/pulls", 200, `<html>Unicorn</html>`), false, "refused", "Report to the maintainers of qory-github that GitHub's answer could not be read. GitHub returned 200."},
		{"400 on the installation lookup", failAt("GET", "/repos/acme/widgets/installation", 400, `{"message":"Bad Request"}`), true, "refused", github.FixForgeRefused + " GitHub returned 400: Bad Request"},
		{"422 on the installation lookup", failAt("GET", "/repos/acme/widgets/installation", 422, `{"message":"Validation Failed"}`), true, "refused", github.FixForgeRefused + " GitHub returned 422: Validation Failed"},
		{"502", failAt("GET", "/repos/acme/widgets/pulls", 502, `{"message":"Bad Gateway"}`), false, "unreachable", github.FixUnreachable + " GitHub returned 502: Bad Gateway"},
		{"408", failAt("GET", "/repos/acme/widgets/pulls", 408, `{"message":"Request Timeout"}`), false, "unreachable", github.FixUnreachable + " GitHub returned 408: Request Timeout"},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, tc.set)
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if tc.now {
			w.stepOK(t)
		} else {
			runPastRetries(t, w)
		}
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets " + tc.reason}) || detailOf(w, 0) != tc.detail {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
	}
}

// TestAMintThatKeepsFailingEndsAsItsReason: the mint of the token for pull requests fails
// on every try, so the entry is applied again until its retries end, then reported by the
// last answer: a 403 that is no rate limit is not_permitted, a 403 that says rate limit,
// a 429 and a 503 are unreachable, a redirect is refused, and an answer with no
// token or with an expiry that is no time is refused with the detail that says the answer's
// status.
func TestAMintThatKeepsFailingEndsAsItsReason(t *testing.T) {
	const unreadable = "Report to the maintainers of qory-github that GitHub's answer could not be read. GitHub returned 201."
	for _, tc := range []struct {
		name   string
		status int
		body   string
		reason string
		detail string
	}{
		{"403", 403, `{"message":"Resource not accessible by integration"}`, "not_permitted", github.FixPermission + " GitHub returned 403: Resource not accessible by integration"},
		{"403 with a rate limit", 403, `{"message":"You have exceeded a secondary rate limit."}`, "unreachable", github.FixUnreachable + " GitHub returned 403: You have exceeded a secondary rate limit."},
		{"429", 429, `{"message":"Too Many Requests"}`, "unreachable", github.FixUnreachable + " GitHub returned 429: Too Many Requests"},
		{"503", 503, `{"message":"Service Unavailable"}`, "unreachable", github.FixUnreachable + " GitHub returned 503: Service Unavailable"},
		{"a redirect", 302, `{"message":"Found"}`, "refused", github.FixForgeRefused},
		{"no token", 201, `{"expires_at":"2099-01-01T00:00:00Z"}`, "refused", unreadable},
		{"an expiry that is no time", 201, `{"token":"` + ghToken + `","expires_at":"tomorrow"}`, "refused", unreadable},
		{"no JSON", 201, `<html>Unicorn</html>`, "refused", unreadable},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, func(f *fakeGitHub) { f.pullMint = func() (int, string) { return tc.status, tc.body } })
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		runPastRetries(t, w)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets " + tc.reason}) || detailOf(w, 0) != tc.detail {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
		if strings.Contains(w.log.String(), ghToken) {
			t.Errorf("%s: the log has the token", tc.name)
		}
	}
}

// TestADraftIsOpenedForARenamedRepositoryFoundByItsCollection: the entry's address has the
// repository's old name, acme/widgets, and its collection is the repository's id, which
// GitHub now answers as acme/sprockets. The draft is opened in acme/sprockets, nothing
// is asked of acme/widgets, and the reply echoes the entry's target.
func TestADraftIsOpenedForARenamedRepositoryFoundByItsCollection(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.widgetsName = "acme/sprockets" })
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	w.apiary.add(entry)
	w.stepOK(t)
	if got := len(w.gh.pullRequests("acme/sprockets")); got != 1 {
		t.Errorf("%d pull requests in acme/sprockets", got)
	}
	for _, c := range w.gh.pullCalls() {
		if strings.Contains(c, "/repos/acme/widgets") {
			t.Errorf("the old name was asked for: %s", c)
		}
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || !reflect.DeepEqual(replies[0].Target, *entry.Target) || replies[0].Address == nil || replies[0].Action != "created" {
		t.Errorf("replies %+v", replies)
	}
	if r := replyData(replies[0]); r.Base.CommitURL != "https://github.com/acme/sprockets/commit/"+sha(1) {
		t.Errorf("the commit address is %q", r.Base.CommitURL)
	}
	if len(w.apiary.changeReports()) != 0 || !cursorIs(w, "c_1") {
		t.Errorf("reports %v", w.apiary.changeReports())
	}
}

// TestATargetWithNoAddressIsFoundByItsCollection: an entry whose target has the
// collection alone gets its draft.
func TestATargetWithNoAddressIsFoundByItsCollection(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	entry.Target.Address = nil
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	replies := w.apiary.replies()
	if len(replies) != 1 || replies[0].Target.Address != nil || replies[0].Action != "created" || len(w.gh.pullRequests("acme/widgets")) != 1 {
		t.Errorf("replies %+v", replies)
	}
}

// TestARepositoryThatCannotBeReadIsReportedByWhatGitHubReturns: each case ends the entry
// with a failure report of its reason, whose detail starts with its fix, and no request
// for pull requests: no installation reaches the repository, the installation is
// suspended, the mint is refused, GitHub returns 403, 404, 410, 301, 308 or 400 for the
// read. The fix for 301 and 308 is the same check as for 404: the read is by id, so it has
// no new name to link.
func TestARepositoryThatCannotBeReadIsReportedByWhatGitHubReturns(t *testing.T) {
	status := func(n int) func(w *wired) {
		return func(w *wired) { setGitHub(w.gh, func(f *fakeGitHub) { f.readStatus = n }) }
	}
	for _, tc := range []struct {
		name, want, fix string
		set             func(w *wired)
	}{
		{"no installation reaches it", "not_permitted", github.FixNotInstalled, func(w *wired) { w.st.Delete(nsRepositories, collectionKey(widgetsRef)) }},
		{"the installation is suspended", "not_permitted", github.FixSuspended, func(w *wired) { setGitHub(w.gh, func(f *fakeGitHub) { f.installSuspended = true }) }},
		{"the mint is refused", "not_permitted", github.FixPermission, func(w *wired) {
			setGitHub(w.gh, func(f *fakeGitHub) { f.refused = []int64{repoID("acme/widgets")} })
		}},
		{"403", "not_permitted", github.FixAppForbidden, status(403)},
		{"404", "target_gone", github.FixGone, status(404)},
		{"410", "target_gone", github.FixGone, status(410)},
		{"301", "target_gone", github.FixGone, status(301)},
		{"308", "target_gone", github.FixGone, status(308)},
		{"400", "refused", github.FixForgeRefused, status(400)},
	} {
		w := newChangeWired(t)
		tc.set(w)
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets " + tc.want}) || !strings.HasPrefix(detailOf(w, 0), tc.fix) || len(w.gh.pullCalls()) != 0 || len(w.apiary.replies()) != 0 {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
	}
}

// TestAServerErrorOnTheReadOfTheRepositoryIsRetried: a 502 for the read fails the step with
// no report, no reply and the cursor where it was; the entry is applied when the read
// passes.
func TestAServerErrorOnTheReadOfTheRepositoryIsRetried(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.readStatus = 502 })
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") || len(w.apiary.changeReports()) != 0 {
		t.Fatalf("err %v", err)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.readStatus = 0 })
	w.stepOK(t)
	if r := w.apiary.replies(); len(r) != 1 || len(w.apiary.changeReports()) != 0 {
		t.Errorf("replies %+v", r)
	}
}

// TestACollectionThatIsNoRepositoryIDIsPermanent: checkTarget refuses it before any
// request, as applyChangeRequest does for an entry.
func TestACollectionThatIsNoRepositoryIDIsPermanent(t *testing.T) {
	w := newChangeWired(t)
	ch := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	ch.Target.Collection = "acme/widgets"
	if _, err := w.adapter.checkTarget(ch, ""); err == nil || !IsPermanent(err) || len(w.gh.requests) != 0 {
		t.Errorf("err %v, %d requests", err, len(w.gh.requests))
	}
}

// TestAnEntryOfAKindTheAdapterDoesNotApplyIsRefused: an entry of the kind reply is
// reported with the reason refused and a detail that starts with the fix, no request
// goes to GitHub, and the cursor moves.
func TestAnEntryOfAKindTheAdapterDoesNotApplyIsRefused(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	entry.ChangeKind = "reply"
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	detail := detailOf(w, 0)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !strings.HasPrefix(detail, github.FixChangeKind+" ") || !strings.Contains(detail, `the kind "reply"`) || utf8.RuneCountInString(github.FixChangeKind) > 100 {
		t.Errorf("reports %v, detail %q", r, detail)
	}
	if len(w.gh.requests) != 0 || len(w.apiary.replies()) != 0 || !cursorIs(w, "c_1") {
		t.Errorf("GitHub was asked %v, replies %+v", w.gh.requests, w.apiary.replies())
	}
}

// TestDataThatBreaksARuleOfTheKindIsRefused: a branch with a space is reported with the
// reason refused and the fix for the data first, before any request to GitHub.
func TestDataThatBreaksARuleOfTheKindIsRefused(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
	entry.Data = json.RawMessage(strings.Replace(string(entry.Data), testBranch, "qory/wi 42", 1))
	w.apiary.add(entry)
	w.stepOK(t)
	detail := detailOf(w, 0)
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !strings.HasPrefix(detail, github.FixChangeData+" data.branch") {
		t.Errorf("reports %v, detail %q", r, detail)
	}
	if len(w.gh.requests) != 0 || !cursorIs(w, "c_1") {
		t.Errorf("GitHub was asked %v", w.gh.requests)
	}
}

// TestAnAddressThatIsNotOwnerSlashNameIsPassed: an address path of another shape is logged
// and passed, with no report, no reply and no request.
func TestAnAddressThatIsNotOwnerSlashNameIsPassed(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets/extra", 1, openDraft)))
	w.stepOK(t)
	if len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.apiary.replies()) != 0 || len(w.gh.requests) != 0 || !strings.Contains(w.log.String(), "the address's path is not owner/name") {
		t.Errorf("the entry was not passed quietly: %s", w.log.String())
	}
}

// TestAPullRequestEntryWithAnotherAddressAndBadDataIsPassed: the address is checked before
// the data and the title, so an entry whose address system or path is wrong is logged and
// passed, with no report, whatever else it has wrong.
func TestAPullRequestEntryWithAnotherAddressAndBadDataIsPassed(t *testing.T) {
	for _, tc := range []struct{ name, system, path, want string }{
		{"another system", "gitlab.example.com", "acme/widgets", "the address's system is not GitHub's host"},
		{"another path", testHost, "acme/widgets/extra", "the address's path is not owner/name"},
	} {
		w := newChangeWired(t)
		target := targetOf(tc.path, 1, openDraft)
		target.system = tc.system
		entry := changeOf(testChangeID, "   ", "Text.", target)
		entry.Target.Collection = refOf("acme/widgets")
		entry.Data = json.RawMessage(strings.Replace(string(entry.Data), testBranch, "qory/wi 42", 1))
		w.apiary.add(entry)
		w.stepOK(t)
		if len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.apiary.replies()) != 0 || len(w.gh.requests) != 0 || !cursorIs(w, "c_1") || !strings.Contains(w.log.String(), tc.want) {
			t.Errorf("%s: the entry was not passed quietly: %s", tc.name, w.log.String())
		}
	}
}

// TestAnEntryOfAnotherKindIsRefusedWhateverItsCollection: the kind is checked first, so an
// entry of the kind reply is reported with the reason refused and the fix for the kind,
// also when its collection is no repository's id or its address is of another system.
func TestAnEntryOfAnotherKindIsRefusedWhateverItsCollection(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(ch *contracts.Change)
	}{
		{"a collection that is no repository's id", func(ch *contracts.Change) { ch.Target.Collection = "R_1001"; ch.Target.Address = nil }},
		{"an address of another system", func(ch *contracts.Change) { ch.Target.Address.System = "gitlab.example.com" }},
	} {
		w := newChangeWired(t)
		entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft))
		entry.ChangeKind = "reply"
		tc.edit(&entry)
		w.apiary.add(entry)
		w.stepOK(t)
		reports := w.apiary.sent(routeChangesFailed)
		if len(reports) != 1 || reports[0].body["reason"] != "refused" || !strings.HasPrefix(detailOf(w, 0), github.FixChangeKind+" ") || len(w.gh.requests) != 0 || !cursorIs(w, "c_1") {
			t.Errorf("%s: reports %+v, detail %q", tc.name, reports, detailOf(w, 0))
		}
	}
}

// TestAStoreEntryThatIsNoReachFailsTheStepWithoutAReport: a store entry for the repository
// that is not an installation's reach is an error that a retry may change: the step fails,
// no report or reply is sent, and the cursor stays.
func TestAStoreEntryThatIsNoReachFailsTheStepWithoutAReport(t *testing.T) {
	w := newChangeWired(t)
	if err := w.st.Put(nsRepositories, collectionKey(widgetsRef), []byte("not json"), 0); err != nil {
		t.Fatal(err)
	}
	w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	err := w.feed.step(context.Background())
	if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "the store's entry for a repository is not one") {
		t.Fatalf("err %v", err)
	}
	if len(w.apiary.changeReports()) != 0 || len(w.apiary.replies()) != 0 || len(w.gh.requests) != 0 || !cursorIs(w, "") {
		t.Errorf("a report or reply was sent, or the cursor moved")
	}
}

// TestACancelledContextAppliesNoChangeRequest: changeRequest returns the context's error
// before it applies the entry, so no request is sent and the entry keeps no state.
func TestACancelledContextAppliesNoChangeRequest(t *testing.T) {
	w := newChangeWired(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := &entryState{}
	err := w.feed.changeRequest(ctx, state, changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	if !errors.Is(err, context.Canceled) || len(w.gh.requests) != 0 || state.applied.done || state.applied.reply != nil || state.applied.cause != nil {
		t.Errorf("err %v, %d requests, state %+v", err, len(w.gh.requests), state.applied)
	}
}

// TestAMintForPullRequestsThatIsRefusedOrSuspendedIsNotPermitted: the read of the repository
// passes, then the mint of the token for pull requests fails for good, as GitHub answers
// 422 for permissions the App has not, or the installation is suspended in between: the
// entry is reported as not_permitted with the fix first, and no pull request is opened.
func TestAMintForPullRequestsThatIsRefusedOrSuspendedIsNotPermitted(t *testing.T) {
	for _, tc := range []struct {
		name string
		fix  string
		set  func(f *fakeGitHub)
	}{
		{"the mint is refused", github.FixPermission, func(f *fakeGitHub) {
			f.pullMint = func() (int, string) { return 422, `{"message":"Validation Failed"}` }
		}},
		{"the installation is suspended after the read", github.FixSuspended, func(f *fakeGitHub) {
			f.pullFail = func(method, path string) (int, string) {
				if strings.HasSuffix(path, "/installation") {
					f.installSuspended = true
				}
				return 0, ""
			}
		}},
	} {
		w := newChangeWired(t)
		setGitHub(w.gh, tc.set)
		w.apiary.add(changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets not_permitted"}) || !strings.HasPrefix(detailOf(w, 0), tc.fix) || len(w.gh.pullRequests("acme/widgets")) != 0 || len(w.apiary.replies()) != 0 {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
	}
}
