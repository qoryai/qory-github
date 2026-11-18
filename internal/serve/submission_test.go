package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
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
	testSubmissionID  = "av_0123456789abcdef"
	testSubmissionID2 = "av_fedcba9876543210"
	testBranch        = "qory/wi_42"
	testTitle         = "Fix the widget"
)

// sha is the commit id the tests give commit n: 40 hexadecimal digits.
func sha(n int) string { return fmt.Sprintf("%040x", n) }

// targetOf is the target of a submission entry for the repository path: the branch the
// run pushed, a base at sha(1) on main, and commits commits, sha(2) on; with draft, the
// target asks for it.
func targetOf(path string, commits int, draft *contracts.DraftRequest) contracts.SubmissionTarget {
	t := contracts.SubmissionTarget{
		System: githubSystem, Path: path, Branch: testBranch, Base: contracts.SubmissionBase{Commit: sha(1), Branch: "main"},
		Commit: sha(1 + commits), Draft: draft,
	}
	for i := range commits {
		t.Commits = append(t.Commits, contracts.SubmissionCommit{Commit: sha(2 + i), Step: "deliverable:d-" + fmt.Sprint(i+1)})
	}
	return t
}

var (
	openDraft = &contracts.DraftRequest{Action: contracts.DraftOpen}
	update    = func(n int) *contracts.DraftRequest {
		return &contracts.DraftRequest{Action: contracts.DraftUpdate, Number: n}
	}
)

// submissionOf is a submission entry with the id id, the text title and description,
// and the targets. A target with no draft needs no text, but the entry has it.
func submissionOf(id, title, description string, targets ...contracts.SubmissionTarget) contracts.Change {
	return contracts.Change{Kind: contracts.ChangeSubmission, SubmissionID: id, Text: &contracts.SubmissionText{Title: title, Description: description}, Targets: targets}
}

var entrySchema = func() *jsonschema.Schema {
	s, err := contracts.Compile("changes.schema.json")
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

// replies are the replies to submission entries Qory Apiary received.
func (f *fakeApiary) replies() []contracts.ChangesSubmitted {
	var out []contracts.ChangesSubmitted
	for _, r := range f.sent(routeChangesSubmitted) {
		var c contracts.ChangesSubmitted
		json.Unmarshal(r.raw, &c)
		out = append(out, c)
	}
	return out
}

// draftReplies are the drafts of each target of the replies, by path.
func (f *fakeApiary) draftsReplied() map[string]*contracts.SubmittedDraft {
	out := map[string]*contracts.SubmittedDraft{}
	for _, r := range f.replies() {
		for _, t := range r.Targets {
			out[t.Path] = t.Draft
		}
	}
	return out
}

// submissionReports are the failure reports for repositories of submission entries,
// each "path reason".
func (f *fakeApiary) submissionReports() []string {
	var out []string
	for _, r := range f.sent(routeChangesFailed) {
		if id, _ := r.body["submission_id"].(string); id != "" {
			out = append(out, fmt.Sprint(r.body["path"], " ", r.body["reason"]))
		}
	}
	return out
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

// TestAFirstSubmissionOpensOneDraftAndRepliesWithTheAddresses reads a submission entry
// that asks for a draft: one draft pull request is opened with the marked body, from the
// branch into the base branch, with a token that has pull_requests: write alone; the
// reply, which passes the contract's schema, has the pull request's number, address,
// title, state draft and action opened, and the address of the base and of each of four
// commits; the cursor moves.
func TestAFirstSubmissionOpensOneDraftAndRepliesWithTheAddresses(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	entry := submissionOf(testSubmissionID, testTitle, "What changed.", targetOf("acme/widgets", 4, openDraft))
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
	w.gh.mu.Lock()
	mints := slices.Clone(w.gh.mints)
	w.gh.mu.Unlock()
	if len(mints) != 1 || mints[0] != `{"permissions":{"pull_requests":"write"},"repositories":["widgets"]}` {
		t.Errorf("mints %v", mints)
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || replies[0].SubmissionID != testSubmissionID || len(replies[0].Targets) != 1 {
		t.Fatalf("replies %+v", replies)
	}
	r := replies[0].Targets[0]
	wantDraft := contracts.SubmittedDraft{Number: 1, URL: "https://github.com/acme/widgets/pull/1", Title: testTitle, State: "draft", Action: "opened"}
	if r.Draft == nil || *r.Draft != wantDraft {
		t.Errorf("the draft is %+v, want %+v", r.Draft, wantDraft)
	}
	if r.System != githubSystem || r.Path != "acme/widgets" || r.Base.Commit != sha(1) || r.Base.CommitURL != "https://github.com/acme/widgets/commit/"+sha(1) || len(r.Commits) != 4 {
		t.Errorf("the reply is %+v", r)
	}
	for i, c := range r.Commits {
		if c.Commit != sha(2+i) || c.CommitURL != "https://github.com/acme/widgets/commit/"+sha(2+i) {
			t.Errorf("commit %d is %+v", i, c)
		}
	}
	if !cursorIs(w, "c_1") || len(w.apiary.submissionReports()) != 0 {
		t.Errorf("the cursor or the reports are wrong: %v", w.apiary.submissionReports())
	}
	if strings.Contains(w.log.String(), ghToken) || strings.Contains(w.log.String(), "What changed.") {
		t.Errorf("the log contains the token or the text: %s", w.log.String())
	}
}

// TestALaterSubmissionUpdatesTheSameDraft reads a second entry with action update: the
// same pull request changes, and only the text between the markers: a person's lines
// before and after the block stay. The title changes while it equals previous_title.
func TestALaterSubmissionUpdatesTheSameDraft(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) {
		p.body = "Dana's line above.\n\n" + p.body + "\n\nDana's line below."
	})
	second := submissionOf(testSubmissionID2, "Fix the widget well", "Second text.", targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
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
	if len(w.apiary.replies()) != 2 || d["acme/widgets"] == nil || *d["acme/widgets"] != (contracts.SubmittedDraft{Number: 1, URL: "https://github.com/acme/widgets/pull/1", Title: "Fix the widget well", State: "draft", Action: "updated"}) {
		t.Errorf("the replies are %+v", w.apiary.replies())
	}
}

// TestAnUpdateKeepsATitleAPersonChanged: the title changes only while it equals
// previous_title; a title a person edited stays, and the description still changes.
func TestAnUpdateKeepsATitleAPersonChanged(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = "Dana's title" })
	second := submissionOf(testSubmissionID2, "A new title", "Second text.", targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = "Dana wrote all of this." })
	w.apiary.add(submissionOf(testSubmissionID2, testTitle, "Second text.", targetOf("acme/widgets", 2, update(1))))
	w.stepOK(t)
	if got, want := w.gh.pullRequests("acme/widgets")[0].body, "Dana wrote all of this.\n\n"+blockOf("Second text."); got != want {
		t.Errorf("the body is %q, want %q", got, want)
	}
}

// TestAnUpdateThatChangesNothingIsKept: the entry's text is the block's already and the
// title stands, so no request writes, and the reply has the action kept.
func TestAnUpdateThatChangesNothingIsKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Same text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	// GitHub may store the body with CRLF line breaks, which is the same text.
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = strings.ReplaceAll(p.body, "\n", "\r\n") })
	second := submissionOf(testSubmissionID2, testTitle, "Same text.", targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
		w.stepOK(t)
		editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.closed, p.merged = true, state == "merged" })
		second := submissionOf(testSubmissionID2, "New title", "Second text.", targetOf("acme/widgets", 2, update(1)))
		second.PreviousTitle = testTitle
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

// TestATargetWithNoDraftGetsOnlyAddresses: a target with no draft, as after a session
// that did not pass, makes no request to GitHub, mints no token, and its reply has the
// address of each of four commits and no draft.
func TestATargetWithNoDraftGetsOnlyAddresses(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	entry := submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 4, nil))
	entry.Text = nil
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	w.gh.mu.Lock()
	asked, mints := len(w.gh.requests), len(w.gh.mints)
	w.gh.mu.Unlock()
	if asked != 0 || mints != 0 {
		t.Errorf("GitHub was asked %d times, %d mints", asked, mints)
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || len(replies[0].Targets) != 1 || replies[0].Targets[0].Draft != nil || len(replies[0].Targets[0].Commits) != 4 {
		t.Fatalf("replies %+v", replies)
	}
	if bytes.Contains(w.apiary.sent(routeChangesSubmitted)[0].raw, []byte(`"draft"`)) {
		t.Errorf("the reply has a draft: %s", w.apiary.sent(routeChangesSubmitted)[0].raw)
	}
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
}

// TestTwoRepositoriesGetOneDraftEachAndOneReply: an entry with two repositories opens a
// draft in each and sends one reply for the entry, with a target for each, in the entry's
// order, with the addresses of that repository.
func TestTwoRepositoriesGetOneDraftEachAndOneReply(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	entry := submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 2, openDraft))
	checkEntries(t, entry)
	w.apiary.add(entry)
	w.stepOK(t)
	for _, repo := range []string{"acme/widgets", "acme/gadgets"} {
		if got := len(w.gh.pullRequests(repo)); got != 1 {
			t.Errorf("%s: %d pull requests", repo, got)
		}
	}
	replies := w.apiary.replies()
	if len(replies) != 1 || len(replies[0].Targets) != 2 {
		t.Fatalf("replies %+v", replies)
	}
	for i, tg := range replies[0].Targets {
		if tg.Path != []string{"acme/widgets", "acme/gadgets"}[i] || len(tg.Commits) != i+1 || !strings.HasPrefix(tg.Base.CommitURL, "https://github.com/"+tg.Path+"/commit/") || tg.Draft == nil || !strings.HasPrefix(tg.Draft.URL, "https://github.com/"+tg.Path+"/pull/") {
			t.Errorf("the reply is %+v", tg)
		}
	}
}

// TestAReplayOfADoneEntryOpensNoSecondDraft reads the feed from the start again, as a
// restart does: the pull request is found by its head, not opened again, and the reply
// has the same number, address, title and state.
func TestAReplayOfADoneEntryOpensNoSecondDraft(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	first, second := *replies[0].Targets[0].Draft, *replies[1].Targets[0].Draft
	if second.Action != "kept" {
		t.Errorf("the replay's action is %s", second.Action)
	}
	second.Action = first.Action
	if first != second || !slices.Equal(replies[0].Targets[0].Commits, replies[1].Targets[0].Commits) {
		t.Errorf("the replies differ: %+v and %+v", replies[0], replies[1])
	}
}

// TestAPageReadAgainAppliesADoneEntryOnce: a page whose cursor does not move, as when
// another entry of it fails, applies a submission that is done once.
func TestAPageReadAgainAppliesADoneEntryOnce(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setReach(w.st, widgetsRef, 42)
	setGitHub(w.gh, func(f *fakeGitHub) { f.commentStatus, f.commentAnswer = 502, `{"message":"Bad Gateway"}` })
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)), commentEntry("acme/widgets", 7))
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, update(9))))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].number != 1 {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "opened" || d.Number != 1 {
		t.Errorf("the draft is %+v", d)
	}
	second := submissionOf(testSubmissionID2, testTitle, "New text.", targetOf("acme/widgets", 2, update(9)))
	second.PreviousTitle = testTitle
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "release", number: 1, title: "Into release", draft: true})
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].base != "release" || pulls[0].body != blockOf("Text.") {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Number != 1 || d.Action != "updated" {
		t.Errorf("the draft is %+v", d)
	}
	later := targetOf("acme/widgets", 2, update(1))
	later.Base.Branch = "develop"
	w.apiary.add(submissionOf(testSubmissionID2, testTitle, "New text.", later))
	w.stepOK(t)
	pulls = w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].base != "release" || pulls[0].body != blockOf("New text.") {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestSeveralPullRequestsFromTheBranchAreChosenByNumberThenNewestOpen: of two or more pull
// requests from the head branch, the entry's number is taken when it is among them;
// otherwise the newest open one, and a closed or merged one only when none is open, then
// the newest of those, which is kept as it is. No case is reported unreachable.
func TestSeveralPullRequestsFromTheBranchAreChosenByNumberThenNewestOpen(t *testing.T) {
	pull := func(n int, base string, closed, merged bool) *ghPullRec {
		return &ghPullRec{repo: "acme/widgets", head: testBranch, base: base, number: n, title: fmt.Sprint("Pull ", n), draft: !closed, closed: closed, merged: merged}
	}
	for _, tc := range []struct {
		name   string
		pulls  []*ghPullRec
		draft  *contracts.DraftRequest
		number int
		action string
		state  string
	}{
		{"the entry's number, though an open one is newer", []*ghPullRec{pull(1, "main", false, false), pull(2, "main", false, false)}, update(1), 1, "updated", "draft"},
		{"a number that is not among them: the newest open one", []*ghPullRec{pull(1, "main", false, false), pull(2, "main", true, false), pull(3, "main", false, false), pull(4, "main", true, false)}, update(9), 3, "updated", "draft"},
		{"an open one, with bases that differ", []*ghPullRec{pull(1, "release", true, false), pull(2, "develop", false, false)}, openDraft, 2, "updated", "draft"},
		{"none open: the newest, which is merged", []*ghPullRec{pull(1, "main", true, false), pull(2, "main", true, true), pull(3, "main", true, false)}, openDraft, 3, "kept", "closed"},
		{"none open, the newest is merged", []*ghPullRec{pull(1, "main", true, false), pull(2, "main", true, true)}, openDraft, 2, "kept", "merged"},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, func(f *fakeGitHub) { f.pulls = tc.pulls })
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, tc.draft)))
		w.stepOK(t)
		d := w.apiary.draftsReplied()["acme/widgets"]
		if d == nil || d.Number != tc.number || d.Action != tc.action || d.State != tc.state || len(w.apiary.submissionReports()) != 0 || len(w.gh.pullRequests("acme/widgets")) != len(tc.pulls) {
			t.Errorf("%s: the draft is %+v, reports %v", tc.name, d, w.apiary.submissionReports())
		}
	}
}

// TestAPullRequestFromAForkIsNotTheDraft: a pull request with the head branch's name
// from another repository is not the draft, so a draft is opened.
func TestAPullRequestFromAForkIsNotTheDraft(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", headRepo: "acme/widgets-fork", head: testBranch, base: "main", number: 1, title: "A fork's"})
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 2 || pulls[1].number != 2 || pulls[0].title != "A fork's" {
		t.Errorf("pull requests %+v", pulls)
	}
}

// TestASubmissionThatCannotBePutOnGitHubIsReportedWithItsReason: each case is an entry
// whose draft a retry cannot open or update; one failure report, which passes the
// contract's schema, has the submission_id, system, path, the reason and a detail that
// starts with the fix line of that case, at most 100 characters; no reply is sent; the
// cursor moves; the log has the fix once, with the submission_id and without the text or
// the token.
func TestASubmissionThatCannotBePutOnGitHubIsReportedWithItsReason(t *testing.T) {
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
		{"the installation lookup is 301", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 301, `{"message":"Moved Permanently"}`), "forge_refused", github.FixMoved, "GitHub returned 301: Moved Permanently", false},
		{"the installation lookup is 308", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 308, `{"message":"Permanent Redirect"}`), "forge_refused", github.FixMoved, "GitHub returned 308: Permanent Redirect", false},
		{"the installation lookup is 404", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 404, `{"message":"Not Found"}`), "not_permitted", fixNotInstalled, "", false},
		{"the installation lookup is 302", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 302, `{"message":"Found"}`), "not_permitted", fixNotInstalled, "", false},
		{"the installation lookup is 307", "Text.", forbidden("GET", "/repos/acme/widgets/installation", 307, `{"message":"Temporary Redirect"}`), "not_permitted", fixNotInstalled, "", false},
		{"a suspended installation", "Text.", func(f *fakeGitHub) { f.installSuspended = true }, "not_permitted", "Unsuspend the App's installation on GitHub.", "", false},
		{"the create is 403", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 403, `{"message":"Resource not accessible by integration"}`), "not_permitted", fixPermission, "GitHub returned 403: Resource not accessible by integration", false},
		{"the repository moved", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 301, `{"message":"Moved Permanently"}`), "forge_refused", "Link the repository by its new name: GitHub moved it.", "GitHub returned 301: Moved Permanently", false},
		{"the head branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{testBranch: true} }, "branch_gone", "Push the run's branch to the repository again, then submit again.", "GitHub returned 422: Validation Failed; PullRequest head invalid", false},
		{"GitHub's message for an invalid head", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"invalid","message":"head\ninvalid"}]}`), "branch_gone", "Push the run's branch to the repository again, then submit again.", "GitHub returned 422: Validation Failed; PullRequest invalid head invalid", false},
		{"the base branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{"main": true} }, "branch_gone", "Create the base branch on GitHub, or choose another base branch, then submit again.", "GitHub returned 422: Validation Failed; PullRequest base invalid", false},
		{"a description over 20000 characters", long, nil, "too_long", "Shorten the description of the run to 20000 characters or fewer.", "", true},
		{"GitHub's 422 for a body too long", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"body","code":"custom","message":"body is too long (maximum is 65536 characters)"}]}`), "too_long", "Shorten the description of the pull request on GitHub outside the Qory block.", "GitHub returned 422: Validation Failed; PullRequest body custom body is too long (maximum is 65536 characters)", false},
		{"GitHub's 422 for a title too long", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"title","code":"custom","message":"title is too long (maximum is 256 characters)"}]}`), "too_long", "Shorten the title of the pull request on GitHub to 256 characters or fewer.", "GitHub returned 422: Validation Failed; PullRequest title custom title is too long (maximum is 256 characters)", false},
		{"400", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 400, `{"message":"Problems parsing JSON"}`), "forge_refused", fixRefused, "GitHub returned 400: Problems parsing JSON", false},
		{"another 422", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"No commits between main and `+testBranch+`"}]}`), "forge_refused", fixRefused, "GitHub returned 422: Validation Failed; PullRequest custom No commits between main and " + testBranch, false},
		{"a 422 on the list", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 422, `{"message":"Validation Failed"}`), "forge_refused", fixRefused, "GitHub returned 422: Validation Failed", false},
		{"409", "Text.", forbidden("POST", "/repos/acme/widgets/pulls", 409, `{"message":"Conflict"}`), "forge_refused", fixRefused, "GitHub returned 409: Conflict", false},
		{"451", "Text.", forbidden("GET", "/repos/acme/widgets/pulls", 451, `{"message":"Unavailable For Legal Reasons"}`), "forge_refused", fixRefused, "GitHub returned 451: Unavailable For Legal Reasons", false},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		if tc.set != nil {
			setGitHub(w.gh, tc.set)
		}
		w.apiary.add(submissionOf(testSubmissionID, testTitle, tc.description, targetOf("acme/widgets", 2, openDraft)))
		if err := w.feed.step(context.Background()); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !cursorIs(w, "c_1") {
			t.Errorf("%s: the cursor did not move", tc.name)
		}
		if r := w.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets "+tc.want {
			t.Errorf("%s: reports %v, want %s", tc.name, r, tc.want)
			continue
		}
		if len(w.apiary.replies()) != 0 {
			t.Errorf("%s: replies %+v", tc.name, w.apiary.replies())
		}
		report := w.apiary.sent(routeChangesFailed)[0].body
		if report["submission_id"] != testSubmissionID || report["system"] != githubSystem || report["comment_id"] != nil {
			t.Errorf("%s: the report is %v", tc.name, report)
		}
		detail, _ := report["detail"].(string)
		if len(tc.fix) > 100 || !strings.HasSuffix(tc.fix, ".") || !strings.HasPrefix(detail, tc.fix) || (tc.forge == "" && detail != tc.fix) || (tc.forge != "" && detail != tc.fix+" "+tc.forge) {
			t.Errorf("%s: the detail is %q, want the fix %q and %q", tc.name, detail, tc.fix, tc.forge)
		}
		logged := w.log.String()
		if strings.Count(logged, tc.fix) != 1 || !strings.Contains(logged, testSubmissionID) || !strings.Contains(logged, "failure report sent to Qory Apiary with the reason "+tc.want) {
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				if m == "POST" && p == "/repos/acme/widgets/pulls" {
					return status, `{"message":"Try again"}`
				}
				return 0, ""
			}
		})
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || len(w.apiary.submissionReports()) != 0 || !cursorIs(w, "") {
			t.Errorf("%d: step %v, reports %v", status, err, w.apiary.submissionReports())
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.failHeader = map[string]string{"X-Secret-Header": "header-value-9f3a", "Set-Cookie": "session=cookie-value-77", "X-GitHub-Request-Id": "ABCD:1234"}
		f.pullFail = func(m, p string) (int, string) {
			if m == "POST" && p == "/repos/acme/widgets/pulls" {
				return 400, string(body)
			}
			return 0, ""
		}
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	exact := submissionOf(testSubmissionID, strings.Repeat("t", 256), strings.Repeat("d", 20000), targetOf("acme/widgets", 1, openDraft))
	checkEntries(t, exact)
	w.apiary.add(exact)
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "opened" || len(d.Title) != 256 {
		t.Errorf("the draft is %+v", d)
	}
	w2 := newWired(t, filepath.Join(t.TempDir(), "state"))
	w2.apiary.add(submissionOf(testSubmissionID, strings.Repeat("t", 257), "Text.", targetOf("acme/widgets", 1, openDraft)))
	w2.stepOK(t)
	w2.gh.mu.Lock()
	asked := len(w2.gh.requests)
	w2.gh.mu.Unlock()
	if r := w2.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets too_long" || asked != 0 {
		t.Errorf("reports %v, GitHub asked %d times", r, asked)
	}
}

// TestAPullRequestWhoseBodyGrowsPastGitHubsLimitIsTooLong: a person's long description
// plus the block is over GitHub's limit of 65536 characters, so the update is reported as
// too_long with the fix for that description, and GitHub is sent no update.
func TestAPullRequestWhoseBodyGrowsPastGitHubsLimitIsTooLong(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = strings.Repeat("b", 65530) })
	w.apiary.add(submissionOf(testSubmissionID2, testTitle, "Second text.", targetOf("acme/widgets", 2, update(1))))
	w.stepOK(t)
	if r := w.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets too_long" {
		t.Errorf("reports %v", r)
	}
	if d, _ := w.apiary.sent(routeChangesFailed)[0].body["detail"].(string); d != "Shorten the description of the pull request on GitHub outside the Qory block." {
		t.Errorf("the detail is %q", d)
	}
	if slices.Contains(w.gh.pullCalls(), "PATCH /repos/acme/widgets/pulls/1") {
		t.Error("GitHub was sent the update")
	}
}

// TestOneRepositoryFailingDoesNotBlockTheOther: a refused repository is reported and the
// other is in the one reply for the entry, in one step that moves the cursor.
func TestOneRepositoryFailingDoesNotBlockTheOther(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) { f.noInstallation = map[string]bool{"acme/widgets": true} })
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	if r := w.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets not_permitted" {
		t.Errorf("reports %v", r)
	}
	if d, r := w.apiary.draftsReplied(), w.apiary.replies(); len(d) != 1 || d["acme/gadgets"] == nil || len(r) != 1 || len(r[0].Targets) != 1 {
		t.Errorf("drafts %+v, replies %+v", d, r)
	}
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
}

// TestTheCursorMovesOnlyWhenEveryRepositoryIsDone: one repository fails, not for good,
// while the other's draft is opened once; no reply is sent and the cursor stays, and the
// next read applies the one that failed alone and sends the one reply for the entry.
func TestTheCursorMovesOnlyWhenEveryRepositoryIsDone(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			if strings.HasPrefix(p, "/repos/acme/widgets/pulls") {
				return 502, `{"message":"Bad Gateway"}`
			}
			return 0, ""
		}
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
		t.Fatalf("err %v", err)
	}
	if !cursorIs(w, "") {
		t.Error("the cursor moved")
	}
	if r := w.apiary.replies(); len(r) != 0 || len(w.gh.pullRequests("acme/gadgets")) != 1 {
		t.Errorf("replies %+v before every repository is put on GitHub", r)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
	w.stepOK(t)
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
	if d := w.apiary.draftsReplied(); len(d) != 2 || len(w.apiary.replies()) != 1 {
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

// TestASubmissionThatFailsForADayIsReportedUnreachable has GitHub return 502 for a day:
// the entry stays, with no report, until the day has passed, then each repository that
// is not put on GitHub is reported unreachable, the one reply for the repositories that
// are is sent, and the entry is passed. A repository that is put on GitHub is not
// reported.
func TestASubmissionThatFailsForADayIsReportedUnreachable(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
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
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	for _, after := range []time.Duration{0, stuckFor - time.Second} {
		now = now.Add(after)
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) {
			t.Fatalf("after %v: err %v", after, err)
		}
		if !cursorIs(w, "") {
			t.Fatalf("after %v: the cursor is kept", after)
		}
	}
	if r := w.apiary.submissionReports(); len(r) != 0 {
		t.Errorf("reported before a day: %v", r)
	}
	now = now.Add(time.Second)
	w.stepOK(t)
	if r := w.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets unreachable" {
		t.Errorf("reports %v", r)
	}
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
	if !strings.Contains(w.log.String(), github.FixUnreachable) {
		t.Errorf("the log %s", w.log.String())
	}
	if d, _ := w.apiary.sent(routeChangesFailed)[0].body["detail"].(string); d != github.FixUnreachable+" GitHub returned 502: Bad Gateway" {
		t.Errorf("the detail is %q", d)
	}
	if r := w.apiary.replies(); len(r) != 1 || len(r[0].Targets) != 1 || r[0].Targets[0].Path != "acme/gadgets" {
		t.Errorf("replies %+v", r)
	}
}

// TestALaterSubmissionWaitsForAnEarlierOneOfItsBranch: while the first entry of a branch
// fails, not for good, the second, which would write older text over newer if it ran
// first, is not applied.
func TestALaterSubmissionWaitsForAnEarlierOneOfItsBranch(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
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
	second := submissionOf(testSubmissionID2, testTitle, "Second.", targetOf("acme/widgets", 2, update(1)))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)), second)
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

// TestATargetOfAnotherSystemIsPassedAndTheOthersAreApplied: the entry's repository on
// another system is logged and passed, no reply, no report, and no request to GitHub
// for it; the other repository is replied to.
func TestATargetOfAnotherSystemIsPassedAndTheOthersAreApplied(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	other := targetOf("acme/widgets", 1, openDraft)
	other.System = "gitlab.example.com"
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", other, targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	if d := w.apiary.draftsReplied(); len(d) != 1 || d["acme/gadgets"] == nil {
		t.Errorf("drafts %+v", d)
	}
	if len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.gh.pullRequests("acme/widgets")) != 0 {
		t.Error("a report was sent, or a draft opened")
	}
	if !strings.Contains(w.log.String(), "the entry's system is not github.com") || !cursorIs(w, "c_1") {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestAMalformedSubmissionEntryIsPassedWithoutAReport: an entry whose submission_id is
// not one, or that has no repository, fails for good and is passed with no request.
func TestAMalformedSubmissionEntryIsPassedWithoutAReport(t *testing.T) {
	for _, entry := range []contracts.Change{
		submissionOf("av_nope", testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)),
		submissionOf(testSubmissionID, testTitle, "Text."),
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		w.apiary.add(entry)
		w.stepOK(t)
		if !cursorIs(w, "c_1") || len(w.apiary.sent(routeChangesFailed)) != 0 || len(w.apiary.replies()) != 0 || len(w.gh.pullCalls()) != 0 {
			t.Errorf("entry %+v: the step did not pass it quietly", entry)
		}
		if !strings.Contains(w.log.String(), "a change of the feed failed, and is passed") {
			t.Errorf("the log %s", w.log.String())
		}
	}
}

// TestAPullRequestCallAnswered401DropsTheTokens: a pull request call that GitHub answers 401
// drops the tokens kept, so the next try mints a new one.
func TestAPullRequestCallAnswered401DropsTheTokens(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) {
			return map[bool]int{true: 401}[m == "GET" && strings.HasPrefix(p, "/repos/acme/widgets/pulls")], `{"message":"Bad credentials"}`
		}
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	w.gh.mu.Lock()
	mints := len(w.gh.mints)
	w.gh.mu.Unlock()
	if mints != 2 {
		t.Errorf("%d mints, want 2", mints)
	}
}

// TestTheDeclarationHasNoSubmitModuleAndNamesSubmissions: the start-up body, checked
// against the contract's adapter.schema.json, has no submit_module, and its description
// says the source takes submissions.
func TestTheDeclarationHasNoSubmitModuleAndNamesSubmissions(t *testing.T) {
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
	if source["submissions"] != true {
		t.Errorf("the source role is %v", source)
	}
}

// TestEachRepositoryOfAnEntryIsMintedAToken pins that a two repository entry mints one
// token for each repository, with that repository's name and pull_requests: write, so
// the token of one is never used for the other; a later entry for the same repository
// mints no new one.
func TestEachRepositoryOfAnEntryIsMintedAToken(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	w.gh.mu.Lock()
	mints := slices.Clone(w.gh.mints)
	w.gh.mu.Unlock()
	want := []string{
		`{"permissions":{"pull_requests":"write"},"repositories":["widgets"]}`,
		`{"permissions":{"pull_requests":"write"},"repositories":["gadgets"]}`,
	}
	if !slices.Equal(mints, want) {
		t.Errorf("mints %v, want %v", mints, want)
	}
	second := submissionOf(testSubmissionID2, testTitle, "More text.", targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
	w.apiary.add(second)
	w.stepOK(t)
	w.gh.mu.Lock()
	again := len(w.gh.mints)
	w.gh.mu.Unlock()
	if again != 2 {
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
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
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		err := w.feed.step(context.Background())
		switch tc.want {
		case "opened":
			if err != nil || !cursorIs(w, "c_1") || len(w.gh.pullRequests("acme/widgets")) != 1 || len(w.apiary.submissionReports()) != 0 {
				t.Errorf("%s: err %v, reports %v", tc.name, err, w.apiary.submissionReports())
			}
			if len(slept) < 2 {
				t.Errorf("%s: waited %v, want a wait after each refusal", tc.name, slept)
			}
		case "stays":
			if err == nil || IsPermanent(err) || !cursorIs(w, "") || len(w.apiary.submissionReports()) != 0 {
				t.Errorf("%s: err %v, reports %v", tc.name, err, w.apiary.submissionReports())
			}
		default:
			if err != nil || !cursorIs(w, "c_1") || !slices.Equal(w.apiary.submissionReports(), []string{"acme/widgets not_permitted"}) || len(slept) != 0 {
				t.Errorf("%s: err %v, reports %v, waits %v", tc.name, err, w.apiary.submissionReports(), slept)
			}
		}
	}
}

// TestACRLFBodyWithAMultiLineBlockIsKept: GitHub may store a description with CRLF line
// breaks, the block's text among them. The entry's text has LF breaks, so the new
// description differs from it by line breaks alone, which is no change: no write, and the
// action kept.
func TestACRLFBodyWithAMultiLineBlockIsKept(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	text := "Line one.\nLine two.\n\nLine four."
	w.apiary.add(submissionOf(testSubmissionID, testTitle, text, targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	crlf := "Dana above.\r\n" + strings.ReplaceAll(blockOf(text), "\n", "\r\n") + "\r\nDana below."
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.body = crlf })
	second := submissionOf(testSubmissionID2, testTitle, text, targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	const edited = "Fix\u200b the\u00ad widget\u202e\u0085"
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = edited })
	second := submissionOf(testSubmissionID2, "Another title", "Second.", targetOf("acme/widgets", 2, update(1)))
	second.PreviousTitle = testTitle
	w.apiary.add(second)
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != "Fix the widget" {
		t.Errorf("the draft is %+v", d)
	}
	if got := w.gh.pullRequests("acme/widgets")[0].title; got != edited {
		t.Errorf("the pull request's title is %q, want it unchanged", got)
	}
	editPull(w, "acme/widgets", 1, func(p *ghPullRec) { p.title = "\u200b\u2060 \u00a0" })
	third := submissionOf("av_0a0a0a0a0a0a0a0a", "A third title", "Third.", targetOf("acme/widgets", 3, update(1)))
	third.PreviousTitle = "Another title"
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted && n == 1 {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "opened" || d.Number != 1 {
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.failHeader = tc.header
			f.pullFail = func(m, p string) (int, string) {
				if m == "GET" && p == "/repos/acme/widgets/installation" {
					return 403, `{"message":"` + tc.message + `"}`
				}
				return 0, ""
			}
		})
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if !tc.retried {
			w.stepOK(t)
			if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets not_permitted"}) || !cursorIs(w, "c_1") {
				t.Errorf("%s: reports %v", tc.name, r)
			}
			continue
		}
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") || len(w.apiary.submissionReports()) != 0 {
			t.Fatalf("%s: err %v, reports %v", tc.name, err, w.apiary.submissionReports())
		}
		setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
		w.stepOK(t)
		if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "opened" || !cursorIs(w, "c_1") {
			t.Errorf("%s: the draft is %+v", tc.name, d)
		}
	}
}

// TestAnUpdateOfAnEmptyDescriptionWritesTheBlockAlone: a pull request whose description
// is empty, which GitHub returns as null, gets the block alone, with no blank line before
// it and no other text; with CRLF in the run's text nothing else changes.
func TestAnUpdateOfAnEmptyDescriptionWritesTheBlockAlone(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 1, title: testTitle, draft: true})
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, update(1))))
	w.stepOK(t)
	if pulls := w.gh.pullRequests("acme/widgets"); len(pulls) != 1 || pulls[0].body != blockOf("Text.") || !strings.HasPrefix(pulls[0].body, "<!-- qory:start -->\n") {
		t.Errorf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "updated" {
		t.Errorf("the draft is %+v", d)
	}
}

// TestAReplyThatKeepsFailingEndsAsFailureReports: Qory Apiary refuses the reply of an
// entry with a 503 for two days after the first failure; the drafts exist, so the entry
// is applied once, and when its retries end each repository of the reply is reported
// unreachable, once, and the entry is passed.
func TestAReplyThatKeepsFailingEndsAsFailureReports(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	now := time.Now()
	w.feed.now = func() time.Time { return now }
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	for _, after := range []time.Duration{0, stuckFor, stuckFor - time.Second} {
		now = now.Add(after)
		if err := w.feed.step(context.Background()); err == nil || IsPermanent(err) || !cursorIs(w, "") {
			t.Fatalf("after %v: err %v", after, err)
		}
	}
	if r := w.apiary.submissionReports(); len(r) != 0 {
		t.Errorf("reported too early: %v", r)
	}
	now = now.Add(time.Second)
	w.stepOK(t)
	if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets unreachable", "acme/gadgets unreachable"}) || !cursorIs(w, "c_1") {
		t.Errorf("reports %v", r)
	}
	for _, repo := range []string{"acme/widgets", "acme/gadgets"} {
		if got := len(w.gh.pullRequests(repo)); got != 1 {
			t.Errorf("%s: %d pull requests", repo, got)
		}
	}
	for n := range 2 {
		if d := detailOf(w, n); !strings.HasPrefix(d, github.FixReplyRefused+" ") || !strings.Contains(d, "503") {
			t.Errorf("the detail %d is %q", n, d)
		}
	}
}

// TestAReplyThatQoryApiaryRefusesIsLoggedAndTheEntryIsDone: a 400 for the reply is
// Permanent, as for every request; the entry is done, with no failure report, and the
// reply is not sent again.
func TestAReplyThatQoryApiaryRefusesIsLoggedAndTheEntryIsDone(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.refuse = func(route string, n int) (int, string) {
		if route == routeChangesSubmitted {
			return http.StatusBadRequest, `{"error":"invalid_request"}`
		}
		return 0, ""
	}
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if !cursorIs(w, "c_1") || len(w.apiary.submissionReports()) != 0 || len(w.apiary.sent(routeChangesSubmitted)) != 1 || !strings.Contains(w.log.String(), "the reply for a submission failed permanently") {
		t.Errorf("reports %v, log %s", w.apiary.submissionReports(), w.log.String())
	}
}

// TestTheRunsTitleInTheReplyIsCleanedToo: a pull request whose title is nothing but
// invisible characters gets the run's title in the reply, without the forbidden characters
// the run's title has; a run's title with no usable character is Qory Apiary's defect, so
// it is logged and passed before any request, with no reply and no report.
func TestTheRunsTitleInTheReplyIsCleanedToo(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 1, title: "\u200b\u2060", draft: true})
	})
	w.apiary.add(submissionOf(testSubmissionID, "Fix\u200b the widget", "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Title != "Fix the widget" {
		t.Errorf("the draft is %+v", d)
	}
	w2 := newWired(t, filepath.Join(t.TempDir(), "state"))
	w2.apiary.add(submissionOf(testSubmissionID, "\u200b \u202e", "Text.", targetOf("acme/widgets", 1, openDraft)))
	w2.stepOK(t)
	if len(w2.gh.pullCalls()) != 0 || len(w2.apiary.replies()) != 0 || len(w2.apiary.sent(routeChangesFailed)) != 0 || !cursorIs(w2, "c_1") {
		t.Errorf("the entry was not passed quietly")
	}
	if !strings.Contains(w2.log.String(), "the entry's title has no character") {
		t.Errorf("the log %s", w2.log.String())
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
	if len(w.apiary.submissionReports()) != 0 {
		t.Fatalf("reported before the retries ended: %v", w.apiary.submissionReports())
	}
	now = now.Add(stuckFor)
	w.stepOK(t)
	if !cursorIs(w, "c_1") {
		t.Fatal("the cursor did not move")
	}
}

// TestACancelledContextKeepsAnEntryWhoseRetriesEnded: the retries of an entry have ended,
// and the step that would report it is cancelled. The step returns the cancellation, sends
// no report, and keeps the entry and its cursor; the next step reports it once.
func TestACancelledContextKeepsAnEntryWhoseRetriesEnded(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
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
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	if r := w.apiary.submissionReports(); len(r) != 0 || !cursorIs(w, "") {
		t.Fatalf("reports %v, cursor moved: %v", r, !cursorIs(w, ""))
	}
	cancelling = false
	w.stepOK(t)
	if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets unreachable"}) || !cursorIs(w, "c_1") {
		t.Errorf("reports %v", r)
	}
}

// detailOf is the detail of the failure report n of the submission entries.
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, func(f *fakeGitHub) {
			f.pulls = append(f.pulls, tc.other, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 2, title: testTitle, draft: true})
		})
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, update(1))))
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
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, failAt("POST", "/repos/acme/widgets/pulls", status, string(body)))
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
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
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, failAt("GET", "/repos/acme/widgets/installation", 502, `{"message":"first\njwt eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0In0.c2lnbmF0dXJl end"}`))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	err := w.feed.step(context.Background())
	if err == nil || strings.Contains(err.Error(), "eyJ") || strings.ContainsAny(err.Error(), "\r\n") || !strings.Contains(err.Error(), "first jwt [removed] end") {
		t.Errorf("err %v", err)
	}
}

// TestWhenTheRetriesEndEachRepositoryIsReportedByItsLastCause: the first repository of
// an entry fails with 502, the second with a 422 that says a pull request exists though
// none is found, so each is tried again; at the end the first is unreachable and the second
// forge_refused, with GitHub's message in its detail, not the first's.
func TestWhenTheRetriesEndEachRepositoryIsReportedByItsLastCause(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
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
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	runPastRetries(t, w)
	if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets unreachable", "acme/gadgets forge_refused"}) {
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
// forge_refused with a detail that says so, a 4xx from the installation lookup is
// forge_refused at once, and only 5xx, a rate limit and a timeout are unreachable.
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
		{"an answer that is no JSON", failAt("GET", "/repos/acme/widgets/pulls", 200, `<html>Unicorn</html>`), false, "forge_refused", "Report to the maintainers of qory-github that GitHub's answer could not be read. GitHub returned 200."},
		{"400 on the installation lookup", failAt("GET", "/repos/acme/widgets/installation", 400, `{"message":"Bad Request"}`), true, "forge_refused", github.FixForgeRefused + " GitHub returned 400: Bad Request"},
		{"422 on the installation lookup", failAt("GET", "/repos/acme/widgets/installation", 422, `{"message":"Validation Failed"}`), true, "forge_refused", github.FixForgeRefused + " GitHub returned 422: Validation Failed"},
		{"502", failAt("GET", "/repos/acme/widgets/pulls", 502, `{"message":"Bad Gateway"}`), false, "unreachable", github.FixUnreachable + " GitHub returned 502: Bad Gateway"},
		{"408", failAt("GET", "/repos/acme/widgets/pulls", 408, `{"message":"Request Timeout"}`), false, "unreachable", github.FixUnreachable + " GitHub returned 408: Request Timeout"},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, tc.set)
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		if tc.now {
			w.stepOK(t)
		} else {
			runPastRetries(t, w)
		}
		if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets " + tc.reason}) || detailOf(w, 0) != tc.detail {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
	}
}

// TestAMintThatKeepsFailingEndsAsItsReason: the mint of the token for pull requests fails
// on every try, so the entry is applied again until its retries end, then reported by the
// last answer: a 403 that is no rate limit is not_permitted, a 403 that says rate limit,
// a 429 and a 503 are unreachable, a redirect is forge_refused, and an answer with no
// token or with an expiry that is no time is forge_refused with the detail that says the answer's
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
		{"a redirect", 302, `{"message":"Found"}`, "forge_refused", github.FixForgeRefused},
		{"no token", 201, `{"expires_at":"2099-01-01T00:00:00Z"}`, "forge_refused", unreadable},
		{"an expiry that is no time", 201, `{"token":"` + ghToken + `","expires_at":"tomorrow"}`, "forge_refused", unreadable},
		{"no JSON", 201, `<html>Unicorn</html>`, "forge_refused", unreadable},
	} {
		w := newWired(t, filepath.Join(t.TempDir(), "state"))
		setGitHub(w.gh, func(f *fakeGitHub) { f.pullMint = func() (int, string) { return tc.status, tc.body } })
		w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
		runPastRetries(t, w)
		if r := w.apiary.submissionReports(); !slices.Equal(r, []string{"acme/widgets " + tc.reason}) || detailOf(w, 0) != tc.detail {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
		if strings.Contains(w.log.String(), ghToken) {
			t.Errorf("%s: the log has the token", tc.name)
		}
	}
}
