package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
// action kept. This needs the states closed and merged in changes-submitted.schema.json,
// which the pinned contract at 7758ce9d does not have yet.
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

// TestTwoRepositoriesGetOneDraftAndOneReplyEach: an entry with two repositories opens a
// draft in each and sends one reply for each, with the addresses of that repository.
func TestTwoRepositoriesGetOneDraftAndOneReplyEach(t *testing.T) {
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
	if len(replies) != 2 {
		t.Fatalf("%d replies", len(replies))
	}
	for _, r := range replies {
		tg := r.Targets[0]
		if !strings.HasPrefix(tg.Base.CommitURL, "https://github.com/"+tg.Path+"/commit/") || tg.Draft == nil || !strings.HasPrefix(tg.Draft.URL, "https://github.com/"+tg.Path+"/pull/") {
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

// TestAPullRequestIntoAnotherBaseIsNotTheDraft: a pull request from the branch into
// another base branch is not the draft of the entry, as bin/open-draft chooses it, so a
// draft is opened into the entry's base branch.
func TestAPullRequestIntoAnotherBaseIsNotTheDraft(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "release", number: 1, title: "Into release"})
	})
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 2 || pulls[1].base != "main" || pulls[0].body != "" {
		t.Errorf("pull requests %+v", pulls)
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
// contract's schema, has the submission_id, system, path and the reason; no reply is
// sent; the cursor moves; the log has the fix once, with the submission_id and without
// the text or the token.
func TestASubmissionThatCannotBePutOnGitHubIsReportedWithItsReason(t *testing.T) {
	long := strings.Repeat("a", 20001)
	for _, tc := range []struct {
		name        string
		description string
		set         func(f *fakeGitHub)
		want        string
		quiet       bool // GitHub is asked nothing
	}{
		{"the list is 403", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 403}[m == "GET" && p == "/repos/acme/widgets/pulls"], `{"message":"Resource not accessible by integration"}`
			}
		}, "not_permitted", false},
		{"the list is 404", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 404}[m == "GET" && p == "/repos/acme/widgets/pulls"], `{"message":"Not Found"}`
			}
		}, "not_permitted", false},
		{"no installation", "Text.", func(f *fakeGitHub) { f.noInstallation = map[string]bool{"acme/widgets": true} }, "not_permitted", false},
		{"a suspended installation", "Text.", func(f *fakeGitHub) { f.installSuspended = true }, "not_permitted", false},
		{"the create is 403", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 403}[m == "POST" && p == "/repos/acme/widgets/pulls"], `{"message":"Resource not accessible by integration"}`
			}
		}, "not_permitted", false},
		{"the head branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{testBranch: true} }, "branch_gone", false},
		{"GitHub's message for an invalid head", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 422}[m == "POST" && p == "/repos/acme/widgets/pulls"], `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"invalid","message":"head\ninvalid"}]}`
			}
		}, "branch_gone", false},
		{"the base branch is gone", "Text.", func(f *fakeGitHub) { f.goneBranches = map[string]bool{"main": true} }, "branch_gone", false},
		{"a description over 20000 characters", long, nil, "too_long", true},
		{"GitHub's 422 for a body too long", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 422}[m == "POST" && p == "/repos/acme/widgets/pulls"], `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"body","code":"custom","message":"body is too long (maximum is 65536 characters)"}]}`
			}
		}, "too_long", false},
		{"two pull requests have the head", "Text.", func(f *fakeGitHub) {
			f.pulls = append(f.pulls, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 1, closed: true}, &ghPullRec{repo: "acme/widgets", head: testBranch, base: "main", number: 2})
		}, "unreachable", false},
		{"400", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 400}[m == "POST" && p == "/repos/acme/widgets/pulls"], `{"message":"Problems parsing JSON"}`
			}
		}, "unreachable", false},
		{"another 422", "Text.", func(f *fakeGitHub) {
			f.pullFail = func(m, p string) (int, string) {
				return map[bool]int{true: 422}[m == "POST" && p == "/repos/acme/widgets/pulls"], `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"No commits between main and ` + testBranch + `"}]}`
			}
		}, "unreachable", false},
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
		logged := w.log.String()
		fix := strings.TrimSuffix((&github.SubmitRefused{Reason: tc.want, Err: errors.New("x")}).Error(), ": x")
		if strings.Count(logged, fix) != 1 || !strings.Contains(logged, testSubmissionID) || !strings.Contains(logged, "failure report sent to Qory Apiary with the reason "+tc.want) {
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
// plus the block is over GitHub's limit, whose 422 is reported as too_long.
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
}

// TestOneRepositoryFailingDoesNotBlockTheOther: a refused repository is reported and the
// other is replied to, in one step that moves the cursor.
func TestOneRepositoryFailingDoesNotBlockTheOther(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) { f.noInstallation = map[string]bool{"acme/widgets": true} })
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "Text.", targetOf("acme/widgets", 1, openDraft), targetOf("acme/gadgets", 1, openDraft)))
	w.stepOK(t)
	if r := w.apiary.submissionReports(); len(r) != 1 || r[0] != "acme/widgets not_permitted" {
		t.Errorf("reports %v", r)
	}
	if d := w.apiary.draftsReplied(); len(d) != 1 || d["acme/gadgets"] == nil {
		t.Errorf("drafts %+v", d)
	}
	if !cursorIs(w, "c_1") {
		t.Error("the cursor did not move")
	}
}

// TestTheCursorMovesOnlyWhenEveryRepositoryIsDone: one repository fails, not for good,
// while the other is replied to once; the cursor stays, and the next read applies the one
// that failed alone.
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
	if d := w.apiary.draftsReplied(); len(d) != 1 || d["acme/gadgets"] == nil {
		t.Errorf("drafts %+v", d)
	}
	setGitHub(w.gh, func(f *fakeGitHub) { f.pullFail = nil })
	w.stepOK(t)
	if !cursorIs(w, "c_1") {
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

// TestASubmissionThatFailsForADayIsReportedUnreachable has GitHub return 502 for a day:
// the entry stays, with no report, until the day has passed, then each repository that
// is not done is reported unreachable and the entry is passed. A repository replied to
// before is not reported.
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
	fix := strings.TrimSuffix((&github.SubmitRefused{Reason: "unreachable", Err: errors.New("x")}).Error(), ": x")
	if !strings.Contains(w.log.String(), fix) {
		t.Errorf("the log %s", w.log.String())
	}
}

// TestALaterSubmissionWaitsForAnEarlierOneOfItsBranch: while the first entry of a branch
// fails, not for good, the second, which would write older text over newer if it ran
// first, is not applied.
func TestALaterSubmissionWaitsForAnEarlierOneOfItsBranch(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	setGitHub(w.gh, func(f *fakeGitHub) {
		f.pullFail = func(m, p string) (int, string) { return 502, `{"message":"Bad Gateway"}` }
	})
	second := submissionOf(testSubmissionID2, testTitle, "Second.", targetOf("acme/widgets", 2, update(1)))
	w.apiary.add(submissionOf(testSubmissionID, testTitle, "First.", targetOf("acme/widgets", 1, openDraft)), second)
	if err := w.feed.step(context.Background()); err == nil {
		t.Fatal("no error")
	}
	for _, c := range w.gh.pullCalls() {
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
