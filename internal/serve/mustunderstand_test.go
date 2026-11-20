package serve

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// syncEntry is a sync entry that sets the interval to seconds.
func syncEntry(seconds int) contracts.Change {
	return contracts.Change{Kind: contracts.ChangeSync, Interval: &seconds}
}

// intervalIs reports whether the store has the sync interval seconds, "" for none.
func intervalIs(w *wired, seconds string) bool {
	got, err := w.st.Get(nsAdapter, keySyncInterval)
	if errors.Is(err, store.ErrNotFound) {
		return seconds == ""
	}
	return err == nil && string(got) == seconds
}

// TestTheFeedSkipsAnEntryOfAnUnknownKindAndReadsTheNext reads a page whose middle entry
// has a kind that the contract does not define, and a member of the wrong type: the entry
// applies nothing, the entry after it is applied, the cursor moves past all of them, and
// the log says the entry is skipped.
func TestTheFeedSkipsAnEntryOfAnUnknownKindAndReadsTheNext(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(syncEntry(1200), contracts.Change{Kind: "label", Status: "added"}, syncEntry(1800))
	w.apiary.withMembers(1, map[string]any{"interval": "soon", "extra": map[string]any{"zz": 1}})
	w.stepOK(t)
	if !intervalIs(w, "1800") || !cursorIs(w, "c_3") {
		t.Errorf("the interval or the cursor is wrong: cursor %v", cursorIs(w, "c_3"))
	}
	want := `"level":"WARN","msg":"an entry of the change feed is skipped","kind":"label"`
	if logged := w.log.String(); !strings.Contains(logged, want) {
		t.Errorf("the log %s", logged)
	}
	w.stepOK(t)
	if gets := w.apiary.sent("GET " + routeChanges); len(gets) != 2 || gets[1].target != routeChanges+"?after=c_3" {
		t.Errorf("read %v", gets)
	}
}

// TestTheFeedIgnoresAMemberItDoesNotDefine reads a sync entry with a member the entry
// does not define, and a page of the feed with one: the entry is applied.
func TestTheFeedIgnoresAMemberItDoesNotDefine(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(syncEntry(1200))
	w.apiary.withMembers(0, map[string]any{"zz": map[string]any{"a": 1}})
	w.stepOK(t)
	if !intervalIs(w, "1200") || !cursorIs(w, "c_1") {
		t.Errorf("the interval or the cursor is wrong")
	}
}

// TestAnEntryWhoseMustUnderstandListsAPointerItDoesNotDefineIsSkipped has a sync entry
// whose must_understand lists a member the sync entry does not define: it is skipped and
// acknowledged, and the entry that lists a member it defines is applied.
func TestAnEntryWhoseMustUnderstandListsAPointerItDoesNotDefineIsSkipped(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	first, second := syncEntry(1200), syncEntry(1800)
	first.MustUnderstand = []string{"/zz"}
	w.apiary.add(first)
	w.stepOK(t)
	if !intervalIs(w, "") || !cursorIs(w, "c_1") {
		t.Errorf("the entry is applied, or the cursor is not moved")
	}
	if logged := w.log.String(); !strings.Contains(logged, `"msg":"an entry of the change feed is skipped"`) || !strings.Contains(logged, `\"/zz\"`) {
		t.Errorf("the log %s", logged)
	}
	second.MustUnderstand = []string{"/interval"}
	w.apiary.add(second)
	w.stepOK(t)
	if !intervalIs(w, "1800") || !cursorIs(w, "c_2") {
		t.Errorf("the entry that lists /interval is not applied")
	}
}

// TestAChangeRequestWithAPointerBelowDataIsCheckedAgainstTheKind has two entries: one
// lists /data/zz, which the pull-request kind does not define, and is reported refused
// with the fix first and no request to GitHub; the other lists members of the data that
// the adapter reads, and opens its draft.
func TestAChangeRequestWithAPointerBelowDataIsCheckedAgainstTheKind(t *testing.T) {
	w := newChangeWired(t)
	refused := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
	refused.MustUnderstand = []string{"/title", "/data/branch", "/data/zz"}
	checkEntries(t, refused)
	w.apiary.add(refused)
	w.stepOK(t)
	detail := detailOf(w, 0)
	want := github.FixUndefinedData + ` The entry lists "/data/zz", which this adapter does not define.`
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || detail != want || utf8.RuneCountInString(github.FixUndefinedData) > 100 || utf8.RuneCountInString(detail) > 1000 {
		t.Errorf("reports %v, detail %q", r, detail)
	}
	if len(w.gh.requests) != 0 || len(w.apiary.replies()) != 0 || !cursorIs(w, "c_1") {
		t.Errorf("GitHub was asked %v, replies %+v", w.gh.requests, w.apiary.replies())
	}

	w = newChangeWired(t)
	applied := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
	applied.MustUnderstand = []string{"/data/branch", "/data/base/commit", "/data/commits/1/step", "/data/draft/action", "/data/earlier_commits", "/data"}
	checkEntries(t, applied)
	w.apiary.add(applied)
	w.stepOK(t)
	if len(w.gh.pullRequests("acme/widgets")) != 1 || len(w.apiary.replies()) != 1 || len(w.apiary.changeReports()) != 0 {
		t.Errorf("pull requests %d, replies %d, reports %v", len(w.gh.pullRequests("acme/widgets")), len(w.apiary.replies()), w.apiary.changeReports())
	}
}

// TestAChangeRequestWithAPointerOfTheEntryItDoesNotDefineIsRefused lists a member of the
// entry that the contract does not define: the report is the contract's text, which
// starts with the fix, and the entry is not applied.
func TestAChangeRequestWithAPointerOfTheEntryItDoesNotDefineIsRefused(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
	entry.MustUnderstand = []string{"/target/extra"}
	w.apiary.add(entry)
	w.stepOK(t)
	want := `Use an adapter that defines "/target/extra". The entry lists it in must_understand, and this adapter does not define it.`
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || detailOf(w, 0) != want {
		t.Errorf("reports %v, detail %q", r, detailOf(w, 0))
	}
	if len(w.gh.requests) != 0 || len(w.apiary.replies()) != 0 || !cursorIs(w, "c_1") {
		t.Errorf("GitHub was asked %v, replies %+v", w.gh.requests, w.apiary.replies())
	}
}

// TestTheDetailOfARefusedPointerIsOneShortLine lists a pointer of 250 control characters,
// below data and not: the detail has at most 1000 characters, no control character and no
// line break.
func TestTheDetailOfARefusedPointerIsOneShortLine(t *testing.T) {
	for _, pointer := range []string{"/data/" + strings.Repeat("\x01", 240), "/" + strings.Repeat("\n", 250), "/data/" + strings.Repeat("ü", 240)} {
		w := newChangeWired(t)
		entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
		entry.MustUnderstand = []string{pointer}
		w.apiary.add(entry)
		w.stepOK(t)
		detail := detailOf(w, 0)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || detail == "" || utf8.RuneCountInString(detail) > 1000 || strings.ContainsFunc(detail, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			t.Errorf("%.20q: reports %v, detail %q", pointer, r, detail)
		}
	}
}

// TestAPreviousWithOnlyAnUnknownMemberReadsAsEmpty has a change request whose previous is
// {"zz":1}: it has no title, so the entry opens a new draft with the entry's title.
func TestAPreviousWithOnlyAnUnknownMemberReadsAsEmpty(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
	w.apiary.add(entry)
	w.apiary.withMembers(0, map[string]any{"previous": map[string]any{"zz": 1}})
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].title != testTitle || !pulls[0].draft {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "created" || len(w.apiary.changeReports()) != 0 {
		t.Errorf("the reply %+v, reports %v", d, w.apiary.changeReports())
	}
}

// TestAPreviousWithAKnownAndAnUnknownMemberReadsTheKnownOne has an update whose previous
// is {"title":"<the title of the pull request>","zz":1}: the unknown member is ignored and
// the title is read, so the title of the pull request changes to the entry's title, as it
// does while it equals previous.title.
func TestAPreviousWithAKnownAndAnUnknownMemberReadsTheKnownOne(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(changeOf(testChangeID, testTitle, "First text.", targetOf("acme/widgets", 1, openDraft)))
	w.stepOK(t)
	w.apiary.add(changeOf(testChangeID2, "Fix the widget well", "Second text.", targetOf("acme/widgets", 2, update(1))))
	w.apiary.withMembers(1, map[string]any{"previous": map[string]any{"title": testTitle, "zz": 1}})
	w.stepOK(t)
	pulls := w.gh.pullRequests("acme/widgets")
	if len(pulls) != 1 || pulls[0].title != "Fix the widget well" || !pulls[0].draft {
		t.Fatalf("pull requests %+v", pulls)
	}
	if d := w.apiary.draftsReplied()["acme/widgets"]; d == nil || d.Action != "updated" || d.Title != "Fix the widget well" || len(w.apiary.changeReports()) != 0 {
		t.Errorf("the reply %+v, reports %v", d, w.apiary.changeReports())
	}
}

// TestTheFeedReadsAPageWithMembersItDoesNotDefine reads pages as Qory Apiary may write
// them: a member of the answer and of an entry that the contract does not define is
// ignored; an entry of an unknown kind is read as its kind alone; a must_understand that
// is no list ends in an error for its entry alone; and an entry with no kind, or no
// object, or another member of the wrong type, is no feed.
func TestTheFeedReadsAPageWithMembersItDoesNotDefine(t *testing.T) {
	const head = `{"version":1,"revision":1,"cursor":"c_1",`
	page, err := checkChanges([]byte(head + `"more":true,"changes":[{"kind":"sync","interval":null,"x":1},{"kind":"label","status":["a"],"interval":"soon"},{"kind":"watch","work_item_id":"wi_1","url":"https://apiary.example.com/","must_understand":["/zz"]},{"kind":"sync","must_understand":["/interval"]}]}`))
	if err != nil || len(page.Changes) != 4 || len(page.unmet) != 4 {
		t.Fatalf("%+v %v", page, err)
	}
	if page.unmet[0] != nil || page.unmet[1] == nil || page.unmet[2] == nil || page.Changes[1].Kind != "label" || page.Changes[1].Status != "" || page.Changes[1].Interval != nil {
		t.Errorf("%+v", page)
	}
	if page.unmet[3] != nil || !slices.Equal(page.Changes[3].MustUnderstand, []string{"/interval"}) {
		t.Errorf("a list that the entry defines is lost: %+v", page.Changes[3])
	}
	// A must_understand that is no list belongs to its entry, whatever the kind: the page
	// is read, and the entry has the error of the contract's check.
	const fix = "set must_understand to a list of JSON Pointers, or leave it out"
	for _, value := range []string{`null`, `"/zz"`, `{"/zz":1}`, `5`, `["/zz",5]`} {
		for _, kind := range []string{`"kind":"sync"`, `"kind":"change_request","change_kind":"pull-request"`} {
			page, err := checkChanges([]byte(head + `"changes":[{` + kind + `,"must_understand":` + value + `}]}`))
			if err != nil || len(page.unmet) != 1 || page.unmet[0] == nil || !strings.HasPrefix(page.unmet[0].Error(), fix) {
				t.Errorf("%s %s: %+v %v", kind, value, page, err)
			}
		}
	}
	for _, body := range []string{`"changes":[{"status":"added"}]`, `"changes":[null]`, `"changes":["sync"]`, `"changes":[{"kind":"sync","interval":"soon"}]`, `"changes":[{"kind":"sync","interval":"soon","must_understand":"/zz"}]`} {
		if _, err := checkChanges([]byte(head + body + `}`)); err == nil || !strings.Contains(err.Error(), "not the feed's document") {
			t.Errorf("%s: err %v", body, err)
		}
	}
}

// TestAMustUnderstandThatIsNoListEndsInOneEntry reads a page whose sync entry has a string
// for must_understand, and whose change_request entry has an object: the sync entry is
// skipped and the change_request entry is reported refused with the fix first, the entry
// after them is applied, and the cursor moves past all three.
func TestAMustUnderstandThatIsNoListEndsInOneEntry(t *testing.T) {
	w := newChangeWired(t)
	w.apiary.add(syncEntry(1200), changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft)), syncEntry(1800))
	w.apiary.withMembers(0, map[string]any{"must_understand": "/interval"})
	w.apiary.withMembers(1, map[string]any{"must_understand": map[string]any{"/data": 1}})
	w.stepOK(t)
	if !intervalIs(w, "1800") || !cursorIs(w, "c_3") {
		t.Errorf("the interval is wrong, or the cursor is not at c_3")
	}
	if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || !strings.HasPrefix(detailOf(w, 0), "set must_understand to a list of JSON Pointers, or leave it out: ") {
		t.Errorf("reports %v, detail %q", r, detailOf(w, 0))
	}
	if len(w.gh.requests) != 0 || len(w.apiary.replies()) != 0 || strings.Count(w.log.String(), `"msg":"an entry of the change feed is skipped"`) != 1 {
		t.Errorf("GitHub was asked %v, replies %+v, log %s", w.gh.requests, w.apiary.replies(), w.log.String())
	}
}

// TestAChangeRequestWithAMalformedMustUnderstandIsRefused lists a pointer twice, 33
// pointers, and null: each entry is reported refused with the contract's text, which
// starts with the fix, and nothing is asked of GitHub.
func TestAChangeRequestWithAMalformedMustUnderstandIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		list    []string
		members map[string]any
		want    string
	}{
		{"a pointer twice", []string{"/title", "/text", "/title"}, nil, `list "/title" once in must_understand`},
		{"33 pointers", slices.Repeat([]string{"/title"}, contracts.MustUnderstandPointers+1), nil, "list at most 32 pointers in must_understand, not 33"},
		{"null", nil, map[string]any{"must_understand": nil}, "set must_understand to a list of JSON Pointers, or leave it out, not null"},
	} {
		w := newChangeWired(t)
		entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
		entry.MustUnderstand = tc.list
		w.apiary.add(entry)
		if tc.members != nil {
			w.apiary.withMembers(0, tc.members)
		}
		w.stepOK(t)
		if r := w.apiary.changeReports(); !slices.Equal(r, []string{"acme/widgets refused"}) || detailOf(w, 0) != tc.want {
			t.Errorf("%s: reports %v, detail %q", tc.name, r, detailOf(w, 0))
		}
		if len(w.gh.requests) != 0 || len(w.apiary.replies()) != 0 || !cursorIs(w, "c_1") {
			t.Errorf("%s: GitHub was asked %v, replies %+v", tc.name, w.gh.requests, w.apiary.replies())
		}
	}
}

// TestACommentWhoseMustUnderstandListsAPointerItDoesNotDefineIsSkipped has a comment
// entry, a known kind other than sync, and a work_item entry with a status serve does not
// know, each with an undefined pointer: both are skipped and acknowledged, nothing is
// posted or reported, and the page is not refused.
func TestACommentWhoseMustUnderstandListsAPointerItDoesNotDefineIsSkipped(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	comment := commentEntry("acme/widgets", 7)
	comment.MustUnderstand = []string{"/zz"}
	shelved := contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "shelved", MustUnderstand: []string{"/zz"}}
	w.apiary.add(comment, shelved)
	w.stepOK(t)
	if !cursorIs(w, "c_2") || len(w.apiary.reports()) != 0 || len(w.apiary.changeReports()) != 0 || len(w.gh.requests) != 0 {
		t.Errorf("the cursor is not at c_2, or a report or a request was sent: %v %v", w.apiary.reports(), w.gh.requests)
	}
	logged := w.log.String()
	for _, kind := range []string{"comment", "work_item"} {
		if !strings.Contains(logged, `"msg":"an entry of the change feed is skipped","kind":"`+kind+`"`) {
			t.Errorf("the log has no skipped %s: %s", kind, logged)
		}
	}
}

// TestASkippedEntryStaysDoneWhenThePageIsReadAgain has a skipped sync entry before a
// comment entry whose post fails: the page is read twice, and the skipped entry is
// logged once and applies nothing.
func TestASkippedEntryStaysDoneWhenThePageIsReadAgain(t *testing.T) {
	w := newChangeWired(t)
	setGitHub(w.gh, func(f *fakeGitHub) { f.commentStatus, f.commentAnswer = 502, `{"message":"Bad Gateway"}` })
	skipped := syncEntry(900)
	skipped.MustUnderstand = []string{"/zz"}
	w.apiary.add(skipped, commentEntry("acme/widgets", 7))
	for range 2 {
		if err := w.feed.step(context.Background()); err == nil {
			t.Fatal("the comment fails, but the step passed")
		}
	}
	if n := strings.Count(w.log.String(), `"msg":"an entry of the change feed is skipped"`); n != 1 || !intervalIs(w, "") || !cursorIs(w, "") {
		t.Errorf("%d skipped lines, interval unset %v, cursor unset %v", n, intervalIs(w, ""), cursorIs(w, ""))
	}
}

// TestTheDetailOfACutPointerEndsWithTheCutMark lists a pointer below data of 106
// characters: the detail has its first 64 characters, then "...", closes the quote, and
// ends with the sentence of the refusal.
func TestTheDetailOfACutPointerEndsWithTheCutMark(t *testing.T) {
	w := newChangeWired(t)
	entry := changeOf(testChangeID, testTitle, "Text.", targetOf("acme/widgets", 2, openDraft))
	pointer := "/data/" + strings.Repeat("z", 100)
	entry.MustUnderstand = []string{pointer}
	w.apiary.add(entry)
	w.stepOK(t)
	want := github.FixUndefinedData + ` The entry lists "` + pointer[:maxLogged] + `...", which this adapter does not define.`
	if detail := detailOf(w, 0); detail != want {
		t.Errorf("detail %q, want %q", detail, want)
	}
}

// TestAnEntryWithAnUnknownStatusIsStillRefusedWhole checks that a work_item entry with a
// status serve does not know still stops its page, so the skip is for kinds alone.
func TestAnEntryWithAnUnknownStatusIsStillRefusedWhole(t *testing.T) {
	w := newWired(t, filepath.Join(t.TempDir(), "state"))
	w.apiary.add(contracts.Change{Kind: contracts.ChangeWorkItem, WorkItemID: "wi_42", Ref: itemOf("acme/widgets", 7), Status: "shelved", URL: "https://apiary.example.com/work-items/wi_42"})
	var u *unknownChange
	if err := w.feed.step(context.Background()); !errors.As(err, &u) || u.status != "shelved" {
		t.Errorf("err %v", err)
	}
}
