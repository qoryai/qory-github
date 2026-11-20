package serve

import (
	"errors"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
)

// TestReadObjectMatchesMemberNamesInExactCase reads documents that have a member whose name
// differs from a defined one in case alone: Error beside error, and Must_Understand beside
// must_understand. A name in other case is a member the contract does not define, so it is
// ignored, whichever comes first, and the exact member decides.
func TestReadObjectMatchesMemberNamesInExactCase(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{`{"Error":"connection_ended"}`, ""},
		{`{"ERROR":"connection_ended"}`, ""},
		{`{"error":"connection_suspended","Error":"connection_ended"}`, "connection_suspended"},
		{`{"Error":"connection_ended","error":"connection_suspended"}`, "connection_suspended"},
		{`{"error":"connection_suspended","error":"connection_ended"}`, "connection_ended"},
	} {
		var doc struct {
			Error string `json:"error"`
		}
		if err := readObject([]byte(tc.body), &doc, contracts.Refusal{}); err != nil || doc.Error != tc.want {
			t.Errorf("%s: error %q, %v, want %q", tc.body, doc.Error, err, tc.want)
		}
	}
	var doc struct {
		Error string `json:"error"`
	}
	// The must_understand that the document spells right is the one that is checked: a
	// pointer in it that the type does not define refuses the document, and a pointer in
	// another spelling of the name is ignored.
	if err := readObject([]byte(`{"error":"x","must_understand":["/zz"],"Must_Understand":[]}`), &doc, contracts.Refusal{}); err == nil || errors.Is(err, errNotObject) {
		t.Errorf("an unmet pointer beside an empty variant: %v", err)
	}
	if err := readObject([]byte(`{"error":"x","Must_Understand":["/zz"]}`), &doc, contracts.Refusal{}); err != nil {
		t.Errorf("a must_understand in other case is read as one: %v", err)
	}
}

// TestAFeedIsReadInExactCase has a page and an entry with a member in other case: Kind
// beside kind keeps kind, Kind alone is an entry with no kind, which refuses the page, and
// Cursor alone is a page with no cursor.
func TestAFeedIsReadInExactCase(t *testing.T) {
	const head = `{"version":1,"revision":1,"cursor":"c_1",`
	page, err := checkChanges([]byte(head + `"changes":[{"kind":"sync","Kind":"label"},{"Kind":"label","kind":"sync"}]}`))
	if err != nil || len(page.Changes) != 2 || page.Changes[0].Kind != "sync" || page.Changes[1].Kind != "sync" {
		t.Errorf("%+v, %v", page, err)
	}
	for _, body := range []string{head + `"changes":[{"Kind":"sync"}]}`, `{"version":1,"revision":1,"Cursor":"c_1","changes":[]}`, `{"version":1,"Revision":1,"cursor":"c_1","changes":[]}`} {
		if _, err := checkChanges([]byte(body)); err == nil {
			t.Errorf("%s is read", body)
		}
	}
	// An entry's must_understand in other case lists nothing.
	page, err = checkChanges([]byte(head + `"changes":[{"kind":"sync","Must_Understand":["/zz"]}]}`))
	if err != nil || len(page.unmet) != 1 || page.unmet[0] != nil {
		t.Errorf("%+v, %v", page, err)
	}
}

// TestACallIsReadInExactCase has a call's body with the member Path beside path, as the
// open schemas allow: the call reads path, and the time of a body with Time alone is none.
func TestACallIsReadInExactCase(t *testing.T) {
	members := readPublic("github.com/acme/tools", "a.md", devCommit)
	for _, extra := range []string{`,"Path":"b.md"`, `,"PATH":"b.md"`} {
		var req contracts.ReadPublic
		if !decodeCall("read-public.schema.json", []byte(callBodyAt(time.Now(), members+extra)), &req) || req.Path != "a.md" {
			t.Errorf("%s: path %q", extra, req.Path)
		}
	}
	if _, ok := callTime([]byte(`{"Time":"` + contracts.FormatTime(time.Now()) + `"}`)); ok {
		t.Error("a Time is the call's time")
	}
	if _, ok := callTime([]byte(callBodyAt(time.Now(), members))); !ok {
		t.Error("a time is not the call's time")
	}
}
