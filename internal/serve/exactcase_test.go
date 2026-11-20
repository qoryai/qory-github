package serve

import (
	"errors"
	"fmt"
	"strings"
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

// TestAMemberRepeatedInADocumentIsNoDocument has each reader of a document from Qory
// Apiary read a body that repeats a member, with the same value, another value and a
// repeated must_understand: the body is not read.
func TestAMemberRepeatedInADocumentIsNoDocument(t *testing.T) {
	// readObject: the connect pass, the setup pass, the grants and the secrets share it.
	for _, body := range []string{
		`{"error":"connection_ended","error":"connection_ended"}`,
		`{"error":"connection_ended","error":"connection_suspended"}`,
		`{"error":"x","must_understand":[],"must_understand":[]}`,
		`{"error":"x","must_understand":["/error"],"must_understand":["/error"]}`,
	} {
		var doc struct {
			Error string `json:"error"`
		}
		if err := readObject([]byte(body), &doc, contracts.Refusal{}); !errors.Is(err, errNotObject) {
			t.Errorf("readObject %s: %v", body, err)
		}
	}
	// A refusal that repeats a member is unreadable: the answer is judged by its status,
	// so a 409 and a 403 have no code, end nothing and may pass.
	for _, tc := range []struct {
		status int
		body   string
	}{
		{409, `{"error":"connection_ended","error":"connection_ended"}`},
		{409, `{"error":"connection_ended","must_understand":[],"must_understand":[]}`},
		{403, `{"error":"connection_unknown","error":"forbidden"}`},
	} {
		ended := false
		a := &Apiary{Ended: func(string) { ended = true }}
		err := a.judge("reading", &answer{status: tc.status, signed: true, body: []byte(tc.body)}, testConnection, testConnection)
		var refused *refusedError
		if !errors.As(err, &refused) || refused.code != "" || IsPermanent(err) || ended {
			t.Errorf("%d %s: err %v, ended %v", tc.status, tc.body, err, ended)
		}
	}
	// The feed: a page that repeats a member of the page, of an entry or of a member of an
	// entry stops the whole page, as a body that is not UTF-8 does.
	const head = `{"version":1,"revision":1,"cursor":"c_1",`
	for _, body := range []string{
		`{"version":1,"revision":1,"cursor":"c_1","cursor":"c_1","changes":[]}`,
		head + `"changes":[],"changes":[]}`,
		head + `"changes":[{"kind":"sync","kind":"sync"}]}`,
		head + `"changes":[{"kind":"sync","interval":1,"interval":2}]}`,
		head + `"changes":[{"kind":"sync","must_understand":[],"must_understand":[]}]}`,
		head + `"changes":[{"kind":"change_request","target":{"collection":"1","collection":"2"}}]}`,
		head + `"changes":[{"kind":"zz","a":1,"a":1}]}`,
	} {
		if page, err := checkChanges([]byte(body)); err == nil || !strings.Contains(err.Error(), "not the feed's document") || len(page.Changes) != 0 {
			t.Errorf("%s: %+v, %v", body, page, err)
		}
	}
	// The error of such a page is short: it does not quote the member's name, which can
	// be as long as the page.
	long := strings.Repeat("m", 100000)
	_, err := checkChanges([]byte(head + `"changes":[],"` + long + `":1,"` + long + `":2}`))
	if err == nil || !strings.Contains(err.Error(), "not the feed's document") || len(err.Error()) > 200 {
		t.Errorf("a page that repeats a long member: %.300v (%d characters)", err, len(fmt.Sprint(err)))
	}
	// A call: a time repeated, and a member of the call repeated. Only the callTime row is
	// new: regression guard: calls already stopped on a repeated member.
	at := contracts.FormatTime(time.Now())
	if _, ok := callTime([]byte(`{"time":"` + at + `","time":"` + at + `"}`)); ok {
		t.Error("a repeated time is the call's time")
	}
	var req contracts.ReadPublic
	for _, extra := range []string{`,"path":"a.md"`, `,"path":"b.md"`, `,"must_understand":[],"must_understand":[]`} {
		if decodeCall("read-public.schema.json", []byte(callBodyAt(time.Now(), readPublic("github.com/acme/tools", "a.md", devCommit)+extra)), &req) {
			t.Errorf("a call with %s is read", extra)
		}
	}
}
