package exactjson

import (
	"strings"
	"testing"
)

// TestUnmarshalMatchesNamesInExactCase reads objects into a struct with the field a: a
// member in other case is ignored whichever side of a it is on, a repeated name keeps
// its last value, and a repeated name whose last value is null zeroes the field.
func TestUnmarshalMatchesNamesInExactCase(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"a":"x"}`, "x"},
		{`{"A":"x"}`, ""},
		{`{"A":"y","a":"x"}`, "x"},
		{`{"a":"x","A":"y"}`, "x"},
		{`{"a":"x","a":"y"}`, "y"},
		{`{"a":"x","a":null}`, ""},
		{`{"a":null}`, ""},
		{`{"zz":1,"a":"x"}`, "x"},
		{` {"a":"x"} `, "x"},
	} {
		var doc struct {
			A string `json:"a"`
		}
		if err := Unmarshal([]byte(tc.body), &doc); err != nil || doc.A != tc.want {
			t.Errorf("%s: a is %q, %v, want %q", tc.body, doc.A, err, tc.want)
		}
	}
}

// TestUnmarshalRefusesWhatIsNotOneObject has the values that are no object, data after
// the object, a member of the wrong type and a string that is not UTF-8. A null is read as
// an object with no member, so the caller checks the first byte, see readObject.
func TestUnmarshalRefusesWhatIsNotOneObject(t *testing.T) {
	for _, body := range []string{``, `[]`, `"a"`, `5`, `{"a":"x"}{}`, `{"a":"x"} x`, `{"a":1}`, "{\"a\":\"\xff\"}", `{"a"`} {
		var doc struct {
			A string `json:"a"`
		}
		if err := Unmarshal([]byte(body), &doc); err == nil {
			t.Errorf("%q is read as %+v", body, doc)
		}
	}
}

// TestMustUnderstandKeepsTheExactMembersAlone has the copy of an object that has only the
// must_understand and the kind members, each as spelled, and no other member's value.
func TestMustUnderstandKeepsTheExactMembersAlone(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"must_understand":["/a"]}`, `{"must_understand":["/a"]}`},
		{`{"must_understand":null}`, `{"must_understand":null}`},
		{`{"must_understand":"/a"}`, `{"must_understand":"/a"}`},
		{`{}`, `{}`},
		{`{"Must_Understand":["/zz"]}`, `{}`},
		{`{"Must_Understand":["/zz"],"must_understand":["/a"]}`, `{"must_understand":["/a"]}`},
		{`{"must_understand":["/a"],"Must_Understand":["/zz"]}`, `{"must_understand":["/a"]}`},
		{`{"must_understand":["/zz"],"must_understand":["/a"]}`, `{"must_understand":["/a"]}`},
		{`{"kind":"sync","other":1}`, `{"kind":"sync"}`},
		{`{"Kind":"label","kind":"sync","must_understand":[]}`, `{"must_understand":[],"kind":"sync"}`},
		{`{"Kind":"label"}`, `{}`},
	} {
		got, err := MustUnderstand([]byte(tc.body))
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: %s, %v, want %s", tc.body, got, err, tc.want)
		}
	}
	got, err := MustUnderstand([]byte(`{"secret":"qak_0123456789","nested":{"secret":"qak_9"},"must_understand":[]}`))
	if err != nil || strings.Contains(string(got), "qak_") {
		t.Errorf("a secret value is copied: %s, %v", got, err)
	}
	for _, body := range []string{``, `[]`, `"a"`, `{"must_understand":[]}{}`, `{"kind":5`} {
		if got, err := MustUnderstand([]byte(body)); err == nil {
			t.Errorf("%q is read as %s", body, got)
		}
	}
}
