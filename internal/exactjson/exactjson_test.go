package exactjson

import "testing"

// TestUnmarshalMatchesNamesInExactCase reads objects into a struct with the field a: a
// member in other case is ignored whichever side of a it is on.
func TestUnmarshalMatchesNamesInExactCase(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"a":"x"}`, "x"},
		{`{"A":"x"}`, ""},
		{`{"A":"y","a":"x"}`, "x"},
		{`{"a":"x","A":"y"}`, "x"},
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
// the object, a member of the wrong type, a string that is not UTF-8 and an object that
// repeats a name at any depth, whatever the values: the same, different or null. A null is read as
// an object with no member, so the caller checks the first byte, see readObject.
func TestUnmarshalRefusesWhatIsNotOneObject(t *testing.T) {
	for _, body := range []string{``, `[]`, `"a"`, `5`, `{"a":"x"}{}`, `{"a":"x"} x`, `{"a":1}`, "{\"a\":\"\xff\"}", `{"a"`,
		`{"a":"x","a":"y"}`, `{"a":"x","a":"x"}`, `{"a":"x","a":null}`, `{"a":null,"a":"x"}`,
		`{"b":{"c":1,"c":2},"a":"x"}`, `{"must_understand":["/a"],"must_understand":["/a"]}`} {
		var doc struct {
			A string `json:"a"`
		}
		if err := Unmarshal([]byte(body), &doc); err == nil {
			t.Errorf("%q is read as %+v", body, doc)
		}
	}
}
