// Package exactjson reads a JSON document of another system into a Go value, matching
// a member's name to a field's name in exact case.
package exactjson

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// MustUnderstand returns a document of the object b that has only its must_understand
// member and the members named keep, each spelled exactly. contracts.CheckMustUnderstand
// finds must_understand in any case, so a Must_Understand beside must_understand could
// replace it; a check of the result reads the member that [Unmarshal] reads.
func MustUnderstand(b []byte, keep ...string) ([]byte, error) {
	var members map[string]jsontext.Value
	if err := Unmarshal(b, &members); err != nil {
		return nil, err
	}
	only := map[string]jsontext.Value{}
	for _, name := range append([]string{"must_understand"}, keep...) {
		if v, ok := members[name]; ok {
			only[name] = v
		}
	}
	return json.Marshal(only)
}

// Unmarshal reads the one JSON value in b, with nothing but white space after it, into v.
// A member matches a field only when the names are equal letter for letter, so Token does
// not fill token, as it does for [encoding/json.Unmarshal]. A member that v has no field
// for is ignored. A name repeated in an object keeps its last value, as in
// [encoding/json.Unmarshal].
func Unmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v, jsontext.AllowDuplicateNames(true))
}
