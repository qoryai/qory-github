// Package exactjson reads a JSON document of another system into a Go value, matching
// a member's name to a field's name in exact case.
package exactjson

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/qoryai/integrations/contracts"
)

// MustUnderstand returns a document of the object b that has only its must_understand
// member and its kind member, each spelled exactly and left out when b has none. A
// check of the result with contracts.CheckMustUnderstand, or CheckChangeMustUnderstand,
// reads the must_understand member that [Unmarshal] reads. No other member is copied,
// so no secret value of a document is.
//
// shortcut: the pin cf5bf941 of the contracts finds must_understand in any case, so a
// Must_Understand beside it could replace it, replace this copy once the integrations
// pin includes the exact-case readers, integrations a0a92400 or later.
func MustUnderstand(b []byte) ([]byte, error) {
	var doc struct {
		MustUnderstand jsontext.Value `json:"must_understand"`
		Kind           jsontext.Value `json:"kind"`
	}
	if err := Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := []byte("{")
	for _, m := range []struct {
		name  string
		value jsontext.Value
	}{{contracts.MustUnderstand, doc.MustUnderstand}, {"kind", doc.Kind}} {
		if len(m.value) == 0 {
			continue
		}
		if len(out) > 1 {
			out = append(out, ',')
		}
		out = append(out, '"')
		out = append(out, m.name...)
		out = append(out, '"', ':')
		out = append(out, m.value...)
	}
	return append(out, '}'), nil
}

// Unmarshal reads the one JSON value in b, with nothing but white space after it, into v.
// A member matches a field only when the names are equal letter for letter, so Token does
// not fill token, as it does for [encoding/json.Unmarshal]. A member that v has no field
// for is ignored. A name repeated in an object keeps its last value, as in
// [encoding/json.Unmarshal].
//
// The contracts' types are read exactly here only because this is encoding/json/v2.
// Once the integrations pin includes the exact-case readers, integrations a0a92400 or
// later, encoding/json is exact too, and this package can go.
func Unmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v, jsontext.AllowDuplicateNames(true))
}
