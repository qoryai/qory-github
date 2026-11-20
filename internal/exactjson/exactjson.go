// Package exactjson reads a JSON document of another system into a Go value, matching
// a member's name to a field's name in exact case and refusing a repeated member.
package exactjson

import "encoding/json/v2"

// Unmarshal reads the one JSON value in b, with nothing but white space after it, into v.
// A member matches a field only when the names are equal letter for letter, so Token
// does not fill token. A member that v has no field for is ignored. An object that
// repeats a name, at any depth, and a string that is not UTF-8 are errors.
//
// [encoding/json.Unmarshal] matches {"A":"x"} to a field tagged json:"a" in any case, in
// the default build of Go 1.27 too. The pinned contracts' types tag each field
// case:strict, which makes encoding/json exact in the default build, but a build with
// GOEXPERIMENT=nojsonv2 reads a member in any case through them.
func Unmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
