package github

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
)

// limits are what Qory Apiary takes, read from the integrations contract's schemas
// themselves, so the adapter and the contract cannot drift apart: the most characters
// of each text and ref, Unicode code points as JSON Schema counts them, the most
// labels, the most entries of each request, and the pattern a target's system fits.
type limits struct {
	ref, url, title, body, name, label, labels, stateReason, path int
	items, comments, collections                                  int
	system                                                        *regexp.Regexp
}

// contractLimits are the limits, read once. The schemas are embedded in the contracts
// package, so a limit missing from them is the program's fault, and it panics.
var contractLimits = sync.OnceValue(func() limits {
	defs := schema("definitions.schema.json", "$defs")
	return limits{
		ref:         number(defs, "ref", "maxLength"),
		url:         number(defs, "url", "maxLength"),
		title:       number(defs, "title", "maxLength"),
		body:        number(defs, "body", "maxLength"),
		name:        number(defs, "person", "properties", "name", "maxLength"),
		label:       number(defs, "labels", "items", "maxLength"),
		labels:      number(defs, "labels", "maxItems"),
		stateReason: number(defs, "state_reason", "maxLength"),
		path:        number(defs, "target", "properties", "path", "maxLength"),
		system:      regexp.MustCompile(text(defs, "target", "properties", "system", "pattern")),
		items:       number(schema("source-items.schema.json", "properties"), "items", "maxItems"),
		comments:    number(schema("source-item-comments.schema.json", "properties"), "comments", "maxItems"),
		collections: number(schema("source-collections.schema.json", "properties"), "collections", "maxItems"),
	}
})

// schema is the member at path of the contract's schema name.
func schema(name string, path ...string) any {
	doc, err := contracts.Document(name)
	if err != nil {
		panic(err)
	}
	return member(doc, path...)
}

// member is the member at path of a schema's document.
func member(doc any, path ...string) any {
	for _, p := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			panic(fmt.Sprintf("the contract's schema has no %v", path))
		}
		doc = m[p]
	}
	return doc
}

// number is the integer at path.
func number(doc any, path ...string) int {
	n, ok := member(doc, path...).(json.Number)
	if !ok {
		panic(fmt.Sprintf("the contract's schema has no number at %v", path))
	}
	i, err := n.Int64()
	if err != nil {
		panic(err)
	}
	return int(i)
}

// text is the string at path.
func text(doc any, path ...string) string {
	s, ok := member(doc, path...).(string)
	if !ok {
		panic(fmt.Sprintf("the contract's schema has no string at %v", path))
	}
	return s
}

// cut is s cut to at most n characters, on a character's boundary.
func cut(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// tooLong is whether s has more than n characters.
func tooLong(s string, n int) bool { return utf8.RuneCountInString(s) > n }
