package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"unicode"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// pullRequestSchema is testdata/pull-request.schema.json compiled: the schema of the
// pull-request artifact type, a copy of the pull-request schema of the Qory harness
// (modules/software-factory/skills/running-a-software-workflow/schemas/). Copy it again
// when the schema changes.
func pullRequestSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	b, err := os.ReadFile("testdata/pull-request.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	const id = "https://schemas.example/pull-request.schema.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestParsePullRequestDataAgreesWithTheTypesSchema: for each change of a member that the
// adapter reads (branch, base_branch, head, base, commits, steps, earlier_commits,
// draft), the data is valid by the schema of the pull-request type if and only if
// [ParsePullRequestData] accepts it. The members that the adapter does not read (target,
// title, text, the system of an address, a member that the schema does not define) are
// left alone, so a case of them is not here.
func TestParsePullRequestDataAgreesWithTheTypesSchema(t *testing.T) {
	schema := pullRequestSchema(t)
	set := func(path ...any) func(m map[string]any) {
		return func(m map[string]any) {
			v := path[len(path)-1]
			var at any = m
			for _, key := range path[:len(path)-2] {
				switch k := key.(type) {
				case string:
					at = at.(map[string]any)[k]
				case int:
					at = at.([]any)[k]
				}
			}
			switch k := path[len(path)-2].(type) {
			case string:
				if v == absent {
					delete(at.(map[string]any), k)
				} else {
					at.(map[string]any)[k] = v
				}
			case int:
				at.([]any)[k] = v
			}
		}
	}
	type probe struct {
		name string
		edit func(m map[string]any)
	}
	var probes []probe
	add := func(name string, edit func(m map[string]any)) { probes = append(probes, probe{name, edit}) }
	add("no change", nil)
	hex := func(n int) string { return strings.Repeat("a", n) }
	lines := []struct{ name, value string }{
		{"ordinary", "ok"},
		{"empty", ""},
		{"a space", "a b"},
		{"a tab", "a\tb"},
		{"U+0007", "a\u0007b"},
		{"U+007F", "a\u007fb"},
		{"U+0085", "a\u0085b"},
		{"U+00AD", "a\u00adb"},
		{"U+200B", "a\u200bb"},
		{"U+200C", "a\u200cb"},
		{"U+200D", "a\u200db"},
		{"U+200E", "a\u200eb"},
		{"U+2028", "a\u2028b"},
		{"U+2029", "a\u2029b"},
		{"U+202E", "a\u202eb"},
		{"U+2060", "a\u2060b"},
		{"U+2065", "a\u2065b"},
		{"U+206A", "a\u206ab"},
		{"U+FEFF", "a\ufeffb"},
		{"U+FFFC", "a\ufffcb"},
		{"U+110BD", "a\U000110bdb"},
		{"U+1D173", "a\U0001d173b"},
		{"U+E0001", "a\U000e0001b"},
		{"U+E0041", "a\U000e0041b"},
		{"U+E007F", "a\U000e007fb"},
		{"U+E0080", "a\U000e0080b"},
		{"a ZWJ emoji", "\U0001f468\u200d\U0001f469"},
		{"non-ASCII letters", "\u65e5\u672c\u8a9e"},
	}
	for _, l := range lines {
		for _, member := range []string{"branch", "base_branch"} {
			add(member+" "+l.name, set(member, l.value))
		}
		add("a step with "+l.name, set("steps", 0, "step", l.value))
		for _, ref := range []string{"head", "base"} {
			add("the collection of "+ref+" with "+l.name, set(ref, "collection", l.value))
		}
		add("the collection of a commit with "+l.name, set("commits", 0, "collection", l.value))
	}
	for _, branch := range []string{"-a", "a/", "/a", "a..b", "a//b", "a@{b", "a.lock", "a.lock/b", "a/.b", ".a", "a.", "@", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b", "a/b", strings.Repeat("a", 255), strings.Repeat("a", 256), strings.Repeat("\u00e9", 255), strings.Repeat("\u00e9", 256)} {
		add("branch "+branch, set("branch", branch))
		add("base_branch "+branch, set("base_branch", branch))
	}
	types := func(name string, path ...any) {
		values := []any{nil, 5, true, "x", []any{}, map[string]any{}}
		if _, ok := path[len(path)-1].(string); ok {
			values = append(values, absent)
		}
		for _, v := range values {
			add(name, set(append(append([]any{}, path...), v)...))
		}
	}
	types("branch of another type", "branch")
	types("base_branch of another type", "base_branch")
	types("steps of another type", "steps")
	types("commits of another type", "commits")
	types("head of another type", "head")
	types("base of another type", "base")
	types("draft of another type", "draft")
	types("earlier_commits of another type", "earlier_commits")
	types("the collection of head of another type", "head", "collection")
	types("the address of head of another type", "head", "address")
	types("the path of head of another type", "head", "address", "path")
	types("the collection of a commit of another type", "commits", 0, "collection")
	types("the address of a commit of another type", "commits", 0, "address")
	types("the path of a commit of another type", "commits", 0, "address", "path")
	types("a commit of another type", "commits", 0)
	types("a step of another type", "steps", 0)
	types("the step of a step of another type", "steps", 0, "step")
	types("the commit of a step of another type", "steps", 0, "commit")
	for _, s := range []string{strings.Repeat("s", 128), strings.Repeat("s", 129), strings.Repeat("\u00e9", 128), strings.Repeat("\u00e9", 129), " "} {
		add("a step of "+s[:min(len(s), 3)], set("steps", 0, "step", s))
	}
	add("no steps", set("steps", absent))
	add("steps null", set("steps", nil))
	add("an empty list of steps", set("steps", []any{}))
	add("a step with a short commit", set("steps", 0, "commit", "abc"))
	add("a step with a commit in upper case", set("steps", 0, "commit", strings.ToUpper(sha(2))))
	add("a step with a commit of 64 digits", set("steps", 0, "commit", hex(64)))
	add("a step with no commit", set("steps", 0, "commit", absent))
	add("a step with no step", set("steps", 0, "step", absent))
	add("no commits", set("commits", absent))
	add("an empty list of commits", set("commits", []any{}))
	for _, p := range []string{"abc", hex(39), hex(40), hex(64), hex(41), hex(65), strings.ToUpper(hex(40)), "", strings.Repeat("g", 40), hex(40) + "\n"} {
		for _, ref := range []string{"head", "base"} {
			add(ref+" with the path "+p[:min(len(p), 5)], set(ref, "address", "path", p))
		}
		add("a commit with the path "+p[:min(len(p), 5)], set("commits", 0, "address", "path", p))
	}
	for _, c := range []string{strings.Repeat("c", 200), strings.Repeat("c", 201), strings.Repeat("\u00e9", 200), strings.Repeat("\u00e9", 201)} {
		for _, ref := range []string{"head", "base"} {
			add("the collection of "+ref+" of "+c[:3], set(ref, "collection", c))
		}
		add("the collection of a commit of "+c[:3], set("commits", 0, "collection", c))
	}
	for _, ref := range []string{"head", "base"} {
		add("the collection of "+ref+" is absent", set(ref, "collection", absent))
		add(ref+" has no address", set(ref, "address", absent))
	}
	add("the collection of a commit is absent", set("commits", 0, "collection", absent))
	add("a commit has no address", set("commits", 0, "address", absent))
	add("a commit has no path", set("commits", 0, "address", "path", absent))
	for _, n := range []json.RawMessage{json.RawMessage("1"), json.RawMessage("0"), json.RawMessage("-1"), json.RawMessage("5.0"), json.RawMessage("5.5"), json.RawMessage("1e2"), json.RawMessage("1E30"), json.RawMessage("9223372036854775808"), json.RawMessage("0.5"), json.RawMessage("1.0e0"), json.RawMessage("-5.0"), json.RawMessage("1e400"), json.RawMessage("10e-1"), json.RawMessage("15e-1")} {
		add("earlier_commits "+string(n), set("earlier_commits", n))
	}
	add("earlier_commits null", set("earlier_commits", nil))
	add("earlier_commits as a string", set("earlier_commits", "5"))
	add("no draft", set("draft", absent))
	add("draft false", set("draft", false))
	add("draft as a string", set("draft", "true"))
	agree := 0
	for _, p := range probes {
		data := pullData(func(m map[string]any) {
			// pullData sets a commits list and steps of fresh maps, so a probe edits them
			// freely.
			if p.edit != nil {
				p.edit(m)
			}
		})
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		valid := schema.Validate(doc) == nil
		_, err = ParsePullRequestData(data)
		if valid != (err == nil) {
			t.Errorf("%s: the schema says valid: %v, the adapter's error: %v", p.name, valid, err)
			continue
		}
		agree++
	}
	t.Logf("%d cases agree", agree)
	if agree < 400 {
		t.Errorf("only %d cases agree", agree)
	}
}

// absent marks a member that a probe removes.
var absent = new(int)

// TestAStoppedCharacterInAMemberIsRefusedWithItsCodePoint: U+202E, U+E0041, U+0007 and
// U+2028 in the branch, the base branch, a step, and the collection of the head, the base
// and a commit give a refusal with the code point and not the value, and U+200C and
// U+200D pass.
func TestAStoppedCharacterInAMemberIsRefusedWithItsCodePoint(t *testing.T) {
	members := map[string]func(v string) func(m map[string]any){
		"data.branch":      func(v string) func(m map[string]any) { return func(m map[string]any) { m["branch"] = "a" + v } },
		"data.base_branch": func(v string) func(m map[string]any) { return func(m map[string]any) { m["base_branch"] = "a" + v } },
		"the step of a step of data.steps": func(v string) func(m map[string]any) {
			return func(m map[string]any) { m["steps"].([]any)[0].(map[string]any)["step"] = "a" + v }
		},
		"the collection of data.head": func(v string) func(m map[string]any) {
			return func(m map[string]any) { m["head"].(map[string]any)["collection"] = "a" + v }
		},
		"the collection of data.base": func(v string) func(m map[string]any) {
			return func(m map[string]any) { m["base"].(map[string]any)["collection"] = "a" + v }
		},
		"the collection of a commit of data.commits": func(v string) func(m map[string]any) {
			return func(m map[string]any) { m["commits"].([]any)[0].(map[string]any)["collection"] = "a" + v }
		},
	}
	for name, edit := range members {
		for _, c := range []struct {
			value string
			code  string
		}{{"\u202e", "U+202E"}, {"\U000e0041", "U+E0041"}, {"\u0007", "U+0007"}, {"\u2028", "U+2028"}, {"\u0085", "U+0085"}} {
			_, err := ParsePullRequestData(pullData(edit(c.value)))
			var refused *SubmitRefused
			if !errors.As(err, &refused) || refused.Reason != ReasonRefused || refused.Fix != FixChangeData {
				t.Errorf("%s with %s: %v", name, c.code, err)
				continue
			}
			text := err.Error()
			if !strings.HasPrefix(text, FixChangeData+" ") || !strings.Contains(text, name+" has "+c.code) || strings.Contains(text, c.value) {
				t.Errorf("%s with %s: the text is %q", name, c.code, text)
			}
		}
		for _, joiner := range []string{"\u200c", "\u200d"} {
			if _, err := ParsePullRequestData(pullData(edit(joiner))); err != nil {
				t.Errorf("%s with U+%04X: %v", name, []rune(joiner)[0], err)
			}
		}
	}
	if len(FixChangeData) > 100 {
		t.Errorf("the fix is %d characters", len(FixChangeData))
	}
}

// TestLineStoppedAgreesWithTheTypesLinePattern: for every code point that is not a
// surrogate, [LineStopped] stops it if and only if a string of that code point alone is
// invalid by the line definition of the pull-request schema. A change of Go's Unicode
// data, or of the schema, that moves one code point in or out of the rule fails here.
func TestLineStoppedAgreesWithTheTypesLinePattern(t *testing.T) {
	b, err := os.ReadFile("testdata/pull-request.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	const id = "https://schemas.example/pull-request.schema.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	line, err := c.Compile(id + "#/$defs/line")
	if err != nil {
		t.Fatal(err)
	}
	checked, stopped := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		checked++
		valid := line.Validate(string(r)) == nil
		if LineStopped(r) {
			stopped++
		}
		if valid == LineStopped(r) {
			t.Errorf("U+%04X: LineStopped is %v, and the schema's line is valid: %v", r, LineStopped(r), valid)
		}
	}
	t.Logf("%d code points agree, %d of them stopped", checked, stopped)
}
