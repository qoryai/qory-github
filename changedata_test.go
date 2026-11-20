package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/integrations/contracts"
)

func sha(n int) string { return fmt.Sprintf("%040x", n) }

// commitRef is the commit id as the pull-request type writes a commit: a reference whose
// address path is the id.
func commitRef(id string) map[string]any {
	return map[string]any{"collection": "R_1001", "address": map[string]any{"system": "code.example.com", "path": id}}
}

// steps are the steps of the commits sha(2) to sha(n), in the form of the type.
func stepsOf(n int) []any {
	var out []any
	for i := 2; i <= n; i++ {
		out = append(out, map[string]any{"commit": sha(i), "step": "deliverable:d-" + fmt.Sprint(i-1)})
	}
	return out
}

// commitsTo are the commits sha(2) to sha(n).
func commitsTo(n int) []any {
	var out []any
	for i := 2; i <= n; i++ {
		out = append(out, commitRef(sha(i)))
	}
	return out
}

// pullData is the data of a change request with two commits, as the pull-request type
// writes it, a draft wanted, and mutate applied.
func pullData(mutate func(m map[string]any)) json.RawMessage {
	m := map[string]any{
		"target":      map[string]any{"collection": "R_1001"},
		"title":       "Show delivery dates",
		"text":        "Text.",
		"branch":      "qory/wi_42",
		"base_branch": "main",
		"base":        commitRef(sha(1)),
		"head":        commitRef(sha(3)),
		"commits":     commitsTo(3),
		"steps":       stepsOf(3),
		"draft":       true,
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return b
}

// TestParsePullRequestDataReadsTheMembers: the branch, the base, the commits and the
// draft are read from the members of the pull-request type; the members of the envelope
// that the data repeats are ignored.
func TestParsePullRequestDataReadsTheMembers(t *testing.T) {
	d, err := ParsePullRequestData(pullData(nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.Branch != "qory/wi_42" || d.BaseBranch != "main" || d.BaseCommit != sha(1) || len(d.Commits) != 2 || d.Commits[0] != sha(2) || d.Commits[1] != sha(3) || !d.Draft {
		t.Errorf("%+v", d)
	}
	d, err = ParsePullRequestData(pullData(func(m map[string]any) { m["draft"] = false }))
	if err != nil || d.Draft {
		t.Errorf("no draft wanted: %+v, %v", d, err)
	}
}

// TestParsePullRequestDataHasNoRuleThatTheSchemaLacks: the schema of the type states no
// upper limit of commits, no relation between head and the last commit, and no relation
// between earlier_commits and the number of commits, so the adapter accepts each. The
// commits that it reads are those of commits, in order: head and earlier_commits do not
// change them.
func TestParsePullRequestDataHasNoRuleThatTheSchemaLacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
		want int
	}{
		{"a head that is not the last commit", func(m map[string]any) { m["head"] = commitRef(sha(9)) }, 2},
		{"earlier_commits 5 with 2 commits", func(m map[string]any) { m["earlier_commits"] = 5 }, 2},
		{"earlier_commits 5.0 with 2 commits", func(m map[string]any) { m["earlier_commits"] = json.RawMessage("5.0") }, 2},
		{"101 commits", func(m map[string]any) { m["commits"], m["steps"] = commitsTo(102), stepsOf(102) }, 101},
		{"3000 commits", func(m map[string]any) { m["commits"], m["steps"] = commitsTo(3001), stepsOf(3001) }, 3000},
	} {
		d, err := ParsePullRequestData(pullData(tc.edit))
		if err != nil || len(d.Commits) != tc.want || d.Commits[0] != sha(2) || d.Commits[tc.want-1] != sha(tc.want+1) {
			t.Errorf("%s: %d commits, %v", tc.name, len(d.Commits), err)
		}
	}
}

// TestParsePullRequestDataReadsTheContractsFixtures: the data of every change request of
// the kind pull-request in the contract's fixtures is read, and each fixture's draft is
// what the entry has.
func TestParsePullRequestDataReadsTheContractsFixtures(t *testing.T) {
	names, err := fs.Glob(contracts.FS, "fixtures/adapter/changes/change-request-pull-request*.json")
	if err != nil || len(names) < 5 {
		t.Fatalf("%d fixtures, %v", len(names), err)
	}
	for _, name := range names {
		b, err := fs.ReadFile(contracts.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Changes []struct {
				Kind string          `json:"kind"`
				Data json.RawMessage `json:"data"`
			} `json:"changes"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			t.Fatal(err)
		}
		for i, c := range page.Changes {
			if c.Kind != "change_request" {
				continue
			}
			var want struct {
				Draft bool `json:"draft"`
			}
			json.Unmarshal(c.Data, &want)
			d, err := ParsePullRequestData(c.Data)
			if err != nil || d.Draft != want.Draft || len(d.Commits) == 0 {
				t.Errorf("%s, entry %d: %+v, %v", name, i, d, err)
			}
		}
	}
}

// TestParsePullRequestDataRefusesEachBrokenRule: each rule of the data is refused, as
// refused, with the fix first and no value in the text.
func TestParsePullRequestDataRefusesEachBrokenRule(t *testing.T) {
	set := func(k string, v any) func(m map[string]any) { return func(m map[string]any) { m[k] = v } }
	secret := "SECRET-VALUE"
	many := func(n int, mutate func(m map[string]any)) func(m map[string]any) {
		return func(m map[string]any) {
			m["commits"], m["steps"], m["head"] = commitsTo(n+1), stepsOf(n+1), commitRef(sha(n+1))
			if mutate != nil {
				mutate(m)
			}
		}
	}
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
		raw  string
		want string
	}{
		{"a branch with a space", set("branch", "qory/wi 42"), "", "data.branch"},
		{"a branch with two dots", set("branch", "a..b"), "", "data.branch"},
		{"a branch that ends in .lock", set("branch", "a.lock"), "", "data.branch"},
		{"a branch of 256 characters", set("branch", strings.Repeat("a", 256)), "", "data.branch"},
		{"a branch that is @", set("branch", "@"), "", "data.branch"},
		{"no branch", set("branch", nil), "", "data.branch"},
		{"a base branch with a colon", set("base_branch", "a:b"), "", "data.base_branch"},
		{"an empty base branch", set("base_branch", ""), "", "data.base_branch"},
		{"no base branch", set("base_branch", nil), "", "data.base_branch"},
		{"a short base commit", set("base", commitRef("abc")), "", "data.base is not a commit"},
		{"a base without an address", set("base", map[string]any{"collection": "R_1001"}), "", "data.base is not a commit"},
		{"no base", set("base", nil), "", "data.base is not a commit"},
		{"a head that is not a commit", set("head", commitRef(secret)), "", "data.head is not a commit"},
		{"no head", set("head", nil), "", "data.head is not a commit"},
		{"no commits", func(m map[string]any) { m["commits"] = []any{} }, "", "data.commits has no commit"},
		{"a commit in upper case", set("commits", []any{commitRef(strings.ToUpper(sha(10)))}), "", "a commit of data.commits"},
		{"a commit that is a string", nil, `{"branch":"qory/wi_42","commits":["` + sha(3) + `"]}`, "not a JSON object"},
		{"a step of 129 characters", set("steps", []any{map[string]any{"commit": sha(3), "step": strings.Repeat("s", 129)}}), "", "the step"},
		{"an empty step", set("steps", []any{map[string]any{"commit": sha(3), "step": ""}}), "", "the step"},
		{"a step with U+0000", set("steps", []any{map[string]any{"commit": sha(3), "step": "a\u0000b"}}), "", "the step"},
		{"a step with a short commit", set("steps", []any{map[string]any{"commit": "abc", "step": "s"}}), "", "a step of data.steps"},
		{"earlier_commits 0", many(100, set("earlier_commits", 0)), "", "data.earlier_commits"},
		{"earlier_commits as a string", many(100, set("earlier_commits", "3")), "", "data.earlier_commits"},
		{"earlier_commits null", many(100, set("earlier_commits", nil)), "", "data.earlier_commits"},
		{"earlier_commits 0.5", many(100, set("earlier_commits", json.RawMessage("0.5"))), "", "data.earlier_commits"},
		{"no draft", set("draft", nil), "", "data.draft is not true or false"},
		{"a draft that is a string", set("draft", "true"), "", "not a JSON object"},
		{"a draft that is an object", set("draft", map[string]any{"action": "open"}), "", "not a JSON object"},
		{"data that is an array", nil, `[]`, "not a JSON object"},
		{"data that is null", nil, `null`, "not a JSON object"},
		{"a branch that is a number", nil, `{"branch": 5}`, "not a JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := json.RawMessage(tc.raw)
			if tc.raw == "" {
				data = pullData(tc.edit)
			}
			_, err := ParsePullRequestData(data)
			var refused *SubmitRefused
			if !errors.As(err, &refused) || refused.Reason != ReasonRefused || refused.Fix != FixChangeData {
				t.Fatalf("got %v, want a refusal with the reason refused", err)
			}
			if !strings.HasPrefix(err.Error(), FixChangeData+" ") || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), secret) {
				t.Errorf("the text is %q, want the fix first, then a cause with %q and no value", err.Error(), tc.want)
			}
		})
	}
}

// TestAWholeNumberFromOneIsAcceptedOfAnySize: a JSON number that is a whole number of 1
// or more is accepted, written with a zero fraction or an exponent too, with no limit of
// size, and nothing else is.
func TestAWholeNumberFromOneIsAcceptedOfAnySize(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"1", true},
		{"34", true},
		{"34.0", true},
		{"1e2", true},
		{"0.5e1", true},
		{"3.4E+1", true},
		{"10e-1", true},
		{"100e-2", true},
		{"1.50e1", true},
		{"9007199254740993", true},
		{"9007199254740993.0", true},
		{"9.007199254740993e15", true},
		{"9223372036854775808", true},
		{"1E30", true},
		{"1e1000000000", true},
		{"1e99999999999999999999999999", true},
		{"0", false},
		{"0.0", false},
		{"0e5", false},
		{"0.0e5", false},
		{"-1", false},
		{"-5.0", false},
		{"1.00000000000000000001", false},
		{"1.5", false},
		{"5e-1", false},
		{"1e-1", false},
		{"100e-3", false},
		{"1e-99999999999999999999999999", false},
		{`"4"`, false},
		{"null", false},
		{"true", false},
		{"0x10", false},
		{"", false},
	} {
		if got := wholeFrom1(json.RawMessage(tc.in)); got != tc.ok {
			t.Errorf("%q: got %v, want %v", tc.in, got, tc.ok)
		}
	}
	if wholeFrom1(nil) {
		t.Error("a missing number is accepted")
	}
}

// TestUndefinedDataPointerKnowsTheMembersTheAdapterReads: a pointer to each member that
// the pull-request type defines and the adapter understands, and to each member below it,
// is defined; a pointer to another member, to a member below a scalar, or to an index
// that is no number, is the pointer returned, and a pointer that is not below data is not
// its concern.
func TestUndefinedDataPointerKnowsTheMembersTheAdapterReads(t *testing.T) {
	for _, p := range []string{
		"/data", "/title", "/data/title", "/data/text", "/data/target", "/data/target/collection", "/data/target/address/path", "/data/branch", "/data/base_branch", "/data/base",
		"/data/base/collection", "/data/base/address", "/data/base/address/path", "/data/head/address/system",
		"/data/commits", "/data/commits/0", "/data/commits/12/address/path", "/data/steps/0/step", "/data/steps/3/commit",
		"/data/earlier_commits", "/data/draft",
	} {
		if got := UndefinedDataPointer([]string{p}); got != "" {
			t.Errorf("%s is read, and %q is returned", p, got)
		}
	}
	for _, p := range []string{
		"/data/", "/data/zz", "/data/base/zz", "/data/branch/zz", "/data/commits/-", "/data/commits/01", "/data/commits/zz",
		"/data/commits/0/zz", "/data/earlier_commits/0", "/data/draft/zz", "/data/draft/action", "/data/draft/number",
		"/data/commit", "/data/base/commit", "/data/base/branch", "/data/commits/0/step", "/data/Branch", "/data/a~2",
	} {
		if got := UndefinedDataPointer([]string{"/data/branch", p, "/data/zz2"}); got != p {
			t.Errorf("%s is not read, and %q is returned", p, got)
		}
	}
	if got := UndefinedDataPointer([]string{"/database/zz"}); got != "" {
		t.Errorf("%q is returned for a pointer that is not below data", got)
	}
	if got := UndefinedDataPointer(nil); got != "" {
		t.Errorf("%q is returned for no pointer", got)
	}
}

// memberPaths are the JSON Pointers of the members of t, below t, through structs,
// pointers and slices. A path has no index for a slice: "/steps/step" stands for
// "/steps/1/step".
func memberPaths(t reflect.Type, prefix string) []string {
	for t.Kind() == reflect.Pointer || (t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8) {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return []string{prefix}
	}
	var out []string
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		out = append(out, memberPaths(f.Type, prefix+"/"+name)...)
	}
	return out
}

// TestDataMembersMatchTheMembersParsePullRequestDataReads ties dataMembers, which
// UndefinedDataPointer resolves a pointer through, to rawData by their json tags: a
// member added to one and not the other fails the test. dataMembers also has target,
// title and text, which the type defines and the envelope has too, so the adapter ignores
// them.
func TestDataMembersMatchTheMembersParsePullRequestDataReads(t *testing.T) {
	read := append(memberPaths(reflect.TypeFor[rawData](), ""), "/target", "/title", "/text")
	defined := memberPaths(reflect.TypeFor[dataMembers](), "")
	slices.Sort(read)
	slices.Sort(defined)
	if !slices.Equal(read, defined) {
		t.Errorf("rawData and the envelope's members are %v, and dataMembers has %v", read, defined)
	}
}

// TestParsePullRequestDataMatchesMemberNamesInExactCase has data with Branch beside
// branch: the member in other case is ignored, whichever comes first, and a name in other
// case alone is a member that is missing.
func TestParsePullRequestDataMatchesMemberNamesInExactCase(t *testing.T) {
	data := string(pullData(nil))
	for name, doc := range map[string]string{
		"before": `{"Branch":"other",` + data[1:],
		"after":  data[:len(data)-1] + `,"Branch":"other"}`,
	} {
		d, err := ParsePullRequestData(json.RawMessage(doc))
		if err != nil || d.Branch != "qory/wi_42" {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
	for _, mutate := range []func(m map[string]any){
		func(m map[string]any) { m["Branch"] = m["branch"]; delete(m, "branch") },
		func(m map[string]any) { m["Draft"] = m["draft"]; delete(m, "draft") },
		func(m map[string]any) { m["base_Branch"] = m["base_branch"]; delete(m, "base_branch") },
	} {
		if _, err := ParsePullRequestData(pullData(mutate)); err == nil {
			t.Error("a name in other case is the member")
		}
	}
}

// TestParsePullRequestDataRefusesARepeatedMember has data that repeats a member, with the
// same value or another, at the top and below head: the data stops at the first reading.
func TestParsePullRequestDataRefusesARepeatedMember(t *testing.T) {
	data := string(pullData(nil))
	for name, doc := range map[string]string{
		"branch":      `{"branch":"other",` + data[1:],
		"same branch": `{"branch":"qory/wi_42",` + data[1:],
		"draft":       `{"draft":false,` + data[1:],
		"head":        strings.Replace(data, `"head":{`, `"head":{"collection":"R_9",`, 1),
	} {
		d, err := ParsePullRequestData(json.RawMessage(doc))
		var refused *SubmitRefused
		if !errors.As(err, &refused) {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
}
