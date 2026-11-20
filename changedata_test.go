package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func sha(n int) string { return fmt.Sprintf("%040x", n) }

// pullData is the data of a change request with two commits, the draft draft (a JSON
// object, or "" for none), and the members of extra set after it.
func pullData(draft string, mutate func(m map[string]any)) json.RawMessage {
	m := map[string]any{
		"branch": "qory/wi_42",
		"base":   map[string]any{"commit": sha(1), "branch": "main"},
		"commit": sha(3),
		"commits": []any{
			map[string]any{"commit": sha(2), "step": "deliverable:d-1"},
			map[string]any{"commit": sha(3), "step": "fix:f1"},
		},
	}
	if draft != "" {
		m["draft"] = json.RawMessage(draft)
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return b
}

// TestParsePullRequestDataReadsTheMembers: the branch, the base, the commits and the
// draft are read; a draft's number is read from a whole number in any JSON form.
func TestParsePullRequestDataReadsTheMembers(t *testing.T) {
	d, err := ParsePullRequestData(pullData(`{"action":"update","number":34.0}`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.Branch != "qory/wi_42" || d.BaseBranch != "main" || d.BaseCommit != sha(1) || len(d.Commits) != 2 || d.Commits[1] != sha(3) || d.Draft == nil || d.Draft.Number != 34 {
		t.Errorf("%+v", d)
	}
	d, err = ParsePullRequestData(pullData(`{"action":"open"}`, nil))
	if err != nil || d.Draft == nil || d.Draft.Number != 0 {
		t.Errorf("open: %+v, %v", d, err)
	}
	d, err = ParsePullRequestData(pullData("", func(m map[string]any) { m["base"] = map[string]any{"commit": sha(1)} }))
	if err != nil || d.Draft != nil || d.BaseBranch != "" {
		t.Errorf("no draft, no base branch: %+v, %v", d, err)
	}
	d, err = ParsePullRequestData(pullData(`{"action":"update","number":9223372036854775807}`, nil))
	if err != nil || d.Draft.Number != 9223372036854775807 {
		t.Errorf("the largest number: %+v, %v", d, err)
	}
	d, err = ParsePullRequestData(pullData(`{"action":"update","number":3.4e1}`, nil))
	if err != nil || d.Draft.Number != 34 {
		t.Errorf("an exponent: %+v, %v", d, err)
	}
	d, err = ParsePullRequestData(pullData(`{"action":"update","number":9007199254740993.0}`, nil))
	if err != nil || d.Draft.Number != 9007199254740993 {
		t.Errorf("a number past 2^53: %+v, %v", d, err)
	}
}

// TestParsePullRequestDataRefusesEachBrokenRule: each rule of the data is refused, as
// refused, with the fix first and no value in the text.
func TestParsePullRequestDataRefusesEachBrokenRule(t *testing.T) {
	many := func(n int) []any {
		var out []any
		for i := range n {
			out = append(out, map[string]any{"commit": sha(2 + i), "step": "s"})
		}
		return out
	}
	set := func(k string, v any) func(m map[string]any) { return func(m map[string]any) { m[k] = v } }
	secret := "SECRET-VALUE"
	for _, tc := range []struct {
		name  string
		draft string
		edit  func(m map[string]any)
		raw   string
		want  string
	}{
		{"a branch with a space", "", set("branch", "qory/wi 42"), "", "data.branch"},
		{"a branch with two dots", "", set("branch", "a..b"), "", "data.branch"},
		{"a branch that ends in .lock", "", set("branch", "a.lock"), "", "data.branch"},
		{"a branch of 256 characters", "", set("branch", strings.Repeat("a", 256)), "", "data.branch"},
		{"a branch that is @", "", set("branch", "@"), "", "data.branch"},
		{"a base branch with a colon", "", set("base", map[string]any{"commit": sha(1), "branch": "a:b"}), "", "data.base.branch"},
		{"an empty base branch", "", set("base", map[string]any{"commit": sha(1), "branch": ""}), "", "data.base.branch"},
		{"a null base branch", "", nil, `{"branch":"qory/wi_42","base":{"commit":"` + sha(1) + `","branch":null},"commit":"` + sha(3) + `","commits":[{"commit":"` + sha(3) + `","step":"s"}]}`, "data.base.branch"},
		{"a short base commit", "", set("base", map[string]any{"commit": "abc", "branch": "main"}), "", "data.base.commit"},
		{"no base", "", set("base", nil), "", "data.base.commit"},
		{"a head that is not a commit", "", set("commit", secret), "", "data.commit"},
		{"a head that is not the last commit", "", set("commit", sha(9)), "", "does not end in"},
		{"no commits", "", set("commits", []any{}), "", "not 1 to 100"},
		{"101 commits", "", func(m map[string]any) { m["commits"] = many(101); m["commit"] = sha(102) }, "", "not 1 to 100"},
		{"a commit in upper case", "", func(m map[string]any) {
			m["commits"] = []any{map[string]any{"commit": strings.ToUpper(sha(10)), "step": "s"}}
			m["commit"] = sha(10)
		}, "", "a commit of data.commits"},
		{"a step of 129 characters", "", set("commits", []any{map[string]any{"commit": sha(3), "step": strings.Repeat("s", 129)}}), "", "the step"},
		{"an empty step", "", set("commits", []any{map[string]any{"commit": sha(3), "step": ""}}), "", "the step"},
		{"a step with U+0000", "", set("commits", []any{map[string]any{"commit": sha(3), "step": "a\u0000b"}}), "", "the step"},
		{"earlier_commits 0", "", func(m map[string]any) { m["commits"] = many(100); m["commit"] = sha(101); m["earlier_commits"] = 0 }, "", "data.earlier_commits"},
		{"earlier_commits as a string", "", func(m map[string]any) { m["commits"] = many(100); m["commit"] = sha(101); m["earlier_commits"] = "3" }, "", "data.earlier_commits"},
		{"earlier_commits past int64", "", func(m map[string]any) {
			m["commits"] = many(100)
			m["commit"] = sha(101)
			m["earlier_commits"] = json.RawMessage("9223372036854775808")
		}, "", "data.earlier_commits"},
		{"earlier_commits with 99 commits", "", func(m map[string]any) {
			m["commits"] = many(99)
			m["commit"] = sha(100)
			m["earlier_commits"] = 5
		}, "", "exactly 100"},
		{"a draft without a base branch", `{"action":"open"}`, set("base", map[string]any{"commit": sha(1)}), "", "data.base.branch"},
		{"an open draft with a number", `{"action":"open","number":3}`, nil, "", "data.draft.number is set"},
		{"an update without a number", `{"action":"update"}`, nil, "", "data.draft.number is not"},
		{"an update of number 0", `{"action":"update","number":0}`, nil, "", "data.draft.number is not"},
		{"an update with a fraction", `{"action":"update","number":1.5}`, nil, "", "data.draft.number is not"},
		{"an update past int64", `{"action":"update","number":9223372036854775808}`, nil, "", "data.draft.number is not"},
		{"an update of a string number", `{"action":"update","number":"4"}`, nil, "", "data.draft.number is not"},
		{"an open draft with a null number", `{"action":"open","number":null}`, nil, "", "data.draft.number is set"},
		{"an update of 1.00000000000000000001", `{"action":"update","number":1.00000000000000000001}`, nil, "", "data.draft.number is not"},
		{"an update of 1E400", `{"action":"update","number":1E400}`, nil, "", "data.draft.number is not"},
		{"an update of -0", `{"action":"update","number":-0}`, nil, "", "data.draft.number is not"},
		{"an update of 9223372036854775808.0", `{"action":"update","number":9223372036854775808.0}`, nil, "", "data.draft.number is not"},
		{"a draft of the action close", `{"action":"close"}`, nil, "", "data.draft.action"},
		{"a null draft", "", nil, `{"branch":"qory/wi_42","base":{"commit":"` + sha(1) + `","branch":"main"},"commit":"` + sha(3) + `","commits":[{"commit":"` + sha(3) + `","step":"s"}],"draft":null}`, "data.draft is not an object"},
		{"a draft that is a number", "", nil, `{"branch":"qory/wi_42","base":{"commit":"` + sha(1) + `","branch":"main"},"commit":"` + sha(3) + `","commits":[{"commit":"` + sha(3) + `","step":"s"}],"draft":5}`, "data.draft is not an object"},
		{"data that is an array", "", nil, `[]`, "not a JSON object"},
		{"data that is null", "", nil, `null`, "not a JSON object"},
		{"a branch that is a number", "", nil, `{"branch": 5}`, "not a JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := json.RawMessage(tc.raw)
			if tc.raw == "" {
				data = pullData(tc.draft, tc.edit)
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

// TestAWholeNumberIsReadExactlyOrRefused: a draft number written with a zero fraction or an
// exponent is the integer it equals, with no digit rounded, as 2^53+1 shows; a number that
// is not whole, or past the int64 range, is refused.
func TestAWholeNumberIsReadExactlyOrRefused(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"34", 34, true},
		{"34.0", 34, true},
		{"1e2", 100, true},
		{"0.5e1", 5, true},
		{"3.4E+1", 34, true},
		{"9007199254740993", 9007199254740993, true},
		{"9007199254740993.0", 9007199254740993, true},
		{"9.007199254740993e15", 9007199254740993, true},
		{"9223372036854775807.0", 9223372036854775807, true},
		{"1.00000000000000000001", 0, false},
		{"1.5", 0, false},
		{"9223372036854775808", 0, false},
		{"9223372036854775808.0", 0, false},
		{"1E400", 0, false},
		{"1e1000000000", 0, false},
		{"1e-1", 0, false},
		{`"4"`, 0, false},
		{"null", 0, false},
		{"0x10", 0, false},
	} {
		if n, ok := wholeNumber(json.RawMessage(tc.in)); n != tc.want || ok != tc.ok {
			t.Errorf("%s: got %d, %v, want %d, %v", tc.in, n, ok, tc.want, tc.ok)
		}
	}
	if _, ok := wholeNumber(nil); ok {
		t.Error("a missing number is read")
	}
}

// TestUndefinedDataPointerKnowsTheMembersTheAdapterReads: a pointer to each member that
// ParsePullRequestData reads, and to each member below it, is defined; a pointer to
// another member, to a member below a scalar, or to an index that is no number, is the
// pointer returned, and a pointer that is not below data is not its concern.
func TestUndefinedDataPointerKnowsTheMembersTheAdapterReads(t *testing.T) {
	for _, p := range []string{
		"/data", "/title", "/data/branch", "/data/base", "/data/base/commit", "/data/base/branch", "/data/commit",
		"/data/commits", "/data/commits/0", "/data/commits/12/commit", "/data/commits/0/step", "/data/earlier_commits",
		"/data/draft", "/data/draft/action", "/data/draft/number",
	} {
		if got := UndefinedDataPointer([]string{p}); got != "" {
			t.Errorf("%s is read, and %q is returned", p, got)
		}
	}
	for _, p := range []string{
		"/data/", "/data/zz", "/data/base/zz", "/data/branch/zz", "/data/commits/-", "/data/commits/01", "/data/commits/zz",
		"/data/commits/0/zz", "/data/earlier_commits/0", "/data/draft/zz", "/data/draft/number/0", "/data/Branch", "/data/a~2",
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
// pointers and slices. A path has no index for a slice: "/commits/step" stands for
// "/commits/1/step".
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
// UndefinedDataPointer resolves a pointer through, to rawData and rawDraft by their json
// tags: a member added to one and not the others fails the test. The draft member of
// rawData is raw JSON that rawDraft reads.
func TestDataMembersMatchTheMembersParsePullRequestDataReads(t *testing.T) {
	read := memberPaths(reflect.TypeFor[rawData](), "")
	i := slices.Index(read, "/draft")
	if i < 0 {
		t.Fatalf("rawData has no draft member: %v", read)
	}
	read = slices.Replace(read, i, i+1, memberPaths(reflect.TypeFor[rawDraft](), "/draft")...)
	defined := memberPaths(reflect.TypeFor[dataMembers](), "")
	slices.Sort(read)
	slices.Sort(defined)
	if !slices.Equal(read, defined) {
		t.Errorf("rawData and rawDraft have the members %v, and dataMembers has %v", read, defined)
	}
}

// TestParsePullRequestDataMatchesMemberNamesInExactCase has data with Branch beside
// branch, and Number beside number in the draft: the member in other case is ignored,
// whichever comes first, and a name in other case alone is a member that is missing.
func TestParsePullRequestDataMatchesMemberNamesInExactCase(t *testing.T) {
	data := string(pullData(`{"action":"open","Number":5}`, nil))
	for name, doc := range map[string]string{
		"before": `{"Branch":"other",` + data[1:],
		"after":  data[:len(data)-1] + `,"Branch":"other"}`,
	} {
		d, err := ParsePullRequestData(json.RawMessage(doc))
		if err != nil || d.Branch != "qory/wi_42" || d.Draft == nil || d.Draft.Number != 0 {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
	if _, err := ParsePullRequestData(pullData("", func(m map[string]any) { m["Branch"] = m["branch"]; delete(m, "branch") })); err == nil {
		t.Error("a Branch is the branch")
	}
	if _, err := ParsePullRequestData(pullData(`{"Action":"open"}`, nil)); err == nil {
		t.Error("an Action is the action of the draft")
	}
}

// TestParsePullRequestDataRefusesARepeatedMember has data that repeats a member, with the
// same value or another, at the top, below base and in the draft: the data stops at the
// first reading.
func TestParsePullRequestDataRefusesARepeatedMember(t *testing.T) {
	data := string(pullData(`{"action":"open"}`, nil))
	for name, doc := range map[string]string{
		"branch":       `{"branch":"other",` + data[1:],
		"same branch":  `{"branch":"qory/wi_42",` + data[1:],
		"base":         strings.Replace(data, `"base":{`, `"base":{"commit":"`+sha(9)+`",`, 1),
		"draft action": strings.Replace(data, `"action":"open"`, `"action":"open","action":"update"`, 1),
	} {
		d, err := ParsePullRequestData(json.RawMessage(doc))
		var refused *SubmitRefused
		if !errors.As(err, &refused) {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
}
