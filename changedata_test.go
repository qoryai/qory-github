package github

import (
	"encoding/json"
	"errors"
	"fmt"
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
}

// TestParsePullRequestDataRefusesEachBrokenRule: each rule of the removed submission entry
// is refused, as refused, with the fix first and no value in the text.
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
		{"a draft of the action close", `{"action":"close"}`, nil, "", "data.draft.action"},
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
