package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github/internal/exactjson"
)

// FixChangeData is the fix line for a change request whose data breaks a rule of the
// pull-request kind. The contract lists no member of data, so [ParsePullRequestData]
// checks each member it reads.
const FixChangeData = "Fix the data of the pull-request artifact type in the process, then submit again."

// FixUndefinedData is the fix line for a change request whose must_understand lists a
// pointer below data that [UndefinedDataPointer] returns.
const FixUndefinedData = "List only members that the pull-request kind defines in must_understand, or use another adapter."

// The limits of the data of a pull-request change request.
const (
	maxBranch     = 255
	maxStep       = 128
	maxCollection = 200
)

var (
	// branchShape and branchNever are git's rule for a branch name after refs/heads/: no
	// leading hyphen or slash, no space or control character, none of ~ ^ : ? * [ \, no
	// "..", "//" or "@{", no segment that starts with a dot or ends in .lock, no ending
	// dot or slash, and not @ alone.
	branchShape = regexp.MustCompile(`^[^\x00-\x20\x7f~^:?*\[\\/-][^\x00-\x20\x7f~^:?*\[\\]*$`)
	branchNever = regexp.MustCompile(`\.\.|//|@\{|(^|/)\.|\.lock(/|$)|[./]$|^@$`)
	// commitShape is a full commit id: 40 or 64 lower-case hexadecimal digits.
	commitShape = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	// numberShape is a JSON number, in the groups sign, integer part, fraction digits and
	// exponent.
	numberShape = regexp.MustCompile(`^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)
)

// PullRequestData is the data of a change request of the kind pull-request, as the
// members it has that the adapter reads: Branch, the branch the run pushed, BaseBranch
// and BaseCommit, the branch and the commit it started at, Commits, the commit ids of the
// run, oldest first, and Draft, whether the pull request is opened as a draft.
type PullRequestData struct {
	Branch     string
	BaseBranch string
	BaseCommit string
	Commits    []string
	Draft      bool
}

// reference is an object in a system, as the pull-request type writes it: the collection,
// the repository, and its address. A commit is a reference whose address.path is the
// commit id.
type reference struct {
	Collection string `json:"collection"`
	Address    *struct {
		System string `json:"system"`
		Path   string `json:"path"`
	} `json:"address"`
}

// commitID is the commit id of the reference r, "" when it has no address.
func (r *reference) commitID() string {
	if r == nil || r.Address == nil {
		return ""
	}
	return r.Address.Path
}

// rawData is the wire form of the data of a pull-request change request: the type's
// members that the adapter reads. A member the adapter does not read is ignored, the
// title and the text of the envelope's among them.
type rawData struct {
	Branch         string          `json:"branch"`
	BaseBranch     string          `json:"base_branch"`
	Head           *reference      `json:"head"`
	Base           *reference      `json:"base"`
	Commits        []reference     `json:"commits"`
	EarlierCommits json.RawMessage `json:"earlier_commits"`
	Steps          []struct {
		Commit string `json:"commit"`
		Step   string `json:"step"`
	} `json:"steps"`
	Draft *bool `json:"draft"`
}

// stopped is the refusal text for a string that has a character that the line rule of the
// type's schema stops, or "" when it has none. It has the code point, never the value.
func stopped(name, s string) string {
	i := strings.IndexFunc(s, LineStopped)
	if i < 0 {
		return ""
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return fmt.Sprintf("%s has U+%04X, which a line may not have", name, r)
}

// refusalOfCommit is the refusal text for a commit of the data, or "" when it is valid
// by the type's schema: a reference whose collection is a line of 1 to 200 characters and
// whose address has a full commit id as its path. The text has the rule, never the
// value. name is how the text calls the commit.
func refusalOfCommit(name string, r *reference) string {
	if r == nil || r.Address == nil || !commitShape.MatchString(r.Address.Path) {
		return name + " is not a commit with a full commit id as its address path"
	}
	if n := utf8.RuneCountInString(r.Collection); n < 1 || n > maxCollection {
		return fmt.Sprintf("the collection of %s is not 1 to %d characters", name, maxCollection)
	}
	return stopped("the collection of "+name, r.Collection)
}

// dataMembers are the members of the data that the pull-request type defines and that the
// adapter understands, as types whose json tags [contracts.CheckMustUnderstand] resolves
// a pointer through. A scalar has no member below it. The adapter reads the members of
// rawData and ignores target, title and text, which the envelope has too. Keep it in step
// with rawData.
type dataMembers struct {
	Target         json.RawMessage `json:"target"`
	Title          json.RawMessage `json:"title"`
	Text           json.RawMessage `json:"text"`
	Branch         string          `json:"branch"`
	BaseBranch     string          `json:"base_branch"`
	Head           *reference      `json:"head"`
	Base           *reference      `json:"base"`
	Commits        []reference     `json:"commits"`
	EarlierCommits int64           `json:"earlier_commits"`
	Steps          []struct {
		Commit string `json:"commit"`
		Step   string `json:"step"`
	} `json:"steps"`
	Draft bool `json:"draft"`
}

// UndefinedDataPointer returns the first of pointers, JSON Pointers counted from a
// change request entry, that points below data and not to a member of the data of the
// pull-request kind that [ParsePullRequestData] reads, or "" when there is none. The
// contract leaves every member of data to the artifact type of the kind, so the check
// is the adapter's. A pointer to data itself, and a pointer that does not point below
// data, are not its concern.
func UndefinedDataPointer(pointers []string) string {
	for _, p := range pointers {
		below, ok := strings.CutPrefix(p, "/data/")
		if !ok {
			continue
		}
		doc, err := json.Marshal(map[string][]string{contracts.MustUnderstand: {"/" + below}})
		if err != nil || contracts.CheckMustUnderstand(doc, dataMembers{}) != nil {
			return p
		}
	}
	return ""
}

// ParsePullRequestData reads the data of a change request of the kind pull-request, as the
// pull-request artifact type writes it (the pull-request schema of the Qory harness,
// copied to testdata/pull-request.schema.json, which is copied again when the schema
// changes), and checks these rules for the members it reads: the branch and the base
// branch are names git accepts, of at most 255 characters, and a line; the head, the base
// and each commit have a full commit id as address.path and a collection of 1 to 200
// characters that is a line; there is at least 1 commit; steps is a list, and each step
// has a full commit id and a step of 1 to 128 characters that is a line; earlier_commits
// is a whole number from 1; and draft is true or false. A line has none of the characters
// that [LineStopped] stops. The adapter reads only what the schema states: it sets no
// limit on the number of commits (the contract bounds the data), and head and
// earlier_commits have no further rule. A member that the schema does not define is
// ignored, and so is one that the adapter does not read. earlier_commits has no upper
// limit, and a whole number such as 34.0 or 3.4e1 counts. A repeated member, a lone
// surrogate escape and an invalid UTF-8 byte are refused although a JSON Schema validator
// accepts them, since the data is read by [exactjson]; the refusal text is the generic
// "data is not a JSON object whose members have the types of the pull-request kind", which
// has no cause. The error is a [*SubmitRefused] with the reason refused, the fix
// [FixChangeData] and the broken rule as its message; the text has the rule and the code
// point of a stopped character, never the value.
func ParsePullRequestData(data json.RawMessage) (PullRequestData, error) {
	refuse := func(format string, args ...any) (PullRequestData, error) {
		err := fmt.Errorf(format, args...)
		return PullRequestData{}, &SubmitRefused{Reason: ReasonRefused, Fix: FixChangeData, Err: err, Message: OneLine(err.Error(), MaxDetail)}
	}
	var raw rawData
	if err := exactjson.Unmarshal(data, &raw); err != nil || bytes.TrimSpace(data)[0] != '{' {
		return refuse("data is not a JSON object whose members have the types of the pull-request kind")
	}
	for _, b := range []struct{ name, value string }{{"data.branch", raw.Branch}, {"data.base_branch", raw.BaseBranch}} {
		if msg := stopped(b.name, b.value); msg != "" {
			return refuse("%s", msg)
		}
		if !validBranch(b.value) {
			return refuse("%s is not a branch name that git accepts", b.name)
		}
	}
	if msg := refusalOfCommit("data.base", raw.Base); msg != "" {
		return refuse("%s", msg)
	}
	if msg := refusalOfCommit("data.head", raw.Head); msg != "" {
		return refuse("%s", msg)
	}
	if len(raw.Commits) == 0 {
		return refuse("data.commits has no commit")
	}
	out := PullRequestData{Branch: raw.Branch, BaseBranch: raw.BaseBranch, BaseCommit: raw.Base.commitID()}
	for i := range raw.Commits {
		if msg := refusalOfCommit("a commit of data.commits", &raw.Commits[i]); msg != "" {
			return refuse("%s", msg)
		}
		out.Commits = append(out.Commits, raw.Commits[i].commitID())
	}
	if raw.Steps == nil {
		return refuse("data.steps is not a list")
	}
	for _, s := range raw.Steps {
		if !commitShape.MatchString(s.Commit) {
			return refuse("a step of data.steps has no full commit id")
		}
		if n := utf8.RuneCountInString(s.Step); n < 1 || n > maxStep {
			return refuse("the step of a step of data.steps is not 1 to %d characters", maxStep)
		}
		if msg := stopped("the step of a step of data.steps", s.Step); msg != "" {
			return refuse("%s", msg)
		}
	}
	if raw.EarlierCommits != nil {
		if !wholeFrom1(raw.EarlierCommits) {
			return refuse("data.earlier_commits is not a whole number from 1")
		}
	}
	if raw.Draft == nil {
		return refuse("data.draft is not true or false")
	}
	out.Draft = *raw.Draft
	return out, nil
}

// validBranch is whether name is a branch name git accepts, at most 255 characters.
func validBranch(name string) bool {
	return utf8.RuneCountInString(name) <= maxBranch && branchShape.MatchString(name) && !branchNever.MatchString(name)
}

// wholeFrom1 is whether the JSON number raw is a whole number of 1 or more, of any size:
// the type's schema has `integer` with `minimum` 1, and a writer may write 34.0 or 3.4e1
// for 34. It reads the digits, the number of digits after the point and the exponent, so
// the value is never built, rounded or capped; only the exponent is read into a
// big.Int. A missing member, a string, null, zero, a negative number and a number with a
// fraction that is not zero give false.
func wholeFrom1(raw json.RawMessage) bool {
	m := numberShape.FindStringSubmatch(string(raw))
	if m == nil || m[1] == "-" {
		return false
	}
	digits := strings.TrimLeft(m[2]+m[3], "0")
	if digits == "" {
		return false
	}
	exp, ok := new(big.Int).SetString(m[4], 10)
	if !ok {
		exp = new(big.Int)
	}
	// The value is digits * 10^scale. It is whole when the scale is not negative, or
	// when digits ends in at least -scale zeros.
	scale := exp.Sub(exp, big.NewInt(int64(len(m[3]))))
	if scale.Sign() >= 0 {
		return true
	}
	zeros := len(digits) - len(strings.TrimRight(digits, "0"))
	return scale.Neg(scale).IsInt64() && int64(zeros) >= scale.Int64()
}
