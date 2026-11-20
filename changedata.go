package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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
	maxBranch = 255
	maxStep   = 128
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
	// numberShape is a JSON number.
	numberShape = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
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

// ParsePullRequestData reads the data of a change request of the kind pull-request, as
// the pull-request artifact type writes it, and checks these rules: the branch and the
// base branch are names git accepts, the head, the base and each commit have a full
// commit id as address.path, at least 1 commit, each step of steps has a full commit id
// and 1 to 128 characters, earlier_commits is a whole number from 1, and draft is true or
// false. The adapter reads only what the type's schema states: it does not cap the number
// of commits, and head and earlier_commits have no further rule. A number that is whole, such as 34.0 or 3.4e1,
// is read as the integer it equals. The error is a [*SubmitRefused] with the reason
// refused, the fix [FixChangeData] and the broken rule as its message; the text states
// the rule, never the value.
func ParsePullRequestData(data json.RawMessage) (PullRequestData, error) {
	refuse := func(format string, args ...any) (PullRequestData, error) {
		err := fmt.Errorf(format, args...)
		return PullRequestData{}, &SubmitRefused{Reason: ReasonRefused, Fix: FixChangeData, Err: err, Message: OneLine(err.Error(), MaxDetail)}
	}
	var raw rawData
	if err := exactjson.Unmarshal(data, &raw); err != nil || bytes.TrimSpace(data)[0] != '{' {
		return refuse("data is not a JSON object whose members have the types of the pull-request kind")
	}
	if !validBranch(raw.Branch) {
		return refuse("data.branch is not a branch name that git accepts")
	}
	if !validBranch(raw.BaseBranch) {
		return refuse("data.base_branch is not a branch name that git accepts")
	}
	if !commitShape.MatchString(raw.Base.commitID()) {
		return refuse("data.base is not a commit with a full commit id as its address path")
	}
	if !commitShape.MatchString(raw.Head.commitID()) {
		return refuse("data.head is not a commit with a full commit id as its address path")
	}
	if len(raw.Commits) == 0 {
		return refuse("data.commits has no commit")
	}
	out := PullRequestData{Branch: raw.Branch, BaseBranch: raw.BaseBranch, BaseCommit: raw.Base.commitID()}
	for _, c := range raw.Commits {
		if !commitShape.MatchString(c.commitID()) {
			return refuse("a commit of data.commits has no full commit id as its address path")
		}
		out.Commits = append(out.Commits, c.commitID())
	}
	for _, s := range raw.Steps {
		if !commitShape.MatchString(s.Commit) {
			return refuse("a step of data.steps has no full commit id")
		}
		if n := utf8.RuneCountInString(s.Step); n < 1 || n > maxStep || strings.ContainsRune(s.Step, 0) {
			return refuse("the step of a step of data.steps is not 1 to %d characters without U+0000", maxStep)
		}
	}
	if raw.EarlierCommits != nil {
		if n, ok := wholeNumber(raw.EarlierCommits); !ok || n < 1 {
			return refuse("data.earlier_commits is not a whole number from 1 to %d", int64(math.MaxInt64))
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

// wholeNumber is the integer that the JSON number raw equals exactly, or false for
// anything else: a missing member, a string, null, a number with a fraction that is not
// zero, or a value past the int64 range. The artifact type of the kind may write 34.0 or
// 3.4e1 for 34. The value is read as a rational number, so no digit is rounded.
func wholeNumber(raw json.RawMessage) (int64, bool) {
	s := string(raw)
	if !numberShape.MatchString(s) {
		return 0, false
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || !r.IsInt() || !r.Num().IsInt64() {
		return 0, false
	}
	return r.Num().Int64(), true
}
