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
)

// FixChangeData is the fix line for a change request whose data breaks a rule of the
// pull-request kind. The contract lists no member of data, so [ParsePullRequestData]
// checks each member it reads.
const FixChangeData = "Fix the data of the pull-request artifact type in the process, then submit again."

// The limits of the data of a pull-request change request.
const (
	maxBranch      = 255
	maxCommits     = 100
	maxStep        = 128
	maxDraftNumber = math.MaxInt64
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
// members it has that the adapter reads: Branch, the branch the run pushed, the
// base branch and commit it started at, Commits, the commit ids of the run, oldest
// first, and Draft, nil when the entry asks for no draft.
type PullRequestData struct {
	Branch     string
	BaseBranch string
	BaseCommit string
	Commits    []string
	Draft      *DraftAsk
}

// DraftAsk is what the data asks for the repository: a draft to open, or, with Number
// above 0, the draft to update, whose number is a hint.
type DraftAsk struct {
	Number int64
}

// rawData is the wire form of the data of a pull-request change request. A member the
// adapter does not read is ignored.
type rawData struct {
	Branch string `json:"branch"`
	Base   *struct {
		Commit string          `json:"commit"`
		Branch json.RawMessage `json:"branch"`
	} `json:"base"`
	Commit  string `json:"commit"`
	Commits []struct {
		Commit string `json:"commit"`
		Step   string `json:"step"`
	} `json:"commits"`
	EarlierCommits json.RawMessage `json:"earlier_commits"`
	Draft          json.RawMessage `json:"draft"`
}

// rawDraft is the wire form of the draft member of the data.
type rawDraft struct {
	Action string          `json:"action"`
	Number json.RawMessage `json:"number"`
}

// ParsePullRequestData reads the data of a change request of the kind pull-request, and
// checks these rules: the branch names git accepts (an empty base.branch is not one), full
// commit ids, 1 to 100 commits that end in the head commit, each with a step of 1 to 128
// characters, earlier_commits from 1, only with exactly 100 commits, a draft that is an
// object of the action open without a number, or update with one from 1 to
// 9223372036854775807, and a base branch when the entry asks for a draft. A number that
// is whole, such as 34.0 or 3.4e1, is read as the integer it equals. The error is a
// [*SubmitRefused] with the reason refused, the fix [FixChangeData] and the broken rule as
// its message; the text states the rule, never the value.
func ParsePullRequestData(data json.RawMessage) (PullRequestData, error) {
	refuse := func(format string, args ...any) (PullRequestData, error) {
		err := fmt.Errorf(format, args...)
		return PullRequestData{}, &SubmitRefused{Reason: ReasonRefused, Fix: FixChangeData, Err: err, Message: OneLine(err.Error(), MaxDetail)}
	}
	var raw rawData
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil || bytes.TrimSpace(data)[0] != '{' {
		return refuse("data is not a JSON object whose members have the types of the pull-request kind")
	}
	if !validBranch(raw.Branch) {
		return refuse("data.branch is not a branch name that git accepts")
	}
	if raw.Base == nil || !commitShape.MatchString(raw.Base.Commit) {
		return refuse("data.base.commit is not a full commit id")
	}
	var baseBranch string
	if raw.Base.Branch != nil {
		if json.Unmarshal(raw.Base.Branch, &baseBranch) != nil || !validBranch(baseBranch) {
			return refuse("data.base.branch is not a branch name that git accepts")
		}
	}
	if !commitShape.MatchString(raw.Commit) {
		return refuse("data.commit is not a full commit id")
	}
	if len(raw.Commits) == 0 || len(raw.Commits) > maxCommits {
		return refuse("data.commits has %d commits, not 1 to %d", len(raw.Commits), maxCommits)
	}
	out := PullRequestData{Branch: raw.Branch, BaseBranch: baseBranch, BaseCommit: raw.Base.Commit}
	for _, c := range raw.Commits {
		if !commitShape.MatchString(c.Commit) {
			return refuse("a commit of data.commits is not a full commit id")
		}
		if n := utf8.RuneCountInString(c.Step); n < 1 || n > maxStep || strings.ContainsRune(c.Step, 0) {
			return refuse("the step of a commit of data.commits is not 1 to %d characters without U+0000", maxStep)
		}
		out.Commits = append(out.Commits, c.Commit)
	}
	if out.Commits[len(out.Commits)-1] != raw.Commit {
		return refuse("data.commits does not end in data.commit")
	}
	if raw.EarlierCommits != nil {
		if n, ok := wholeNumber(raw.EarlierCommits); !ok || n < 1 {
			return refuse("data.earlier_commits is not a whole number from 1 to %d", int64(maxDraftNumber))
		}
		if len(raw.Commits) != maxCommits {
			return refuse("data.earlier_commits is set, and data.commits does not have exactly %d commits", maxCommits)
		}
	}
	if raw.Draft != nil {
		var draft rawDraft
		if string(raw.Draft) == "null" || json.Unmarshal(raw.Draft, &draft) != nil {
			return refuse("data.draft is not an object")
		}
		if out.BaseBranch == "" {
			return refuse("data.draft is set, and data.base.branch is not")
		}
		ask := DraftAsk{}
		switch draft.Action {
		case "open":
			if draft.Number != nil {
				return refuse("data.draft.number is set with the action open")
			}
		case "update":
			n, ok := wholeNumber(draft.Number)
			if !ok || n < 1 {
				return refuse("data.draft.number is not a whole number from 1 to %d with the action update", int64(maxDraftNumber))
			}
			ask.Number = n
		default:
			return refuse("data.draft.action is not open or update")
		}
		out.Draft = &ask
	}
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
