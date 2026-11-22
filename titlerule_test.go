package github

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qoryai/integrations/contracts"
)

// titleCases are titles and whether the rule of a title takes them.
var titleCases = []struct {
	name, title string
	ok          bool
}{
	{"plain text", "Fix the build", true},
	{"a ZWJ emoji sequence", "family \U0001F468\u200d\U0001F469\u200d\U0001F467", true},
	{"a ZWNJ inside a word", "a\u200cb", true},
	{"a no-break space between words", "a\u00a0b", true},
	{"a bell", "a\a b", false},
	{"a line feed", "a\nb", false},
	{"a DEL", "a\x7fb", false},
	{"a C1 control", "a\u0085b", false},
	{"U+2028", "a\u2028b", false},
	{"U+2029", "a\u2029b", false},
	{"a zero-width space", "a\u200bb", false},
	{"a soft hyphen", "a\u00adb", false},
	{"a byte order mark", "a\ufeffb", false},
	{"a right-to-left override", "a\u202eb", false},
	{"U+206F, a deprecated format character", "a\u206fb", false},
	{"a tag letter", "a\U000E0041b", false},
	{"the language tag character", "a\U000E0001b", false},
	{"only spaces", "   ", false},
	{"only an ideographic space", "\u3000", false},
	{"only ZWNJ and ZWJ", "\u200c\u200d", false},
	{"spaces, ZWNJ and ZWJ", " \u200d \u200c", false},
	{"empty", "", false},
}

func TestTheTitleRuleStopsWhatTheContractStops(t *testing.T) {
	for _, tc := range titleCases {
		err := CheckTitle(tc.title)
		if (err == nil) != tc.ok {
			t.Errorf("%s: CheckTitle gives %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if err == nil {
			continue
		}
		refused, ok := err.(*SubmitRefused)
		if !ok || refused.Reason != ReasonRefused || utf8.RuneCountInString(refused.Fix) > 100 || !strings.HasPrefix(refused.Detail(), refused.Fix) || strings.ContainsFunc(refused.Detail(), LineStopped) {
			t.Errorf("%s: %#v", tc.name, err)
		}
	}
}

// TestTheTitleRuleAgreesWithTheContractsPattern compares CheckTitle with the schema of
// the contract's change_title, so a change of the pinned contract fails here.
func TestTheTitleRuleAgreesWithTheContractsPattern(t *testing.T) {
	schema, err := contracts.Compile("definitions.schema.json#/$defs/change_title")
	if err != nil {
		t.Fatal(err)
	}
	agree := func(title string) {
		t.Helper()
		if got, want := CheckTitle(title) == nil, schema.Validate(title) == nil; got != want {
			t.Fatalf("%+q: the adapter takes it: %v, the contract: %v", title, got, want)
		}
	}
	for _, tc := range titleCases {
		agree(tc.title)
	}
	// Each character alone and between two letters, over the planes that have a Cc, Cf or
	// space character: the Unicode version of Go and of the schema validator must agree.
	for _, plane := range [][2]rune{{0, 0x2ffff}, {0xe0000, 0xe0fff}} {
		for r := plane[0]; r <= plane[1]; r++ {
			if r >= 0xd800 && r <= 0xdfff {
				continue
			}
			agree("a" + string(r) + "b")
			agree(string(r))
		}
	}
}

func TestOneLineStopsEveryStoppedCharacter(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a tag letter", "a\U000E0041b", "a b"},
		{"a deprecated format character", "a\u206fb", "a b"},
		{"a right-to-left override", "a\u202eb", "a b"},
		{"a line separator", "a\u2028b", "a b"},
		{"a ZWJ emoji sequence stays", "\U0001F468\u200d\U0001F469", "\U0001F468\u200d\U0001F469"},
		{"ZWNJ stays", "a\u200cb", "a\u200cb"},
	} {
		if got := OneLine(tc.in, 1000); got != tc.want {
			t.Errorf("%s: %+q, want %+q", tc.name, got, tc.want)
		}
	}
}

// TestACredentialMatchSkipsEveryFormatCharacter: between, which matches the characters
// that may split a credential, matches every stopped character, U+200C and U+200D.
func TestACredentialMatchSkipsEveryFormatCharacter(t *testing.T) {
	skip := regexp.MustCompile("^" + between + "$")
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		if (LineStopped(r) || r == 0x200c || r == 0x200d) && !skip.MatchString(string(r)) {
			t.Fatalf("U+%04X is not skipped inside a credential", r)
		}
	}
}

// TestAnAuthorNameFollowsTheSameRule: a name has the stopped characters other than
// controls removed, a line separator made a space, and U+200C and U+200D kept; a name
// with a control character, or none that is not a space, ZWNJ or ZWJ, is refused.
func TestAnAuthorNameFollowsTheSameRule(t *testing.T) {
	if got, want := cleanName("A\U000E0041‮B C‍D"), "AB C‍D"; got != want {
		t.Errorf("cleanName gives %+q, want %+q", got, want)
	}
	ref := "1#1"
	for name, ok := range map[string]bool{
		"Dana Example":  true,
		"Dana‍Ex":       true,
		"Dana\aExample": false,
		"‍‌ ":           false,
		"\U000E0041":    false,
		"   ":           false,
	} {
		_, err := parseComment(Comment{Ref: ref, CommentID: "sc_0123456789abcdef", AuthorName: name, Body: "b"})
		if (err == nil) != ok {
			t.Errorf("%+q: %v, want ok %v", name, err, ok)
		}
	}
}
