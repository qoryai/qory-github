package serve

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/qory-github"
)

// openDraftText is the text of the submit program of the module github.
func openDraftText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runeSet is a set of code points.
type runeSet map[rune]bool

// escapedRunes reads the code points that the character class text names with escapes
// such as \\x{00ad} or \x{2028}, alone or as a range a-b.
func escapedRunes(t *testing.T, class string) runeSet {
	t.Helper()
	one := `\\+x\{([0-9a-fA-F]+)\}`
	item := regexp.MustCompile(one + `(?:-` + one + `)?`)
	out := runeSet{}
	rest := class
	for _, m := range item.FindAllStringSubmatch(class, -1) {
		lo, err := strconv.ParseInt(m[1], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		hi := lo
		if m[2] != "" {
			if hi, err = strconv.ParseInt(m[2], 16, 32); err != nil {
				t.Fatal(err)
			}
		}
		for r := lo; r <= hi; r++ {
			out[rune(r)] = true
		}
		rest = strings.Replace(rest, m[0], "", 1)
	}
	if strings.Trim(rest, " -") != "" {
		t.Fatalf("the class has text that is no escape: %q", rest)
	}
	return out
}

// shellClass is the text between the brackets of the class that the program assigns to
// the shell variable name, without a leading ^.
func shellClass(t *testing.T, text, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `='\[(\^?)([^\]]*)\]'$`).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("the program has no %s", name)
	}
	return m[2]
}

// TestTheProgramStopsNoCharacterThatTheAdapterAllows: every character that the program's
// expression removes from a title is stopped by the adapter's rule, [github.LineStopped],
// and the program's spaces are those of [github.HasVisible]. The program's lists are older
// than the rule: the adapter also stops the format characters that the lists miss, such as
// the tag characters U+E0020 to U+E007F, and the program counts U+200C and U+200D as
// visible. The test pins those two differences, so the lists change with the rule.
func TestTheProgramStopsNoCharacterThatTheAdapterAllows(t *testing.T) {
	text := openDraftText(t)
	forbidden := escapedRunes(t, shellClass(t, text, "FORBIDDEN"))
	spaces := escapedRunes(t, shellClass(t, text, "NOT_SPACE"))
	// The class of NOT_SPACE starts with a plain space, which escapedRunes leaves out.
	spaces[' '] = true
	if len(forbidden) < 50 || len(spaces) < 15 {
		t.Fatalf("%d forbidden, %d spaces", len(forbidden), len(spaces))
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		stopped := github.LineStopped(r)
		if forbidden[r] && !stopped {
			t.Fatalf("U+%04X: the program removes it, the adapter allows it", r)
		}
		if stopped && !forbidden[r] && !unicode.Is(unicode.Cf, r) {
			t.Fatalf("U+%04X: the adapter stops it, the program keeps it, and it is no format character", r)
		}
		if stopped {
			continue
		}
		visible := github.HasVisible(string(r))
		if want := !spaces[r] && r != 0x200c && r != 0x200d; visible != want {
			t.Fatalf("U+%04X: the adapter takes it for visible: %v, the program: %v", r, visible, want)
		}
	}
	listed := seqRunes(t, text, "forbidden_seqs")
	blank := seqRunes(t, text, "space_seqs")
	if len(blank) != 17 {
		t.Fatalf("space_seqs lists %d characters, the adapter has 17 spaces", len(blank))
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		if !github.LineStopped(r) && r != 0x200c && r != 0x200d && blank[r] == github.HasVisible(string(r)) {
			t.Fatalf("U+%04X: the adapter takes it for a space: %v, space_seqs: %v", r, !github.HasVisible(string(r)), blank[r])
		}
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		c0 := r < 0x20 || r == 0x7f
		if want := forbidden[r] && !c0; listed[r] != want {
			t.Fatalf("U+%04X: the program's list has it: %v, want %v", r, listed[r], want)
		}
	}
}

// seqRunes are the code points that the sequences listed by the shell function fn of the
// program stand for: each is a printf escape of the UTF-8 bytes of one character, such as
// '\\302\\255', in the word list of the function.
func seqRunes(t *testing.T, text, fn string) runeSet {
	t.Helper()
	start := strings.Index(text, fn+"() {")
	if start < 0 {
		t.Fatalf("the program has no %s", fn)
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s has no end", fn)
	}
	body := text[start : start+end]
	out := runeSet{}
	for _, m := range regexp.MustCompile(`'((?:\\[0-7]{3})+)'`).FindAllStringSubmatch(body, -1) {
		var bytes []byte
		for _, o := range regexp.MustCompile(`[0-7]{3}`).FindAllString(m[1], -1) {
			v, err := strconv.ParseUint(o, 8, 8)
			if err != nil {
				t.Fatal(err)
			}
			bytes = append(bytes, byte(v))
		}
		r, n := utf8.DecodeRune(bytes)
		if r == utf8.RuneError || n != len(bytes) {
			t.Fatalf("the bytes % x of %s are no one character", bytes, fn)
		}
		if out[r] {
			t.Fatalf("%s lists U+%04X twice", fn, r)
		}
		out[r] = true
	}
	return out
}
