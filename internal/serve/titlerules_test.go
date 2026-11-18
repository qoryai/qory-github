package serve

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
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

// TestTheProgramAndTheAdapterRefuseTheSameCharactersInATitle: the characters that the
// program's expression removes from a title are exactly those of the adapter's forbidden
// set, and its spaces, which make a title blank, are those of the adapter's. The awk
// rule of the program, which cleans the title of the run, removes the same characters
// but the C0 controls and DEL, which the program refuses before.
func TestTheProgramAndTheAdapterRefuseTheSameCharactersInATitle(t *testing.T) {
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
		if got := github.LineForbidden.MatchString(string(r)); got != forbidden[r] {
			t.Fatalf("U+%04X: the adapter forbids it: %v, the program's expression: %v", r, got, forbidden[r])
		}
		if github.LineForbidden.MatchString(string(r)) {
			continue
		}
		if _, notSpace := cleanTitle(string(r)); notSpace == spaces[r] {
			t.Fatalf("U+%04X: the adapter takes it for a space: %v, the program: %v", r, !notSpace, spaces[r])
		}
	}
	awkRemoved := awkRunes(t, text, "clean_title")
	blank := awkRunes(t, text, "is_blank")
	if len(blank) != 17 {
		t.Fatalf("is_blank removes %d characters, the adapter has 17 spaces", len(blank))
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		if _, notSpace := cleanTitle(string(r)); !github.LineForbidden.MatchString(string(r)) && blank[r] == notSpace {
			t.Fatalf("U+%04X: the adapter takes it for a space: %v, is_blank: %v", r, !notSpace, blank[r])
		}
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		c0 := r < 0x20 || r == 0x7f
		if want := forbidden[r] && !c0; awkRemoved[r] != want {
			t.Fatalf("U+%04X: the program's awk rule removes it: %v, want %v", r, awkRemoved[r], want)
		}
	}
}

// awkRunes are the code points that the gsub calls of the function fn of the program
// remove, written there as the octal bytes of their UTF-8 form, each byte a literal or a
// class, or as a plain space.
func awkRunes(t *testing.T, text, fn string) runeSet {
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
	pattern := regexp.MustCompile(`gsub\(/((?:\\[0-7]{3}|\[[^\]]*\]| )+)/, ""\)`)
	octal := regexp.MustCompile(`\\([0-7]{3})`)
	out := runeSet{}
	for _, m := range pattern.FindAllStringSubmatch(body, -1) {
		var alternatives [][]byte
		for _, el := range regexp.MustCompile(`\\[0-7]{3}|\[[^\]]*\]| `).FindAllString(m[1], -1) {
			var bytes []byte
			if el == " " {
				bytes = []byte{' '}
			} else if strings.HasPrefix(el, "[") {
				inner := el[1 : len(el)-1]
				for inner != "" {
					lo := octal.FindStringSubmatch(inner[:4])
					l, _ := strconv.ParseUint(lo[1], 8, 8)
					inner = inner[4:]
					h := l
					if strings.HasPrefix(inner, "-") {
						hi := octal.FindStringSubmatch(inner[1:5])
						h, _ = strconv.ParseUint(hi[1], 8, 8)
						inner = inner[5:]
					}
					for b := l; b <= h; b++ {
						bytes = append(bytes, byte(b))
					}
				}
			} else {
				v, _ := strconv.ParseUint(el[1:], 8, 8)
				bytes = []byte{byte(v)}
			}
			alternatives = append(alternatives, bytes)
		}
		seqs := [][]byte{nil}
		for _, alt := range alternatives {
			var next [][]byte
			for _, s := range seqs {
				for _, b := range alt {
					next = append(next, append(append([]byte{}, s...), b))
				}
			}
			seqs = next
		}
		for _, s := range seqs {
			r, n := utf8.DecodeRune(s)
			if r == utf8.RuneError || n != len(s) {
				t.Fatalf("the bytes % x of clean_title are no one character", s)
			}
			out[r] = true
		}
	}
	return out
}
