package opendraft

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// shellFunction is the text of the shell function name of the program.
func shellFunction(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n"+name+"() {")
	if start < 0 {
		t.Fatalf("the program has no %s", name)
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s has no end", name)
	}
	return text[start : start+end+3]
}

// TestTheAwkProgramHasNoEscape: the awk text of strip_seqs has no octal or hexadecimal
// escape and no bracket range, since only printf escapes are POSIX in a shell, and an awk
// regular expression with bytes above 127 is not.
func TestTheAwkProgramHasNoEscape(t *testing.T) {
	body := shellFunction(t, "strip_seqs")
	if regexp.MustCompile(`\\[0-7xX]|\[[^]]*-[^]]*\]|gsub|match\(|sub\(`).MatchString(body) {
		t.Errorf("strip_seqs has an escape, a range or a regular expression:\n%s", body)
	}
}

// awkProgram is an awk to run the title rules with: its name and path.
type awkProgram struct{ name, path string }

// awksUnderTest are the awks of OPEN_DRAFT_TEST_AWK, a list of paths or name=path words
// separated by spaces, or the awk on PATH.
func awksUnderTest(t *testing.T) []awkProgram {
	t.Helper()
	list := strings.Fields(os.Getenv("OPEN_DRAFT_TEST_AWK"))
	if len(list) == 0 {
		list = []string{"awk"}
	}
	var out []awkProgram
	for _, w := range list {
		name, path, ok := strings.Cut(w, "=")
		if !ok {
			name, path = filepath.Base(w), w
		}
		out = append(out, awkProgram{name, path})
	}
	return out
}

// TestTheTitleRulesGiveTheSameResultInEveryAwk runs clean_title's and is_blank's shell
// functions of the program, with each awk of OPEN_DRAFT_TEST_AWK, over every character
// from U+0020 to U+FFFF but the surrogates and DEL, and a few above. A character of the
// forbidden list is removed, and a space is removed by the list of spaces, and no other
// character is. An awk that is not on this machine is skipped, with the reason.
func TestTheTitleRulesGiveTheSameResultInEveryAwk(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not on PATH: the program needs a POSIX shell")
	}
	spaces := " \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"
	var chars []rune
	for r := rune(0x20); r <= 0xffff; r++ {
		if r == 0x7f || r >= 0xd800 && r <= 0xdfff {
			continue
		}
		chars = append(chars, r)
	}
	chars = append(chars, 0x10000, 0x1f600, 0xe0001, 0x10ffff)
	var in strings.Builder
	for _, r := range chars {
		in.WriteString("x" + string(r) + "x\n")
	}
	// A line with several of each, one after another, and one that is only spaces.
	in.WriteString("a\u00ad\u200b\u2028\u202e\ufeffb\u00a0\u3000c\n \u00a0\u2003\u3000 \n")
	want := func(drop func(rune) bool) string {
		var out strings.Builder
		for _, r := range chars {
			if drop(r) {
				out.WriteString("xx\n")
			} else {
				out.WriteString("x" + string(r) + "x\n")
			}
		}
		return out.String()
	}
	cleanWant := want(func(r rune) bool { return r >= 0x80 && forbidden.MatchString(string(r)) }) + "ab\u00a0\u3000c\n \u00a0\u2003\u3000 \n"
	spaceWant := want(func(r rune) bool { return strings.ContainsRune(spaces, r) }) + "a\u00ad\u200b\u2028\u202e\ufeffbc\n\n"
	for _, a := range awksUnderTest(t) {
		t.Run(a.name, func(t *testing.T) {
			path, err := exec.LookPath(a.path)
			if err != nil {
				t.Skipf("%s is not on this machine (%v): set OPEN_DRAFT_TEST_AWK to a path of it", a.name, err)
			}
			bin := t.TempDir()
			links := map[string]string{"sh": sh, "awk": path}
			if cat, err := exec.LookPath("cat"); err == nil {
				links["cat"] = cat
			}
			for name, target := range links {
				if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
					t.Fatal(err)
				}
			}
			input := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(input, []byte(in.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			funcs := shellFunction(t, "forbidden_seqs") + shellFunction(t, "space_seqs") + shellFunction(t, "strip_seqs")
			for _, tc := range []struct{ name, seqs, want string }{
				{"forbidden_seqs", `"$(forbidden_seqs)"`, cleanWant},
				{"space_seqs", `"$(space_seqs)"`, spaceWant},
			} {
				script := "set -eu\nLC_ALL=C\nexport LC_ALL\n" + funcs + "\ntext=$(cat \"$1\")\nstrip_seqs " + tc.seqs + ` "$text"` + "\n"
				cmd := exec.Command(filepath.Join(bin, "sh"), "-c", script, "sh", input)
				// HOME and DOCKER_* stay, for an awk that is a script that runs a container.
				cmd.Env = []string{"PATH=" + bin}
				for _, k := range []string{"HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"} {
					if v, ok := os.LookupEnv(k); ok {
						cmd.Env = append(cmd.Env, k+"="+v)
					}
				}
				got, err := cmd.Output()
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if string(got) != tc.want {
					g, w := strings.Split(string(got), "\n"), strings.Split(tc.want, "\n")
					for i := range w {
						if i >= len(g) || g[i] != w[i] {
							t.Fatalf("%s: line %d is %q, want %q (%d lines, want %d)", tc.name, i+1, g[min(i, len(g)-1)], w[i], len(g), len(w))
						}
					}
					t.Fatalf("%s: %d lines, want %d", tc.name, len(g), len(w))
				}
			}
		})
	}
}
