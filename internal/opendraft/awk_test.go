package opendraft

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qoryai/qory-github"
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

// programLine is the line of the program that starts with prefix.
func programLine(t *testing.T, prefix string) string {
	t.Helper()
	b, err := os.ReadFile("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("the program has no line that starts with %s", prefix)
	return ""
}

// ruleChars are the code points that a test of the title rules runs the program over:
// every character from U+0020 to U+FFFF but the surrogates and DEL, U+E0000 to U+E0FFF,
// every character that the adapter's rule stops with the character before and after each
// run of them, the characters that the adapter takes for spaces, and a few more.
func ruleChars() []rune {
	var chars []rune
	seen := map[rune]bool{}
	add := func(r rune) {
		if r < 0x20 || r == 0x7f || r > 0x10ffff || r >= 0xd800 && r <= 0xdfff || seen[r] {
			return
		}
		seen[r] = true
		chars = append(chars, r)
	}
	for r := rune(0x20); r <= 0xffff; r++ {
		add(r)
	}
	for r := rune(0xe0000); r <= 0xe0fff; r++ {
		add(r)
	}
	for r := rune(0); r <= 0x10ffff; r++ {
		if !github.LineStopped(r) {
			continue
		}
		start := r
		for r < 0x10ffff && github.LineStopped(r+1) {
			r++
		}
		add(start - 1)
		for c := start; c <= r; c++ {
			add(c)
		}
		add(r + 1)
	}
	for _, r := range []rune{0x10000, 0x1f600, 0x10ffff, 0x200c, 0x200d} {
		add(r)
	}
	return chars
}

// TestTheTitleRulesGiveTheSameResultInEveryAwk runs clean_title's and is_blank's shell
// functions of the program, with each awk of OPEN_DRAFT_TEST_AWK, over [ruleChars]. The
// program removes the characters that the adapter's [github.LineStopped] stops, and no
// other, and its list of spaces is the adapter's spaces with U+200C and U+200D, which
// [github.HasVisible] does not count. An awk that is not on this machine is skipped, with
// the reason.
func TestTheTitleRulesGiveTheSameResultInEveryAwk(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not on PATH: the program needs a POSIX shell")
	}
	chars := ruleChars()
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
	cleanWant := want(func(r rune) bool { return r >= 0x80 && github.LineStopped(r) }) + "ab\u00a0\u3000c\n \u00a0\u2003\u3000 \n"
	spaceWant := want(func(r rune) bool { return !github.LineStopped(r) && !github.HasVisible(string(r)) }) + "a\u00ad\u200b\u2028\u202e\ufeffbc\n\n"
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
			funcs := programLine(t, "FORBIDDEN_RANGES=") + "\n" + shellFunction(t, "utf8_seq") + shellFunction(t, "forbidden_seqs") + shellFunction(t, "space_seqs") + shellFunction(t, "strip_seqs")
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

// jqExpression is the --jq expression that the program passes to gh for a list of pull
// requests: the text of its LIST_JQ, which the shell builds from the top of the program.
func jqExpression(t *testing.T, sh string) string {
	t.Helper()
	b, err := os.ReadFile("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	end := strings.Index(text, "\nREAD_JQ=")
	if end < 0 {
		t.Fatal("the program has no READ_JQ")
	}
	end += strings.Index(text[end+1:], "\n") + 1
	out, err := exec.Command(sh, "-c", text[:end]+"\nprintf '%s' \"$LIST_JQ\"\n").Output()
	if err != nil {
		t.Fatalf("the top of the program: %v", err)
	}
	return string(out)
}

// TestTheJqExpressionRemovesExactlyWhatTheAdapterStops runs the --jq expression of the
// program with jq over the controls and [ruleChars], in two titles: the code point
// between two letters, and the code point alone. Plane 0, U+E0000 to U+E0FFF and
// each stopped character with its neighbours are in ruleChars; planes 2 to 13 have no
// stopped character, and TestTheForbiddenRangesAreTheAdaptersRule compares the ranges with
// the rule for every code point. The title that the program prints is the one that the
// adapter's rule makes of it: without the characters of [github.LineStopped], and empty
// when [github.HasVisible] is false. It fails when the rule or the program changes alone.
// gh uses gojq, whose regular expressions read the same escapes; this test runs jq, which
// is on the machines that run the tests.
func TestTheJqExpressionRemovesExactlyWhatTheAdapterStops(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq is not on PATH")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not on PATH: the program needs a POSIX shell")
	}
	chars := []rune{0x7f}
	for r := rune(0); r < 0x20; r++ {
		chars = append(chars, r)
	}
	chars = append(chars, ruleChars()...)
	titles := func(r rune) (between, alone string) {
		between, alone = "a"+string(r)+"b", string(r)
		wantBetween, wantAlone := between, alone
		switch {
		case github.LineStopped(r):
			wantBetween, wantAlone = "ab", ""
		case !github.HasVisible(alone):
			wantAlone = ""
		}
		return wantBetween, wantAlone
	}
	for _, shell := range []string{sh, "dash"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		expr := jqExpression(t, path)
		cmd := exec.Command(jq, "-r", expr)
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() {
			w := bufio.NewWriter(in)
			item := func(title string) map[string]any {
				return map[string]any{"number": 1, "state": "open", "draft": false, "title": title, "html_url": "u", "merged_at": nil,
					"head": map[string]any{"ref": "b", "repo": nil}}
			}
			var chunk []map[string]any
			flush := func() {
				b, _ := json.Marshal(chunk)
				w.Write(b)
				w.WriteByte('\n')
				chunk = chunk[:0]
			}
			for _, r := range chars {
				chunk = append(chunk, item("a"+string(r)+"b"), item(string(r)))
				if len(chunk) >= 4096 {
					flush()
				}
			}
			flush()
			w.Flush()
			in.Close()
		}()
		lines := bufio.NewReader(out)
		bad := 0
		for _, r := range chars {
			if bad >= 20 {
				break
			}
			wantBetween, wantAlone := titles(r)
			for _, want := range []string{wantBetween, wantAlone} {
				var rec [8]string
				for i := range rec {
					line, err := lines.ReadString('\n')
					if err != nil && err != io.EOF {
						t.Fatalf("%s: U+%04X: %v", shell, r, err)
					}
					rec[i] = strings.TrimSuffix(line, "\n")
				}
				if rec[6] != want {
					t.Errorf("%s: U+%04X: the program prints %+q, the adapter's rule makes %+q", shell, r, rec[6], want)
					bad++
				}
			}
		}
		io.Copy(io.Discard, out)
		if err := cmd.Wait(); err != nil && bad == 0 {
			t.Fatalf("%s: jq: %v", shell, err)
		}
	}
}

// TestTheForbiddenRangesAreTheAdaptersRule: the ranges of FORBIDDEN_RANGES in the program
// are exactly the code points that [github.LineStopped] stops, written as the shortest
// list of ranges. It fails when the Unicode version of Go moves a format character, so a
// reader updates the ranges, with the version in the comment above them.
func TestTheForbiddenRangesAreTheAdaptersRule(t *testing.T) {
	line := programLine(t, "FORBIDDEN_RANGES=")
	list := strings.Trim(strings.TrimPrefix(line, "FORBIDDEN_RANGES="), "'")
	var want []string
	for r := rune(0); r <= 0x10ffff; r++ {
		if !github.LineStopped(r) {
			continue
		}
		start := r
		for r < 0x10ffff && github.LineStopped(r+1) {
			r++
		}
		if r == start {
			want = append(want, fmt.Sprintf("%04X", r))
		} else {
			want = append(want, fmt.Sprintf("%04X-%04X", start, r))
		}
	}
	if got := strings.Fields(list); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("FORBIDDEN_RANGES is\n%s\nthe adapter's rule is\n%s", strings.Join(got, " "), strings.Join(want, " "))
	}
}
