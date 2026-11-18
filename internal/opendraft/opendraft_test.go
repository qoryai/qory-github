package opendraft

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"gopkg.in/yaml.v3"
)

const (
	repo       = "acme-corp/widgets-app"
	branch     = "qory/run-01HZX"
	baseBranch = "main"
	title      = "Show delivery dates at checkout"
	loginLine  = "Run `gh auth login`, then `qory run` again."
	secret     = "ghp_never-printed-0123456789abcdef"
	startLine  = "<!-- qory:start -->"
	endLine    = "<!-- qory:end -->"
)

func sha(c string) string { return strings.Repeat(c, 40) }

func block(text string) string { return startLine + "\n" + text + "\n" + endLine }

// fakeGh is a stand-in for gh: a shell script first on PATH that records each call and
// prints the output that the test stored for it. In the mode jq it runs the --jq
// expression of the program with the real jq over the stored JSON, as gh does; in the
// mode text it prints the stored output of that expression.
const fakeGh = `#!/bin/sh
d=$FAKE_GH_DIR
n=$(cat "$d/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" >"$d/count"
: >"$d/call.$n"
echo $$ >"$d/pid.$n"
if [ "$n" = 1 ]; then
	# The program starts the timer before its first call; wait until the fake sleep has
	# written its line, so a test reads it, whatever the load.
	i=0
	while [ ! -s "$d/sleep.args" ] && [ "$i" -lt 100000 ]; do i=$((i + 1)); done
fi
for a in "$@"; do printf '%s\n' "$a" >>"$d/call.$n"; done
prev=
method=GET
endpoint=
jq=
for a in "$@"; do
	case $prev in
	--body-file) cp "$a" "$d/call.$n.file" ;;
	-X) method=$a ;;
	--jq) jq=$a ;;
	esac
	case $a in
	body=@*) cp "${a#body=@}" "$d/call.$n.file" ;;
	repos/*) endpoint=$a ;;
	esac
	prev=$a
done
case "$1 $2" in
"auth token") key=auth ;;
"pr create") key=create ;;
*)
	case "$method $endpoint" in
	"GET "*/pulls) key=list ;;
	"GET "*/pulls/*) key=read.${endpoint##*/} ;;
	"PATCH "*) key=patch ;;
	*) echo "fake gh: unexpected call $*" >&2; exit 99 ;;
	esac
	;;
esac
if [ -f "$d/hang.$key" ]; then
	# A hang file with text makes a gh that ignores TERM; exec keeps the ignoring.
	if [ -s "$d/hang.$key" ]; then trap '' TERM; fi
	exec sleep 31337
fi
k=$(cat "$d/k.$key" 2>/dev/null || echo 0)
k=$((k + 1))
echo "$k" >"$d/k.$key"
pick() { if [ -f "$d/$key.$k.$1" ]; then echo "$d/$key.$k.$1"; else echo "$d/$key.$1"; fi; }
if [ -f "$(pick err)" ]; then cat "$(pick err)" >&2; fi
if [ -n "$jq" ] && [ -n "${FAKE_GH_JQ:-}" ]; then
	jq -r "$jq" "$(pick json)"
elif [ -f "$(pick out)" ]; then
	cat "$(pick out)"
fi
if [ -f "$(pick status)" ]; then exit "$(cat "$(pick status)")"; fi
exit 0
`

const fakeGit = `#!/bin/sh
echo "$@" >>"$FAKE_GH_DIR/git-called"
exit 1
`

// pull is a pull request that the fake gh returns.
type pull struct {
	Number   int
	Ref      string // empty is the branch of the run
	Repo     string // empty is the repository; "-" is no head repository
	State    string // empty is open
	Title    string
	Body     string
	NullBody bool
	Draft    bool
	Merged   bool
}

func (p pull) norm() pull {
	if p.Ref == "" {
		p.Ref = branch
	}
	if p.Repo == "" {
		p.Repo = repo
	}
	if p.State == "" {
		p.State = "open"
	}
	if p.Title == "" {
		p.Title = "Title of " + strconv.Itoa(p.Number)
	}
	return p
}

func (p pull) url() string { return "https://github.com/" + repo + "/pull/" + strconv.Itoa(p.Number) }

// text is what gh prints for the program's --jq expression: 8 lines, and for a read the
// description with the line feed that gh adds.
func (p pull) text(read bool) string {
	p = p.norm()
	s := fmt.Sprintf("%d\n%s\n%s\n%s\n%t\n%t\n%s\n%s\n", p.Number, p.Ref, p.Repo, p.State, p.Merged, p.Draft, jqTitle(p.Title), p.url())
	if read {
		s += p.Body + "\n"
	}
	return s
}

func (p pull) json() map[string]any {
	p = p.norm()
	m := map[string]any{"number": p.Number, "state": p.State, "draft": p.Draft, "title": p.Title,
		"html_url": p.url(), "merged_at": nil, "body": p.Body, "head": map[string]any{"ref": p.Ref, "repo": nil}}
	if p.Merged {
		m["merged_at"] = "2026-11-01T10:00:00Z"
	}
	if p.NullBody {
		m["body"] = nil
	}
	if p.Repo != "-" {
		m["head"].(map[string]any)["repo"] = map[string]any{"full_name": p.Repo}
	}
	return m
}

// forbidden is the set of characters that the contract's draft_title refuses, as the
// adapter's cleanTitle removes them.
var forbidden = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f\x{00ad}\x{061c}\x{180e}\x{200b}\x{200e}\x{200f}\x{2028}\x{2029}\x{202a}-\x{202e}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{feff}\x{fff9}-\x{fffb}]`)

// jqTitle is what the --jq expression of the program prints for a title: the title
// without the forbidden characters, or nothing when only spaces are left.
func jqTitle(title string) string {
	shown := forbidden.ReplaceAllString(title, "")
	if strings.Trim(shown, " \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000") == "" {
		return ""
	}
	return shown
}

type fake struct {
	t     *testing.T
	dir   string
	bin   string
	tmp   string
	mode  string
	input map[string]string
}

func newFake(t *testing.T, mode string) *fake {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not on PATH: the program needs a POSIX shell")
	}
	if mode == "jq" {
		if _, err := exec.LookPath("jq"); err != nil {
			t.Skip("jq is not on PATH: the mode that runs the --jq expression needs it")
		}
	}
	f := &fake{t: t, dir: t.TempDir(), bin: t.TempDir(), tmp: t.TempDir(), mode: mode}
	// The PATH has the tools the program may use, and the fake gh and git.
	for _, tool := range []string{"sh", "sed", "awk", "grep", "tr", "head", "cut", "wc", "cat", "cmp", "mktemp", "rm", "tail", "jq", "dirname", "env", "cp"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// sleep records its process id and its arguments, then runs the real one.
	if realSleep, err := exec.LookPath("sleep"); err == nil {
		f.write(filepath.Join(f.bin, "sleep"), "#!/bin/sh\necho \"$$ $@\" >>\""+f.dir+"/sleep.args\"\nexec "+realSleep+" \"$@\"\n", 0o755)
	}
	if awk := os.Getenv("OPEN_DRAFT_TEST_AWK_SUITE"); awk != "" {
		// An awk that runs every awk program of the suite in place of the one on PATH.
		if _, err := os.Stat(awk); err != nil {
			t.Skipf("OPEN_DRAFT_TEST_AWK_SUITE=%s: %v", awk, err)
		}
		os.Remove(filepath.Join(f.bin, "awk"))
		if err := os.Symlink(awk, filepath.Join(f.bin, "awk")); err != nil {
			t.Fatal(err)
		}
	}
	f.write(filepath.Join(f.bin, "gh"), fakeGh, 0o755)
	f.write(filepath.Join(f.bin, "git"), fakeGit, 0o755)
	f.input = map[string]string{
		"QORY_SUBMIT_SYSTEM":      "github.com",
		"QORY_SUBMIT_PATH":        repo,
		"QORY_SUBMIT_BRANCH":      branch,
		"QORY_SUBMIT_BASE_BRANCH": baseBranch,
		"QORY_SUBMIT_BASE_COMMIT": sha("a"),
		"QORY_SUBMIT_COMMITS":     sha("b") + " " + sha("c"),
		"QORY_SUBMIT_DRAFT":       "open",
		"QORY_SUBMIT_TITLE":       title,
	}
	f.setText("Show the delivery date.")
	f.set("list.out", "")
	f.set("list.json", "[]")
	return f
}

func (f *fake) write(path, content string, mode os.FileMode) {
	f.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) set(name, content string) { f.write(filepath.Join(f.dir, name), content, 0o644) }

func (f *fake) setText(text string) {
	f.t.Helper()
	p := filepath.Join(f.t.TempDir(), "description.md")
	f.write(p, text, 0o644)
	f.input["QORY_SUBMIT_DESCRIPTION_FILE"] = p
}

// setList sets what the search from the branch returns.
func (f *fake) setList(ps ...pull) {
	f.t.Helper()
	var text strings.Builder
	var js []map[string]any
	for _, p := range ps {
		text.WriteString(p.text(false))
		js = append(js, p.json())
	}
	b, err := json.Marshal(js)
	if err != nil {
		f.t.Fatal(err)
	}
	f.set("list.out", text.String())
	f.set("list.json", string(b))
}

// setRead sets what the read of one pull request returns.
func (f *fake) setRead(p pull) {
	f.t.Helper()
	b, err := json.Marshal(p.json())
	if err != nil {
		f.t.Fatal(err)
	}
	key := "read." + strconv.Itoa(p.Number)
	f.set(key+".out", p.text(true))
	f.set(key+".json", string(b))
}

// have makes the pull requests exist: the search returns them, and each can be read.
func (f *fake) have(ps ...pull) {
	f.setList(ps...)
	for _, p := range ps {
		f.setRead(p)
	}
}

type result struct {
	stdout, stderr string
	code           int
}

func (f *fake) run(env ...string) result {
	f.t.Helper()
	var shell []string
	if sh := os.Getenv("OPEN_DRAFT_TEST_SHELL"); sh != "" {
		// A shell that runs the program in place of its shebang, such as dash.
		shell = []string{sh}
	}
	return f.runProgram(program(f.t), shell, env...)
}

func (f *fake) runProgram(prog string, shell []string, env ...string) result {
	f.t.Helper()
	cmd := f.command(prog, shell, env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return f.finish(err, out.String(), errb.String())
}

// command is the program with the inputs of the fake and env, not started.
func (f *fake) command(prog string, shell []string, env ...string) *exec.Cmd {
	f.t.Helper()
	vars := map[string]string{}
	for k, v := range f.input {
		vars[k] = v
	}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		if v == "\x00" {
			delete(vars, k)
		} else {
			vars[k] = v
		}
	}
	cmd := exec.Command(prog)
	if shell != nil {
		cmd = exec.Command(shell[0], append(shell[1:], prog)...)
	}
	cmd.Dir = f.t.TempDir()
	cmd.Env = []string{"PATH=" + f.bin, "HOME=" + f.t.TempDir(), "TMPDIR=" + f.tmp, "GH_TOKEN=" + secret, "FAKE_GH_DIR=" + f.dir}
	if f.mode == "jq" {
		cmd.Env = append(cmd.Env, "FAKE_GH_JQ=1")
	}
	for k, v := range vars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}

// finish is the result of a run that ended with err, after the checks that every run has.
func (f *fake) finish(err error, stdout, stderr string) result {
	f.t.Helper()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		f.t.Fatal(err)
	}
	r := result{stdout, stderr, code}
	if left, _ := filepath.Glob(filepath.Join(f.tmp, "*")); len(left) > 0 {
		f.t.Errorf("the program left %v in TMPDIR", left)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "git-called")); err == nil {
		f.t.Errorf("the program ran git")
	}
	for _, s := range []string{r.stdout, r.stderr} {
		if strings.Contains(s, secret) {
			f.t.Errorf("the output has the token: %q", s)
		}
	}
	return r
}

// calls are the calls to gh, each as its arguments, and files the copies of the files
// that a call named.
func (f *fake) calls() [][]string {
	var all [][]string
	for n := 1; ; n++ {
		b, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("call.%d", n)))
		if err != nil {
			return all
		}
		all = append(all, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"))
	}
}

func (f *fake) file(n int) string {
	b, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("call.%d.file", n)))
	if err != nil {
		f.t.Fatalf("call %d has no file: %v", n, err)
	}
	return string(b)
}

// kinds lists the calls by their kind: auth, list, read, create, patch.
func (f *fake) kinds() []string {
	var ks []string
	for _, c := range f.calls() {
		line := strings.Join(c, " ")
		switch {
		case strings.HasPrefix(line, "auth token"):
			ks = append(ks, "auth")
		case strings.HasPrefix(line, "pr create"):
			ks = append(ks, "create")
		case strings.Contains(line, "-X PATCH"):
			ks = append(ks, "patch")
		case strings.Contains(line, "/pulls/"):
			ks = append(ks, "read")
		default:
			ks = append(ks, "list")
		}
	}
	return ks
}

func program(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func eachMode(t *testing.T, fn func(t *testing.T, mode string)) {
	for _, mode := range []string{"text", "jq"} {
		t.Run(mode, func(t *testing.T) { fn(t, mode) })
	}
}

// commitLines are the lines for the base commit and the two commits of the default input.
func commitLines() string {
	var s strings.Builder
	for _, c := range []string{"a", "b", "c"} {
		fmt.Fprintf(&s, "commit_url %s https://github.com/%s/commit/%s\n", sha(c), repo, sha(c))
	}
	return s.String()
}

func draftLines(n int, ttl, state, action string) string {
	return fmt.Sprintf("draft_number %d\ndraft_url https://github.com/%s/pull/%d\ndraft_title %s\ndraft_state %s\ndraft_action %s\n", n, repo, n, ttl, state, action)
}

func wantResult(t *testing.T, r result, code int, stdout string) {
	t.Helper()
	if r.code != code || r.stdout != stdout {
		t.Errorf("exit %d (want %d), stdout %q, want %q, stderr %q", r.code, code, r.stdout, stdout, r.stderr)
	}
}

func TestAFirstRunOpensOneDraft(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		f := newFake(t, mode)
		f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
		f.setRead(pull{Number: 12, Draft: true, Title: title, Body: block("Show the delivery date.")})
		r := f.run()
		wantResult(t, r, 0, commitLines()+draftLines(12, title, "draft", "opened"))
		if r.stderr != "" {
			t.Errorf("stderr %q", r.stderr)
		}
		if got, want := strings.Join(f.kinds(), " "), "auth list create read"; got != want {
			t.Fatalf("calls %s, want %s", got, want)
		}
		calls := f.calls()
		wantAuth := "auth token --hostname github.com"
		if got := strings.Join(calls[0], " "); got != wantAuth {
			t.Errorf("auth call %q, want %q", got, wantAuth)
		}
		list := calls[1]
		wantList := []string{"api", "-X", "GET", "--hostname", "github.com", "repos/" + repo + "/pulls",
			"-f", "head=acme-corp:" + branch, "-f", "state=all", "-f", "per_page=100", "--jq"}
		if strings.Join(list[:len(list)-1], "\x00") != strings.Join(wantList, "\x00") {
			t.Errorf("search call %q, want %q and an expression", list, wantList)
		}
		create := calls[2]
		wantCreate := []string{"pr", "create", "--repo", "github.com/" + repo, "--draft", "--head", branch, "--base", baseBranch,
			"--title", title, "--body-file"}
		if strings.Join(create[:len(create)-1], "\x00") != strings.Join(wantCreate, "\x00") {
			t.Errorf("create call %q, want %q and a file", create, wantCreate)
		}
		if got, want := f.file(3), block("Show the delivery date."); got != want {
			t.Errorf("the description is %q, want %q", got, want)
		}
	})
}

func TestAnOpenedDraftThatIsReadyShowsOpen(t *testing.T) {
	f := newFake(t, "text")
	f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
	f.setRead(pull{Number: 12, Title: "Edited by GitHub", Body: block("x")})
	wantResult(t, f.run(), 0, commitLines()+draftLines(12, "Edited by GitHub", "open", "opened"))
}

func TestARunWithoutAPrintedAddressFindsTheDraftFromTheBranch(t *testing.T) {
	f := newFake(t, "text")
	f.set("create.out", "created\n")
	f.set("list.2.out", pull{Number: 31, Draft: true, Title: title}.text(false))
	f.setRead(pull{Number: 31, Draft: true, Title: title})
	wantResult(t, f.run(), 0, commitLines()+draftLines(31, title, "draft", "opened"))
}

func TestALaterRunUpdatesOnlyTheBlockAndNeverTheTitle(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		f := newFake(t, mode)
		f.setText("Second round.\nTwo lines.")
		existing := "Dana above.\n\n" + block("First round.") + "\n\nDana below."
		f.have(pull{Number: 8, Draft: true, Title: "Dana renamed this", Body: existing})
		r := f.run()
		wantResult(t, r, 0, commitLines()+draftLines(8, "Dana renamed this", "draft", "updated"))
		if got, want := strings.Join(f.kinds(), " "), "auth list read patch"; got != want {
			t.Fatalf("calls %s, want %s", got, want)
		}
		patch := f.calls()[3]
		if len(patch) != 9 || strings.Join(patch[:7], " ") != "api -X PATCH --hostname github.com repos/"+repo+"/pulls/8 -F" ||
			!strings.HasPrefix(patch[7], "body=@") || patch[8] != "--silent" {
			t.Errorf("update call %q: it sends the description alone", patch)
		}
		if got, want := f.file(4), "Dana above.\n\n"+block("Second round.\nTwo lines.")+"\n\nDana below."; got != want {
			t.Errorf("the description is %q, want %q", got, want)
		}
	})
}

func TestARunWhoseTextIsInTheBlockChangesNothing(t *testing.T) {
	f := newFake(t, "text")
	f.have(pull{Number: 8, Title: "Dana renamed this", Body: "Before.\n" + block("Show the delivery date.")})
	wantResult(t, f.run(), 0, commitLines()+draftLines(8, "Dana renamed this", "open", "kept"))
	if got := strings.Join(f.kinds(), " "); got != "auth list read" {
		t.Errorf("calls %s", got)
	}
}

func TestAClosedOrMergedPullRequestIsNotEdited(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		for _, c := range []struct {
			name  string
			p     pull
			state string
		}{
			{"closed", pull{Number: 4, State: "closed", Title: "Closed one", Body: "Text."}, "closed"},
			{"merged", pull{Number: 5, State: "closed", Merged: true, Title: "Merged one", Body: "Text."}, "merged"},
			{"a draft that was closed", pull{Number: 6, State: "closed", Draft: true, Title: "Closed draft", Body: "Text."}, "closed"},
		} {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				f := newFake(t, mode)
				f.have(c.p)
				wantResult(t, f.run(), 0, commitLines()+draftLines(c.p.Number, c.p.Title, c.state, "kept"))
				if got := strings.Join(f.kinds(), " "); got != "auth list read" {
					t.Errorf("calls %s: it changes nothing and opens nothing", got)
				}
			})
		}
	})
}

// The draft among several: the highest number that is not closed and not merged, else
// the highest number.
func TestSeveralPullRequestsFromTheBranch(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		closed := pull{Number: 5, State: "closed", Title: "Five"}
		open7 := pull{Number: 7, Title: "Seven", Draft: true, Body: "Text."}
		open9 := pull{Number: 9, Title: "Nine", Draft: true, Body: "Text."}
		merged11 := pull{Number: 11, State: "closed", Merged: true, Title: "Eleven"}
		closed12 := pull{Number: 12, State: "closed", Title: "Twelve"}
		fork := pull{Number: 20, Repo: "someone/widgets-app", Title: "Fork"}
		noRepo := pull{Number: 21, Repo: "-", Title: "Deleted fork"}
		otherBranch := pull{Number: 22, Ref: "other", Title: "Other branch"}
		upper := pull{Number: 23, Repo: "Acme-Corp/Widgets-App", Title: "Upper case", Draft: true, Body: "Text."}
		for _, c := range []struct {
			name   string
			ps     []pull
			want   pull
			state  string
			action string
		}{
			{"the highest that is not closed or merged", []pull{open7, closed, open9, merged11, closed12}, open9, "draft", "updated"},
			{"none is open, so the highest number", []pull{closed, merged11, closed12}, closed12, "closed", "kept"},
			{"none is open and the highest is merged", []pull{closed, closed12, pull{Number: 13, State: "closed", Merged: true, Title: "Thirteen"}}, pull{Number: 13, State: "closed", Merged: true, Title: "Thirteen"}, "merged", "kept"},
			{"forks, deleted forks and other branches are not it", []pull{open7, fork, noRepo, otherBranch}, open7, "draft", "updated"},
			{"the repository is compared without regard to case", []pull{open7, upper}, upper, "draft", "updated"},
		} {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				f := newFake(t, mode)
				f.setText("New text.")
				f.have(c.ps...)
				wantResult(t, f.run(), 0, commitLines()+draftLines(c.want.Number, c.want.norm().Title, c.state, c.action))
				kinds := strings.Join(f.kinds(), " ")
				if want := map[string]string{"updated": "auth list read patch", "kept": "auth list read"}[c.action]; kinds != want {
					t.Errorf("calls %s, want %s", kinds, want)
				}
			})
		}
	})
}

func TestADescriptionIsWrittenByTheRuleOfTheContract(t *testing.T) {
	dirs, err := filepath.Glob("testdata/description/*")
	if err != nil || len(dirs) < 20 {
		t.Fatalf("fixtures %v, %v", dirs, err)
	}
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	eachMode(t, func(t *testing.T, mode string) {
		for _, dir := range dirs {
			existing, text, want := read(dir+"/existing.md"), read(dir+"/text.md"), read(dir+"/result.md")
			for _, null := range []bool{false, true} {
				if null && existing != "" {
					continue
				}
				t.Run(filepath.Base(dir)+fmt.Sprint(map[bool]string{true: " null", false: ""}[null]), func(t *testing.T) {
					t.Parallel()
					f := newFake(t, mode)
					f.setText(text)
					f.have(pull{Number: 3, Body: existing, NullBody: null})
					r := f.run()
					if want == existing {
						wantResult(t, r, 0, commitLines()+draftLines(3, "Title of 3", "open", "kept"))
						if got := strings.Join(f.kinds(), " "); got != "auth list read" {
							t.Errorf("calls %s", got)
						}
						return
					}
					wantResult(t, r, 0, commitLines()+draftLines(3, "Title of 3", "open", "updated"))
					if got := strings.Join(f.kinds(), " "); got != "auth list read patch" {
						t.Fatalf("calls %s", got)
					}
					if got := f.file(4); got != want {
						t.Errorf("the description is %q, want %q", got, want)
					}
				})
			}
		}
	})
}

// The adapter writes the description with contracts.MarkedDescription: the program gives
// the same bytes for the same description and text, the cases of the contract's fixtures
// and the cases of the adapter's tests (internal/serve/submission_test.go).
func TestTheProgramWritesWhatTheAdapterWrites(t *testing.T) {
	type c struct{ name, existing, text string }
	cases := []c{
		{"a person's lines around the block", "Dana above.\n\n" + block("First.") + "\n\nDana below.", "Second.\nTwo lines."},
		{"no markers", "Dana wrote all of this.", "Second text."},
		{"the block is the text already", block("Same text."), "Same text."},
		{"a CRLF description with a multi-line block", "Dana above.\r\n" + strings.ReplaceAll(block("Line one.\nLine two.\n\nLine four."), "\n", "\r\n") + "\r\nDana below.", "Line one.\nLine two.\n\nLine four."},
		{"a stray start marker", "Intro.\n" + startLine + "\nA person wrote this.\n", "One."},
		{"a stray start marker and a block", "Intro.\n" + startLine + "\nA person wrote this.\n\n" + block("One."), "Two."},
		{"an end marker before a start marker", endLine + "\ntext\n" + startLine + "\n", "Text."},
		{"a marker with trailing spaces and a tab", startLine + " \t\nold\n" + endLine + "  \r\nafter", "New."},
		{"only a line feed", "\n", "Text."},
		{"two line feeds", "\n\n", "Text."},
		{"a carriage return line", "\r\n", "Text."},
		{"a line of spaces", "   ", "Text."},
		{"an empty text", "Before.\n" + block("Old."), ""},
		{"a text with a trailing line feed", "Before.", "Text.\n"},
		{"two blocks", block("One.") + "\nmiddle\n" + block("Two."), "New."},
		{"a long description", strings.Repeat("A line of the description.\n", 2000), "Text."},
	}
	dirs, _ := filepath.Glob("testdata/description/*")
	for _, dir := range dirs {
		e, _ := os.ReadFile(dir + "/existing.md")
		x, _ := os.ReadFile(dir + "/text.md")
		cases = append(cases, c{filepath.Base(dir), string(e), string(x)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake(t, "text")
			f.setText(tc.text)
			f.have(pull{Number: 3, Body: tc.existing})
			r := f.run()
			want := contracts.MarkedDescription(tc.existing, tc.text)
			if r.code != 0 {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			if want == tc.existing {
				if got := strings.Join(f.kinds(), " "); got != "auth list read" {
					t.Errorf("calls %s: the adapter writes nothing", got)
				}
				return
			}
			if got := strings.Join(f.kinds(), " "); got != "auth list read patch" {
				t.Fatalf("calls %s", got)
			}
			if got := f.file(4); got != want {
				t.Errorf("the program writes %q, the adapter writes %q", got, want)
			}
		})
	}
}

func TestARunWithNoDraftPrintsOnlyTheAddresses(t *testing.T) {
	f := newFake(t, "text")
	r := f.run("QORY_SUBMIT_DRAFT=none", "QORY_SUBMIT_TITLE=\x00", "QORY_SUBMIT_DESCRIPTION_FILE=\x00", "QORY_SUBMIT_BASE_BRANCH=\x00")
	wantResult(t, r, 0, commitLines())
	if len(f.calls()) != 0 || r.stderr != "" {
		t.Errorf("calls %v, stderr %q: no call to gh is needed", f.calls(), r.stderr)
	}
}

func TestEachCommitGetsAnAddress(t *testing.T) {
	f := newFake(t, "text")
	var ids, want []string
	for _, c := range []string{"1", "2", "3", "4"} {
		ids = append(ids, sha(c))
	}
	want = append(want, "commit_url "+sha("a")+" https://github.com/"+repo+"/commit/"+sha("a"))
	for _, id := range ids {
		want = append(want, "commit_url "+id+" https://github.com/"+repo+"/commit/"+id)
	}
	r := f.run("QORY_SUBMIT_DRAFT=none", "QORY_SUBMIT_COMMITS="+strings.Join(ids, " "))
	wantResult(t, r, 0, strings.Join(want, "\n")+"\n")
	// A SHA-256 repository has 64 digits.
	long := strings.Repeat("e", 64)
	r = f.run("QORY_SUBMIT_DRAFT=none", "QORY_SUBMIT_BASE_COMMIT="+long, "QORY_SUBMIT_COMMITS="+long)
	wantResult(t, r, 0, "commit_url "+long+" https://github.com/"+repo+"/commit/"+long+"\ncommit_url "+long+" https://github.com/"+repo+"/commit/"+long+"\n")
	var hundred []string
	for i := range 100 {
		hundred = append(hundred, fmt.Sprintf("%040x", i+1))
	}
	r = f.run("QORY_SUBMIT_DRAFT=none", "QORY_SUBMIT_COMMITS="+strings.Join(hundred, " "))
	if r.code != 0 || strings.Count(r.stdout, "\n") != 101 {
		t.Errorf("exit %d, %d lines", r.code, strings.Count(r.stdout, "\n"))
	}
}

func TestNoLoginIsExit3WithTheLoginCommandFirst(t *testing.T) {
	f := newFake(t, "text")
	f.set("auth.err", "no oauth token found for github.com\n")
	f.set("auth.status", "1")
	r := f.run()
	if r.code != 3 || strings.SplitN(r.stderr, "\n", 2)[0] != loginLine || r.stderr != loginLine+"\n" {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
	// The login is read locally with gh auth token; gh auth status, which calls GitHub, is not run.
	calls := f.calls()
	if len(calls) != 1 || strings.Join(calls[0], " ") != "auth token --hostname github.com" {
		t.Errorf("calls %q", calls)
	}
	if r.stdout != commitLines() {
		t.Errorf("stdout %q", r.stdout)
	}
}

func TestTheTokenIsNeverPrinted(t *testing.T) {
	f := newFake(t, "text")
	f.set("auth.out", secret+"\n")
	f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
	f.setRead(pull{Number: 12, Draft: true, Title: title})
	r := f.run()
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, secret) {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestANetworkFailureIsExit1NotALoginError(t *testing.T) {
	for _, key := range []string{"list", "create", "read.8", "patch"} {
		f := newFake(t, "text")
		if key != "list" && key != "create" {
			f.have(pull{Number: 8, Body: "old"})
		}
		f.set(key+".err", `Get "https://api.github.com/repos/acme-corp/widgets-app/pulls": dial tcp: lookup api.github.com: no such host`+"\n")
		f.set(key+".status", "1")
		r := f.run()
		if r.code != 1 || strings.Contains(r.stderr, "gh auth login") || !strings.Contains(r.stderr, "no such host") || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("%s: exit %d, stderr %q", key, r.code, r.stderr)
		}
	}
}

func TestARejectedLoginIsExit3(t *testing.T) {
	for _, key := range []string{"list", "create", "patch"} {
		f := newFake(t, "text")
		switch key {
		case "create":
			f.set("create.err", "gh: Bad credentials (HTTP 401)\n")
		case "patch":
			f.have(pull{Number: 8, Body: "old"})
		}
		f.set(key+".err", "gh: Bad credentials (HTTP 401)\n")
		f.set(key+".status", "1")
		r := f.run()
		if r.code != 3 || r.stderr != loginLine+"\n" {
			t.Errorf("%s: exit %d, stderr %q", key, r.code, r.stderr)
		}
	}
}

func TestAFailedCallIsExit1WithTheFixAndTheCauseOnTheFirstLine(t *testing.T) {
	for _, c := range []struct{ key, cause, what string }{
		{"list", "gh: Bad gateway (HTTP 502)", "the search for the pull request of the branch"},
		{"create", "gh: Validation Failed (HTTP 422)\nA pull request already exists", "the opening of the draft pull request"},
		{"read.8", "gh: Not Found (HTTP 404)", "the read of pull request 8"},
		{"patch", "gh: Resource not accessible by integration (HTTP 403)", "the update of pull request 8"},
	} {
		t.Run(c.key, func(t *testing.T) {
			f := newFake(t, "text")
			if c.key != "list" && c.key != "create" {
				f.have(pull{Number: 8, Body: "old"})
			}
			first, rest, _ := strings.Cut(c.cause, "\n")
			f.set(c.key+".err", first+" token "+secret+"\n"+rest+"\n")
			f.set(c.key+".status", "1")
			r := f.run()
			gotFirst := strings.SplitN(r.stderr, "\n", 2)[0]
			wantFirst := "Check your gh login and its access to " + repo + ", then run `qory run` again: " + c.what + " failed: " +
				strings.SplitN(c.cause, "\n", 2)[0] + " token ***"
			if r.code != 1 || gotFirst != wantFirst || r.stderr != gotFirst+"\n" {
				t.Errorf("exit %d, stderr %q, want the line %q", r.code, r.stderr, wantFirst)
			}
			if !strings.HasPrefix(r.stdout, commitLines()) || strings.Contains(r.stdout, "draft_") {
				t.Errorf("stdout %q: the addresses stay, and no draft line", r.stdout)
			}
		})
	}
}

func TestAFailedCallWithNoMessageIsExit1(t *testing.T) {
	f := newFake(t, "text")
	f.set("list.status", "1")
	r := f.run()
	if r.code != 1 || !strings.HasSuffix(r.stderr, "failed: gh printed no message\n") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestAReadThatReturnsNoPullRequestIsExit1(t *testing.T) {
	f := newFake(t, "text")
	f.setList(pull{Number: 8})
	f.set("read.8.out", "")
	r := f.run()
	if r.code != 1 || !strings.HasPrefix(r.stderr, "Check that gh reaches github.com") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestNoGhIsExit1WithTheFixFirst(t *testing.T) {
	f := newFake(t, "text")
	if err := os.Remove(filepath.Join(f.bin, "gh")); err != nil {
		t.Fatal(err)
	}
	r := f.run()
	if r.code != 1 || !strings.HasPrefix(r.stderr, "Install gh from https://cli.github.com") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestTheCapsOf20000And256Characters(t *testing.T) {
	two := "é" // two bytes, one character
	for _, c := range []struct {
		name, ttl, text string
		code            int
	}{
		{"a description of 20000 characters", title, strings.Repeat(two, 20000), 0},
		{"a description of 20001 characters", title, strings.Repeat(two, 20001), 2},
		{"a description of 20000 ASCII characters", title, strings.Repeat("d", 20000), 0},
		{"a description of 20001 ASCII characters", title, strings.Repeat("d", 20001), 2},
		{"a title of 256 characters", strings.Repeat(two, 256), "Text.", 0},
		{"a title of 257 characters", strings.Repeat(two, 257), "Text.", 2},
		{"a title of 256 ASCII characters", strings.Repeat("t", 256), "Text.", 0},
		{"a title of 257 ASCII characters", strings.Repeat("t", 257), "Text.", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t, "text")
			f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
			f.setRead(pull{Number: 12, Draft: true, Title: c.ttl})
			f.setText(c.text)
			r := f.run("QORY_SUBMIT_TITLE=" + c.ttl)
			if r.code != c.code {
				t.Fatalf("exit %d, want %d, stderr %q", r.code, c.code, r.stderr)
			}
			if c.code == 2 && (r.stdout != commitLines() || len(f.calls()) != 0 || !strings.HasPrefix(r.stderr, "Shorten ")) {
				t.Errorf("stdout %q, calls %v, stderr %q", r.stdout, f.calls(), r.stderr)
			}
		})
	}
}

// draftInputs are the cases of TestInputsThatCannotBeUsedAreExit2WithTheFixFirst whose bad
// input is one of the draft's: the program has printed the commit addresses before it
// refuses them, since they need only the commits.
var draftInputs = map[string]bool{
	"no title": true, "a title with a line feed": true, "a title of spaces": true, "no base branch": true,
	"a bad base branch": true, "no description file": true, "a description file that is missing": true,
}

func TestInputsThatCannotBeUsedAreExit2WithTheFixFirst(t *testing.T) {
	for _, c := range []struct {
		name string
		env  []string
		want string
	}{
		{"no system", []string{"QORY_SUBMIT_SYSTEM=\x00"}, "Set QORY_SUBMIT_SYSTEM"},
		{"another system", []string{"QORY_SUBMIT_SYSTEM=code.example.com"}, "Compose a submit program for code.example.com"},
		{"no path", []string{"QORY_SUBMIT_PATH=\x00"}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"a path with no name", []string{"QORY_SUBMIT_PATH=acme"}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"a path of three parts", []string{"QORY_SUBMIT_PATH=a/b/c"}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"a path with a dot name", []string{"QORY_SUBMIT_PATH=acme/.."}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"a path with a space", []string{"QORY_SUBMIT_PATH=acme/my app"}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"an owner that starts with a dash", []string{"QORY_SUBMIT_PATH=-acme/app"}, "Set QORY_SUBMIT_PATH to owner/name"},
		{"no branch", []string{"QORY_SUBMIT_BRANCH=\x00"}, "Set QORY_SUBMIT_BRANCH to a branch name: it is empty"},
		{"a branch that starts with a dash", []string{"QORY_SUBMIT_BRANCH=-x"}, "Set QORY_SUBMIT_BRANCH to a branch name that git accepts"},
		{"a branch with a space", []string{"QORY_SUBMIT_BRANCH=a b"}, "Set QORY_SUBMIT_BRANCH to a branch name that git accepts"},
		{"a branch with two dots", []string{"QORY_SUBMIT_BRANCH=a..b"}, "Set QORY_SUBMIT_BRANCH to a branch name that git accepts"},
		{"a branch with a line feed", []string{"QORY_SUBMIT_BRANCH=a\nb"}, "Set QORY_SUBMIT_BRANCH to a branch name: the value has a control character"},
		{"a draft that is neither open nor none", []string{"QORY_SUBMIT_DRAFT=update"}, "Set QORY_SUBMIT_DRAFT to open or none"},
		{"a short base commit", []string{"QORY_SUBMIT_BASE_COMMIT=abc123"}, "Set QORY_SUBMIT_BASE_COMMIT"},
		{"an upper-case base commit", []string{"QORY_SUBMIT_BASE_COMMIT=" + strings.Repeat("A", 40)}, "Set QORY_SUBMIT_BASE_COMMIT"},
		{"no commits", []string{"QORY_SUBMIT_COMMITS=\x00"}, "Set QORY_SUBMIT_COMMITS to 1 to 100 commit ids: it has 0"},
		{"a commit that is not a commit id", []string{"QORY_SUBMIT_COMMITS=" + sha("b") + " main"}, "Set QORY_SUBMIT_COMMITS to commit ids"},
		{"commits on two lines", []string{"QORY_SUBMIT_COMMITS=" + sha("b") + "\n" + sha("c")}, "Join the commit ids in QORY_SUBMIT_COMMITS"},
		{"commits joined by two spaces", []string{"QORY_SUBMIT_COMMITS=" + sha("b") + "  " + sha("c")}, "Join the commit ids in QORY_SUBMIT_COMMITS"},
		{"no title", []string{"QORY_SUBMIT_TITLE=\x00"}, "Set QORY_SUBMIT_TITLE"},
		{"a title with a line feed", []string{"QORY_SUBMIT_TITLE=a\nb"}, "Set QORY_SUBMIT_TITLE to a title on one line"},
		{"a title of spaces", []string{"QORY_SUBMIT_TITLE=   "}, "Set QORY_SUBMIT_TITLE to a title with a character"},
		{"no base branch", []string{"QORY_SUBMIT_BASE_BRANCH=\x00"}, "Set QORY_SUBMIT_BASE_BRANCH to the base branch of the draft"},
		{"a bad base branch", []string{"QORY_SUBMIT_BASE_BRANCH=a~b"}, "Set QORY_SUBMIT_BASE_BRANCH to a branch name that git accepts"},
		{"no description file", []string{"QORY_SUBMIT_DESCRIPTION_FILE=\x00"}, "Set QORY_SUBMIT_DESCRIPTION_FILE"},
		{"a description file that is missing", []string{"QORY_SUBMIT_DESCRIPTION_FILE=/nonexistent/d.md"}, "Make the description file readable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newFake(t, "text")
			r := f.run(c.env...)
			wantOut := ""
			if draftInputs[c.name] {
				wantOut = commitLines()
			}
			if r.code != 2 || r.stdout != wantOut || !strings.HasPrefix(r.stderr, c.want) || strings.Count(r.stderr, "\n") != 1 || len(f.calls()) != 0 {
				t.Errorf("exit %d, stdout %q, stderr %q, calls %v; want stdout %q and stderr that starts %q", r.code, r.stdout, r.stderr, f.calls(), wantOut, c.want)
			}
			if first := strings.SplitN(r.stderr, "\n", 2)[0]; len(first) > 200 {
				t.Errorf("the line has %d characters", len(first))
			}
		})
	}
}

func TestACarriageReturnInTheDescriptionFileKeepsItsBytes(t *testing.T) {
	f := newFake(t, "text")
	f.setText("One.\r\nTwo.\r\n")
	f.have(pull{Number: 3, Body: "Plain."})
	wantResult(t, f.run(), 0, commitLines()+draftLines(3, "Title of 3", "open", "updated"))
	if got, want := f.file(4), "Plain.\n\n"+startLine+"\nOne.\r\nTwo.\r\n\n"+endLine; got != want {
		t.Errorf("the description is %q, want %q", got, want)
	}
}

func TestTheProgramRunsUnderDash(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is not on PATH")
	}
	for _, args := range [][]string{{dash}, {"sh"}} {
		f := newFake(t, "text")
		f.have(pull{Number: 8, Draft: true, Body: "Dana.\n" + block("Old.")})
		sh := args
		if args[0] == "sh" {
			p, _ := exec.LookPath("sh")
			sh = []string{p}
		}
		r := f.runProgram(program(t), sh)
		wantResult(t, r, 0, commitLines()+draftLines(8, "Title of 8", "draft", "updated"))
		if out, err := exec.Command(sh[0], "-n", program(t)).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v: %s", sh[0], err, out)
		}
	}
}

func TestTheModuleDeclaresTheProgram(t *testing.T) {
	b, err := os.ReadFile("../../modules/github/qory-module.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Name          string `yaml:"name"`
		SubmitProgram struct {
			Command []string `yaml:"command"`
		} `yaml:"submit_program"`
	}
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "github" || len(m.SubmitProgram.Command) != 1 || m.SubmitProgram.Command[0] != "bin/open-draft" {
		t.Errorf("the manifest is %+v", m)
	}
	fi, err := os.Stat("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Errorf("bin/open-draft mode = %v, want executable", fi.Mode())
	}
	src, err := os.ReadFile("../../modules/github/bin/open-draft")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(src), "#!/bin/sh\n") {
		t.Errorf("the program does not start with #!/bin/sh")
	}
	for _, word := range []string{"QORY_SUBMIT_BASES", "QORY_PROXY", "node", "python", "git push", "bash"} {
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, word) {
				t.Errorf("line %d has %q: %s", i+1, word, line)
			}
		}
	}
}

// parsed checks that qory records the lines of a run: the five draft lines are valid
// (contracts.ParseSubmitLines gives a draft and no line that it leaves out).
func parsed(t *testing.T, stdout string) *contracts.SubmittedDraft {
	t.Helper()
	ids := []string{sha("a"), sha("b"), sha("c")}
	res := contracts.ParseSubmitLines(stdout, "github.com", "open", ids)
	if res.Draft == nil || len(res.Invalid) != 0 || len(res.CommitURLs) != 3 {
		t.Fatalf("qory does not record %q: draft %+v, left out %v", stdout, res.Draft, res.Invalid)
	}
	return res.Draft
}

func TestATitleHasNoCharacterTheContractRefuses(t *testing.T) {
	eachMode(t, func(t *testing.T, mode string) {
		classes := map[string]string{
			"a C0 control":        "\x01",
			"a delete":            "\x7f",
			"a line feed":         "\n",
			"a carriage return":   "\r",
			"a tab":               "\t",
			"a C1 control":        "\u0085",
			"the highest C1":      "\u009f",
			"a soft hyphen":       "\u00ad",
			"an Arabic mark":      "\u061c",
			"a Mongolian vowel":   "\u180e",
			"a zero width space":  "\u200b",
			"a left-to-right":     "\u200e",
			"a right-to-left":     "\u200f",
			"a line separator":    "\u2028",
			"a paragraph sep":     "\u2029",
			"a bidi embedding":    "\u202a",
			"a bidi override":     "\u202e",
			"a word joiner":       "\u2060",
			"an invisible plus":   "\u2064",
			"an isolate":          "\u2066",
			"a pop isolate":       "\u2069",
			"a byte order mark":   "\ufeff",
			"an annotation start": "\ufff9",
			"an annotation end":   "\ufffb",
		}
		for name, ch := range classes {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				f := newFake(t, mode)
				f.have(pull{Number: 8, Draft: true, Title: "Show" + ch + " dates", Body: "x"})
				r := f.run()
				wantResult(t, r, 0, commitLines()+draftLines(8, "Show dates", "draft", "updated"))
				if d := parsed(t, r.stdout); d.Title != "Show dates" {
					t.Errorf("recorded title %q", d.Title)
				}
			})
		}
		// A character next to the allowed ones stays: the neighbours of each range.
		for _, keep := range []string{"\u00a0x", "¬", "؛", "᠍", "\u200a", "\u2010", "\u202f", "\u205f", "\u2065", "\u206a", "﻾", "￸", "￼", "é", "日本語"} {
			t.Run("keeps "+keep, func(t *testing.T) {
				t.Parallel()
				f := newFake(t, mode)
				f.have(pull{Number: 8, Draft: true, Title: "Show" + keep, Body: "x"})
				wantResult(t, f.run(), 0, commitLines()+draftLines(8, "Show"+keep, "draft", "updated"))
			})
		}
		t.Run("nothing but forbidden characters and spaces uses the title of the run", func(t *testing.T) {
			for _, ghTitle := range []string{"\u200b\u202e", " \u200f ", "\u00a0\u3000\u200b", "\n\n", "   "} {
				f := newFake(t, mode)
				f.have(pull{Number: 8, Draft: true, Title: ghTitle, Body: "x"})
				r := f.run("QORY_SUBMIT_TITLE=Show\u200b dates\u202e")
				wantResult(t, r, 0, commitLines()+draftLines(8, "Show dates", "draft", "updated"))
				parsed(t, r.stdout)
			}
		})
		t.Run("a closed pull request is cleaned too", func(t *testing.T) {
			f := newFake(t, mode)
			f.have(pull{Number: 4, State: "closed", Title: "Old\u200f\nname"})
			wantResult(t, f.run(), 0, commitLines()+draftLines(4, "Oldname", "closed", "kept"))
		})
		t.Run("a new draft shows the title that GitHub has, cleaned", func(t *testing.T) {
			f := newFake(t, mode)
			f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
			f.setRead(pull{Number: 12, Draft: true, Title: "Show\u200b dates"})
			r := f.run()
			wantResult(t, r, 0, commitLines()+draftLines(12, "Show dates", "draft", "opened"))
			parsed(t, r.stdout)
		})
	})
}

func TestATitleOfTheRunWithNothingToShowIsRefused(t *testing.T) {
	for _, bad := range []string{"\u200b", "\u00a0\u3000", " \u202e "} {
		f := newFake(t, "text")
		r := f.run("QORY_SUBMIT_TITLE=" + bad)
		if r.code != 2 || r.stdout != commitLines() || !strings.HasPrefix(r.stderr, "Set QORY_SUBMIT_TITLE to a title with a character") || len(f.calls()) != 0 {
			t.Errorf("title %q: exit %d, stdout %q, stderr %q, calls %v", bad, r.code, r.stdout, r.stderr, f.calls())
		}
	}
}

func TestEveryRunOfTheProgramIsRecordedByQory(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(f *fake)
	}{
		{"opened", func(f *fake) {
			f.set("create.out", "https://github.com/"+repo+"/pull/12\n")
			f.setRead(pull{Number: 12, Draft: true, Title: title})
		}},
		{"updated", func(f *fake) { f.have(pull{Number: 8, Title: "Mine", Body: "x"}) }},
		{"kept merged", func(f *fake) { f.have(pull{Number: 8, State: "closed", Merged: true, Title: "Mine"}) }},
	} {
		f := newFake(t, "text")
		c.set(f)
		r := f.run()
		if r.code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", c.name, r.code, r.stderr)
		}
		parsed(t, r.stdout)
	}
}

// TestTheAddressesAreOnStandardOutputWhenTheDraftInputsAreBad: with QORY_SUBMIT_DRAFT open
// and no base branch, the program exits 2 with the fix on standard error, and has printed
// the address of each commit, which qory reads: the contract reads the lines of a program
// that exits 2, and a draft that they do not make is recorded as program-failed.
func TestTheAddressesAreOnStandardOutputWhenTheDraftInputsAreBad(t *testing.T) {
	f := newFake(t, "text")
	r := f.run("QORY_SUBMIT_BASE_BRANCH=\x00")
	if r.code != 2 || r.stdout != commitLines() || !strings.HasPrefix(r.stderr, "Set QORY_SUBMIT_BASE_BRANCH") || len(f.calls()) != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q, calls %v", r.code, r.stdout, r.stderr, f.calls())
	}
}

// sleeps are the process ids and the arguments of the sleeps that the program started.
func (f *fake) sleeps() [][]string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "sleep.args"))
	var out [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if w := strings.Fields(l); len(w) > 0 {
			out = append(out, w)
		}
	}
	return out
}

// alive returns the process ids, of those given, that still run after up to 3 seconds.
func alive(pids ...string) []string {
	deadline := time.Now().Add(3 * time.Second)
	for {
		var left []string
		for _, p := range pids {
			if p != "" && exec.Command("kill", "-0", p).Run() == nil {
				left = append(left, p)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAHungGhEndsTheProgramWithStatus1AndTheAddressesPrinted: gh does not answer the
// search for the pull request. The program ends with status 1 after the watchdog's limit,
// 3 seconds here, with the fix on the first line of standard error and the commit lines on
// standard output, and no process of the program is left: neither gh nor the timer.
func TestAHungGhEndsTheProgramWithStatus1AndTheAddressesPrinted(t *testing.T) {
	f := newFake(t, "text")
	f.have(pull{Number: 8, Draft: true, Body: block("Old.")})
	f.set("hang.list", "")
	began := time.Now()
	r := f.run("OPEN_DRAFT_WATCHDOG_SECONDS=3")
	if took := time.Since(began); took > 15*time.Second || took < 2*time.Second {
		t.Errorf("the program ended after %v, want about 3 seconds", took)
	}
	wantResult(t, r, 1, commitLines())
	if want := "Run `qory run` again; `gh` did not answer within 3 seconds.\n"; r.stderr != want {
		t.Errorf("stderr %q, want %q", r.stderr, want)
	}
	// The sleeps are the timer and the hung gh, which the fake makes a sleep.
	var pids []string
	for _, s := range f.sleeps() {
		pids = append(pids, s[0])
	}
	if len(pids) != 2 {
		t.Fatalf("the program started %d sleeps, want the timer and the hung gh: %v", len(pids), f.sleeps())
	}
	if left := alive(pids...); len(left) != 0 {
		t.Errorf("processes %v are still running", left)
	}
}

// TestTheWatchdogLeavesNoTimerAfterAnEndOfTheWork: a run that ends in time, with any
// status, leaves no sleep of the timer, and the program waits for none.
func TestTheWatchdogLeavesNoTimerAfterAnEndOfTheWork(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(f *fake)
		code int
	}{
		{"done", func(f *fake) { f.have(pull{Number: 8, Draft: true, Body: block("Old.")}) }, 0},
		{"gh fails", func(f *fake) { f.have(pull{Number: 8}); f.set("list.status", "1") }, 1},
		{"no login", func(f *fake) { f.set("auth.status", "1") }, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t, "text")
			c.set(f)
			began := time.Now()
			r := f.run("OPEN_DRAFT_WATCHDOG_SECONDS=4")
			if r.code != c.code || time.Since(began) > 3*time.Second {
				t.Errorf("exit %d after %v, want %d at once; stderr %q", r.code, time.Since(began), c.code, r.stderr)
			}
			var pids []string
			for _, s := range f.sleeps() {
				pids = append(pids, s[0])
			}
			if len(pids) != 1 {
				t.Fatalf("the program started %d sleeps, want the timer: %v", len(pids), f.sleeps())
			}
			if left := alive(pids...); len(left) != 0 {
				t.Errorf("the timer %v is still running", left)
			}
		})
	}
}

// TestTheWatchdogLimitIsAtMost110Seconds: the variable of the tests takes 1 to 110, and
// any other value is 110.
func TestTheWatchdogLimitIsAtMost110Seconds(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{"", "110"}, {"5", "5"}, {"110", "110"}, {"111", "110"}, {"999", "110"}, {"0", "110"}, {"05", "110"},
		{"-5", "110"}, {"abc", "110"}, {"5 ", "110"}, {"99999999999999999999", "110"},
	} {
		f := newFake(t, "text")
		f.have(pull{Number: 8, Draft: true, Body: block("Old.")})
		r := f.run("OPEN_DRAFT_WATCHDOG_SECONDS=" + c.value)
		if r.code != 0 {
			t.Fatalf("%q: exit %d, stderr %q", c.value, r.code, r.stderr)
		}
		if got := f.sleeps(); len(got) != 1 || len(got[0]) != 2 || got[0][1] != c.want {
			t.Errorf("%q: the timer slept %q, want %s", c.value, got, c.want)
		}
	}
}

// started runs the program and waits until its hung gh, the second call, is running; it
// returns the command, which the test signals, and a function that waits for its result.
func (f *fake) started(env ...string) (*exec.Cmd, func() result) {
	f.t.Helper()
	var shell []string
	if sh := os.Getenv("OPEN_DRAFT_TEST_SHELL"); sh != "" {
		shell = []string{sh}
	}
	cmd := f.command(program(f.t), shell, env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if b, err := os.ReadFile(filepath.Join(f.dir, "pid.2")); err == nil && len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			f.t.Fatal("the hung gh did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cmd, func() result {
		select {
		case err := <-done:
			return f.finish(err, out.String(), errb.String())
		case <-time.After(30 * time.Second):
			cmd.Process.Kill()
			f.t.Fatal("the program did not end")
			return result{}
		}
	}
}

// allStopped checks that every sleep that the program started, the timer and the hung gh,
// is gone, and the temporary directory too, which finish checks.
func (f *fake) allStopped() {
	f.t.Helper()
	var pids []string
	for _, s := range f.sleeps() {
		pids = append(pids, s[0])
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, "pid.2")); err == nil {
		pids = append(pids, strings.TrimSpace(string(b)))
	}
	if len(pids) < 2 {
		f.t.Fatalf("the program started %d processes to check: %v", len(pids), pids)
	}
	if left := alive(pids...); len(left) != 0 {
		f.t.Errorf("processes %v are still running", left)
	}
}

// TestASignalEndsTheProgramWithStatus1AndLeavesNothing: HUP, INT and TERM, sent to the
// program while gh hangs, end it with status 1, the commit lines printed, no timer, no gh,
// and no file in the temporary directory.
func TestASignalEndsTheProgramWithStatus1AndLeavesNothing(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newFake(t, "text")
			f.have(pull{Number: 8, Draft: true, Body: block("Old.")})
			f.set("hang.list", "")
			cmd, wait := f.started()
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			began := time.Now()
			r := wait()
			wantResult(t, r, 1, commitLines())
			if took := time.Since(began); took > 10*time.Second {
				t.Errorf("the program took %v to end", took)
			}
			f.allStopped()
		})
	}
}

// TestAGhThatIgnoresTermIsKilled: gh ignores SIGTERM, and the watchdog, or a signal to
// the program, ends it after a second with SIGKILL: status 1, and no gh left.
func TestAGhThatIgnoresTermIsKilled(t *testing.T) {
	t.Run("the watchdog", func(t *testing.T) {
		f := newFake(t, "text")
		f.have(pull{Number: 8, Draft: true, Body: block("Old.")})
		f.set("hang.list", "ignore TERM")
		r := f.run("OPEN_DRAFT_WATCHDOG_SECONDS=2")
		wantResult(t, r, 1, commitLines())
		f.allStopped()
	})
	t.Run("a signal", func(t *testing.T) {
		f := newFake(t, "text")
		f.have(pull{Number: 8, Draft: true, Body: block("Old.")})
		f.set("hang.list", "ignore TERM")
		cmd, wait := f.started()
		cmd.Process.Signal(syscall.SIGTERM)
		wantResult(t, wait(), 1, commitLines())
		f.allStopped()
	})
}
