package runner

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"gopkg.in/yaml.v3"
)

// valid are values Fill takes.
var valid = Values{
	PublicURL:  "https://starter.example.com",
	Repository: "acme/qory-runner",
	AgentImage: "registry.example.com:5000/qory/agent@sha256:" + strings.Repeat("0123456789abcdef", 4),
	HarnessRef: strings.Repeat("0123456789", 4),
}

// The lines of the run step the tests pin byte for byte: the mkdir and qory run lines
// as the plan has them, the key's branch of the pipe, the line that writes the inputs
// and spoils the key when any command of the pipe fails, the key's jq aside, which
// writes nothing when it fails, and the end of the group.
const (
	mkdirLine = `mkdir "$RUNNER_TEMP/in"`
	jqLine    = `jq -se 'if length == 1 and (.[0] | type) == "object" then .[0].inputs | objects else empty end' > "$RUNNER_TEMP/in/inputs.json" || { printf '\n!' >&3; exit 1; }`
	teeLine   = `tee >(jq -sje 'if length == 1 and (.[0] | type) == "object" and (.[0].inputs | type) == "object" then .[0].run_key | strings else empty end' >&3) |`
	groupLine = `} 3>&1 1>&2 |`
	qoryLine  = `qory run claude --home "$RUNNER_TEMP/homes" --run-key-fd 0 --wall docker --image "$AGENT_IMAGE" --mount "$RUNNER_TEMP/in:ro" --timeout 12m -- --max-turns 40 --add-dir "$RUNNER_TEMP/in" -p "Explore the ticket described in $RUNNER_TEMP/in/inputs.json, following the explore-an-item skill. End with the explore v1 JSON document alone as your final response."`
)

// The qory release the install step takes, and its SHA-256s, from qory v0.13.0's
// checksums.txt.
const (
	qoryURL   = `"https://github.com/qoryai/qory/releases/download/v0.13.0/qory_0.13.0_linux_$arch.tar.gz"`
	sumAMD64  = "955e977bb0d2f4217d8892a424da6d54309df9bfaa6de0fcc17cc8e2daf10ed6"
	sumARM64  = "74ac91bc4c4fd42717f067d44ec6377c44c039ec18b20eec75c70bb0073212be"
	checkLine = `echo "$sum  $RUNNER_TEMP/qory.tar.gz" | sha256sum --check --strict --quiet`
)

// workflow is the part of a GitHub Actions workflow the tests read.
type workflow struct {
	Name        string                 `yaml:"name"`
	On          map[string]any         `yaml:"on"`
	Permissions map[string]any         `yaml:"permissions"`
	Jobs        map[string]job         `yaml:"jobs"`
	Rest        map[string]interface{} `yaml:",inline"`
}

type job struct {
	If             string            `yaml:"if"`
	RunsOn         any               `yaml:"runs-on"`
	TimeoutMinutes any               `yaml:"timeout-minutes"`
	Env            map[string]string `yaml:"env"`
	Steps          []map[string]any  `yaml:"steps"`
	Rest           map[string]any    `yaml:",inline"`
}

// parse reads text as a workflow, failing the test when it is not YAML or has a key
// the workflow should not have.
func parse(t *testing.T, text string) workflow {
	t.Helper()
	var w workflow
	if err := yaml.Unmarshal([]byte(text), &w); err != nil {
		t.Fatalf("the template is not YAML: %v", err)
	}
	if len(w.Rest) != 0 {
		t.Errorf("the workflow has other keys: %v", w.Rest)
	}
	return w
}

// filled is the template filled with valid.
func filled(t *testing.T) string {
	t.Helper()
	s, err := Fill(valid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// runs are the scripts of the workflow's steps, in order.
func runs(t *testing.T, w workflow) []string {
	t.Helper()
	var out []string
	for i, step := range w.Jobs["explore"].Steps {
		run, ok := step["run"].(string)
		if !ok {
			t.Fatalf("step %d has no run", i)
		}
		out = append(out, run)
	}
	return out
}

// lines are the lines of script with the white space around each left out.
func lines(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		out = append(out, strings.TrimSpace(l))
	}
	return out
}

// index is the first line of script equal to want, or -1.
func index(script, want string) int {
	for i, l := range lines(script) {
		if l == want {
			return i
		}
	}
	return -1
}

// TestTheTemplateIsTheWorkflow pins the workflow's shape, as committed and as filled:
// it parses as YAML; workflow_dispatch with one required string input, dispatch_id;
// permissions id-token: write and nothing else; one job on ubuntu-24.04 with
// timeout-minutes 15, run only in the runner repository; its environment the four
// values, dispatch_id among them through the one expression of the template; and three
// steps of bash scripts, each starting set -euo pipefail, and no action used.
func TestTheTemplateIsTheWorkflow(t *testing.T) {
	for name, text := range map[string]string{"committed": Template, "filled": filled(t)} {
		t.Run(name, func(t *testing.T) {
			w := parse(t, text)
			wantOn := map[string]any{"workflow_dispatch": map[string]any{"inputs": map[string]any{"dispatch_id": map[string]any{
				"description": "The dispatch's id, which qory-github-starter sends", "required": true, "type": "string"}}}}
			if !reflect.DeepEqual(w.On, wantOn) {
				t.Errorf("on = %v", w.On)
			}
			if !reflect.DeepEqual(w.Permissions, map[string]any{"id-token": "write"}) {
				t.Errorf("permissions = %v, want id-token: write alone", w.Permissions)
			}
			if len(w.Jobs) != 1 {
				t.Fatalf("jobs = %v, want explore alone", w.Jobs)
			}
			j, ok := w.Jobs["explore"]
			if !ok {
				t.Fatal("no job explore")
			}
			if len(j.Rest) != 0 {
				t.Errorf("the job has other keys: %v", j.Rest)
			}
			if j.RunsOn != "ubuntu-24.04" {
				t.Errorf("runs-on = %v", j.RunsOn)
			}
			if j.TimeoutMinutes != 15 {
				t.Errorf("timeout-minutes = %v (%T), want 15", j.TimeoutMinutes, j.TimeoutMinutes)
			}
			wantEnv := map[string]string{"DISPATCH_ID": "${{ inputs.dispatch_id }}", "STARTER_URL": placeholderPublicURL, "AGENT_IMAGE": placeholderAgentImage, "HARNESS_REF": placeholderHarnessRef}
			wantIf := "github.repository == '" + placeholderRepository + "'"
			if name == "filled" {
				wantEnv["STARTER_URL"], wantEnv["AGENT_IMAGE"], wantEnv["HARNESS_REF"] = valid.PublicURL, valid.AgentImage, valid.HarnessRef
				wantIf = "github.repository == '" + valid.Repository + "'"
			}
			if !reflect.DeepEqual(j.Env, wantEnv) {
				t.Errorf("env = %v, want %v", j.Env, wantEnv)
			}
			if j.If != wantIf {
				t.Errorf("if = %q, want %q", j.If, wantIf)
			}
			if len(j.Steps) != 3 {
				t.Fatalf("%d steps, want 3", len(j.Steps))
			}
			for i, step := range j.Steps {
				for k := range step {
					if k != "name" && k != "shell" && k != "run" {
						t.Errorf("step %d has %s", i, k)
					}
				}
				if step["shell"] != "bash" {
					t.Errorf("step %d: shell = %v", i, step["shell"])
				}
			}
			for i, run := range runs(t, w) {
				if lines(run)[0] != "set -euo pipefail" {
					t.Errorf("step %d starts %q", i, lines(run)[0])
				}
			}
			if n := strings.Count(text, "${{"); n != 1 {
				t.Errorf("the template holds ${{ %d times, want once, for dispatch_id in env", n)
			}
		})
	}
}

// TestNoExpressionInARun pins that no script holds a GitHub Actions expression, ${{,
// and that no value Fill puts in reaches a script: a script reads each through the
// job's environment.
func TestNoExpressionInARun(t *testing.T) {
	for name, text := range map[string]string{"committed": Template, "filled": filled(t)} {
		for i, run := range runs(t, parse(t, text)) {
			if strings.Contains(run, "${{") {
				t.Errorf("%s: step %d's script holds ${{", name, i)
			}
			for _, v := range []string{valid.PublicURL, valid.Repository, valid.AgentImage, valid.HarnessRef, "__"} {
				if strings.Contains(run, v) {
					t.Errorf("%s: step %d's script holds %q", name, i, v)
				}
			}
		}
	}
	committed, fill := runs(t, parse(t, Template)), runs(t, parse(t, filled(t)))
	if !reflect.DeepEqual(committed, fill) {
		t.Error("filling the template changed a script")
	}
}

// TestTheRunLines pins the run step: the dispatch id checked against the provisioner
// contract's pattern before anything else, then the plan's lines byte for byte, in
// order: the mkdir, the handover with curl --fail, the run key to descriptor 3, the
// inputs to the file alone, and qory run with --run-key-fd 0.
//
// Both jq calls slurp the answer, -s, so each reads all the answer it reads before it
// writes anything, and takes it only when it is exactly one JSON value, an object. The
// run key goes to descriptor 3 only when the answer's inputs is also an object and its
// run_key a string; the inputs go to the file only when they are an object. Otherwise
// a call writes nothing and exits non-zero, and prints on stderr at most a parse
// error, whose message names the line and column alone. How a raw NUL byte in the
// answer is read differs between versions of jq, but both calls read the answer with
// the same jq and judge what they read by the same rules. Neither call prints
// anything of the answer, since each ends in empty, not error. Without a run key, qory
// refuses it before anything starts.
//
// When any command of the pipe fails, the key's jq aside, the handover, its curl, the
// jq before it, the tee or the inputs' jq, a write of the inputs file that fails or a
// file bash cannot open among them, pipefail makes the pipe's status non-zero, and the
// group writes a line end and ! to descriptor 3 before it exits. The key's jq runs in
// a process substitution, whose status pipefail does not see, so its failure writes no
// spoiler; it writes nothing when it fails, and qory refuses what it then reads. qory
// reads its standard input to the end, which comes only once every holder of
// descriptor 3 has closed it, the group included, so the ! always arrives before the
// end, wherever it falls beside the run key. qory trims white space around what it
// read and parses the rest as a run key, which never holds a !, so it refuses it
// before anything starts, whatever else arrived, and names the rule it breaks, never
// the value. A spoiler of white space alone would be trimmed away and leave the key
// good, so the ! is what spoils it.
func TestTheRunLines(t *testing.T) {
	script := runs(t, parse(t, filled(t)))[2]
	ls := lines(script)
	doc, err := contracts.ProvisionerDocument("definitions.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	pattern := doc.(map[string]any)["$defs"].(map[string]any)["dispatch_id"].(map[string]any)["pattern"].(string)
	if pattern != `^dp_[0-9a-hjkmnp-tv-z]{16}$` {
		t.Errorf("the contract's pattern is %s", pattern)
	}
	check := `[[ "$DISPATCH_ID" =~ ` + pattern + ` ]] || { echo "dispatch_id is not a dispatch's id" >&2; exit 1; }`
	if ls[1] != check {
		t.Errorf("the run step's second line is %q, want %q", ls[1], check)
	}
	if ls[0] != "set -euo pipefail" {
		t.Errorf("the run step starts %q", ls[0])
	}
	for i, run := range runs(t, parse(t, filled(t)))[:2] {
		if strings.Contains(run, "DISPATCH_ID") {
			t.Errorf("step %d uses DISPATCH_ID, which only the run step checks", i)
		}
	}
	order := []string{mkdirLine, `cd "$RUNNER_TEMP/work"`, "{",
		`printf 'Authorization: bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" |`,
		`curl --fail --silent --show-error --proto =https --header @- --get --data-urlencode "audience=$STARTER_URL" "$ACTIONS_ID_TOKEN_REQUEST_URL" |`,
		`jq -re '.value | strings | "Authorization: Bearer " + .' |`,
		`curl --fail --silent --show-error --proto =https --data '' --header @- "$STARTER_URL/v1/dispatches/$DISPATCH_ID/handover" |`,
		teeLine, jqLine, groupLine, qoryLine}
	if !reflect.DeepEqual(ls[2:len(ls)-1], order) || ls[len(ls)-1] != "" {
		t.Errorf("the run step's lines after the check are\n%q\nwant\n%q", ls[2:], order)
	}
	for _, l := range ls {
		if strings.Contains(l, "run_key") && l != teeLine {
			t.Errorf("a line other than the tee reads the run key: %q", l)
		}
		if strings.Contains(l, "inputs.json") && l != jqLine && l != qoryLine {
			t.Errorf("a line other than the jq and qory run lines names inputs.json: %q", l)
		}
	}
}

// TestTheInstallIsChecked pins the install of qory: v0.13.0's archive for the runner's
// architecture, from its release URL, checked by its SHA-256 before it is unpacked, and
// never unpacked otherwise.
func TestTheInstallIsChecked(t *testing.T) {
	script := runs(t, parse(t, filled(t)))[0]
	want := []string{"set -euo pipefail",
		`case "$RUNNER_ARCH" in`,
		"X64) arch=amd64 sum=" + sumAMD64 + " ;;",
		"ARM64) arch=arm64 sum=" + sumARM64 + " ;;",
		`*) echo "qory 0.13.0 has no release for the runner's architecture, $RUNNER_ARCH" >&2; exit 1 ;;`,
		"esac",
		`mkdir "$RUNNER_TEMP/qory"`,
		`curl --fail --silent --show-error --location --proto =https --proto-redir =https --output "$RUNNER_TEMP/qory.tar.gz" ` + qoryURL,
		checkLine,
		`tar -xzf "$RUNNER_TEMP/qory.tar.gz" -C "$RUNNER_TEMP/qory" qory`,
		`echo "$RUNNER_TEMP/qory" >> "$GITHUB_PATH"`,
		""}
	if got := lines(script); !reflect.DeepEqual(got, want) {
		t.Errorf("the install step is\n%q\nwant\n%q", got, want)
	}
	all := filled(t)
	if strings.Count(all, "sha256sum") != 1 || strings.Count(all, "tar -x") != 1 || strings.Count(all, "releases/download") != 1 {
		t.Error("the template downloads, checks or unpacks more than once")
	}
}

// TestTheHarness pins the compose step: the stack with the explore-an-item module from
// qory-github at HARNESS_REF, after HARNESS_REF is checked as Fill checks it, composed
// for claude into the home qory run reads, from a git working tree.
func TestTheHarness(t *testing.T) {
	script := runs(t, parse(t, filled(t)))[1]
	if strings.ReplaceAll(harnessRefShape.String(), "(?:", "(") != `^([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+)$` {
		t.Errorf("Fill checks the harness's ref with %s, which the script does not", harnessRefShape)
	}
	check := `[[ "$HARNESS_REF" =~ ^([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+)$ ]] || { echo "HARNESS_REF is neither a commit id nor a release tag" >&2; exit 1; }`
	if lines(script)[1] != check {
		t.Errorf("the compose step's second line is %q, want %q", lines(script)[1], check)
	}
	stack := "apiVersion: qory.dev/v1alpha1\nname: explore\nmodules:\n  - name: explore-an-item\n    source: {git: https://github.com/qoryai/qory-github, ref: $HARNESS_REF, path: harness/explore-an-item}\nEOF\n"
	if !strings.Contains(script, `cat > "$RUNNER_TEMP/stack/qory-stack.yaml" <<EOF`+"\n"+stack) {
		t.Errorf("the compose step writes no stack, or another:\n%s", script)
	}
	for _, l := range []string{`git init --quiet "$RUNNER_TEMP/work"`, `cd "$RUNNER_TEMP/work"`, `qory harness compose -f "$RUNNER_TEMP/stack/qory-stack.yaml" --runtime claude --home "$RUNNER_TEMP/homes"`} {
		if index(script, l) < 0 {
			t.Errorf("the compose step has no line %q", l)
		}
	}
}

// TestNothingForbidden pins what the template never holds: QORY_RUN_KEY, which with
// --run-key-fd is refused and an unwalled agent could read; --permission-mode and
// --permission-prompts; a forager.yaml, its gateway section or an access key; a flag
// qory run refuses with a run key; :latest; an action; an export; and set -x, which
// would print the scripts' lines.
func TestNothingForbidden(t *testing.T) {
	text := filled(t)
	for _, bad := range []string{"QORY_RUN_KEY", "--permission-mode", "--permission-prompts", "forager.yaml", "gateway:", "QORY_ACCESS_KEY", "QORY_APIARY_PUBLIC_KEY", "access-key",
		"--label", "--kind", "--title", "--subject", "--details", "--local", "--policy", "--relabel", ":latest", "uses:", "export ", "set -x", "secrets.", "pull_request"} {
		if strings.Contains(text, bad) {
			t.Errorf("the template holds %q", bad)
		}
	}
}

// TestPlaceholders pins that each placeholder is in the committed template where Fill
// replaces it, and that a filled template holds none.
func TestPlaceholders(t *testing.T) {
	for p, n := range map[string]int{placeholderRepository: 2, placeholderPublicURL: 1, placeholderAgentImage: 1, placeholderHarnessRef: 1} {
		if got := strings.Count(Template, p); got != n {
			t.Errorf("%s is in the template %d times, want %d", p, got, n)
		}
	}
	if s := filled(t); strings.Contains(s, "__") {
		t.Error("the filled template holds a placeholder")
	}
	if !strings.Contains(filled(t), "# repository acme/qory-runner.\n") {
		t.Error("the filled template's first comment does not name the repository")
	}
}

// TestFillTakes pins the values Fill takes, and the public URL as it goes in.
func TestFillTakes(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct {
		v         Values
		publicURL string
	}{
		{valid, "https://starter.example.com"},
		{Values{PublicURL: "HTTPS://Starter.Example.COM/", Repository: "Acme-1/qory.runner_2", AgentImage: "qory-agent" + digest, HarnessRef: "v0.13.0"}, "https://starter.example.com"},
		{Values{PublicURL: "https://starter.example.com:8443/qory/starter/", Repository: "a/b", AgentImage: "ghcr.io/acme/qory__agent-x" + digest, HarnessRef: "v10.0.1"}, "https://starter.example.com:8443/qory/starter"},
		{Values{PublicURL: "https://[2001:db8::1]:8443/a%2Fb", Repository: "a/b", AgentImage: "localhost:5000/agent" + digest, HarnessRef: "v1.2.3"}, "https://[2001:db8::1]:8443/a%2Fb"},
	} {
		s, err := Fill(c.v)
		if err != nil {
			t.Errorf("%+v: %v", c.v, err)
			continue
		}
		if j := parse(t, s).Jobs["explore"]; j.Env["STARTER_URL"] != c.publicURL || j.Env["AGENT_IMAGE"] != c.v.AgentImage || j.Env["HARNESS_REF"] != c.v.HarnessRef || j.If != "github.repository == '"+c.v.Repository+"'" {
			t.Errorf("%+v: env %v, if %q", c.v, j.Env, j.If)
		}
	}
}

// TestFillRefuses pins that a value that could change the YAML or a script, or is not
// of its shape, is refused, with an error that names the flag and the rule and never
// the value: a line break, a quote, a backslash, ${{, $( ), a backtick, white space,
// a # and the like in each value, an image not pinned by digest or with a tag, and a
// branch as the harness's ref.
func TestFillRefuses(t *testing.T) {
	injections := []string{"\n", "\r", "\"", "'", "\\", "${{ secrets.TOKEN }}", "$(id)", "$X", "`id`", " ", "\t", "#", ": x", "{", "}", "\x00", " ", ";", "&", "|", "<", ">", "!", "*", "é"}
	type field struct {
		flag string
		set  func(*Values, string)
		base string
	}
	fields := []field{
		{"--public-url", func(v *Values, s string) { v.PublicURL = s }, valid.PublicURL + "/a"},
		{"--repository", func(v *Values, s string) { v.Repository = s }, valid.Repository},
		{"--agent-image", func(v *Values, s string) { v.AgentImage = s }, "registry.example.com/agent"},
		{"--harness-ref", func(v *Values, s string) { v.HarnessRef = s }, valid.HarnessRef},
	}
	digest := "@sha256:" + strings.Repeat("ab", 32)
	for _, f := range fields {
		var values []string
		for _, inj := range injections {
			if f.flag == "--agent-image" {
				values = append(values, f.base+inj+digest, inj+f.base+digest, f.base+digest+inj)
			} else {
				values = append(values, f.base+inj, inj+f.base, f.base[:2]+inj+f.base[2:])
			}
		}
		values = append(values, "")
		for _, s := range values {
			v := valid
			f.set(&v, s)
			out, err := Fill(v)
			if err == nil {
				t.Errorf("%s %q: taken", f.flag, s)
				continue
			}
			if out != "" || !strings.HasPrefix(err.Error(), f.flag+" ") {
				t.Errorf("%s %q: %q, %v", f.flag, s, out, err)
			}
			if s != "" && strings.Contains(err.Error(), s) {
				t.Errorf("%s %q: the error holds the value: %v", f.flag, s, err)
			}
		}
	}
	for _, c := range []struct{ flag, value string }{
		{"--public-url", "http://starter.example.com"},
		{"--public-url", "https://user@starter.example.com"},
		{"--public-url", "https://starter.example.com/?q"},
		{"--public-url", "https://starter.example.com/qrk_" + strings.Repeat("a", 43)},
		{"--public-url", "https://starter.example.com/a$(id)"},
		{"--public-url", "https://starter.example.com/a'b"},
		{"--public-url", "https://starter.example.com/a(b)"},
		{"--repository", "acme/a,acme/b"},
		{"--repository", "acme"},
		{"--repository", "acme/b/c"},
		{"--agent-image", "registry.example.com/agent:latest"},
		{"--agent-image", "registry.example.com/agent:1" + digest},
		{"--agent-image", "registry.example.com/agent"},
		{"--agent-image", "registry.example.com/Agent" + digest},
		{"--agent-image", "registry.example.com/agent@sha256:" + strings.Repeat("AB", 32)},
		{"--agent-image", "registry.example.com/agent@sha256:" + strings.Repeat("ab", 31)},
		{"--agent-image", "registry.example.com/agent@sha512:" + strings.Repeat("ab", 64)},
		{"--agent-image", strings.Repeat("a/", 300) + "a" + digest},
		{"--harness-ref", "main"},
		{"--harness-ref", "0123456"},
		{"--harness-ref", strings.Repeat("A", 40)},
		{"--harness-ref", "v1.2"},
		{"--harness-ref", "refs/tags/v1.2.3"},
	} {
		v := valid
		for _, f := range fields {
			if f.flag == c.flag {
				f.set(&v, c.value)
			}
		}
		if _, err := Fill(v); err == nil || !strings.HasPrefix(err.Error(), c.flag+" ") || strings.Contains(err.Error(), c.value) {
			t.Errorf("%s %q: %v", c.flag, c.value, err)
		}
	}
}

// TestShapesHoldNoSpecialCharacter pins that the values the tests fill in hold no
// character that would change the YAML or a script, so a test that finds one of them
// in a script finds the value.
func TestShapesHoldNoSpecialCharacter(t *testing.T) {
	special := regexp.MustCompile(`["'\\$` + "`" + `{}()\s#;&|<>!*]`)
	for _, s := range []string{valid.PublicURL, valid.Repository, valid.AgentImage, valid.HarnessRef} {
		if special.MatchString(s) {
			t.Errorf("%q holds a special character", s)
		}
	}
}

// TestThePublicURLLayer pins what Fill's check of the public URL takes beyond
// github.CheckPublicURL: publicURLChars on the URL as given and publicURLShape on the
// URL as CheckPublicURL returns it: each URL refused here is one CheckPublicURL takes,
// so the refusal is this layer's, with its error, word for word.
func TestThePublicURLLayer(t *testing.T) {
	for _, c := range []struct{ given, filled string }{
		{"https://starter.example.com", "https://starter.example.com"},
		{"https://Starter.Example.COM/", "https://starter.example.com"},
		{"https://starter-1.example.com:8443", "https://starter-1.example.com:8443"},
		{"https://203.0.113.7:443", "https://203.0.113.7:443"},
		{"https://[2001:db8::1]", "https://[2001:db8::1]"},
		{"https://[2001:DB8::1]:8443/", "https://[2001:db8::1]:8443"},
		{"https://[::ffff:192.0.2.1]", "https://[::ffff:192.0.2.1]"},
		{"https://starter.example.com/qory/starter", "https://starter.example.com/qory/starter"},
		{"https://starter.example.com/a%2Fb/c%20d", "https://starter.example.com/a%2Fb/c%20d"},
		{"https://starter.example.com/~a_b.c-d", "https://starter.example.com/~a_b.c-d"},
		{"https://starter.example.com/A/Z/0/9//", "https://starter.example.com/A/Z/0/9"},
	} {
		v := valid
		v.PublicURL = c.given
		s, err := Fill(v)
		if err != nil {
			t.Errorf("%q: %v", c.given, err)
			continue
		}
		if got := parse(t, s).Jobs["explore"].Env["STARTER_URL"]; got != c.filled {
			t.Errorf("%q: STARTER_URL %q, want %q", c.given, got, c.filled)
		}
	}
	const layer = "--public-url has a character the runner template does not take: its host is letters, digits, dots and hyphens, or an IPv6 address in brackets, and its path letters, digits and . _ ~ - / %"
	// Each group's comment is checked: CheckPublicURL returns a URL of kept as it is
	// given, and changes each of changed.
	kept := []string{
		// The host: an underscore, a character outside ASCII, or another character
		// CheckPublicURL leaves as it is.
		"https://star_ter.example.com",
		"https://stärter.example.com",
		"https://starter.example.com~",
		"https://starter!.example.com",
		"https://starter$.example.com",
		// The path: a character CheckPublicURL leaves as it is.
		"https://starter.example.com/a$b",
		"https://starter.example.com/a'b",
		"https://starter.example.com/a(b)",
		"https://starter.example.com/a*b",
		"https://starter.example.com/a!b",
		"https://starter.example.com/a+b",
		"https://starter.example.com/a,b",
		"https://starter.example.com/a;b",
		"https://starter.example.com/a=b",
		"https://starter.example.com/a&b",
		"https://starter.example.com/a@b",
		"https://starter.example.com/a:b",
		"https://starter.example.com/a[b]",
	}
	changed := []string{
		// The host: an IPv6 zone, whose %25 CheckPublicURL turns into %, which the
		// host's shape does not take.
		"https://[fe80::1%25en0]",
		// The path: a character CheckPublicURL would escape, which is refused, not
		// escaped.
		`https://starter.example.com/a"b`,
		`https://starter.example.com/a\b`,
		"https://starter.example.com/a`b",
		"https://starter.example.com/a{b}",
		"https://starter.example.com/a|b",
		"https://starter.example.com/a<b>",
		"https://starter.example.com/a^b",
		"https://starter.example.com/é",
	}
	for _, given := range append(append([]string(nil), kept...), changed...) {
		public, err := github.CheckPublicURL(given)
		if err != nil {
			t.Errorf("%q: CheckPublicURL refuses it, so it tests nothing here: %v", given, err)
			continue
		}
		if wantKept := slices.Contains(kept, given); (public == given) != wantKept {
			t.Errorf("%q: CheckPublicURL returns %q, which the group's comment does not say", given, public)
		}
		v := valid
		v.PublicURL = given
		if out, err := Fill(v); err == nil || err.Error() != layer || out != "" {
			t.Errorf("%q: %q, %v", given, out, err)
		}
	}
}
