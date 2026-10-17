package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/qoryai/qory-github/runner"
)

// templateArgs are flags template takes.
var templateArgs = []string{"--public-url", "https://Starter.example.com/", "--repository", "acme/qory-runner",
	"--agent-image", "registry.example.com/qory-agent@sha256:" + strings.Repeat("0123456789abcdef", 4), "--harness-ref", strings.Repeat("0123456789", 4)}

// templateRun runs template with factory on, and returns the exit status, stdout and
// stderr.
func templateRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("QORY_FEATURES", "factory")
	var out, errs bytes.Buffer
	c := run(context.Background(), append([]string{"template"}, args...), &out, &errs)
	return c, out.String(), errs.String()
}

// TestTemplatePrintsTheFilledTemplate pins that template prints the runner template
// filled with its flags' values, as [runner.Fill] fills it, the public URL as the
// starter's settings hold it, and nothing else, on standard output alone.
func TestTemplatePrintsTheFilledTemplate(t *testing.T) {
	code, out, errs := templateRun(t, templateArgs...)
	want, err := runner.Fill(runner.Values{PublicURL: "https://starter.example.com", Repository: "acme/qory-runner", AgentImage: templateArgs[5], HarnessRef: templateArgs[7]})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || errs != "" || out != want {
		t.Errorf("exit %d, stderr %q, stdout\n%s\nwant\n%s", code, errs, out, want)
	}
	if !strings.Contains(out, `STARTER_URL: "https://starter.example.com"`) {
		t.Error("the public URL is not as the starter's settings hold it")
	}
}

// TestTemplateRefuses pins template's errors, each one line naming the flag and the
// rule, never the value, with exit 1 and nothing on standard output; and that a flag
// left out is named.
func TestTemplateRefuses(t *testing.T) {
	with := func(flag, value string) []string {
		args := append([]string(nil), templateArgs...)
		for i := range args {
			if args[i] == flag {
				args[i+1] = value
			}
		}
		return args
	}
	without := func(flag string) []string {
		var args []string
		for i := 0; i < len(templateArgs); i += 2 {
			if templateArgs[i] != flag {
				args = append(args, templateArgs[i], templateArgs[i+1])
			}
		}
		return args
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{without("--public-url"), "qory-github-starter template: --public-url is required\n"},
		{without("--repository"), "qory-github-starter template: --repository is required\n"},
		{without("--agent-image"), "qory-github-starter template: --agent-image is required\n"},
		{without("--harness-ref"), "qory-github-starter template: --harness-ref is required\n"},
		{append(append([]string(nil), templateArgs...), "extra"), "qory-github-starter template: template takes no arguments\n"},
		{with("--public-url", "http://starter.example.com"), "qory-github-starter template: --public-url is not an https URL of a host, an optional port and an optional path, without a user, a query or a fragment\n"},
		{with("--public-url", "https://starter.example.com/\nx: $(id)"), "qory-github-starter template: --public-url is not an https URL of a host, an optional port and an optional path, without a user, a query or a fragment\n"},
		{with("--public-url", "https://starter.example.com/${{x}}"), "qory-github-starter template: --public-url has a character the runner template does not take: its host is letters, digits, dots and hyphens, or an IPv6 address in brackets, and its path letters, digits and . _ ~ - / %\n"},
		{with("--public-url", `https://starter.example.com/a"b`), "qory-github-starter template: --public-url has a character the runner template does not take: its host is letters, digits, dots and hyphens, or an IPv6 address in brackets, and its path letters, digits and . _ ~ - / %\n"},
		{with("--repository", "acme/x'y"), "qory-github-starter template: --repository is not one repository, owner/name\n"},
		{with("--repository", "acme/x\ny"), "qory-github-starter template: --repository is not one repository, owner/name\n"},
		{with("--agent-image", "registry.example.com/qory-agent:latest"), "qory-github-starter template: --agent-image is not an image pinned by its digest with no tag, NAME@sha256: and 64 lower-case hexadecimal digits\n"},
		{with("--harness-ref", "main"), "qory-github-starter template: --harness-ref is neither a commit id, 40 lower-case hexadecimal digits, nor a release tag, vMAJOR.MINOR.PATCH\n"},
	} {
		code, out, errs := templateRun(t, c.args...)
		if code != 1 || out != "" || errs != c.want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q, want %q", c.args, code, out, errs, c.want)
		}
	}
}

// templateHelpText is template's help, as -h prints it on standard error.
const templateHelpText = `Print the runner template, a GitHub Actions workflow, filled in with the values given.

Commit it to the runner repository as .github/workflows/qory-explore.yml, on the
branch or tag the starter's settings name as ref, with workflow set to
qory-explore.yml, and protect that ref, so that only a reviewed change reaches it: the
starter hands a run key only to a job of this workflow at that ref. The starter never
commits it.

The job runs only in the repository --repository names. It installs qory 0.13.0,
checked by its SHA-256, composes the harness harness/explore-an-item of qory-github at
--harness-ref, asks the starter at --public-url for its run with the job's GitHub
Actions OIDC token, and runs the agent walled in a Docker container, in the image
--agent-image names, for at most 12 minutes; the job stops after 15.

--public-url and --repository are the starter's settings' public_url and repository.

usage:
  qory-github-starter template --public-url URL --repository OWNER/NAME --agent-image NAME@sha256:DIGEST --harness-ref REF

flags:
  -agent-image string
    	the image the agent runs in, pinned by its digest: NAME@sha256:DIGEST (required)
  -harness-ref string
    	the commit id or release tag of qory-github whose harness/explore-an-item the job composes (required)
  -public-url string
    	where the starter is reached from outside, its settings' public_url (required)
  -repository string
    	the runner repository, owner/name, its settings' repository (required)

examples:
  qory-github-starter template --public-url https://starter.example.com --repository acme/qory-runner --agent-image "registry.example.com/qory-agent@sha256:$digest" --harness-ref "$commit" > qory-explore.yml
`

// TestTemplateHelpIsPinned pins template's help, word for word.
func TestTemplateHelpIsPinned(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		code, out, errs := templateRun(t, args...)
		if code != 2 || out != "" || errs != templateHelpText {
			t.Errorf("%q: exit %d, stderr\n%s\nwant\n%s", args, code, errs, templateHelpText)
		}
	}
}

// TestTemplateUnknownFlag pins that a flag template does not know prints the usage and
// flags alone, after the flag parser's message, then the error line, with exit 1 and
// nothing on standard output, as setup does.
func TestTemplateUnknownFlag(t *testing.T) {
	code, out, errs := templateRun(t, "--bogus")
	want := "flag provided but not defined: -bogus\n" + templateHelpText[strings.Index(templateHelpText, "usage:\n"):strings.Index(templateHelpText, "\nexamples:")] +
		"qory-github-starter template: flag provided but not defined: -bogus\n"
	if code != 1 || out != "" || errs != want {
		t.Errorf("exit %d, stdout %q, stderr\n%s\nwant\n%s", code, out, errs, want)
	}
}
