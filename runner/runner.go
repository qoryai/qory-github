// Package runner holds the runner template, qory-explore.yml, a GitHub Actions workflow
// that qory-github-starter template prints for a person to commit to the runner
// repository, and fills it in with the values the command is given.
//
// The job the workflow runs asks the starter for its run with the job's GitHub Actions
// OIDC token, and runs qory with the run key it gets, walled. Every value [Fill] puts in
// the template is checked first against a narrow shape, which holds no quote, no
// backslash, no dollar sign, no brace, no parenthesis, no white space and no control
// character, so a value can change neither the YAML nor a shell script of the workflow.
// The values reach the job's scripts through the job's environment alone: no script of
// the template holds a value, and none holds a GitHub Actions expression.
package runner

import (
	_ "embed"
	"errors"
	"regexp"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
)

// Template is the runner template as it is committed here, with a placeholder for each
// value [Fill] puts in it.
//
//go:embed qory-explore.yml
var Template string

// The placeholders of [Template], each of which [Fill] replaces with a value.
const (
	placeholderRepository = "__REPOSITORY__"
	placeholderPublicURL  = "__PUBLIC_URL__"
	placeholderAgentImage = "__AGENT_IMAGE__"
	placeholderHarnessRef = "__HARNESS_REF__"
)

// Values are what [Fill] puts in the template.
type Values struct {
	// PublicURL is where the starter is reached from outside, the starter's settings'
	// public_url: the job asks for its run there, and its OIDC token is for it.
	PublicURL string
	// Repository is the runner repository, owner/name, the starter's settings'
	// repository: the job runs only there.
	Repository string
	// AgentImage is the image the agent runs in, pinned by its digest:
	// NAME@sha256:DIGEST.
	AgentImage string
	// HarnessRef is the commit id or release tag of qory-github whose
	// harness/explore-an-item the job composes.
	HarnessRef string
}

var (
	// publicURLShape is a public URL [github.CheckPublicURL] returns, narrowed to what
	// the template carries: a host of letters, digits, dots and hyphens, or an IPv6
	// address in brackets, an optional port, and a path of letters, digits and . _ ~ - /
	// and %.
	publicURLShape = regexp.MustCompile(`^https://(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?$`)
	// publicURLChars are the characters a public URL may be given in, before
	// [github.CheckPublicURL] reads it: a character it would escape is refused, not
	// escaped.
	publicURLChars = regexp.MustCompile(`^[A-Za-z0-9.:/\[\]_~%-]+$`)
	// agentImageShape is an image reference pinned by its digest, with no tag: an
	// optional registry host and port, a path of lower-case components, and
	// @sha256: with 64 lower-case hexadecimal digits.
	agentImageShape = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@sha256:[0-9a-f]{64}$`)
	// harnessRefShape is a full commit id, or a release tag vMAJOR.MINOR.PATCH.
	harnessRefShape = regexp.MustCompile(`^(?:[0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+)$`)
)

// maxAgentImage is the longest image reference [Fill] takes.
const maxAgentImage = 512

// Fill is the template with the values in it, each checked first: an error names the
// flag of qory-github-starter template the value comes from, and the rule, never the
// value. The public URL goes in as [github.CheckPublicURL] returns it, with its scheme
// and host in lower case and no slash at its end, as the starter's settings hold it, so
// the job asks for its OIDC token for the audience the starter checks.
func Fill(v Values) (string, error) {
	public, err := github.CheckPublicURL(v.PublicURL)
	if err != nil || accesskey.ContainsSecret(v.PublicURL) {
		return "", errors.New("--public-url " + github.ErrPublicURL.Error())
	}
	if !publicURLChars.MatchString(v.PublicURL) || !publicURLShape.MatchString(public) {
		return "", errors.New("--public-url has a character the runner template does not take: its host is letters, digits, dots and hyphens, or an IPv6 address in brackets, and its path letters, digits and . _ ~ - / %")
	}
	if err := checkRepository(v.Repository); err != nil {
		return "", errors.New("--repository is not one repository, owner/name")
	}
	if len(v.AgentImage) > maxAgentImage || !agentImageShape.MatchString(v.AgentImage) {
		return "", errors.New("--agent-image is not an image pinned by its digest with no tag, NAME@sha256: and 64 lower-case hexadecimal digits")
	}
	if !harnessRefShape.MatchString(v.HarnessRef) {
		return "", errors.New("--harness-ref is neither a commit id, 40 lower-case hexadecimal digits, nor a release tag, vMAJOR.MINOR.PATCH")
	}
	return strings.NewReplacer(
		placeholderRepository, v.Repository,
		placeholderPublicURL, public,
		placeholderAgentImage, v.AgentImage,
		placeholderHarnessRef, v.HarnessRef,
	).Replace(Template), nil
}

// checkRepository takes one repository, owner/name, as [github.ParseRepositories] takes
// each, as the starter's settings take their repository.
func checkRepository(s string) error {
	if strings.Contains(s, ",") {
		return errors.New("is not one repository")
	}
	_, err := github.ParseRepositories(s)
	return err
}
