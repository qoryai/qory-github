// Command qory-github is Qory's integration with GitHub, the gateway's credential
// adapter: `qory-github credential --settings <json> -- owner/name` mints a
// GitHub App installation token for the repositories listed and prints the gateway's
// credential document. `qory-github describe` prints the integration's description,
// contracts/integration/v1, and `qory-github setup` creates the App.
package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// version is the program's version, set when it is built with
// -ldflags "-X main.version=...", or else by init to the version of the module it was
// built from, see [cli.ProgramVersion].
var version string

func init() { version = cli.ProgramVersion(version, debug.ReadBuildInfo) }

// usage is what the command prints when it is run without a command it knows.
func usage() string {
	return `qory-github mints GitHub App access tokens for Qory's gateway. The agent works on
GitHub and never holds the access token.

usage:
  qory-github <command> [flags]

commands:
  describe     ` + describeHelp.Short + `
  credential   ` + credentialHelp.Short + `
  setup        ` + setupHelp.Short + `

qory-github <command> -h prints a command's help.

More: ` + cli.More
}

var describeHelp = cli.Help{
	Short: "Print the integration's description, for qory",
	Use:   "qory-github describe",
	Long: `Print the integration's description: one JSON document, as the integration contract
defines it.

It contains the settings qory-github takes, as a JSON Schema, with the private key
marked writeOnly, a secret. It contains the credential role: the repositories an
argument may list, and the hosts the access token is for. qory runs describe, and checks
the declaration's settings against it.

It takes no settings and reaches no network.`,
	Example: `  qory-github describe                  # the whole description
  qory-github describe | jq .settings   # the settings, as a JSON Schema`,
	Section: "describe",
}

var credentialHelp = cli.Help{
	Short: "Mint an access token for a run's repositories",
	Use:   "qory-github credential --settings JSON [--] owner/name[,owner/name...]",
	Long: `Mint a GitHub App access token for the repositories listed, and print the gateway's
credential document: the access token, its expiry, and where it goes.

The gateway runs credential outside the container, as a credential's adapter. qory
writes that adapter from the gateway: integrations: section of forager.yaml.

The settings are one JSON document, given with --settings; qory-github describe lists
what it contains. The settings go on a command line, so a secret is refused there: set
private_key_file, a file only its owner reads, never private_key. credential reads no
setting and no secret from its environment.

The repositories follow --, one owner's, separated by commas. The access token covers
them alone, with the permissions of the settings and no more.`,
	Example: `  qory-github credential --settings "$settings" -- acme/shop            # one repository
  qory-github credential --settings "$settings" -- acme/shop,acme/lib   # two of one owner's`,
	Section: "credential",
}

var setupHelp = cli.Help{
	Short: "Create the GitHub App and write its private key",
	Use:   "qory-github setup [--org ORG] [--name NAME] [--key-file FILE]",
	Long: `Create the GitHub App that qory-github mints access tokens with, and write its private
key.

setup opens GitHub in the browser with the App filled in: private, no webhook, contents
and pull requests write, metadata read. You approve it there; nothing is created
without you. setup waits ten minutes at most.

The private key goes to --key-file, which only you may read. setup never writes over a
file that exists, and never prints the key. GitHub hands the key out once: when the
file cannot be written, the key goes beside it, and setup prints where.

Then setup prints where to install the App, the declaration for forager.yaml, and a
policy that selects it.`,
	Example: `  qory-github setup                                       # under your account
  qory-github setup --org acme                            # under the organisation acme
  qory-github setup --name qory-github-acme               # the App's name`,
	Section: "setup",
}

// setupPublicHelp is the paragraph setup's help adds after the App's description where
// QORY_FEATURES names factory, see [cli.Factory], for the App --public-url makes.
//
// placeholder: wording waits for the user
const setupPublicHelp = `With --public-url, the App is instead public, with a webhook at the public URL and
` + github.WebhookPath + `, the events issues, issue_comment, workflow_run, pull_request and
push, and actions, checks, contents, issues and pull requests write, administration,
members and metadata read. It is qory-github-server's App: setup then prints
qory-github-server serve's settings in place of the declaration and the policy.
setup asks which GitHub account the App is for, and suggests the name qory- and its
handle, which you can change on GitHub's form.`

// setupLong is setup's help where QORY_FEATURES names factory: [setupHelp]'s, with
// [setupPublicHelp] after its paragraph on the App.
func setupLong() string {
	return strings.Replace(setupHelp.Long, "setup waits ten minutes at most.\n\n", "setup waits ten minutes at most.\n\n"+setupPublicHelp+"\n\n", 1)
}

// run is the command, with its streams, so a test runs it whole. It returns the exit
// status; an error is one line on stderr describing what failed, never a secret.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return 2
	}
	var err error
	switch args[0] {
	case "credential":
		err = credential(ctx, args[1:], stdout, stderr)
	case "setup":
		err = setup(ctx, args[1:], stdout, stderr)
	case "describe":
		err = describe(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usage())
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "qory-github %s: %s\n", args[0], cli.OneLine(err.Error()))
		return 1
	}
	return 0
}

// describe prints the integration's description, one JSON document. It takes no
// settings and reaches no network. -h alone prints its help instead.
func describe(args []string, stdout, stderr io.Writer) error {
	if cli.HelpAlone(args) {
		return describeHelp.Parse(flag.NewFlagSet("describe", flag.ContinueOnError), args, stderr)
	}
	if len(args) != 0 {
		return errors.New("describe takes no arguments")
	}
	b, err := json.MarshalIndent(github.Describe(version), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", b)
	return err
}

// credential mints a token and prints the gateway's credential document, nothing else
// on standard output. The settings are one document, --settings, the only input besides
// the argument; `--` ends the flags, so the argument is never read as one.
func credential(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("credential", flag.ContinueOnError)
	doc := fs.String("settings", "", "the settings, one JSON document (required)")
	if err := credentialHelp.Parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("want one argument, owner/name[,owner/name...]")
	}
	if *doc == "" {
		return errors.New("--settings is required")
	}
	s, err := github.ReadSettings(*doc)
	if err != nil {
		return err
	}
	repos, err := github.ParseRepositories(fs.Arg(0))
	if err != nil {
		return err
	}
	key, err := github.ReadKeyFile(s.PrivateKeyFile)
	if err != nil {
		return err
	}
	answer, err := github.Client{API: s.APIURL}.Mint(ctx, github.Request{AppID: s.AppID, Key: key, InstallationID: s.InstallationID, Repositories: repos, Permissions: s.Permissions})
	if err != nil {
		return err
	}
	b, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", b)
	return err
}

// setup creates the App with a person's approval in the browser, writes its key and
// prints what to do next.
func setup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	org := fs.String("org", "", "create the App under this organisation")
	name := fs.String("name", "", "the App's name (default qory-github- and six random hex digits)")
	keyFile := fs.String("key-file", "", "where the private key is written (default ~/.config/qory/github-app.pem)")
	api := fs.String("api-url", github.APIURL, "GitHub's API: https://api.github.com, or for a test http or https on a loopback host")
	web := fs.String("web-url", github.WebURL, "GitHub's website: https://github.com, or for a test http or https on a loopback host")
	// --public-url exists only where QORY_FEATURES names factory, see [cli.Factory]:
	// without it setup's flags, its App and what it prints are as they were.
	var publicURL *string
	help := setupHelp
	if cli.Factory() {
		help.Long = setupLong()
		// placeholder: wording waits for the user
		fs.Lookup("name").Usage = "the App's name (default qory-github- and six random hex digits, or with --public-url qory- and the account's handle)"
		publicURL = fs.String("public-url", "", "where qory-github-server serve is reached from outside, https: the App then gets serve's Connect, webhook, events and permissions, and its client secret and webhook secret are written beside the key")
	}
	if err := help.Parse(fs, args, stderr); err != nil {
		return err
	}
	// The URLs are checked before anything is created, listened on or opened.
	if err := github.CheckAPIURL(*api); err != nil {
		return err
	}
	if err := github.CheckWebURL(*web); err != nil {
		return err
	}
	public := ""
	if publicURL != nil && *publicURL != "" {
		var err error
		if public, err = github.CheckPublicURL(*publicURL); err != nil {
			return fmt.Errorf("--public-url %w", err)
		}
	}
	dir := ""
	if *keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".config", "qory")
		*keyFile = filepath.Join(dir, "github-app.pem")
		if err := checkKeyFile(*keyFile); err != nil {
			return err
		}
	}
	s := github.Setup{Org: *org, Name: *name, KeyFile: *keyFile, Web: *web, Client: github.Client{API: *api}, Open: opener}
	handle := *org
	if public != "" {
		s.PublicURL, s.ClientSecretFile, s.WebhookSecretFile = public, clientSecretFile(*keyFile), webhookSecretFile(*keyFile)
		// Without --org, setup asks which account the App is for, once every check
		// setup makes before it creates anything has passed.
		if *org == "" {
			if err := checkKeyFile(s.KeyFile); err != nil {
				return err
			}
			if err := s.Check(); err != nil {
				return err
			}
			login, kind, err := askAccount(ctx, s.Client, stdout)
			if err != nil {
				return err
			}
			handle = login
			if kind == github.AccountOrganization {
				s.Org = login
			} else {
				fmt.Fprintf(stdout, "Sign in to GitHub as %s to create the App.\n", login)
			}
		}
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if s.Name == "" {
		// With --public-url the name GitHub's form is filled in with is qory- and the
		// account's handle, which the person may change there.
		s.Name = "qory-github-" + randomSuffix()
		if public != "" {
			s.Name = "qory-" + handle
		}
	}
	return runSetup(ctx, s, stdout)
}

// errNoAccountAnswer is setup's error when it needs the App's account and cannot ask:
// standard input is not a terminal, or ends before an answer.
var errNoAccountAnswer = errors.New("setup needs the GitHub account for the App: give --org or run it in a terminal")

// stdin is where setup reads the answer to its question, and stdinTerminal whether it is
// a terminal; a test replaces both.
var (
	stdin         io.Reader = os.Stdin
	stdinTerminal           = func() bool {
		info, err := os.Stdin.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
)

// askAccount asks on stdout which GitHub account the App is for, reads the answer from
// [stdin], and looks it up with GitHub through c: it returns the account's login and
// kind, [github.AccountOrganization] or [github.AccountUser]. An empty answer, or one
// GitHub has no organisation or user by, is asked again. Standard input that is not a
// terminal, or that ends before an answer, is [errNoAccountAnswer]; any other error
// from GitHub is returned as it is.
func askAccount(ctx context.Context, c github.Client, stdout io.Writer) (string, string, error) {
	if !stdinTerminal() {
		return "", "", errNoAccountAnswer
	}
	// The lines are read apart, so an interrupt ends setup while it waits for one; the
	// reader stops at the next line once the question is answered.
	lines, done := make(chan string), make(chan struct{})
	defer close(done)
	r := bufio.NewReader(stdin)
	go func() {
		defer close(lines)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				select {
				case lines <- line:
				case <-done:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		fmt.Fprint(stdout, "GitHub account for the App, an organisation or a user: ")
		var line string
		var ok bool
		select {
		case line, ok = <-lines:
		case <-ctx.Done():
			fmt.Fprintln(stdout)
			return "", "", ctx.Err()
		}
		if !ok {
			fmt.Fprintln(stdout)
			return "", "", errNoAccountAnswer
		}
		handle := strings.TrimSpace(line)
		if handle == "" {
			continue
		}
		login, kind, err := c.Account(ctx, handle)
		if errors.Is(err, github.ErrNoAccount) {
			fmt.Fprintf(stdout, "GitHub has no account %s\n", handle)
			continue
		}
		if err != nil {
			return "", "", err
		}
		return login, kind, nil
	}
}

// runSetup is setup past its flags, so a test drives it with a page opener the test supplies.
func runSetup(ctx context.Context, s github.Setup, stdout io.Writer) error {
	if err := checkKeyFile(s.KeyFile); err != nil {
		return err
	}
	page, wait, err := s.Start(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Approve the App in the browser. If none opened, open %s\n", page)
	app, err := wait()
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(app.KeyFile)
	if app.Moved != nil {
		fmt.Fprint(stdout, movedLine(abs, s.KeyFile, app.Moved))
	}
	// The App --public-url makes is qory-github-server's: it lacks the permissions a
	// run's token needs, so no declaration is printed for it.
	if s.PublicURL != "" {
		fmt.Fprintf(stdout, `
The App %d (%s) is created, and its private key is in %s.

Install it on the repositories your agents work on:
  %s
`, app.ID, app.Slug, abs, app.InstallURL(s.Web))
	} else {
		integrations, policy, err := declaration(app.ID, abs)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, `
The App %d (%s) is created, and its private key is in %s.

Install it on the repositories your agents work on:
  %s

Then declare the integration in the machine's configuration, ~/.config/qory/forager.yaml:

%s
qory expands the declaration into the gateway's credential %s. A run's policy selects it
with the repositories the run works on, and allows GitHub's hosts beside the others the
run reaches:

%s`, app.ID, app.Slug, abs, app.InstallURL(s.Web), integrations, github.Describe(version).Name, policy)
	}
	// serve's settings for the secrets that are kept are printed, and then why the
	// others are not.
	if app.ClientSecretFile != "" || app.WebhookSecretFile != "" {
		block, err := serveSettings(app)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, block)
	}
	if app.ClientSecretErr != nil && app.WebhookSecretErr != nil {
		return fmt.Errorf("%w; and %w", app.ClientSecretErr, app.WebhookSecretErr)
	}
	return cmp.Or(app.ClientSecretErr, app.WebhookSecretErr)
}

// serveSettings is what setup prints for qory-github-server serve's settings: where
// the App's client secret and webhook secret are, those of them that are kept, made
// absolute, and the settings' members, one per line, with no braces around them.
func serveSettings(app *github.App) (string, error) {
	var client, webhook string
	var members []string
	if app.ClientSecretFile != "" {
		abs, err := filepath.Abs(app.ClientSecretFile)
		if err != nil {
			return "", err
		}
		id, _ := json.Marshal(app.ClientID)
		path, _ := json.Marshal(abs)
		client = abs
		members = append(members, fmt.Sprintf(`  "client_id": %s`, id), fmt.Sprintf(`  "client_secret_file": %s`, path))
	}
	if app.WebhookSecretFile != "" {
		abs, err := filepath.Abs(app.WebhookSecretFile)
		if err != nil {
			return "", err
		}
		path, _ := json.Marshal(abs)
		webhook = abs
		members = append(members, fmt.Sprintf(`  "webhook_secret_file": %s`, path))
	}
	var intro string
	switch {
	case webhook == "":
		intro = fmt.Sprintf(`The App's client secret is in %s, which only you may read. Add these settings to
qory-github-server serve's settings, for Connect:`, client)
	case client == "":
		intro = fmt.Sprintf(`The App's webhook secret is in %s, which only you may read. Add this setting to
qory-github-server serve's settings, for the App's webhook:`, webhook)
	default:
		intro = fmt.Sprintf(`The App's client secret is in %s and its webhook secret in %s, files only you may
read. Add these settings to qory-github-server serve's settings, for Connect and the
App's webhook:`, client, webhook)
	}
	return "\n" + intro + "\n\n" + strings.Join(members, ",\n") + "\n", nil
}

// clientSecretFile is where setup writes the App's client secret, beside the key file:
// its name without .pem, and .client-secret.
func clientSecretFile(keyFile string) string {
	return strings.TrimSuffix(keyFile, ".pem") + ".client-secret"
}

// webhookSecretFile is where setup writes the App's webhook secret, beside the key
// file: its name without .pem, and .webhook-secret.
func webhookSecretFile(keyFile string) string {
	return strings.TrimSuffix(keyFile, ".pem") + ".webhook-secret"
}

// movedLine is the line setup prints when the key is in abs, beside file, since file could
// not be written, or was written and its sync failed, and why: the error of the
// [*fs.PathError] that moved wraps, or "it exists".
func movedLine(abs, file string, moved error) string {
	what, why := "written", moved.Error()
	var pe *fs.PathError
	switch {
	case errors.Is(moved, fs.ErrExist):
		why = "it exists"
	case errors.As(moved, &pe):
		why = pe.Err.Error()
		if pe.Op == "sync" {
			what = "written or synced"
		}
	}
	return fmt.Sprintf("\nThe key is in %s, since %s could not be %s: %s.\n", abs, file, what, why)
}

// declaration is what setup prints for the App: the integration as the machine's
// configuration declares it, by its settings alone, and a run's policy that allows
// GitHub's hosts and selects the credential qory expands the declaration into.
func declaration(appID int64, keyFile string) (integrations, policy string, err error) {
	settings, err := json.Marshal(struct {
		AppID          int64  `json:"app_id"`
		PrivateKeyFile string `json:"private_key_file"`
	}{appID, keyFile})
	if err != nil {
		return "", "", err
	}
	d := github.Describe(version)
	integrations = fmt.Sprintf(`gateway:
  integrations:
    %s:
      settings: %s
`, d.Name, settings)
	policy = fmt.Sprintf(`egress:
  mode: enforce
  allow: [%s]
credentials:
  - {name: %s, argument: acme/shop}
`, strings.Join(d.Roles.Credential.Hosts, ", "), d.Name)
	return integrations, policy, nil
}

// checkKeyFile refuses a key file's path that the declaration cannot contain as it is
// written: one that is not UTF-8, or that contains a control character, C0, DEL or C1.
// It runs before setup creates a directory or the App, so nothing is created for a path
// setup refuses.
func checkKeyFile(p string) error {
	p, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("the key file's path %q is not UTF-8; choose another with --key-file", p)
	}
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return fmt.Errorf("the key file's path %q contains a control character; choose another with --key-file", p)
	}
	return nil
}

// browse opens a URL in the machine's browser. It never fails the setup: the URL is
// printed as well.
// opener opens setup's page in the machine's browser; a test replaces it, so it never
// opens one.
var opener = browse

func browse(u string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	cmd := exec.Command(name, u)
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
	return nil
}

// randomSuffix is six hex digits, so a default App name is likely free.
func randomSuffix() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
