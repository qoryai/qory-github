// Command qory-github is Qory's integration with GitHub, the gateway's credential
// adapter: `qory-github credential --settings <json> -- owner/name` mints a
// GitHub App installation token for the repositories listed and prints the gateway's
// credential document. `qory-github describe` prints the integration's description,
// contracts/integration/v1, and `qory-github setup` creates the App.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/cli"
	"github.com/qoryai/qory-github/internal/setupcmd"
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
	b, err := json.MarshalIndent(description(), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", b)
	return err
}

// description is what describe prints: the integration's description, without the
// source role unless QORY_FEATURES names factory, see [cli.Factory]. description.json
// holds the role either way. Where QORY_FEATURES names factory it is [github.Describe]
// whole, the same document qory-github-server serve sends Qory Apiary at each start.
func description() github.Description {
	d := github.Describe(version)
	if !cli.Factory() {
		d.Roles.Source = nil
	}
	return d
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
	if err := setupHelp.Parse(fs, args, stderr); err != nil {
		return err
	}
	// The URLs are checked before anything is created, listened on or opened.
	if err := github.CheckAPIURL(*api); err != nil {
		return err
	}
	if err := github.CheckWebURL(*web); err != nil {
		return err
	}
	if *keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(home, ".config", "qory")
		*keyFile = filepath.Join(dir, "github-app.pem")
		if err := setupcmd.CheckKeyFile(*keyFile); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if *name == "" {
		*name = "qory-github-" + setupcmd.RandomSuffix()
	}
	s := github.Setup{Org: *org, Name: *name, KeyFile: *keyFile, Web: *web, Client: github.Client{API: *api}, Open: opener}
	return runSetup(ctx, s, stdout)
}

// runSetup is setup past its flags, so a test drives it with a page opener the test supplies.
func runSetup(ctx context.Context, s github.Setup, stdout io.Writer) error {
	app, abs, err := setupcmd.Create(ctx, s, stdout)
	if err != nil {
		return err
	}
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
	return nil
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
`, strings.Join(d.EgressHosts, ", "), d.Name)
	return integrations, policy, nil
}

// opener opens setup's page in the machine's browser; a test replaces it, so it never
// opens one.
var opener = setupcmd.Browse
