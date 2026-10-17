// Command qory-github-starter is the program for a node pool of Qory Apiary. Its
// commands are `qory-github-starter access-key enrol`, which enrols the node pool's
// access key, and `qory-github-starter setup`, which creates the starter's GitHub App.
//
// The whole program is switched on by QORY_FEATURES alone, see [cli.Factory]: without
// factory it knows no command, and prints a usage that lists none.
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
	"runtime/debug"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/cli"
	"github.com/qoryai/qory-github/internal/enrol"
	"github.com/qoryai/qory-github/internal/ownerfile"
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

// init sets the program's version, and its name in the errors of [ownerfile].
func init() {
	version = cli.ProgramVersion(version, debug.ReadBuildInfo)
	ownerfile.Program = "qory-github-starter"
}

// gitHub is a client of GitHub's API at api whose requests, an installation token's mint
// among them, have the User-Agent qory-github-starter/ and the program's version.
func gitHub(api string) github.Client {
	return github.Client{API: api, UserAgent: "qory-github-starter/" + version}
}

// usage is what the program prints when it is run without a command it knows: the
// usage line, and, where QORY_FEATURES names factory, see [cli.Factory], the commands.
// Work behind a feature that is off is described nowhere a person sees. The usage holds
// no description of the program.
func usage() string {
	line := `usage:
  qory-github-starter <command> [flags]`
	if !cli.Factory() {
		return line
	}
	return line + `

commands:
  access-key   ` + accessKeyHelp.Short + `
  setup        ` + setupHelp.Short + `

qory-github-starter <command> -h prints a command's help.`
}

// accessKeyHelp is the help of access-key enrol, which has no section on qory-github's
// page: the command is switched on by QORY_FEATURES alone, see [cli.Factory]. Its texts,
// and the lines and errors enrol prints, are placeholders awaiting the user's wording,
// as qory-github-server's are.
var accessKeyHelp = cli.Help{
	Short: "Enrol the node pool's access key with a code from Qory Apiary",
	Use:   "qory-github-starter access-key enrol --secret-file FILE [--] SERVER CODE",
	Long: `Enrol a new access key for this node pool with an enrolment code a workspace admin
of Qory Apiary created on the node pool's Access key tab. The code is valid for 15
minutes and used once. The key enrol makes is the node pool's access key.

qory-github-starter makes the key, prints its fingerprint and sends Qory Apiary, at
SERVER, the public key. Qory Apiary's signed answer gives the key its id and lists
Qory Apiary's public key. Only then is the secret written, to --secret-file, which
only you may read. enrol never writes over a file that exists, and never prints the
secret.

Then enrol prints the settings to add to the starter's settings: apiary_url,
access_key_id, access_key_secret_file, apiary_public_key and pool_id.`,
	Example: `  qory-github-starter access-key enrol --secret-file /etc/qory-github-starter/access-key-secret https://apiary.example.com "$code"`,
}

// poolKind is what qory-github-starter's access-key enrol takes: a node pool's code,
// and the words its lines and errors name it with. A code for a node, a gateway or an
// integration is refused.
func poolKind() enrol.Kind {
	return enrol.Kind{
		Program:   "qory-github-starter",
		Help:      accessKeyHelp,
		NodeKind:  "pool",
		Noun:      "node pool",
		ANoun:     "a node pool",
		Tab:       "the node pool's Access key tab",
		TabIn:     "the node pool's Access key tab",
		Admin:     "a workspace admin of Qory Apiary",
		Settings:  "the starter's settings",
		IDMember:  "pool_id",
		KindWords: true,
		UserAgent: "qory-github/" + version,
	}
}

// enrol's test seams, see [enrol.Seams]: the key it makes; the access key's name, from
// this machine's host name; and how the probe of the secret file's directory is
// removed.
var (
	generateKey = accesskey.Generate
	hostname    = os.Hostname
	removeProbe = os.Remove
)

// run is the command, with its streams, so a test runs it whole. It returns the exit
// status; an error is one line on stderr describing what failed, never a secret.
// Without factory every command is one the program does not know.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || !cli.Factory() {
		fmt.Fprintln(stderr, usage())
		return 2
	}
	var err error
	switch args[0] {
	case "access-key":
		err = enrol.AccessKey(ctx, poolKind(), enrol.Seams{GenerateKey: generateKey, Hostname: hostname, RemoveProbe: removeProbe}, args[1:], stdout, stderr)
	case "setup":
		err = setup(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usage())
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "qory-github-starter %s: %s\n", args[0], cli.OneLine(err.Error()))
		return 1
	}
	return 0
}

// setupHelp is the help of setup, which has no section on qory-github's page: the
// command is switched on by QORY_FEATURES alone, see [cli.Factory].
var setupHelp = cli.Help{
	Short: "Create the starter's GitHub App and write its private key",
	Use:   "qory-github-starter setup --key-file FILE [--org ORG] [--name NAME]",
	Long: `Create the starter's GitHub App, and write its private key.

setup opens GitHub in the browser with the App filled in: private, no webhook, actions
write, metadata read. You approve it there; nothing is created without you. setup
waits ten minutes at most.

The private key goes to --key-file, which only you may read. setup never writes over a
file that exists, and never prints the key. GitHub hands the key out once: when the
file cannot be written, the key goes beside it, and setup prints where.

Then setup prints where to install the App, and the two settings to add to the
starter's settings: app_id and private_key_file. Install the App on the one repository
the starter's settings name as repository.`,
	Example: `  qory-github-starter setup --key-file /etc/qory-github-starter/github-app.pem              # under your account
  qory-github-starter setup --org acme --key-file /etc/qory-github-starter/github-app.pem   # under the organisation acme`,
}

// opener opens setup's page in the machine's browser; a test replaces it, so it never
// opens one.
var opener = setupcmd.Browse

// setup creates the starter's App, see [github.StarterManifest], with a person's
// approval in the browser, writes its key and prints where to install the App and the
// starter's settings for it.
func setup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	org := fs.String("org", "", "create the App under this organisation")
	name := fs.String("name", "", "the App's name (default qory-github-starter- and six random hex digits)")
	keyFile := fs.String("key-file", "", "where the private key is written; a file that exists is refused (required)")
	api := fs.String("api-url", github.APIURL, "GitHub's API: https://api.github.com, or for a test http or https on a loopback host")
	web := fs.String("web-url", github.WebURL, "GitHub's website: https://github.com, or for a test http or https on a loopback host")
	if err := setupHelp.Parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("setup takes no arguments")
	}
	if *keyFile == "" {
		return errors.New("--key-file is required")
	}
	// The URLs are checked before anything is created, listened on or opened.
	if err := github.CheckAPIURL(*api); err != nil {
		return err
	}
	if err := github.CheckWebURL(*web); err != nil {
		return err
	}
	s := github.Setup{Org: *org, Name: *name, KeyFile: *keyFile, Web: *web, Client: gitHub(*api), Open: opener, Starter: true}
	if s.Name == "" {
		s.Name = "qory-github-starter-" + setupcmd.RandomSuffix()
	}
	// api_url is printed with the settings only when --api-url is given.
	apiURL := ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "api-url" {
			apiURL = *api
		}
	})
	return setupRunner(ctx, s, apiURL, stdout)
}

// setupRunner is [runSetup], which a test replaces to read what setup hands it.
var setupRunner = runSetup

// runSetup is setup past its flags, so a test drives it with a page opener the test
// supplies. apiURL, when set, is the --api-url given, which the settings printed hold.
func runSetup(ctx context.Context, s github.Setup, apiURL string, stdout io.Writer) error {
	app, abs, err := setupcmd.Create(ctx, s, stdout)
	if err != nil {
		return err
	}
	settings, err := setupSettings(app.ID, abs, apiURL)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, `
The App %d (%s) is created, and its private key is in %s.

Install it on the one repository the starter's settings name as repository:
  %s

Then add these to the starter's settings:

%s`, app.ID, app.Slug, abs, app.InstallURL(s.Web), settings)
	return err
}

// setupSettings is what setup prints for the starter's settings: app_id,
// private_key_file and, when apiURL is set, api_url, one per line, as they go into the
// settings' JSON object, with no braces around them.
func setupSettings(appID int64, keyFile, apiURL string) (string, error) {
	path, err := json.Marshal(keyFile)
	if err != nil {
		return "", err
	}
	if apiURL == "" {
		return fmt.Sprintf("  \"app_id\": %d,\n  \"private_key_file\": %s\n", appID, path), nil
	}
	api, err := json.Marshal(apiURL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("  \"app_id\": %d,\n  \"private_key_file\": %s,\n  \"api_url\": %s\n", appID, path, api), nil
}
