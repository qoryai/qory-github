// Command qory-github-server is the server that connects a GitHub App to Qory Apiary:
// `qory-github-server serve` takes the App's webhook deliveries and writes on GitHub
// what Qory Apiary's change feed says, with its settings in a file, --settings FILE, or
// in the environment, and
// `qory-github-server access-key enrol` enrols the access key it signs its requests to
// Qory Apiary with.
//
// The whole program is switched on by QORY_FEATURES alone, see [cli.Factory]: without
// factory it knows no command, and prints a usage that lists none.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/qoryai/qory-github/internal/cli"
	"github.com/qoryai/qory-github/internal/ownerfile"
	"github.com/qoryai/qory-github/internal/serve"
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
	ownerfile.Program = "qory-github-server"
}

// usage is what the program prints when it is run without a command it knows. Where
// QORY_FEATURES does not name factory, see [cli.Factory], it is the usage line alone:
// work behind a feature that is off is described nowhere a person sees. The
// description and the commands are printed only where it names factory.
func usage() string {
	line := `usage:
  qory-github-server <command> [flags]`
	if !cli.Factory() {
		return line
	}
	return `qory-github-server connects a GitHub App to Qory Apiary: it takes the App's webhook
deliveries and writes on GitHub what Qory Apiary's change feed says.

` + line + `

commands:
  serve        ` + serveHelp.Short + `
  access-key   ` + accessKeyHelp.Short + `

qory-github-server <command> -h prints a command's help.`
}

// serveHelp is serve's help, which has no section on qory-github's page: the command is
// switched on by QORY_FEATURES alone, see [cli.Factory].
var serveHelp = cli.Help{
	Short: "Take the GitHub App's webhook deliveries",
	Use:   "qory-github-server serve [--settings FILE]",
	Long: `Take the GitHub App's webhook deliveries at POST /v1/events, on plain HTTP: a
proxy in front terminates TLS and passes each request on with its path unchanged.
public_url is the adapter's host name only, such as https://github.example.com, so
GitHub sends the deliveries to https://github.example.com/v1/events.

serve checks each delivery's signature with the App's webhook secret, keeps it in a
store in the state directory and answers GitHub at once; it handles the delivery
after. For each installation linked to Qory Apiary it sends the repositories, issues
and comments to Qory Apiary, and it reads Qory Apiary's change feed and writes on GitHub
what the feed says. It runs until it is stopped with SIGINT or SIGTERM.

serve also answers the connect page at /v1/connect, which a browser reaches at
public_url followed by /v1/connect: Qory Apiary sends a person there who connects the
App's installation. /health answers 200 from the first moment.

With call_url set, serve also takes Qory Apiary's calls at /v1/calls/: a credential
for a run, the repository at an address, and a file at a version. serve checks
each call's signature against the Qory Apiary keys it pinned at enrolment. Set
call_url to the address Qory Apiary sends the calls to: public_url followed by
/v1/calls/, such as https://github.example.com/v1/calls/. Without call_url, serve
takes no call.

The settings come from a file or from the environment, never both. With --settings,
they are one JSON document in FILE: listen, state_dir, apiary_url, public_url,
access_key_id, access_key_secret_file, apiary_public_key and adapter_id; api_url,
which may be left out for GitHub's API; apiary_public_url, where a person's browser
is sent back to Qory Apiary, https, which may be left out for apiary_url;
enrolment_code_file and call_url, which may be left out; public_address, false when
GitHub cannot reach public_url: the App setup creates has its webhook inactive, and
serve learns of changes on GitHub by pulling. Left out, it is true.
upload_retry_seconds is how long the App setup tries again to store the App in Qory
Apiary, 60 to 86400; left out, it is 600. The access key's secret is in a file only
its owner may read.

No setting contains the GitHub App. Qory Apiary stores it: its id, slug, client id,
private key, webhook secret and client secret. At each start serve reads the App
from Qory Apiary, sealed to its access key, and keeps it in memory; serve writes
none of it to disk. Until Qory Apiary stores an App, serve serves GitHub's App setup
at public_url's /setup, which an instance admin opens with Set up in Qory Apiary.
GitHub issues the App's private key once: when storing the App in Qory Apiary
fails, the setup tries again for upload_retry_seconds, and then shows which App to
delete on GitHub.

access_key_id, access_key_secret_file, apiary_public_key and adapter_id, the
enrolment in Qory Apiary, may be left out together. serve then uses the enrolment it
keeps in the state directory or, at its first start, enrols itself: it reads an
adapter's enrolment code from the file enrolment_code_file names, makes its access
key in the state directory, enrols it with Qory Apiary at apiary_url, and keeps the
key and Qory Apiary's answer there. It waits for the code, and takes no
delivery until it is enrolled.

Once its enrolment is kept in the state directory, serve looks at that file again at
each start and after each 401 Qory Apiary answers a request with. Qory Apiary,
installed with the adapter, writes a code there only while the adapter holds no live
key, so a code found then makes serve enrol a new key beside the one in use, which
goes on serving; once Qory Apiary accepts the new key, it replaces the old one in the
state directory and in every request. A 401 alone changes nothing. With the
enrolment in the settings, serve never reads the file.

Without --settings, they are environment variables, each a setting's name in upper
case after QORY_GITHUB_: QORY_GITHUB_LISTEN for listen, QORY_GITHUB_APIARY_PUBLIC_KEY
for apiary_public_key, which holds its JSON, QORY_GITHUB_PUBLIC_ADDRESS for
public_address, and so on. The access key's secret is given as its value or as a
file that a variable ending in _FILE names, never both:
  QORY_GITHUB_ACCESS_KEY_SECRET or QORY_GITHUB_ACCESS_KEY_SECRET_FILE
An empty variable counts as one not set.`,
	Example: `  qory-github-server serve --settings /etc/qory-github/serve.json   # the settings in a file
  qory-github-server serve                                          # the settings in QORY_GITHUB_ variables`,
}

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
	case "serve":
		err = runServe(ctx, args[1:], stderr, os.LookupEnv)
	case "access-key":
		err = accessKey(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usage())
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "qory-github-server %s: %s\n", args[0], cli.OneLine(err.Error()))
		return 1
	}
	return 0
}

// runServe takes the App's webhook deliveries until ctx is done, a signal, with the
// settings in the file --settings names or, without the flag, in the environment,
// which lookup reads, as [os.LookupEnv] does; --settings given empty is refused. It
// writes its lines, one JSON object each, on standard error, and nothing on standard
// output.
func runServe(ctx context.Context, args []string, stderr io.Writer, lookup func(string) (string, bool)) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	file := fs.String("settings", "", "the settings file, one JSON document; without it the settings are read from QORY_GITHUB_ variables")
	if err := serveHelp.Parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve takes no arguments")
	}
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "settings" })
	if given && *file == "" {
		return errors.New("--settings names no file")
	}
	var s serve.Settings
	var err error
	if given {
		s, err = serve.ReadSettings(*file)
	} else {
		s, err = serve.ReadEnvironment(lookup)
	}
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	return serve.Run(ctx, s, serve.Options{ProgramVersion: version, Log: log})
}
