// Command qory-github-server is the server that connects a GitHub App to Qory Apiary:
// `qory-github-server serve --settings FILE` takes the App's webhook deliveries and
// writes on GitHub what Qory Apiary's change feed says, and
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

func init() { version = cli.ProgramVersion(version, debug.ReadBuildInfo) }

// usage is what the program prints when it is run without a command it knows. Its
// commands are listed only where QORY_FEATURES names factory, see [cli.Factory].
func usage() string {
	head := `qory-github-server connects a GitHub App to Qory Apiary: it takes the App's webhook
deliveries and writes on GitHub what Qory Apiary's change feed says.

usage:
  qory-github-server <command> [flags]`
	if !cli.Factory() {
		return head
	}
	return head + `

commands:
  serve        ` + serveHelp.Short + `
  access-key   ` + accessKeyHelp.Short + `

qory-github-server <command> -h prints a command's help.`
}

// serveHelp is serve's help, which has no section on qory-github's page: the command is
// switched on by QORY_FEATURES alone, see [cli.Factory].
var serveHelp = cli.Help{
	Short: "Take the GitHub App's webhook deliveries",
	Use:   "qory-github-server serve --settings FILE",
	Long: `Take the GitHub App's webhook deliveries at POST /github/webhook, on plain HTTP: a
proxy in front terminates TLS.

serve checks each delivery's signature with the App's webhook secret, keeps it in a
store in the state directory and answers GitHub at once; it handles the delivery
after. For each installation linked to Qory Apiary it sends the repositories, issues
and comments to Qory Apiary, and it reads Qory Apiary's change feed and writes on GitHub
what the feed says. It runs until it is stopped with SIGINT or SIGTERM.

serve also answers the connect page under public_url, /v1/connect, where Qory Apiary
sends a person who connects the App's installation.

The settings are one JSON document in FILE: app_id, private_key_file,
webhook_secret_file, listen, state_dir, app_slug, apiary_url, public_url,
access_key_id, access_key_secret_file, apiary_public_key, adapter_id, client_id and
client_secret_file, and api_url, which may be left out for GitHub's API. The private
key, the webhook secret, the access key's secret and the App's client secret are each
in a file only its owner may read.`,
	Example: `  qory-github-server serve --settings /etc/qory-github/serve.json`,
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
		err = runServe(ctx, args[1:], stderr)
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

// runServe takes the App's webhook deliveries until ctx is done, a signal. It writes
// its lines, one JSON object each, on standard error, and nothing on standard output.
func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	file := fs.String("settings", "", "the settings file, one JSON document (required)")
	if err := serveHelp.Parse(fs, args, stderr); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve takes no arguments")
	}
	if *file == "" {
		return errors.New("--settings is required")
	}
	s, err := serve.ReadSettings(*file)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	return serve.Run(ctx, s, serve.Options{Log: log})
}
