// Command qory-github-starter is the program for a node pool of Qory Apiary. Its one
// command, `qory-github-starter access-key enrol`, enrols the node pool's access key.
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
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github/internal/cli"
	"github.com/qoryai/qory-github/internal/enrol"
	"github.com/qoryai/qory-github/internal/ownerfile"
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

// usage is what the program prints when it is run without a command it knows: the
// usage line, and, where QORY_FEATURES names factory, see [cli.Factory], the commands.
// Work behind a feature that is off is described nowhere a person sees. The program has
// no description yet: it comes with a later command.
func usage() string {
	line := `usage:
  qory-github-starter <command> [flags]`
	if !cli.Factory() {
		return line
	}
	return line + `

commands:
  access-key   ` + accessKeyHelp.Short + `

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
