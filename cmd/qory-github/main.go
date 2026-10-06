// Command qory-github is Qory's integration with GitHub, the runner's credential
// adapter: `qory-github credential -- owner/name` reads its settings on standard input,
// mints a GitHub App installation token for the repositories listed and prints the
// runner's credential document. `qory-github describe` prints the integration's
// description, contracts/integration/v1, and `qory-github setup` creates the App.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/qory-github"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// version is the program's version, set when it is built with
// -ldflags "-X main.version=...", or else by init to the version of the module it was
// built from.
var version string

func init() { version = programVersion(version, debug.ReadBuildInfo) }

// programVersion is the version set with ldflags when there is one, as it is given, or
// else the main module's version from the build info without its leading v, as the
// integration contract's releases have it, the tag without its v: go records v0.1.0
// for go install ...@v0.1.0, reported as 0.1.0, or a pseudo-version for a commit,
// v0.2.1-0.20261006195344-0f167ba9a536 reported as 0.2.1-0.20261006195344-0f167ba9a536.
// Only a v followed by a digit is dropped; any other version is reported as recorded.
// A build whose module version is (devel) or empty is "dev".
func programVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
	if ldflags != "" {
		return ldflags
	}
	info, ok := read()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	v := info.Main.Version
	if len(v) > 1 && v[0] == 'v' && '0' <= v[1] && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// more is where the program's page is; each command's help links to a section of it.
const more = "https://github.com/qoryai/qory-github/blob/main/README.md"

// usage is what the command prints when it is run without a command it knows.
var usage = `qory-github mints GitHub App access tokens for Qory's runner. The agent works on
GitHub and never holds the access token.

usage:
  qory-github <command> [flags]

commands:
  describe     ` + describeHelp.short + `
  credential   ` + credentialHelp.short + `
  setup        ` + setupHelp.short + `

qory-github <command> -h prints a command's help.

More: ` + more

// help is one command's help. short is its line in usage; -h prints the rest, and the
// command's flags, on standard error. machine is set for a command a machine runs,
// whose failure is one line.
type help struct {
	short, use, long, example, section string
	machine                            bool
}

// parse parses args into fs. -h prints the whole help. A flag fs refuses prints the
// command's usage and flags alone, after the flag package's own line, unless the
// command is a machine's: then the error alone is its failure, the one line run writes.
func (h help) parse(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	fs.SetOutput(stderr)
	if h.machine {
		fs.SetOutput(io.Discard)
	}
	fs.Usage = func() {}
	err := fs.Parse(args)
	fs.SetOutput(stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprintf(stderr, "%s\n\n", h.long)
		h.usage(stderr, fs)
		fmt.Fprintf(stderr, "\nexamples:\n%s\n\nMore: %s#%s\n", h.example, more, h.section)
	case err != nil && !h.machine:
		h.usage(stderr, fs)
	}
	return err
}

// usage prints the command's usage line, and the flags of fs when it has any.
func (h help) usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage:\n  %s\n", h.use)
	flags := false
	fs.VisitAll(func(*flag.Flag) { flags = true })
	if flags {
		fmt.Fprint(w, "\nflags:\n")
		fs.PrintDefaults()
	}
}

var describeHelp = help{
	short: "Print the integration's description, for qory",
	use:   "qory-github describe",
	long: `Print the integration's description: one JSON document, as the integration contract
defines it.

It contains who publishes qory-github, and the settings it takes, as a JSON Schema, with
the private key marked writeOnly, a secret. It contains the credential role: the
repositories an argument may list, the hosts the access token is for, and the settings
the runner hands credential and those it requires. qory runs describe, and checks the
declaration's settings against it.

It takes no settings and reaches no network.`,
	example: `  qory-github describe                  # the whole description
  qory-github describe | jq .settings   # the settings, as a JSON Schema`,
	section: "describe",
}

var credentialHelp = help{
	short: "Mint an access token for a run's repositories",
	use:   "qory-github credential [--] owner/name[,owner/name...]",
	long: `Mint a GitHub App access token for the repositories listed, and print the runner's
credential document: the access token, its expiry, and where it goes.

The runner runs credential outside the container, as a credential's adapter. qory
writes that adapter from the integrations: section of runner.yaml.

The settings come on standard input, one JSON document; qory-github describe lists what
it contains. credential reads standard input to its end, or until it has more than
64 KiB, before it checks the argument and before any network call. It refuses empty
input, anything after the document but white space, and more than 64 KiB. It requires
app_id and the private key, which comes as private_key itself or as private_key_file, a
file only its owner reads, one of them and never both. credential takes no flags and
reads nothing from its environment.

The repositories follow --, one owner's, separated by commas. The access token covers
them alone, with the permissions of the settings and no more.`,
	example: `  qory-github credential -- acme/shop < settings.json            # one repository
  qory-github credential -- acme/shop,acme/lib < settings.json   # two of one owner's`,
	section: "credential",
	machine: true,
}

var setupHelp = help{
	short: "Create the GitHub App and write its private key",
	use:   "qory-github setup [--org ORG] [--name NAME] [--key-file FILE]",
	long: `Create the GitHub App that qory-github mints access tokens with, and write its private
key.

setup opens GitHub in the browser with the App filled in: private, no webhook, contents
and pull requests write, metadata read. You approve it there; nothing is created
without you. setup waits ten minutes at most.

The private key goes to --key-file, which only you may read. setup never writes over a
file that exists, and never prints the key. GitHub hands the key out once: when the
file cannot be written, the key goes beside it, and setup prints where.

Then setup prints where to install the App, the declaration for runner.yaml, and a
policy that selects it.`,
	example: `  qory-github setup                                       # under your account
  qory-github setup --org acme                            # under the organisation acme
  qory-github setup --name qory-github-acme               # the App's name`,
	section: "setup",
}

// run is the command, with its streams, so a test runs it whole. It returns the exit
// status; an error is one line on stderr describing what failed, never a secret.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "credential":
		err = credential(ctx, args[1:], stdin, stdout, stderr)
	case "setup":
		err = setup(ctx, args[1:], stdout, stderr)
	case "describe":
		err = describe(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "qory-github %s: %s\n", args[0], oneLine(err.Error()))
		return 1
	}
	return 0
}

// oneLine is an error's text as the one line it is written on: a line break, \n or
// \r\n, is a space, and every other control character, C0, DEL or C1, and the Unicode
// line and paragraph separators are escaped as Go escapes them in a string, \r, \x7f,
// \u2028, and so is a byte that is not UTF-8, wherever the text comes from, GitHub's
// answer among them. The rest is left as it is, a quote or a backslash too, so a name
// the settings' error already quoted reads the same.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}

// describe prints the integration's description, one JSON document. It takes no
// settings and reaches no network. -h alone prints its help instead.
func describe(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && slices.Contains([]string{"-h", "-help", "--h", "--help"}, args[0]) {
		return describeHelp.parse(flag.NewFlagSet("describe", flag.ContinueOnError), args, stderr)
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

// credential mints a token and prints the runner's credential document, nothing else
// on standard output. The settings are one document on standard input, the only input
// besides the argument, so a machine and a control plane hand them in the same way. It
// takes no flags, which it parses first, since that needs no input; then it reads
// standard input whole, before it checks the argument. `--` ends the flags, so the
// argument is never read as one.
func credential(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("credential", flag.ContinueOnError)
	if err := credentialHelp.parse(fs, args, stderr); err != nil {
		return err
	}
	s, err := github.ReadSettings(stdin)
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("want one argument, owner/name[,owner/name...]")
	}
	repos, err := github.ParseRepositories(fs.Arg(0))
	if err != nil {
		return err
	}
	key, err := readKey(s)
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

// readKey is the App's private key the settings hand in: the key itself, or else the
// file that contains it.
func readKey(s github.Settings) (*rsa.PrivateKey, error) {
	if s.PrivateKey != "" {
		return github.ParseKey([]byte(s.PrivateKey))
	}
	return github.ReadKeyFile(s.PrivateKeyFile)
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
	if err := setupHelp.parse(fs, args, stderr); err != nil {
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
		if err := checkKeyFile(*keyFile); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if *name == "" {
		*name = "qory-github-" + randomSuffix()
	}
	s := github.Setup{Org: *org, Name: *name, KeyFile: *keyFile, Web: *web, Client: github.Client{API: *api}, Open: opener}
	return runSetup(ctx, s, stdout)
}

// runSetup is setup past its flags, so a test drives it with a page opener of its own.
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
		why := app.Moved.Error()
		var pe *fs.PathError
		switch {
		case errors.Is(app.Moved, fs.ErrExist):
			why = "it exists"
		case errors.As(app.Moved, &pe):
			why = pe.Err.Error()
		}
		fmt.Fprintf(stdout, "\nThe key is in %s, since %s could not be written: %s.\n", abs, s.KeyFile, why)
	}
	integrations, policy, err := declaration(app.ID, abs)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, `
The App %d (%s) is created, and its private key is in %s.

Install it on the repositories your agents work on:
  %s

Then declare the integration in the machine's configuration, ~/.config/qory/runner.yaml:

%s
qory expands the declaration into the runner's credential %s. A run's policy selects it
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
	integrations = fmt.Sprintf(`integrations:
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
