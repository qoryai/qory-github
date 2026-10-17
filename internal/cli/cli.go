// Package cli is what the programs qory-github, qory-github-server and
// qory-github-starter share on their command lines: a command's help and how its flags
// are parsed, the one line an error is written on, the program's version, and whether
// QORY_FEATURES switches on factory.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// More is where qory-github's page is; a command's help links to a section of it.
const More = "https://github.com/qoryai/qory-github/blob/main/README.md"

// ProgramVersion is the version set with ldflags when there is one, as it is given, or
// else the main module's version from the build info without its leading v, as the
// integration contract's releases have it, the tag without its v: go records v0.1.0
// for go install ...@v0.1.0, reported as 0.1.0, or a pseudo-version for a commit,
// v0.2.1-0.20261006195344-0f167ba9a536 reported as 0.2.1-0.20261006195344-0f167ba9a536.
// Only a v followed by a digit is dropped; any other version is reported as recorded.
// A build whose module version is (devel) or empty is "dev".
func ProgramVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
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

// Factory is whether the environment variable QORY_FEATURES switches on factory: the
// program qory-github-server, with its commands serve, the webhook receiver, and
// access-key, which enrols its access key for Qory Apiary; the program
// qory-github-starter, with its commands access-key, which enrols a node pool's access
// key, setup, which creates the starter's App, and template, which prints the runner
// template; and --public-url of qory-github's setup.
// Qory Apiary's factory is an opt-in feature of the same name, and the programs read the
// variable by the rules Qory Apiary applies to the name of an opt-in feature:
//
//   - unset, blank, all, and all- followed by the features left out, all-security,factory
//     among them, leave factory off;
//   - a list of the features on, names separated by commas with white space around
//     each ignored, switches factory on when it names factory;
//   - a list that names all or all-… among its features, which Qory Apiary refuses,
//     leaves factory off.
//
// Any other name in the list is ignored.
func Factory() bool {
	v := strings.TrimSpace(os.Getenv("QORY_FEATURES"))
	if v == "all" || strings.HasPrefix(v, "all-") {
		return false
	}
	on := false
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		if name == "all" || strings.HasPrefix(name, "all-") {
			return false
		}
		on = on || name == "factory"
	}
	return on
}

// Help is one command's help. Short is its line in the program's usage; -h prints the
// rest, and the command's flags, on standard error. Section is the command's section on
// the page at [More], or empty for a command the page has none for.
type Help struct {
	Short, Use, Long, Example, Section string
}

// Parse parses args into fs. -h prints the whole help; a flag fs refuses prints the
// command's usage and flags alone, after the flag parser's message.
func (h Help) Parse(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprintf(stderr, "%s\n\n", h.Long)
		h.Usage(stderr, fs)
		fmt.Fprintf(stderr, "\nexamples:\n%s\n", h.Example)
		if h.Section != "" {
			fmt.Fprintf(stderr, "\nMore: %s#%s\n", More, h.Section)
		}
	case err != nil:
		h.Usage(stderr, fs)
	}
	return err
}

// HelpAlone is whether args is a request for help and nothing else: -h, -help, --h or
// --help, alone.
func HelpAlone(args []string) bool {
	return len(args) == 1 && slices.Contains([]string{"-h", "-help", "--h", "--help"}, args[0])
}

// Usage prints the command's usage line, and the flags of fs when it has any.
func (h Help) Usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage:\n  %s\n", h.Use)
	flags := false
	fs.VisitAll(func(*flag.Flag) { flags = true })
	if flags {
		fmt.Fprint(w, "\nflags:\n")
		fs.PrintDefaults()
	}
}

// OneLine is an error's text as the one line it is written on: a line break, \n or
// \r\n, is a space, and every other control character, C0, DEL or C1, the Unicode line
// and paragraph separators, and the bidirectional formatting characters, Unicode's
// Bidi_Control, U+202A to U+202E, U+2066 to U+2069, U+200E, U+200F and U+061C, which
// reorder what a terminal shows, are escaped as Go escapes them in a string, \r, \x7f,
// \u2028, \u202e, and so is a byte that is not UTF-8, wherever the text comes from,
// GitHub's answer among them. The rest is left as it is, a quote or a backslash too, so
// a name the settings' error already quoted reads the same.
func OneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Bidi_Control, r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}
