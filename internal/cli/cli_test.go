package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestOneLine pins how an error's text is written on its line: a line break as a space,
// every other control character, a line or paragraph separator, a bidirectional
// formatting character and a byte that is not UTF-8 escaped, and the rest as it is.
func TestOneLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"the settings are invalid: /permissions/contents: value must be one of 'read', 'write'", "the settings are invalid: /permissions/contents: value must be one of 'read', 'write'"},
		{`/permissions/"a\u2028b": a quote " and a backslash \ stay`, `/permissions/"a\u2028b": a quote " and a backslash \ stay`},
		{"one\ntwo\r\nthree", "one two three"},
		{"a\rb\tc\x00d\x1be\x7ff", `a\rb\tc\x00d\x1be\x7ff`},
		{"a\u0085b\u009bc\u2028d\u2029e", `a\u0085b\u009bc\u2028d\u2029e`},
		{"a\x85b\xffc", `a\x85b\xffc`},
		{"GitHub – Ölsardine ✓", "GitHub – Ölsardine ✓"},
		{"acme\u202epohs", `acme\u202epohs`},
		{"a\u202ab\u202bc\u202cd\u202de\u202ef", `a\u202ab\u202bc\u202cd\u202de\u202ef`},
		{"a\u2066b\u2067c\u2068d\u2069e", `a\u2066b\u2067c\u2068d\u2069e`},
		{"a\u200eb\u200fc\u061cd", `a\u200eb\u200fc\u061cd`},
		// The characters beside them are left as they are: a zero-width joiner, U+200D, an
		// Arabic letter, U+0628, a narrow no-break space, U+202F, and U+2065 and U+206A.
		{"a\u200db\u0628c\u202fd\u2065e\u206af", "a\u200db\u0628c\u202fd\u2065e\u206af"},
	} {
		if got := OneLine(tc.in); got != tc.want {
			t.Errorf("OneLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestProgramVersionFallsBackToTheModuleVersion pins the program's version: the one
// set with ldflags first, as it is given, then the module version go install records,
// a release or a pseudo-version, without its leading v, as the integration contract
// reports a release's version, which the contract's schema accepts, and "dev" for a
// build whose module version is (devel) or empty, or with no build info.
func TestProgramVersionFallsBackToTheModuleVersion(t *testing.T) {
	pseudo := "0.2.1-0.20261006195344-0f167ba9a536"
	for _, tc := range []struct {
		ldflags, module string
		info            bool
		want            string
	}{
		{"1.2.3", "v0.1.0", true, "1.2.3"},
		{"v1.2.3", "v0.1.0", true, "v1.2.3"},
		{"", "v0.1.0", true, "0.1.0"},
		{"", "v" + pseudo, true, pseudo},
		{"", "v1", true, "1"},
		{"", "0.1.0", true, "0.1.0"},
		{"", "vv0.1.0", true, "vv0.1.0"},
		{"", "version", true, "version"},
		{"", "v", true, "v"},
		{"", "(devel)", true, "dev"},
		{"", "", true, "dev"},
		{"", "", false, "dev"},
	} {
		read := func() (*debug.BuildInfo, bool) {
			if !tc.info {
				return nil, false
			}
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/qoryai/qory-github", Version: tc.module}}, true
		}
		if got := ProgramVersion(tc.ldflags, read); got != tc.want {
			t.Errorf("ldflags %q, module %q, build info %v: %q, want %q", tc.ldflags, tc.module, tc.info, got, tc.want)
		}
	}
	schema, err := contracts.Compile("description.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(github.Describe(pseudo))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the contract refuses the pseudo-version %s: %v", pseudo, err)
	}
}

// TestFactory pins how QORY_FEATURES is read: factory is on where a list of features
// names it, and off where the variable is unset, blank, all, or all- followed by the
// features left out, or where the list names all or all- and more among its features.
func TestFactory(t *testing.T) {
	for _, features := range []string{"", " ", "all", "all-security", "all-security,factory", " all-factory", "factory2", "observability,security", "factory,all", "factory, all-security"} {
		t.Setenv("QORY_FEATURES", features)
		if Factory() {
			t.Errorf("QORY_FEATURES=%q switches factory on", features)
		}
	}
	for _, features := range []string{"factory", "observability, factory ", " factory,", "observability,security,secrets,factory"} {
		t.Setenv("QORY_FEATURES", features)
		if !Factory() {
			t.Errorf("QORY_FEATURES=%q leaves factory off", features)
		}
	}
}

// TestHelpAlone pins which arguments are a request for help and nothing else.
func TestHelpAlone(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--h"}, {"--help"}} {
		if !HelpAlone(args) {
			t.Errorf("%q is not help alone", args)
		}
	}
	for _, args := range [][]string{nil, {}, {"-h", "x"}, {"x", "-h"}, {"help"}, {"---h"}} {
		if HelpAlone(args) {
			t.Errorf("%q is help alone", args)
		}
	}
}

// TestHelpParse pins what a command's help prints: with -h, the whole help, and the link
// to its section only when it has one; with a flag it does not know, its usage and flags
// alone.
func TestHelpParse(t *testing.T) {
	h := Help{Short: "short", Use: "prog cmd --x X", Long: "long", Example: "  prog cmd --x 1", Section: "cmd"}
	newFlags := func() *flag.FlagSet {
		fs := flag.NewFlagSet("cmd", flag.ContinueOnError)
		fs.String("x", "", "the x")
		return fs
	}
	var errs bytes.Buffer
	if err := h.Parse(newFlags(), []string{"-h"}, &errs); err != flag.ErrHelp {
		t.Errorf("-h: %v", err)
	}
	if want := "long\n\nusage:\n  prog cmd --x X\n\nflags:\n  -x string\n    \tthe x\n\nexamples:\n  prog cmd --x 1\n\nMore: " + More + "#cmd\n"; errs.String() != want {
		t.Errorf("-h prints %q, want %q", errs.String(), want)
	}
	errs.Reset()
	h.Section = ""
	h.Parse(newFlags(), []string{"-h"}, &errs)
	if strings.Contains(errs.String(), "More:") {
		t.Errorf("-h without a section prints %q", errs.String())
	}
	errs.Reset()
	if err := h.Parse(newFlags(), []string{"--y"}, &errs); err == nil || err == flag.ErrHelp {
		t.Errorf("--y: %v", err)
	}
	if want := "flag provided but not defined: -y\nusage:\n  prog cmd --x X\n\nflags:\n  -x string\n    \tthe x\n"; errs.String() != want {
		t.Errorf("--y prints %q, want %q", errs.String(), want)
	}
}
