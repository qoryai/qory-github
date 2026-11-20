package github

import (
	"io/fs"
	"path"
	"testing"

	"github.com/qoryai/integrations/contracts"
)

func descriptionFile(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(contracts.RunFS, path.Join("submit-program", "fixtures", "description", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestTheDescriptionIsMarkedAsTheContractsFixturesWriteIt: markedDescription gives the
// result of every case of the contract's fixtures/description, and a second write of the
// same text changes nothing.
func TestTheDescriptionIsMarkedAsTheContractsFixturesWriteIt(t *testing.T) {
	cases, err := fs.ReadDir(contracts.RunFS, "submit-program/fixtures/description")
	if err != nil || len(cases) < 15 {
		t.Fatalf("%d cases, %v", len(cases), err)
	}
	for _, c := range cases {
		existing := descriptionFile(t, c.Name()+"/existing.md")
		text := descriptionFile(t, c.Name()+"/text.md")
		result := descriptionFile(t, c.Name()+"/result.md")
		if got := markedDescription(existing, text); got != result {
			t.Errorf("%s: got %q, want %q", c.Name(), got, result)
		}
		if again := markedDescription(result, text); again != result {
			t.Errorf("%s: a second write gives %q, want %q", c.Name(), again, result)
		}
	}
}

func TestATitleChangesOnlyWhileItIsThePreviousOne(t *testing.T) {
	for _, c := range []struct{ name, current, previous, next, want string }{
		{"unchanged title", "Show dates", "Show dates", "Show delivery dates", "Show delivery dates"},
		{"edited title", "Show dates (urgent)", "Show dates", "Show delivery dates", "Show dates (urgent)"},
		{"no previous title", "Show dates", "", "Show delivery dates", "Show dates"},
		{"empty title, no previous title", "", "", "Show delivery dates", ""},
		{"empty title, a previous title", "", "Show dates", "Show delivery dates", ""},
		{"same title again", "Show dates", "Show dates", "Show dates", "Show dates"},
	} {
		if got := nextTitle(c.current, c.previous, c.next); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestATextWithAMarkerLineIsRefused: a line that is a marker, with trailing spaces, tabs or
// a carriage return, is refused; a marker inside a line, or with other text after it, is
// not a marker line to markedDescription, so it is allowed.
func TestATextWithAMarkerLineIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"no marker", "Text.\nMore.", false},
		{"the start marker alone", markerStart, true},
		{"the end marker after text", "Text.\n" + markerEnd, true},
		{"a marker with trailing spaces and a tab", "a\n" + markerEnd + " \t\nb", true},
		{"a marker line in CRLF text", "a\r\n" + markerStart + "\r\nb", true},
		{"a marker inside a line", "see " + markerStart + " here", false},
		{"a marker with text after it", markerEnd + " no", false},
		{"a marker with a space before it", " " + markerEnd, false},
	} {
		err := CheckMarkers(tc.text)
		if (err != nil) != tc.refused {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if tc.refused {
			refused, ok := err.(*SubmitRefused)
			if !ok || refused.Reason != ReasonRefused || len(refused.Fix) > 100 || refused.Detail()[:len(refused.Fix)] != refused.Fix {
				t.Errorf("%s: %#v", tc.name, err)
			}
		}
		if got := hasMarkerLine(tc.text); got != tc.refused {
			t.Errorf("%s: hasMarkerLine is %v", tc.name, got)
		}
	}
}
