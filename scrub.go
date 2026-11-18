package github

import (
	"errors"
	"regexp"
	"strings"
)

// lineForbidden is the character class of the characters that a line of prose in the
// contract may not have: the control characters, C0, DEL and C1, the bidirectional
// controls, the line and paragraph separators, and the format characters that are
// usually not shown.
const lineForbidden = `[\x00-\x1f\x7f-\x9f\x{00ad}\x{061c}\x{180e}\x{200b}\x{200e}\x{200f}\x{2028}\x{2029}\x{202a}-\x{202e}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{feff}\x{fff9}-\x{fffb}]`

// LineForbidden matches one character of [lineForbidden].
var LineForbidden = regexp.MustCompile(lineForbidden)

// between matches any number of forbidden characters, so a pattern built with [spread]
// finds a credential that a line break splits.
const between = `(?:` + lineForbidden + `)*`

// spread is the pattern for the literal text lit, with [between] between its characters.
func spread(lit string) string {
	var parts []string
	for _, r := range lit {
		parts = append(parts, regexp.QuoteMeta(string(r)))
	}
	return strings.Join(parts, between)
}

// secretShape matches what looks like a credential, also when a line break or another
// forbidden character splits it: a GitHub token, a signed token of three parts, a bearer
// value, and the user information of an address.
var secretShape = regexp.MustCompile(`(?i)\b(?:` + spread("gh") + between + `[pousr]` + between + `_|` + spread("github_pat_") + `)(?:` + between + `[A-Za-z0-9_]){8,}` +
	`|\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){1,2}` +
	`|bearer\s+\S+` +
	`|\b[a-z][a-z0-9+.-]*://[^\s/@]*@\S*`)

// OneLine is s as one line of at most max characters. It first replaces by "[removed]"
// each of secrets, a literal credential, and anything that looks like a credential, also
// when a forbidden character splits it, and only then replaces each forbidden character
// (see [LineForbidden]) and each run of white space by one space and cuts the rest at max
// characters, so no part of a credential is left by the cut.
func OneLine(s string, max int, secrets ...string) string {
	s = strings.ToValidUTF8(s, "")
	for _, secret := range secrets {
		if secret != "" {
			s = regexp.MustCompile(spread(secret)).ReplaceAllString(s, "[removed]")
		}
	}
	s = secretShape.ReplaceAllString(s, "[removed]")
	s = LineForbidden.ReplaceAllString(s, " ")
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = strings.TrimRight(string(r[:max]), " ")
	}
	return s
}

// maxErrorText is the most characters of the text of an error that [Scrubbed] returns.
const maxErrorText = 2000

// scrubbedError is an error whose text is clean, see [Scrubbed], and that wraps the
// error it was made from, so errors.Is and errors.As find what they found before.
type scrubbedError struct {
	err  error
	text string
}

func (e *scrubbedError) Error() string { return e.text }
func (e *scrubbedError) Unwrap() error { return e.err }

// Scrubbed is err with a text of one line and at most 2000 characters, as [OneLine]
// makes it, with no secret, no credential and no control character. It wraps err, so
// errors.Is and errors.As still find what they found. A [*SubmitRefused] is copied with
// its cause and its message scrubbed, its fix and reason unchanged. A nil err is nil.
func Scrubbed(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	var refused *SubmitRefused
	if errors.As(err, &refused) && err == error(refused) {
		r := *refused
		r.Err = Scrubbed(refused.Err, secrets...)
		r.Message = OneLine(refused.Message, MaxDetail, secrets...)
		return &r
	}
	return &scrubbedError{err: err, text: OneLine(err.Error(), maxErrorText, secrets...)}
}
