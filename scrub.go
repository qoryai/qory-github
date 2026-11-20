package github

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// LineStopped is whether the rule of a line stops r: every control character (category
// Cc), U+2028, U+2029, and every format character (category Cf) but U+200C and U+200D,
// which emoji sequences and some scripts need. It is the rule of $defs.line in the
// contract's description.schema.json, and of a title, an account title, an author name
// and a failure detail, which refer to it. The Unicode version of the Go release decides
// which characters are in category Cf.
func LineStopped(r rune) bool {
	switch r {
	case '\u2028', '\u2029':
		return true
	case '\u200c', '\u200d':
		return false
	}
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

// HasVisible is whether s has a character that is not a space (category Zs) and not
// U+200C or U+200D, as a title needs: the contract's change_title.
func HasVisible(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return !unicode.Is(unicode.Zs, r) && r != '\u200c' && r != '\u200d'
	})
}

// between matches any number of characters that may split a credential: every character
// that [LineStopped] stops, and U+200C and U+200D, so every format character. It is for
// matching only.
const between = `(?:[\p{Cc}\p{Cf}\x{2028}\x{2029}])*`

// spread is the pattern for the literal text lit, with [between] between its characters.
func spread(lit string) string {
	var parts []string
	for _, r := range lit {
		parts = append(parts, regexp.QuoteMeta(string(r)))
	}
	return strings.Join(parts, between)
}

// space matches white space, or a character of [between], between the words of a
// credential.
const space = `(?:[\s\p{Zs}]|[\p{Cc}\p{Cf}\x{2028}\x{2029}])+`

// valueChars is the class of the characters of a bearer or header value, and base64Chars
// the class of those of a basic value, which is base64 and has no dot.
const (
	valueChars  = `[A-Za-z0-9+/=_.~-]`
	base64Chars = `[A-Za-z0-9+/=_-]`
)

// valueShape is the pattern for a value that looks like a credential, also when a
// character of [between] splits it: a run of 20 or more characters of class, or a run of
// at least n of them that has a character of marks. It has no word of prose: a word of
// letters only and fewer than 20 characters is not a credential.
func valueShape(class string, n int, marks string) string {
	one := between + class
	alternatives := []string{tokenChars(class, 20)}
	for before := 0; before < n; before++ {
		alternatives = append(alternatives, `(?:`+one+`){`+strconv.Itoa(before)+`}`+between+marks+`(?:`+one+`){`+strconv.Itoa(n-1-before)+`}(?:`+one+`)*`)
	}
	alternatives = append(alternatives, `(?:`+one+`){`+strconv.Itoa(n)+`,}`+between+marks+`(?:`+one+`)*`)
	return `(?:` + strings.Join(alternatives, `|`) + `)`
}

// tokenChars is the pattern for n or more characters of a token, each of which a
// character of [between] may precede.
func tokenChars(class string, n int) string {
	return `(?:` + between + class + `){` + strconv.Itoa(n) + `,}`
}

var (
	// authorizationHeader matches a header value, and the group is what stays: the name
	// of the header. The value is, after a known scheme, any word, and otherwise a value
	// that looks like a credential, with or without a scheme word before it, so a sentence
	// such as "Authorization: required for" stays.
	authorizationHeader = regexp.MustCompile(`(?i)(\b` + spread("authorization") + `[\s\p{Zs}]*[:=][\s\p{Zs}]*)(?:` +
		`(?:token|bearer|basic|digest|negotiate|ntlm|apikey)` + space + `\S+` +
		`|(?:[a-z][a-z0-9_-]*` + space + `)?` + valueShape(valueChars, 8, `[0-9]`) + `)`)
	// secretShape matches what looks like a credential, also when a line break or another
	// character of [between] splits it: a GitHub token, a signed token of three parts, a
	// bearer or basic value, a block of a PEM key, and the user information of an address.
	// The prefix of a GitHub token is lower case, so a constant such as HIGHS_AND_LOWS_FLAG
	// stays. A bearer or basic value is removed only when it looks like a credential, so
	// "the basic permissions" stays.
	secretShape = regexp.MustCompile(`(?i)(?-i:` + spread("gh") + between + `[pousr]` + between + `_|` + spread("github_pat_") + `)` + tokenChars(`[A-Za-z0-9_]`, 8) +
		`|` + spread("eyJ") + tokenChars(`[A-Za-z0-9_-]`, 8) + `(?:` + between + `\.` + tokenChars(`[A-Za-z0-9_-]`, 1) + `){1,2}` +
		`|\b` + spread("bearer") + space + valueShape(valueChars, 8, `[0-9]`) +
		// A basic value of letters only and under 20 characters is not removed: GitHub never echoes one.
		`|\b` + spread("basic") + space + valueShape(base64Chars, 12, `[0-9+/=]`) +
		`|(?s:-----BEGIN[^-]*KEY-----.*?(?:-----END[^-]*KEY-----|$))` +
		`|\b[a-z][a-z0-9+.-]*://[^\s/@]*@\S*`)
)

// preCut is the most bytes of a text [OneLine] reads: what follows is left out before
// any pattern runs, so a long answer costs the same as a short one.
const preCut = 64 << 10

// maxCredential is the most characters of a run at the end of a cut text that [cutAt]
// takes for a credential and drops: no credential has more.
const maxCredential = 4096

// cutAt is s cut at about max bytes on a character boundary, and without the run of
// characters that a credential has at its end, at most [maxCredential] of them, so a
// credential that the cut halves leaves no part of it.
func cutAt(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	s = s[:max]
	for trimmed := 0; len(s) > 0 && trimmed < maxCredential; trimmed++ {
		r, n := utf8.DecodeLastRuneInString(s)
		if !(r < utf8.RuneSelf && (r == '_' || r == '-' || r == '.' || r == '+' || r == '/' || r == '=' ||
			'0' <= r && r <= '9' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z') || unicode.Is(unicode.Cf, r) || LineStopped(r)) {
			break
		}
		s = s[:len(s)-n]
	}
	return s
}

// OneLine is s as one line of at most max characters. It reads at most 64 KiB of s. It
// first replaces by "[removed]" each of secrets, a literal credential, and anything that
// looks like a credential, also when a forbidden character splits it, and only then
// replaces each stopped character (see [LineStopped]) and each run of white space by
// one space and cuts the rest at max characters, so no part of a credential is left by
// the cut.
func OneLine(s string, max int, secrets ...string) string {
	s = cutAt(strings.ToValidUTF8(s, ""), preCut)
	for _, secret := range secrets {
		if secret != "" {
			s = regexp.MustCompile(spread(secret)).ReplaceAllString(s, "[removed]")
		}
	}
	s = authorizationHeader.ReplaceAllString(s, "${1}[removed]")
	s = secretShape.ReplaceAllString(s, "[removed]")
	s = strings.Map(func(r rune) rune {
		if LineStopped(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = strings.TrimRight(string(r[:max]), " ")
	}
	return s
}

// maxErrorText is the most characters of the text of an error that [Scrubbed] returns.
const maxErrorText = 2000

// scrubbedError is an error whose text is clean, see [Scrubbed], and that wraps the
// error it was made from, so errors.Is and errors.As find what they found before. When
// the error wraps an answer of GitHub, status and message are the answer's, the message
// clean, so a caller never reads the raw one again, see [AnswerOf].
type scrubbedError struct {
	err     error
	text    string
	status  int
	message string
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
	out := &scrubbedError{err: err, text: OneLine(err.Error(), maxErrorText, secrets...)}
	var answered *answerError
	if errors.As(err, &answered) {
		out.status, out.message = answered.status, OneLine(answered.message, MaxDetail, secrets...)
	}
	return out
}

// ErrTransport is wrapped in the error of a request that did not reach GitHub or whose
// answer could not be read from the connection: a timeout, a failed connection. A retry
// can succeed.
var ErrTransport = errors.New("GitHub's API could not be reached")

// connectionError is the error of a connection that failed while GitHub's answer was
// read. It is [ErrTransport] for errors.Is, and wraps the cause, so a timeout stays one.
type connectionError struct {
	text  string
	cause error
}

func (e *connectionError) Error() string { return e.text }
func (e *connectionError) Unwrap() error { return e.cause }

// Is makes the error [ErrTransport] for errors.Is.
func (e *connectionError) Is(target error) bool { return target == ErrTransport }

// connectionFailed is the error for a read of GitHub's answer to the request what, to
// path, that failed with err after the status was received.
func connectionFailed(what, path string, err error) error {
	cause := unsent(err, path)
	return &connectionError{text: fmt.Sprintf("%s: the connection failed while GitHub's answer was read: %v", what, cause), cause: cause}
}

// unreadableError is the error for an answer of GitHub that does not have the shape the
// adapter reads. It is [ErrUnreadableAnswer] for errors.Is, and says text.
type unreadableError struct {
	text  string
	cause error
	// status is the status of the answer, 0 when it is not known.
	status int
}

func (e *unreadableError) Error() string { return e.text }
func (e *unreadableError) Unwrap() error { return e.cause }

// Is makes the error [ErrUnreadableAnswer] for errors.Is.
func (e *unreadableError) Is(target error) bool { return target == ErrUnreadableAnswer }

// unreadableAt is the [unreadableError] that says text, for cause, which may be nil, of
// an answer with status.
func unreadableAt(status int, text string, cause error) error {
	return &unreadableError{text: text, cause: cause, status: status}
}
