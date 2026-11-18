package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestEveryFixLineIsOneSentenceOfAtMost100Characters: each fix line, which starts the
// text of a refusal and the detail of its failure report, ends with a period and fits in
// 100 characters.
func TestEveryFixLineIsOneSentenceOfAtMost100Characters(t *testing.T) {
	for _, fix := range []string{FixNotInstalled, FixPermission, FixSuspended, FixAppForbidden, FixUnreachable, fixMoved, fixHeadGone, fixBaseGone, fixBranchGone, fixRunDescription, fixRunTitle, fixPullBody, fixPullTitle, fixPullText, FixForgeRefused} {
		if n := utf8.RuneCountInString(fix); n > 100 || !strings.HasSuffix(fix, ".") || strings.Contains(fix, "\n") {
			t.Errorf("%d characters: %q", n, fix)
		}
	}
}

// TestOneLineCleansAndCuts: control characters, line breaks and runs of spaces become one
// space, a token, a bearer value and an address with a password are removed, and the line
// is cut at the limit without a trailing space or a broken character.
func TestOneLineCleansAndCuts(t *testing.T) {
	got := OneLine("a\nb\r\n\tc\x00d e  ghp_abcdefgh12345678 Bearer xyz https://u:p@host/x ok", 1000)
	if want := "a b c d e [removed] [removed] [removed] ok"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if got := OneLine(strings.Repeat("é ", 600), 1000); utf8.RuneCountInString(got) != 999 || !utf8.ValidString(got) || strings.HasSuffix(got, " ") {
		t.Errorf("%d characters", utf8.RuneCountInString(got))
	}
}

// TestTheChosenPullRequestIsTheOpenOneWithTheHighestNumber: of pull requests from the
// branch, an open one is chosen over any closed or merged one, the highest number first;
// with none open, the closed or merged one with the highest number.
func TestTheChosenPullRequestIsTheOpenOneWithTheHighestNumber(t *testing.T) {
	pull := func(n int, state string) ghPull { return ghPull{Number: n, State: state} }
	for _, tc := range []struct {
		pulls []ghPull
		want  int
	}{
		{[]ghPull{pull(1, "open"), pull(2, "open")}, 2},
		{[]ghPull{pull(3, "open"), pull(2, "open")}, 3},
		{[]ghPull{pull(1, "open"), pull(5, "closed")}, 1},
		{[]ghPull{pull(5, "closed"), pull(1, "open"), pull(7, "closed")}, 1},
		{[]ghPull{pull(4, "closed"), pull(6, "closed"), pull(2, "closed")}, 6},
		{[]ghPull{pull(9, "closed")}, 9},
	} {
		if got := chosenOf(tc.pulls); got.Number != tc.want {
			t.Errorf("%v: %d, want %d", tc.pulls, got.Number, tc.want)
		}
	}
}

// TestAnAnswerThatEchoesTheTokenDoesNotCarryItInTheRefusal: GitHub's message for a 400 has
// the token that was sent; the refusal's message, which the failure report's detail has,
// does not.
func TestAnAnswerThatEchoesTheTokenDoesNotCarryItInTheRefusal(t *testing.T) {
	const tok = "plain-token-value-1234"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"Bad credentials ` + tok + ` sent"}`))
	}))
	defer srv.Close()
	_, err := Client{API: srv.URL}.SubmitDraft(context.Background(), nil, tok, Draft{Repository: Repository{Owner: "acme", Name: "widgets"}, Branch: "qory/wi_1", Base: "main", Title: "T", Description: "D"})
	refused, ok := err.(*SubmitRefused)
	if !ok || refused.Reason != ReasonForgeRefused || refused.Status != 400 || strings.Contains(refused.Message, tok) || !strings.Contains(refused.Detail(), "GitHub answered 400: Bad credentials [removed] sent") {
		t.Errorf("%#v", err)
	}
}

// TestOneLineRemovesACredentialThatALineBreakSplitsOrTheCutWouldHalve: the secret and the
// patterns are replaced before the forbidden characters become spaces and before the cut,
// so a token split by a line break is removed whole, and a token that starts before the
// boundary of the cut leaves no prefix of it.
func TestOneLineRemovesACredentialThatALineBreakSplitsOrTheCutWouldHalve(t *testing.T) {
	const plain = "a-plain-secret-value"
	pattern := "ghs_" + "AbCdEfGh1234567890"
	for _, tc := range []struct {
		name, in, want string
	}{
		{"the secret split by LF", "x " + plain[:7] + "\n" + plain[7:] + " y", "x [removed] y"},
		{"the secret split by CRLF and a tab", "x " + plain[:3] + "\r\n\t" + plain[3:] + " y", "x [removed] y"},
		{"a token split by LF", "x " + pattern[:6] + "\n" + pattern[6:] + " y", "x [removed] y"},
		{"a token split by U+2028", "x " + pattern[:9] + " " + pattern[9:] + " y", "x [removed] y"},
		{"a fine-grained token", "x github_pat_" + "AbCdEfGh1234567890" + " y", "x [removed] y"},
		{"two lines that no secret joins", "line one\nline two", "line one line two"},
	} {
		if got := OneLine(tc.in, 1000, plain); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, token := range []string{pattern, plain} {
		for pad := 990; pad <= 1000; pad++ {
			got := OneLine(strings.Repeat("x", pad-1)+" "+token, 1000, plain)
			for i := 3; i <= len(token); i++ {
				if strings.Contains(got, token[:i]) {
					t.Fatalf("pad %d: the cut left %q of %q", pad, token[:i], token)
				}
			}
			if utf8.RuneCountInString(got) > 1000 {
				t.Fatalf("pad %d: %d characters", pad, utf8.RuneCountInString(got))
			}
		}
	}
}

// TestScrubbedKeepsWhatErrorsFindAndCleansTheText: the text has no secret, no credential,
// no line break and at most 2000 characters; errors.Is and errors.As find what they found;
// a refusal keeps its reason and fix and has a clean cause and message.
func TestScrubbedKeepsWhatErrorsFindAndCleansTheText(t *testing.T) {
	const secret = "a-plain-secret-value"
	cause := &answerError{what: "opening", status: 400, message: "bad\n" + secret[:5] + "\n" + secret[5:] + strings.Repeat(" long", 1000)}
	wrapped := Scrubbed(cause, secret)
	var found *answerError
	if !errors.As(wrapped, &found) || found != cause || strings.ContainsAny(wrapped.Error(), "\r\n") || strings.Contains(wrapped.Error(), secret[:5]) || utf8.RuneCountInString(wrapped.Error()) > 2000 {
		t.Errorf("%q", wrapped.Error())
	}
	if !errors.Is(Scrubbed(fmt.Errorf("x: %w", ErrNotInstalled), secret), ErrNotInstalled) || Scrubbed(nil, secret) != nil {
		t.Error("errors.Is no longer finds the error, or nil is not nil")
	}
	refused := Scrubbed(&SubmitRefused{Reason: ReasonForgeRefused, Fix: FixForgeRefused, Err: cause, Status: 400, Message: "a " + secret + "\nb"}, secret)
	var r *SubmitRefused
	if !errors.As(refused, &r) || r.Reason != ReasonForgeRefused || r.Fix != FixForgeRefused || r.Message != "a [removed] b" || strings.Contains(refused.Error(), secret[:5]) || !strings.HasPrefix(refused.Error(), FixForgeRefused+" ") {
		t.Errorf("%#v: %q", r, refused.Error())
	}
}

// TestEndedRefusalByTheLastCause: the reason of a repository whose retries ended is by
// the error of its last try: 5xx, 408, a rate limit, a timeout and a failed connection are
// unreachable; a 401, not_permitted; any other 4xx, and an answer that is no JSON,
// forge_refused; a refusal stays what it is.
func TestEndedRefusalByTheLastCause(t *testing.T) {
	answer := func(status int) error { return &answerError{what: "w", status: status, message: "m"} }
	limited := &answerError{what: "w", status: 403, message: "rate limit", limited: true}
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"500", answer(500), ReasonUnreachable},
		{"502", answer(502), ReasonUnreachable},
		{"408", answer(408), ReasonUnreachable},
		{"429", answer(429), ReasonUnreachable},
		{"a rate limit", limited, ReasonUnreachable},
		{"a timeout", context.DeadlineExceeded, ReasonUnreachable},
		{"a failed connection", errors.New("dial tcp: connection refused"), ReasonUnreachable},
		{"401", answer(401), ReasonNotPermitted},
		{"400", answer(400), ReasonForgeRefused},
		{"409", answer(409), ReasonForgeRefused},
		{"422", answer(422), ReasonForgeRefused},
		{"an unreadable answer", unreadable("reading", errors.New("invalid character")), ReasonForgeRefused},
		{"a refusal", &SubmitRefused{Reason: ReasonBranchGone, Fix: fixHeadGone, Err: errors.New("x")}, ReasonBranchGone},
	} {
		got := EndedRefusal(fmt.Errorf("%w (entry)", tc.cause))
		if got.Reason != tc.reason || got.Fix == "" || got.Detail() == "" {
			t.Errorf("%s: %s, want %s", tc.name, got.Reason, tc.reason)
		}
	}
}
