package github

import (
	"context"
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
	for _, fix := range []string{FixNotInstalled, FixPermission, FixSuspended, FixAppForbidden, FixUnreachable, fixMoved, fixHeadGone, fixBaseGone, fixBranchGone, fixRunDescription, fixRunTitle, fixPullBody, fixPullTitle, fixPullText, fixForgeRefused} {
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
