package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestEveryFixLineIsOneSentenceOfAtMost100Characters: each fix line, which starts the
// text of a refusal and the detail of its failure report, ends with a period and fits in
// 100 characters.
func TestEveryFixLineIsOneSentenceOfAtMost100Characters(t *testing.T) {
	for _, fix := range []string{FixNotInstalled, FixPermission, FixSuspended, FixAppForbidden, FixUnreachable, FixMoved, fixHeadGone, fixBaseGone, fixBranchGone, fixRunDescription, fixRunTitle, fixTitleStopped, fixTitleBlank, fixMarkerLine, fixPullBody, fixPullTitle, fixPullText, FixForgeRefused, FixGone, FixChangeKind, FixChangeData} {
		if n := utf8.RuneCountInString(fix); n > 100 || !strings.HasSuffix(fix, ".") || strings.Contains(fix, "\n") {
			t.Errorf("%d characters: %q", n, fix)
		}
	}
}

// TestOneLineCleansAndCuts: control characters, line breaks and runs of spaces become one
// space, a token, a bearer value and an address with a password are removed, and the line
// is cut at the limit without a trailing space or a broken character.
func TestOneLineCleansAndCuts(t *testing.T) {
	got := OneLine("a\nb\r\n\tc\x00d e  ghp_abcdefgh12345678 Bearer xyz98765 https://u:p@host/x ok", 1000)
	if want := "a b c d e [removed] [removed] [removed] ok"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if got := OneLine(strings.Repeat("é ", 600), 1000); utf8.RuneCountInString(got) != 999 || !utf8.ValidString(got) || strings.HasSuffix(got, " ") {
		t.Errorf("%d characters", utf8.RuneCountInString(got))
	}
}

// TestTheChosenPullRequestIsTheOneWithTheHighestNumber: of the open pull requests from the
// branch, the one with the highest number is chosen.
func TestTheChosenPullRequestIsTheOneWithTheHighestNumber(t *testing.T) {
	pull := func(n int) ghPull { return ghPull{Number: n, State: "open"} }
	for _, tc := range []struct {
		pulls []ghPull
		want  int
	}{
		{[]ghPull{pull(1), pull(2)}, 2},
		{[]ghPull{pull(3), pull(2)}, 3},
		{[]ghPull{pull(9)}, 9},
	} {
		if got := chosenOf(tc.pulls); got.Number != tc.want {
			t.Errorf("%v: %d, want %d", tc.pulls, got.Number, tc.want)
		}
	}
}

// TestSubmitDraftStopsATitleOrATextThatBreaksTheRulesBeforeAnyRequest: SubmitDraft itself
// returns a refusal with the reason refused for a text with a marker line and for a title
// that the title rule stops, and sends nothing to GitHub.
func TestSubmitDraftStopsATitleOrATextThatBreaksTheRulesBeforeAnyRequest(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	for _, tc := range []struct{ name, title, text, fix string }{
		{"a marker line", "T", "a\n<!-- qory:end -->\nb", fixMarkerLine},
		{"a stopped character", "T\u202e", "D", fixTitleStopped},
		{"a blank title", " \u200d ", "D", fixTitleBlank},
	} {
		_, err := Client{API: srv.URL}.SubmitDraft(context.Background(), nil, "tok", Draft{Repository: Repository{Owner: "acme", Name: "widgets"}, Branch: "qory/wi_1", Base: "main", Title: tc.title, Description: tc.text})
		refused, ok := err.(*SubmitRefused)
		if !ok || refused.Reason != ReasonRefused || refused.Fix != tc.fix {
			t.Errorf("%s: %#v", tc.name, err)
		}
	}
	if requests != 0 {
		t.Errorf("%d requests reached GitHub", requests)
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
	if !ok || refused.Reason != ReasonRefused || refused.Status != 400 || strings.Contains(refused.Message, tok) || !strings.Contains(refused.Detail(), "GitHub returned 400: Bad credentials [removed] sent") {
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
	refused := Scrubbed(&SubmitRefused{Reason: ReasonRefused, Fix: FixForgeRefused, Err: cause, Status: 400, Message: "a " + secret + "\nb"}, secret)
	var r *SubmitRefused
	if !errors.As(refused, &r) || r.Reason != ReasonRefused || r.Fix != FixForgeRefused || r.Message != "a [removed] b" || strings.Contains(refused.Error(), secret[:5]) || !strings.HasPrefix(refused.Error(), FixForgeRefused+" ") {
		t.Errorf("%#v: %q", r, refused.Error())
	}
}

// TestEndedRefusalByTheLastCause: the reason of a repository whose retries ended is by
// the error of its last try: 5xx, 408, a rate limit, a timeout and a failed connection are
// unreachable; a 401, not_permitted; any other 4xx, and an answer that is no JSON,
// refused; a moved repository, target_gone; a refusal stays what it is.
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
		{"a failed connection", fmt.Errorf("w: %w: %w", ErrTransport, errors.New("dial tcp: connection refused")), ReasonUnreachable},
		{"401", answer(401), ReasonNotPermitted},
		{"403 that is no rate limit", answer(403), ReasonNotPermitted},
		{"404", answer(404), ReasonNotPermitted},
		{"301, a moved repository", answer(301), ReasonTargetGone},
		{"308, a moved repository", answer(308), ReasonTargetGone},
		{"302, a redirect that is not followed", answer(302), ReasonRefused},
		{"307, a redirect that is not followed", answer(307), ReasonRefused},
		{"the redirect of a mint", errMintRedirected, ReasonRefused},
		{"an answer without a token", unreadableAt(201, "minting: GitHub answered without a token", nil), ReasonRefused},
		{"an expiry that is no time", unreadableAt(201, `minting: the expiry "x" is not a time`, errors.New("x")), ReasonRefused},
		{"a canceled call", context.Canceled, ReasonUnreachable},
		{"an error that is no answer and no failure to reach GitHub", errors.New("no private key"), ReasonRefused},
		{"400", answer(400), ReasonRefused},
		{"409", answer(409), ReasonRefused},
		{"422", answer(422), ReasonRefused},
		{"an unreadable answer", unreadable(200, "reading", errors.New("invalid character")), ReasonRefused},
		{"a refusal", &SubmitRefused{Reason: ReasonTooLong, Fix: fixRunTitle, Err: errors.New("x")}, ReasonTooLong},
	} {
		got := EndedRefusal(fmt.Errorf("%w (entry)", tc.cause))
		if got.Reason != tc.reason || got.Fix == "" || got.Detail() == "" {
			t.Errorf("%s: %s, want %s", tc.name, got.Reason, tc.reason)
		}
	}
}

// TestTheDetailOfAnEndedRefusalHasNoTokenThatTheMessageHas: the message of a 502 has the
// token after a word character (a prefix glued to it), a literal secret that is no
// pattern, and a line break; after Scrubbed with the secret, EndedRefusal and Detail,
// the detail has none of them, though EndedRefusal reads the answer through the error it
// wraps.
func TestTheDetailOfAnEndedRefusalHasNoTokenThatTheMessageHas(t *testing.T) {
	const plain = "a-plain-secret-value"
	const token = "ghs_AbCdEfGh1234567890"
	cause := &answerError{what: "w", status: 502, message: "bad creds for xx" + token + " and token_" + token + "\n" + plain[:6] + "\n" + plain[6:] + " end"}
	ended := EndedRefusal(fmt.Errorf("%w (change request)", Scrubbed(cause, plain)))
	detail := ended.Detail()
	if ended.Reason != ReasonUnreachable || strings.Contains(detail, "AbCdEf") || strings.Contains(detail, plain[:6]) || strings.Contains(detail, "secret") || !strings.HasSuffix(detail, "end") || strings.ContainsAny(detail, "\r\n") {
		t.Errorf("%s: %q", ended.Reason, detail)
	}
}

// TestACredentialIsRemovedInEveryShapeItTakes: each text has a credential in a shape that
// a line break, a zero-width character or a prefix may hide; the output has no part of it.
func TestACredentialIsRemovedInEveryShapeItTakes(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0In0.c2lnbmF0dXJl"
	for _, tc := range []struct {
		name, in string
		gone     []string
	}{
		{"a token after a word character", "xghs_AbCdEfGh1234567890 and token_ghs_AbCdEfGh1234567890", []string{"AbCdEfGh"}},
		{"a token with U+200C inside", "ghs_AbCd\u200cEfGh12345678", []string{"AbCd", "EfGh"}},
		{"a token with U+200D inside", "ghs_AbCd\u200dEfGh12345678", []string{"AbCd", "EfGh"}},
		{"a signed token split by line breaks", "eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi\nOiIxMjM0In0.c2ln\nbmF0dXJl", []string{"OiIxMjM0", "bmF0dXJl", "hbGciOiJS"}},
		{"a signed token whole", jwt, []string{"hbGciOiJS", "c2lnbmF0"}},
		{"a bearer value split by a line break", "Bearer abc123\ndef456 done", []string{"abc123", "def456"}},
		{"a bearer value after a zero-width space", "bearer\u200bxyz98765", []string{"xyz98765"}},
		{"a bearer value after a line break", "bearer\nxyz98765", []string{"xyz98765"}},
		{"an authorization header with a scheme", "Authorization: Token abcdef12345 more", []string{"abcdef12345"}},
		{"an authorization header with a value", "authorization=abcdef12345", []string{"abcdef12345"}},
		{"an authorization header split", "Authori\nzation: Custom abcdef12345", []string{"abcdef12345"}},
		{"a basic value", "Basic dXNlcjpwYXNzd29yZA==", []string{"dXNlcjpw"}},
		{"a bearer value after a no-break space", "Bearer\u00a0xyz98765", []string{"xyz98765"}},
		{"a bearer value after an em space", "Bearer\u2003xyz98765", []string{"xyz98765"}},
		{"a basic value after a no-break space", "Basic\u00a0dXNlcjpwYXNzd29yZA==", []string{"dXNlcjpw"}},
		{"a basic value of 12 characters with padding", "Basic dXNlcjpwYQ==", []string{"dXNlcjpw"}},
		{"a basic value of 16 characters with a digit", "Basic dXNlcjpwYXNz12 ok", []string{"dXNlcjpw"}},
		{"a basic value of exactly 12 characters with a digit", "Basic abcdefghijk1 ok", []string{"abcdefghijk1"}},
		{"a bearer value of 8 characters with a digit", "Bearer abcdefg1 ok", []string{"abcdefg1"}},
		{"a bearer value of letters", "bearer abcdefghijklmnopqrstuvwxyz", []string{"abcdefgh"}},
		{"an authorization header with a no-break space", "Authorization:\u00a0Bearer\u00a0abcdef", []string{"abcdef"}},
		{"an authorization header with a known scheme", "authorization: basic secret", []string{"secret"}},
		{"an authorization header with a long word", "authorization: abcdefghijklmnopqrstuvwxyz", []string{"abcdefgh"}},
		{"a PEM block", "key -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdefgh\n-----END RSA PRIVATE KEY----- after", []string{"MIIEow", "abcdefgh"}},
		{"a PEM block with no end", "key -----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg\nrest", []string{"MIIEvg", "rest"}},
		{"an address with a password", "see https://user:hunter2@example.com/x", []string{"hunter2"}},
	} {
		got := OneLine(tc.in, 1000)
		for _, part := range tc.gone {
			if strings.Contains(got, part) {
				t.Errorf("%s: %q has %q", tc.name, got, part)
			}
		}
		if !strings.Contains(got, "[removed]") || strings.ContainsFunc(got, LineStopped) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
}

// TestProseThatNamesACredentialSchemeStaysUnchanged: a text that only uses a word such as
// basic, bearer or authorization, or a constant with a token prefix in capitals, has no
// credential, and OneLine leaves it as it is.
func TestProseThatNamesACredentialSchemeStaysUnchanged(t *testing.T) {
	for _, in := range []string{
		"Basic authentication using username and password is not supported",
		"the basic permissions of the App",
		"Authorization: required for this request",
		"authorization is needed",
		"HIGHS_AND_LOWS_FLAG",
		"the bearer of this notice",
		"Basic HTTP is not enough",
		"Basic HTTP/1.1 is used",
		"Bearer 2024 release notes",
		"Basic 2024 pricing",
		"Basic Auth/OAuth2 tokens",
		"Basic account/v2 settings",
		"Basic auth-2024",
		"Basic OAuth2 flows",
		"Basic abcdefghij1 is short",
		"Bearer abcdef1 is short",
		"Bearer 2 minutes ago",
		"Bearer tokens are refused",
	} {
		if got := OneLine(in, 1000); got != in {
			t.Errorf("%q became %q", in, got)
		}
	}
}

// TestALongTextIsCutBeforeTheCredentialsAreFoundWithoutLeavingAPrefix: a text of megabytes
// is read to 64 KiB; a token that starts before that cut and ends after it leaves no
// prefix, and the work takes a fraction of a second.
func TestALongTextIsCutBeforeTheCredentialsAreFoundWithoutLeavingAPrefix(t *testing.T) {
	const token = "ghs_AbCdEfGh1234567890AbCdEfGh1234567890"
	for _, start := range []int{65500, 65530, 65533, 65535, 65536 - len("ghs_Ab")} {
		got := OneLine(strings.Repeat("\n", start)+token+strings.Repeat("x ", 1000), 1000)
		if strings.Contains(got, "ghs") || strings.Contains(got, "AbCd") {
			t.Errorf("start %d: %q", start, got)
		}
	}
	long := strings.Repeat("word ghs_AbCdEfGh1234567890 ", 1000000)
	began := time.Now()
	if got := OneLine(long, 1000); strings.Contains(got, "AbCd") || time.Since(began) > 2*time.Second {
		t.Errorf("%d characters in %v", len(long), time.Since(began))
	}
	if got := OneLine("é"+strings.Repeat("y", 70000), 1000); !utf8.ValidString(got) || len(got) != 1000+1 {
		t.Errorf("%d bytes", len(got))
	}
}

// TestAnUnreadableAnswerOfACallIsUnreadable: GitHub's answers to the installation lookup
// that are no JSON, or have no id or login, are [ErrUnreadableAnswer], as is a failure to
// reach GitHub [ErrTransport].
func TestAnUnreadableAnswerOfACallIsUnreadable(t *testing.T) {
	for _, body := range []string{`<html>Unicorn</html>`, `{"id":0}`, `{"id":42,"account":{"login":"bad name"}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, _, err := Client{API: srv.URL}.RepositoryInstallation(context.Background(), appID, key(t), Repository{Owner: "acme", Name: "widgets"})
		srv.Close()
		if !errors.Is(err, ErrUnreadableAnswer) || errors.Is(err, ErrTransport) || EndedRefusal(err).Reason != ReasonRefused {
			t.Errorf("%s: %v", body, err)
		}
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	api := srv.URL
	srv.Close()
	_, _, err := Client{API: api}.RepositoryInstallation(context.Background(), appID, key(t), Repository{Owner: "acme", Name: "widgets"})
	if !errors.Is(err, ErrTransport) || errors.Is(err, ErrUnreadableAnswer) || EndedRefusal(err).Reason != ReasonUnreachable {
		t.Errorf("%v", err)
	}
}

// TestAnAnswerCutDuringItsBodyIsUnreachableAndACompleteOneThatIsNoJSONIsForgeRefused:
// GitHub answers the installation lookup and the mint with the right status and starts
// the body, but the connection closes before it ends, or stays silent until the client's
// timeout. Each ends as [ReasonUnreachable] and wraps [ErrTransport]. A body that is
// complete but no JSON ends as [ReasonRefused].
func TestAnAnswerCutDuringItsBodyIsUnreachableAndACompleteOneThatIsNoJSONIsForgeRefused(t *testing.T) {
	repos, _ := ParseRepositories("acme/widgets")
	lookup := func(c Client) error {
		_, _, err := c.RepositoryInstallation(context.Background(), appID, key(t), Repository{Owner: "acme", Name: "widgets"})
		return err
	}
	mint := func(c Client) error {
		_, err := c.MintInstallationToken(context.Background(), Request{AppID: appID, Key: key(t), InstallationID: 7, Repositories: repos, Permissions: map[string]string{"pull_requests": "write"}})
		return err
	}
	for _, tc := range []struct {
		name string
		// body writes the answer to the call under test, its status and body.
		body   func(w http.ResponseWriter, r *http.Request)
		reason string
		cut    bool
	}{
		{"a body that ends early", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":4`))
		}, ReasonUnreachable, true},
		{"a body that stops until the timeout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":4`))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}, ReasonUnreachable, true},
		{"a complete body that is no JSON", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html>Unicorn</html>`))
		}, ReasonRefused, false},
	} {
		for _, call := range []struct {
			name string
			run  func(Client) error
			// status is the status the call under test wants.
			status int
			// path is the path of its request that the body is cut for.
			path string
		}{
			{"the lookup", lookup, http.StatusOK, "/repos/acme/widgets/installation"},
			{"the mint", mint, http.StatusCreated, "/app/installations/7/access_tokens"},
		} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/app/installations/7" && r.Method == http.MethodGet:
					w.Write([]byte(`{"account":{"login":"acme"}}`))
				case r.URL.Path == call.path:
					tc.body(&statusWriter{ResponseWriter: w, status: call.status}, r)
				default:
					http.NotFound(w, r)
				}
			}))
			c := Client{API: srv.URL, HTTP: &http.Client{Timeout: 300 * time.Millisecond}}
			err := call.run(c)
			srv.Close()
			ended := EndedRefusal(err)
			if err == nil || errors.Is(err, ErrTransport) != tc.cut || errors.Is(err, ErrUnreadableAnswer) == tc.cut || ended.Reason != tc.reason {
				t.Errorf("%s, %s: %v, %s", tc.name, call.name, err, ended.Reason)
			}
			if tc.cut && !strings.Contains(err.Error(), "the connection failed while GitHub's answer was read") {
				t.Errorf("%s, %s: %v", tc.name, call.name, err)
			}
		}
	}
}

// statusWriter writes status where the handler writes 200.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(int) { w.ResponseWriter.WriteHeader(w.status) }
func (w *statusWriter) Flush()          { w.ResponseWriter.(http.Flusher).Flush() }

// TestAnAnswerCutDuringItsBodyOfAPagedReadIsATransportFailure: GitHub answers 200 to a
// read of a page of the pull requests with a Content-Length that its body does not reach,
// so the connection closes before the body ends. The read is [ErrTransport], and never an
// unreadable answer.
func TestAnAnswerCutDuringItsBodyOfAPagedReadIsATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"number":4`))
	}))
	defer srv.Close()
	var out any
	_, err := Client{API: srv.URL}.get(context.Background(), (&fakeClock{}).pacer(), false, "reading", "/a", fakeToken, &out)
	if !errors.Is(err, ErrTransport) || errors.Is(err, ErrUnreadableAnswer) || EndedRefusal(err).Reason != ReasonUnreachable ||
		!strings.Contains(err.Error(), "the connection failed while GitHub's answer was read") {
		t.Errorf("%v", err)
	}
}

// TestARedirectOnTheInstallationLookupSaysTheRepositoryMovedOnlyFor301And308: the lookup
// of the repository's installation is [ErrNotInstalled] for a 404 and for any redirect,
// and also [ErrRepositoryMoved], with GitHub's status and message, for a 301 or 308.
func TestARedirectOnTheInstallationLookupSaysTheRepositoryMovedOnlyFor301And308(t *testing.T) {
	for _, tc := range []struct {
		status int
		moved  bool
	}{{301, true}, {308, true}, {302, false}, {307, false}, {404, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://api.github.com/repositories/1/installation")
			w.WriteHeader(tc.status)
			w.Write([]byte(`{"message":"Moved"}`))
		}))
		_, _, err := Client{API: srv.URL}.RepositoryInstallation(context.Background(), appID, key(t), Repository{Owner: "acme", Name: "widgets"})
		srv.Close()
		status, _ := AnswerOf(Scrubbed(err))
		if !errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrRepositoryMoved) != tc.moved || (status == tc.status) != tc.moved {
			t.Errorf("%d: %v, status %d", tc.status, err, status)
		}
	}
}

// TestAMovedPullRequestRepositoryIsTargetGoneWithTheMovedFix: GitHub's 301 and 308 to a
// request of a change request are [ReasonTargetGone] with [FixMoved], with the answer's
// status and message in the detail, and never [ReasonNotPermitted].
func TestAMovedPullRequestRepositoryIsTargetGoneWithTheMovedFix(t *testing.T) {
	for _, status := range []int{301, 308} {
		a := &apiReply{status: status, body: []byte(`{"message":"Moved Permanently"}`)}
		err := submitFailed(a, "listing the pull requests", false)
		var refused *SubmitRefused
		if !errors.As(err, &refused) || refused.Reason != ReasonTargetGone || refused.Fix != FixMoved || refused.Status != status {
			t.Errorf("%d: %v", status, err)
		}
	}
}
