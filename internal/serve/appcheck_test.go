package serve

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// appAnswer is one answer of GitHub's to GET /app: a status and a body; status -1
// answers what is not HTTP and closes the connection.
type appAnswer struct {
	status int
	body   string
}

// appGitHub is GitHub's API as serve's check of the App at start reaches it: it answers
// GET /app with each of answers in turn, and then as [answerApp] does, and counts the
// checks. onAsk, when set, is called with each check before it is answered.
type appGitHub struct {
	srv   *httptest.Server
	onAsk func()

	mu      sync.Mutex
	answers []appAnswer
	asked   int
}

func newAppGitHub(t *testing.T, answers ...appAnswer) *appGitHub {
	t.Helper()
	g := &appGitHub{answers: answers}
	g.srv = httptest.NewServer(g)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *appGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/app" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	g.mu.Lock()
	g.asked++
	var a *appAnswer
	if len(g.answers) > 0 {
		a = &g.answers[0]
		g.answers = g.answers[1:]
	}
	g.mu.Unlock()
	if g.onAsk != nil {
		g.onAsk()
	}
	switch {
	case a == nil:
		answerApp(w, r)
	case a.status == -1:
		c, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			io.WriteString(c, "not HTTP\r\n\r\n")
			c.Close()
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		w.Write([]byte(a.body))
	}
}

func (g *appGitHub) checks() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.asked
}

// checkSettings are settings for a start whose GitHub is gh, with the App a stored in
// the fake Qory Apiary, which it returns, or [testApp] when a is nil.
func checkSettings(t *testing.T, gh *appGitHub, a *app) (Settings, *fakeApiary) {
	t.Helper()
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.APIURL = gh.srv.URL
	if a == nil {
		a = testApp()
	}
	apiary.storeApp(a)
	return s, apiary
}

// refusedStart runs serve with s until it returns, which it must before the serving
// phase, and returns its log and its error.
func refusedStart(t *testing.T, s Settings) (string, error) {
	t.Helper()
	var log syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), s, Options{ProgramVersion: testVersion, feedSleep: shortSleep, Log: slog.New(slog.NewJSONHandler(&log, nil))})
	}()
	select {
	case err := <-done:
		if strings.Contains(log.String(), lineServing) {
			t.Error("serve served before it refused to start")
		}
		return log.String(), err
	case <-time.After(10 * time.Second):
		t.Fatalf("Run does not return: %s", log.String())
	}
	return "", nil
}

// The lines of the App's check.
const (
	lineRetried = `"level":"WARN","msg":"checking the App with GitHub failed, and is tried again"`
	lineServing = `"msg":"serving"`
)

// TestTheAppWithItsSlugServes pins that the App Qory Apiary delivers, whose id and
// slug GitHub answers, serves after one check, with no line of it and no upload.
func TestTheAppWithItsSlugServes(t *testing.T) {
	gh := newAppGitHub(t)
	s, apiary := checkSettings(t, gh, nil)
	_, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
	stop()
	if n := gh.checks(); n != 1 || !strings.Contains(log.String(), lineServing) || strings.Contains(log.String(), "checking the App") || len(apiary.sent(routeSecrets)) != 0 {
		t.Errorf("checked %d times, %d uploads; the log: %s", n, len(apiary.sent(routeSecrets)), log.String())
	}
}

// TestAnAnswerWithNoSlugIsRefused pins that an answer for the App's id that names no
// slug, or what is not one, refuses the start, with no echo of the answer.
func TestAnAnswerWithNoSlugIsRefused(t *testing.T) {
	for _, body := range []string{`{"id":1}`, `{"id":1,"slug":null}`, `{"id":1,"slug":7}`, `{"id":1,"slug":""}`, `{"id":1,"slug":"no slug at all"}`, `{"id":1,"slug":"-qory"}`} {
		gh := newAppGitHub(t, appAnswer{200, body})
		s, apiary := checkSettings(t, gh, nil)
		_, err := refusedStart(t, s)
		const want = "checking the App with GitHub: GitHub's answer has no slug for the App with app_id 1"
		if err == nil || err.Error() != want || len(apiary.sent(routeSecrets)) != 0 {
			t.Errorf("%s: err %v", body, err)
		}
	}
}

// TestTheAppIsRefusedForAnotherID pins that an App whose id GitHub answers is another
// refuses the start, whatever the slug.
func TestTheAppIsRefusedForAnotherID(t *testing.T) {
	for _, body := range []string{`{"id":5,"slug":"qory-acme"}`, `{"id":5,"slug":"qory-other"}`, `{"id":5}`} {
		gh := newAppGitHub(t, appAnswer{200, body})
		s, _ := checkSettings(t, gh, setupApp())
		log, err := refusedStart(t, s)
		const want = "Qory Apiary stores the App with app_id 777001, and GitHub's answer is for another App"
		if err == nil || err.Error() != want || strings.Contains(log, lineServing) {
			t.Errorf("%s: err %v; the log: %s", body, err, log)
		}
	}
}

// TestAnAnswerWithNoIDIsRefused pins that an answer that names no id, or one that is
// not a positive integer, refuses the start.
func TestAnAnswerWithNoIDIsRefused(t *testing.T) {
	for _, body := range []string{`{"slug":"qory-acme"}`, `{"id":null,"slug":"qory-acme"}`, `{"id":"777001","slug":"qory-acme"}`, `{"id":0,"slug":"qory-acme"}`, `{"id":-777001,"slug":"qory-acme"}`, `{"id":777001.5,"slug":"qory-acme"}`, `{"id":7.77001e5,"slug":"qory-acme"}`, `not JSON`, `[]`} {
		gh := newAppGitHub(t, appAnswer{200, body})
		s, _ := checkSettings(t, gh, setupApp())
		_, err := refusedStart(t, s)
		const want = "checking the App with GitHub: GitHub's answer names no id for the App with app_id 777001"
		if err == nil || err.Error() != want {
			t.Errorf("%s: err %v", body, err)
		}
	}
}

// TestTheAppKeepsItsNewSlug pins that an App whose id GitHub answers with a new slug
// is uploaded to Qory Apiary with that alone changed, the line that says so once, and
// serve serves with the new slug: the App's page the line of an inactive webhook links
// to is the new slug's.
func TestTheAppKeepsItsNewSlug(t *testing.T) {
	a := setupApp()
	a.webhookActive = false
	gh := newAppGitHub(t, appAnswer{200, `{"id":777001,"slug":"qory-acme-2"}`})
	s, apiary := checkSettings(t, gh, a)
	_, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
	stop()
	const line = `"level":"INFO","msg":"GitHub's answer has the slug qory-acme-2 for the App with app_id 777001 now, so serve uses qory-acme-2 in place of qory-acme"`
	if strings.Count(log.String(), line) != 1 || !strings.Contains(log.String(), "/organizations/acme/settings/apps/qory-acme-2\"") || !strings.Contains(log.String(), lineServing) {
		t.Errorf("the log: %s", log.String())
	}
	ups := apiary.uploaded()
	if len(ups) != 1 {
		t.Fatalf("%d uploads", len(ups))
	}
	got, err := appOf(ups[0])
	want := a.with(func(c *app) { c.slug = "qory-acme-2" })
	if err != nil || got.slug != want.slug || got.numericID != want.numericID || got.webhookActive || string(got.pem) != string(want.pem) ||
		string(got.webhookSecret) != setupHookSecret || string(got.clientSecret) != setupClientSecret || got.clientID != setupClientID {
		t.Errorf("uploaded %+v %v", got, err)
	}
}

// TestANewSlugThatCannotBeStoredServes pins that serve serves with the new slug when
// Qory Apiary refuses its upload, with a line that says the next start stores it.
func TestANewSlugThatCannotBeStoredServes(t *testing.T) {
	gh := newAppGitHub(t, appAnswer{200, `{"id":777001,"slug":"qory-acme-2"}`})
	s, apiary := checkSettings(t, gh, setupApp())
	apiary.refuse = func(route string, _ int) (int, string) {
		if route == routeSecrets {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	_, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
	stop()
	const line = `"msg":"storing the App's new slug in Qory Apiary failed; serve stores it again at its next start","slug":"qory-acme-2"`
	if !strings.Contains(log.String(), line) || !strings.Contains(log.String(), lineServing) || apiary.stored()[secretApp] == "" ||
		strings.Contains(apiary.stored()[secretApp], "qory-acme-2") {
		t.Errorf("the log: %s", log.String())
	}
}

// TestA401RefusesTheStart pins that GitHub's 401 to the App's token refuses the start
// at once.
func TestA401RefusesTheStart(t *testing.T) {
	const want = "checking the App with GitHub: GitHub does not take the App's token, made from app_id and the App's private key: reading the App: GitHub answered 401: Bad credentials"
	gh := newAppGitHub(t, appAnswer{401, `{"message":"Bad credentials"}`})
	s, _ := checkSettings(t, gh, nil)
	log, err := refusedStart(t, s)
	if err == nil || err.Error() != want || gh.checks() != 1 || strings.Contains(log, lineRetried) {
		t.Errorf("err %v, checked %d times; the log: %s", err, gh.checks(), log)
	}
}

// TestAFailedCheckIsTriedAgainWhileHealthAnswers pins that a check GitHub does not
// answer 200 or 401 is asked again after a wait, with one line for the failures of a
// minute, while /health answers 200 with the App check's line, and that serve serves
// once GitHub answers.
func TestAFailedCheckIsTriedAgainWhileHealthAnswers(t *testing.T) {
	gh := newAppGitHub(t, appAnswer{503, `{"message":"Service Unavailable"}`})
	s, _ := checkSettings(t, gh, nil)
	release := make(chan struct{})
	var once sync.Once
	sleep := func(ctx context.Context, d time.Duration) error {
		first := false
		once.Do(func() { first = true })
		if first {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
		return shortSleep(ctx, d)
	}
	addr, log, _ := runListening(t, s, Options{feedSleep: sleep})
	eventually(t, "the first failure's line", func() bool { return strings.Contains(log.String(), lineRetried) })
	// serve listens while it waits to ask again.
	if resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, nil); resp.StatusCode != http.StatusOK || body != "waiting for GitHub to answer the App check\n" {
		t.Errorf("/health answered %d %q while the check waits", resp.StatusCode, body)
	}
	if strings.Count(log.String(), lineRetried) != 1 || !strings.Contains(log.String(), `"error":"reading the App: GitHub answered 503: Service Unavailable"`) || strings.Contains(log.String(), lineServing) {
		t.Errorf("the log while the check waits: %s", log.String())
	}
	close(release)
	eventually(t, "serving", func() bool {
		resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, nil)
		return resp.StatusCode == http.StatusOK && body == "serving\n"
	})
	if n := gh.checks(); n != 2 || strings.Count(log.String(), lineRetried) != 1 {
		t.Errorf("checked %d times; the log: %s", n, log.String())
	}
}

// TestAnEnrolledStartAnswersWhileGitHubDoesNotAnswerTheCheck pins that a start with
// the enrolment kept in the state directory or given by the settings listens while
// GitHub has not answered GET /app: /health answers 200 with the App check's line, and
// every other request 503 with the App check's 503 line.
func TestAnEnrolledStartAnswersWhileGitHubDoesNotAnswerTheCheck(t *testing.T) {
	for _, keptEnrolment := range []bool{false, true} {
		gh := newAppGitHub(t)
		// GitHub's answer to GET /app is held until the test ends; this cleanup runs
		// after serve's stop and before GitHub's server closes.
		block := make(chan struct{})
		gh.onAsk = func() { <-block }
		t.Cleanup(func() { close(block) })
		var s Settings
		if keptEnrolment {
			e := newEnrolEnv(t)
			e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
			if _, err := e.enrol(); err != nil {
				t.Fatal(err)
			}
			e.apiary.storeTestApp()
			s = e.settings
			s.APIURL = gh.srv.URL
		} else {
			s, _ = checkSettings(t, gh, nil)
		}
		addr, log, _ := runListening(t, s, Options{feedSleep: shortSleep})
		eventually(t, "the check asked", func() bool { return gh.checks() == 1 })
		checkPhase(t, addr, "waiting for GitHub to answer the App check",
			"This adapter is starting. It is waiting for GitHub to answer a check of its GitHub App. Try again in a few minutes. If this message stays, the adapter's log shows GitHub's error.")
		if strings.Contains(log.String(), lineServing) {
			t.Errorf("enrolment kept %v: the log: %s", keptEnrolment, log.String())
		}
	}
}

// TestEachOtherAnswerIsTriedAgain pins that a redirect, a 403, a 404, a 429, a 5xx and
// an answer that is not HTTP are each asked again after a wait that doubles from
// two seconds to a minute, the failures of a minute with one line, until GitHub
// answers.
func TestEachOtherAnswerIsTriedAgain(t *testing.T) {
	gh := newAppGitHub(t,
		appAnswer{301, `{}`}, appAnswer{403, `{"message":"rate limited"}`}, appAnswer{404, `{"message":"Not Found"}`},
		appAnswer{429, `{}`}, appAnswer{502, `{}`}, appAnswer{-1, ""},
	)
	s, _ := checkSettings(t, gh, setupApp())
	// The waits are recorded in order: the check's come before the change feed
	// reader's, which starts once serve serves.
	var mu sync.Mutex
	var waits []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return shortSleep(ctx, d)
	}
	_, log, stop := runWith(t, s, Options{feedSleep: sleep})
	eventually(t, "serving", func() bool { return strings.Contains(log.String(), lineServing) })
	stop()
	if n := gh.checks(); n != 7 || strings.Count(log.String(), lineRetried) != 1 {
		t.Errorf("checked %d times; the log: %s", n, log.String())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute}
	if len(waits) < len(want) || !slices.Equal(waits[:len(want)], want) {
		t.Errorf("waited %v, want %v first", waits, want)
	}
}

// TestAStopWhileTheCheckWaitsStops pins that serve stops while its check waits to ask
// GitHub again, with no error.
func TestAStopWhileTheCheckWaitsStops(t *testing.T) {
	gh := newAppGitHub(t, appAnswer{503, `{}`}, appAnswer{503, `{}`}, appAnswer{503, `{}`})
	s, _ := checkSettings(t, gh, nil)
	var log syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, s, Options{ProgramVersion: testVersion, Log: slog.New(slog.NewJSONHandler(&log, nil)), Listening: func(net.Addr) { close(listening) },
			feedSleep: func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }})
	}()
	<-listening
	cancel()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(log.String(), `"msg":"stopped"`) || strings.Contains(log.String(), lineServing) {
			t.Errorf("err %v; the log: %s", err, log.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run does not stop")
	}
}
