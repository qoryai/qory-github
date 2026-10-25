package serve

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github/internal/store"
)

// noRedirect is a client that follows no redirect, so a test reads each answer.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}

// fetch sends method target to serve at addr, with j's cookies when j is set, and
// returns the status and the body, keeping the cookies the answer sets in j.
func fetch(t *testing.T, j jar, method, addr, target string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+target, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if h := header.Get("Host"); h != "" {
		req.Host = h
	}
	if j != nil {
		req.Header.Set("Cookie", j.header())
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if j != nil {
		j.take(resp.Header)
	}
	return resp, string(b)
}

// runWith runs serve with s and opts until the test ends or the returned function
// stops it, and returns its address and its log once serve listens and /health answers
// a line other than the App check's.
func runWith(t *testing.T, s Settings, opts Options) (string, *syncBuffer, func()) {
	t.Helper()
	addr, log, stop := runListening(t, s, opts)
	pastAppCheck(t, addr)
	return addr, log, stop
}

// pastAppCheck waits until serve at addr answers /health with a line other than the
// App check's. Each request is sent on a connection that is closed after the answer,
// so a test with a bound of one connection keeps its slot.
func pastAppCheck(t *testing.T, addr string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := c.Get("http://" + addr + healthPath)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != healthAppCheck+"\n" && string(b) != healthLoading+"\n" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health answers %q after 10 s", b)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// runListening runs serve with s and opts as [runWith] does, and returns once serve
// listens, in whichever phase.
func runListening(t *testing.T, s Settings, opts Options) (string, *syncBuffer, func()) {
	t.Helper()
	log := &syncBuffer{}
	opts.Log = slog.New(slog.NewJSONHandler(log, nil))
	opts.ProgramVersion = testVersion
	addr := make(chan net.Addr, 1)
	opts.Listening = func(a net.Addr) { addr <- a }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, opts) }()
	var once sync.Once
	returned := false
	stop := func() {
		once.Do(func() {
			cancel()
			if returned {
				return
			}
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Error("Run does not stop")
			}
		})
	}
	t.Cleanup(stop)
	select {
	case a := <-addr:
		return a.String(), log, stop
	case err := <-done:
		returned = true
		t.Fatalf("Run returned before it listened: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("Run does not listen: %s", log.String())
	}
	return "", nil, nil
}

// checkPhase checks /health's answer and the 503 of every other request but the
// setup's, which sends no referrer.
func checkPhase(t *testing.T, addr, health, unavailable string) {
	t.Helper()
	resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, http.Header{"Host": {"anything.example.com"}})
	if resp.StatusCode != http.StatusOK || body != health+"\n" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("/health answered %d %q", resp.StatusCode, body)
	}
	if unavailable == "" {
		return
	}
	for _, rq := range []struct{ method, target string }{{http.MethodPost, WebhookPath}, {http.MethodGet, "/v1/connect?state=x"}, {http.MethodGet, "/other"}, {http.MethodGet, "/base/health"}} {
		resp, body := fetch(t, nil, rq.method, addr, rq.target, strings.NewReader(body1), nil)
		if resp.StatusCode != http.StatusServiceUnavailable || body != unavailable+"\n" || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
			resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s answered %d %q", rq.method, rq.target, resp.StatusCode, body)
		}
	}
}

// TestRunListensWhileItEnrols pins that serve listens from the moment its store is
// open, at a first start that waits for its code: /health answers 200 and every other
// request, the setup's among them, 503, until it is enrolled.
func TestRunListensWhileItEnrols(t *testing.T) {
	e := newEnrolEnv(t)
	opts := e.opts()
	opts.enrolWait = func(ctx context.Context, _ time.Duration) error { return wait(ctx, 10*time.Millisecond) }
	addr, log, _ := runWith(t, e.settings, opts)
	const enrolling = "This adapter is not enrolled in Qory Apiary yet."
	checkPhase(t, addr, "enrolling in Qory Apiary", enrolling)
	// A setup pass that comes while serve enrolls stays in the browser's address: the
	// 503 sends no referrer.
	if resp, body := fetch(t, nil, http.MethodGet, addr, "/setup?state=x", nil, nil); resp.StatusCode != http.StatusServiceUnavailable || body != enrolling+"\n" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("/setup answered %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if !strings.Contains(log.String(), `"msg":"listening"`) {
		t.Errorf("the log: %s", log.String())
	}
	e.writeCode(enrolCode(codeCore, e.apiary.server) + "\n")
	eventually(t, "serving", func() bool {
		resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, nil)
		return resp.StatusCode == 200 && body == "serving\n"
	})
}

// TestRunWithoutAnAppServesTheSetup runs serve for which Qory Apiary stores no App,
// with public_address true and false: it declares setup_url, answers 503 but for
// /health and the setup, reads no feed; an instance admin sets the App up through it,
// against the fake GitHub, which stores the App in Qory Apiary; then, without a
// restart, it serves: the webhook takes a delivery signed with the stored secret, the
// connect page answers, the setup refuses a pass, and it declares again without
// setup_url, after the declaration with it. A restart serves at once with the App it
// reads from Qory Apiary alone. The state directory contains the access key,
// enrolment.json and the store alone, and no file contains a value of the App.
func TestRunWithoutAnAppServesTheSetup(t *testing.T) {
	for _, public := range []bool{true, false} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		apiary.noApp()
		gh := newSetupGitHub(t)
		s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
		s.APIURL = gh.srv.URL
		s.PublicAddress = &public
		handled := make(chan string, 1)
		hs := &Handlers{}
		hs.HandleFunc("issues", func(_ context.Context, d Delivery) error { handled <- d.GUID; return nil })
		opts := Options{Handlers: hs, feedSleep: shortSleep, refusalEvery: time.Nanosecond}
		addr, log, stop := runWith(t, s, opts)
		checkPhase(t, addr, "waiting for the GitHub App's setup", "This adapter's GitHub App is not set up yet. An instance admin sets it up with Set up on the adapter's page in Qory Apiary.")
		eventually(t, "declared with setup_url", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
		first := apiary.sent(routeAdapter)[0].body
		firstSync, _ := json.Marshal(first["sync"])
		wantSync := `{"default_interval":3600,"minimum_interval":900,"sends_changes":` + map[bool]string{true: "true", false: "false"}[public] + `}`
		if first["setup_url"] != "https://qory-github.example.com/setup" || string(firstSync) != wantSync {
			t.Errorf("public %v: declared %v", public, first)
		}
		if n := len(apiary.sent("GET " + routeChanges)); n != 0 {
			t.Errorf("public %v: the feed was read %d times without an App", public, n)
		}
		const waiting = `"msg":"waiting for the GitHub App's setup: an instance admin presses Set up on the adapter's page in Qory Apiary"`
		const pulling = `"msg":"public_address is false: GitHub sends no webhooks, and serve learns of changes on GitHub by pulling"`
		if !strings.Contains(log.String(), waiting) || strings.Contains(log.String(), pulling) == public || strings.Contains(log.String(), `"msg":"serving"`) {
			t.Errorf("public %v: the log %s", public, log.String())
		}

		// The setup, through serve's listener.
		pass, resp, body := setUpThrough(t, apiary, addr)
		if resp.StatusCode != http.StatusOK || strings.Contains(body, "GitHub sends this App no webhooks") == public {
			t.Fatalf("public %v: the end answered %d %s", public, resp.StatusCode, body)
		}

		// Serving, without a restart.
		eventually(t, "serving", func() bool {
			resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, nil)
			return resp.StatusCode == 200 && body == "serving\n"
		})
		eventually(t, "declared again", func() bool {
			sent := apiary.sent(routeAdapter)
			return len(sent) > 1 && sent[len(sent)-1].body["setup_url"] == nil
		})
		eventually(t, "the feed read", func() bool { return len(apiary.sent("GET "+routeChanges)) > 0 })
		apiary.mu.Lock()
		without := -1
		for i, rq := range apiary.requests {
			if rq.method == http.MethodGet && strings.HasPrefix(rq.target, routeChanges) && without < 0 {
				t.Errorf("public %v: the feed was read before the declaration without setup_url", public)
			}
			if rq.target != routeAdapter {
				continue
			}
			_, has := rq.body["setup_url"]
			if !has && without < 0 {
				without = i
			}
			if has && without >= 0 {
				t.Errorf("public %v: a declaration with setup_url follows the one without", public)
			}
			if !has {
				got, _ := json.Marshal(rq.body["sync"])
				if string(got) != wantSync {
					t.Errorf("public %v: declared %s", public, got)
				}
			}
		}
		apiary.mu.Unlock()
		kept := storedApp(t, apiary)
		if kept.numericID != setupAppID || len(kept.webhookSecret) != 64 || string(kept.clientSecret) != setupClientSecret || len(apiary.uploaded()) != 1 {
			t.Errorf("public %v: Qory Apiary stores %v after %d uploads", public, kept, len(apiary.uploaded()))
		}
		mac := hmac.New(sha256.New, kept.webhookSecret)
		mac.Write([]byte(body1))
		resp, _ = fetch(t, nil, http.MethodPost, addr, WebhookPath, strings.NewReader(body1), http.Header{
			"X-Github-Event": {"issues"}, "X-Github-Delivery": {guid1}, "X-Hub-Signature-256": {"sha256=" + hex.EncodeToString(mac.Sum(nil))}, "Content-Type": {"application/json"},
		})
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("public %v: the delivery answered %d", public, resp.StatusCode)
		}
		select {
		case <-handled:
		case <-time.After(5 * time.Second):
			t.Errorf("public %v: the delivery is not handled", public)
		}
		if resp, _ := fetch(t, nil, http.MethodGet, addr, "/v1/connect", nil, nil); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/v1/connect/refused" {
			t.Errorf("public %v: the connect page answered %d", public, resp.StatusCode)
		}
		j := jar{}
		fetch(t, j, http.MethodGet, addr, "/setup?state="+signSetupPass(apiary.server, setupPayload(testAdapterID, newNonce(), time.Now().Add(time.Minute))), nil, nil)
		if resp, body := fetch(t, j, http.MethodGet, addr, "/setup/refused", nil, nil); resp.StatusCode != http.StatusConflict || body != "This adapter's GitHub App is set up already.\n" {
			t.Errorf("public %v: a pass in serving answered %d %q", public, resp.StatusCode, body)
		}
		if !strings.Contains(log.String(), `"msg":"serving"`) {
			t.Errorf("public %v: the log %s", public, log.String())
		}
		noSetupLeak(t, log.String(), pass, string(kept.webhookSecret), access.Secret())
		stop()
		// The App the setup keeps is GitHub's answer of seconds before: it is not checked
		// with GitHub again until the next start.
		if n := gh.checks(); n != 0 {
			t.Errorf("public %v: the App was checked %d times after the setup", public, n)
		}

		onlyAllowedFiles(t, s.StateDir)

		// A restart serves with the App it reads from Qory Apiary at once, once it is
		// checked with GitHub, and declares without setup_url.
		n := len(apiary.sent(routeAdapter))
		addr, log, _ = runWith(t, s, opts)
		checkPhase(t, addr, "serving", "")
		eventually(t, "declared at the restart", func() bool { return len(apiary.sent(routeAdapter)) > n })
		if last := apiary.sent(routeAdapter)[n]; last.body["setup_url"] != nil {
			t.Errorf("public %v: the restart declared %v", public, last.body)
		}
		if strings.Contains(log.String(), waiting) {
			t.Errorf("public %v: the restart waits for a setup: %s", public, log.String())
		}
		if n := gh.checks(); n != 1 || len(apiary.uploaded()) != 1 {
			t.Errorf("public %v: the restart checked the App %d times, and uploaded %d times in all", public, n, len(apiary.uploaded()))
		}
		onlyAllowedFiles(t, s.StateDir)
	}
}

// storedApp is the App the fake Qory Apiary stores.
func storedApp(t *testing.T, f *fakeApiary) *app {
	t.Helper()
	f.mu.Lock()
	p := contracts.AdapterSecretsPlaintext{Version: contracts.Version, Secrets: slices.Clone(f.secrets)}
	f.mu.Unlock()
	a, err := appOf(p)
	if err != nil || a == nil {
		t.Fatalf("Qory Apiary stores no App: %v", err)
	}
	return a
}

// onlyAllowedFiles checks that the state directory dir contains the access key,
// enrolment.json, the store and nothing else, and that no file in it contains a value
// of the App.
func onlyAllowedFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{accessKeyFile, enrolmentFile, store.FileName}
	for _, e := range entries {
		if !slices.Contains(allowed, e.Name()) {
			t.Errorf("the state directory contains %s", e.Name())
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for _, bad := range []string{setupHookSecret, setupClientSecret, secret, clientSecret, "PRIVATE KEY"} {
			if bytes.Contains(b, []byte(bad)) {
				t.Errorf("%s contains a value of the App", e.Name())
			}
		}
	}
}

// setUpThrough sets the App up through serve's listener at addr, with a pass the fake
// Qory Apiary signs, the account acme, and the fake GitHub's code, and returns the
// pass and the answer of the last step.
func setUpThrough(t *testing.T, apiary *fakeApiary, addr string) (string, *http.Response, string) {
	t.Helper()
	pass := signSetupPass(apiary.server, setupPayload(testAdapterID, newNonce(), time.Now().Add(10*time.Minute)))
	j := jar{}
	resp, _ := fetch(t, j, http.MethodGet, addr, "/setup?state="+pass, nil, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup/continue" || j[setupCookie] == "" {
		t.Fatalf("the pass answered %d %v", resp.StatusCode, resp.Header)
	}
	_, body := fetch(t, j, http.MethodGet, addr, "/setup/continue", nil, nil)
	token := tokenField.FindStringSubmatch(body)
	if token == nil {
		t.Fatalf("the form %s", body)
	}
	_, body = fetch(t, j, http.MethodPost, addr, "/setup/continue", strings.NewReader(url.Values{"token": {token[1]}, "account": {"acme"}, "install": {installPrivate}}.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	action := formAction.FindStringSubmatch(body)
	if action == nil {
		t.Fatalf("the manifest page %s", body)
	}
	resp, body = fetch(t, j, http.MethodGet, addr, "/setup/created?code="+setupCode+"&state="+stateOf(t, strings.ReplaceAll(action[1], "&amp;", "&")), nil, nil)
	return pass, resp, body
}

// firstWithout is the index among the fake's requests of the first start-up body
// without setup_url, and that of the first upload of secrets the fake accepted, each
// -1 when there is none.
func firstWithout(f *fakeApiary) (declared, uploaded int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	declared, uploaded = -1, -1
	accepted := 0
	for i, rq := range f.requests {
		if rq.method != http.MethodPost {
			continue
		}
		if _, has := rq.body["setup_url"]; rq.target == routeAdapter && !has && declared < 0 {
			declared = i
		}
		if rq.target == routeSecrets {
			accepted++
			if accepted > f.refusedUploads && uploaded < 0 {
				uploaded = i
			}
		}
	}
	return declared, uploaded
}

// TestTheSetupDeclaresWithoutSetupURLOnlyAfterTheUpload pins the order of a first
// setup: the start-up body without setup_url never comes before Qory Apiary accepts
// the upload of the App, so Qory Apiary never shows the adapter set up with no
// values. While the setup tries the upload again, and after every try failed, serve
// sends no start-up body without setup_url.
func TestTheSetupDeclaresWithoutSetupURLOnlyAfterTheUpload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refused int
		stored  bool
	}{{"stored on the fourth try", 3, true}, {"never stored", 1 << 30, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			access := newKey(t)
			apiary := newFakeApiary(t, access)
			apiary.noApp()
			apiary.refusedUploads = tc.refused
			apiary.refuse = func(route string, n int) (int, string) {
				if route == routeSecrets && n <= tc.refused {
					return http.StatusServiceUnavailable, ""
				}
				return 0, ""
			}
			gh := newSetupGitHub(t)
			s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
			s.APIURL = gh.srv.URL
			waits := 0
			var mu sync.Mutex
			opts := Options{feedSleep: shortSleep, refusalEvery: time.Nanosecond, uploadWait: func(ctx context.Context, _ time.Duration) error {
				mu.Lock()
				defer mu.Unlock()
				// Six waits stand for the whole of upload_retry_seconds.
				if waits++; waits > 6 {
					return context.DeadlineExceeded
				}
				return ctx.Err()
			}}
			addr, log, stop := runWith(t, s, opts)
			defer stop()
			eventually(t, "declared with setup_url", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
			// The first upload fails, so the browser goes to the status page.
			if _, resp, body := setUpThrough(t, apiary, addr); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup/status" {
				t.Fatalf("the end answered %d %v %s", resp.StatusCode, resp.Header, body)
			}
			if tc.stored {
				eventually(t, "declared without setup_url", func() bool { d, _ := firstWithout(apiary); return d >= 0 })
				if d, u := firstWithout(apiary); u < 0 || d < u {
					t.Errorf("the start-up body without setup_url is request %d, the accepted upload %d", d, u)
				}
				return
			}
			eventually(t, "the setup failed for good", func() bool {
				return strings.Contains(log.String(), "storing the GitHub App in Qory Apiary failed for good")
			})
			time.Sleep(200 * time.Millisecond)
			if d, u := firstWithout(apiary); d >= 0 || u >= 0 || len(apiary.uploaded()) != 0 {
				t.Errorf("the start-up body without setup_url is request %d, the accepted upload %d", d, u)
			}
		})
	}
}

// TestTheDeclarationWithSetupURLIsAnsweredFirst pins the order at the setup's end. Qory
// Apiary holds the declaration with setup_url under way open across the setup's
// commit, and answers it once serve's stop of it starts to wait, or else when a
// declaration without setup_url comes, which is then too soon. A declarer serve does
// not stop, or a change feed's reader that starts before that stop waits, fails it at
// each run. A stop that does not wait for the declaration's end fails it when the
// change feed's reader starts before the declarer has read Qory Apiary's answer, which
// takes a round trip: most runs, not each.
func TestTheDeclarationWithSetupURLIsAnsweredFirst(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	var (
		mu       sync.Mutex
		answered bool
		fed      bool
		ended    <-chan struct{}
		faults   []string
	)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	answer := func() { once.Do(func() { close(release) }) }
	apiary.refuse = func(route string, n int) (int, string) {
		if route != routeAdapter {
			return 0, ""
		}
		if _, has := apiary.sent(routeAdapter)[n-1].body["setup_url"]; has {
			if n == 1 {
				close(held)
				<-release
				mu.Lock()
				answered = true
				mu.Unlock()
			}
			return 0, ""
		}
		mu.Lock()
		if !answered {
			faults = append(faults, "a declaration without setup_url came while the one with it was open")
		}
		mu.Unlock()
		answer()
		return 0, ""
	}
	apiary.noApp()
	gh := newSetupGitHub(t)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.APIURL = gh.srv.URL
	opts := Options{feedSleep: shortSleep}
	opts.declarerWaits = func(done <-chan struct{}) {
		mu.Lock()
		ended = done
		if fed {
			faults = append(faults, "the change feed's reader started before the declaration with setup_url ended")
		}
		mu.Unlock()
		answer()
	}
	opts.feedStarts = func() {
		mu.Lock()
		defer mu.Unlock()
		fed = true
		if ended == nil {
			return
		}
		select {
		case <-ended:
		default:
			faults = append(faults, "the change feed's reader started before the declarer read Qory Apiary's answer")
		}
	}
	addr, _, _ := runWith(t, s, opts)
	<-held
	if _, resp, body := setUpThrough(t, apiary, addr); resp.StatusCode != http.StatusOK {
		t.Fatalf("the end answered %d %s", resp.StatusCode, body)
	}
	eventually(t, "declared without setup_url", func() bool {
		for _, rq := range apiary.sent(routeAdapter) {
			if _, has := rq.body["setup_url"]; !has {
				return true
			}
		}
		return false
	})
	mu.Lock()
	defer mu.Unlock()
	if len(faults) != 0 || !answered {
		t.Errorf("answered %v: %v", answered, faults)
	}
	without := false
	for _, rq := range apiary.sent(routeAdapter) {
		_, has := rq.body["setup_url"]
		if has && without {
			t.Error("a declaration with setup_url follows the one without")
		}
		without = without || !has
	}
}

// TestAnAppWithAnInactiveWebhookDeclaresPulling pins that an App whose webhook was
// created inactive makes serve declare that it does not send changes, with the line
// that says how to change that, though public_address is true.
func TestAnAppWithAnInactiveWebhookDeclaresPulling(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	apiary.storeApp(setupApp().with(func(a *app) { a.webhookActive = false }))
	_, log, _ := runWith(t, s, Options{feedSleep: shortSleep})
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	got, _ := json.Marshal(apiary.sent(routeAdapter)[0].body["sync"])
	if !strings.Contains(string(got), `"sends_changes":false`) || apiary.sent(routeAdapter)[0].body["setup_url"] != nil {
		t.Errorf("declared %s", apiary.sent(routeAdapter)[0].raw)
	}
	want := `"msg":"the App's webhook was created inactive, so serve declares that it learns of changes by pulling; to change that, set the App's webhook URL to https://qory-github.example.com/v1/events and turn the webhook on at ` + s.APIURL + `/organizations/acme/settings/apps/qory-acme"`
	if !strings.Contains(log.String(), want) {
		t.Errorf("the log: %s", log.String())
	}
}

// TestAnInactiveAppWithoutAPublicAddressSaysPullingOnce pins that an App whose webhook
// was created inactive, with public_address false, makes serve declare that it pulls
// with the line public_address false gives, and not the line that says how to turn the
// webhook on, which GitHub could not reach.
func TestAnInactiveAppWithoutAPublicAddressSaysPullingOnce(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.PublicAddress = new(bool)
	apiary.storeApp(setupApp().with(func(a *app) { a.webhookActive = false }))
	_, log, _ := runWith(t, s, Options{feedSleep: shortSleep})
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	got, _ := json.Marshal(apiary.sent(routeAdapter)[0].body["sync"])
	if !strings.Contains(string(got), `"sends_changes":false`) {
		t.Errorf("declared %s", got)
	}
	const pulling = `"msg":"public_address is false: GitHub sends no webhooks, and serve learns of changes on GitHub by pulling"`
	if !strings.Contains(log.String(), pulling) || strings.Contains(log.String(), "created inactive") {
		t.Errorf("the log: %s", log.String())
	}
}

// TestAnUnconfirmedWebhookSecretIsSetAgainAtStart pins that an App whose webhook secret
// GitHub did not confirm has it set again at the start, which, once GitHub confirms it,
// an upload to Qory Apiary records; when GitHub does not, a line says so, and nothing
// is uploaded.
func TestAnUnconfirmedWebhookSecretIsSetAgainAtStart(t *testing.T) {
	for _, confirms := range []bool{true, false} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		gh := newSetupGitHub(t)
		if !confirms {
			gh.hookStatus = http.StatusBadGateway
		}
		s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
		s.APIURL = gh.srv.URL
		apiary.storeApp(setupApp().with(func(a *app) { a.confirmed = false }))
		_, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
		eventually(t, "set again", func() bool { return len(gh.patched()) > 0 })
		if p := gh.patched(); p[0] != setupHookSecret {
			t.Errorf("set %v", p)
		}
		const line = `"msg":"GitHub did not confirm the App's webhook secret; serve sets it again at its next start"`
		if confirms {
			eventually(t, "recorded", func() bool { return len(apiary.uploaded()) == 1 })
		} else {
			eventually(t, "said", func() bool { return strings.Contains(log.String(), line) })
		}
		stop()
		if a := storedApp(t, apiary); a.confirmed != confirms || string(a.webhookSecret) != setupHookSecret || len(apiary.uploaded()) != map[bool]int{true: 1, false: 0}[confirms] {
			t.Errorf("confirms %v: %+v after %d uploads", confirms, a, len(apiary.uploaded()))
		}
		noSetupLeak(t, log.String())
	}
}

// TestPublicAddressFalseDeclaresPullingWithAnyApp pins that public_address false
// makes serve declare that it does not send changes with an App whose webhook is
// active, as the test App's is, with the line that says so, and that it is true
// when public_address is left out.
func TestPublicAddressFalseDeclaresPullingWithAnyApp(t *testing.T) {
	for _, public := range []*bool{nil, new(bool)} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
		s.PublicAddress = public
		_, log, _ := runWith(t, s, Options{feedSleep: shortSleep})
		eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
		got, _ := json.Marshal(apiary.sent(routeAdapter)[0].body["sync"])
		want := `"sends_changes":` + strconv.FormatBool(public == nil)
		if !strings.Contains(string(got), want) {
			t.Errorf("public_address given %v: declared %s", public != nil, got)
		}
		const line = `"msg":"public_address is false: GitHub sends no webhooks, and serve learns of changes on GitHub by pulling"`
		if strings.Contains(log.String(), line) != (public != nil) || strings.Contains(log.String(), "created inactive") {
			t.Errorf("public_address given %v: the log %s", public != nil, log.String())
		}
	}
}

// TestSecretsServeCannotUseRefuseTheStart pins that secrets in Qory Apiary that are not
// the App as serve uploads it stop serve before it serves, with the error that names
// the secret and no value.
func TestSecretsServeCannotUseRefuseTheStart(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	apiary.mu.Lock()
	apiary.secrets = slices.DeleteFunc(slices.Clone(apiary.secrets), func(e contracts.SecretEntry) bool { return e.Name == secretClientSecret })
	apiary.mu.Unlock()
	var log syncBuffer
	err := Run(context.Background(), s, Options{ProgramVersion: testVersion, Log: slog.New(slog.NewJSONHandler(&log, nil))})
	if err == nil || err.Error() != "reading the GitHub App from Qory Apiary: Qory Apiary stores no secret client-secret for the GitHub App" || strings.Contains(log.String(), lineServing) {
		t.Errorf("err %v; the log: %s", err, log.String())
	}
	if strings.Contains(log.String(), secret) || strings.Contains(log.String(), "PRIVATE KEY") {
		t.Error("the log contains a value of the App")
	}
}

// TestReadingTheAppIsTriedAgainWhileHealthAnswers pins that serve listens while it
// cannot read the App from Qory Apiary: /health answers 200 with the reading's line,
// every other request 503, the failures of a minute have one line, and serve serves
// once Qory Apiary answers.
func TestReadingTheAppIsTriedAgainWhileHealthAnswers(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	var mu sync.Mutex
	failing := true
	apiary.refuseGet = func(int) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		if failing {
			return http.StatusServiceUnavailable, `{"error":"unavailable"}`
		}
		return 0, ""
	}
	addr, log, _ := runListening(t, s, Options{feedSleep: func(ctx context.Context, _ time.Duration) error { return wait(ctx, 20*time.Millisecond) }})
	const line = `"level":"WARN","msg":"reading the GitHub App from Qory Apiary failed, and is tried again"`
	eventually(t, "the failure's line", func() bool { return strings.Contains(log.String(), line) })
	checkPhase(t, addr, healthLoading, unavailableLoading)
	eventually(t, "tried again", func() bool { return len(apiary.sent("GET "+routeSecrets)) > 2 })
	mu.Lock()
	failing = false
	mu.Unlock()
	eventually(t, "serving", func() bool {
		resp, body := fetch(t, nil, http.MethodGet, addr, "/health", nil, nil)
		return resp.StatusCode == http.StatusOK && body == "serving\n"
	})
	if strings.Count(log.String(), line) != 1 {
		t.Errorf("the log: %s", log.String())
	}
}

// TestServeAtAHostOnlyPublicURLDeclaresItsAddresses runs serve with public_url the
// adapter's host name: the webhook deliveries are taken at /v1/events, the connect
// page's redirect is /v1/connect/refused, and the connect_url serve declares is the
// origin followed by /v1/connect.
func TestServeAtAHostOnlyPublicURLDeclaresItsAddresses(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.PublicURL = "https://github.example.com"
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error { return nil })
	addr, _, _ := runWith(t, s, Options{Handlers: hs, feedSleep: shortSleep})
	delivery := http.Header{"X-Github-Event": {"issues"}, "X-Github-Delivery": {guid1}, "X-Hub-Signature-256": {sign(body1)}}
	if resp, _ := fetch(t, nil, http.MethodPost, addr, "/v1/events", strings.NewReader(body1), delivery); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the delivery answered %d", resp.StatusCode)
	}
	if resp, _ := fetch(t, nil, http.MethodGet, addr, "/v1/connect?state=x", nil, nil); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/v1/connect/refused" {
		t.Errorf("the connect page answered %d %v", resp.StatusCode, resp.Header)
	}
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	if b := apiary.sent(routeAdapter)[0].body; b["connect_url"] != "https://github.example.com/v1/connect" {
		t.Errorf("declared %v", b)
	}
}

// TestHealthAndSetupAreAtTheRoot pins that /health is answered at the root on any
// host and the setup at /setup, and that the setup's cookie is for /setup and its
// redirect is /setup/refused.
func TestHealthAndSetupAreAtTheRoot(t *testing.T) {
	setup := &appSetup{PublicURL: "https://github.example.com", Store: openStore(t, filepath.Join(t.TempDir(), "state")), creds: &credentials{e: enrolment{pin: pinOf(newKey(t)), adapterID: testAdapterID}}}
	p := &phase{health: healthNoApp, unavailable: unavailableNoApp, setup: setup}
	for target, want := range map[string]int{"/health": 200, "http://other.example.com/health": 200, "/base/health": 503, "/setup?state=x": 303, "/base/setup?state=x": 503, "/setupx": 503} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != want {
			t.Errorf("%s answered %d, want %d", target, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/setup?state=x", nil))
	if ck := (&http.Response{Header: w.Header()}).Cookies(); len(ck) != 1 || ck[0].Path != "/setup" || w.Header().Get("Location") != "/setup/refused" {
		t.Errorf("the page cookie %v, the redirect %q", ck, w.Header().Get("Location"))
	}
}
