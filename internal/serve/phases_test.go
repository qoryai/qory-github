package serve

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
		if string(b) != healthAppCheck+"\n" {
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

// noApp is s without the App.
func noApp(s Settings) Settings {
	s.AppID, s.AppSlug, s.ClientID, s.PrivateKeyFile, s.WebhookSecretFile, s.ClientSecretFile = "", "", "", "", "", ""
	return s
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

// TestRunWithoutAnAppServesTheSetup runs serve whose settings give no App and whose
// state directory keeps none, with public_address true and false: it declares
// setup_url, answers 503 but for /health and the setup, reads no feed; an instance
// admin sets the App up through it, against the fake GitHub; then, without a
// restart, it serves: the webhook takes a delivery signed with the kept secret, the
// connect page answers, the setup refuses a pass, and it declares again without
// setup_url, after the declaration with it. A restart serves at once with the kept App.
func TestRunWithoutAnAppServesTheSetup(t *testing.T) {
	for _, public := range []bool{true, false} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		gh := newSetupGitHub(t)
		s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
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
			if rq.method == http.MethodGet && without < 0 {
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
		kept, err := loadApp(s.StateDir)
		if err != nil {
			t.Fatal(err)
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

		// A restart serves with the kept App at once, once it is checked with GitHub, and
		// declares without setup_url.
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
		if n := gh.checks(); n != 1 {
			t.Errorf("public %v: the restart checked the App %d times", public, n)
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
	gh := newSetupGitHub(t)
	s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
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

// TestAKeptAppWithAnInactiveWebhookDeclaresPulling pins that a kept App whose webhook
// was created inactive makes serve declare that it does not send changes, with the
// line that says how to change that, though public_address is true.
func TestAKeptAppWithAnInactiveWebhookDeclaresPulling(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
	k := testKeptApp()
	k.WebhookActive = false
	os.Mkdir(s.StateDir, 0o700)
	if err := keepApp(s.StateDir, k, []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	_, log, _ := runWith(t, s, Options{feedSleep: shortSleep})
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	got, _ := json.Marshal(apiary.sent(routeAdapter)[0].body["sync"])
	if !strings.Contains(string(got), `"sends_changes":false`) || apiary.sent(routeAdapter)[0].body["setup_url"] != nil {
		t.Errorf("declared %s", apiary.sent(routeAdapter)[0].raw)
	}
	want := `"msg":"the kept App's webhook was created inactive, so serve declares that it learns of changes by pulling; to change that, set the App's webhook URL to https://qory-github.example.com/v1/events and turn the webhook on at ` + s.APIURL + `/organizations/acme/settings/apps/qory-acme"`
	if !strings.Contains(log.String(), want) {
		t.Errorf("the log: %s", log.String())
	}
}

// TestAnInactiveKeptAppWithoutAPublicAddressSaysPullingOnce pins that a kept App whose
// webhook was created inactive, with public_address false, makes serve declare that
// it pulls with the line public_address false gives, and not the line that says how to
// turn the webhook on, which GitHub could not reach.
func TestAnInactiveKeptAppWithoutAPublicAddressSaysPullingOnce(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
	s.PublicAddress = new(bool)
	k := testKeptApp()
	k.WebhookActive = false
	os.Mkdir(s.StateDir, 0o700)
	if err := keepApp(s.StateDir, k, []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
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

// TestAnUnconfirmedWebhookSecretIsSetAgainAtStart pins that a kept App whose webhook
// secret GitHub did not confirm has it set again at the start, which, once GitHub
// confirms it, app.json records; when GitHub does not, a line says so.
func TestAnUnconfirmedWebhookSecretIsSetAgainAtStart(t *testing.T) {
	for _, confirms := range []bool{true, false} {
		dir := t.TempDir()
		access := newKey(t)
		apiary := newFakeApiary(t, access)
		gh := newSetupGitHub(t)
		if !confirms {
			gh.hookStatus = http.StatusBadGateway
		}
		s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
		s.APIURL = gh.srv.URL
		k := testKeptApp()
		k.WebhookSecretConfirmed = false
		os.Mkdir(s.StateDir, 0o700)
		if err := keepApp(s.StateDir, k, []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
			t.Fatal(err)
		}
		_, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
		eventually(t, "set again", func() bool { return len(gh.patched()) > 0 })
		if p := gh.patched(); p[0] != setupHookSecret {
			t.Errorf("set %v", p)
		}
		const line = `"msg":"GitHub did not confirm the App's webhook secret; serve sets it again at its next start"`
		if confirms {
			// app.json is read alone, as loadApp would remove a rewrite under way.
			eventually(t, "recorded", func() bool {
				b, _ := os.ReadFile(filepath.Join(s.StateDir, appFile))
				k, err := parseKeptApp(b)
				return err == nil && k.WebhookSecretConfirmed
			})
		} else {
			eventually(t, "said", func() bool { return strings.Contains(log.String(), line) })
		}
		stop()
		if a, err := loadApp(s.StateDir); err != nil || a.confirmed != confirms {
			t.Errorf("confirms %v: %+v %v", confirms, a, err)
		}
		noSetupLeak(t, log.String())
	}
}

// TestTheSettingsAppWinsOverTheKeptOne pins that the settings' App is used when the
// state directory keeps one too, with the line that says so, and that no setup_url is
// declared.
func TestTheSettingsAppWinsOverTheKeptOne(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	os.Mkdir(s.StateDir, 0o700)
	if err := keepApp(s.StateDir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	handled := make(chan string, 1)
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error { handled <- d.GUID; return nil })
	addr, log, _ := runWith(t, s, Options{Handlers: hs, feedSleep: shortSleep})
	if !strings.Contains(log.String(), `"msg":"the settings give the App, so the App kept in the state directory is not used"`) {
		t.Errorf("the log: %s", log.String())
	}
	// The settings' webhook secret signs what is taken.
	resp, _ := fetch(t, nil, http.MethodPost, addr, WebhookPath, strings.NewReader(body1), http.Header{"X-Github-Event": {"issues"}, "X-Github-Delivery": {guid1}, "X-Hub-Signature-256": {sign(body1)}})
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("the delivery answered %d", resp.StatusCode)
	}
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	if b := apiary.sent(routeAdapter)[0].body; b["setup_url"] != nil {
		t.Errorf("declared %v", b)
	}
}

// TestPublicAddressFalseDeclaresPullingWithAnyApp pins that public_address false
// makes serve declare that it does not send changes with an App whose webhook is
// active, as the settings' App is, with the line that says so, and that it is true
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

// TestAStartResolvesTheKeptAppsFiles pins the start with what a setup left in the
// state directory: files of one that did not finish are removed, with the line, and
// serve waits for a setup; a kept App whose file is missing stops it before it serves.
func TestAStartResolvesTheKeptAppsFiles(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := noApp(settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server)))
	os.Mkdir(s.StateDir, 0o700)
	writeFile(t, filepath.Join(s.StateDir, appTemp), "{", 0o600)
	writeFile(t, filepath.Join(s.StateDir, appKeyFile), appKeyPEM(), 0o600)
	addr, log, stop := runWith(t, s, Options{feedSleep: shortSleep})
	checkPhase(t, addr, "waiting for the GitHub App's setup", "")
	if !strings.Contains(log.String(), `"msg":"a setup that did not finish left files in the state directory, which are removed: delete the App it created on GitHub"`) {
		t.Errorf("the log: %s", log.String())
	}
	stop()
	for _, name := range []string{appTemp, appKeyFile} {
		if _, err := os.Lstat(filepath.Join(s.StateDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is left: %v", name, err)
		}
	}
	if err := keepApp(s.StateDir, testKeptApp(), []byte(appKeyPEM()), []byte(setupHookSecret), []byte(setupClientSecret)); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(s.StateDir, appClientFile))
	listened := false
	err := Run(context.Background(), s, Options{ProgramVersion: testVersion, Listening: func(net.Addr) { listened = true }})
	if err == nil || err.Error() != "the App file app.json names app-client-secret in the state directory, which is missing or does not hold what app.json names" || listened {
		t.Errorf("err %v, listened %v", err, listened)
	}
}

// TestServeUnderAPublicURLWithAPathAnswersAtTheListenersRoot runs serve with a
// public_url that has a path, behind a proxy that strips it: the webhook deliveries are
// taken at /v1/events and the connect page answers at /v1/connect, as the listener
// receives them, while the connect page's redirect and the connect_url serve declares
// have the path. A request that still has the path is answered 404.
func TestServeUnderAPublicURLWithAPathAnswersAtTheListenersRoot(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	s.PublicURL = "https://qory-github.example.com/adapters/github"
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error { return nil })
	addr, _, _ := runWith(t, s, Options{Handlers: hs, feedSleep: shortSleep})
	delivery := http.Header{"X-Github-Event": {"issues"}, "X-Github-Delivery": {guid1}, "X-Hub-Signature-256": {sign(body1)}}
	if resp, _ := fetch(t, nil, http.MethodPost, addr, "/adapters/github"+WebhookPath, strings.NewReader(body1), delivery); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the delivery with the path answered %d", resp.StatusCode)
	}
	if resp, _ := fetch(t, nil, http.MethodPost, addr, "/v1/events", strings.NewReader(body1), delivery); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the delivery answered %d", resp.StatusCode)
	}
	if resp, _ := fetch(t, nil, http.MethodGet, addr, "/v1/connect?state=x", nil, nil); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/adapters/github/v1/connect/refused" {
		t.Errorf("the connect page answered %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := fetch(t, nil, http.MethodGet, addr, "/adapters/github/v1/connect?state=x", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the connect page with the path answered %d", resp.StatusCode)
	}
	eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > 0 })
	if b := apiary.sent(routeAdapter)[0].body; b["connect_url"] != "https://qory-github.example.com/adapters/github/v1/connect" {
		t.Errorf("declared %v", b)
	}
}

// TestHealthAndSetupAreAtTheListenersRoot pins that, with a public_url that has a path,
// which a proxy in front of serve strips, /health is answered at the listener's root on
// any host and the setup at /setup, and that the setup's cookie and redirect have the
// path a browser sees. A request that still has the path is not answered as either.
func TestHealthAndSetupAreAtTheListenersRoot(t *testing.T) {
	setup := &appSetup{PublicURL: "https://qory-github.example.com/base", Store: openStore(t, filepath.Join(t.TempDir(), "state")), creds: &credentials{e: enrolment{pin: pinOf(newKey(t)), adapterID: testAdapterID}}}
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
	if ck := (&http.Response{Header: w.Header()}).Cookies(); len(ck) != 1 || ck[0].Path != "/base/setup" || w.Header().Get("Location") != "/base/setup/refused" {
		t.Errorf("the page cookie %v, the redirect %q", ck, w.Header().Get("Location"))
	}
}
