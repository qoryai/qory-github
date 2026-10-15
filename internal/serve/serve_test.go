package serve

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/qory-github/internal/store"
)

const (
	secret = "a-webhook-secret-that-must-not-leak"
	guid1  = "72d3162e-cc78-11e3-81ab-4c9367dc0958"
	guid2  = "8a1e6b40-0f6c-11ef-9d3a-0242ac120002"
	guid3  = "9b2f7c51-1a7d-11ef-8e4b-0242ac120003"
	body1  = `{"action":"opened","installation":{"id":42},"issue":{"title":"a body that must not be logged"}}`
)

// syncBuffer is a log a test reads while the worker writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sign(body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// post sends a delivery to h, signed with sig unless sig is empty.
func post(h http.Handler, event, guid, body, sig string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, WebhookPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if event != "" {
		r.Header.Set("X-GitHub-Event", event)
	}
	if guid != "" {
		r.Header.Set("X-GitHub-Delivery", guid)
	}
	if sig != "" {
		r.Header.Set("X-Hub-Signature-256", sig)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func pending(t *testing.T, st *store.Store) []store.Delivery {
	t.Helper()
	p, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestASignedDeliveryIsKeptAndAccepted(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	notified := 0
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: slog.New(slog.NewJSONHandler(&log, nil)), Stored: func() { notified++ }}
	w := post(rc.Mux(), "issues", guid1, body1, sign(body1))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	d, err := st.Lookup(guid1)
	if err != nil || d.Event != "issues" || d.Action != "opened" || d.InstallationID != 42 || d.State != store.Pending {
		t.Fatalf("%+v %v", d, err)
	}
	if full, _ := st.Load(d.Seq); string(full.Body) != body1 {
		t.Errorf("the body kept is %q", full.Body)
	}
	if notified != 1 {
		t.Errorf("notified %d times", notified)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(log.String()), &line); err != nil || line["event"] != "issues" || line["action"] != "opened" || line["guid"] != guid1 || line["outcome"] != "accepted" {
		t.Errorf("the line %s: %v", log.String(), err)
	}
	if strings.Contains(log.String(), "must not") {
		t.Errorf("the log carries the body or the secret: %s", log.String())
	}
}

func TestADeliveryWithoutTheSignatureIsRefusedAndNothingIsKept(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: slog.New(slog.NewJSONHandler(&log, nil))}
	other := hmac.New(sha256.New, []byte("another secret"))
	other.Write([]byte(body1))
	for name, sig := range map[string]string{
		"missing":              "",
		"another secret's":     "sha256=" + hex.EncodeToString(other.Sum(nil)),
		"another body's":       sign(body1 + " "),
		"sha1":                 "sha1=" + strings.Repeat("0", 40),
		"no prefix":            strings.TrimPrefix(sign(body1), "sha256="),
		"short":                sign(body1)[:70],
		"not hex":              "sha256=" + strings.Repeat("z", 64),
		"upper case prefix":    "SHA256=" + strings.TrimPrefix(sign(body1), "sha256="),
		"with a trailing byte": sign(body1) + "0",
	} {
		if w := post(rc.Mux(), "issues", guid1, body1, sig); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	// A body that is not JSON is never parsed without its signature: it is refused 401,
	// not 400.
	if w := post(rc.Mux(), "issues", guid1, "not json", sign(body1)); w.Code != http.StatusUnauthorized {
		t.Errorf("not JSON, unsigned: status %d", w.Code)
	}
	if p := pending(t, st); len(p) != 0 {
		t.Errorf("kept %+v", p)
	}
	if _, err := st.Lookup(guid1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the GUID is known: %v", err)
	}
	if strings.Contains(log.String(), "must not") {
		t.Errorf("the log carries the body or the secret: %s", log.String())
	}
}

func TestADeliveryLargerThanTheCapIsRefused(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st}
	large := `{"x":"` + strings.Repeat("a", MaxBody) + `"}`
	if w := post(rc.Mux(), "issues", guid1, large, sign(large)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d", w.Code)
	}
	// A body without a length is cut at the cap as it is read.
	r := httptest.NewRequest(http.MethodPost, WebhookPath, io.MultiReader(strings.NewReader(large)))
	r.ContentLength = -1
	r.Header.Set("X-GitHub-Event", "issues")
	r.Header.Set("X-GitHub-Delivery", guid2)
	r.Header.Set("X-Hub-Signature-256", sign(large))
	w := httptest.NewRecorder()
	rc.Mux().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("without a length: status %d", w.Code)
	}
	if p := pending(t, st); len(p) != 0 {
		t.Errorf("kept %+v", p)
	}
	// One at the cap is taken.
	at := `{"x":"` + strings.Repeat("a", MaxBody-8) + `"}`
	if w := post(rc.Mux(), "issues", guid3, at, sign(at)); w.Code != http.StatusAccepted {
		t.Errorf("at the cap: status %d", w.Code)
	}
}

func TestADeliveryWithoutItsHeadersOrJSONIsRefused(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st}
	for name, tc := range map[string]struct{ event, guid, body string }{
		"no event":        {"", guid1, body1},
		"no GUID":         {"issues", "", body1},
		"a GUID too long": {"issues", guid1 + "0", body1},
		"not a GUID":      {"issues", "not-a-guid", body1},
		"an odd event":    {"Issues\n", guid1, body1},
		"not JSON":        {"issues", guid1, "payload=%7B%7D"},
		"a JSON array":    {"issues", guid1, "[]"},
	} {
		if w := post(rc.Mux(), tc.event, tc.guid, tc.body, sign(tc.body)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	if p := pending(t, st); len(p) != 0 {
		t.Errorf("kept %+v", p)
	}
	mux := rc.Mux()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, WebhookPath, http.StatusMethodNotAllowed},
		{http.MethodPut, WebhookPath, http.StatusMethodNotAllowed},
		{http.MethodPost, "/", http.StatusNotFound},
		{http.MethodPost, "/github/webhook/x", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(body1)))
		if w.Code != tc.want {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}

// harness is a receiver and a worker on one store.
type harness struct {
	st     *store.Store
	worker *Worker
	mux    http.Handler
	log    *syncBuffer
}

func newHarness(t *testing.T, dir string, hs *Handlers, attempts int) *harness {
	t.Helper()
	st := openStore(t, dir)
	log := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(log, nil))
	w := &Worker{Store: st, Handlers: hs, Log: logger, Attempts: attempts, Backoff: func(int) time.Duration { return time.Millisecond }}
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: logger, Stored: w.Notify}
	w.Start()
	t.Cleanup(func() { w.Stop(5 * time.Second) })
	return &harness{st: st, worker: w, mux: rc.Mux(), log: log}
}

// eventually waits for cond, five seconds at most.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: timed out", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func state(st *store.Store, guid string) store.State {
	d, err := st.Lookup(guid)
	if err != nil {
		return ""
	}
	return d.State
}

func TestARepeatGUIDIsAnswered200AndHandledOnce(t *testing.T) {
	var calls atomic.Int32
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error {
		calls.Add(1)
		if string(d.Body) != body1 || d.GUID != guid1 || d.InstallationID != 42 {
			t.Errorf("handed %+v", d)
		}
		return nil
	})
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 0)
	if w := post(h.mux, "issues", guid1, body1, sign(body1)); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	eventually(t, "done", func() bool { return state(h.st, guid1) == store.Done })
	if w := post(h.mux, "issues", strings.ToUpper(guid1), body1, sign(body1)); w.Code != http.StatusOK {
		t.Fatalf("a repeat: status %d", w.Code)
	}
	h.worker.Notify()
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("handled %d times", n)
	}
	eventually(t, "logged", func() bool { return strings.Contains(h.log.String(), `"outcome":"done"`) })
	if !strings.Contains(h.log.String(), `"outcome":"duplicate"`) || !strings.Contains(h.log.String(), `"outcome":"done"`) {
		t.Errorf("the log: %s", h.log.String())
	}
}

func TestTheAnswerDoesNotWaitForTheHandler(t *testing.T) {
	release := make(chan struct{})
	hs := &Handlers{}
	hs.HandleFunc("issues", func(ctx context.Context, _ Delivery) error {
		<-release
		return nil
	})
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 0)
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+WebhookPath, strings.NewReader(body1))
	req.Header.Set("X-GitHub-Event", "issues")
	req.Header.Set("X-GitHub-Delivery", guid1)
	req.Header.Set("X-Hub-Signature-256", sign(body1))
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the answer waits for the handler: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status %d", resp.StatusCode)
	}
	if s := state(h.st, guid1); s != store.Pending {
		t.Errorf("the delivery is %s while its handler runs", s)
	}
	close(release)
	eventually(t, "done", func() bool { return state(h.st, guid1) == store.Done })
}

func TestAHandlersErrorIsTriedAgainThenFails(t *testing.T) {
	var calls atomic.Int32
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error {
		calls.Add(1)
		return errors.New("GitHub answered 502")
	})
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 3)
	post(h.mux, "issues", guid1, body1, sign(body1))
	eventually(t, "failed", func() bool { return state(h.st, guid1) == store.Failed })
	eventually(t, "logged", func() bool { return strings.Contains(h.log.String(), `"outcome":"failed"`) })
	if n := calls.Load(); n != 3 {
		t.Errorf("called %d times, want 3", n)
	}
	if !strings.Contains(h.log.String(), `"outcome":"failed"`) || !strings.Contains(h.log.String(), `"attempts":3`) {
		t.Errorf("the log: %s", h.log.String())
	}
	if strings.Contains(h.log.String(), "must not") {
		t.Errorf("the log carries the body: %s", h.log.String())
	}
}

func TestAHandlersPanicFailsItsDeliveryAlone(t *testing.T) {
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error { panic("a bug") })
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 2)
	post(h.mux, "issues", guid1, body1, sign(body1))
	eventually(t, "failed", func() bool { return state(h.st, guid1) == store.Failed })
}

func TestAnEventWithoutAHandlerIsDone(t *testing.T) {
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), &Handlers{}, 0)
	post(h.mux, "star", guid1, `{"action":"created"}`, sign(`{"action":"created"}`))
	eventually(t, "done", func() bool { return state(h.st, guid1) == store.Done })
	eventually(t, "logged", func() bool { return strings.Contains(h.log.String(), `"outcome":"unhandled"`) })
}

func TestOneInstallationsDeliveriesAreHandledInOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	first := make(chan struct{})
	release := make(chan struct{})
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error {
		if d.GUID == guid1 {
			close(first)
			<-release
		}
		mu.Lock()
		order = append(order, d.GUID)
		mu.Unlock()
		return nil
	})
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 0)
	other := `{"action":"opened","installation":{"id":43}}`
	post(h.mux, "issues", guid1, body1, sign(body1))
	<-first
	post(h.mux, "issues", guid2, body1, sign(body1))
	post(h.mux, "issues", guid3, other, sign(other))
	// The other installation's delivery is handled while the first one waits.
	eventually(t, "the other installation", func() bool { return state(h.st, guid3) == store.Done })
	if s := state(h.st, guid2); s != store.Pending {
		t.Errorf("the second delivery of the installation is %s before the first is done", s)
	}
	close(release)
	eventually(t, "done", func() bool { return state(h.st, guid2) == store.Done })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, " ") != guid3+" "+guid1+" "+guid2 {
		t.Errorf("order %v", order)
	}
}

func TestPendingDeliveriesAreHandledAfterARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(dir, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rc := &Receiver{Secret: []byte(secret), Store: st}
	post(rc.Mux(), "issues", guid1, body1, sign(body1))
	post(rc.Mux(), "issues", guid2, body1, sign(body1))
	st.Close()

	var handled sync.Map
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error {
		handled.Store(d.GUID, true)
		return nil
	})
	h := newHarness(t, dir, hs, 0)
	eventually(t, "both done", func() bool { return state(h.st, guid1) == store.Done && state(h.st, guid2) == store.Done })
	for _, g := range []string{guid1, guid2} {
		if _, ok := handled.Load(g); !ok {
			t.Errorf("%s was not handed to its handler", g)
		}
	}
}

func TestAStopLeavesAnInterruptedDeliveryPending(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st := openStore(t, dir)
	started := make(chan struct{})
	hs := &Handlers{}
	hs.HandleFunc("issues", func(ctx context.Context, _ Delivery) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	w := &Worker{Store: st, Handlers: hs}
	rc := &Receiver{Secret: []byte(secret), Store: st, Stored: w.Notify}
	w.Start()
	post(rc.Mux(), "issues", guid1, body1, sign(body1))
	<-started
	begun := time.Now()
	w.Stop(50 * time.Millisecond)
	if d := time.Since(begun); d > 2*time.Second {
		t.Errorf("the stop took %s", d)
	}
	if s := state(st, guid1); s != store.Pending {
		t.Errorf("the interrupted delivery is %s", s)
	}
}

func TestRegisteringAnEventTwicePanics(t *testing.T) {
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error { return nil })
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	hs.HandleFunc("issues", func(context.Context, Delivery) error { return nil })
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, mode)
}

func TestReadSettings(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "serve.json")
	writeFile(t, file, `{"app_id":123456,"private_key_file":"/k.pem","webhook_secret_file":"/s","listen":"127.0.0.1:8080","state_dir":"/var/lib/qory-github"}`, 0o644)
	s, err := ReadSettings(file)
	want := Settings{AppID: "123456", PrivateKeyFile: "/k.pem", WebhookSecretFile: "/s", Listen: "127.0.0.1:8080", StateDir: "/var/lib/qory-github"}
	if err != nil || s != want {
		t.Fatalf("%+v %v", s, err)
	}
	base := map[string]any{"app_id": "Iv1.abc", "private_key_file": "/k.pem", "webhook_secret_file": "/s", "listen": ":8080", "state_dir": "/d"}
	for name, tc := range map[string]struct {
		change map[string]any
		want   string
	}{
		"an unknown field":    {map[string]any{"api_url": "https://api.github.com"}, `unknown fields "api_url"`},
		"an odd unknown name": {map[string]any{"a\nb": 1}, `unknown fields "a\nb"`},
		"a missing field":     {map[string]any{"state_dir": nil}, "/state_dir: is not a string that is not empty"},
		"an empty path":       {map[string]any{"private_key_file": ""}, "/private_key_file: is not a string"},
		"a bad App id":        {map[string]any{"app_id": "secret value"}, "/app_id: is not an App's id"},
		"a negative App id":   {map[string]any{"app_id": -1}, "/app_id: is neither"},
		"no port":             {map[string]any{"listen": "127.0.0.1"}, "/listen: is not an address and a port"},
		"a port too large":    {map[string]any{"listen": ":65536"}, "/listen: has a port"},
	} {
		doc := map[string]any{}
		for k, v := range base {
			doc[k] = v
		}
		for k, v := range tc.change {
			doc[k] = v
		}
		b, _ := json.Marshal(doc)
		_, err := parseSettings(b)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "secret value") {
			t.Errorf("%s: the error says a value: %v", name, err)
		}
	}
	delete(base, "listen")
	b, _ := json.Marshal(base)
	if _, err := parseSettings(b); err == nil || !strings.Contains(err.Error(), "missing fields listen") {
		t.Errorf("err %v", err)
	}
	for doc, want := range map[string]string{
		"":                  "are empty",
		"[]":                "not one JSON object",
		"null":              "not one JSON object",
		`{"app_id":` + "x}": "breaks at byte",
		"{} {}":             "something other than white space",
	} {
		if _, err := parseSettings([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", doc, err, want)
		}
	}
}

func TestAWebhookSecretFileOthersMayReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o610, 0o620, 0o601} {
		open := filepath.Join(dir, "open")
		os.Remove(open)
		writeFile(t, open, secret, mode)
		_, err := ReadWebhookSecret(open)
		if err == nil || !strings.Contains(err.Error(), "the webhook secret file") || !strings.Contains(err.Error(), "group or others have permissions on it; make it 0600") {
			t.Errorf("%s: err %v", mode, err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("the error says the secret: %v", err)
		}
	}
	own := filepath.Join(dir, "own")
	writeFile(t, own, secret+"\n", 0o600)
	if b, err := ReadWebhookSecret(own); err != nil || string(b) != secret {
		t.Errorf("%q %v", b, err)
	}
	empty := filepath.Join(dir, "empty")
	writeFile(t, empty, "\n", 0o600)
	if _, err := ReadWebhookSecret(empty); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("err %v", err)
	}
	large := filepath.Join(dir, "large")
	writeFile(t, large, strings.Repeat("a", maxSecretFile+1), 0o600)
	if _, err := ReadWebhookSecret(large); err == nil || !strings.Contains(err.Error(), "larger than a webhook secret") {
		t.Errorf("err %v", err)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(own, link)
	if _, err := ReadWebhookSecret(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("err %v", err)
	}
}

func TestRunServesUntilItsContextIsDone(t *testing.T) {
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "app.pem")
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), 0o600)
	secretFile := filepath.Join(dir, "secret")
	writeFile(t, secretFile, secret, 0o600)
	s := Settings{AppID: "1", PrivateKeyFile: keyFile, WebhookSecretFile: secretFile, Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state")}

	handled := make(chan string, 1)
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error { handled <- d.GUID; return nil })
	var log syncBuffer
	addr := make(chan net.Addr, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, s, Options{Handlers: hs, Log: slog.New(slog.NewJSONHandler(&log, nil)), Listening: func(a net.Addr) { addr <- a }})
	}()
	var url string
	select {
	case a := <-addr:
		url = fmt.Sprintf("http://%s%s", a, WebhookPath)
	case err := <-done:
		t.Fatalf("Run: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body1))
	req.Header.Set("X-GitHub-Event", "issues")
	req.Header.Set("X-GitHub-Delivery", guid1)
	req.Header.Set("X-Hub-Signature-256", sign(body1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status %d", resp.StatusCode)
	}
	select {
	case g := <-handled:
		if g != guid1 {
			t.Errorf("handled %s", g)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not handled")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run does not return")
	}
	if strings.Contains(log.String(), "must not") || strings.Contains(log.String(), "PRIVATE KEY") {
		t.Errorf("the log carries the body, the secret or the key: %s", log.String())
	}
	// The store is closed: it opens again.
	openStore(t, s.StateDir)
}

func TestRunRefusesALooseSecretBeforeItListens(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret")
	writeFile(t, secretFile, secret, 0o644)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(dir, "app.pem")
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), 0o600)
	listened := false
	err := Run(context.Background(), Settings{AppID: "1", PrivateKeyFile: keyFile, WebhookSecretFile: secretFile, Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state")}, Options{Listening: func(net.Addr) { listened = true }})
	if err == nil || !strings.Contains(err.Error(), "group or others") || listened {
		t.Errorf("err %v, listened %v", err, listened)
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Errorf("the state directory is made: %v", err)
	}
}
