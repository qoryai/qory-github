package serve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/qory-github"
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

func TestAnEventWithDigitsIsTaken(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st}
	body := `{"action":"v2_edited","installation":{"id":42}}`
	for i, event := range []string{"projects_v2", "projects_v2_item", "projects_v2_status_update", "a" + strings.Repeat("b", 63)} {
		guid := fmt.Sprintf("72d3162e-cc78-11e3-81ab-4c9367dc%04d", i)
		if w := post(rc.Mux(), event, guid, body, sign(body)); w.Code != http.StatusAccepted {
			t.Errorf("%s: status %d: %s", event, w.Code, w.Body)
		}
		if d, err := st.Lookup(guid); err != nil || d.Event != event || d.Action != "v2_edited" {
			t.Errorf("%s: %+v %v", event, d, err)
		}
	}
}

// rawDelivery is a delivery's request line and headers, its Content-Length length, as
// a sender writes them on a connection.
func rawDelivery(guid string, length int) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: example.com\r\nX-GitHub-Event: issues\r\nX-GitHub-Delivery: %s\r\nX-Hub-Signature-256: %s\r\nContent-Length: %d\r\n\r\n", WebhookPath, guid, sign(body1), length)
}

func held(rc *Receiver) (int64, int64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.held, rc.peak
}

func TestASenderThatSendsNothingHoldsNothing(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	// The budget is one body, its chunk and its joined bytes: a sender that held it by
	// what it claims would leave none.
	rc := &Receiver{Secret: []byte(secret), Store: st, maxBudget: firstChunk + int64(len(body1))}
	srv := httptest.NewServer(rc.Mux())
	defer srv.Close()
	for i := range 5 {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, rawDelivery(fmt.Sprintf("72d3162e-cc78-11e3-81ab-4c9367dc%04d", i), len(body1)))
	}
	time.Sleep(100 * time.Millisecond)
	if h, _ := held(rc); h != 0 {
		t.Errorf("senders that sent nothing hold %d bytes", h)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+WebhookPath, strings.NewReader(body1))
	req.Header.Set("X-GitHub-Event", "issues")
	req.Header.Set("X-GitHub-Delivery", guid1)
	req.Header.Set("X-Hub-Signature-256", sign(body1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("a genuine delivery: status %d", resp.StatusCode)
	}
}

func TestTheBudgetIsNeverExceededNorTakenFromTheLengthClaimed(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st, maxBudget: firstChunk + int64(len(body1))}
	larger := body1 + strings.Repeat(" ", 10)
	if w := post(rc.Mux(), "issues", guid1, larger, sign(larger)); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a body beyond the budget: status %d", w.Code)
	}
	if p := pending(t, st); len(p) != 0 {
		t.Errorf("kept %+v", p)
	}
	// A length claimed far beyond the budget takes nothing from it: the body that
	// arrives is what counts.
	r := httptest.NewRequest(http.MethodPost, WebhookPath, strings.NewReader(body1))
	r.ContentLength = MaxBody
	r.Header.Set("X-GitHub-Event", "issues")
	r.Header.Set("X-GitHub-Delivery", guid2)
	r.Header.Set("X-Hub-Signature-256", sign(body1))
	w := httptest.NewRecorder()
	rc.Mux().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Errorf("a body within the budget, its length claimed larger: status %d", w.Code)
	}
	h, peak := held(rc)
	if h != 0 || peak > rc.maxBudget || peak != firstChunk+int64(len(body1)) {
		t.Errorf("held %d, peak %d, budget %d", h, peak, rc.maxBudget)
	}
}

// oneByte is a body that sends one byte, then waits until release is closed.
type oneByte struct {
	sent    bool
	release chan struct{}
}

func (o *oneByte) Read(p []byte) (int, error) {
	if !o.sent {
		o.sent = true
		p[0] = '{'
		return 1, nil
	}
	<-o.release
	return 0, io.EOF
}

func TestSendersOfOneByteEachHoldOneSmallChunk(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st}
	const senders = 8192
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := range senders {
		r := httptest.NewRequest(http.MethodPost, WebhookPath, &oneByte{release: release})
		r.ContentLength = 1000
		r.Header.Set("X-GitHub-Event", "issues")
		r.Header.Set("X-GitHub-Delivery", fmt.Sprintf("72d3162e-cc78-11e3-81ab-%012x", i))
		r.Header.Set("X-Hub-Signature-256", sign(body1))
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc.Mux().ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	eventually(t, "every sender's byte", func() bool { h, _ := held(rc); return h == senders*firstChunk })
	time.Sleep(50 * time.Millisecond)
	if h, _ := held(rc); h > senders*firstChunk {
		t.Errorf("%d senders of one byte hold %d bytes, more than %d", senders, h, senders*firstChunk)
	}
	close(release)
	wg.Wait()
	if h, _ := held(rc); h != 0 {
		t.Errorf("held %d after", h)
	}
}

func TestChunksGrowToTheirBound(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st}
	body := `{"x":"` + strings.Repeat("a", 200<<10) + `"}`
	if w := post(rc.Mux(), "issues", guid1, body, sign(body)); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	// 1, 2, 4, 8 and 16 KiB, then 32 KiB chunks: the chunks never hold more than the
	// body and one chunk of 32 KiB, and the joined body is held beside them.
	_, peak := held(rc)
	if limit := int64(2*len(body) + progressBytes); peak > limit || peak < int64(2*len(body)) {
		t.Errorf("peak %d, body %d", peak, len(body))
	}
	if d, err := st.Lookup(guid1); err != nil {
		t.Errorf("%+v %v", d, err)
	} else if full, _ := st.Load(d.Seq); string(full.Body) != body {
		t.Error("the body kept is not the body sent")
	}
}

func TestTheBudgetIsHeldUntilTheHandlingIsOver(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st := openStore(t, dir)
	var during int64
	rc := &Receiver{Secret: []byte(secret), Store: st}
	rc.Stored = func() { during, _ = held(rc) }
	post(rc.Mux(), "issues", guid1, body1, sign(body1))
	if h, _ := held(rc); during != int64(len(body1)) || h != 0 {
		t.Errorf("held %d while the delivery was kept, %d after", during, h)
	}
}

func TestASenderThatSendsTooSlowlyIsCut(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	rc := &Receiver{Secret: []byte(secret), Store: st, progress: 300 * time.Millisecond}
	srv := httptest.NewServer(rc.Mux())
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, rawDelivery(guid1, 100000))
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		// 10 bytes each 50 ms is far below 32 KiB in 300 ms.
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := io.WriteString(c, strings.Repeat("a", 10)); err != nil {
				return
			}
		}
	}()
	begun := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout || time.Since(begun) > 2*time.Second {
		t.Errorf("status %d after %s", resp.StatusCode, time.Since(begun))
	}
	if p := pending(t, st); len(p) != 0 {
		t.Errorf("kept %+v", p)
	}
	if h, _ := held(rc); h != 0 {
		t.Errorf("held %d after the cut", h)
	}
}

func TestThrottleCountsWhatItDropsAndFlushesTheCount(t *testing.T) {
	flushed := make(chan int, 1)
	th := &throttle{every: 50 * time.Millisecond, flush: func(n int) { flushed <- n }}
	if ok, _ := th.allow(); !ok {
		t.Fatal("the first line is dropped")
	}
	for range 3 {
		if ok, _ := th.allow(); ok {
			t.Fatal("a line within the period is allowed")
		}
	}
	select {
	case n := <-flushed:
		if n != 3 {
			t.Errorf("flushed %d, want 3", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the count is never flushed")
	}
	time.Sleep(60 * time.Millisecond)
	if ok, dropped := th.allow(); !ok || dropped != 0 {
		t.Errorf("after the flush: %v %d", ok, dropped)
	}
}

func TestRefusalsAreLoggedOnceASecond(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: slog.New(slog.NewJSONHandler(&log, nil)), now: func() time.Time { return now }}
	// The clock is a test's, so no timer flushes the count: the next line says it.
	rc.init()
	rc.refusals.flush = nil
	for range 5 {
		if w := post(rc.Mux(), "issues", guid1, body1, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", w.Code)
		}
	}
	if n := strings.Count(log.String(), `"outcome":"refused"`); n != 1 {
		t.Errorf("%d lines in a second:\n%s", n, log.String())
	}
	now = now.Add(time.Second)
	post(rc.Mux(), "issues", guid1, body1, "")
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], `"refusals_dropped":4`) {
		t.Errorf("the log:\n%s", log.String())
	}
}

func TestACountOfRefusalsIsLoggedWhenNoRefusalFollows(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: slog.New(slog.NewJSONHandler(&log, nil))}
	rc.init()
	rc.refusals.every = 50 * time.Millisecond
	for range 3 {
		post(rc.Mux(), "issues", guid1, body1, "")
	}
	eventually(t, "the count", func() bool {
		return strings.Contains(log.String(), `"msg":"refusals dropped","refusals_dropped":2`)
	})
}

func TestACountOfRefusalsIsLoggedAtTheStop(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	var log syncBuffer
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: slog.New(slog.NewJSONHandler(&log, nil))}
	for range 3 {
		post(rc.Mux(), "issues", guid1, body1, "")
	}
	rc.stopLog()
	if !strings.Contains(log.String(), `"msg":"refusals dropped","refusals_dropped":2`) {
		t.Errorf("the log:\n%s", log.String())
	}
	// A refusal after the stop sets no timer, and is never flushed.
	post(rc.Mux(), "issues", guid1, body1, "")
	rc.refusals.mu.Lock()
	timer := rc.refusals.timer
	rc.refusals.mu.Unlock()
	if timer != nil {
		t.Error("a timer is set after the stop")
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
		"no event":            {"", guid1, body1},
		"no GUID":             {"issues", "", body1},
		"a GUID too long":     {"issues", guid1 + "0", body1},
		"not a GUID":          {"issues", "not-a-guid", body1},
		"an odd event":        {"Issues\n", guid1, body1},
		"an upper-case event": {"Issues", guid1, body1},
		"a leading digit":     {"2fa", guid1, body1},
		"a hyphen":            {"pull-request", guid1, body1},
		"an event too long":   {"a" + strings.Repeat("b", 64), guid1, body1},
		"not JSON":            {"issues", guid1, "payload=%7B%7D"},
		"a JSON array":        {"issues", guid1, "[]"},
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
	// The handler is released only after the answer, so the timeout only bounds a
	// test that would otherwise hang; it is long, so a loaded machine does not fail it.
	client := http.Client{Timeout: 30 * time.Second}
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

func TestAPermanentErrorFailsTheDeliveryAtOnce(t *testing.T) {
	for _, err := range []error{Permanent(errors.New("Qory Apiary answered 403 forbidden")), fmt.Errorf("taking in: %w", github.ErrIssueGone), github.ErrUnreachable, github.ErrInvalidChange} {
		var calls atomic.Int32
		hs := &Handlers{}
		hs.HandleFunc("issues", func(context.Context, Delivery) error { calls.Add(1); return err })
		h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 5)
		post(h.mux, "issues", guid1, body1, sign(body1))
		eventually(t, "failed", func() bool { return state(h.st, guid1) == store.Failed })
		eventually(t, "logged", func() bool { return strings.Contains(h.log.String(), `"permanent":true`) })
		if n := calls.Load(); n != 1 {
			t.Errorf("%v: called %d times, want 1", err, n)
		}
	}
	if Permanent(nil) != nil || Held(nil) != nil || IsPermanent(errors.New("GitHub answered 502")) || IsHeld(errors.New("x")) {
		t.Error("nil or a plain error is marked")
	}
}

// TestAHeldErrorIsTriedUntilItPasses has a handler held more times than the attempts,
// as a 401 holds it while the access key waits for its approval, and checks the
// delivery is done once it passes, never failed meanwhile.
func TestAHeldErrorIsTriedUntilItPasses(t *testing.T) {
	var calls atomic.Int32
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error {
		if calls.Add(1) <= 6 {
			return Held(errors.New("Qory Apiary answered 401 unauthorized"))
		}
		return nil
	})
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 2)
	post(h.mux, "issues", guid1, body1, sign(body1))
	eventually(t, "done", func() bool { return state(h.st, guid1) == store.Done })
	if n := calls.Load(); n != 7 {
		t.Errorf("called %d times, want 7", n)
	}
}

// TestAnOutageIsTriedForADay has a handler meet Qory Apiary's outage on every attempt,
// on a clock an hour later at each look, and checks the delivery is tried far past the
// attempts, with waits that double to five minutes, and failed and logged once a day has
// passed since its first attempt.
func TestAnOutageIsTriedForADay(t *testing.T) {
	var calls atomic.Int32
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error {
		calls.Add(1)
		return fmt.Errorf("sending the items: %w", Outage(errors.New("Qory Apiary answered 502")))
	})
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	log := &syncBuffer{}
	var mu sync.Mutex
	now := time.Now()
	var waits []time.Duration
	w := &Worker{Store: st, Handlers: hs, Log: slog.New(slog.NewJSONHandler(log, nil)), now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Hour)
		return now
	}}
	// The waits are the worker's, recorded, and made short.
	w.Backoff = func(n int) time.Duration {
		mu.Lock()
		defer mu.Unlock()
		waits = append(waits, (&Worker{}).backoffTo(n, outageMaxBackoff))
		return time.Millisecond
	}
	rc := &Receiver{Secret: []byte(secret), Store: st, Log: w.Log, Stored: w.Notify}
	w.Start()
	t.Cleanup(func() { w.Stop(5 * time.Second) })
	post(rc.Mux(), "issues", guid1, body1, sign(body1))
	eventually(t, "failed", func() bool { return state(st, guid1) == store.Failed })
	eventually(t, "logged", func() bool { return strings.Contains(log.String(), `"outcome":"failed","attempts":24,"outage":true`) })
	if n := calls.Load(); n != 24 {
		t.Errorf("called %d times, want 24", n)
	}
	if logged := log.String(); strings.Count(logged, `"level":"WARN","msg":"delivery","event":"issues","action":"opened","guid":"`+guid1+`","outcome":"retrying","outage":true,"error":"sending the items: Qory Apiary answered 502"`) != 1 {
		t.Errorf("the log %s", logged)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(waits) != 23 || waits[0] != 2*time.Second || waits[1] != 4*time.Second || waits[8] != outageMaxBackoff || waits[22] != outageMaxBackoff {
		t.Errorf("waits %v", waits)
	}
}

// TestAJoinedErrorIsPermanentOnlyWhenEveryPartIs checks a listing's error joined with
// the error of its last part is permanent only when both are.
func TestAJoinedErrorIsPermanentOnlyWhenEveryPartIs(t *testing.T) {
	transient := errors.New("listing the issues of acme/widgets: GitHub answered 502: Bad Gateway")
	refused := Permanent(errors.New("sending the items of acme/widgets: Qory Apiary answered 409 collection_not_linked"))
	for err, want := range map[error]bool{
		errors.Join(transient, refused):                                      false,
		errors.Join(refused, transient):                                      false,
		errors.Join(refused, refused):                                        true,
		fmt.Errorf("filling: %w", errors.Join(transient, refused)):           false,
		fmt.Errorf("filling: %w", errors.Join(refused, github.ErrIssueGone)): true,
		fmt.Errorf("%w and %w", transient, refused):                          false,
		fmt.Errorf("%w: %w", github.ErrIssueGone, transient):                 true,
		fmt.Errorf("%w: %w", github.ErrUnreachable, transient):               true,
		fmt.Errorf("filling: %w", refused):                                   true,
		transient:                                                            false,
	} {
		if IsPermanent(err) != want {
			t.Errorf("%v: permanent %v, want %v", err, !want, want)
		}
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

func TestNoMoreThanTheBoundOfInstallationsRunAtOnce(t *testing.T) {
	var running, most atomic.Int32
	release := make(chan struct{})
	hs := &Handlers{}
	hs.HandleFunc("issues", func(context.Context, Delivery) error {
		n := running.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		<-release
		running.Add(-1)
		return nil
	})
	st := openStore(t, filepath.Join(t.TempDir(), "state"))
	w := &Worker{Store: st, Handlers: hs, maxLanes: 2}
	rc := &Receiver{Secret: []byte(secret), Store: st, Stored: w.Notify}
	w.Start()
	defer w.Stop(5 * time.Second)
	guids := []string{guid1, guid2, guid3, "72d3162e-cc78-11e3-81ab-4c9367dc0000"}
	for i, g := range guids {
		body := fmt.Sprintf(`{"installation":{"id":%d}}`, i+1)
		post(rc.Mux(), "issues", g, body, sign(body))
	}
	eventually(t, "two run", func() bool { return running.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := running.Load(); n != 2 {
		t.Errorf("%d run at once", n)
	}
	close(release)
	eventually(t, "all done", func() bool {
		for _, g := range guids {
			if state(st, g) != store.Done {
				return false
			}
		}
		return true
	})
	if m := most.Load(); m != 2 {
		t.Errorf("at most %d ran at once, want 2", m)
	}
}

func TestAHandlersPanicIsLoggedWithoutItsValue(t *testing.T) {
	hs := &Handlers{}
	hs.HandleFunc("issues", func(_ context.Context, d Delivery) error { panic(string(d.Body)) })
	h := newHarness(t, filepath.Join(t.TempDir(), "state"), hs, 1)
	post(h.mux, "issues", guid1, body1, sign(body1))
	eventually(t, "logged", func() bool { return strings.Contains(h.log.String(), `"outcome":"failed"`) })
	if !strings.Contains(h.log.String(), "the handler for issues panicked") || strings.Contains(h.log.String(), "must not") {
		t.Errorf("the log: %s", h.log.String())
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

// pinJSON is a pin with one key that is no fixture's.
const pinJSON = `[{"alg":"ed25519","public_key":"Pjsm5s3nnSkGz0Vag3fbXsTMycY1__2Z0w5jggPsA70"}]`

func TestReadSettings(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "serve.json")
	writeFile(t, file, `{"app_id":123456,"private_key_file":"/k.pem","webhook_secret_file":"/s","listen":"127.0.0.1:8080","state_dir":"/var/lib/qory-github",
		"app_slug":"qory-acme","apiary_url":"https://apiary.example.com/","public_url":"https://qory-github.example.com/","access_key_id":"ak_0123456789abcdef",
		"access_key_secret_file":"/a","apiary_public_key":`+pinJSON+`,"adapter_id":"na_0123456789abcdef","client_id":"Iv1.abc","client_secret_file":"/c"}`, 0o644)
	s, err := ReadSettings(file)
	want := Settings{AppID: "123456", PrivateKeyFile: "/k.pem", WebhookSecretFile: "/s", Listen: "127.0.0.1:8080", StateDir: "/var/lib/qory-github",
		AppSlug: "qory-acme", APIURL: "https://api.github.com", ApiaryURL: "https://apiary.example.com", PublicURL: "https://qory-github.example.com",
		AccessKeyID: "ak_0123456789abcdef", AccessKeySecretFile: "/a", ApiaryPublicKey: accesskey.Pin{{Alg: "ed25519", PublicKey: "Pjsm5s3nnSkGz0Vag3fbXsTMycY1__2Z0w5jggPsA70"}},
		AdapterID: "na_0123456789abcdef", ClientID: "Iv1.abc", ClientSecretFile: "/c"}
	if err != nil || !reflect.DeepEqual(s, want) {
		t.Fatalf("%+v %v", s, err)
	}
	base := map[string]any{"app_id": "Iv1.abc", "private_key_file": "/k.pem", "webhook_secret_file": "/s", "listen": ":8080", "state_dir": "/d",
		"app_slug": "qory-acme", "api_url": "http://127.0.0.1:9", "apiary_url": "http://localhost:8443", "public_url": "https://qory-github.example.com/github",
		"access_key_id": "ak_0123456789abcdef", "access_key_secret_file": "/a", "apiary_public_key": json.RawMessage(pinJSON),
		"adapter_id": "na_0123456789abcdef", "client_id": "Iv1.abc", "client_secret_file": "/c"}
	b, _ := json.Marshal(base)
	if s, err := parseSettings(b); err != nil || s.APIURL != "http://127.0.0.1:9" || s.ApiaryURL != "http://localhost:8443" || s.PublicURL != "https://qory-github.example.com/github" {
		t.Errorf("%+v %v", s, err)
	}
	for name, tc := range map[string]struct {
		change map[string]any
		want   string
	}{
		"an unknown field":     {map[string]any{"github_url": "https://api.github.com"}, `unknown fields "github_url"`},
		"a bad slug":           {map[string]any{"app_slug": "secret value"}, "/app_slug: is not an App's slug"},
		"another API":          {map[string]any{"api_url": "https://secret.example.com"}, "/api_url: the API is neither"},
		"Qory Apiary on http":  {map[string]any{"apiary_url": "http://secret.example.com"}, "/apiary_url: is neither an https origin"},
		"Qory Apiary's path":   {map[string]any{"apiary_url": "https://apiary.example.com/secret"}, "/apiary_url: is neither an https origin"},
		"a user":               {map[string]any{"apiary_url": "https://secret@apiary.example.com"}, "/apiary_url: is neither an https origin"},
		"a public http URL":    {map[string]any{"public_url": "http://secret.example.com"}, "/public_url: is not an https URL"},
		"a public query":       {map[string]any{"public_url": "https://qory-github.example.com/?secret"}, "/public_url: is not an https URL"},
		"a public fragment":    {map[string]any{"public_url": "https://qory-github.example.com/#secret"}, "/public_url: is not an https URL of a host and an optional port, without a user, a query or a fragment"},
		"a public bad port":    {map[string]any{"public_url": "https://qory-github.example.com:0"}, "/public_url: is not an https URL of a host and an optional port"},
		"a bad key id":         {map[string]any{"access_key_id": "ak_secret"}, "/access_key_id: is not ak_"},
		"a pin of no list":     {map[string]any{"apiary_public_key": "secret value"}, `/apiary_public_key: is not a list of {"alg": "ed25519"`},
		"a pin of a bad key":   {map[string]any{"apiary_public_key": []any{map[string]any{"alg": "ed25519", "public_key": "c2VjcmV0"}}}, `/apiary_public_key: is not a list`},
		"a fixture pin":        {map[string]any{"apiary_public_key": []any{map[string]any{"alg": "ed25519", "public_key": "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}}}, "/apiary_public_key: lists a published fixture key"},
		"a secret in the pin":  {map[string]any{"apiary_public_key": "qak_secret value"}, "the settings contain what looks like an access key secret, qak_, which belongs in the file access_key_secret_file names"},
		"a secret as the path": {map[string]any{"access_key_secret_file": "qak_secret value"}, "the settings contain what looks like an access key secret"},
		"a secret as a name":   {map[string]any{"qak_secret value": "/a"}, "the settings contain what looks like an access key secret"},
		"a run key":            {map[string]any{"state_dir": "QRK_secret value"}, "the settings contain what looks like a run key, qrk_, which belongs nowhere in them"},
		"a PEM as the path":    {map[string]any{"private_key_file": "-----BEGIN RSA PRIVATE KEY-----\nsecret value\n-----END RSA PRIVATE KEY-----"}, "/private_key_file: holds a control character, so it is not a file's path"},
		"a PEM on one line":    {map[string]any{"private_key_file": "-----BEGIN RSA PRIVATE KEY----- secret value"}, "/private_key_file: holds a PEM block, which belongs in the file it names"},
		"a control character":  {map[string]any{"webhook_secret_file": "/s\tsecret value"}, "/webhook_secret_file: holds a control character"},
		"an odd unknown name":  {map[string]any{"a\nb": 1}, `unknown fields "a\nb"`},
		"a null field":         {map[string]any{"state_dir": nil}, "/state_dir: is not a string that is not empty"},
		"an empty path":        {map[string]any{"private_key_file": ""}, "/private_key_file: is not a string"},
		"a bad App id":         {map[string]any{"app_id": "secret value"}, "/app_id: is not an App's id"},
		"a negative App id":    {map[string]any{"app_id": -1}, "/app_id: is neither"},
		"no port":              {map[string]any{"listen": "127.0.0.1"}, "/listen: is not an address and a port"},
		"a port too large":     {map[string]any{"listen": ":65536"}, "/listen: has a port"},
		"a node's id":          {map[string]any{"adapter_id": "nd_0123456789abcdef"}, "/adapter_id: is not na_"},
		"a bad client id":      {map[string]any{"client_id": "secret value"}, "/client_id: is not an App's client id"},
		"a client secret path": {map[string]any{"client_secret_file": "-----BEGIN secret value"}, "/client_secret_file: holds a PEM block"},
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
		if err != nil && strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: the error says a value: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret value") {
			t.Errorf("%s: the error says a value: %v", name, err)
		}
	}
	// A secret hidden from the bytes by an escape is found in the decoded document.
	escaped := strings.Replace(string(b), `"/a"`, `"\u0071ak_secret value"`, 1)
	if _, err := parseSettings([]byte(escaped)); err == nil || err.Error() != errSecretInSettings.Error() {
		t.Errorf("an escaped secret: err %v", err)
	}
	delete(base, "listen")
	delete(base, "access_key_id")
	delete(base, "api_url")
	b, _ = json.Marshal(base)
	if _, err := parseSettings(b); err == nil || !strings.HasSuffix(err.Error(), "missing fields listen, access_key_id") {
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

// TestAFileASettingNamesIsNeverQuoted names, in each file's setting, a file that does
// not exist by a path that is a pasted secret, and checks Run's error names the setting
// and the cause, never the path.
func TestAFileASettingNamesIsNeverQuoted(t *testing.T) {
	const pasted = "a-pasted-one-line-secret-0123456789"
	for _, setting := range []string{"private_key_file", "webhook_secret_file", "access_key_secret_file", "client_secret_file"} {
		dir := t.TempDir()
		s := settingsFiles(t, dir, newKey(t), "https://apiary.example.com", pinOf(newKey(t)))
		s.StateDir = filepath.Join(dir, "state")
		switch setting {
		case "private_key_file":
			s.PrivateKeyFile = pasted
		case "webhook_secret_file":
			s.WebhookSecretFile = pasted
		case "access_key_secret_file":
			s.AccessKeySecretFile = pasted
		case "client_secret_file":
			s.ClientSecretFile = pasted
		}
		err := Run(context.Background(), s, Options{})
		if err == nil || err.Error() != "the file "+setting+" names: no such file or directory" {
			t.Errorf("%s: err %v", setting, err)
		}
		if err != nil && strings.Contains(err.Error(), pasted) {
			t.Errorf("%s: the error quotes the path: %v", setting, err)
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
		if err == nil || !strings.HasPrefix(err.Error(), "the file webhook_secret_file names is ") || !strings.Contains(err.Error(), "group or others have permissions on it; make it 0600") || strings.Contains(err.Error(), dir) {
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
	for _, short := range []string{"\n", "fifteen-bytes!!\n", "fifteen-bytes!!\r\n"} {
		file := filepath.Join(dir, "short")
		writeFile(t, file, short, 0o600)
		if _, err := ReadWebhookSecret(file); err == nil || !strings.Contains(err.Error(), "shorter than 16 bytes") || strings.Contains(err.Error(), "fifteen") {
			t.Errorf("%q: err %v", short, err)
		}
	}
	sixteen := filepath.Join(dir, "sixteen")
	writeFile(t, sixteen, "sixteen-bytes!!!", 0o600)
	if _, err := ReadWebhookSecret(sixteen); err != nil {
		t.Errorf("sixteen bytes: %v", err)
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
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))

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
	// The connect page is served beside the receiver.
	resp, err = http.Get(strings.TrimSuffix(url, WebhookPath) + "/v1/connect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("the connect page answered %d %v", resp.StatusCode, resp.Header)
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
	if strings.Contains(log.String(), "must not") || strings.Contains(log.String(), "PRIVATE KEY") || strings.Contains(log.String(), access.Secret()) {
		t.Errorf("the log carries the body, the secret or the key: %s", log.String())
	}
	// The store is closed: it opens again.
	openStore(t, s.StateDir)
}

// TestRunDeclaresTheAdapterAtStart runs serve and checks its first request to Qory
// Apiary, POST /v1/adapter: signed, with its time, the connect page under the public
// URL and the sync serve declares; and that the instance id is kept across a restart.
func TestRunDeclaresTheAdapterAtStart(t *testing.T) {
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	for i := range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, s, Options{}) }()
		eventually(t, "declared", func() bool { return len(apiary.sent(routeAdapter)) > i && len(apiary.sent("GET "+routeChanges)) > i })
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	declared := apiary.sent(routeAdapter)
	if len(declared) != 2 {
		t.Fatalf("declared %d times", len(declared))
	}
	b := declared[0].body
	sync, _ := json.Marshal(b["sync"])
	if len(b) != 4 || b["version"] != 1.0 || b["connect_url"] != "https://qory-github.example.com/v1/connect" || string(sync) != `{"default_interval":3600,"minimum_interval":900,"sends_changes":true}` {
		t.Errorf("declared %s", declared[0].raw)
	}
	if declared[0].instance != declared[1].instance || !strings.HasPrefix(declared[0].instance, "i_") {
		t.Errorf("the instance ids %s and %s", declared[0].instance, declared[1].instance)
	}
}

func TestRunRefusesALooseSecretBeforeItListens(t *testing.T) {
	access := newKey(t)
	for _, loose := range []string{"secret", "access-key", "client-secret"} {
		dir := t.TempDir()
		s := settingsFiles(t, dir, access, "https://apiary.example.com", pinOf(newKey(t)))
		os.Chmod(filepath.Join(dir, loose), 0o644)
		listened := false
		err := Run(context.Background(), s, Options{Listening: func(net.Addr) { listened = true }})
		if err == nil || !strings.Contains(err.Error(), "group or others") || listened || strings.Contains(err.Error(), access.Secret()) {
			t.Errorf("%s: err %v, listened %v", loose, err, listened)
		}
		if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
			t.Errorf("%s: the state directory is made: %v", loose, err)
		}
	}
}

func TestReadAccessKeySecret(t *testing.T) {
	dir := t.TempDir()
	k := newKey(t)
	file := filepath.Join(dir, "access-key")
	for _, content := range []string{k.Secret(), k.Secret() + "\n", k.Secret() + "\r\n"} {
		writeFile(t, file, content, 0o600)
		got, err := ReadAccessKeySecret(file)
		if err != nil || got.PublicKey() != k.PublicKey() {
			t.Errorf("%q: %v", content, err)
		}
	}
	for content, want := range map[string]string{
		"qak_secret value":  "the access key secret",
		k.Secret() + "\n\n": "the access key secret",
		// The fixture access key of the contract, whose secret is published.
		"qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA": "a published fixture key",
	} {
		writeFile(t, file, content, 0o600)
		_, err := ReadAccessKeySecret(file)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "qak_") {
			t.Errorf("%q: err %v", content, err)
		}
	}
}

// running runs serve with opts on a loopback port, and returns its address, its log and
// a function that stops it and waits for it. It stops when the test ends.
func running(t *testing.T, opts Options) (string, *syncBuffer, func()) {
	t.Helper()
	dir := t.TempDir()
	access := newKey(t)
	apiary := newFakeApiary(t, access)
	s := settingsFiles(t, dir, access, apiary.srv.URL, pinOf(apiary.server))
	log := &syncBuffer{}
	opts.Log = slog.New(slog.NewJSONHandler(log, nil))
	addr := make(chan net.Addr, 1)
	opts.Listening = func(a net.Addr) { addr <- a }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, opts) }()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	select {
	case a := <-addr:
		return a.String(), log, stop
	case err := <-done:
		t.Fatalf("Run: %v", err)
	}
	return "", nil, nil
}

// idle opens a connection to addr and makes one request on it, which it keeps open.
func idle(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	return c
}

func TestAnIdleConnectionIsClosedAfterTheIdleTimeout(t *testing.T) {
	if idleTimeout != 5*time.Second {
		t.Errorf("the idle timeout is %s", idleTimeout)
	}
	addr, _, _ := running(t, Options{idleTimeout: 200 * time.Millisecond})
	c := idle(t, addr)
	begun := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF || time.Since(begun) > 2*time.Second {
		t.Errorf("read %v after %s, want the connection closed", err, time.Since(begun))
	}
}

func TestAFullConnectionBoundIsLogged(t *testing.T) {
	addr, log, _ := running(t, Options{maxConns: 1})
	first := idle(t, addr)
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	eventually(t, "logged", func() bool { return strings.Contains(log.String(), `"msg":"connections at the bound","max":1`) })
	// Once the first closes, the second is served.
	first.Close()
	io.WriteString(second, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(second), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestRunLogsTheCountsHeldBackBeforeItStops(t *testing.T) {
	// The period is long, so the count of the refusals after the first is logged by
	// the stop alone, however long the requests take.
	addr, log, stop := running(t, Options{refusalEvery: time.Hour})
	for range 3 {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+WebhookPath, strings.NewReader(body1))
		req.Header.Set("X-GitHub-Event", "issues")
		req.Header.Set("X-GitHub-Delivery", guid1)
		req.Header.Set("Connection", "close")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	stop()
	out := log.String()
	dropped := strings.Index(out, `"refusals_dropped":2`)
	stopped := strings.Index(out, `"msg":"stopped"`)
	if dropped < 0 || stopped < dropped {
		t.Errorf("the log:\n%s", out)
	}
}

func TestAStaleTickDoesNothing(t *testing.T) {
	flushed := make(chan int, 4)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	th := &throttle{every: time.Hour, now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }, flush: func(n int) { flushed <- n }}
	th.allow()
	th.allow()
	th.mu.Lock()
	stale := th.gen
	th.mu.Unlock()
	// A line is allowed in the next period, which cancels that timer, and one is held
	// back after it, which sets another.
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	if ok, dropped := th.allow(); !ok || dropped != 1 {
		t.Fatalf("%v %d", ok, dropped)
	}
	th.allow()
	th.tick(stale)
	th.mu.Lock()
	timer := th.timer
	th.mu.Unlock()
	if timer == nil {
		t.Error("a stale tick orphaned the timer that is set")
	}
	select {
	case n := <-flushed:
		t.Errorf("a stale tick flushed %d", n)
	default:
	}
	th.stop()
	if n := <-flushed; n != 1 {
		t.Errorf("the stop flushed %d, want 1", n)
	}
}
