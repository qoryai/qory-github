package serve

import (
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
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/qory-github/internal/ownerfile"
	"github.com/qoryai/qory-github/internal/store"
)

// WebhookPath is where GitHub sends the App's webhook deliveries, by POST.
const WebhookPath = "/github/webhook"

// MaxBody is the largest delivery the receiver takes, 25 MiB: GitHub caps a payload at
// 25 MB and sends none larger.
const MaxBody = 25 << 20

// maxSecretFile is the most a webhook secret file may hold; one byte more is read to
// tell a larger file apart. A secret is far shorter.
const maxSecretFile = 4 << 10

// minSecret is the shortest webhook secret taken, in bytes: a shorter one is guessed
// sooner, and the signature it makes proves less.
const minSecret = 16

// readBudget is how many bytes of bodies the receiver holds at once, eight times
// [MaxBody]. A body is read before its signature can be checked, so a sender with no
// secret can send bodies for the receiver to hold. Each request takes from the budget
// the bytes of its body as they arrive, never what Content-Length claims, and gives them
// back when its handling is over, after the store has its copy and the answer is sent:
// a sender that sends nothing holds nothing. A request whose next bytes would take the
// budget past the bound is answered 503. The budget counts the bodies' bytes; the
// buffer a body is read into may be up to twice its length while it grows.
const readBudget = 8 * MaxBody

// The body's progress: progressBytes, or the rest of the body, must arrive within
// progressWithin, the window starting again each time they have, so a sender that
// sends slowly is cut within about progressWithin, and the whole body within
// [readTimeout] of the handler's start.
const (
	progressBytes  = 32 << 10
	progressWithin = 2 * time.Second
)

// refusalEvery is how often a refusal is logged at most; those in between are counted,
// and the next line logged says how many were dropped, or a separate line once the
// period is over.
const refusalEvery = time.Second

// ReadWebhookSecret reads the App's webhook secret from a file that only its owner has
// any permission on, as [github.ReadKeyFile] reads a key: the same checks, a bounded
// read. One line break at the end of the file, \n or \r\n, is not part of the secret,
// and a secret shorter than 16 bytes is refused. An error never contains the secret.
func ReadWebhookSecret(path string) ([]byte, error) {
	b, err := ownerfile.ReadFile(path, maxSecretFile, "the webhook secret file", "a webhook secret")
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) < minSecret {
		return nil, fmt.Errorf("the webhook secret in %s is shorter than %d bytes; set a longer random secret on the App and in the file", path, minSecret)
	}
	return b, nil
}

var (
	// eventShape is an event's name as GitHub sends it in X-GitHub-Event, such as
	// issue_comment or projects_v2_item: a lower-case letter, then lower-case letters,
	// digits and underscores, 64 in all at most. An action's is the same.
	eventShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// guidShape is a delivery's GUID as GitHub sends it in X-GitHub-Delivery.
	guidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Receiver takes GitHub's webhook deliveries. It checks each delivery's signature, keeps
// the delivery in the store and answers, and does nothing else on the request: GitHub
// counts a delivery that is not answered within ten seconds as failed, so the handlers
// run in the [Worker], after the answer.
type Receiver struct {
	// Secret is the App's webhook secret, which signs each delivery.
	Secret []byte
	// Store keeps the deliveries.
	Store *store.Store
	// Log takes one line for each delivery: its event, its action when it has one, its
	// GUID and the outcome, and never its body, a secret or another header's value.
	Log *slog.Logger
	// Stored, when set, is called after a delivery is kept, such as [Worker.Notify].
	Stored func()

	once sync.Once
	// budget is the bytes of bodies held; maxBudget is its bound, which a test lowers,
	// zero being [readBudget]; peak is the most it has held, which a test reads.
	mu        sync.Mutex
	held      int64
	peak      int64
	maxBudget int64
	// progress is the window for the body's progress, which a test lowers; zero is
	// [progressWithin]. readBound is the bound on the whole body; zero is
	// [readTimeout].
	progress  time.Duration
	readBound time.Duration
	// now is the clock refusals are logged by; nil is time.Now.
	now      func() time.Time
	refusals *throttle
}

func (rc *Receiver) init() {
	rc.once.Do(func() {
		if rc.maxBudget <= 0 {
			rc.maxBudget = readBudget
		}
		if rc.progress <= 0 {
			rc.progress = progressWithin
		}
		if rc.readBound <= 0 {
			rc.readBound = readTimeout
		}
		rc.refusals = &throttle{every: refusalEvery, now: rc.now, flush: func(dropped int) {
			if rc.Log != nil {
				rc.Log.LogAttrs(context.Background(), slog.LevelInfo, "refusals dropped", slog.Int("refusals_dropped", dropped))
			}
		}}
	})
}

// take takes n bytes from the budget, or nothing and false when they would take it
// past its bound.
func (rc *Receiver) take(n int64) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.held+n > rc.maxBudget {
		return false
	}
	rc.held += n
	rc.peak = max(rc.peak, rc.held)
	return true
}

// give gives n bytes back to the budget.
func (rc *Receiver) give(n int64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.held -= n
}

// Mux is the receiver at [WebhookPath], POST alone. Another method on that path is
// answered 405 and another path 404, as [http.ServeMux] answers them.
func (rc *Receiver) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("POST "+WebhookPath, rc)
	return mux
}

// ServeHTTP takes one delivery. It answers:
//
//   - 400 when X-GitHub-Event is missing or not an event's name, a lower-case letter
//     then lower-case letters, digits and underscores, 64 at most; when
//     X-GitHub-Delivery is missing or not a GUID; or when the body is not a JSON object;
//   - 413 when the body is larger than [MaxBody];
//   - 401 when X-Hub-Signature-256 is missing, malformed or not the HMAC-SHA256 of the
//     body with the secret, which is checked before the body is parsed;
//   - 408 when the body arrives too slowly: 32 KiB, or the rest of it, not within two
//     seconds, or the whole of it not within 15 seconds;
//   - 503 when the body's bytes would take the bodies held past their budget, eight
//     times [MaxBody];
//   - 202 when the delivery is kept, 200 when the store has its GUID already, which
//     drops it, and 500 when the store fails.
//
// Nothing is kept for any answer but 202. The body is read as it arrives, into a buffer
// that grows with it: nothing is set aside, nor taken from the budget, by the length
// the request claims.
func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// GitHub sends a GUID in lower case; it is kept and logged so, whatever its case.
	event, guid := r.Header.Get("X-GitHub-Event"), strings.ToLower(r.Header.Get("X-GitHub-Delivery"))
	rc.init()
	if !eventShape.MatchString(event) || !guidShape.MatchString(guid) {
		rc.refuse(w, event, guid, http.StatusBadRequest, "X-GitHub-Event is missing or not an event's name, or X-GitHub-Delivery is missing or not a GUID")
		return
	}
	if r.ContentLength > MaxBody {
		rc.refuse(w, event, guid, http.StatusRequestEntityTooLarge, "the body is larger than 25 MiB")
		return
	}
	sig, ok := signature(r.Header.Get("X-Hub-Signature-256"))
	if !ok {
		rc.refuse(w, event, guid, http.StatusUnauthorized, "X-Hub-Signature-256 is missing or not sha256= and 64 hex digits")
		return
	}
	var held int64
	defer func() { rc.give(held) }()
	body, status, why := rc.readBody(w, r, &held)
	if status != 0 {
		rc.refuse(w, event, guid, status, why)
		return
	}
	mac := hmac.New(sha256.New, rc.Secret)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), sig) {
		rc.refuse(w, event, guid, http.StatusUnauthorized, "the signature is not the body's")
		return
	}
	// The body is GitHub's from here on, and only now is it parsed.
	var payload struct {
		Action       json.RawMessage `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if !bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("{")) || json.Unmarshal(body, &payload) != nil {
		rc.refuse(w, event, guid, http.StatusBadRequest, "the body is not a JSON object")
		return
	}
	var action string
	if json.Unmarshal(payload.Action, &action) != nil || !eventShape.MatchString(action) {
		action = ""
	}
	d, added, err := rc.Store.AddDelivery(store.Delivery{GUID: guid, Event: event, Action: action, InstallationID: payload.Installation.ID, Body: body})
	if err != nil {
		rc.log(event, action, guid, "store_failed", slog.String("error", err.Error()))
		http.Error(w, "the delivery could not be kept", http.StatusInternalServerError)
		return
	}
	if !added {
		rc.log(event, action, guid, "duplicate")
		w.WriteHeader(http.StatusOK)
		return
	}
	rc.log(event, action, guid, "accepted", slog.Uint64("seq", d.Seq))
	w.WriteHeader(http.StatusAccepted)
	if rc.Stored != nil {
		rc.Stored()
	}
}

// readBody reads r's body as it arrives, taking each byte from the budget and adding
// what it took to held, which the caller gives back. It moves the connection's read
// deadline forward as the body makes progress: [progressBytes], or the rest of the body,
// within rc.progress, and the whole body within rc.readBound of the start. A response
// writer that has no connection, as in a test, has no deadline. It returns the body, or
// the status and why it is refused.
func (rc *Receiver) readBody(w http.ResponseWriter, r *http.Request, held *int64) ([]byte, int, string) {
	ctl := http.NewResponseController(w)
	end := time.Now().Add(rc.readBound)
	deadline := func() {
		d := time.Now().Add(rc.progress)
		if d.After(end) {
			d = end
		}
		ctl.SetReadDeadline(d)
	}
	deadline()
	lr := http.MaxBytesReader(w, r.Body, MaxBody)
	var body []byte
	buf := make([]byte, progressBytes)
	progress := 0
	for {
		n, err := lr.Read(buf)
		if n > 0 {
			if !rc.take(int64(n)) {
				return nil, http.StatusServiceUnavailable, "too many bodies are being read; try again"
			}
			*held += int64(n)
			body = append(body, buf[:n]...)
			if progress += n; progress >= progressBytes {
				progress = 0
				deadline()
			}
		}
		var tooLarge *http.MaxBytesError
		switch {
		case err == io.EOF:
			// The deadline left once the body is read is the whole body's, as
			// net/http's ReadTimeout would have it. A body that is refused keeps the
			// deadline it has, so net/http does not wait on the rest of it before it
			// answers.
			ctl.SetReadDeadline(end)
			return body, 0, ""
		case errors.As(err, &tooLarge):
			return nil, http.StatusRequestEntityTooLarge, "the body is larger than 25 MiB"
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil, http.StatusRequestTimeout, "the body arrives too slowly"
		case err != nil:
			return nil, http.StatusBadRequest, "the body could not be read"
		}
	}
}

// signature is the HMAC-SHA256 that X-Hub-Signature-256 carries, sha256= and 64 hex
// digits.
func signature(header string) ([]byte, bool) {
	h, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(h) != 2*sha256.Size {
		return nil, false
	}
	b, err := hex.DecodeString(h)
	return b, err == nil
}

// refuse answers status with why, and logs it, once each [refusalEvery] at most: a
// refusal in between is counted, and the next line logged says how many were dropped,
// or a separate line when the period is over, so a sender with no secret cannot fill
// the log and a burst's count is never lost. The event and the GUID are logged
// only when they have the shape GitHub sends, so a line never carries what another
// sender chose.
func (rc *Receiver) refuse(w http.ResponseWriter, event, guid string, status int, why string) {
	http.Error(w, why, status)
	if !eventShape.MatchString(event) {
		event = ""
	}
	if !guidShape.MatchString(guid) {
		guid = ""
	}
	ok, dropped := rc.refusals.allow()
	if !ok {
		return
	}
	attrs := []slog.Attr{slog.Int("status", status), slog.String("reason", why)}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("refusals_dropped", dropped))
	}
	rc.log(event, "", guid, "refused", attrs...)
}

// log writes one line for a delivery.
func (rc *Receiver) log(event, action, guid, outcome string, more ...slog.Attr) {
	if rc.Log == nil {
		return
	}
	attrs := deliveryAttrs(event, action, guid, outcome)
	rc.Log.LogAttrs(context.Background(), slog.LevelInfo, "delivery", append(attrs, more...)...)
}

// deliveryAttrs are a delivery's line's attributes: its event, its action when it has
// one, its GUID and the outcome.
func deliveryAttrs(event, action, guid, outcome string) []slog.Attr {
	attrs := []slog.Attr{slog.String("event", event)}
	if action != "" {
		attrs = append(attrs, slog.String("action", action))
	}
	return append(attrs, slog.String("guid", guid), slog.String("outcome", outcome))
}
