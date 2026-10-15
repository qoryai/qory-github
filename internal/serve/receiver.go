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

// maxReading is how many deliveries' bodies the receiver reads at once. A body is read
// before its signature can be checked, so a sender with no secret can make the receiver
// hold [MaxBody] for each body it sends slowly: the bound keeps that to maxReading
// times MaxBody, and a delivery beyond it is answered 503 without its body being read.
const maxReading = 8

// refusalEvery is how often a refusal is logged at most; those in between are counted,
// and the next line logged says how many were dropped.
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
	// reading holds a token for each body being read, maxReading at most.
	reading chan struct{}
	// maxReading is the bound on reading, which a test lowers; zero is [maxReading].
	maxReading int
	// now is the clock refusals are logged by; nil is time.Now.
	now func() time.Time
	// mu guards the refusals' log: when one was last logged, and how many were dropped
	// since.
	mu      sync.Mutex
	refused time.Time
	dropped int
}

func (rc *Receiver) init() {
	rc.once.Do(func() {
		n := rc.maxReading
		if n <= 0 {
			n = maxReading
		}
		rc.reading = make(chan struct{}, n)
		if rc.now == nil {
			rc.now = time.Now
		}
	})
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
//   - 503 when eight bodies are being read already, without reading this one;
//   - 202 when the delivery is kept, 200 when the store has its GUID already, which
//     drops it, and 500 when the store fails.
//
// Nothing is kept for any answer but 202. The body is read as it arrives, into a buffer
// that grows with it: nothing is set aside by the length the request claims.
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
	select {
	case rc.reading <- struct{}{}:
	default:
		rc.refuse(w, event, guid, http.StatusServiceUnavailable, "too many deliveries are being read; try again")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	<-rc.reading
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		rc.refuse(w, event, guid, http.StatusRequestEntityTooLarge, "the body is larger than 25 MiB")
		return
	case err != nil:
		rc.refuse(w, event, guid, http.StatusBadRequest, "the body could not be read")
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
// so a sender with no secret cannot fill the log. The event and the GUID are logged
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
	rc.mu.Lock()
	now := rc.now()
	if !rc.refused.IsZero() && now.Sub(rc.refused) < refusalEvery {
		rc.dropped++
		rc.mu.Unlock()
		return
	}
	dropped := rc.dropped
	rc.refused, rc.dropped = now, 0
	rc.mu.Unlock()
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
