package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
)

// testApiary is a client of Qory Apiary, an [Apiary], of the access key access, enrolled as testKeyID in
// testAdapterID, that reaches the fake f.
func testApiary(t *testing.T, f *fakeApiary, access *accesskey.Key) *Apiary {
	t.Helper()
	return &Apiary{
		URL: f.srv.URL, KeyID: testKeyID, Key: access, Pin: pinOf(f.server), AdapterID: testAdapterID,
		InstanceID: mustInstance(t), Sleep: shortSleep,
	}
}

// TestTheAppIsSealedAndOpenedWhole uploads the App, which the fake opens with the
// server key, and reads it back sealed to the access key: every value comes back as it
// went, and no request or answer contains a value in the clear.
func TestTheAppIsSealedAndOpenedWhole(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	a := setupApp()
	p, err := a.plaintext()
	if err != nil {
		t.Fatal(err)
	}
	if err := api.UploadSecrets(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	got, err := api.Secrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	back, err := appOf(got)
	if err != nil {
		t.Fatal(err)
	}
	if back.id != "777001" || back.numericID != setupAppID || back.slug != setupSlug || back.clientID != setupClientID || !back.key.Equal(appKey()) ||
		string(back.pem) != string(a.pem) || string(back.webhookSecret) != setupHookSecret || string(back.clientSecret) != setupClientSecret ||
		!back.webhookActive || !back.confirmed || back.owner != "acme" || back.ownerKind != github.AccountOrganization {
		t.Errorf("read back %+v", back)
	}
	for _, r := range f.sent(routeSecrets) {
		for _, bad := range []string{setupHookSecret, setupClientSecret, "PRIVATE KEY", setupClientID} {
			if strings.Contains(string(r.raw), bad) {
				t.Errorf("the upload contains a value in the clear")
			}
		}
	}
	if b := f.sealedSecrets(access.PublicKey(), testKeyID); strings.Contains(b, setupHookSecret) || strings.Contains(b, "PRIVATE KEY") {
		t.Error("the answer contains a value in the clear")
	}
}

// TestAnAppPrintsNoSecret pins that the App prints as its id and slug with every verb,
// as a value and as a pointer.
func TestAnAppPrintsNoSecret(t *testing.T) {
	a := setupApp()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{a, *a} {
			got := fmt.Sprintf(verb, v)
			if got != "the App with app_id 777001, qory-acme" {
				t.Errorf("%s prints %q", verb, got)
			}
		}
	}
}

// TestNoSecretsAreNoApp pins that the answer before the App setup, no secret, is no
// App and no error.
func TestNoSecretsAreNoApp(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	f.noApp()
	got, err := testApiary(t, f, access).Secrets(context.Background())
	if err != nil || len(got.Secrets) != 0 {
		t.Fatalf("%d secrets, %v", len(got.Secrets), err)
	}
	if a, err := appOf(got); a != nil || err != nil {
		t.Errorf("%+v %v", a, err)
	}
}

// TestAWrongSecretsAnswerIsRefused pins the refusals of an answer to GET
// /v1/adapter/secrets: one not signed under the pin, one sealed to another access key,
// one sealed for another adapter or bound to another key id, one of another revision or
// suite, and one whose ciphertext was changed. No error contains a value.
func TestAWrongSecretsAnswerIsRefused(t *testing.T) {
	other := newKey(t)
	for name, tc := range map[string]struct {
		change func(f *fakeApiary, access *accesskey.Key)
		want   string
	}{
		"signed under another key": {func(f *fakeApiary, _ *accesskey.Key) { f.signer = newKey(t) }, "is not signed under a key of apiary_public_key, so it is not used"},
		"sealed to another access key": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, keyID string) {
				enc, ct := sealTo(t, other.PublicKey(), []byte(`{"version":1,"secrets":[]}`), contracts.SecretsInfo(keyID), contracts.SecretsAAD(testAdapterID, keyID))
				doc["sealed"].(map[string]any)["enc"], doc["sealed"].(map[string]any)["ct"] = enc, ct
			}
		}, "the answer is refused: its seal does not open with this adapter's access key"},
		"sealed for another adapter": {func(f *fakeApiary, access *accesskey.Key) {
			f.sealing = func(doc map[string]any, keyID string) {
				enc, ct := sealTo(t, access.PublicKey(), []byte(`{"version":1,"secrets":[]}`), contracts.SecretsInfo(keyID), contracts.SecretsAAD("na_fedcba9876543210", keyID))
				doc["sealed"].(map[string]any)["enc"], doc["sealed"].(map[string]any)["ct"] = enc, ct
			}
		}, "the answer is refused: its seal does not open with this adapter's access key"},
		"sealed with another key id's info": {func(f *fakeApiary, access *accesskey.Key) {
			f.sealing = func(doc map[string]any, keyID string) {
				enc, ct := sealTo(t, access.PublicKey(), []byte(`{"version":1,"secrets":[]}`), contracts.SecretsInfo("ak_fedcba9876543210"), contracts.SecretsAAD(testAdapterID, keyID))
				doc["sealed"].(map[string]any)["enc"], doc["sealed"].(map[string]any)["ct"] = enc, ct
			}
		}, "the answer is refused: its seal does not open with this adapter's access key"},
		"naming another access key": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, _ string) {
				doc["sealed"].(map[string]any)["access_key_id"] = "ak_fedcba9876543210"
			}
		}, "the answer is sealed to another access key than " + testKeyID + ", which signed the request"},
		"of another revision": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, _ string) { doc["revision"] = contracts.Revision + 1 }
		}, "the answer is not of the contract's revision 1"},
		"of another suite": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, _ string) {
				doc["sealed"].(map[string]any)["suite"] = "x25519-sha256-chacha20poly1305"
			}
		}, "the answer is not sealed with the suite " + contracts.SealSuite},
		"with a changed ciphertext": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, _ string) {
				s := doc["sealed"].(map[string]any)
				ct := []byte(s["ct"].(string))
				// The first character changes to another of base64url's, and so do the
				// six bits it encodes.
				if ct[0] == 'A' {
					ct[0] = 'B'
				} else {
					ct[0] = 'A'
				}
				s["ct"] = string(ct)
			}
		}, "the answer is refused: its seal does not open with this adapter's access key"},
		"with a member the contract does not define": {func(f *fakeApiary, _ *accesskey.Key) {
			f.sealing = func(doc map[string]any, _ string) { doc["expires_at"] = "2026-10-25T00:00:00Z" }
		}, "the answer is not the secrets' document"},
	} {
		access := newKey(t)
		f := newFakeApiary(t, access)
		f.storeApp(setupApp())
		tc.change(f, access)
		_, err := testApiary(t, f, access).Secrets(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v", name, err)
			continue
		}
		for _, bad := range []string{setupHookSecret, setupClientSecret, "PRIVATE KEY"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%s: the error contains a value", name)
			}
		}
	}
}

// TestAnAnswerBoundToAnotherRequestIsRefused pins that an answer signed for a request
// of a minute before, as one replayed is, is refused: its signature binds it to that
// request's signature, which covers that request's timestamp.
func TestAnAnswerBoundToAnotherRequestIsRefused(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	f.storeApp(setupApp())
	api := testApiary(t, f, access)
	if _, err := api.Secrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := f.sent("GET " + routeSecrets)[0]
	body := f.sealedSecrets(access.PublicKey(), testKeyID)
	old := f.server.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: first.signature, Body: []byte(body)})
	api.HTTP = &http.Client{Transport: replayed{signature: old, body: body}}
	api.Now = func() time.Time { return time.Now().Add(time.Minute) }
	if _, err := api.Secrets(context.Background()); err == nil || !strings.Contains(err.Error(), "is not signed under a key of apiary_public_key, so it is not used") {
		t.Errorf("err %v", err)
	}
}

// TestAppOfRefusesWhatServeDoesNotUpload pins the refusals of secrets that are not the
// App as serve uploads it, each with the secret's name and no value.
func TestAppOfRefusesWhatServeDoesNotUpload(t *testing.T) {
	base := func() map[string]string {
		p, _ := setupApp().plaintext()
		m := map[string]string{}
		for _, e := range p.Secrets {
			m[e.Name] = e.Value
		}
		return m
	}
	entry := func(change func(map[string]any)) string {
		var m map[string]any
		json.Unmarshal([]byte(base()[secretApp]), &m)
		change(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	for name, tc := range map[string]struct {
		change func(map[string]string)
		want   string
	}{
		"another secret":           {func(m map[string]string) { m["token"] = "x" }, "Qory Apiary stores the secret token, which serve does not upload"},
		"no private key":           {func(m map[string]string) { delete(m, secretPrivateKey) }, "Qory Apiary stores no secret private-key for the GitHub App"},
		"no client secret":         {func(m map[string]string) { delete(m, secretClientSecret) }, "Qory Apiary stores no secret client-secret for the GitHub App"},
		"an app without its slug":  {func(m map[string]string) { m[secretApp] = entry(func(e map[string]any) { delete(e, "app_slug") }) }, errAppEntry.Error()},
		"an app with another kind": {func(m map[string]string) { m[secretApp] = entry(func(e map[string]any) { e["owner_kind"] = "Bot" }) }, errAppEntry.Error()},
		"an app with more":         {func(m map[string]string) { m[secretApp] = entry(func(e map[string]any) { e["pem"] = "x" }) }, errAppEntry.Error()},
		"a key that is no key":     {func(m map[string]string) { m[secretPrivateKey] = "not a key" }, "the secret private-key in Qory Apiary: "},
		"a short webhook secret":   {func(m map[string]string) { m[secretWebhookSecret] = "short" }, "the secret webhook-secret in Qory Apiary is shorter than"},
		"a webhook secret with a space": {func(m map[string]string) { m[secretWebhookSecret] = setupHookSecret + " x" },
			"the secret webhook-secret in Qory Apiary is shorter than"},
		"a client secret with a line break": {func(m map[string]string) { m[secretClientSecret] = setupClientSecret + "\n" },
			"the secret client-secret in Qory Apiary is larger than"},
		"a run key in the webhook secret": {func(m map[string]string) { m[secretWebhookSecret] = "qrk_" + strings.Repeat("a", 43) },
			"the secret webhook-secret in Qory Apiary contains what looks like a run key"},
	} {
		m := base()
		tc.change(m)
		p := contracts.AdapterSecretsPlaintext{Version: contracts.Version}
		for k, v := range m {
			p.Secrets = append(p.Secrets, contracts.SecretEntry{Name: k, Value: v})
		}
		a, err := appOf(p)
		if a != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v %v", name, a, err)
			continue
		}
		for _, bad := range []string{setupHookSecret, setupClientSecret, "PRIVATE KEY", "qrk_aaaa"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%s: the error contains a value", name)
			}
		}
	}
}

// sealedTo are the server keys the fake's uploads were sealed to, in order, and their
// encs.
func sealedTo(f *fakeApiary) (keys, encs []string) {
	for _, r := range f.sent(routeSecrets) {
		sealed, _ := r.body["sealed"].(map[string]any)
		k, _ := sealed["server_key"].(string)
		e, _ := sealed["enc"].(string)
		keys, encs = append(keys, k), append(encs, e)
	}
	return keys, encs
}

// TestAnUnknownServerKeyMovesTheUploadToTheNextKey pins that a signed 400
// unknown_server_key, Qory Apiary's answer to a seal to a key it does not hold, has the
// upload sealed again, anew, to the pin's next key not tried yet, until one is
// accepted; that the next upload starts from the key that verified the latest signed
// answer; and that an upload fails once every key is tried.
func TestAnUnknownServerKeyMovesTheUploadToTheNextKey(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	x, y := newKey(t), newKey(t)
	api.Pin = append(append(pinOf(x), pinOf(y)...), pinOf(f.server)...)
	p, _ := setupApp().plaintext()
	ctx := context.Background()
	if err := api.UploadSecrets(ctx, p); err != nil {
		t.Fatal(err)
	}
	keys, encs := sealedTo(f)
	want := []string{x.PublicKey().String(), y.PublicKey().String(), f.server.PublicKey().String()}
	if !slices.Equal(keys, want) || len(f.uploaded()) != 1 || len(slices.Compact(slices.Clone(encs))) != 3 {
		t.Errorf("sealed to %v with %d encs apart, %d opened; want %v, each anew", keys, len(slices.Compact(slices.Clone(encs))), len(f.uploaded()), want)
	}
	// Each refusal was signed with the server's key, so the next upload starts there.
	if err := api.UploadSecrets(ctx, p); err != nil {
		t.Fatal(err)
	}
	if keys, _ := sealedTo(f); len(keys) != 4 || keys[3] != f.server.PublicKey().String() || len(f.uploaded()) != 2 {
		t.Errorf("the next upload is sealed to %v, want the server's key alone", keys[3:])
	}
	// Qory Apiary holds none of the keys now: the upload is sealed to each once, the
	// latest answer's signer first, and fails.
	f.mu.Lock()
	f.refuse = func(route string, _ int) (int, string) {
		if route == routeSecrets {
			return http.StatusBadRequest, `{"error":"unknown_server_key"}`
		}
		return 0, ""
	}
	f.mu.Unlock()
	err := api.UploadSecrets(ctx, p)
	all := []string{f.server.PublicKey().String(), x.PublicKey().String(), y.PublicKey().String()}
	if keys, _ := sealedTo(f); !refusedAs(err, http.StatusBadRequest, codeUnknownServerKey) || !slices.Equal(keys[4:], all) || len(f.uploaded()) != 2 {
		t.Errorf("with no key Qory Apiary holds: %v, sealed to %v, want %v", err, keys[4:], all)
	}
}

// TestAnInvalidRequestKeepsTheUploadsKey pins that a signed 400 invalid_request
// changes no key: the upload fails after one try.
func TestAnInvalidRequestKeepsTheUploadsKey(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	api.Pin = append(pinOf(f.server), pinOf(newKey(t))...)
	f.mu.Lock()
	f.refuse = func(route string, _ int) (int, string) {
		if route == routeSecrets {
			return http.StatusBadRequest, `{"error":"invalid_request"}`
		}
		return 0, ""
	}
	f.mu.Unlock()
	p, _ := setupApp().plaintext()
	err := api.UploadSecrets(context.Background(), p)
	if keys, _ := sealedTo(f); !refusedAs(err, http.StatusBadRequest, codeInvalidRequest) || !slices.Equal(keys, []string{f.server.PublicKey().String()}) {
		t.Errorf("%v, sealed to %v; want one try", err, keys)
	}
}

// TestAnUploadSealsFirstToTheKeyThatSignedLast pins the order of the keys an upload is
// sealed to: the key that verified Qory Apiary's latest signed answer first, so one
// upload is enough when it comes second in the pin; without a signed answer yet, the
// pin's order.
func TestAnUploadSealsFirstToTheKeyThatSignedLast(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	api.Pin = append(pinOf(newKey(t)), pinOf(f.server)...)
	if _, err := api.Secrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	p, _ := setupApp().plaintext()
	if err := api.UploadSecrets(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	sent := f.sent(routeSecrets)
	if len(sent) != 1 || len(f.uploaded()) != 1 {
		t.Fatalf("%d uploads, %d opened, want 1 of each", len(sent), len(f.uploaded()))
	}
	if sealed, _ := sent[0].body["sealed"].(map[string]any); sealed["server_key"] != f.server.PublicKey().String() {
		t.Errorf("the upload is sealed to %v, want the key that signed the latest answer", sealed["server_key"])
	}
}

// TestSealOrder pins [sealOrder]: the latest answer's signer first, the others in the
// pin's order; the pin's order when no answer was signed yet, or when the signer is not
// in the pin, as after a re-enrolment with another pin.
func TestSealOrder(t *testing.T) {
	a, b, c := newKey(t).PublicKey(), newKey(t).PublicKey(), newKey(t).PublicKey()
	keys := []accesskey.PublicKey{a, b, c}
	api := &Apiary{}
	if got := sealOrder(keys, api); !slices.Equal(got, keys) {
		t.Errorf("with no signer: %v", got)
	}
	api.signer, api.signerKnown = c, true
	if got := sealOrder(keys, api); !slices.Equal(got, []accesskey.PublicKey{c, a, b}) || !slices.Equal(keys, []accesskey.PublicKey{a, b, c}) {
		t.Errorf("with the third key as signer: %v, and the pin is %v", got, keys)
	}
	api.signer = newKey(t).PublicKey()
	if got := sealOrder(keys, api); !slices.Equal(got, keys) {
		t.Errorf("with a signer not in the pin: %v", got)
	}
}

// getTimestamps are the X-Qory-Timestamps of the fake's GETs, in the order they came.
func getTimestamps(f *fakeApiary) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if r.method == http.MethodGet {
			out = append(out, r.timestamp)
		}
	}
	return out
}

// secondsFrom are the Unix seconds of at, at+1 and so on, n of them, in decimal.
func secondsFrom(at time.Time, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.FormatInt(at.Unix()+int64(i), 10)
	}
	return out
}

// TestGETsInOneSecondHaveLaterTimestamps pins that GETs in one second, to
// /v1/adapter/secrets and to /v1/grants, each carry a timestamp a second later than
// the GET before, whatever its target, at once, with no wait, and log nothing: Qory
// Apiary returns 401 for a signature it has seen, and the contract wants each GET of
// an instance to carry a later timestamp than the one before it.
func TestGETsInOneSecondHaveLaterTimestamps(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	api.lastGet = storeLastGet{openStore(t, filepath.Join(t.TempDir(), "state"))}
	var log syncBuffer
	api.Log = slog.New(slog.NewJSONHandler(&log, nil))
	now := time.Now().Truncate(time.Second).Add(400 * time.Millisecond)
	var waits []time.Duration
	api.Now = func() time.Time { return now }
	api.Sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	ctx := context.Background()
	if _, err := api.Secrets(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Grants(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Secrets(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := getTimestamps(f), secondsFrom(now, 3); !slices.Equal(got, want) {
		t.Errorf("the GETs carry the timestamps %v, want %v", got, want)
	}
	if len(waits) != 0 {
		t.Errorf("waited %v, want no wait", waits)
	}
	if log.String() != "" {
		t.Errorf("the log: %s, want nothing", log.String())
	}
}

// TestARestartKeepsTheLatestGETsTimestamp pins that the latest GET's timestamp is
// kept in the store, so a client started again on the store never sends a GET at or
// before that second: with its clock a minute behind, the next GET carries the stored
// second and one more, at once, with no wait. One line says so, at the first GET,
// which reads the stored second ahead of the clock. A store it cannot read stops the
// GET before it is sent.
func TestARestartKeepsTheLatestGETsTimestamp(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	dir := filepath.Join(t.TempDir(), "state")
	st := openStore(t, dir)
	now := time.Now().Truncate(time.Second).Add(400 * time.Millisecond)
	var waits []time.Duration
	started := func(log *syncBuffer) *Apiary {
		api := testApiary(t, f, access)
		api.Now = func() time.Time { return now }
		api.Sleep = func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		}
		api.lastGet = storeLastGet{st}
		api.Log = slog.New(slog.NewJSONHandler(log, nil))
		return api
	}
	ctx := context.Background()
	var quiet syncBuffer
	if _, err := started(&quiet).Secrets(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := started(&quiet).Grants(ctx); err != nil {
		t.Fatal(err)
	}
	stored := now.Unix() + 1
	if b, err := st.Get(nsAdapter, keyLastGet); err != nil || string(b) != strconv.FormatInt(stored, 10) {
		t.Errorf("the store keeps %q %v, want the second GET's timestamp", b, err)
	}
	now = now.Add(-time.Minute)
	var log syncBuffer
	behind := started(&log)
	for range 2 {
		if _, err := behind.Secrets(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := getTimestamps(f), secondsFrom(now.Add(time.Minute), 4); !slices.Equal(got, want) {
		t.Errorf("the GETs carry the timestamps %v, want %v", got, want)
	}
	if len(waits) != 0 {
		t.Errorf("waited %v, want no wait", waits)
	}
	line := `"level":"WARN","msg":"the last GET's timestamp in the store is later than the clock, so serve continues from it; ` +
		`Qory Apiary returns 401 for a GET more than 300 seconds ahead of its clock","last_get_timestamp":` +
		strconv.FormatInt(stored, 10) + `,"clock":` + strconv.FormatInt(now.Unix(), 10) + `}`
	if strings.Count(log.String(), "WARN") != 1 || !strings.Contains(log.String(), line) || quiet.String() != "" {
		t.Errorf("the log: %s; before the clock went back: %s", log.String(), quiet.String())
	}
	if err := st.Put(nsAdapter, keyLastGet, []byte("soon"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := started(&quiet).Secrets(ctx); err == nil || len(getTimestamps(f)) != 4 {
		t.Errorf("a GET was sent with no timestamp to follow: %v", err)
	}
}

// replayed answers every request 200 with body under signature, as an answer replayed
// from an earlier request is.
type replayed struct{ signature, body string }

func (r replayed) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{accesskey.HeaderSignature: {r.signature}, "Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(r.body)), ContentLength: int64(len(r.body)), Request: req,
	}, nil
}

// mustInstance is a new instance id.
func mustInstance(t *testing.T) string {
	t.Helper()
	id, err := accesskey.NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
