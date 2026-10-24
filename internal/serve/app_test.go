package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
				ct[0] ^= 1
				if ct[0] == '-' || ct[0] == '_' || (ct[0] >= '0' && ct[0] <= '9') || (ct[0] >= 'A' && ct[0] <= 'Z') || (ct[0] >= 'a' && ct[0] <= 'z') {
					s["ct"] = string(ct)
				} else {
					s["ct"] = "A" + s["ct"].(string)[1:]
				}
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

// TestAnUploadTriesThePinsNextKey pins that an upload Qory Apiary refuses with 400,
// as it refuses one sealed to a key it does not hold, is sealed again to the pin's next
// key, and that a pin of one key Qory Apiary does not hold makes one try, which fails.
func TestAnUploadTriesThePinsNextKey(t *testing.T) {
	access := newKey(t)
	f := newFakeApiary(t, access)
	api := testApiary(t, f, access)
	api.Pin = append(pinOf(newKey(t)), pinOf(f.server)...)
	p, _ := setupApp().plaintext()
	if err := api.UploadSecrets(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if n := len(f.sent(routeSecrets)); n != 2 || len(f.uploaded()) != 1 {
		t.Errorf("%d uploads, %d opened", n, len(f.uploaded()))
	}
	api.Pin = pinOf(newKey(t))
	if err := api.UploadSecrets(context.Background(), p); err == nil || len(f.sent(routeSecrets)) != 3 || len(f.uploaded()) != 1 {
		t.Errorf("err %v after %d uploads", err, len(f.sent(routeSecrets)))
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
