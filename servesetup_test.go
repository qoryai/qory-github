package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServeManifestMakesTheWebhookInactiveWithoutAPublicAddress pins [ServeManifest]:
// with active, the App serveManifest makes of Manifest, public or private as asked;
// without it, the same App with its webhook inactive at the address Manifest gives a
// webhook.
func TestServeManifestMakesTheWebhookInactiveWithoutAPublicAddress(t *testing.T) {
	for _, public := range []bool{true, false} {
		want := Manifest("qory-acme", "https://qory-github.example.com/setup/created")
		serveManifest(want, "https://qory-github.example.com", public)
		got := ServeManifest("qory-acme", "https://qory-github.example.com/setup/created", "https://qory-github.example.com", public, true)
		if a, b := mustJSON(got), mustJSON(want); a != b || got["public"] != public {
			t.Errorf("active, public %v: %s\nwant %s", public, a, b)
		}
	}
	want := Manifest("qory-acme", "https://qory-github.example.com/setup/created")
	serveManifest(want, "https://qory-github.example.com", true)
	m := ServeManifest("qory-acme", "https://qory-github.example.com/setup/created", "https://qory-github.example.com", true, false)
	hook, _ := json.Marshal(m["hook_attributes"])
	if string(hook) != `{"active":false,"url":"https://github.com/qoryai/qory-github"}` {
		t.Errorf("inactive: the webhook is %s", hook)
	}
	m["hook_attributes"] = want["hook_attributes"]
	if a, b := mustJSON(m), mustJSON(want); a != b {
		t.Errorf("inactive: the rest is %s\nwant %s", a, b)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestTheURLsOfTheManifestFlow pins where the manifest is posted, and the pages of an
// App and of an account's Apps on GitHub.
func TestTheURLsOfTheManifestFlow(t *testing.T) {
	for got, want := range map[string]string{
		ManifestAction("", "", "s1"):                       "https://github.com/settings/apps/new?state=s1",
		ManifestAction("https://github.com/", "acme", "s"): "https://github.com/organizations/acme/settings/apps/new?state=s",
		AppSettingsURL("", "", "qory-alice"):               "https://github.com/settings/apps/qory-alice",
		AppSettingsURL("http://127.0.0.1:9", "acme", "q"):  "http://127.0.0.1:9/organizations/acme/settings/apps/q",
		AppsURL("", ""):     "https://github.com/settings/apps",
		AppsURL("", "acme"): "https://github.com/organizations/acme/settings/apps",
	} {
		if got != want {
			t.Errorf("%s, want %s", got, want)
		}
	}
	if s := NewWebhookSecret(); len(s) != 64 || s == NewWebhookSecret() || strings.Trim(s, "0123456789abcdef") != "" {
		t.Errorf("the webhook secret %s", s)
	}
}

// TestConvertManifestTakesGitHubsAnswer pins the exchange of the code: GitHub's 201 as
// it says the App, its owner among it; a redirect, which is not followed; an answer
// without the App; and that no error says the code, which goes in the path escaped.
func TestConvertManifestTakesGitHubsAnswer(t *testing.T) {
	var paths []string
	status, body := http.StatusCreated, `{"id":7,"slug":"qory-acme","client_id":"Iv1.x","html_url":"https://github.com/apps/qory-acme","pem":"P","client_secret":"cs","webhook_secret":null,"owner":{"login":"acme","type":"Organization"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.EscapedPath())
		if status == http.StatusFound {
			w.Header().Set("Location", "https://elsewhere.example.com/")
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	c := Client{API: srv.URL}
	got, err := c.ConvertManifest(context.Background(), "a-code")
	if err != nil || got.ID != 7 || got.Slug != "qory-acme" || got.ClientID != "Iv1.x" || got.PEM != "P" || got.ClientSecret != "cs" || got.WebhookSecret != "" || got.Owner.Login != "acme" || got.Owner.Type != AccountOrganization {
		t.Errorf("%+v %v", got, err)
	}
	if _, err := c.ConvertManifest(context.Background(), "a/b"); err != nil || paths[1] != "POST /app-manifests/a%2Fb/conversions" {
		t.Errorf("%v %v", paths, err)
	}
	status = http.StatusFound
	if _, err := c.ConvertManifest(context.Background(), "a-secret-code"); err == nil || err.Error() != "exchanging the code for the App: GitHub answered with a redirect, which setup never follows, so the code is sent nowhere else" {
		t.Errorf("a redirect: %v", err)
	}
	status, body = http.StatusCreated, `{"slug":"qory-acme"}`
	if _, err := c.ConvertManifest(context.Background(), "a-secret-code"); err == nil || err.Error() != "exchanging the code for the App: GitHub answered without the App" {
		t.Errorf("no App: %v", err)
	}
	status, body = http.StatusNotFound, `{"message":"a-secret-code is gone"}`
	if _, err := c.ConvertManifest(context.Background(), "a-secret-code"); err == nil || strings.Contains(err.Error(), "a-secret-code") || !strings.Contains(err.Error(), "[the code] is gone") || strings.Contains(err.Error(), "/app-manifests/") {
		t.Errorf("a refusal: %v", err)
	}
}

// TestSetAppWebhookSecretKeepsTheSecretOutOfItsError pins that an error of the
// webhook secret's setting never says the secret, though GitHub's message does.
func TestSetAppWebhookSecretKeepsTheSecretOutOfItsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Secret string `json:"secret"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if r.Method != http.MethodPatch || r.URL.Path != "/app/hook/config" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"message":"bad secret `+b.Secret+`"}`)
	}))
	defer srv.Close()
	err := Client{API: srv.URL}.SetAppWebhookSecret(context.Background(), 7, key(t), "a-secret-of-the-webhook")
	if err == nil || strings.Contains(err.Error(), "a-secret-of-the-webhook") || !strings.Contains(err.Error(), "[the secret]") {
		t.Errorf("err %v", err)
	}
}

// TestAppReadsTheIDAndTheSlug pins [Client.App]: GET /app under the App's token, the
// id taken only as a positive integer and the slug only as a string, a body that is
// not a JSON object naming neither, and any status but 200 an error.
func TestAppReadsTheIDAndTheSlug(t *testing.T) {
	for body, want := range map[string]AppIdentity{
		`{"id":7,"slug":"qory-acme"}`: {7, "qory-acme"}, `{"id":-7,"slug":"qory-acme"}`: {0, "qory-acme"}, `{"id":0}`: {},
		`{"id":"7","slug":7}`: {}, `{"id":7.5,"slug":null}`: {}, `{"id":7e0}`: {}, `not JSON`: {}, `[7]`: {}, `{"slug":"a b"}`: {0, "a b"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/app" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			io.WriteString(w, body)
		}))
		got, err := Client{API: srv.URL}.App(context.Background(), "7", key(t))
		srv.Close()
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", body, got, err, want)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()
	if _, err := (Client{API: srv.URL}).App(context.Background(), "7", key(t)); !Unauthorized(err) || err.Error() != "reading the App: GitHub answered 401: Bad credentials" {
		t.Errorf("err %v", err)
	}
}
