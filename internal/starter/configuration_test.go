package starter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	foragercontracts "github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// digestOf is X-Qory-Configuration for body: sha256= and the hex SHA-256.
func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256=" + hex.EncodeToString(sum[:])
}

// confAnswer is the signed 200 of a configuration document, with its digest.
func confAnswer(body string) reply {
	return reply{status: http.StatusOK, body: body, configuration: digestOf(body)}
}

// discovery is Forager's known configuration document, known-answers/discovery.json.
func discovery(t *testing.T) string {
	t.Helper()
	return string(foragerFixture(t, "known-answers/discovery.json"))
}

// withRunURL is the known configuration document with its run.url set to u.
func withRunURL(t *testing.T, u string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(discovery(t)), &m); err != nil {
		t.Fatal(err)
	}
	m["run"] = map[string]any{"url": u}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fixtureKeys are Forager's published fixture keys, known-answers/keys.json, and the
// known answers to the GET of the configuration document, known-answers/signatures.json.
type fixtureKeys struct {
	access    *accesskey.Key
	keyID     string
	instance  string
	signing   *accesskey.Key
	pin       accesskey.Pin
	answer200 struct{ configuration, signature string }
	answer404 struct{ signature string }
}

func readFixtureKeys(t *testing.T) fixtureKeys {
	t.Helper()
	var keys struct {
		AccessKey struct {
			Secret      string `json:"secret"`
			AccessKeyID string `json:"access_key_id"`
			InstanceID  string `json:"instance_id"`
		} `json:"access_key"`
		SigningKey struct {
			Seed      string `json:"seed"`
			PublicKey string `json:"public_key"`
		} `json:"signing_key"`
	}
	var sigs struct {
		Answers []struct {
			Note      string   `json:"note"`
			Body      string   `json:"body"`
			Lines     []string `json:"lines"`
			Signature string   `json:"signature"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(foragerFixture(t, "known-answers/keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(foragerFixture(t, "known-answers/signatures.json"), &sigs); err != nil {
		t.Fatal(err)
	}
	var k fixtureKeys
	var err error
	if k.access, err = accesskey.ParseSecret(keys.AccessKey.Secret); err != nil {
		t.Fatal(err)
	}
	if k.signing, err = accesskey.ParseSecret(accesskey.SecretPrefix + keys.SigningKey.Seed); err != nil {
		t.Fatal(err)
	}
	k.keyID, k.instance = keys.AccessKey.AccessKeyID, keys.AccessKey.InstanceID
	k.pin = accesskey.Pin{{Alg: "ed25519", PublicKey: keys.SigningKey.PublicKey}}
	for _, a := range sigs.Answers {
		if len(a.Lines) != 6 || a.Lines[0] != accesskey.AnswerDomain {
			continue
		}
		switch {
		case a.Lines[1] == "200" && a.Body == "fixtures/known-answers/discovery.json":
			k.answer200.configuration, k.answer200.signature = a.Lines[4], a.Signature
		case a.Lines[1] == "404" && strings.Contains(a.Note, "discovery"):
			k.answer404.signature = a.Signature
		}
	}
	if k.answer200.signature == "" || k.answer404.signature == "" {
		t.Fatal("the known answers hold no answer to the GET of the configuration document")
	}
	return k
}

// signedFixture is one of Forager's signed requests, fixtures/signed/*.json: a header
// is a string, or a list of the values it is sent with.
type signedFixture struct {
	Method     string                     `json:"method"`
	Target     string                     `json:"target"`
	Headers    map[string]json.RawMessage `json:"headers"`
	Expect     int                        `json:"expect"`
	ExpectCode string                     `json:"expect_code"`
}

// header is the fixture's header name, its values in order.
func (f signedFixture) header(t *testing.T, name string) []string {
	t.Helper()
	raw, ok := f.Headers[name]
	if !ok {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		t.Fatalf("the header %s is neither a string nor a list", name)
	}
	return many
}

// sentRequest is a request the fixture server received.
type sentRequest struct {
	method, target string
	header         http.Header
	body           []byte
}

// signedHeaders are the request headers the signature depends on, and the revision,
// each of which the contract asks to be sent once.
var signedHeaders = []string{accesskey.HeaderAccessKeyID, accesskey.HeaderInstanceID, accesskey.HeaderTimestamp, accesskey.HeaderSignature, headerContractVersion}

// TestConfigurationSignedFixtures builds the GET of the configuration document under
// Forager's fixture access key and instance at each get-configuration fixture's time,
// and answers it as the fixture says Qory Apiary answers: the known signed 200, the
// unsigned 401, the unsigned 400 sent before verification, and the signed 400
// bad_request. Every get-configuration fixture under fixtures/signed is named here, so
// a new one fails the test until it is.
func TestConfigurationSignedFixtures(t *testing.T) {
	keys := readFixtureKeys(t)
	entries, err := fs.ReadDir(foragercontracts.FS, "fixtures/signed")
	if err != nil {
		t.Fatal(err)
	}
	known := discovery(t)
	var tested int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "get-configuration-") {
			continue
		}
		tested++
		t.Run(name, func(t *testing.T) {
			var fx signedFixture
			if err := json.Unmarshal(foragerFixture(t, "signed/"+name), &fx); err != nil {
				t.Fatal(err)
			}
			if fx.Method != http.MethodGet || fx.Target != server.WellKnown {
				t.Fatalf("the fixture is %s %s, not the GET of the configuration document", fx.Method, fx.Target)
			}
			stamp := fx.header(t, accesskey.HeaderTimestamp)
			if len(stamp) != 1 {
				t.Fatal("the fixture carries no one X-Qory-Timestamp")
			}
			sec, err := strconv.ParseInt(stamp[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			fixtureSig := fx.header(t, accesskey.HeaderSignature)[0]
			// answer is how Qory Apiary answers the fixture's request: its status, its
			// body, its X-Qory-Configuration, and its signature, or "" for none.
			type answerOf func(sig string) (status int, body, conf, signature string)
			unsigned := func(status int, code string) answerOf {
				return func(string) (int, string, string, string) { return status, `{"error":"` + code + `"}`, "", "" }
			}
			var answer answerOf
			var check func(t *testing.T, sent []sentRequest, got Configuration, err error)
			retried := func(t *testing.T, sent []sentRequest, err error, status int) {
				t.Helper()
				var r *Refusal
				if !errors.Is(err, ErrUnsigned) || !errors.As(err, &r) || r.Status != status || r.Signed || r.Code != "" {
					t.Errorf("the unsigned %d is not ErrUnsigned with no code: %v", status, err)
				}
				if len(sent) != tries {
					t.Errorf("the unsigned %d was answered after %d tries, not %d", status, len(sent), tries)
				}
				stamps := map[string]bool{}
				for _, s := range sent {
					stamps[s.header.Get(accesskey.HeaderTimestamp)] = true
				}
				if len(stamps) != tries {
					t.Error("a try sent again is not built anew with a new X-Qory-Timestamp")
				}
			}
			switch name {
			case "get-configuration-valid.json":
				answer = func(sig string) (int, string, string, string) {
					if sig != fixtureSig {
						return http.StatusUnauthorized, `{"error":"unauthorized"}`, "", ""
					}
					return http.StatusOK, known, keys.answer200.configuration, keys.answer200.signature
				}
				check = func(t *testing.T, sent []sentRequest, got Configuration, err error) {
					if err != nil {
						t.Fatalf("the known answer is not taken: %v", err)
					}
					if len(sent) != 1 {
						t.Errorf("%d tries, not 1", len(sent))
					}
					if got.NodeID != "nd_f1xt0re000000000" || !slices.Equal(got.Workspaces, []string{"ws_f1xt0re000000000"}) || got.RunURL != "https://qory.example/v1/runs" {
						t.Errorf("the configuration is not the known document's: %+v", got)
					}
				}
			case "get-configuration-stale.json", "get-configuration-bad-signature.json":
				answer = unsigned(http.StatusUnauthorized, "unauthorized")
				check = func(t *testing.T, sent []sentRequest, _ Configuration, err error) {
					retried(t, sent, err, http.StatusUnauthorized)
					if !strings.Contains(err.Error(), "never taken as the access key revoked") {
						t.Errorf("the error does not say a 401 is no revocation: %v", err)
					}
				}
			case "get-configuration-header-twice.json":
				answer = unsigned(http.StatusBadRequest, "bad_request")
				check = func(t *testing.T, sent []sentRequest, _ Configuration, err error) {
					retried(t, sent, err, http.StatusBadRequest)
				}
			case "get-configuration-no-instance-id.json":
				answer = func(sig string) (int, string, string, string) {
					body := `{"error":"bad_request","names":["X-Qory-Instance-Id"]}`
					return http.StatusBadRequest, body, "", keys.signing.SignAnswer(accesskey.Answer{Status: http.StatusBadRequest, RequestSignature: sig, Body: []byte(body)})
				}
				check = func(t *testing.T, sent []sentRequest, _ Configuration, err error) {
					var r *Refusal
					if !errors.As(err, &r) || !r.Signed || r.Status != http.StatusBadRequest || r.Code != fx.ExpectCode {
						t.Errorf("the signed 400 is not a refusal with its code: %v", err)
					}
					for _, s := range sentinels {
						if errors.Is(err, s) {
							t.Errorf("the signed 400 bad_request matches %v", s)
						}
					}
					if len(sent) != 1 {
						t.Errorf("a signed refusal was sent %d times", len(sent))
					}
				}
			default:
				t.Fatalf("the signed fixture %s is not tested", name)
			}
			var mu sync.Mutex
			var sent []sentRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				sent = append(sent, sentRequest{method: r.Method, target: r.URL.RequestURI(), header: r.Header.Clone(), body: b})
				mu.Unlock()
				status, body, conf, signature := answer(r.Header.Get(accesskey.HeaderSignature))
				if conf != "" {
					w.Header().Set(accesskey.HeaderConfiguration, conf)
				}
				if signature != "" {
					w.Header().Set(accesskey.HeaderSignature, signature)
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			sl := &sleeps{}
			sl.set(time.Unix(sec, 0).UTC())
			a := &Apiary{
				URL: srv.URL, KeyID: keys.keyID, Key: keys.access, InstanceID: keys.instance, Pin: keys.pin,
				Now: sl.clock, Sleep: sl.sleep,
			}
			got, err := a.Configuration(context.Background())
			mu.Lock()
			defer mu.Unlock()
			if len(sent) == 0 {
				t.Fatal("nothing was sent")
			}
			first := sent[0]
			if first.method != http.MethodGet || first.target != fx.Target || len(first.body) != 0 || first.header.Get("Content-Type") != "" {
				t.Errorf("the request is %s %s with %d bytes of body and Content-Type %q", first.method, first.target, len(first.body), first.header.Get("Content-Type"))
			}
			for _, s := range sent {
				for _, h := range signedHeaders {
					if len(s.header.Values(h)) != 1 {
						t.Errorf("%s is sent %d times", h, len(s.header.Values(h)))
					}
				}
			}
			for _, h := range []string{accesskey.HeaderAccessKeyID, accesskey.HeaderInstanceID, accesskey.HeaderTimestamp, headerContractVersion} {
				if want := fx.header(t, h); len(want) > 0 && first.header.Get(h) != want[0] {
					t.Errorf("%s is %q, not the fixture's %q", h, first.header.Get(h), want[0])
				}
			}
			if first.header.Get(accesskey.HeaderInstanceID) != keys.instance {
				t.Error("the request does not carry the instance id")
			}
			// The client signs the contract's request string: the fixture's signature,
			// but for the fixture signed over another string or without an instance id.
			sig := first.header.Get(accesskey.HeaderSignature)
			switch name {
			case "get-configuration-bad-signature.json", "get-configuration-no-instance-id.json":
				if sig == fixtureSig {
					t.Error("the client's signature is the fixture's, which is not over the contract's request string")
				}
				if !keys.access.PublicKey().VerifyRequest(accesskey.Request{
					AccessKeyID: keys.keyID, InstanceID: keys.instance, Method: http.MethodGet, Target: server.WellKnown, Timestamp: stamp[0],
				}, sig) {
					t.Error("the client's signature is not over the contract's request string")
				}
			default:
				if sig != fixtureSig {
					t.Error("the signature is not the fixture's")
				}
			}
			check(t, sent, got, err)
		})
	}
	if tested == 0 {
		t.Fatal("no get-configuration fixture was found")
	}
}

// TestConfigurationKnown404 answers the GET with the known signed 404, an empty body
// and no digest, and checks it is a signed refusal with no code, after one try.
func TestConfigurationKnown404(t *testing.T) {
	keys := readFixtureKeys(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set(accesskey.HeaderSignature, keys.answer404.signature)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	a := &Apiary{
		URL: srv.URL, KeyID: keys.keyID, Key: keys.access, InstanceID: keys.instance, Pin: keys.pin,
		Now: func() time.Time { return time.Unix(1700000000, 0) },
		Sleep: func(context.Context, time.Duration) error {
			t.Error("the known 404 was sent again")
			return errors.New("stop")
		},
	}
	got, err := a.Configuration(context.Background())
	var r *Refusal
	if !errors.As(err, &r) || !r.Signed || r.Status != http.StatusNotFound || r.Code != "" || got.RunURL != "" || hits.Load() != 1 {
		t.Fatalf("the known 404 is not a signed refusal with no code: %v", err)
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			t.Errorf("the signed 404 matches %v", s)
		}
	}
}

// TestConfigurationRequest checks the GET the client sends: its target, no body and no
// Content-Type, X-Qory-Timestamp the clock's second, Forager's revision, the access key
// id and the instance id, a signature under the pool's key, and each signed header
// once; and that identical GETs in one second wait for the clock's next second, so no
// two share bytes.
func TestConfigurationRequest(t *testing.T) {
	ctx := context.Background()
	body := discovery(t)
	f := newFake(t, func(int, seen) reply { return confAnswer(body) })
	a := f.client(&sleeps{}, nil)
	for range 3 {
		if _, err := a.Configuration(ctx); err != nil {
			t.Fatalf("the configuration document is not taken: %v", err)
		}
	}
	reqs := f.requests()
	r := reqs[0]
	switch {
	case r.target != server.WellKnown:
		t.Errorf("the target is %s", r.target)
	case len(r.body) != 0 || r.header.Get("Content-Type") != "":
		t.Error("the GET carries a body or a Content-Type")
	case r.header.Get(accesskey.HeaderTimestamp) != strconv.FormatInt(testClock.Unix(), 10):
		t.Errorf("X-Qory-Timestamp is %q, not the clock's second", r.header.Get(accesskey.HeaderTimestamp))
	case r.header.Get(headerContractVersion) != strconv.Itoa(foragercontracts.Revision):
		t.Errorf("X-Qory-Contract-Version is %q, not Forager's revision", r.header.Get(headerContractVersion))
	case r.header.Get(accesskey.HeaderAccessKeyID) != testKeyID || r.header.Get(accesskey.HeaderInstanceID) != testInstance:
		t.Error("the access key id or the instance id is not the client's")
	}
	for _, h := range signedHeaders {
		if len(r.header.Values(h)) != 1 {
			t.Errorf("%s is sent %d times", h, len(r.header.Values(h)))
		}
	}
	checkBuiltAnew(t, reqs, 3)
}

// TestConfigurationDocuments answers each configuration document of Forager's
// fixtures, and the known one, and checks each is taken with its run endpoint and ids;
// and answers each invalid configuration fixture and checks none is used, after one
// try.
func TestConfigurationDocuments(t *testing.T) {
	ctx := context.Background()
	entries, err := fs.ReadDir(foragercontracts.FS, "fixtures/configuration")
	if err != nil {
		t.Fatal(err)
	}
	valid := []string{"known-answers/discovery.json"}
	for _, e := range entries {
		valid = append(valid, "configuration/"+e.Name())
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			body := string(foragerFixture(t, name))
			var want server.Configuration
			if err := json.Unmarshal([]byte(body), &want); err != nil {
				t.Fatal(err)
			}
			f := newFake(t, func(int, seen) reply { return confAnswer(body) })
			got, err := f.client(&sleeps{}, nil).Configuration(ctx)
			if err != nil {
				t.Fatalf("the document is not taken: %v", err)
			}
			if got.RunURL != want.Run.URL || got.NodeID != want.NodeID || !slices.Equal(got.Workspaces, want.Workspaces) {
				t.Errorf("the configuration is %+v, not the document's", got)
			}
		})
	}
	invalid, err := fs.ReadDir(foragercontracts.FS, "fixtures/invalid")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range invalid {
		name := e.Name()
		if !strings.HasPrefix(name, "configuration-") {
			continue
		}
		n++
		t.Run("invalid/"+name, func(t *testing.T) {
			body := string(foragerFixture(t, "invalid/"+name))
			f := newFake(t, func(int, seen) reply { return confAnswer(body) })
			got, err := f.client(&sleeps{}, nil).Configuration(ctx)
			if !errors.Is(err, ErrAnswerUnusable) || got.RunURL != "" || got.NodeID != "" {
				t.Errorf("the document is used: %v", err)
			}
			if len(f.requests()) != 1 {
				t.Error("an unusable answer was sent again")
			}
		})
	}
	if n == 0 {
		t.Fatal("no invalid configuration fixture was found")
	}
}

// TestRunURLShapeIsTheSchemas checks runURLShape is configuration.schema.json's run.url
// pattern, character for character, so the check PostOutcome and Configuration make
// cannot drift from the contract.
func TestRunURLShapeIsTheSchemas(t *testing.T) {
	var schema struct {
		Properties struct {
			Run struct {
				Properties struct {
					URL struct {
						Pattern string `json:"pattern"`
					} `json:"url"`
				} `json:"properties"`
			} `json:"run"`
		} `json:"properties"`
	}
	b, err := fs.ReadFile(foragercontracts.FS, "configuration.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if p := schema.Properties.Run.Properties.URL.Pattern; p == "" || p != runURLShape.String() {
		t.Errorf("runURLShape is %s, not the schema's run.url pattern %s", runURLShape, p)
	}
}

// TestConfigurationRunURL answers documents whose run.url is or is not a run endpoint,
// and checks only a run endpoint is taken: https, or http to a loopback address, with
// no query, no fragment and no trailing slash, and holding neither qak_ nor qrk_. A
// run.url that holds a secret but that the schema accepts is refused too, with an error
// that names no URL.
func TestConfigurationRunURL(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{
		"https://qory.example/v1/runs", "https://qory.example", "https://qory.example:8443/a/b",
		"http://127.0.0.1:8787/v1/runs", "http://localhost/v1/runs", "http://[::1]:1/runs",
	} {
		body := withRunURL(t, u)
		f := newFake(t, func(int, seen) reply { return confAnswer(body) })
		got, err := f.client(&sleeps{}, nil).Configuration(ctx)
		if err != nil || got.RunURL != u {
			t.Errorf("%s is not taken: %v", u, err)
		}
	}
	for name, u := range map[string]string{
		"http to another host":   "http://qory.example/v1/runs",
		"http to a private host": "http://10.0.0.1/v1/runs",
		"a query":                "https://qory.example/v1/runs?node=1",
		"an empty query":         "https://qory.example/v1/runs?",
		"a fragment":             "https://qory.example/v1/runs#runs",
		"a trailing slash":       "https://qory.example/v1/runs/",
		"only a slash":           "https://qory.example/",
		"user info":              "https://user@qory.example/v1/runs",
		"another scheme":         "ftp://qory.example/v1/runs",
		"empty":                  "",
		"white space":            "https://qory.example/v1/r uns",
		"qak_ in the path":       "https://qory.example/qak_RunURLMarker1",
		"QAK_ in the path":       "https://qory.example/v1/QAK_RunURLMarker2",
		"qrk_ in the host":       "https://qrk_RunURLMarker3.example.com/v1/runs",
		"qrk_ on loopback":       "http://127.0.0.1:8787/v1/qrk_RunURLMarker4.x",
	} {
		t.Run(name, func(t *testing.T) {
			body := withRunURL(t, u)
			f := newFake(t, func(int, seen) reply { return confAnswer(body) })
			got, err := f.client(&sleeps{}, nil).Configuration(ctx)
			if !errors.Is(err, ErrAnswerUnusable) || got.RunURL != "" {
				t.Fatalf("the run endpoint %q is taken: %v", u, err)
			}
			if strings.Contains(strings.ToLower(err.Error()), "runurlmarker") || (u != "" && strings.Contains(err.Error(), u)) {
				t.Errorf("the error names the run endpoint: %v", err)
			}
			if len(f.requests()) != 1 {
				t.Error("an unusable answer was sent again")
			}
		})
	}
	t.Run("a secret the schema accepts", func(t *testing.T) {
		body := withRunURL(t, "https://qory.example/qak_RunURLMarker5")
		var doc any
		if readAnswer(foragerSchema, "configuration.schema.json", []byte(body), &doc) != nil {
			t.Fatal("the schema refuses the document, so the test proves nothing of the secret check")
		}
		f := newFake(t, func(int, seen) reply { return confAnswer(body) })
		_, err := f.client(&sleeps{}, nil).Configuration(ctx)
		if !errors.Is(err, ErrAnswerUnusable) || !strings.Contains(err.Error(), runURLSecret) {
			t.Errorf("a run endpoint that holds qak_ is not refused as one: %v", err)
		}
	})
}

// TestConfigurationMembers checks a document's members are read by their exact names:
// a member whose name differs only in case, before or after the one the schema names,
// is ignored as any member the schema does not define.
func TestConfigurationMembers(t *testing.T) {
	ctx := context.Background()
	known := discovery(t)
	for _, body := range []string{
		strings.Replace(known, `"run":`, `"RUN":{"url":"https://elsewhere.example/v1/runs"},"run":`, 1),
		strings.Replace(known, `"run":{"url":"https://qory.example/v1/runs"}`, `"run":{"url":"https://qory.example/v1/runs"},"Run":{"url":"https://elsewhere.example/v1/runs"},"NODE_ID":"np_0000000000000000"`, 1),
	} {
		f := newFake(t, func(int, seen) reply { return confAnswer(body) })
		got, err := f.client(&sleeps{}, nil).Configuration(ctx)
		if err != nil {
			t.Fatalf("the document is not taken: %v", err)
		}
		if got.RunURL != "https://qory.example/v1/runs" || got.NodeID != "nd_f1xt0re000000000" {
			t.Errorf("a member named in another case is read: %+v", got)
		}
	}
}

// TestConfigurationSigned checks an answer not signed under the pin is never used: a
// signature under another key, none, the signature header twice, X-Qory-Configuration
// twice, and X-Qory-Configuration the signature does not cover. Each is sent again,
// built anew, and after every try the error is ErrUnsigned. A signed 200 without
// X-Qory-Configuration is ErrAnswerUnusable, after one try.
func TestConfigurationSigned(t *testing.T) {
	ctx := context.Background()
	body := discovery(t)
	for name, rep := range map[string]reply{
		"another key":                 {status: http.StatusOK, body: body, configuration: digestOf(body), wrongKey: true},
		"no signature":                {status: http.StatusOK, body: body, configuration: digestOf(body), unsigned: true},
		"the signature twice":         {status: http.StatusOK, body: body, configuration: digestOf(body), dupSignature: true},
		"the configuration twice":     {status: http.StatusOK, body: body, configuration: digestOf(body), dupConfiguration: true},
		"a configuration not covered": {status: http.StatusOK, body: body, configuration: digestOf(body), confOutside: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, func(int, seen) reply { return rep })
			sl := &sleeps{}
			got, err := f.client(sl, nil).Configuration(ctx)
			if !errors.Is(err, ErrUnsigned) || got.RunURL != "" {
				t.Fatalf("an answer not signed under the pin is used: %v", err)
			}
			checkBuiltAnew(t, f.requests(), tries)
			if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}; !slices.Equal(sl.waits(), want) {
				t.Errorf("the waits are %v, not %v", sl.waits(), want)
			}
		})
	}
	t.Run("no X-Qory-Configuration", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusOK, body: body} })
		got, err := f.client(&sleeps{}, nil).Configuration(ctx)
		if !errors.Is(err, ErrAnswerUnusable) || got.RunURL != "" || !strings.Contains(err.Error(), "X-Qory-Configuration") {
			t.Errorf("a signed 200 without X-Qory-Configuration is used: %v", err)
		}
		if len(f.requests()) != 1 {
			t.Error("an unusable answer was sent again")
		}
	})
	t.Run("a signed 204", func(t *testing.T) {
		f := newFake(t, func(int, seen) reply { return reply{status: http.StatusNoContent, configuration: digestOf("")} })
		if _, err := f.client(&sleeps{}, nil).Configuration(ctx); !errors.Is(err, ErrAnswerUnusable) || len(f.requests()) != 1 {
			t.Errorf("a signed 204 is not refused at once: %v", err)
		}
	})
	t.Run("a body that is not one document", func(t *testing.T) {
		for _, b := range []string{
			body + body, strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1), "not json", "{\"version\":1,\"x\":\"\xff\"}",
		} {
			f := newFake(t, func(int, seen) reply { return confAnswer(b) })
			if _, err := f.client(&sleeps{}, nil).Configuration(ctx); !errors.Is(err, ErrAnswerUnusable) {
				t.Errorf("%q is used: %v", b, err)
			}
		}
	})
	t.Run("a server error is sent again", func(t *testing.T) {
		f := newFake(t, func(n int, _ seen) reply {
			if n == 1 {
				return reply{status: http.StatusServiceUnavailable, body: `{"error":"unavailable"}`}
			}
			return confAnswer(body)
		})
		if _, err := f.client(&sleeps{}, nil).Configuration(ctx); err != nil {
			t.Fatalf("the configuration document is not taken: %v", err)
		}
		checkBuiltAnew(t, f.requests(), 2)
	})
	t.Run("an unsigned 401 is sent again, built anew", func(t *testing.T) {
		f := newFake(t, func(n int, _ seen) reply {
			if n == 1 {
				return reply{status: http.StatusUnauthorized, unsigned: true}
			}
			return confAnswer(body)
		})
		if _, err := f.client(&sleeps{}, nil).Configuration(ctx); err != nil {
			t.Fatalf("the configuration document is not taken: %v", err)
		}
		checkBuiltAnew(t, f.requests(), 2)
	})
}

// TestConfigurationRefusals checks the signed refusals of the GET: a 400 bad_request or
// unsupported_contract_version and a 404 are refusals that match no sentinel, with
// their code; a code that holds qrk_ names no code. Each comes after one try.
func TestConfigurationRefusals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		status int
		body   string
		code   string
	}{
		{http.StatusBadRequest, `{"error":"bad_request","names":["X-Qory-Instance-Id"]}`, "bad_request"},
		{http.StatusBadRequest, `{"error":"unsupported_contract_version"}`, "unsupported_contract_version"},
		{http.StatusNotFound, "", ""},
		{http.StatusConflict, `{"error":"qrk_codemarker"}`, ""},
	} {
		f := newFake(t, func(int, seen) reply { return reply{status: c.status, body: c.body} })
		got, err := f.client(&sleeps{}, nil).Configuration(ctx)
		var r *Refusal
		if !errors.As(err, &r) || !r.Signed || r.Status != c.status || r.Code != c.code || got.RunURL != "" {
			t.Errorf("%d %s: not the signed refusal with its code: %v", c.status, c.body, err)
		}
		for _, s := range append(slices.Clone(sentinels), ErrUnsigned, ErrTooLarge, ErrAnswerUnusable) {
			if errors.Is(err, s) {
				t.Errorf("%d %s matches %v", c.status, c.body, s)
			}
		}
		if strings.Contains(strings.ToLower(err.Error()), "codemarker") {
			t.Errorf("the error names a code that holds qrk_: %v", err)
		}
		if len(f.requests()) != 1 {
			t.Errorf("%d %s was sent %d times", c.status, c.body, len(f.requests()))
		}
	}
}

// TestConfigurationBounds checks the bound of the answer at its edge: a document of
// server.MaxDocument bytes is taken and one byte more is not, and a refusal one byte
// over maxAnswer is refused for its size; each over its bound is sent again, built
// anew, then ErrTooLarge.
func TestConfigurationBounds(t *testing.T) {
	ctx := context.Background()
	body := padTo(t, discovery(t), server.MaxDocument)
	f := newFake(t, func(int, seen) reply { return confAnswer(body) })
	if got, err := f.client(&sleeps{}, nil).Configuration(ctx); err != nil || got.RunURL == "" {
		t.Errorf("a document of its bound is not taken: %v", err)
	}
	for name, rep := range map[string]reply{
		"a document of its bound and a byte": confAnswer(" " + body),
		"a refusal over maxAnswer":           {status: http.StatusBadRequest, body: padTo(t, `{"error":"bad_request"}`, maxAnswer+1)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, func(int, seen) reply { return rep })
			got, err := f.client(&sleeps{}, nil).Configuration(ctx)
			if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnsigned) || got.RunURL != "" {
				t.Fatalf("not ErrTooLarge alone: %v", err)
			}
			checkBuiltAnew(t, f.requests(), tries)
		})
	}
}

// TestConfigurationFeedsOutcome takes the run endpoint from the configuration document
// and posts an outcome to it as it is: the outcome goes to <run.url>/<run_id>/outcome,
// signed under the pool's key.
func TestConfigurationFeedsOutcome(t *testing.T) {
	ctx := context.Background()
	var runURL string
	f := newFake(t, func(_ int, s seen) reply {
		if s.target == server.WellKnown {
			return confAnswer(withRunURL(t, runURL))
		}
		return reply{status: http.StatusOK, body: `{"version":1}`}
	})
	runURL = f.srv.URL + "/v1/runs"
	a := f.client(&sleeps{}, nil)
	c, err := a.Configuration(ctx)
	if err != nil {
		t.Fatalf("the configuration document is not taken: %v", err)
	}
	if c.RunURL != runURL {
		t.Fatalf("the run endpoint is %s, not %s", c.RunURL, runURL)
	}
	if err := a.PostOutcome(ctx, c.RunURL, testRun, Outcome{State: StateSucceeded}); err != nil {
		t.Fatalf("the outcome failed: %v", err)
	}
	reqs := f.requests()
	if len(reqs) != 2 || reqs[1].target != "/v1/runs/"+testRun+"/outcome" || !reqs[1].verified {
		t.Errorf("the outcome did not go to the run endpoint the document gave, signed")
	}
}

// TestConfigurationNoSecretLeaks answers the GET with documents and refusals that hold
// the pool's access key secret and markers of qak_ and qrk_, used, refused and
// unsigned, and checks no error, no line of the log and nothing the client shows of a
// result holds any of them, nor does any request it sends hold the secret.
func TestConfigurationNoSecretLeaks(t *testing.T) {
	ctx := context.Background()
	const (
		akMarker = "qak_ConfMarker6vR"
		rkMarker = "qrk_ConfMarker8pL.SigMarker2nB"
	)
	known := discovery(t)
	var logs bytes.Buffer
	makers := []func(secret string) reply{
		func(string) reply { return confAnswer(known) },
		func(s string) reply { return confAnswer(withRunURL(t, "https://qory.example/"+s)) },
		func(string) reply { return confAnswer(withRunURL(t, "https://qory.example/"+akMarker)) },
		func(string) reply { return confAnswer(withRunURL(t, "https://"+rkMarker+".example/v1/runs")) },
		func(string) reply { return confAnswer(withRunURL(t, "https://qory.example/runs/?"+rkMarker)) },
		func(s string) reply {
			return confAnswer(strings.Replace(known, `"run":`, `"extra":{"key":"`+s+`","run_key":"`+rkMarker+`"},"run":`, 1))
		},
		func(s string) reply {
			return confAnswer(strings.Replace(known, "https://qory.example/v1/events", "https://qory.example/v1/"+s, 1))
		},
		func(s string) reply {
			return reply{status: http.StatusBadRequest, body: `{"error":"` + rkMarker + `"}`}
		},
		func(s string) reply {
			return reply{status: http.StatusConflict, body: `{"error":"x","names":["` + s + `"]}`}
		},
		func(s string) reply {
			return reply{status: http.StatusOK, body: withRunURL(t, "https://qory.example/"+s), unsigned: true}
		},
		func(s string) reply {
			return reply{status: http.StatusUnauthorized, body: `{"error":"` + s + `"}`, unsigned: true}
		},
		func(s string) reply {
			return reply{status: http.StatusOK, body: withRunURL(t, "https://qory.example/"+s), configuration: rkMarker}
		},
		func(s string) reply {
			return confAnswer(padTo(t, withRunURL(t, "https://qory.example/"+s), server.MaxDocument+1))
		},
	}
	for i, mk := range makers {
		f := newFake(t, nil)
		a := f.client(&sleeps{}, &logs)
		secret := a.Key.Secret()
		rep := mk(secret)
		f.answer = func(int, seen) reply { return rep }
		got, err := a.Configuration(ctx)
		if i == 0 && (err != nil || got.RunURL == "") {
			t.Fatal("the known document is not taken, so the test proves nothing of a result")
		}
		a.Log.Info("configuration", "configuration", got)
		js, _ := json.Marshal(got)
		texts := []string{fmt.Sprint(got), fmt.Sprintf("%+v %#v %q", got, got, got), string(js), logs.String()}
		if err != nil {
			texts = append(texts, err.Error())
		}
		for _, s := range texts {
			low := strings.ToLower(s)
			for _, m := range []string{secret, akMarker, rkMarker, "confmarker", "sigmarker"} {
				if strings.Contains(low, strings.ToLower(m)) {
					t.Errorf("answer %d: an error, the log or a result holds a secret or a marker", i)
				}
			}
		}
		for _, r := range f.requests() {
			if strings.Contains(string(r.body), secret) || strings.Contains(fmt.Sprint(r.header), secret) {
				t.Errorf("answer %d: a request holds the access key secret", i)
			}
		}
	}
	if !strings.Contains(logs.String(), "sent again") {
		t.Error("the log holds no try sent again, so the test proves nothing of it")
	}
}
