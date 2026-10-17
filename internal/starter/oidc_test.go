package starter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// marker is in every test token's claims, and in each changed claim's value where it
// fits, so a test can tell that no error quotes a token or a claim.
const marker = "MARKER7f3a"

const (
	testAudience = "https://starter.example.com"
	testRepo     = "example-org/runners"
	testRepoID   = 4242
	testWorkflow = "qory-runner.yml"
	testSHA      = "0123456789abcdef0123456789abcdef01234567"
	testRunID    = 987654321
	testTemplate = testRepo + "/.github/workflows/" + testWorkflow + "@refs/heads/main"
)

// t0 is the tests' time.
var t0 = time.Unix(1_900_000_000, 0)

var (
	keysOnce             sync.Once
	keyA, keyB, keySmall *rsa.PrivateKey
	errGenerateTestKeys  error
)

// testKeys are two 2048-bit keys and a 1024-bit key, made once.
func testKeys(t *testing.T) (a, b, small *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		var err1, err2, err3 error
		keyA, err1 = rsa.GenerateKey(rand.Reader, 2048)
		keyB, err2 = rsa.GenerateKey(rand.Reader, 2048)
		keySmall, err3 = rsa.GenerateKey(rand.Reader, 1024)
		errGenerateTestKeys = errors.Join(err1, err2, err3)
	})
	if errGenerateTestKeys != nil {
		t.Fatal(errGenerateTestKeys)
	}
	return keyA, keyB, keySmall
}

// jwk is k's public key as a JWK with kid and the members extra.
func jwk(k *rsa.PublicKey, kid string, extra map[string]any) map[string]any {
	m := map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
	for name, v := range extra {
		if v == nil {
			delete(m, name)
		} else {
			m[name] = v
		}
	}
	return m
}

// fakeIssuer is an httptest TLS server that serves an openid-configuration and a JWKS,
// and counts the JWKS's fetches.
type fakeIssuer struct {
	srv *httptest.Server

	mu        sync.Mutex
	discovery func(url string) any
	jwks      []byte
	status    int
	jwksHits  int
	discHits  int
}

func newFakeIssuer(t *testing.T, keys ...map[string]any) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{status: http.StatusOK}
	f.setKeys(t, keys...)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discHits++
			doc := any(map[string]any{"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/.well-known/jwks"})
			if f.discovery != nil {
				doc = f.discovery(f.srv.URL)
			}
			if s, ok := doc.(string); ok {
				http.Redirect(w, r, s, http.StatusFound)
				return
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/.well-known/jwks":
			f.jwksHits++
			w.WriteHeader(f.status)
			_, _ = w.Write(f.jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) setKeys(t *testing.T, keys ...map[string]any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.jwks = b
	f.mu.Unlock()
}

func (f *fakeIssuer) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksHits
}

// clock is a test's time, which it moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (f *fakeIssuer) verifier(c *clock) *Verifier {
	return newVerifier(f.srv.URL, f.srv.Client().Transport, c.Now)
}

// claims are a token's claims for the expected run, as GitHub writes them.
func claims(issuer string) map[string]any {
	return map[string]any{
		"jti":                marker + "-jti",
		"sub":                "repo:" + testRepo + ":ref:refs/heads/main",
		"actor":              marker,
		"iss":                issuer,
		"aud":                testAudience,
		"ref":                "refs/heads/main",
		"ref_type":           "branch",
		"sha":                testSHA,
		"repository":         testRepo,
		"repository_owner":   "example-org",
		"repository_id":      "4242",
		"run_id":             "987654321",
		"run_number":         "7",
		"run_attempt":        "1",
		"runner_environment": "github-hosted",
		"event_name":         "workflow_dispatch",
		"workflow":           "qory runner",
		"workflow_ref":       testTemplate,
		"workflow_sha":       testSHA,
		"job_workflow_ref":   testTemplate,
		"job_workflow_sha":   testSHA,
		"nbf":                t0.Unix() - 600,
		"iat":                t0.Unix(),
		"exp":                t0.Unix() + 300,
	}
}

func expect() Expect {
	return Expect{
		Audience: testAudience, Repository: testRepo, RepositoryID: testRepoID, Workflow: testWorkflow,
		Ref: "main", SHA: testSHA, RunID: testRunID, LeaseUntil: t0.Add(10 * time.Minute),
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64(b)
}

// signRaw signs the encoded header h and payload p with k under hash.
func signRaw(t *testing.T, k *rsa.PrivateKey, hash crypto.Hash, h, p string) string {
	t.Helper()
	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256([]byte(h + "." + p))
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512([]byte(h + "." + p))
		digest = d[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + b64(sig)
}

// token is an RS256 token of claims c under k with kid.
func token(t *testing.T, k *rsa.PrivateKey, kid string, c map[string]any) string {
	t.Helper()
	return signRaw(t, k, crypto.SHA256, encode(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid}), encode(t, c))
}

func TestVerifyTakesTheDispatchedRunsToken(t *testing.T) {
	a, _, _ := testKeys(t)
	f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
	c := &clock{now: t0}
	v := f.verifier(c)
	got, err := v.Verify(context.Background(), token(t, a, "k1", claims(f.srv.URL)), expect())
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{Repository: testRepo, RepositoryID: testRepoID, RunID: testRunID, Ref: "refs/heads/main",
		WorkflowSHA: testSHA, RunnerEnvironment: "github-hosted", Expiry: t0.Add(300 * time.Second)}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestVerifyTakesTheFormsItAllows pins the forms that pass: an aud array that names
// the audience, a full ref, a tag, no sha pinned, no nbf, and the leeway.
func TestVerifyTakesTheFormsItAllows(t *testing.T) {
	a, _, _ := testKeys(t)
	cases := []struct {
		name   string
		change func(c map[string]any, w *Expect)
	}{
		{"aud array", func(c map[string]any, _ *Expect) { c["aud"] = []any{"https://other.example.com", testAudience} }},
		{"full ref", func(_ map[string]any, w *Expect) { w.Ref = "refs/heads/main" }},
		{"tag", func(c map[string]any, w *Expect) {
			w.Ref = "v1"
			c["ref"] = "refs/tags/v1"
			c["job_workflow_ref"] = testRepo + "/.github/workflows/" + testWorkflow + "@refs/tags/v1"
			c["workflow_ref"] = c["job_workflow_ref"]
		}},
		{"no sha pinned", func(c map[string]any, w *Expect) {
			w.SHA = ""
			c["job_workflow_sha"] = "ffffffffffffffffffffffffffffffffffffffff"
			delete(c, "workflow_sha")
		}},
		{"no nbf", func(c map[string]any, _ *Expect) { delete(c, "nbf") }},
		{"exp within the leeway", func(c map[string]any, _ *Expect) { c["exp"] = t0.Unix() - 29 }},
		{"iat and nbf within the leeway", func(c map[string]any, _ *Expect) {
			c["iat"] = t0.Unix() + 29
			c["nbf"] = t0.Unix() + 29
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
			c, w := claims(f.srv.URL), expect()
			tc.change(c, &w)
			if _, err := f.verifier(&clock{now: t0}).Verify(context.Background(), token(t, a, "k1", c), w); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// refusalCase is one way a token is refused: change sets up the token, the run and the
// issuer, and raw, when set, makes the token from scratch.
type refusalCase struct {
	name   string
	change func(t *testing.T, f *fakeIssuer, c map[string]any, w *Expect)
	raw    func(t *testing.T, issuer string) string
	reason string
}

func refusalCases() []refusalCase {
	setClaim := func(name string, v any) func(*testing.T, *fakeIssuer, map[string]any, *Expect) {
		return func(_ *testing.T, _ *fakeIssuer, c map[string]any, _ *Expect) {
			if v == nil {
				delete(c, name)
			} else {
				c[name] = v
			}
		}
	}
	header := func(h map[string]any) func(*testing.T, string) string {
		return func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			return signRaw(t, a, crypto.SHA256, encode(t, h), encode(t, claims(issuer)))
		}
	}
	jwkB64 := func(t *testing.T) map[string]any {
		a, _, _ := testKeys(t)
		return jwk(&a.PublicKey, "k1", nil)
	}
	otherTemplate := "example-org/runners/.github/workflows/" + marker + ".yml@refs/heads/main"
	return []refusalCase{
		{name: "wrong iss", change: setClaim("iss", "https://"+marker+".example.com"), reason: "iss"},
		{name: "iss missing", change: setClaim("iss", nil), reason: "iss"},
		{name: "wrong aud", change: setClaim("aud", "https://"+marker+".example.com"), reason: "aud"},
		{name: "aud with a trailing slash", change: setClaim("aud", testAudience+"/"), reason: "aud"},
		{name: "aud array without it", change: setClaim("aud", []any{"https://" + marker + ".example.com", "https://github.com/example-org"}), reason: "aud"},
		{name: "aud array empty", change: setClaim("aud", []any{}), reason: "aud"},
		{name: "aud array with a non-string", change: setClaim("aud", []any{testAudience, 1}), reason: "aud"},
		{name: "aud missing", change: setClaim("aud", nil), reason: "aud"},
		{name: "wrong repository", change: setClaim("repository", "example-org/"+marker), reason: "repository"},
		{name: "repository in another case", change: setClaim("repository", "Example-Org/runners"), reason: "repository"},
		{name: "wrong repository_id", change: setClaim("repository_id", "4243"), reason: "repository_id"},
		{name: "repository_id a number", change: setClaim("repository_id", 4242), reason: "repository_id"},
		{name: "wrong file", change: func(_ *testing.T, _ *fakeIssuer, c map[string]any, _ *Expect) {
			c["job_workflow_ref"], c["workflow_ref"] = otherTemplate, otherTemplate
		}, reason: "job_workflow_ref"},
		{name: "job in a reusable workflow", change: setClaim("job_workflow_ref", "example-org/shared/.github/workflows/"+marker+".yml@refs/heads/main"), reason: "job_workflow_ref"},
		{name: "called from another workflow", change: setClaim("workflow_ref", otherTemplate), reason: "workflow_ref"},
		{name: "wrong ref", change: func(_ *testing.T, _ *fakeIssuer, c map[string]any, _ *Expect) {
			c["ref"] = "refs/heads/" + marker
			c["job_workflow_ref"] = testRepo + "/.github/workflows/" + testWorkflow + "@refs/heads/" + marker
			c["workflow_ref"] = c["job_workflow_ref"]
		}, reason: "ref"},
		{name: "ref and template at different refs", change: setClaim("ref", "refs/tags/main"), reason: "job_workflow_ref"},
		{name: "full ref expected, short claim", change: func(_ *testing.T, _ *fakeIssuer, c map[string]any, w *Expect) {
			w.Ref = "refs/heads/main"
			c["ref"] = "main"
		}, reason: "ref"},
		{name: "wrong job_workflow_sha", change: setClaim("job_workflow_sha", "ffffffffffffffffffffffffffffffffffffffff"), reason: "job_workflow_sha"},
		{name: "wrong workflow_sha", change: setClaim("workflow_sha", "ffffffffffffffffffffffffffffffffffffffff"), reason: "workflow_sha"},
		{name: "workflow_sha missing", change: setClaim("workflow_sha", nil), reason: "workflow_sha"},
		{name: "wrong run_id", change: setClaim("run_id", "987654322"), reason: "run_id"},
		{name: "run_id a number", change: setClaim("run_id", testRunID), reason: "run_id"},
		{name: "run_attempt 2", change: setClaim("run_attempt", "2"), reason: "run_attempt"},
		{name: "event push", change: setClaim("event_name", "push"), reason: "event_name"},
		{name: "expired", change: setClaim("exp", t0.Unix()-30), reason: "exp"},
		{name: "exp missing", change: setClaim("exp", nil), reason: "exp"},
		{name: "exp a fraction", change: setClaim("exp", float64(t0.Unix())+300.5), reason: "exp"},
		{name: "nbf in the future", change: setClaim("nbf", t0.Unix()+31), reason: "nbf"},
		{name: "iat in the future", change: setClaim("iat", t0.Unix()+31), reason: "iat"},
		{name: "at lease_until", change: func(_ *testing.T, _ *fakeIssuer, _ map[string]any, w *Expect) { w.LeaseUntil = t0 }, reason: "lease_until"},
		{name: "after lease_until", change: func(_ *testing.T, _ *fakeIssuer, _ map[string]any, w *Expect) { w.LeaseUntil = t0.Add(-time.Second) }, reason: "lease_until"},
		{name: "alg none", raw: func(t *testing.T, issuer string) string {
			return encode(t, map[string]any{"alg": "none", "kid": "k1"}) + "." + encode(t, claims(issuer)) + "."
		}, reason: "alg"},
		{name: "HS256 under the public key's bytes", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			der, err := x509.MarshalPKIXPublicKey(&a.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			secret := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			in := encode(t, map[string]any{"alg": "HS256", "kid": "k1"}) + "." + encode(t, claims(issuer))
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(in))
			return in + "." + b64(mac.Sum(nil))
		}, reason: "alg"},
		{name: "RS512", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			return signRaw(t, a, crypto.SHA512, encode(t, map[string]any{"alg": "RS512", "kid": "k1"}), encode(t, claims(issuer)))
		}, reason: "alg"},
		{name: "alg in another case", raw: header(map[string]any{"alg": "rs256", "kid": "k1"}), reason: "alg"},
		{name: "kid missing", raw: header(map[string]any{"alg": "RS256"}), reason: "kid"},
		{name: "kid empty", raw: header(map[string]any{"alg": "RS256", "kid": ""}), reason: "kid"},
		{name: "unknown kid after one refetch", raw: header(map[string]any{"alg": "RS256", "kid": marker}), reason: "key"},
		{name: "key under 2048 bits", change: func(t *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			_, _, small := testKeys(t)
			f.setKeys(t, jwk(&small.PublicKey, "k1", nil))
		}, reason: "key"},
		{name: "key with use enc", change: func(t *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			a, _, _ := testKeys(t)
			f.setKeys(t, jwk(&a.PublicKey, "k1", map[string]any{"use": "enc"}))
		}, reason: "key"},
		{name: "key for another alg", change: func(t *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			a, _, _ := testKeys(t)
			f.setKeys(t, jwk(&a.PublicKey, "k1", map[string]any{"alg": "RS512"}))
		}, reason: "key"},
		{name: "jku present", raw: header(map[string]any{"alg": "RS256", "kid": "k1", "jku": "https://" + marker + ".example.com/jwks"}), reason: "jku"},
		{name: "x5u present", raw: header(map[string]any{"alg": "RS256", "kid": "k1", "x5u": "https://" + marker + ".example.com/x5u"}), reason: "x5u"},
		{name: "jwk present", raw: func(t *testing.T, issuer string) string {
			return header(map[string]any{"alg": "RS256", "kid": "k1", "jwk": jwkB64(t)})(t, issuer)
		}, reason: "jwk"},
		{name: "x5c present", raw: header(map[string]any{"alg": "RS256", "kid": "k1", "x5c": []any{marker}}), reason: "x5c"},
		{name: "crit present", raw: header(map[string]any{"alg": "RS256", "kid": "k1", "crit": []any{"exp"}}), reason: "crit"},
		{name: "bad base64", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			tok := token(t, a, "k1", claims(issuer))
			i := strings.Index(tok, ".")
			return tok[:i+1] + "*" + tok[i+2:]
		}, reason: "format"},
		{name: "line end in base64", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			tok := token(t, a, "k1", claims(issuer))
			i := strings.Index(tok, ".")
			return tok[:i+5] + "\n" + tok[i+5:]
		}, reason: "format"},
		{name: "padding", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			h := base64.URLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
			if !strings.HasSuffix(h, "=") {
				t.Fatal("the header needs padding")
			}
			return signRaw(t, a, crypto.SHA256, h, encode(t, claims(issuer)))
		}, reason: "format"},
		{name: "standard alphabet", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			tok := token(t, a, "k1", claims(issuer))
			i := strings.Index(tok, ".")
			return tok[:i+1] + "+" + tok[i+2:]
		}, reason: "format"},
		{name: "trailing segment", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			return token(t, a, "k1", claims(issuer)) + ".e30"
		}, reason: "format"},
		{name: "two segments", raw: func(t *testing.T, issuer string) string {
			return encode(t, map[string]any{"alg": "RS256", "kid": "k1"}) + "." + encode(t, claims(issuer))
		}, reason: "format"},
		{name: "trailing data after the payload", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			b, _ := json.Marshal(claims(issuer))
			return signRaw(t, a, crypto.SHA256, encode(t, map[string]any{"alg": "RS256", "kid": "k1"}), b64(append(b, []byte(` {"run_id":"1"}`)...)))
		}, reason: "payload_json"},
		{name: "a claim twice", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			b, _ := json.Marshal(claims(issuer))
			b = append([]byte(`{"run_id":"`+marker+`",`), b[1:]...)
			return signRaw(t, a, crypto.SHA256, encode(t, map[string]any{"alg": "RS256", "kid": "k1"}), b64(b))
		}, reason: "payload_json"},
		{name: "a claim twice, escaped", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			b, _ := json.Marshal(claims(issuer))
			b = append([]byte(`{"run_id":"`+marker+`",`), b[1:]...)
			return signRaw(t, a, crypto.SHA256, encode(t, map[string]any{"alg": "RS256", "kid": "k1"}), b64(b))
		}, reason: "payload_json"},
		{name: "a header member twice", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			return signRaw(t, a, crypto.SHA256, b64([]byte(`{"alg":"none","alg":"RS256","kid":"k1"}`)), encode(t, claims(issuer)))
		}, reason: "header_json"},
		{name: "payload not UTF-8", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			b, _ := json.Marshal(claims(issuer))
			b = append([]byte("{\"x\":\"\xff\","), b[1:]...)
			return signRaw(t, a, crypto.SHA256, encode(t, map[string]any{"alg": "RS256", "kid": "k1"}), b64(b))
		}, reason: "payload_json"},
		{name: "payload an array", raw: func(t *testing.T, _ string) string {
			a, _, _ := testKeys(t)
			return signRaw(t, a, crypto.SHA256, encode(t, map[string]any{"alg": "RS256", "kid": "k1"}), b64([]byte(`["`+marker+`"]`)))
		}, reason: "payload_json"},
		{name: "oversize token", change: setClaim("pad", strings.Repeat(marker, 2000)), reason: "size"},
		{name: "oversize JWKS", change: func(t *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			f.mu.Lock()
			f.jwks = append(f.jwks[:len(f.jwks)-1], []byte(`,"pad":"`+strings.Repeat("x", maxJWKS)+`"}`)...)
			f.mu.Unlock()
		}, reason: "jwks"},
		{name: "JWKS answers 500", change: func(_ *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) { f.status = 500 }, reason: "jwks"},
		{name: "JWKS with a kid twice", change: func(t *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			a, b, _ := testKeys(t)
			f.setKeys(t, jwk(&a.PublicKey, "k1", nil), jwk(&b.PublicKey, "k1", nil))
		}, reason: "jwks"},
		{name: "jwks_uri on another host", change: func(_ *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			f.discovery = func(u string) any {
				return map[string]any{"issuer": u, "jwks_uri": strings.Replace(u, "127.0.0.1", "localhost", 1) + "/.well-known/jwks"}
			}
		}, reason: "discovery"},
		{name: "jwks_uri over http", change: func(_ *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			f.discovery = func(u string) any {
				return map[string]any{"issuer": u, "jwks_uri": strings.Replace(u, "https:", "http:", 1) + "/.well-known/jwks"}
			}
		}, reason: "discovery"},
		{name: "discovery names another issuer", change: func(_ *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			f.discovery = func(u string) any {
				return map[string]any{"issuer": Issuer, "jwks_uri": u + "/.well-known/jwks"}
			}
		}, reason: "discovery"},
		{name: "discovery redirects", change: func(_ *testing.T, f *fakeIssuer, _ map[string]any, _ *Expect) {
			f.discovery = func(u string) any { return u + "/.well-known/jwks" }
		}, reason: "discovery"},
		{name: "signature over a changed payload", raw: func(t *testing.T, issuer string) string {
			a, _, _ := testKeys(t)
			tok := token(t, a, "k1", claims(issuer))
			parts := strings.Split(tok, ".")
			c := claims(issuer)
			c["run_id"] = "987654322"
			parts[1] = encode(t, c)
			return strings.Join(parts, ".")
		}, reason: "signature"},
		{name: "signed by another key with the kid", raw: func(t *testing.T, issuer string) string {
			_, b, _ := testKeys(t)
			return token(t, b, "k1", claims(issuer))
		}, reason: "signature"},
		{name: "signature empty", raw: func(t *testing.T, issuer string) string {
			return encode(t, map[string]any{"alg": "RS256", "kid": "k1"}) + "." + encode(t, claims(issuer)) + "."
		}, reason: "signature"},
	}
}

// TestVerifyRefusesEachCheck pins each check's refusal and its reason, and that no
// error, and nothing logged, quotes the token or a claim's value.
func TestVerifyRefusesEachCheck(t *testing.T) {
	a, _, _ := testKeys(t)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for _, tc := range refusalCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
			c, w := claims(f.srv.URL), expect()
			if tc.change != nil {
				tc.change(t, f, c, &w)
			}
			raw := token(t, a, "k1", c)
			if tc.raw != nil {
				raw = tc.raw(t, f.srv.URL)
			}
			_, err := f.verifier(&clock{now: t0}).Verify(context.Background(), raw, w)
			if err == nil {
				t.Fatal("the token is taken")
			}
			if got := Reason(err); got != tc.reason {
				t.Errorf("Reason = %q, want %q: %v", got, tc.reason, err)
			}
			msg := err.Error()
			if strings.Contains(msg, marker) {
				t.Errorf("the error quotes a claim: %s", msg)
			}
			for _, part := range strings.Split(raw, ".") {
				if len(part) >= 8 && strings.Contains(msg, part) {
					t.Errorf("the error quotes the token: %s", msg)
				}
			}
		})
	}
	if strings.Contains(logged.String(), marker) {
		t.Errorf("the log quotes a claim: %s", logged.String())
	}
}

func TestVerifyRefusesAnIncompleteExpect(t *testing.T) {
	a, _, _ := testKeys(t)
	f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
	raw := token(t, a, "k1", claims(f.srv.URL))
	for _, change := range []func(*Expect){
		func(w *Expect) { w.Audience = "" }, func(w *Expect) { w.Repository = "" },
		func(w *Expect) { w.RepositoryID = 0 }, func(w *Expect) { w.Workflow = "" },
		func(w *Expect) { w.Ref = "" }, func(w *Expect) { w.RunID = 0 },
		func(w *Expect) { w.LeaseUntil = time.Time{} },
	} {
		w := expect()
		change(&w)
		_, err := f.verifier(&clock{now: t0}).Verify(context.Background(), raw, w)
		if !errors.Is(err, errExpect) || Reason(err) != "" {
			t.Errorf("err = %v", err)
		}
	}
}

// TestVerifyFetchesKeysAtMostOncePerInterval pins the JWKS's cache: it is fetched once
// for many tokens, again for an unknown kid but not twice within refetchInterval, and
// again once it is older than keysMaxAge.
func TestVerifyFetchesKeysAtMostOncePerInterval(t *testing.T) {
	a, b, _ := testKeys(t)
	f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
	c := &clock{now: t0}
	v := f.verifier(c)
	ctx := context.Background()
	verify := func(k *rsa.PrivateKey, kid string) error {
		cl := claims(f.srv.URL)
		cl["iat"], cl["nbf"], cl["exp"] = c.Now().Unix(), c.Now().Unix(), c.Now().Unix()+300
		w := expect()
		w.LeaseUntil = c.Now().Add(time.Minute)
		_, err := v.Verify(ctx, token(t, k, kid, cl), w)
		return err
	}
	step := func(name string, err error, reason string, hits int) {
		t.Helper()
		if Reason(err) != reason || (reason == "" && err != nil) {
			t.Errorf("%s: err = %v, want reason %q", name, err, reason)
		}
		if got := f.hits(); got != hits {
			t.Errorf("%s: %d fetches of the JWKS, want %d", name, got, hits)
		}
	}
	step("first", verify(a, "k1"), "", 1)
	step("cached", verify(a, "k1"), "", 1)
	step("unknown kid right after a fetch", verify(b, "k2"), "key", 1)
	c.add(refetchInterval)
	step("unknown kid", verify(b, "k2"), "key", 2)
	step("unknown kid again", verify(b, "k2"), "key", 2)
	step("known kid meanwhile", verify(a, "k1"), "", 2)
	c.add(refetchInterval - time.Second)
	step("unknown kid within the interval", verify(b, "k2"), "key", 2)
	f.setKeys(t, jwk(&a.PublicKey, "k1", nil), jwk(&b.PublicKey, "k2", nil))
	c.add(time.Second)
	step("rotated key after the interval", verify(b, "k2"), "", 3)
	c.add(keysMaxAge)
	step("keys too old", verify(a, "k1"), "", 4)

	f.mu.Lock()
	f.status = 500
	f.mu.Unlock()
	c.add(keysMaxAge)
	step("fetch fails", verify(a, "k1"), "jwks", 5)
	step("stale keys within the interval", verify(a, "k1"), "jwks", 5)
	f.mu.Lock()
	f.status = 200
	f.mu.Unlock()
	c.add(refetchInterval)
	step("fetch again", verify(a, "k1"), "", 6)
}

// TestVerifyFetchesOnceForConcurrentTokens pins that tokens that arrive together share
// one fetch.
func TestVerifyFetchesOnceForConcurrentTokens(t *testing.T) {
	a, _, _ := testKeys(t)
	f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
	v := f.verifier(&clock{now: t0})
	raw := token(t, a, "k1", claims(f.srv.URL))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := v.Verify(context.Background(), raw, expect())
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := f.hits(); got != 1 {
		t.Errorf("%d fetches of the JWKS, want 1", got)
	}
}

// TestVerifyFetchesForACallerThatWentAway pins that a caller's cancelled context does
// not cut the fetch short, so it cannot spend the refetch for nothing.
func TestVerifyFetchesForACallerThatWentAway(t *testing.T) {
	a, _, _ := testKeys(t)
	f := newFakeIssuer(t, jwk(&a.PublicKey, "k1", nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.verifier(&clock{now: t0}).Verify(ctx, token(t, a, "k1", claims(f.srv.URL)), expect()); err != nil {
		t.Fatal(err)
	}
}

func TestNewVerifierTrustsGitHubsIssuer(t *testing.T) {
	v := NewVerifier()
	if v.issuer != "https://token.actions.githubusercontent.com" || v.client.Timeout != fetchTimeout {
		t.Errorf("issuer %q, timeout %v", v.issuer, v.client.Timeout)
	}
}

func TestParseJWKSSkipsKeysThatCannotVerifyRS256(t *testing.T) {
	a, _, small := testKeys(t)
	ok := func(kid string) map[string]any { return jwk(&a.PublicKey, kid, nil) }
	b, err := json.Marshal(map[string]any{"keys": []any{
		ok("good"),
		jwk(&a.PublicKey, "no-use-no-alg", map[string]any{"use": nil, "alg": nil}),
		jwk(&small.PublicKey, "small", nil),
		jwk(&a.PublicKey, "ec", map[string]any{"kty": "EC"}),
		jwk(&a.PublicKey, "enc", map[string]any{"use": "enc"}),
		jwk(&a.PublicKey, "null-use", map[string]any{"use": json.RawMessage("null")}),
		jwk(&a.PublicKey, "even-e", map[string]any{"e": "Ag"}),
		jwk(&a.PublicKey, "leading-zero", map[string]any{"n": b64(append([]byte{0}, a.N.Bytes()...))}),
		jwk(&a.PublicKey, "padded-n", map[string]any{"n": base64.URLEncoding.EncodeToString(append([]byte{1}, a.N.Bytes()...))}),
		jwk(&a.PublicKey, "", nil),
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["good"] == nil || keys["no-use-no-alg"] == nil {
		t.Errorf("keys %v", keys)
	}
}
