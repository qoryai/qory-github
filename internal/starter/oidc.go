package starter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Issuer is GitHub Actions' OIDC issuer: a job's token must name it in iss, and its
// signing keys are read from its openid-configuration's jwks_uri. It is fixed here and
// never read from a token.
const Issuer = "https://token.actions.githubusercontent.com"

const (
	// maxToken is the most a token may hold. GitHub's tokens are about 1 KiB.
	maxToken = 16 << 10
	// maxDiscovery and maxJWKS are the most the openid-configuration and the JWKS may
	// hold.
	maxDiscovery = 64 << 10
	maxJWKS      = 64 << 10
	// maxKeys is the most keys a JWKS may list.
	maxKeys = 64
	// minKeyBits and maxKeyBits bound an RSA key's modulus.
	minKeyBits = 2048
	maxKeyBits = 8192
	// leeway is the clock skew exp, nbf and iat are allowed.
	leeway = 30 * time.Second
	// maxAhead is the furthest after now a token's exp, nbf or iat may be, in seconds.
	// A later one is refused before it is made a time, so no value wraps.
	maxAhead = 24 * 60 * 60
	// fetchTimeout bounds one fetch of the openid-configuration and the JWKS together.
	fetchTimeout = 10 * time.Second
	// refetchInterval is the least time between two fetches of the JWKS, whatever
	// tokens arrive.
	refetchInterval = 10 * time.Second
	// keysMaxAge is how long fetched keys are used before they are fetched again.
	keysMaxAge = time.Hour
	// maxDepth is the deepest a token's or a JWKS's JSON may nest.
	maxDepth = 32
)

// Expect is the run a job's token must be for: the dispatch the starter made, and the
// runner template it ran.
type Expect struct {
	// Audience is the starter's public URL, which the token's aud must name.
	Audience string
	// Repository is the template's repository, owner/name, as GitHub writes it in
	// the API's full_name.
	Repository string
	// RepositoryID is the repository's numeric id.
	RepositoryID int64
	// Workflow is the template's file name in .github/workflows.
	Workflow string
	// Ref is the branch or tag the run was dispatched on: a full name, refs/heads/main
	// or refs/tags/v1, which the token's ref must equal, or a short one, main, which is a
	// branch: the token's ref must be refs/heads/ and the name. A tag is given in full.
	Ref string
	// SHA is the commit the template must be at, 40 hexadecimal digits, or empty.
	SHA string
	// RunID is the dispatched workflow run's id.
	RunID int64
	// LeaseUntil is the dispatch's deadline: a token is refused at or after it, both
	// before the issuer's key is fetched and after.
	LeaseUntil time.Time
}

// Claims are a verified token's claims the starter uses.
type Claims struct {
	// Repository and RepositoryID are the run's repository.
	Repository   string
	RepositoryID int64
	// RunID is the workflow run's id.
	RunID int64
	// Ref is the run's full ref, refs/heads/... or refs/tags/....
	Ref string
	// WorkflowSHA is the template's commit, job_workflow_sha.
	WorkflowSHA string
	// RunnerEnvironment is github-hosted or self-hosted, as GitHub says. It is not
	// checked.
	RunnerEnvironment string
	// Expiry is when the token expires.
	Expiry time.Time
}

// TokenRefusal is a token's refusal: the check that failed, and never the token or a
// claim's value.
type TokenRefusal struct {
	reason string
	err    error
}

// Error says which check refused the token.
func (r *TokenRefusal) Error() string {
	if r.err != nil {
		return "the token is refused: check " + r.reason + " failed: " + r.err.Error()
	}
	return "the token is refused: check " + r.reason + " failed"
}

// Unwrap is why the keys could not be fetched, for the checks discovery and jwks, or
// nil.
func (r *TokenRefusal) Unwrap() error { return r.err }

// Reason is the check that refused err, such as aud, run_id or signature, or empty
// when err is not a [TokenRefusal].
func Reason(err error) string {
	var r *TokenRefusal
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}

// refuse is the refusal of the check reason.
func refuse(reason string) error { return &TokenRefusal{reason: reason} }

// errExpect is the error of an Expect that is missing a field: the starter's fault,
// not the token's.
var errExpect = errors.New("the run a token is checked against is incomplete")

// Verifier verifies GitHub Actions OIDC tokens. Its keys are cached and fetched again
// at most once per [refetchInterval], by one fetch at a time. A token whose key is
// cached does not wait for a fetch. It is safe for concurrent use.
type Verifier struct {
	issuer string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	attempted time.Time
	// inflight is closed when the fetch that runs now ends, or nil when none runs.
	inflight chan struct{}
}

// NewVerifier is a Verifier of [Issuer]'s tokens.
func NewVerifier() *Verifier {
	return newVerifier(Issuer, http.DefaultTransport.(*http.Transport).Clone(), time.Now)
}

// newVerifier is a Verifier of issuer's tokens, which fetches through transport and
// tells the time with now. A test passes the URL of its fake issuer.
func newVerifier(issuer string, transport http.RoundTripper, now func() time.Time) *Verifier {
	return &Verifier{
		issuer: issuer,
		client: &http.Client{
			Transport: transport,
			Timeout:   fetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: now,
	}
}

// Verify verifies the job's token raw, a compact JWS, against the run want: its form,
// its header, its RS256 signature under the issuer's key its kid names, and its claims.
// A failed check is a [TokenRefusal] whose [Reason] names it.
func (v *Verifier) Verify(ctx context.Context, raw string, want Expect) (Claims, error) {
	if want.Audience == "" || want.Repository == "" || want.RepositoryID <= 0 || want.Workflow == "" ||
		want.Ref == "" || want.RunID <= 0 || want.LeaseUntil.IsZero() {
		return Claims{}, errExpect
	}
	if !v.now().Before(want.LeaseUntil) {
		return Claims{}, refuse("lease_until")
	}
	if len(raw) > maxToken {
		return Claims{}, refuse("size")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return Claims{}, refuse("format")
	}
	var dec [3][]byte
	for i, p := range parts {
		b, ok := base64url(p)
		if !ok {
			return Claims{}, refuse("format")
		}
		dec[i] = b
	}
	header, err := strictObject(dec[0])
	if err != nil {
		return Claims{}, refuse("header_json")
	}
	if alg, ok := str(header, "alg"); !ok || alg != "RS256" {
		return Claims{}, refuse("alg")
	}
	for _, name := range []string{"jku", "x5u", "jwk", "x5c", "crit"} {
		if _, ok := header[name]; ok {
			return Claims{}, refuse(name)
		}
	}
	kid, ok := str(header, "kid")
	if !ok || kid == "" {
		return Claims{}, refuse("kid")
	}
	key, err := v.key(ctx, kid)
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], dec[2]) != nil {
		return Claims{}, refuse("signature")
	}
	payload, err := strictObject(dec[1])
	if err != nil {
		return Claims{}, refuse("payload_json")
	}
	return v.claims(payload, want)
}

// claims checks a token's payload, whose signature holds, against want. The lease is
// checked again here, since fetching the key takes time.
func (v *Verifier) claims(p map[string]json.RawMessage, want Expect) (Claims, error) {
	now := v.now()
	if !now.Before(want.LeaseUntil) {
		return Claims{}, refuse("lease_until")
	}
	if iss, ok := str(p, "iss"); !ok || iss != v.issuer {
		return Claims{}, refuse("iss")
	}
	if !audience(p["aud"], want.Audience) {
		return Claims{}, refuse("aud")
	}
	exp, ok := numericDate(p, "exp", now)
	if !ok || !now.Before(exp.Add(leeway)) {
		return Claims{}, refuse("exp")
	}
	if _, present := p["nbf"]; present {
		if nbf, ok := numericDate(p, "nbf", now); !ok || nbf.After(now.Add(leeway)) {
			return Claims{}, refuse("nbf")
		}
	}
	if iat, ok := numericDate(p, "iat", now); !ok || iat.After(now.Add(leeway)) {
		return Claims{}, refuse("iat")
	}
	if repo, ok := str(p, "repository"); !ok || repo != want.Repository {
		return Claims{}, refuse("repository")
	}
	if id, ok := str(p, "repository_id"); !ok || id != strconv.FormatInt(want.RepositoryID, 10) {
		return Claims{}, refuse("repository_id")
	}
	ref, ok := str(p, "ref")
	if !ok || !refMatches(ref, want.Ref) {
		return Claims{}, refuse("ref")
	}
	template := want.Repository + "/.github/workflows/" + want.Workflow + "@" + ref
	if got, ok := str(p, "job_workflow_ref"); !ok || got != template {
		return Claims{}, refuse("job_workflow_ref")
	}
	if got, ok := str(p, "workflow_ref"); !ok || got != template {
		return Claims{}, refuse("workflow_ref")
	}
	sha, _ := str(p, "job_workflow_sha")
	if want.SHA != "" {
		if sha != want.SHA {
			return Claims{}, refuse("job_workflow_sha")
		}
		if got, ok := str(p, "workflow_sha"); !ok || got != want.SHA {
			return Claims{}, refuse("workflow_sha")
		}
	}
	if id, ok := str(p, "run_id"); !ok || id != strconv.FormatInt(want.RunID, 10) {
		return Claims{}, refuse("run_id")
	}
	if attempt, ok := str(p, "run_attempt"); !ok || attempt != "1" {
		return Claims{}, refuse("run_attempt")
	}
	if event, ok := str(p, "event_name"); !ok || event != "workflow_dispatch" {
		return Claims{}, refuse("event_name")
	}
	env, _ := str(p, "runner_environment")
	return Claims{
		Repository:        want.Repository,
		RepositoryID:      want.RepositoryID,
		RunID:             want.RunID,
		Ref:               ref,
		WorkflowSHA:       sha,
		RunnerEnvironment: env,
		Expiry:            exp,
	}, nil
}

// refMatches is whether the token's ref, a full name, is the ref want: equal to it
// when want is a full name, refs/..., or the branch refs/heads/ and want when want is
// short. A short want never matches a tag, a pull request's ref or any other ref.
func refMatches(ref, want string) bool {
	if strings.HasPrefix(want, "refs/") {
		return ref == want
	}
	return ref == "refs/heads/"+want
}

// audience is whether aud, a token's aud claim, names want: a string equal to it, or
// an array of strings, not empty, one of them equal to it.
func audience(aud json.RawMessage, want string) bool {
	if one, ok := str(map[string]json.RawMessage{"aud": aud}, "aud"); ok {
		return one == want
	}
	var many []json.RawMessage
	if json.Unmarshal(aud, &many) != nil || len(many) == 0 {
		return false
	}
	found := false
	for _, raw := range many {
		one, ok := str(map[string]json.RawMessage{"aud": raw}, "aud")
		if !ok {
			return false
		}
		found = found || one == want
	}
	return found
}

// str is the member name of an object as a string, and whether it is one; null is not.
func str(obj map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := obj[name]
	if !ok || !bytes.HasPrefix(raw, []byte(`"`)) {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// numericDate is the member name of an object as a NumericDate in whole seconds after
// the epoch, positive and at most maxAhead seconds after now, and whether it is one.
func numericDate(obj map[string]json.RawMessage, name string, now time.Time) (time.Time, bool) {
	raw, ok := obj[name]
	if !ok {
		return time.Time{}, false
	}
	var n int64
	if json.Unmarshal(raw, &n) != nil || n <= 0 || n > now.Unix()+maxAhead {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// base64url decodes s, base64url without padding, strictly: only the alphabet's
// characters, no padding and no line end, which the decoder would skip, and no bits
// set past the data.
func base64url(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// errJSON is the error of JSON strictObject refuses.
var errJSON = errors.New("not one JSON object, in UTF-8, with no member twice")

// strictObject decodes b, one JSON object in UTF-8 with nothing after it but white
// space, no member twice in any object and nesting at most maxDepth deep.
func strictObject(b []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(b) {
		return nil, errJSON
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errJSON
	}
	if err := walkObject(dec, 1); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errJSON
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, errJSON
	}
	return obj, nil
}

// walkObject reads the rest of an object whose { dec has read, and refuses a member
// that is there twice.
func walkObject(dec *json.Decoder, depth int) error {
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return errJSON
		}
		seen[name] = true
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// walkValue reads one value, and refuses an object in it with a member twice.
func walkValue(dec *json.Decoder, depth int) error {
	t, err := dec.Token()
	if err != nil {
		return errJSON
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return errJSON
	}
	if d == '{' {
		return walkObject(dec, depth+1)
	}
	for dec.More() {
		if err := walkValue(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// key is the issuer's key kid names. The keys are fetched when there are none, when
// they are older than keysMaxAge, or when kid is not among them, but never twice within
// refetchInterval. The fetch runs without the lock held, one at a time: a caller whose
// kid is cached takes its key at once, and a caller that needs the keys waits for the
// fetch that runs, or for ctx to end, which refuses the token.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	for {
		v.mu.Lock()
		now := v.now()
		fresh := v.keys != nil && now.Sub(v.fetchedAt) < keysMaxAge
		if k, ok := v.keys[kid]; ok && fresh {
			v.mu.Unlock()
			return k, nil
		}
		if done := v.inflight; done != nil {
			v.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, &TokenRefusal{reason: "jwks", err: ctx.Err()}
			}
		}
		if !v.attempted.IsZero() && now.Sub(v.attempted) < refetchInterval {
			v.mu.Unlock()
			if fresh {
				return nil, refuse("key")
			}
			return nil, refuse("jwks")
		}
		done := make(chan struct{})
		v.attempted, v.inflight = now, done
		v.mu.Unlock()

		keys, err := v.fetch(ctx)
		v.mu.Lock()
		if err == nil {
			v.keys, v.fetchedAt = keys, now
		}
		v.inflight = nil
		v.mu.Unlock()
		close(done)
		if err != nil {
			return nil, err
		}
		if k, ok := keys[kid]; ok {
			return k, nil
		}
		return nil, refuse("key")
	}
}

// fetch reads the issuer's openid-configuration and the JWKS its jwks_uri names,
// which must be https on the issuer's host. A caller that goes away does not cut the
// fetch short, so it cannot spend the refetch for nothing.
func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	b, err := v.get(ctx, v.issuer+"/.well-known/openid-configuration", maxDiscovery)
	if err != nil {
		return nil, &TokenRefusal{reason: "discovery", err: err}
	}
	doc, err := strictObject(b)
	if err != nil {
		return nil, &TokenRefusal{reason: "discovery", err: err}
	}
	if iss, ok := str(doc, "issuer"); !ok || iss != v.issuer {
		return nil, &TokenRefusal{reason: "discovery", err: errors.New("the openid-configuration names another issuer")}
	}
	jwksURI, ok := str(doc, "jwks_uri")
	if !ok || !sameHost(jwksURI, v.issuer) {
		return nil, &TokenRefusal{reason: "discovery", err: errors.New("the openid-configuration's jwks_uri is not https on the issuer's host")}
	}
	b, err = v.get(ctx, jwksURI, maxJWKS)
	if err != nil {
		return nil, &TokenRefusal{reason: "jwks", err: err}
	}
	keys, err := parseJWKS(b)
	if err != nil {
		return nil, &TokenRefusal{reason: "jwks", err: err}
	}
	return keys, nil
}

// sameHost is whether u is an https URL on issuer's host and port, with no user and no
// fragment. The host must be ASCII, and is compared in ASCII lower case only, so no
// Unicode character that folds to an ASCII letter passes for one.
func sameHost(u, issuer string) bool {
	a, err := url.Parse(u)
	if err != nil || a.Scheme != "https" || a.User != nil || a.Fragment != "" || a.Opaque != "" ||
		a.Host == "" || !isASCII(a.Host) {
		return false
	}
	b, err := url.Parse(issuer)
	return err == nil && lowerASCII(a.Host) == lowerASCII(b.Host)
}

// isASCII is whether s holds only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// lowerASCII is s with its ASCII upper-case letters made lower case, and every other
// byte kept.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// get fetches u, which must answer 200 with at most limit bytes. A redirect is not
// followed.
func (v *Verifier) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the issuer answers %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("the answer is larger than %d KiB", limit>>10)
	}
	return b, nil
}

// parseJWKS reads a JWKS's keys that can verify RS256: kty RSA, use sig or none, alg
// RS256 or none, a kid, and a modulus of 2048 to 8192 bits. Other keys are skipped. Two
// such keys with one kid refuse the JWKS.
func parseJWKS(b []byte) (map[string]*rsa.PublicKey, error) {
	doc, err := strictObject(b)
	if err != nil {
		return nil, err
	}
	var list []json.RawMessage
	if json.Unmarshal(doc["keys"], &list) != nil || list == nil {
		return nil, errors.New("the JWKS has no list of keys")
	}
	if len(list) > maxKeys {
		return nil, fmt.Errorf("the JWKS lists more than %d keys", maxKeys)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, raw := range list {
		jwk, err := strictObject(raw)
		if err != nil {
			return nil, err
		}
		kid, k := rsaKey(jwk)
		if k == nil {
			continue
		}
		if _, dup := keys[kid]; dup {
			return nil, errors.New("two keys in the JWKS share a kid")
		}
		keys[kid] = k
	}
	return keys, nil
}

// rsaKey is a JWK's kid and RSA key, or nil when it cannot verify RS256.
func rsaKey(jwk map[string]json.RawMessage) (string, *rsa.PublicKey) {
	if kty, _ := str(jwk, "kty"); kty != "RSA" {
		return "", nil
	}
	if use, ok := str(jwk, "use"); jwk["use"] != nil && (!ok || use != "sig") {
		return "", nil
	}
	if alg, ok := str(jwk, "alg"); jwk["alg"] != nil && (!ok || alg != "RS256") {
		return "", nil
	}
	kid, ok := str(jwk, "kid")
	if !ok || kid == "" {
		return "", nil
	}
	ns, _ := str(jwk, "n")
	es, _ := str(jwk, "e")
	n, ok1 := base64url(ns)
	e, ok2 := base64url(es)
	if !ok1 || !ok2 || len(n) == 0 || n[0] == 0 || len(e) == 0 || e[0] == 0 || len(e) > 4 {
		return "", nil
	}
	mod := new(big.Int).SetBytes(n)
	exp := new(big.Int).SetBytes(e).Int64()
	if bits := mod.BitLen(); bits < minKeyBits || bits > maxKeyBits || exp < 3 || exp%2 == 0 || exp > 1<<31-1 {
		return "", nil
	}
	return kid, &rsa.PublicKey{N: mod, E: int(exp)}
}
